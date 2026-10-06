#!/usr/bin/env python3
"""One entry point for the whole Security Decision Record (SDR) pipeline.

Nothing here does any work of its own. `sdr.py validate` runs the same
validation suite (validators + offline tests) that .github/workflows/validate.yml
runs via `python sdr.py validate`, so the local and CI VALIDATION SUITES cannot
drift. CI additionally enforces three gates OUTSIDE this command:
regenerate-and-diff, a double-build reproducibility check, and scanner-catalog
freshness. So a clean local run means the validation suite would pass in CI, not
that every CI gate would. If this file and that workflow ever disagree on the
suite, the workflow is correct and this file is the bug.

    python sdr.py all         build, validate, scan, then print a summary
    python sdr.py build       regenerate every deliverable
    python sdr.py validate    run the build gate (0 hard failures required)
    python sdr.py scan        run the readiness scanner (does not gate)
    python sdr.py clean       remove caches and scanner reports
    python sdr.py diff        show what a dataset change would affect
    python sdr.py review      report the human review register
    python sdr.py release     build, verify consistency, print the release tag

Exit codes: 0 success, 1 a step failed, 2 a dependency or path problem.
The readiness scanner's "findings exist" exit code is not a failure and is
not propagated; open findings are the normal state of an unfinished record.
"""

import argparse
import glob
import json
import os
import shutil
import subprocess
import sys
import time

BASE = os.path.dirname(os.path.abspath(__file__))


def _utc_today():
    """The single audit clock (finding F10). Collection (append_metrics) stamps
    datapoints in UTC; preflight windows MUST use the SAME UTC calendar day, not
    the host's local date. At UTC midnight a local-date preflight can judge a
    genuinely-current UTC observation as future-dated, so the same code+fixture
    passes in GitHub's UTC runner and fails on a local machine west of UTC. One
    UTC clock removes that host-timezone dependence."""
    import datetime as _d
    return _d.datetime.now(_d.timezone.utc).date()

SCRIPTS = os.path.join(BASE, "validation", "scripts")
SDRSCAN = os.path.join(BASE, "automation", "sdrscan", "sdrscan.py")

# AUD-F37: package-preflight verifies the metric history's hash chain and its
# signed digest with the same modules the appender and publisher use.
sys.path.insert(0, os.path.join(BASE, "automation", "metrics"))
sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
import history_integrity as _hi  # noqa: E402
import sign_evidence as _se  # noqa: E402
# AUD-F38: a labelled proposal (DRAFT / Example) is unanswered until a human
# accepts it; the one definition lives in validation/scripts/unreviewed_text.py.
from unreviewed_text import is_unreviewed as _is_unreviewed  # noqa: E402
VALIDATION_REPORT = os.path.join(BASE, "validation", "reports", "validation-report.json")
SCAN_REPORT_GLOB = os.path.join(BASE, "validation", "reports", "sdrscan", "sdrscan-class-*.json")
OFFERING_PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
RULES_DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")

# Finding 1: the submitted SDR JSON normalizes every non-official authoring
# status (Planned, Gap, Exception, Not Applicable, Needs validation, TBD, ...)
# to "Not Implemented" via build_sdr.official_status(). Preflight and the
# scanner MUST evaluate the SAME normalized status, or a record authored
# "Planned" is treated as followed by the gate while the JSON says
# "Not Implemented" - a false-ready path. This mirrors build_sdr.official_status
# byte-for-byte; the semantic-roundtrip test pins that mapping and a parity
# assertion in test_submission_readiness keeps the two in lockstep.
_OFFICIAL_STATUSES = {"Implemented", "Not Implemented", "Partially Implemented"}


def official_status(authoring_status):
    s = str(authoring_status or "").strip()
    if s in _OFFICIAL_STATUSES:
        return s
    if s.lower() in ("partially implemented", "partial"):
        return "Partially Implemented"
    return "Not Implemented"

# Artifact-requirement classification (external re-audit finding 4). The prior
# model was binary: any artifact whose wording contained a conditional marker
# was demoted to advisory and NEVER gated. That wrongly dropped mandatory
# ONE-OF artifacts - "a recent vulnerability report OR a sample vulnerability
# report", "URL or explanation of how to request" - where the artifact is still
# REQUIRED, just satisfiable by either alternative. A provider could omit the
# artifact entirely and reach READY.
#
# Three classes, resolved from the dataset artifact wording:
#   REQUIRED         unconditional "provide X"          -> gate: non-empty artifact
#   REQUIRED_ONE_OF  "X or a sample", "URL or explanation",
#                    "if not available ... MUST provide a sample" (both
#                    branches yield an artifact)         -> gate: non-empty artifact
#                    (we cannot judge WHICH alternative from free text, but a
#                    non-empty rule_artifacts is still mandatory)
#   CONDITIONAL      "if applicable", "(if applicable)",
#                    "if no SCN notifications", "if no documentation updates"
#                    (a legitimate no-artifact branch exists)  -> advisory
#
# A bare " or " is NOT a one-of signal: descriptive noun-phrase text uses it
# ("validated ... or are update streams", "one or more incidents", "manual or
# automated", "collected or maintained") and such artifacts are UNCONDITIONAL.
# Only the specific alternative-DELIVERABLE phrasings below mark a one-of.

# Genuinely conditional: a legitimate "no artifact" branch exists, so advisory.
_ARTIFACT_CONDITIONAL_MARKERS = (
    "if applicable", "(if applicable)", "as applicable",
    "if no ", "if the report is not available and no",
    "if and how", "when available", "where available", "unless no",
)
# One-of alternative deliverables: the artifact is still mandatory (a non-empty
# rule_artifacts is required) but satisfiable by either alternative.
_ARTIFACT_ONE_OF_MARKERS = (
    "or a sample", "or sample", "or an explanation", "or explanation",
    "url or explanation", "report or a sample", "if the report is not available",
    "or a recent",
)

_ARTIFACT_REQUIRED_RULES_CACHE = {}


def _classify_artifact(strs):
    """Classify a rule's artifact wording as REQUIRED, REQUIRED_ONE_OF, or
    CONDITIONAL. CONDITIONAL wins when a genuine no-artifact branch exists;
    otherwise ONE_OF when an alternative-deliverable phrasing is present;
    otherwise REQUIRED. Both REQUIRED and REQUIRED_ONE_OF are hard-gated for a
    non-empty artifact; CONDITIONAL is advisory."""
    if not strs:
        return None
    joined = " ".join(strs).lower()
    if any(m in joined for m in _ARTIFACT_CONDITIONAL_MARKERS):
        return "CONDITIONAL"
    if any(m in joined for m in _ARTIFACT_ONE_OF_MARKERS):
        return "REQUIRED_ONE_OF"
    return "REQUIRED"


def artifact_required_rule_ids(cls=None, forces=("MUST",)):
    """Rule IDs that carry an UNCONDITIONAL artifact requirement at one of the
    given force levels, for a given certification class.

    SDR-CSO-FRR item on rule-specific artifacts was previously treated as
    always 'if applicable, not gated', so a provider could fill every narrative
    field and still omit a canonical required artifact and reach READY (external
    re-audit finding 2). The dataset states, per rule, when an artifact is
    required: each rule dict carries an `artifacts` map keyed by applicability
    (`all`/`20x`/`rev5`). Many rules ALSO vary by class: their force + artifacts
    live under `varies_by_class.<a|b|c|d>`, not at the rule top level (finding
    6). This resolves the force + artifacts for the ACTUAL class, reading the
    varies_by_class branch when present.

    `forces` selects which force levels count. Default ("MUST",) is the base
    gate: a mandatory rule that omits its canonical artifact is blocked.
    Passing ("MUST", "MAY") additionally captures OPTIONAL artifact-bearing
    rules, used to gate a Class A MAY rule the provider SELECTED - a selected
    MAY rule is fully reviewed, so its artifact requirement then applies
    (finding 6).

    Only rules whose class-resolved artifact wording is UNCONDITIONAL are
    returned; conditional / OR-satisfiable wording (see
    _ARTIFACT_CONDITIONAL_MARKERS) stays advisory to avoid over-blocking on
    text no machine can judge. Cached per (class, forces); safe if the dataset
    is missing (returns an empty set -> nothing newly gated)."""
    key = ((cls or "").lower(), tuple(sorted(forces)))
    if key in _ARTIFACT_REQUIRED_RULES_CACHE:
        return _ARTIFACT_REQUIRED_RULES_CACHE[key]
    result = set()
    try:
        with open(RULES_DATASET, encoding="utf-8") as _f:
            ds = json.load(_f)
    except (OSError, ValueError):
        _ARTIFACT_REQUIRED_RULES_CACHE[key] = result
        return result
    clsk = key[0]
    allowed_forces = set(forces)

    def _flat_artifacts(node):
        arts = node.get("artifacts")
        strs = []
        if isinstance(arts, dict):
            for av in arts.values():
                if isinstance(av, list):
                    strs.extend(str(x) for x in av)
        elif isinstance(arts, list):
            strs.extend(str(x) for x in arts)
        return strs

    def _requires_artifact(node):
        """(force, artifact-strings) resolved from a rule node, honoring a
        class-specific varies_by_class branch when the caller named a class."""
        vbc = node.get("varies_by_class")
        if clsk and isinstance(vbc, dict) and clsk in vbc and isinstance(vbc[clsk], dict):
            branch = vbc[clsk]
            return branch.get("force"), _flat_artifacts(branch)
        return node.get("force"), _flat_artifacts(node)

    def _gate_if_unconditional(rid, force, strs):
        if strs and force in allowed_forces:
            # Finding 4: REQUIRED and REQUIRED_ONE_OF both demand a non-empty
            # artifact (a mandatory one-of is still mandatory); only CONDITIONAL
            # wording with a legitimate no-artifact branch stays advisory.
            if _classify_artifact(strs) in ("REQUIRED", "REQUIRED_ONE_OF"):
                result.add(rid)

    def _walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                # varies_by_class children are class-override branches of a
                # parent rule, not standalone rule IDs; handled via the parent.
                if k == "varies_by_class" and isinstance(v, dict):
                    continue
                if isinstance(v, dict):
                    # A rule is keyed by its ID and carries force+statement
                    # either at the top level or inside varies_by_class.
                    is_rule = ("force" in v and "statement" in v) or (
                        isinstance(v.get("varies_by_class"), dict)
                        and any(isinstance(b, dict) and "force" in b
                                for b in v["varies_by_class"].values()))
                    if is_rule:
                        force, strs = _requires_artifact(v)
                        _gate_if_unconditional(k, force, strs)
                _walk(v)
        elif isinstance(node, list):
            for v in node:
                _walk(v)

    _walk(ds)
    _ARTIFACT_REQUIRED_RULES_CACHE[key] = result
    return result

# Build order matters. Each step reads what the step above it wrote:
# catalogs feed notes, notes feed profiles and the collector registry,
# profiles feed the record, the record feeds the Word file. Reordering these
# does not fail loudly; it silently builds against stale inputs.
BUILD_STEPS = [
    ("validate_upstream.py", "validate the pinned dataset against the official rules schema + lock"),
    ("build_catalogs.py", "rule and indicator catalogs from the pinned dataset"),
    ("build_notes.py", "per-rule notes and family name expansions"),
    ("build_profiles.py", "per-class profiles, Class C overlay, Class D register"),
    ("build_collector_registry.py", "indicator to read-only AWS check map"),
    ("build_inactive_classes.py", "inactive-class SDR outputs (JSON, text, Word) so committed A/B/C never drift"),
    ("build_sdr.py", "schema JSON, extensions companion, plain text record"),
    ("build_cpo.py", "Certification Package Overview (CPO-CSO-OVR)"),
    ("build_ocr.py", "example Ongoing Certification Report (CCM-OCR-AVL)"),
    ("build_scg.py", "Secure Configuration Guide scaffold (SCG-CSO-RSC/AUP)"),
    ("build_events.py", "example incident, SCN, and vulnerability artifacts"),
    ("automation/exporters/oscal_export.py", "OSCAL export of the SDR"),
    ("build_docx.py", "authoring Word document"),
    ("build_crosswalk.py", "NIST SP 800-53 Revision 5 to 20x crosswalk"),
    ("build_applicability_decisions.py", "applicability decision ledger (included and excluded, with reasons)"),
    ("build_assurance_graph.py", "unified assurance graph joining all artifacts"),
    ("build_sbom.py", "CycloneDX SBOM of the framework's own pinned dependencies"),
    ("build_release_manifest.py", "cryptographic release manifest of the package"),
    ("validate_package_consistency.py", "cross-artifact consistency check"),
    ("build_reports.py", "evidence-coverage and reviewer reports"),
    ("build_visualization.py", "self-contained HTML assurance-graph view"),
]

# The authoritative validation gate. `cmd_validate` runs every entry, and CI
# calls `python sdr.py validate` rather than listing scripts of its own, so the
# local and CI VALIDATION SUITES cannot drift. This is suite parity only: CI
# also runs regenerate-and-diff, a reproducibility gate, and scanner-catalog
# freshness outside this command. Paths are relative to the repository root.
VALIDATION_GATE = [
    ("validation/scripts/validate_sdr.py", "SDR schema, coverage, minimums, hygiene, content fidelity"),
    ("validation/scripts/validate_package.py", "CPO/OCR against official schemas"),
    ("validation/scripts/validate_cpo_semantics.py", "CPO rule-completeness (CPO-CSO-OVR/MTD, not just schema)"),
    ("validation/scripts/validate_assurance_graph.py", "assurance graph (full-chain traceability)"),
    ("validation/scripts/validate_reviews.py", "human review register (no machine-authored approvals)"),
    ("validation/scripts/validate_evidence.py", "live evidence-integrity gate (malformed/mismatched digests)"),
    ("validation/scripts/validate_evidence_store_controls.py", "evidence-store control mapping cites only real CR26 identifiers"),
    ("validation/scripts/validate_isolation_stack.py", "evidence-store isolation reference stack keeps its load-bearing invariants"),
    ("validation/scripts/validate_package_consistency.py", "cross-artifact package consistency"),
]

# The full offline test suite CI runs. Same source of truth as CI.
TEST_SUITE = [
    "validation/scripts/test_sdr_semantic_roundtrip.py",
    "validation/scripts/test_package_build.py",
    "tests/test_cli.py",
    "validation/scripts/test_reviews.py",
    "tests/adversarial/run_adversarial.py",
    "tests/adversarial/test_e2e_tampering.py",
    "automation/collectors/test_collectors.py",
    "automation/collectors/test_collectors_scale.py",
    "automation/collectors/test_collectors_fixtures.py",
    "automation/collectors/test_multi_account.py",
    "automation/prefill/test_prefill.py",
    "automation/ai/test_draft_narratives.py",
    "automation/review/test_review_proposals.py",
    "validation/scripts/test_unreviewed_text.py",
    "automation/ai/test_explain_findings.py",
    "automation/ai/test_rollup_evidence.py",
    "automation/ai/test_review_overclaim.py",
    "automation/ai/test_suggest_ksi_mapping.py",
    "automation/metrics/test_append_metrics.py",
    "automation/metrics/test_publish_history.py",
    "automation/prefill/test_binding_e2e.py",
    "automation/metrics/test_metric_history_longitudinal.py",
    "automation/metrics/test_per_metric_series.py",
    "validation/scripts/test_kmt_summary_derivation.py",
    "automation/config-rules/test_evidence_existence_rule.py",
    "automation/config-rules/deploy/test_generate_templates.py",
    "automation/config-rules/deploy/test_cdk_synth.py",
    "automation/collectors/test_collector_iam_matches.py",
    "automation/collectors/test_collection_fail_closed.py",
    "validation/scripts/test_docx_integrity.py",
    "automation/metrics/test_history_integrity.py",
    "automation/collectors/test_service_registry.py",
    "automation/collectors/test_thirdparty_upsert.py",
    "automation/pipeline/test_release_gate.py",
    "automation/pipeline/test_json_download_headers.py",
    "automation/storage/test_provision_store.py",
    "automation/storage/test_ingest_evidence.py",
    "automation/ai/test_bedrock_boundary.py",
    "validation/scripts/test_dataset_diff.py",
    "validation/scripts/test_change_impact.py",
    "validation/scripts/test_sbom.py",
    "validation/scripts/test_fedramp_time.py",
    "validation/scripts/test_mot_continuity.py",
    "validation/scripts/test_vvk_automated_methods.py",
    "validation/scripts/test_init_wizard.py",
    "validation/scripts/test_customer_config_rules.py",
    "validation/scripts/test_assurance_graph_method_count.py",
    "validation/scripts/test_validate_class_matrix.py",
    "validation/scripts/test_lock_closure.py",
    "validation/scripts/test_update_sources_lock.py",
    "validation/scripts/test_class_a_framework.py",
    "validation/scripts/test_class_a_applicable_scope.py",
    "validation/scripts/test_class_b_optional_ksi_scope.py",
    "validation/scripts/test_config_rule_vocabulary.py",
    "validation/scripts/test_bucket_b_outcome_metrics.py",
    "validation/scripts/test_install_dependencies.py",
    "validation/scripts/test_dataset_version_consistency.py",
    "validation/scripts/test_evidence_freshness.py",
    "validation/scripts/test_evidence_integrity.py",
    "automation/collectors/test_sign_evidence.py",    "validation/scripts/test_applicability.py",
    "automation/exporters/test_oscal_export.py",
    "automation/collectors/test_evidence_wiring.py",
    "automation/collectors/test_thirdparty_adapters.py",
    "automation/collectors/test_evidence_lifecycle.py",
    "examples/shift-left/test_run_policy.py",
    "automation/sdrscan/test_checks.py",
    "automation/sdrscan/test_mute_expiry.py",
    "validation/scripts/test_visualization_xss.py",
    "validation/scripts/test_submission_readiness.py",
    "validation/scripts/test_assessor_attack.py",
    "validation/scripts/test_cpo_semantics_adversarial.py",
]

REQUIRED_MODULES = [
    ("jsonschema", "jsonschema"),
    ("referencing", "referencing"),
    ("docx", "python-docx"),
    ("cryptography", "cryptography"),
]

RULE = "-" * 68


def out(line=""):
    print(line, flush=True)


def step_header(n, total, label):
    out()
    out(f"[{n}/{total}] {label}")
    out(RULE)


def run(script_path, args=None, label=None):
    """Run one pipeline script as a child process, streaming its output.

    Returns the child's exit code. Output is inherited rather than captured so
    that a long build shows progress, and so a traceback lands in the terminal
    where the reader expects it.
    """
    if not os.path.exists(script_path):
        out(f"FAIL. Missing script: {os.path.relpath(script_path, BASE)}")
        return 2
    cmd = [sys.executable, script_path] + list(args or [])
    started = time.monotonic()
    proc = subprocess.run(cmd, cwd=BASE)
    elapsed = time.monotonic() - started
    name = label or os.path.basename(script_path)
    if proc.returncode == 0:
        out(f"OK. {name} ({elapsed:.1f}s)")
    else:
        out(f"FAIL. {name} exited {proc.returncode} ({elapsed:.1f}s)")
    return proc.returncode


def _validation_gate_only():
    """Run the VALIDATION_GATE validators (no test suite), quietly, returning 0
    only if every gate passes. Used as a preflight precondition so a package
    that fails structural validation can never be reported submission-ready."""
    failures = 0
    for rel, _label in VALIDATION_GATE:
        proc = subprocess.run([sys.executable, os.path.join(BASE, rel)],
                              cwd=BASE, capture_output=True, text=True)
        if proc.returncode != 0:
            failures += 1
    return 1 if failures else 0


def check_dependencies():
    """Refuse to start rather than fail three steps in with an import error."""
    missing = []
    for module, package in REQUIRED_MODULES:
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    if sys.version_info < (3, 10):
        out(f"FAIL. Python 3.10 or newer is required; this is {sys.version.split()[0]}.")
        return False
    if missing:
        out("FAIL. Missing dependencies: " + ", ".join(missing))
        out("Install them with:")
        out("    pip install " + " ".join(missing))
        return False
    return True


def current_class():
    """The certification class the pipeline is currently building for."""
    try:
        with open(OFFERING_PROFILE, encoding="utf-8") as f:
            return (json.load(f).get("certification_class") or "?").upper()
    except (OSError, ValueError):
        return "?"


def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


# FRC-CSX-MOT continuity tolerance (AUD-F21). PROJECT POLICY, NOT A FEDRAMP
# NUMBER: the dataset says Class C MUST provide status "from persistent
# validation over at least the past 6 months" (18 at D) and mandates no cadence
# and no maximum gap. This repository turns "persistent" into a checkable bound:
# no gap between consecutive observations, nor the leading or trailing gap, may
# exceed MOT_MAX_GAP_DAYS_DEFAULT days. 45 accepts an honest weekly, biweekly or
# monthly cadence with the occasional miss while rejecting a hollow two-point
# series and a quarter-long silence. A provider may declare a different
# tolerance in the offering profile (`mot_max_gap_days`), reviewable by the
# assessor, bounded above by MOT_MAX_GAP_DAYS_CEILING because a gap of a quarter
# or more inside a six-month window is not persistence under any reading.
MOT_MAX_GAP_DAYS_DEFAULT = 45
MOT_MAX_GAP_DAYS_CEILING = 90

# AUD-F33: an EARLY WARNING, distinct from the hard continuity bound above. The
# bound tolerates up to mot_max_gap_days of silence before it blocks, which is
# right for a monthly cadence but means a daily collector can be broken for six
# weeks before anyone is told. Preflight therefore reports (as an advisory, not
# a blocker) every in-scope KSI whose newest datapoint is older than this many
# days, so a stalled collection is visible the week it stalls. Project policy,
# not a FedRAMP figure; FedRAMP mandates no cadence.
MOT_STALE_ADVISORY_DAYS = 7


def mot_stale_days(dates, today, threshold=MOT_STALE_ADVISORY_DAYS):
    """Days since the NEWEST observation when that exceeds the advisory
    threshold, else None. Independent of the hard continuity bound: this is the
    early warning that a collection has stopped, reported as an advisory long
    before the gap can become an FRC-CSX-MOT blocker (AUD-F33)."""
    if not dates:
        return None
    gap = (today - max(dates)).days
    return gap if gap > threshold else None


def mot_max_gap_days(offering):
    """The continuity tolerance in force: the offering profile's
    `mot_max_gap_days` when declared and valid (integer, 1..ceiling), else the
    project default. Returns (days, source) where source is 'offering-profile'
    or 'project-default'; an invalid declaration is reported as
    ('invalid', ...) so preflight can block rather than silently default."""
    raw = (offering or {}).get("mot_max_gap_days")
    if raw is None or raw == "":
        return MOT_MAX_GAP_DAYS_DEFAULT, "project-default"
    try:
        days = int(raw)
    except (TypeError, ValueError):
        return None, f"invalid ({raw!r} is not an integer)"
    if not 1 <= days <= MOT_MAX_GAP_DAYS_CEILING:
        return None, f"invalid ({days} is outside 1..{MOT_MAX_GAP_DAYS_CEILING})"
    return days, "offering-profile"


def mot_continuity(window_dates, today, max_gap_days=MOT_MAX_GAP_DAYS_DEFAULT,
                   window_start=None):
    """Assess whether an in-window metric series shows PERSISTENT validation,
    not just sufficient age. FRC-CSX-MOT requires "status from persistent
    validation over at least the past 6 months"; the age check elsewhere only
    proves the oldest point is old enough, so [6-months-ago, today] passes it
    while being two lonely points.

    The rule does NOT mandate a fixed cadence, so this does not require a daily
    (or any specific) cadence. It flags a series as non-persistent when any gap
    between consecutive observations, the LEADING gap (window start to the first
    in-window observation), OR the trailing gap (newest point to today) exceeds
    max_gap_days. max_gap_days is REPOSITORY POLICY (see mot_max_gap_days), not
    a FedRAMP figure: the default accepts an honest weekly, biweekly, or
    monthly (~30-day) cadence with the occasional miss, while rejecting the
    hollow case (two points 6 months apart) and a quarter-long silence. The
    observed median cadence is REPORTED alongside, not used to set the bound.

    Finding F06: WITHOUT the leading-gap check, a series like [300 days ago,
    yesterday, today] evaluated against a 6-month window silently passed - the
    300-days-ago point falls BEFORE the cutoff and is filtered out, leaving
    [yesterday, today] whose internal and trailing gaps are tiny, so nearly the
    entire required window was unobserved yet no gap was flagged. Measuring the
    leading gap from window_start closes that: an in-window series that only
    starts near `today` cannot claim coverage of the whole period.

    window_dates: iterable of datetime.date already filtered to >= window_start.
    window_start: the required window's start date (mot_cutoff). When provided,
    the leading gap (window_start -> first observation) is enforced too.
    Returns (gappy: bool, largest_gap|None, median_gap|None, trailing_gap|None).
    A single (or zero) in-window point is not persistent validation -> gappy.
    """
    win = sorted(window_dates)
    if len(win) < 2:
        return True, None, None, None
    deltas = [(win[i] - win[i - 1]).days for i in range(1, len(win))]
    ds = sorted(deltas)
    mid = len(ds) // 2
    median = ds[mid] if len(ds) % 2 else (ds[mid - 1] + ds[mid]) / 2
    largest = max(deltas)
    trailing = (today - win[-1]).days
    leading = (win[0] - window_start).days if window_start is not None else 0
    gappy = (largest > max_gap_days or trailing > max_gap_days
             or leading > max_gap_days)
    # Surface the leading gap in `largest` when it dominates, so the reported
    # number reflects the actual worst coverage hole (F06).
    largest = max(largest, leading)
    return gappy, largest, round(median, 1), trailing


# --- FRC-CLA-ASF / FRC-CLA-EAM: Class A approved frameworks + materials ---
# Verbatim from the pinned dataset. ASF approves: FedRAMP Rev5 (including
# FedRAMP Ready) at any historical Impact Level, SOC 2 Type II, GovRAMP at any
# Impact Level. EAM enumerates required materials for exactly three keys: SOC 2
# Type II, FedRAMP Ready, GovRAMP. FedRAMP Rev5 (full authorization) has no
# fixed EAM material-type list ("any other materials required by FedRAMP").

# SOC 2 eligibility is Type II specifically; a bare "SOC 2" (could be Type I) is
# NOT aliased. Rev5 (full authorization) and Ready are DISTINCT keys.
CLA_FRAMEWORK_ALIASES = {
    "soc2_type_ii": "soc2_type_ii", "soc 2 type ii": "soc2_type_ii",
    "soc2 type ii": "soc2_type_ii", "soc 2 type 2": "soc2_type_ii",
    "soc2 type 2": "soc2_type_ii",
    "fedramp_rev5": "fedramp_rev5", "fedramp rev5": "fedramp_rev5",
    "fedramp rev 5": "fedramp_rev5", "rev5": "fedramp_rev5",
    "fedramp ready": "fedramp_ready", "fedramp_ready": "fedramp_ready",
    "govramp": "govramp",
}
# Force-gated material TYPES per framework (if-applicable items excluded). Rev5
# has an empty list: no fixed type set, but at least one material is required.
CLA_REQUIRED_MATERIALS = {
    "soc2_type_ii": [
        ("complete_report", "Complete SOC 2 Type II report"),
        ("verified_audit_engagement", "Verified audit engagement documentation"),
        ("upcoming_report_schedule", "Estimated schedule for upcoming report"),
    ],
    "fedramp_rev5": [],
    "fedramp_ready": [
        ("readiness_assessment_report", "Readiness Assessment Report"),
        ("security_assessment_plan", "Security Assessment Plan"),
    ],
    "govramp": [
        ("readiness_assessment_report", "Readiness Assessment Report"),
        ("security_assessment_plan", "Security Assessment Plan"),
    ],
}


def class_a_framework_key(raw):
    """Normalize a declared Class A external-assessment framework to a canonical
    key, or None if it is not FedRAMP-approved. A bare 'SOC 2' is None (must be
    Type II); Rev5 and Ready are distinct."""
    if raw is None:
        return None
    return CLA_FRAMEWORK_ALIASES.get(str(raw).strip().lower())


def class_a_required_material_types(key):
    """Return the force-gated EAM material type keys for a canonical framework."""
    return [k for k, _label in CLA_REQUIRED_MATERIALS.get(key, [])]


def optional_at_class_b_ksis(ksi_indicators):
    """The KSI ids that are OPTIONAL at Class B, detected from the dataset's
    varies_by_class 'b' statement carrying the "**Optional:**" prefix (verified
    against the pinned CR26 dataset: KSI-CNA-EIS, KSI-MLA-ALA, KSI-SVC-PRR,
    KSI-SVC-RUD, KSI-SVC-VCM lose that prefix at Class C where they are
    mandatory). Single source of truth shared by preflight and its test."""
    out = set()
    for ind in ksi_indicators or []:
        vbc = ind.get("varies_by_class") or {}
        if not isinstance(vbc, dict):
            continue
        b_stmt = (vbc.get("b") or {}).get("statement", "")
        if str(b_stmt).lstrip().startswith("**Optional:**"):
            out.add(ind.get("ksi_id"))
    return out


def submitted_rule_ids(profile_rules, cls, selected_optional=None):
    """The rule IDs that enter the SUBMITTED SDR for a class.

    For Class A this mirrors build_sdr.py exactly: FRC-CLA-OFR optional (MAY)
    rules are opt-in, so an optional rule is submitted only when its rule_id is
    in selected_optional (default empty). Every other class submits all profile
    rules. Preflight uses this so its applicable-record scan matches what the
    SDR actually contains, instead of gating optional rules the SDR excluded.
    """
    ids = {r.get("rule_id") for r in profile_rules}
    if cls == "a":
        selected = set(selected_optional or [])
        ids = {
            r.get("rule_id") for r in profile_rules
            if r.get("class_a_obligation") != "optional" or r.get("rule_id") in selected
        }
    return ids


def submitted_ksi_ids(ksi_indicators, cls, selected_optional_ksis=None):
    """The KSI ids that enter the SUBMITTED SDR for a class.

    Single source of truth shared by the builder (build_sdr.py), the validator
    (validate_sdr.py), the scanner, the assurance-graph, and preflight so every
    layer scopes Class B identically. At Class B the optional-at-B KSIs
    (varies_by_class 'b' carrying "**Optional:**") are opt-in: an optional KSI is
    submitted only when its ksi_id is in selected_optional_ksis (default empty),
    mirroring how Class A treats FRC-CLA-OFR MAY rules. Every other class
    submits all KSIs (optional-at-B KSIs are mandatory at Class C/D).

    Returns the set of submitted ksi_ids. Use unknown_optional_ksi_selections()
    to detect misspelled/unknown selections and block on them.
    """
    all_ids = {ind.get("ksi_id") for ind in (ksi_indicators or [])}
    if cls != "b":
        return all_ids
    optional = optional_at_class_b_ksis(ksi_indicators)
    selected = set(selected_optional_ksis or [])
    # Baseline (non-optional) KSIs are always submitted; optional-at-B KSIs only
    # when explicitly selected.
    return {kid for kid in all_ids if kid not in optional or kid in selected}


def unknown_optional_ksi_selections(ksi_indicators, selected_optional_ksis):
    """Selections in selected_optional_ksis that are not real optional-at-B KSI
    ids. A misspelled or non-optional selection is a hard error (a provider
    thinks it opted a KSI in but it silently does nothing), so callers block on
    a non-empty return rather than warning."""
    optional = optional_at_class_b_ksis(ksi_indicators)
    return {k for k in (selected_optional_ksis or []) if k not in optional}


# Evidence freshness for the submission gate. FedRAMP guidance is explicit that
# "stale screenshots, expired exports, outdated descriptions, or old evidence
# can cause rejection." This classifies an evidence observation's freshness so
# preflight can gate on EXPIRED evidence backing a populated claim, while never
# equating stale evidence with noncompliance and never touching a status
# (collection failure != control failure; stale != noncompliant).
DEFAULT_EVIDENCE_FRESHNESS_DAYS = 90


def _evidence_observed_at(ev):
    """Extract the observation timestamp from an evidence entry, tolerating the
    three field names the collectors/adapters use. Returns a string or None."""
    if not isinstance(ev, dict):
        return None
    return (ev.get("lastUpdated") or ev.get("collected_at")
            or ev.get("observed_at") or None)


def classify_evidence_freshness(observed_at, now, policy_days=DEFAULT_EVIDENCE_FRESHNESS_DAYS):
    """Return 'current' | 'stale' | 'expired' | 'undated' for one evidence
    observation. 'current' within policy_days; 'stale' up to 2x policy_days;
    'expired' beyond; 'undated' when there is no parseable timestamp (undated
    evidence is a reporting matter for the linkage check, never an expiry
    blocker here). now and observed_at are datetimes/ISO strings."""
    import datetime as _d
    if not observed_at:
        return "undated"
    s = str(observed_at).replace("Z", "+00:00")
    obs = None
    for parse in (lambda: _d.datetime.fromisoformat(s),
                  lambda: _d.datetime.fromisoformat(s[:10])):
        try:
            obs = parse()
            break
        except ValueError:
            continue
    if obs is None:
        return "undated"
    if obs.tzinfo is None:
        obs = obs.replace(tzinfo=_d.timezone.utc)
    now = now if now.tzinfo else now.replace(tzinfo=_d.timezone.utc)
    fresh_until = obs + _d.timedelta(days=policy_days)
    hard_expiry = obs + _d.timedelta(days=policy_days * 2)
    if now <= fresh_until:
        return "current"
    if now <= hard_expiry:
        return "stale"
    return "expired"


# Plain-English offering-profile wizard (Max's request): the offering profile
# is the single customization file the generators read. Editing raw JSON by hand
# is the most error-prone first step; `sdr.py init` asks plain questions and
# writes a valid profile, leaving the deep assessment blocks untouched.
INIT_QUESTIONS = [
    ("organization_name", "What is your organization's legal name?"),
    ("offering_name", "What is the cloud offering's name?"),
    ("offering_abbreviation", "A short abbreviation for the offering (e.g. EPF)?"),
    ("business_purpose", "In one sentence, what does the offering do?"),
    ("service_model", "Service model (IaaS | PaaS | SaaS)?"),
    ("deployment_model", "Deployment model (Public | Government-only | Hybrid)?"),
    ("certification_class", "Certification class (a | b | c)?"),
    ("primary_region", "Primary AWS region (e.g. us-east-1)?"),
    ("dr_region", "Disaster-recovery region (e.g. us-west-2)?"),
    ("security_contact", "Security point-of-contact email?"),
    ("incident_contact", "Incident-reporting point-of-contact email?"),
    ("trust_center_uri", "URL of your FedRAMP-compatible trust center (CDS-CSO-UTC)?"),
    ("secure_config_guide_uri", "URL of your published Secure Configuration Guide (SCG-CSO-RSC)?"),
]


def cmd_init(args):
    """Interactive (or scripted via --set key=value) offering-profile wizard.
    Reads the existing profile, prompts for the plain-English fields, writes it
    back. Non-destructive to fields it does not ask about; validates class."""
    path = OFFERING_PROFILE
    try:
        with open(path, encoding="utf-8") as f:
            profile = json.load(f)
    except (OSError, ValueError) as e:
        out(f"Could not read the offering profile at {path}: {e}")
        return 1

    overrides = {}
    for item in (getattr(args, "set", None) or []):
        if "=" not in item:
            out(f"Ignoring malformed --set '{item}' (expected key=value).")
            continue
        k, _, v = item.partition("=")
        overrides[k.strip()] = v.strip()

    interactive = not overrides and not getattr(args, "non_interactive", False)
    answers = {}
    for key, prompt in INIT_QUESTIONS:
        if key in overrides:
            answers[key] = overrides[key]
        elif interactive:
            try:
                current = profile.get(key, "")
                shown = f" [{current}]" if current and not str(current).startswith("TBD") else ""
                resp = input(f"{prompt}{shown} ").strip()
            except EOFError:
                resp = ""
            if resp:
                answers[key] = resp
        # non-interactive with no override for this key: leave the profile as-is.

    # Validate/normalize the certification class if it was answered.
    if "certification_class" in answers:
        cls = answers["certification_class"].strip().lower()
        if cls not in ("a", "b", "c"):
            out(f"'{cls}' is not a valid certification class (a|b|c). Aborting; "
                "nothing was written.")
            return 1
        answers["certification_class"] = cls.upper() if False else cls

    if not answers:
        out("No values provided; the offering profile is unchanged.")
        return 0

    profile.update(answers)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(profile, f, indent=1)
        f.write("\n")
    out(f"Wrote {len(answers)} field(s) to {os.path.relpath(path, BASE)}: "
        f"{', '.join(sorted(answers))}.")
    out("Next: `python sdr.py build` then `python sdr.py application-preflight` "
        "to see what still blocks submission.")
    return 0


def cmd_build(args):
    if not check_dependencies():
        return 2
    total = len(BUILD_STEPS)
    out(f"Building the Class {current_class()} Security Decision Record.")
    for i, (script, description) in enumerate(BUILD_STEPS, start=1):
        step_header(i, total, f"{script}: {description}")
        # Most steps live in validation/scripts; an entry containing a path
        # separator (e.g. automation/exporters/oscal_export.py) is resolved
        # against the repo root instead.
        script_path = (os.path.join(BASE, script) if ("/" in script or os.sep in script)
                       else os.path.join(SCRIPTS, script))
        code = run(script_path)
        if code != 0:
            out()
            out("Build stopped. Later steps read what this one writes, so "
                "continuing would build against stale inputs.")
            return 1
    out()
    out(f"Build complete. {total} steps, 0 failures.")
    return 0


def cmd_validate(args):
    if not check_dependencies():
        return 2
    out(f"Validating the Class {current_class()} record.")
    out(RULE)
    failures = []

    for rel, label in VALIDATION_GATE:
        code = run(os.path.join(BASE, rel), label=label)
        if code != 0:
            failures.append(rel)

    # AUD-F23: the committed repository ships Class A, B and C artifacts, so the
    # authoritative validator must hold for EVERY supported class, not only the
    # one the offering profile selects. Run validate_sdr.py against each inactive
    # class via SDR_VALIDATE_CLASS (reports go to the gitignored matrix dir).
    out()
    out("Class matrix (A/B/C validated independently)")
    out(RULE)
    active = (current_class() or "b").lower()
    for cls in ("a", "b", "c"):
        if cls == active:
            continue
        env = dict(os.environ, SDR_VALIDATE_CLASS=cls)
        started = time.monotonic()
        proc = subprocess.run([sys.executable,
                               os.path.join(BASE, "validation", "scripts", "validate_sdr.py")],
                              cwd=BASE, env=env, capture_output=True, text=True)
        elapsed = time.monotonic() - started
        tail = [ln for ln in (proc.stdout or "").splitlines() if ln.startswith("FAIL:")]
        if proc.returncode == 0:
            out(f"OK. validate_sdr.py class {cls.upper()} ({elapsed:.1f}s)")
        else:
            out(f"FAIL. validate_sdr.py class {cls.upper()} exited {proc.returncode} ({elapsed:.1f}s)")
            for ln in tail[:6]:
                out("    " + ln)
            failures.append(f"validation/scripts/validate_sdr.py (class {cls.upper()})")

    run_tests = not getattr(args, "no_tests", False)
    if run_tests:
        out()
        out("Offline test suite")
        out(RULE)
        for rel in TEST_SUITE:
            code = run(os.path.join(BASE, rel), label=os.path.basename(rel))
            if code != 0:
                failures.append(rel)
        # Some adversarial tests deliberately tamper a generated artifact and
        # run the validator, which overwrites validation-report.json with a
        # FAILED report before restoring the artifact. Re-run the SDR validator
        # once more so the canonical report on disk always reflects the real,
        # restored tree, never a leftover tampered-run report.
        out()
        out("Restoring canonical validation report (post-adversarial)")
        out(RULE)
        code = run(os.path.join(BASE, "validation/scripts/validate_sdr.py"),
                   label="validate_sdr.py (canonical restore)")
        if code != 0:
            failures.append("validation/scripts/validate_sdr.py (canonical restore)")

    out()
    if failures:
        out(f"The gate failed: {len(failures)} check(s) did not pass.")
        for rel in failures:
            out(f"    - {rel}")
        out("Nothing ships until every gate and test passes. Fix the cause in "
            "sdr/records/records-store.json, then rebuild. Never edit a "
            "generated file to make a check pass; content_fidelity_against_dataset "
            "exists to catch exactly that.")
        return 1
    scope = "gate + full offline test suite" if run_tests else "gate only"
    out(f"All validation passed ({scope}). This is the validation-suite gate "
        "CI runs via `python sdr.py validate`. CI additionally enforces "
        "regenerate-and-diff, a double-build reproducibility gate, and the "
        "scanner-catalog freshness check outside this command, so a clean local "
        "run means the validation suite would pass, not that every CI gate would.")
    return 0


def cmd_scan(args):
    out(f"Scanning assessment readiness for Class {current_class()}.")
    out(RULE)
    # Exit code 3 means the scanner found open findings. On an unfinished
    # record that is the expected state, not an error, so it is suppressed
    # here. Continuous integration suppresses it the same way.
    scan_args = [
        "--output-formats", "json,csv,html,txt",
        "--no-colour",
        "--ignore-exit-code-3",
    ]
    if args.only_fails:
        scan_args.append("--only-fails")
    code = run(SDRSCAN, scan_args, label="sdrscan.py")
    if code == 0:
        out(f"Reports written to {os.path.relpath(os.path.dirname(SCAN_REPORT_GLOB), BASE)}")
    return code


def cmd_explain(args):
    """Print a grounded, plain-language explanation of one rule or KSI."""
    explain_path = os.path.join(SCRIPTS, "explain.py")
    return run(explain_path, [args.identifier], label="explain.py")


def cmd_diff(args):
    """Show what a dataset change would affect, without editing anything.

    Give two dataset files to compare (an old and a new CR26 release); this runs
    the same dataset-diff and change-impact scripts the drift-check workflow
    runs, so a local `diff` and the daily automation agree. With no arguments it
    reports the last recorded change-impact artifact, if one exists.
    """
    code = 0
    old, new = getattr(args, "old", None), getattr(args, "new", None)
    if old and new:
        dd = os.path.join(SCRIPTS, "dataset_diff.py")
        ci = os.path.join(SCRIPTS, "change_impact.py")
        diff_out = os.path.join(BASE, "traceability", "dataset-diff.json")
        code = run(dd, [old, new, "--json", diff_out], label="dataset_diff.py")
        if code == 0:
            code = run(ci, ["--diff", diff_out,
                            "--json", os.path.join(BASE, "traceability", "change-impact.json")],
                       label="change_impact.py")
    elif old or new:
        out("Provide both an old and a new dataset file, or neither.")
        return 2

    impact = load_json(os.path.join(BASE, "traceability", "change-impact.json"))
    if impact:
        s = impact.get("source_summary", {})
        out()
        out("Change impact summary")
        out(RULE)
        out(f"Rules added      {s.get('added', 0)}")
        out(f"Rules removed    {s.get('removed', 0)}")
        out(f"Rules changed    {s.get('changed', 0)}")
        out(f"Requiring human review   {impact.get('total_requiring_review', 0)}")
        for rid in impact.get("rules_requiring_review", [])[:20]:
            out(f"    - {rid}")
        out()
        out("A dataset change never auto-changes a status or an approval. It "
            "flags what a human must re-examine.")
    else:
        out("No change-impact record found. Pass two dataset files to compare, "
            "e.g. `python sdr.py diff old.json new.json`, or let the daily "
            "drift-check workflow produce one.")
    return code


def cmd_review(args):
    """Report the human review register (read-only, the default), or walk the
    pending field proposals (--list / --walk / --decisions / --accept-all).

    The register report never authors an approval. The proposal walk writes a
    field only on a NAMED human's accept or edit decision, strips the DRAFT /
    Example label, and records the decision bound to the written value's hash
    in sdr/reviews/field-review-log.json (automation/review/review_proposals.py).
    It never writes implementation_status or assessment.
    """
    if any(getattr(args, f, None) for f in ("list", "walk", "decisions", "accept_all",
                                            "source", "only")):
        sys.path.insert(0, os.path.join(BASE, "automation", "review"))
        import review_proposals  # noqa: E402
        return review_proposals.run(args, out=out)
    register = load_json(os.path.join(BASE, "sdr", "reviews", "review-register.json"))
    out()
    out("Human review register")
    out(RULE)
    if not register:
        out("No review register found.")
        return 0
    reviews = register.get("reviews", [])
    field_log = load_json(os.path.join(BASE, "sdr", "reviews", "field-review-log.json")) or {}
    field_reviews = field_log.get("reviews", []) if isinstance(field_log, dict) else []
    if not reviews:
        out("Register present, no reviews recorded yet. Nothing is approved.")
        out()
        out("A reviewer records signoff in sdr/reviews/review-register.json. "
            "The pipeline cannot and will not do this.")
        if field_reviews:
            out(f"Field-level decisions recorded     {len(field_reviews)} "
                "(sdr/reviews/field-review-log.json; not approvals)")
        out("Pending proposals: python sdr.py review --list")
        return 0
    approved = [r for r in reviews if r.get("decision") == "approved"]
    other = [r for r in reviews if r.get("decision") != "approved"]
    out(f"Recorded reviews             {len(reviews)}")
    out(f"Approved                     {len(approved)}")
    out(f"Pending / other              {len(other)}")
    for r in other[:20]:
        out(f"    - {r.get('scope', '?')}: {r.get('decision', 'pending')} "
            f"(reviewer {r.get('reviewer', 'TBD')})")
    out()
    out("Approval is a human act. A green build proves the package is "
        "well-formed, not that it is approved or compliant.")
    return 0


def cmd_reproducibility():
    """Verify the build is reproducible: hash the deterministic artifacts,
    rebuild, and confirm they are byte-identical. Mirrors the CI reproducibility
    gate so `release` verifies reproducibility rather than merely asserting it.
    Returns 0 if reproducible, 1 otherwise. Includes *.docx: the Word document
    is byte-reproducible since AUD-F35 (fixed zip entry timestamps, dataset-
    derived core properties), so it is held to the same standard."""
    import hashlib

    watch_dirs = ["sdr", "package", "traceability", "artifacts", "validation/reports"]
    exts = (".json", ".txt", ".md", ".csv", ".docx")

    def fingerprint():
        digests = {}
        for d in watch_dirs:
            root = os.path.join(BASE, d)
            for dirpath, _dirs, files in os.walk(root):
                for fn in files:
                    if fn.endswith(exts):
                        p = os.path.join(dirpath, fn)
                        h = hashlib.sha256()
                        with open(p, "rb") as f:
                            for chunk in iter(lambda: f.read(65536), b""):
                                h.update(chunk)
                        digests[os.path.relpath(p, BASE)] = h.hexdigest()
        return digests

    out("Reproducibility check (double build, byte comparison)")
    out(RULE)
    first = fingerprint()
    code = cmd_build(argparse.Namespace(only_fails=False, no_tests=True))
    if code != 0:
        out("FAIL. Rebuild failed during reproducibility check.")
        return 1
    second = fingerprint()
    changed = sorted(k for k in set(first) | set(second) if first.get(k) != second.get(k))
    if changed:
        out(f"FAIL. {len(changed)} deterministic artifact(s) changed across two builds:")
        for k in changed[:20]:
            out(f"    - {k}")
        return 1
    out(f"Reproducible: {len(second)} deterministic artifacts byte-identical across two builds.")
    return 0


def cmd_release(args):
    """Produce and report a release: build, run the FULL validation gate and
    test suite, run the audit and security sections of the ONE release gate,
    verify reproducibility, hard-run package-preflight, then print the tag.

    Runs the same validation suite CI runs (via cmd_validate) AND the identical
    audit/security step list CI and the AWS RELEASE_MODE build run
    (audit/release_gate.py: oracle, mutation-runner self-test, mutation runner,
    tree-clean, Bandit) AND a local double-build reproducibility check AND
    package-preflight as a HARD gate, so `release` verifies what it claims and
    refuses to prepare a release for a package any of those would reject. Before
    AUD-F12 this command skipped the audit gate and Bandit, so a local release
    could pass while CI's audit-gate was red (v1.4.0 shipped that way). Always
    runs the full test suite (no --no-tests escape). Does not tag git or publish
    anything.
    """
    # A release is not allowed to skip its own tests.
    args.no_tests = False
    code = cmd_build(args)
    if code != 0:
        out("Build failed; not a releasable state.")
        return code
    out()
    code = cmd_validate(args)
    if code != 0:
        out("Validation gate failed; not releasable.")
        return code
    # AUD-F12: the audit and security sections of the ONE release gate, from
    # the same definition CI and the AWS RELEASE_MODE build execute. Run before
    # the reproducibility check so a mutation the runner failed to restore is
    # caught by the gate's own tree-clean step rather than confusing the
    # double-build comparison.
    out()
    code = run(os.path.join(BASE, "audit", "release_gate.py"), ["audit", "security"])
    if code != 0:
        out("Release gate (audit/security sections) failed; not releasable.")
        return code
    out()
    code = cmd_reproducibility()
    if code != 0:
        out("Reproducibility check failed; not releasable.")
        return code
    # A release deliverable must not just be well-formed and reproducible: it
    # must be submission-ready. Hard-run package-preflight and FAIL CLOSED on any
    # blocker, exactly as the deployed CodePipeline does under RELEASE_MODE=true.
    # Without this, `release` could return success and tell an operator how to
    # tag a package that package-preflight would reject. This is the local
    # counterpart of the pipeline's RELEASE_MODE hard gate.
    out()
    code = cmd_preflight(args)
    if code != 0:
        out("Package preflight reported submission blockers; not releasable. "
            "Resolve the blockers above before tagging.")
        return code
    # Reproducibility passed on the deterministic manifest. Do NOT mutate that
    # manifest to add source provenance: it is what the human signoff binds to
    # (package-preflight checks package_manifest_sha256 against it), so changing
    # its bytes here would silently invalidate a prior signoff. Instead emit a
    # SEPARATE release-attestation that binds this manifest's hash to the exact
    # git commit/tree. Ordering: build -> validate -> reproducibility -> human
    # signoff (binds the manifest) -> package-preflight (hard; verifies that
    # signoff) -> attestation -> tag. The signoff therefore already exists by
    # the time this attestation runs; preflight would have blocked otherwise.
    rc = run(os.path.join(SCRIPTS, "build_release_attestation.py"))
    if rc != 0:
        out("Could not write the release attestation (missing git provenance "
            "or no manifest). Release preparation is NOT complete.")
        return rc
    manifest = load_json(os.path.join(BASE, "artifacts", "release-manifest.json"))
    attestation = load_json(os.path.join(BASE, "artifacts", "release-attestation.json"))
    out()
    out("Release")
    out(RULE)
    if manifest:
        out(f"Release tag                  {manifest.get('release_tag', '?')}")
        out(f"Framework version            {manifest.get('framework_version', '?')}")
        out(f"Dataset version              {manifest.get('dataset_version', '?')}")
        out(f"Artifacts fingerprinted      {manifest.get('artifact_count', '?')}")
    if attestation:
        out(f"Source commit                {attestation.get('source_commit') or '(not recorded)'}")
        out(f"Manifest hash (attested)     {attestation.get('release_manifest_sha256', '?')}")
    out()
    out("The release attestation binds the deterministic manifest hash to the "
        "git source WITHOUT changing the manifest, so the human signoff bound "
        "to that manifest stays valid. Package-preflight has already verified "
        "an approved package signoff against this exact manifest, and build, "
        "validation, and reproducibility all passed against it. The remaining "
        "step is to tag the release.")
    out()
    out("This is a build-provenance record, not a compliance determination. A "
        "passing release gate means well-formed, consistent, and verified "
        "reproducible (double-build byte-identical, checked just now); "
        "certification is an accredited assessor and authorizing-body decision.")
    tag = manifest.get('release_tag', '<tag>') if manifest else '<tag>'
    # docs/versioning.md requires a SIGNED release tag; a plain `git tag` here
    # (the pre-AUD-F12 instruction) contradicted that policy, and v1.4.0 shipped
    # unsigned. The release workflow refuses to publish from an unsigned tag.
    out(f"To tag (signed, per docs/versioning.md): "
        f"git tag -s {tag} -m \"FedRAMP 20x SDR framework {tag}\"")
    out(f"Then: git push origin {tag}  -- the release workflow re-runs the full "
        "gate on the tag and attaches manifest, attestation, and SBOM as release "
        "assets.")
    return 0


def cmd_preflight(args):
    """FedRAMP submission preflight: check for submission BLOCKERS.
    Structural validity (the build gate) is necessary but not sufficient to
    submit. FedRAMP requires the initial package to represent the current
    offering and be freshly provider-verified. This reports blockers; it never
    says "compliant" and never changes a status. Grounded in the pinned dataset:
      FRC-APP-FCP (MUST): fresh initial package verified/validated by the
        provider within the previous 7 days.
      FRC-CLA-ASF / FRC-CLA-EAM (MUST, Class A): alternative-framework
        assessment within the past 12 months, and External Assessment Materials
        supplied.
    """
    import datetime as _dt
    offering = load_json(OFFERING_PROFILE) or {}
    cls = current_class().lower()
    blockers = []
    warnings = []
    # Loaded once, early, because both the MOT gate and the applicable-record
    # scan need them.
    class_profile = load_json(os.path.join(BASE, "profiles", f"class-{cls}", "profile.json")) or {}
    ksi_profile = load_json(os.path.join(BASE, "profiles", "common", "ksi-profile.json")) or {}

    # A package cannot be "submission ready" if it does not even pass the
    # validation gate (schema, semantic completeness, evidence integrity, review
    # integrity, assurance graph, package consistency). Run the gate-only path
    # (validators, no tests) as a hard precondition.
    out("Preflight precondition: running the validation gate...")
    if _validation_gate_only() != 0:
        blockers.append("the validation gate does not pass (schema/semantic/"
                        "evidence/review/consistency); submission is impossible "
                        "until `python sdr.py validate` is clean")

    def _is_tbd(v):
        # AUD-F38: a labelled DRAFT / Example proposal is not the provider's
        # answer until a named human accepts it (sdr.py review strips the label).
        return v is None or str(v).strip() == "" or str(v).strip().startswith("TBD") \
            or "placeholder" in str(v).lower() or "has not been provided" in str(v).lower() \
            or _is_unreviewed(v)

    def _is_hollow(v):
        """A content VALUE is hollow if it is TBD/empty/placeholder (per _is_tbd)
        OR a bare non-answer token with no justification (e.g. 'N/A', 'none',
        '.', 'unknown', 'tbc'). Presence of a required field is not enough: a
        structurally complete but content-free answer must not satisfy a MUST.
        A justified N/A ('N/A: <reason>') is NOT hollow - FedRAMP allows a
        justified non-implementation. Used for CPO member values and required
        narrative summaries, where the weaker _is_tbd would accept a non-answer."""
        if _is_tbd(v):
            return True
        s = str(v).strip()
        low = s.lower()
        BARE = {"n/a", "na", "none", "nil", "null", "unknown", "tbc", "?",
                ".", "-", "--", "...", "x", "see documentation", "see docs",
                "not applicable", "not-applicable"}
        if low in BARE:
            return True
        # A "N/A - <reason>" style value is only real if it carries a reason.
        for m in ("n/a", "na", "not applicable", "not-applicable", "none"):
            if low.startswith(m):
                rest = s[len(m):].lstrip(" :.-\u2013\u2014").strip()
                return len(rest) < 3
        return False

    def _is_missing_required_identity(v):
        """Stricter than _is_hollow, for MANDATORY identity / reference / contact
        fields that MUST name a real entity (the FedRAMP Recognized assessor and
        its Recognition id, a freshening reviewer and id, the Sales and Security
        contacts, the CPO responsible official). For these a MUST cannot be
        satisfied by a non-applicability at all: a JUSTIFIED 'N/A: <reason>' is
        still missing, because the requirement is to identify the entity, not to
        explain why one is absent. So ANY N/A / not-applicable / none form is
        missing here, unlike _is_hollow which permits a justified N/A for
        narrative content."""
        if _is_tbd(v):
            return True
        low = str(v).strip().lower()
        if low in {"n/a", "na", "none", "nil", "null", "unknown", "tbc", "?",
                   ".", "-", "--", "...", "x", "see documentation", "see docs",
                   "not applicable", "not-applicable"}:
            return True
        for m in ("n/a", "na", "not applicable", "not-applicable", "none"):
            if low.startswith(m):
                return True
        return False

    def _parse_dt(value):
        """Return (datetime, error). Requires timezone-aware; rejects future."""
        s = str(value).replace("Z", "+00:00")
        try:
            dt = _dt.datetime.fromisoformat(s)
        except ValueError:
            return None, "not a valid ISO datetime"
        if dt.tzinfo is None:
            return None, "must be timezone-aware (include an offset or Z)"
        if dt > _dt.datetime.now(_dt.timezone.utc):
            return None, "is in the future"
        return dt, None

    def _months_before(ref, n):
        """The date exactly n CALENDAR months before ref (a date).

        FedRAMP freshness windows are stated in calendar months ("within the
        previous 3 months", "more than 9 months old", "within the past 12
        months", "at least the past 6/18 months"), NOT in fixed day counts. A
        fixed-day approximation is wrong at the boundary: 2026-06-16 to
        2026-09-16 is exactly 3 calendar months but 92 days, so a days=91 cutoff
        would falsely flag a still-fresh assessment as stale. This subtracts
        real calendar months, clamping the day to the target month's last day
        (e.g. 3 months before May 31 is Feb 28/29). The 7-day FRC-APP-FCP rule
        stays in days because the dataset states it in days.
        """
        y = ref.year + (ref.month - 1 - n) // 12
        m = (ref.month - 1 - n) % 12 + 1
        # Last valid day of the target month (handles 31->30/28/29).
        if m == 12:
            last = 31
        else:
            last = (_dt.date(y, m + 1, 1) - _dt.timedelta(days=1)).day
        return _dt.date(y, m, min(ref.day, last))

    # Required offering-profile fields. Everything not on the optional allowlist
    # that is still a TBD is a submission blocker, not a warning.
    OPTIONAL_FIELDS = {
        "profile_note", "evidence_sources", "external_assessment",
        "provider_verified_at", "dr_region", "iac_technology",
        "materials_item_schema", "note",
        "selected_optional_rules", "_selected_optional_rules_note",
        "evidence_freshness_policy_days", "expected_evidence_signer",
        # AUD-F17: offering may TIGHTEN the telemetry evaluated-coverage floor.
        "telemetry_min_coverage",
        # AUD-F21: assessor-reviewable FRC-CSX-MOT continuity tolerance (days).
        "mot_max_gap_days",
        # AUD-F37: "development" (default) or "production-assurance"; the latter
        # makes an unattested, unchained or unsigned metric history a blocker.
        "evidence_store_profile",
    }
    REQUIRED_FIELDS = [
        "organization_name", "offering_name", "offering_abbreviation",
        "business_purpose", "service_model", "deployment_model",
        "certification_type", "certification_class", "aws_partition",
        "primary_region", "management_plane", "federal_information_types",
        "certification_package_overview_uri", "security_contact",
        "incident_contact", "assessor", "evidence_retention",
    ]
    # A required field answered with a bare non-answer (N/A, none, '.') is not
    # a real answer any more than a TBD is. Narrative required fields may carry a
    # justified 'N/A: <reason>' (so _is_hollow), but identity / contact / URI
    # required fields MUST name a real entity or location, where even a justified
    # N/A is missing (so the stricter _is_missing_required_identity).
    IDENTITY_REQUIRED = {"security_contact", "incident_contact", "assessor",
                         "certification_package_overview_uri"}
    unresolved_required = [
        f for f in REQUIRED_FIELDS
        if (_is_missing_required_identity(offering.get(f)) if f in IDENTITY_REQUIRED
            else _is_hollow(offering.get(f)))
    ]
    if unresolved_required:
        blockers.append(f"{len(unresolved_required)} required offering-profile "
                        f"field(s) unresolved (TBD/placeholder): "
                        f"{', '.join(unresolved_required)}")

    # The engine resolves 20x + Program only. If the profile claims a different
    # path, the generated package would silently be the wrong applicability
    # scope, so block rather than proceed.
    cpath = str(offering.get("certification_path", "Program"))
    if cpath != "Program":
        blockers.append(f"certification_path is '{cpath}', but this framework "
                        "resolves 20x Program-path requirements only; Agency path "
                        "is not supported. Set certification_path to 'Program' or "
                        "do not rely on this package for an Agency-path application.")

    # FRC-APP-FCP: provider verification freshness (7 days, real timedelta).
    verified = offering.get("provider_verified_at")
    if _is_tbd(verified):
        blockers.append("provider_verified_at is not set (FRC-APP-FCP requires "
                        "verification/validation within the previous 7 days)")
    else:
        dt, err = _parse_dt(verified)
        if err:
            blockers.append(f"provider_verified_at {err}: {verified}")
        elif (_dt.datetime.now(_dt.timezone.utc) - dt) > _dt.timedelta(days=7):
            blockers.append("provider_verified_at is older than 7 days "
                            "(FRC-APP-FCP requires within the previous 7 days)")

    # Class A: external assessment materials (FRC-CLA-ASF / EAM).
    if cls == "a":
        ext = offering.get("external_assessment") or {}
        # FRC-CLA-ASF permits ONLY these alternative frameworks; FRC-CLA-EAM
        # enumerates required materials. Both are defined once at module level
        # (CLA_FRAMEWORK_ALIASES / CLA_REQUIRED_MATERIALS) so preflight and the
        # tests share a single source of truth. See those definitions for the
        # verbatim-from-dataset rationale (SOC 2 Type II specificity; Rev5 vs
        # Ready split).
        FRAMEWORK_ALIASES = CLA_FRAMEWORK_ALIASES
        REQUIRED_MATERIALS = CLA_REQUIRED_MATERIALS
        raw_fw = ext.get("framework")
        if not ext or _is_tbd(raw_fw) or _is_tbd(ext.get("assessment_date")):
            blockers.append("Class A: external_assessment not populated "
                            "(FRC-CLA-ASF/EAM require alternative-framework "
                            "assessment materials from the past 12 months)")
        else:
            canon = FRAMEWORK_ALIASES.get(str(raw_fw).strip().lower())
            if canon is None:
                blockers.append(f"Class A: external_assessment.framework '{raw_fw}' is "
                                "not a FedRAMP-approved alternative framework "
                                "(FRC-CLA-ASF permits only FedRAMP Rev5 including "
                                "FedRAMP Ready, SOC 2 Type II, or GovRAMP; note SOC 2 "
                                "must be Type II specifically - a bare 'SOC 2' or "
                                "SOC 2 Type I is not eligible)")
            adate = ext.get("assessment_date")
            try:
                when = _dt.date.fromisoformat(str(adate))
                if when > _utc_today():
                    blockers.append(f"Class A: assessment_date is in the future: {adate}")
                elif when < _months_before(_utc_today(), 12):
                    blockers.append(f"Class A: external assessment {adate} is "
                                    f"older than 12 months (FRC-CLA-ASF)")
            except ValueError:
                blockers.append(f"Class A: assessment_date not a valid date: {adate}")
            materials = ext.get("materials") or []
            # Every supplied material must be a complete reference.
            for i, m in enumerate(materials):
                if not isinstance(m, dict) or _is_missing_required_identity(m.get("type")) \
                        or _is_missing_required_identity(m.get("uri")) or _is_missing_required_identity(m.get("sha256")):
                    blockers.append(f"Class A: materials[{i}] missing "
                                    f"type/uri/sha256 (FRC-CLA-EAM)")
            # The framework-specific required set (FRC-CLA-EAM) must all be present.
            if canon is not None:
                have_types = {str(m.get("type", "")).strip().lower()
                              for m in materials if isinstance(m, dict)}
                for key, label in REQUIRED_MATERIALS.get(canon, []):
                    if key not in have_types:
                        blockers.append(f"Class A: external_assessment is missing the "
                                        f"required '{label}' material for {canon} "
                                        f"(material type '{key}'; FRC-CLA-EAM)")
                # FedRAMP Rev5 (full authorization) has no fixed EAM type list,
                # but EAM still requires supplying assessment materials ("any
                # other materials required by FedRAMP"). Require at least one
                # complete material so a Rev5 declaration cannot pass empty.
                if canon == "fedramp_rev5" and not have_types:
                    blockers.append("Class A: FedRAMP Rev5 external_assessment "
                                    "supplies no materials; FRC-CLA-EAM requires "
                                    "supplying the assessment materials (at least "
                                    "one complete material with type/uri/sha256)")

    # FRC-APP-FIA: a fresh FedRAMP independent assessment within 3 months.
    # Class B and C MUST. Class A MAY (optional) - so it is NOT gated for A
    # UNLESS the provider opts in via selected_optional_rules, in which case
    # FedRAMP reviews it fully (a selected Class A MAY rule gets the same
    # substantive review as a mandatory one). FRC-APP-USA allows freshening a
    # stale assessment unless it is more than 9 months old.
    _fia_selected_a = (cls == "a"
                       and "FRC-APP-FIA" in set(offering.get("selected_optional_rules") or []))
    fia_applies = cls in ("b", "c") or _fia_selected_a
    if fia_applies:
        # Force wording: MUST for B/C; for a selected Class A optional it is a
        # provider-opted-in MAY that is fully reviewed once included.
        _fia_force = "MUST" if cls in ("b", "c") else "MAY (opted in via selected_optional_rules; fully reviewed once included)"
        fia = offering.get("fedramp_independent_assessment") or {}
        completed = fia.get("completed_at")
        if _is_missing_required_identity(fia.get("assessor_name")) or _is_tbd(completed):
            blockers.append(f"Class {cls.upper()}: fedramp_independent_assessment "
                            f"not populated (FRC-APP-FIA {_fia_force}: a fresh FedRAMP "
                            "independent assessment by a FedRAMP Recognized service "
                            "within the previous 3 months)")
        elif _is_missing_required_identity(fia.get("assessor_fedramp_id")):
            # FRC-APP-FIA requires the assessment be completed by a FedRAMP
            # Recognized independent assessment service - the recognition id is
            # what evidences "Recognized". A name alone is insufficient.
            blockers.append(f"Class {cls.upper()}: fedramp_independent_assessment "
                            "has no assessor_fedramp_id (FRC-APP-FIA MUST be completed "
                            "by a FedRAMP Recognized independent assessment service; "
                            "record its FedRAMP Recognition id)")
        else:
            try:
                when = _dt.date.fromisoformat(str(completed))
                if when > _utc_today():
                    blockers.append(f"Class {cls.upper()}: FIA completed_at is in the future: {completed}")
                else:
                    today = _utc_today()
                    if when < _months_before(today, 9):  # older than 9 calendar months
                        blockers.append(f"Class {cls.upper()}: FedRAMP independent assessment "
                                        f"{completed} is older than 9 months; FRC-APP-USA "
                                        "freshening no longer applies - a new assessment is required")
                    elif when < _months_before(today, 3):  # older than 3 calendar months
                        fr = fia.get("freshening") or {}
                        basis = str(fia.get("freshness_basis", ""))
                        # FRC-APP-USA: the freshening MUST be performed by a
                        # FedRAMP Recognized independent assessment service, so a
                        # recognition id is required (not just a reviewer name),
                        # and the review date must be a real, non-future date.
                        reviewed_at = fr.get("reviewed_at")
                        review_date_ok = False
                        if not _is_tbd(reviewed_at):
                            try:
                                rd = _dt.date.fromisoformat(str(reviewed_at))
                                # Valid, not in the future, and not before the
                                # original assessment it claims to freshen.
                                review_date_ok = (rd <= _utc_today() and rd >= when)
                            except ValueError:
                                review_date_ok = False
                        fresh_ok = (basis == "freshened"
                                    and review_date_ok
                                    and not _is_missing_required_identity(fr.get("reviewed_by"))
                                    and not _is_missing_required_identity(fr.get("reviewer_fedramp_id"))
                                    and not _is_missing_required_identity(fr.get("changes_reviewed_reference")))
                        if not fresh_ok:
                            blockers.append(f"Class {cls.upper()}: FedRAMP independent assessment "
                                            f"{completed} is older than 3 months and has no valid "
                                            "FRC-APP-USA freshening review recorded (a Recognized "
                                            "service review: freshening with a valid reviewed_at "
                                            "date, reviewed_by, reviewer_fedramp_id, and "
                                            "changes_reviewed_reference)")
            except ValueError:
                blockers.append(f"Class {cls.upper()}: FIA completed_at not a valid date: {completed}")

    # CPO-CSO-OSA: B/C MUST include the assessor overall summary in the CPO.
    # A distinct rule from FRC-APP-FIA. It is MUST at B/C, and it is also
    # required when a Class A offering SELECTS optional IV&V (IVV-CSO-FIA):
    # FedRAMP's Class A package guidance is that when optional IV&V is used,
    # the package includes the Assessment Summary in the SDR and the Overall
    # Summary of Assessment in the CPO (finding 6). A selected Class A MAY rule
    # is fully reviewed, so its CPO summary obligation is not skipped. Evaluated
    # OUTSIDE the FIA block so it fires for a Class A offering that selects
    # IVV-CSO-FIA without also opting into FRC-APP-FIA.
    _ivv_selected_a = (cls == "a"
                       and "IVV-CSO-FIA" in set(offering.get("selected_optional_rules") or []))
    osa_required = cls in ("b", "c") or _ivv_selected_a
    if osa_required and _is_hollow(offering.get("overall_assessment_summary")):
        _osa_ctx = ("CPO-CSO-OSA MUST" if cls in ("b", "c")
                    else "optional IVV-CSO-FIA is selected, so the CPO overall "
                         "assessment summary is required and fully reviewed")
        blockers.append(f"Class {cls.upper()}: overall_assessment_summary not set "
                        f"({_osa_ctx}: include the assessor's overall assessment "
                        "summary from IVV-IAS-OSA in the CPO)")

    # Finding 6: a SELECTED Class A IVV-CSO-FIA is fully reviewed, so the rule's
    # OWN substance must be proven, not just the CPO overall summary. IVV-CSO-FIA:
    # the optional Class A assessment is performed by a FedRAMP Recognized
    # independent assessment service (or FedRAMP) at least once per year. Require
    # a Recognized assessor identity (name + recognition id), a real
    # completion date, and completion within the past year (the annual cadence,
    # not FRC-APP-FIA's 3-month window). Evaluated only when IVV-CSO-FIA is
    # selected at Class A (the FIA block above covers B/C and selected FRC-APP-FIA).
    if _ivv_selected_a:
        ivv = offering.get("fedramp_independent_assessment") or {}
        ivv_completed = ivv.get("completed_at")
        if _is_missing_required_identity(ivv.get("assessor_name")) or _is_tbd(ivv_completed):
            blockers.append("Class A: selected IVV-CSO-FIA requires a FedRAMP "
                            "Recognized independent assessment (fedramp_independent_"
                            "assessment.assessor_name + completed_at) performed at "
                            "least once per year")
        elif _is_missing_required_identity(ivv.get("assessor_fedramp_id")):
            blockers.append("Class A: selected IVV-CSO-FIA assessment has no "
                            "assessor_fedramp_id (IVV-CSO-FIA MUST be performed by a "
                            "FedRAMP Recognized independent assessment service or "
                            "FedRAMP; record its FedRAMP Recognition id)")
        else:
            try:
                _iv_when = _dt.date.fromisoformat(str(ivv_completed))
                if _iv_when > _utc_today():
                    blockers.append(f"Class A: selected IVV-CSO-FIA completed_at is "
                                    f"in the future: {ivv_completed}")
                elif _iv_when < _months_before(_utc_today(), 12):
                    blockers.append(f"Class A: selected IVV-CSO-FIA assessment "
                                    f"{ivv_completed} is older than 12 months; "
                                    "IVV-CSO-FIA requires an assessment at least once "
                                    "per year")
            except ValueError:
                blockers.append("Class A: selected IVV-CSO-FIA completed_at is not a "
                                f"valid date: {ivv_completed}")
        # Finding 7: when optional IV&V is used, the Class A package includes the
        # Assessment Summary IN THE SDR (IVV-IAS-OSA). Require the summary URI.
        if _is_hollow(ivv.get("assessment_summary_uri")):
            blockers.append("Class A: selected IVV-CSO-FIA requires the IV&V "
                            "Assessment Summary in the SDR (fedramp_independent_"
                            "assessment.assessment_summary_uri; IVV-IAS-OSA)")

    # CDS-CSO-AVR: availability reporting web service. Class B/C MUST, A SHOULD.
    avr = offering.get("availability_reporting") or {}
    avr_missing = (_is_tbd(avr.get("human_readable_uri")) or _is_tbd(avr.get("machine_readable_uri")))
    if cls in ("b", "c"):
        if avr_missing:
            blockers.append(f"Class {cls.upper()}: availability_reporting requires BOTH a "
                            "human_readable_uri AND a machine_readable_uri (CDS-CSO-AVR MUST)")
        else:
            hist = avr.get("history_days")
            if isinstance(hist, int) and hist < 30 or (isinstance(hist, str) and hist.isdigit() and int(hist) < 30):
                blockers.append(f"Class {cls.upper()}: availability history is < 30 days (CDS-CSO-AVR)")
            elif _is_tbd(hist):
                blockers.append(f"Class {cls.upper()}: availability_reporting.history_days not set (CDS-CSO-AVR: >= 30)")
            if avr.get("available_when_primary_unavailable") is not True:
                blockers.append(f"Class {cls.upper()}: the availability service MUST remain "
                                "available when the primary offering is down (CDS-CSO-AVR); "
                                "set available_when_primary_unavailable=true (human-verified)")
    elif cls == "a" and avr_missing:
        warnings.append("Class A: availability_reporting is a SHOULD (CDS-CSO-AVR); not set")

    # FRC-CSX-MOT: historical KSI metrics from persistent validation. Class C
    # MUST have >= 6 months for all KSIs; Class D >= 18 months; A/B advisory.
    # Distinct from SDR-CSX-KMT formatting; this is a duration requirement.
    mot_min_months = {"c": 6, "d": 18}.get(cls)
    if mot_min_months:
        import datetime as _d2
        today = _utc_today()
        mot_cutoff = _months_before(today, mot_min_months)
        # AUD-F21: the continuity tolerance in force. Project policy with a
        # bounded, assessor-reviewable offering override; an invalid declared
        # value is a blocker, never a silent fall-back to the default.
        mot_gap_days, mot_gap_source = mot_max_gap_days(offering)
        if mot_gap_days is None:
            blockers.append(f"Class {cls.upper()}: offering profile mot_max_gap_days is "
                            f"{mot_gap_source}; declare an integer 1..{MOT_MAX_GAP_DAYS_CEILING} "
                            f"or remove it to use the project default "
                            f"({MOT_MAX_GAP_DAYS_DEFAULT} days)")
            mot_gap_days, mot_gap_source = MOT_MAX_GAP_DAYS_DEFAULT, "project-default"
        # FRC-CSX-MOT applies to ALL KSIs. Class C/D resolve all 46.
        mot_ksis = {k.get("ksi_id") for k in ksi_profile.get("indicators", [])}
        # Initial-certification exception: if the service has not operated with
        # metrics long enough, the provider needs mechanisms in place and a
        # recorded commitment to meet the requirement going forward.
        exc = offering.get("metric_history_exception") or {}
        # FRC-CSX-MOT's initial-certification exception (verbatim note) applies
        # "in the event the cloud service has not been operating WITH RELATED
        # METRICS AVAILABLE for the required period." The eligibility date is
        # therefore the metrics-available period, NOT the offering launch date:
        # an offering can be years old yet only have persistent KSI metrics for
        # a couple of months. The faithful field is metrics_available_since;
        # operating_since is accepted as a backward-compatible fallback (older
        # profiles) but metrics_available_since wins when both are present.
        # The date must be a REAL ISO date, must NOT be in the future, and the
        # exception only applies when metrics have been available for LESS than
        # the required window (a service with >= the window is expected to have
        # the full history and cannot use the shortcut).
        import datetime as _dm
        _op_field = ("metrics_available_since"
                     if not _is_tbd(exc.get("metrics_available_since"))
                     else "operating_since")
        _op_raw = exc.get("metrics_available_since")
        if _is_tbd(_op_raw):
            _op_raw = exc.get("operating_since")
        _op_date = None
        if not _is_tbd(_op_raw):
            try:
                _op_date = _dm.date.fromisoformat(str(_op_raw)[:10])
            except (ValueError, TypeError):
                _op_date = None
        mot_window_start = _months_before(today, mot_min_months)
        # Eligible only when the date parses, is NOT in the future, AND is after
        # the window start (metrics available for LESS than the required window).
        _op_not_future = _op_date is not None and _op_date <= today
        exc_window_eligible = _op_not_future and _op_date > mot_window_start
        exc_valid = (exc.get("mechanisms_in_place") is True
                     and not _is_hollow(exc.get("mechanisms_description"))
                     and exc.get("commitment_to_meet_mot") is True
                     and not _is_hollow(exc.get("commitment_reference"))
                     and exc_window_eligible
                     and not _is_hollow(exc.get("responsible_official")))
        # Distinguish "exception fields present but invalid" from "no exception":
        # an invalid/future date or an over-long window should tell the provider
        # WHY the exception did not apply, not silently fall through.
        exc_attempted = (exc.get("mechanisms_in_place") is True
                         or exc.get("commitment_to_meet_mot") is True
                         or not _is_tbd(_op_raw))
        history = load_json(os.path.join(BASE, "automation", "metrics", "metric-history.json"))
        per = (history.get("ksis", history) if isinstance(history, dict) else {}) or {}
        if exc_attempted and not exc_valid:
            if not _is_tbd(_op_raw) and _op_date is None:
                blockers.append(f"Class {cls.upper()}: initial-certification MOT exception has "
                                f"an invalid {_op_field} ({_op_raw!r}); it must be a real "
                                "ISO date (YYYY-MM-DD) for the exception to apply (FRC-CSX-MOT)")
            elif _op_date is not None and not _op_not_future:
                blockers.append(f"Class {cls.upper()}: initial-certification MOT exception has a "
                                f"FUTURE {_op_field} ({_op_date}); metrics-available date cannot "
                                "be in the future (FRC-CSX-MOT)")
            elif _op_date is not None and not exc_window_eligible:
                blockers.append(f"Class {cls.upper()}: initial-certification MOT exception does "
                                f"not apply - metrics have been available since {_op_date} "
                                f"({'6' if cls == 'c' else '18'}+ months), so the full "
                                "persistent-validation history is required, not the exception "
                                "(FRC-CSX-MOT)")
        if exc_valid:
            # Exception path: require mechanisms + CURRENT validation data (a
            # RECENT datapoint per KSI, not merely any old observation), not the
            # full 6/18 months. append_metrics stores each KSI as {"series":[...]}.
            def _series(entry):
                if isinstance(entry, dict):
                    return entry.get("series") or []
                return entry if isinstance(entry, list) else []
            # "Current" = at least one observation within the continuity
            # tolerance (project policy, see mot_max_gap_days) AND not in the
            # future. A six-month-old lone datapoint is NOT current; a
            # future-dated datapoint is not a real observation and must not
            # satisfy the gate either.
            recent_cutoff = (today - _dm.timedelta(days=mot_gap_days)).isoformat()
            today_iso = today.isoformat()

            def _has_recent(entry):
                for e in _series(entry):
                    ds_ = (e or {}).get("date") if isinstance(e, dict) else None
                    if ds_ and recent_cutoff <= str(ds_)[:10] <= today_iso:
                        return True
                return False
            missing_now = [k for k in mot_ksis if not _has_recent(per.get(k))]
            if missing_now:
                blockers.append(f"Class {cls.upper()}: initial-certification MOT exception is "
                                f"recorded, but {len(missing_now)} KSI(s) have no CURRENT "
                                f"validation datapoint (within the last {mot_gap_days} days, "
                                f"the continuity tolerance from {mot_gap_source}, a project "
                                "policy rather than a FedRAMP figure); the mechanisms must be "
                                "operational and producing data now (FRC-CSX-MOT)")
        elif not history:
            blockers.append(f"Class {cls.upper()}: no KSI metric history found (FRC-CSX-MOT "
                            f"MUST: {'6' if cls == 'c' else '18'} months for ALL KSIs, OR a "
                            "recorded initial-certification exception with mechanisms in place "
                            "and a commitment to meet the requirement)")
        else:
            # Missing KSIs (in scope but absent from history) are blockers.
            missing = sorted(mot_ksis - set(per))
            short = []
            gappy = []
            stale = []  # AUD-F33: newest datapoint older than the advisory threshold
            for kid in mot_ksis & set(per):
                dates = []
                _entry = per.get(kid)
                _pts = (_entry.get("series") if isinstance(_entry, dict)
                        else _entry) or []
                for e in _pts:
                    ds_ = (e or {}).get("date") if isinstance(e, dict) else None
                    if ds_:
                        try:
                            dates.append(_d2.date.fromisoformat(str(ds_)[:10]))
                        except ValueError:
                            pass
                if not dates or min(dates) > mot_cutoff:
                    short.append(kid)
                    continue
                # Persistence (not just age): FRC-CSX-MOT requires status from
                # "persistent validation over at least the past 6 months", not
                # merely one old datapoint plus one recent one. A series of
                # [6-months-ago, today] passes the age check above but is not
                # persistent. Prove the validation actually persisted across the
                # window by bounding the largest gap between consecutive
                # observations WITHIN the window.
                #
                # The rule does NOT mandate a fixed cadence (e.g. daily), so we
                # do not impose one. What we bound is the largest gap, against
                # the continuity tolerance from mot_max_gap_days (REPOSITORY
                # POLICY, default 45 days, offering-declared override reviewable
                # by the assessor; AUD-F21). The observed median cadence is
                # reported in the blocker for context, not used as the bound.
                # This catches a hollow two-point series while accepting an
                # honest weekly/monthly cadence with occasional misses.
                win = sorted(d for d in dates if d >= mot_cutoff)
                gappy_flag, largest, median, trailing_gap = mot_continuity(
                    win, today, max_gap_days=mot_gap_days, window_start=mot_cutoff)
                if gappy_flag:
                    gappy.append((kid, largest, median, trailing_gap))
                # AUD-F33: early warning well inside the hard bound. A KSI whose
                # newest datapoint is older than MOT_STALE_ADVISORY_DAYS has a
                # collection that stopped; say so now rather than when the gap
                # crosses the 45-day bound and becomes a blocker.
                newest_gap = mot_stale_days(dates, today)
                if newest_gap is not None:
                    stale.append((kid, newest_gap))
            if stale:
                stale.sort(key=lambda t: -t[1])
                ex = stale[0]
                warnings.append(
                    f"Class {cls.upper()}: {len(stale)} in-scope KSI(s) have no metric "
                    f"datapoint in the last {MOT_STALE_ADVISORY_DAYS} days (e.g. {ex[0]}: "
                    f"newest observation {ex[1]}d old). The collection appears to have "
                    f"stopped; it becomes an FRC-CSX-MOT continuity blocker once a gap "
                    f"exceeds {mot_gap_days}d. Check the scheduled collector run and its "
                    "failure notification (advisory; staleness threshold is project policy)")
            if missing:
                blockers.append(f"Class {cls.upper()}: {len(missing)} in-scope KSI(s) are "
                                f"entirely absent from the metric history (FRC-CSX-MOT covers "
                                f"ALL KSIs): {', '.join(missing[:8])}"
                                + (" ..." if len(missing) > 8 else ""))
            if short:
                blockers.append(f"Class {cls.upper()}: {len(short)} KSI(s) lack "
                                f"{'6' if cls == 'c' else '18'} months of persistent-validation "
                                "history (FRC-CSX-MOT; or record an initial-certification exception)")
            if gappy:
                ex = gappy[0]
                detail = (f"e.g. {ex[0]}: largest gap {ex[1]}d vs ~{ex[2]}d typical"
                          if ex[1] is not None
                          else f"e.g. {ex[0]}: only one observation in the window")
                blockers.append(
                    f"Class {cls.upper()}: {len(gappy)} KSI(s) reach back "
                    f"{'6' if cls == 'c' else '18'} months but the series is not "
                    f"CONTINUOUS across the window - FRC-CSX-MOT requires status "
                    f"from persistent validation, not one old datapoint plus a "
                    f"recent one ({detail}; tolerance {mot_gap_days}d from "
                    f"{mot_gap_source}, a project policy, not a FedRAMP figure). "
                    f"Fill the gaps, declare a reviewed mot_max_gap_days in the "
                    f"offering profile, or record an initial-certification exception.")

            # Summary-vs-history correlation: the SDR states per-KSI narrative
            # metric summaries (historical_metrics.last_30_days / up_to_one_year)
            # from the hand-authored records store. Those summaries must not be
            # asserted for a KSI whose durable metric history has NO observations
            # in the corresponding window - that is a hollow, uncorrelated claim
            # (e.g. "30/30 days passing" with an empty last-30-days series). We
            # do not parse the narrative's numbers (free text), but we DO require
            # backing data to exist before the claim is submittable.
            recs_ksi = ((load_json(os.path.join(BASE, "sdr", "records",
                        "records-store.json")) or {}).get("ksi") or {})
            cutoff30 = (today - _d2.timedelta(days=30)).isoformat()
            uncorrelated = []
            for kid in sorted(mot_ksis & set(per)):
                hm = (recs_ksi.get(kid, {}) or {}).get("historical_metrics", {}) or {}
                _entry = per.get(kid)
                pts = (_entry.get("series") if isinstance(_entry, dict)
                       else _entry) or []
                has_30 = any(isinstance(p, dict)
                             and cutoff30 <= str(p.get("date", ""))[:10] <= today.isoformat()
                             for p in pts)
                has_any = len(pts) > 0
                states_30 = not _is_hollow(hm.get("last_30_days"))
                states_1y = not _is_hollow(hm.get("up_to_one_year"))
                if (states_30 and not has_30) or (states_1y and not has_any):
                    uncorrelated.append(kid)
            if uncorrelated:
                blockers.append(
                    f"Class {cls.upper()}: {len(uncorrelated)} KSI(s) state a "
                    f"historical-metric summary in the SDR that the durable "
                    f"metric history does not back with any observation in that "
                    f"window (uncorrelated claim): {', '.join(uncorrelated[:8])}"
                    + (" ..." if len(uncorrelated) > 8 else "")
                    + ". A stated 30-day/1-year summary must be supported by "
                    "actual metric-history data for that KSI.")
    elif cls in ("a", "b"):
        # A MAY, B SHOULD - advisory only.
        history = load_json(os.path.join(BASE, "automation", "metrics", "metric-history.json"))
        if not history:
            warnings.append(f"Class {cls.upper()}: no KSI metric history yet "
                            f"(FRC-CSX-MOT is {'MAY' if cls == 'a' else 'SHOULD'} at this class)")
        # Finding 5: a SELECTED Class A SDR-CSX-KMT is fully reviewed - once the
        # provider opts historical KSI metrics into the Class A SDR, real
        # in-window metric content must actually back it, not an empty inclusion.
        # FedRAMP: if Class A historical KSI metrics are included, they should be
        # scoped, dated, and attributable to the service/KSI. Require at least
        # one applicable Class A KSI to carry an in-window daily observation.
        if cls == "a" and "SDR-CSX-KMT" in set(offering.get("selected_optional_rules") or []):
            import datetime as _dk5
            _hk = (history or {}).get("ksis", history) if isinstance(history, dict) else {}
            _hk = _hk if isinstance(_hk, dict) else {}
            _cut5 = (_utc_today() - _dk5.timedelta(days=365)).isoformat()
            _today5 = _utc_today().isoformat()
            _a_ksis = set(((class_profile.get("meta", {}) or {})
                           .get("class_a_ksis", {}) or {}).keys())

            def _has_window_obs(kid):
                e = _hk.get(kid)
                s = e.get("series") if isinstance(e, dict) else e
                if not isinstance(s, list):
                    return False
                return any(isinstance(p, dict)
                           and _cut5 <= str(p.get("date", ""))[:10] <= _today5
                           for p in s)

            if not any(_has_window_obs(k) for k in _a_ksis):
                blockers.append(
                    "Class A: selected SDR-CSX-KMT includes historical KSI metrics "
                    "in the SDR, but no applicable Class A KSI carries an in-window "
                    "(past-year) metric observation. Provide real, dated metric "
                    "history for the included KSIs or do not select SDR-CSX-KMT.")

    # Record store: bulk unresolved content stays a readiness warning (FedRAMP
    # explicitly allows an honestly incomplete implementation). Count TBDs only
    # within the records APPLICABLE to this class - counting the whole file
    # would report TBDs in rules that do not apply (e.g. Class A resolves far
    # fewer rules than the file contains), which is misleading.
    records = load_json(os.path.join(BASE, "sdr", "records", "records-store.json")) or {}
    # Mirror build_sdr.py's submitted scope: for Class A, unselected FRC-CLA-OFR
    # optional (MAY) rules are not in the submitted SDR, so preflight must not
    # gate their records either (otherwise the readiness gate evaluates a
    # different rule set than the SDR it is gating). Single source of truth:
    # submitted_rule_ids(), the same filter build_sdr.py applies.
    applicable_frr = submitted_rule_ids(
        class_profile.get("rules", []), cls,
        offering.get("selected_optional_rules"))
    # A selected optional rule the provider names must actually BE a Class A
    # optional (FRC-CLA-OFR) rule in this class profile. An unknown or
    # misspelled ID is silently no-op'd by submitted_rule_ids (it just never
    # matches), so the provider believes they opted a rule into the SDR that is
    # in fact absent. Surface that gap instead of ignoring it. Selected optional
    # rules are a Class A concept only; for B/C the field is inert, and a
    # populated selection there signals a profile authored for the wrong class.
    selected_optional = list(offering.get("selected_optional_rules") or [])
    if selected_optional:
        if cls == "a":
            known_optional = {
                r.get("rule_id") for r in class_profile.get("rules", [])
                if r.get("class_a_obligation") == "optional"
            }
            unknown_selected = [rid for rid in selected_optional
                                if rid not in known_optional]
            if unknown_selected:
                blockers.append(
                    "offering: selected_optional_rules names "
                    f"{len(unknown_selected)} ID(s) that are not Class A optional "
                    f"(FRC-CLA-OFR) rules in the profile - they are silently "
                    f"omitted from the submitted SDR: {', '.join(unknown_selected)}. "
                    "Remove them or correct the rule_id (must be one of: "
                    f"{', '.join(sorted(known_optional))}).")
        else:
            warnings.append(
                f"offering: selected_optional_rules is set ({len(selected_optional)} "
                f"ID(s)) but only applies to Class A (FRC-CLA-OFR opt-in); it is "
                f"ignored at Class {cls.upper()}")
    # Class A resolves only the 7 CLA-enumerated KSIs, not all 46. Use the
    # class-A profile's enumeration (the same source the SDR validator trusts)
    # so preflight does not falsely block on the ~39 KSIs that do not apply to A.
    if cls == "a":
        class_a_ksis = (class_profile.get("meta", {}) or {}).get("class_a_ksis", {})
        applicable_ksi = set(class_a_ksis.keys()) if class_a_ksis else set()
    else:
        _all_inds = ksi_profile.get("indicators", [])
        applicable_ksi = {k.get("ksi_id") for k in _all_inds}
        # Class B optional-KSI scoping (verified against the pinned dataset):
        # five KSIs carry a varies_by_class 'b' statement prefixed "**Optional:**"
        # (CNA-EIS, MLA-ALA, SVC-PRR, SVC-RUD, SVC-VCM) and lose that prefix at
        # Class C. At Class B they are OPTIONAL: gate one only when the provider
        # explicitly selects it via profile.selected_optional_ksis. At Class C/D
        # they are mandatory and stay in scope. Without this, Class B over-gates
        # all 46 KSIs including the five the dataset marks optional at B.
        if cls == "b":
            selected_optional_ksis = list(offering.get("selected_optional_ksis") or [])
            unknown_opt = unknown_optional_ksi_selections(_all_inds, selected_optional_ksis)
            if unknown_opt:
                optional_b_ksis = optional_at_class_b_ksis(_all_inds)
                blockers.append(
                    "offering: selected_optional_ksis names ID(s) that are not "
                    "optional at Class B: "
                    + ", ".join(sorted(unknown_opt))
                    + " (valid optional-at-B KSIs: "
                    + ", ".join(sorted(optional_b_ksis))
                    + "). Fix or remove the selection - a bad selection silently "
                    "opts in nothing.")
            # Scope preflight to the SAME set the builder submits.
            applicable_ksi = submitted_ksi_ids(_all_inds, cls, selected_optional_ksis)

    def _count_markers(rec):
        blob = json.dumps(rec)
        return blob.count("TBD"), blob.count("sdr://placeholder/")

    def _answered(v):
        """A required field is answered when it has real content: non-empty and
        not a TBD/placeholder. An explicit JUSTIFIED N/A counts as answered
        (FedRAMP allows a justified non-implementation), but a BARE 'N/A' does
        not - the whole point is that 'submission ready' cannot be satisfied by
        a content-free token. A justified N/A must carry a reason after the
        marker, e.g. 'N/A: <reason>' or 'Not applicable - <reason>'."""
        if isinstance(v, list):
            return any(_answered(x) for x in v)
        s = str(v or "").strip()
        if not s:
            return False
        if s.startswith("TBD") or "has not been provided" in s \
                or "has not been performed" in s or s.startswith("sdr://placeholder/"):
            return False
        # AUD-F38: a labelled DRAFT / Example proposal is a machine's or the
        # template's text, not the provider's confirmed fact. Unanswered until a
        # named human accepts it through `sdr.py review` (which strips the label).
        if _is_unreviewed(s):
            return False
        # Bare N/A / not-applicable tokens without a justification do not count.
        low = s.lower()
        na_markers = ("n/a", "na", "not applicable", "not-applicable")
        for m in na_markers:
            if low == m:
                return False
            if low.startswith(m):
                # Require a real justification after the marker (a separator plus
                # at least a few characters of reason), not just "N/A." or "N/A -".
                rest = s[len(m):].lstrip(" :.-\u2013\u2014").strip()
                return len(rest) >= 3
        return True

    def _frr_gaps(rec):
        """Missing required SDR-CSO-FRR items for one FRR record, evaluated
        STATUS-AWARE so the release gate agrees with the readiness scanner
        (automation/sdrscan/checks.py rule_checks). Rule-specific artifacts are
        'if applicable', so not gated.

        SDR-CSO-FRR, verbatim item 1 is an OR: "Explanation of how the rule is
        followed, OR an explanation of the reason and resulting risk to customers
        for not following the rule." Items 2-3 (verification, validation) may be
        satisfied, for a rule that is NOT followed, by a senior official's
        acceptance of the reason for not implementing. So the required set
        depends on frrImplementationStatus:

          Implemented           -> implementation + verification + validation
                                   (+ independent verification/validation, responses)
          Not / Partially       -> reason + resulting customer_risk, AND EITHER
            Implemented            verification+validation OR a real
                                   senior_official_acceptance standing in for them

        Gating implementation-only (status-unaware) let a Not-Implemented rule
        with a filled implementation narrative satisfy item 1 while customer_risk
        stayed TBD, and always demanded verification/validation even where the
        senior-official-acceptance alternative applies - diverging from the
        scanner."""
        ext = rec.get("extension", {}) or {}
        status = official_status(rec.get("implementation_status"))
        not_following = status in ("Not Implemented", "Partially Implemented")
        gaps = []

        # Item 1 is an OR whose "not followed" branch has TWO distinct elements,
        # verbatim: "the reason AND resulting risk to customers for not following
        # the rule." Risk is not the reason: a filled resulting_customer_risk
        # alone does not explain WHY the rule is not followed. So:
        #   followed      -> implementation (how) satisfies item 1
        #   not followed  -> BOTH nonimplementation_reason AND customer_risk
        # The reason may be carried in a dedicated nonimplementation_reason
        # field, or in the implementation narrative when the rule is not
        # followed (a provider often writes the "why not" there); either counts
        # as the reason, but the resulting customer risk is always its own
        # distinct element.
        reason_answered = _answered(ext.get("nonimplementation_reason")) or (
            not_following and _answered(rec.get("implementation")))
        if not_following:
            if not reason_answered:
                gaps.append("reason-not-followed (rule not followed)")
            if not _answered(ext.get("customer_risk")):
                gaps.append("resulting-customer-risk (rule not followed)")
        else:
            # Followed: item 1 is the how-followed implementation narrative.
            if not _answered(rec.get("implementation")):
                gaps.append("implementation")

        # Items 2-3: verification + validation, OR senior-official acceptance
        # for a not-followed rule. A bare "Not required: rule is followed"
        # placeholder does NOT count as acceptance.
        acc = ext.get("senior_official_acceptance")
        acceptance_ok = _answered(acc) and not str(acc).startswith("Not required")
        vv_ok = _answered(ext.get("verification")) and _answered(rec.get("validation"))
        if not_following:
            if not (vv_ok or acceptance_ok):
                gaps.append("verification+validation OR senior-official-acceptance "
                            "(rule not followed)")
        else:
            if not _answered(ext.get("verification")):
                gaps.append("verification")
            if not _answered(rec.get("validation")):
                gaps.append("validation")

        # Items 4-6 apply regardless of status.
        for k, v in (("independent_verification", ext.get("independent_verification")),
                     ("independent_validation", ext.get("independent_validation")),
                     ("responses", ext.get("assessor_responses"))):
            if not _answered(v):
                gaps.append(k)
        return gaps

    # SDR-CSX-KMT daily data (Class C/D MUST): the actual daily metric data up
    # to the past year, DERIVED from the immutable metric-history.json snapshot
    # (the same durable store the MOT gate reads), not a hand-authored field and
    # NOT the optional dailyDataReference URI. CR26 requires the data, not a URL,
    # so a package with real daily observations but no external pointer must pass,
    # while one whose durable history has no daily observations for an applicable
    # KSI must block. "(where available)" is honored: a KSI genuinely absent from
    # history is caught by the FRC-CSX-MOT coverage gate above, not double-blocked
    # here - this check only fires when the KSI IS in history but has zero
    # in-window daily observations.
    _kmt_hist = load_json(os.path.join(BASE, "automation", "metrics", "metric-history.json")) or {}
    _kmt_ksis = (_kmt_hist.get("ksis", _kmt_hist) if isinstance(_kmt_hist, dict) else {}) or {}

    # AUD-F37: the metric history must be the collector's record, not a file
    # someone completed. Three checks over the durable history:
    #   1. Chain integrity. Every observation is hash-linked to its predecessor
    #      and carries run provenance. A bad hash, a broken link, a bad pruning
    #      anchor or a series point with no observation behind it is tampering or
    #      corruption, never acceptable: HARD at Class C/D whenever the history
    #      carries chain fields at all. Observations with NO chain fields or NO
    #      provenance (pre-F37 histories, hand-written files) are an ADVISORY
    #      under the development profile and HARD under production-assurance.
    #   2. Signed digest. Anyone can rechain a tampered log; only the separate
    #      signer principal can re-sign its digest. Under production-assurance
    #      the history digest MUST carry a signature that verifies offline
    #      against the independently pinned signer (expected_evidence_signer);
    #      under development it is an advisory when absent.
    #   3. Freshness for VVK binding (below): a method counts as "working" only if
    #      its per-method series has a datapoint within its cadence window.
    _store_profile = str(offering.get("evidence_store_profile") or "development").strip().lower()
    _production = _store_profile == "production-assurance"
    if _store_profile not in ("development", "production-assurance"):
        blockers.append(f"evidence_store_profile {_store_profile!r} is not 'development' or "
                        "'production-assurance' (AUD-F37)")
    if cls in ("c", "d") and isinstance(_kmt_hist, dict) and _kmt_ksis:
        _problems = _hi.verify_history(_kmt_hist)
        _chained_any = any(all(k in o for k in _hi.CHAIN_FIELDS)
                           for e in _kmt_ksis.values() if isinstance(e, dict)
                           for o in (e.get("observations") or []))
        if _chained_any:
            _tamper = [p for p in _problems if p[0] in ("bad-hash", "chain-break", "bad-anchor",
                                                        "unbacked-point", "head-mismatch")]
            _soft = [p for p in _problems if p[0] in ("missing-chain", "unattested")]
        else:
            # Pre-F37 or hand-written shape: nothing is chained, so nothing can
            # be verified. Not tampering, but not the collector's record either.
            _tamper = []
            _soft = [("unchained-history", "*", "no observation carries chain fields")]
        if _tamper:
            ex = _tamper[0]
            blockers.append(
                f"Class {cls.upper()}: metric history INTEGRITY FAILED: {len(_tamper)} chained "
                f"observation(s) do not verify (e.g. {ex[1]}: {ex[0]}, {ex[2]}). An edited, "
                "inserted or deleted observation breaks the hash chain; the history is not "
                "the collector's record (AUD-F37, FRC-CSX-MOT/SDR-CSX-KMT evidence)")
        if _soft:
            ex = _soft[0]
            msg = (f"Class {cls.upper()}: {len(_soft)} metric observation(s) are unchained or "
                   f"unattested (e.g. {ex[1]}: {ex[0]}). They did not come through the "
                   "collector -> appender path with run provenance, so nothing proves the "
                   "collector produced them (AUD-F37)")
            (blockers if _production else warnings).append(
                msg + (" - HARD under evidence_store_profile production-assurance"
                       if _production else " - advisory under the development profile; "
                       "production-assurance makes it a blocker"))
        # Signed digest over the whole log.
        _sig = (_kmt_hist.get("meta") or {}).get("history_signature")
        _signer = offering.get("expected_evidence_signer") or {}
        _pub = _signer.get("public_key_pem") if isinstance(_signer, dict) else None
        if isinstance(_signer, dict) and not _answered(_pub) and _answered(_signer.get("public_key_pem_path")):
            try:
                with open(os.path.join(BASE, str(_signer.get("public_key_pem_path"))), encoding="utf-8") as _pf:
                    _pub = _pf.read()
            except OSError:
                _pub = None
        if _sig:
            _ok = False
            _why = ""
            if not _answered(_pub):
                _why = "no trusted signer public key is pinned in expected_evidence_signer"
            else:
                try:
                    _ok = _se.verify_signature_offline(
                        _sig, _pub, recomputed_hash=_hi.history_digest(_kmt_hist),
                        expected_fingerprint=(_signer.get("public_key_fingerprint")
                                              if _answered(_signer.get("public_key_fingerprint")) else None))
                except Exception as _e:  # noqa: BLE001 - any verifier failure is a fail
                    _why = f"{type(_e).__name__}: {_e}"
            if not _ok:
                blockers.append(
                    f"Class {cls.upper()}: metric history digest signature does NOT verify "
                    f"({_why or 'signature does not cover the current digest, or signer mismatch'}); "
                    "a present-but-unverifiable signature is a hard failure (AUD-F37)")
        elif _production:
            blockers.append(
                f"Class {cls.upper()}: evidence_store_profile is production-assurance but the "
                "metric history digest is UNSIGNED (meta.history_signature absent). Publish "
                "with --sign-key-arn so the separate signer attests the chain head (AUD-F37)")
        else:
            warnings.append(
                f"Class {cls.upper()}: metric history digest is unsigned; anyone with write "
                "access to the history file can rechain a tampered log. Declare "
                "evidence_store_profile production-assurance and publish with --sign-key-arn "
                "to make the signature required (AUD-F37, advisory)")

    # Cadence window (days) within which a declared method's per-method series
    # must carry a datapoint to count as a WORKING automated method (AUD-F37).
    # Derived from the method's declared cadence; a method with no recognisable
    # cadence is held to the staleness advisory window. Project policy: FedRAMP
    # requires persistent verification but names no cadence.
    _VVK_FRESH_DAYS = {"daily": MOT_STALE_ADVISORY_DAYS, "weekly": 14, "monthly": 45,
                       "quarterly": MOT_MAX_GAP_DAYS_CEILING}

    def _method_is_fresh(metric_entry, cadence):
        series = (metric_entry or {}).get("series") or []
        dates = [str(p.get("date", ""))[:10] for p in series if isinstance(p, dict)]
        if not dates:
            return False
        window = _VVK_FRESH_DAYS.get(str(cadence or "").strip().lower(), MOT_STALE_ADVISORY_DAYS)
        import datetime as _df
        cutoff = (_utc_today() - _df.timedelta(days=window)).isoformat()
        return any(cutoff <= d <= _utc_today().isoformat() for d in dates)

    # Per-KSI class minimum number of automated verification methods (FRC-CSX-VVK),
    # read from the pinned KSI profile: class_c = 2, class_d = 4. Used by the VVK
    # method-to-telemetry binding gate so it requires the class minimum of declared
    # methods bound to telemetry, not merely one (existential binding was a
    # false-ready path: 2 declared / 1 bound satisfied the count gate and the
    # binding gate simultaneously).
    _vvk_min_key = {"c": "class_c", "d": "class_d_future"}.get(cls)
    _vvk_min_by_ksi = {}
    if _vvk_min_key:
        for _ind in ksi_profile.get("indicators", []):
            _kid = _ind.get("ksi_id")
            _m = (_ind.get("minimum_automated_methods") or {}).get(_vvk_min_key)
            if _kid and isinstance(_m, int):
                _vvk_min_by_ksi[_kid] = _m

    def _daily_series_for(kid):
        import datetime as _dk
        entry = _kmt_ksis.get(kid)
        series = entry.get("series") if isinstance(entry, dict) else entry
        if not isinstance(series, list):
            return []
        _today = _utc_today().isoformat()
        cutoff = (_utc_today() - _dk.timedelta(days=365)).isoformat()
        # Finding 12: bound the window at both ends. A future-dated observation
        # (date > today) is not a real historical measurement and must not count
        # toward the daily-data requirement.
        return [p for p in series
                if isinstance(p, dict)
                and cutoff <= str(p.get("date", ""))[:10] <= _today]

    def _per_metric_gap_for(kid):
        """Finding 5: SDR-CSX-KMT asks for a "Summary of EACH metric." A KSI
        whose durable history proves MULTIPLE distinct metrics were observed
        must carry a populated per-metric breakdown (the metrics map), not a
        single collapsed aggregate. Returns a gap message when the history shows
        a genuinely multi-metric KSI with no in-window per-metric series, else
        "" (no gap). Honors "where available": a KSI observed as a single metric
        (every datapoint total <= 1) or absent from history is NOT gated - the
        aggregate carries it and forcing per-metric would over-block.

        Multi-metric is detected from the durable history itself, not the
        registry's theoretical maximum: either the entry declares a metrics map
        with >1 metric, OR an aggregate datapoint observed total > 1 (more than
        one check/service contributed that day). The per-metric requirement is
        satisfied when the metrics map carries at least one in-window datapoint
        for each of its metrics.
        """
        import datetime as _pm
        entry = _kmt_ksis.get(kid)
        if not isinstance(entry, dict):
            return ""  # no history -> where-available, not gated
        series = entry.get("series") if isinstance(entry.get("series"), list) else []
        metrics = entry.get("metrics") if isinstance(entry.get("metrics"), dict) else {}
        # Is this a genuinely multi-metric KSI per its own history?
        multi = len(metrics) > 1 or any(
            isinstance(p, dict) and isinstance(p.get("total"), int) and p["total"] > 1
            for p in series)
        if not multi:
            return ""  # single-metric or aggregate-of-one: aggregate suffices
        if not metrics:
            return ("kmt_per_metric (history shows multiple metrics but carries "
                    "no per-metric breakdown; SDR-CSX-KMT requires a summary of "
                    "each metric)")
        cutoff = (_utc_today() - _pm.timedelta(days=365)).isoformat()
        _today_pm = _utc_today().isoformat()
        empty = []
        for mid, m in metrics.items():
            ms = m.get("series") if isinstance(m, dict) else None
            in_window = [p for p in (ms or [])
                         if isinstance(p, dict)
                         and cutoff <= str(p.get("date", ""))[:10] <= _today_pm]
            if not in_window:
                empty.append(mid)
        if empty:
            return ("kmt_per_metric (metric(s) with no in-window observations: "
                    + ", ".join(sorted(empty)[:5]) + ")")
        return ""

    def _kmt_claim_contradicts_history(kid, rec):
        """Finding 1 (correlation): the SDR now DERIVES the 30-day/1-year
        summaries from durable history at build, so the submitted document is
        consistent by construction. But a provider may still hand-author a
        historical_metrics summary in records-store that DISAGREES with the
        real history (e.g. claims '100% passing' while the history has
        failures). build_sdr overrides it, yet the input contradiction is worth
        surfacing so the provider fixes the source rather than shipping a claim
        the build silently rewrote. Returns a message when the hand-authored
        avg_passing_fraction disagrees with the value computed from history for
        the same window, else None. Compares only when BOTH a numeric claim and
        in-window history exist; a tolerance absorbs rounding.
        """
        entry = _kmt_ksis.get(kid)
        series = entry.get("series") if isinstance(entry, dict) else entry
        if not isinstance(series, list) or not series:
            return None  # no history to contradict ("where available")
        import datetime as _dc
        today = _utc_today()
        cut30 = (today - _dc.timedelta(days=29)).isoformat()
        y = today.year + (today.month - 1 - 12) // 12
        m = (today.month - 1 - 12) % 12 + 1
        last_day = 31 if m == 12 else (_dc.date(y, m + 1, 1) - _dc.timedelta(days=1)).day
        year_start = _dc.date(y, m, min(today.day, last_day)).isoformat()

        def _avg(points):
            fr = [p["passing"] / p["total"] for p in points
                  if isinstance(p, dict) and p.get("total")]
            return round(sum(fr) / len(fr), 4) if fr else None

        computed = {
            "last_30_days": _avg([p for p in series
                                  if cut30 <= str(p.get("date", ""))[:10] <= today.isoformat()]),
            "up_to_one_year": _avg([p for p in series
                                    if year_start <= str(p.get("date", ""))[:10] <= today.isoformat()]),
        }
        hm = rec.get("historical_metrics", {}) or {}
        msgs = []
        for key, comp in computed.items():
            claim = hm.get(key)
            if not isinstance(claim, dict) or comp is None:
                continue
            claimed = claim.get("avg_passing_fraction")
            if isinstance(claimed, (int, float)) and abs(claimed - comp) > 0.001:
                msgs.append(f"{key}: claims {claimed} but history computes {comp}")
        return "; ".join(msgs) if msgs else None

    def _ksi_gaps(kid, rec):
        """Missing required SDR-CSX-KSI items for one KSI record (5 items),
        plus SDR-CSX-KMT historical-metric content where it is MUST.
        SDR-CSX-KMT force by class: A MAY (not gated); B MUST (30-day + yearly
        summaries); C/D MUST (those PLUS the actual daily metric data up to the
        past year). Values must be resolved (not TBD) so a Class B/C package
        cannot be 'ready' with empty metric summaries.

        The first SDR-CSX-KSI item is an OR whose "no measures" branch has TWO
        distinct elements, verbatim: "Explanation of measures (and their
        objectives) ... OR an explanation of the reason AND resulting risk to
        customers for not having measures available." So:
          has measures  -> measures/implementation satisfies item 1
          no measures   -> BOTH measures_unavailable_reason AND
                           resulting_customer_risk (risk alone is not the reason)

        Item 2 (operating cycle) is "if applicable" - required ONLY for measures
        implemented persistently. A no-measures / nonpersistent-measures KSI is
        NOT gated on operating_cycle (it would over-block a legitimate case);
        it is gated only when measures are present AND declared persistent."""
        ext = rec.get("extension", {}) or {}
        has_measures = _answered(rec.get("implementation")) or _answered(ext.get("measures"))
        reason_no_measures = _answered(ext.get("measures_unavailable_reason"))
        risk = _answered(ext.get("resulting_customer_risk")) or _answered(ext.get("customer_risk"))
        checks = {
            "measures_verification": ext.get("measures_verification"),
            "automation_verification": ext.get("automation_verification"),
            "validation": rec.get("validation"),
        }
        if cls in ("b", "c", "d"):
            hm = rec.get("historical_metrics", {}) or {}
            checks["kmt_last_30_days"] = hm.get("last_30_days")
            checks["kmt_up_to_one_year"] = hm.get("up_to_one_year")
        gaps = [k for k, v in checks.items() if not _answered(v)]
        # Item 1 (OR).
        if has_measures:
            pass  # measures narrative satisfies item 1
        else:
            if not reason_no_measures:
                gaps.insert(0, "reason-no-measures-available")
            if not risk:
                gaps.insert(0, "resulting-customer-risk (no measures available)")
        # Item 2 "if applicable": operating cycle is required only when measures
        # are present AND run persistently. Detect a persistence declaration
        # from the record; absent one, a KSI with measures is not blocked on
        # cycle here (the scanner reports it MANUAL for human confirmation).
        cycle = ext.get("operating_cycle") or ext.get("cycle")
        persistent = bool(ext.get("measures_persistent")) or (
            "persistent" in str(ext.get("measures") or "").lower())
        if has_measures and persistent and not _answered(cycle):
            gaps.append("operating_cycle (persistent measures)")
        # Finding 3: SDR-CSX-KMT requires a "Summary of each metric" for the
        # 30-day and 1-year windows at Class B (SHOULD/MUST per class), not only
        # C/D. A genuinely multi-metric KSI must carry the per-metric breakdown
        # at B as well, so a Class B package cannot ship one blended aggregate in
        # place of the required summary of each metric. The ACTUAL daily metric
        # data (dailyData) stays C/D-only below.
        if cls in ("b", "c", "d"):
            pm_gap = _per_metric_gap_for(kid)
            if pm_gap:
                gaps.append(pm_gap)
        if cls in ("c", "d"):
            # Class C/D MUST supply the actual daily metric data (SDR-CSX-KMT),
            # derived from the durable history. Require a non-empty in-window
            # daily series for a KSI that IS present in history; a KSI wholly
            # absent from history is left to the FRC-CSX-MOT coverage gate so it
            # is not double-blocked here ("where available").
            if kid in _kmt_ksis and not _daily_series_for(kid):
                gaps.append("kmt_daily_data (no in-window daily observations in metric history)")
        # FRC-CSX-VVK method-to-telemetry binding (Class C/D): a KSI that DECLARES
        # automated verification methods must have the CLASS MINIMUM number of them
        # (C=2, D=4) bound to observed telemetry - each counted method_id must key
        # an in-history per-method metrics series (the method actually produced
        # datapoints). This is SET-based, not existential: two methods declared
        # automated:true where only one emitted keyed telemetry is a false-ready
        # path - the count gate passes on two declarations and old code passed the
        # binding gate on the single bound one, so a half-implemented KSI reached
        # ready. Requiring the class minimum bound closes that.
        #
        # The MOT exception does NOT switch this off. FRC-CSX-MOT's initial-
        # certification exception relaxes the persistent-validation HISTORY
        # DURATION (6/18 months); it does not remove the separate FRC-CSX-VVK
        # obligation to actually implement the class-minimum automated methods. So
        # this gate stays active under exc_valid. "Where available" is still
        # honored the one honest way: a KSI WHOLLY ABSENT from history (no metrics
        # map at all) is left to the MOT coverage gate and not double-blocked here
        # - a brand-new offering may legitimately have no accumulated per-method
        # history yet. But once a KSI IS in history with a metrics map, the class
        # minimum of its declared methods must be bound.
        if cls in ("c", "d"):
            entry = _kmt_ksis.get(kid)
            if isinstance(entry, dict) and isinstance(entry.get("metrics"), dict):
                declared = [t for t in (rec.get("tests") or [])
                            if isinstance(t, dict) and t.get("automated") is True
                            and _answered(t.get("method_id"))]
                if declared:
                    metrics = entry.get("metrics")
                    # F02: identity is the DISTINCT method_id. Duplicate
                    # declarations of the same method_id must not inflate either
                    # the declared count or the bound count, and a method is only
                    # BOUND if its per-method metric series actually carries
                    # observations (a keyed-but-empty series is not telemetry).
                    declared_ids = {t["method_id"] for t in declared}
                    cadence_by_id = {t["method_id"]: t.get("cadence") for t in declared}
                    # AUD-F37: "bound" now means WORKING: the per-method series
                    # carries a datapoint within the method's cadence window. A
                    # series that exists but stopped months ago, or one typed
                    # into the file with old dates, is not a working automated
                    # method (FRC-CSX-VVK: "persistently verify and validate").
                    bound_ids = {
                        mid for mid in declared_ids
                        if isinstance(metrics.get(mid), dict)
                        and _method_is_fresh(metrics[mid], cadence_by_id.get(mid))
                    }
                    need = _vvk_min_by_ksi.get(kid, 2 if cls == "c" else 4)
                    # Cannot require more bound than the KSI actually declares
                    # (distinct): the count-minimum gate (validate_sdr) separately
                    # enforces that enough DISTINCT methods are declared. Here we
                    # bind the class minimum, capped at the distinct declared
                    # count so a KSI that declares exactly the minimum is not
                    # impossible to satisfy.
                    need = min(need, len(declared_ids))
                    if len(bound_ids) < need:
                        gaps.append(
                            f"vvk_method_binding ({len(bound_ids)} of {need} required "
                            "distinct automated method(s) bound to FRESH observed telemetry "
                            "(a datapoint within the method's cadence window); "
                            "declared: "
                            + ", ".join(sorted(declared_ids)[:5])
                            + "; working: "
                            + (", ".join(sorted(bound_ids)[:5]) or "none")
                            + ")")
        return gaps

    tbd = placeholders = scoped_records = 0
    unanswered = []
    # Finding 2: rule-specific canonical artifacts are first-class. For rules the
    # pinned dataset marks with an UNCONDITIONAL MUST artifact, an applicable,
    # followed record must actually carry a rule_artifact - narrative fields
    # alone are not enough. A not-followed rule is exempt (there is no artifact
    # to produce for a control that is honestly not implemented; its reason +
    # customer risk carry the requirement instead).
    artifact_rules = set(artifact_required_rule_ids(cls))
    # Finding 6: a SELECTED Class A optional (MAY) rule is fully reviewed, so an
    # unconditional artifact it carries at this class becomes required too. Add
    # the MAY-force artifact rules, but ONLY for the rules the provider actually
    # selected - an unselected MAY rule stays optional and ungated.
    if selected_optional:
        may_artifact_rules = artifact_required_rule_ids(cls, forces=("MUST", "MAY"))
        for rid in selected_optional:
            if rid in may_artifact_rules:
                artifact_rules.add(rid)

    def _has_real_artifact(rec):
        ext = rec.get("extension", {}) or {}
        for a in (ext.get("rule_artifacts") or []):
            if isinstance(a, dict):
                loc = a.get("evidenceLocation") or a.get("evidence_location")
                if _answered(loc):
                    return True
            elif _answered(a):
                return True
        return False

    for rid, rec in (records.get("frr", {}) or {}).items():
        if rid in applicable_frr:
            t, p = _count_markers(rec); tbd += t; placeholders += p; scoped_records += 1
            gaps = _frr_gaps(rec)
            status = official_status(rec.get("implementation_status"))
            followed = status not in ("Not Implemented", "Partially Implemented")
            if rid in artifact_rules and followed and not _has_real_artifact(rec):
                gaps.append("rule-artifact (canonical MUST artifact required "
                            "for this rule; supply extension.rule_artifacts)")
            if gaps:
                unanswered.append(f"{rid} (missing: {','.join(gaps)})")
    for kid, rec in (records.get("ksi", {}) or {}).items():
        if kid in applicable_ksi:
            t, p = _count_markers(rec); tbd += t; placeholders += p; scoped_records += 1
            gaps = _ksi_gaps(kid, rec)
            if cls in ("b", "c", "d"):
                contradiction = _kmt_claim_contradicts_history(kid, rec)
                if contradiction:
                    gaps.append(f"kmt_summary_contradicts_history ({contradiction})")
            if gaps:
                unanswered.append(f"{kid} (missing: {','.join(gaps)})")
    if tbd:
        warnings.append(f"{tbd} unresolved TBD placeholder(s) across {scoped_records} "
                        f"records applicable to Class {cls.upper()}")
    if placeholders:
        # An explicit sdr://placeholder/ evidence URI in an applicable record is a
        # "replace me" marker: the evidence location is not real. That must block
        # submission, not merely warn - a ready package cannot point at placeholder
        # evidence.
        blockers.append(f"{placeholders} unresolved sdr://placeholder/ evidence URI(s) "
                        f"in records applicable to Class {cls.upper()} (replace each "
                        "with the real evidence location before submission)")
    if unanswered:
        sample = ", ".join(unanswered[:8])
        blockers.append(f"{len(unanswered)} applicable requirement(s) have no "
                        f"implementation information (still placeholder/TBD, not an "
                        f"honest Not-Implemented with rationale): {sample}"
                        + (" ..." if len(unanswered) > 8 else ""))

    # Evidence freshness at submission. FedRAMP guidance: "stale screenshots,
    # expired exports, outdated descriptions, or old evidence can cause
    # rejection." For each POPULATED applicable record carrying DATED evidence,
    # classify freshness against the offering's policy (default 90 days; hard
    # expiry at 2x). EXPIRED evidence backing an active claim is a readiness
    # defect: a blocker at Class C/D (mirroring evidence-linkage force), a
    # warning at A/B. STALE evidence is always a warning. This never changes a
    # status and never treats UNDATED or MISSING evidence as expiry (missing
    # evidence is the linkage check's job); it classifies only.
    import datetime as _d3
    now_ef = _d3.datetime.now(_d3.timezone.utc)
    policy_days = offering.get("evidence_freshness_policy_days") or DEFAULT_EVIDENCE_FRESHNESS_DAYS
    try:
        policy_days = int(policy_days)
    except (TypeError, ValueError):
        policy_days = DEFAULT_EVIDENCE_FRESHNESS_DAYS
    expired_ev, stale_ev = [], []

    def _scan_freshness(rid, rec):
        impl = rec.get("implementation")
        populated = _answered(impl) and not any(
            "TBD" in str(x) for x in (impl if isinstance(impl, list) else [impl]))
        if not populated:
            return
        # Evidence lives in two places by record kind: KSI evidence under
        # rec["evidence"]; FRR rule-specific artifacts under
        # rec["extension"]["rule_artifacts"]. Scan BOTH so an expired FRR
        # artifact is not silently missed.
        ext = rec.get("extension", {}) or {}
        items = list(rec.get("evidence") or []) + list(ext.get("rule_artifacts") or [])
        # Evaluate the WHOLE evidence set rather than breaking on the first
        # expired item: a record with one expired historical artifact AND one
        # current valid artifact still has sufficient current support and must
        # NOT be reported as "backed only by EXPIRED evidence". Only when EVERY
        # dated item is expired (and none is current) is it a blocker; a mix is
        # a stale-artifact warning.
        states = []
        for ev in items:
            observed = _evidence_observed_at(ev)
            if observed is None:
                continue  # undated evidence is the linkage check's job, not freshness
            states.append(classify_evidence_freshness(observed, now_ef, policy_days))
        if not states:
            return
        has_current = any(s == "current" for s in states)
        all_expired = all(s == "expired" for s in states)
        if all_expired and not has_current:
            expired_ev.append(rid)
        elif any(s in ("stale", "expired") for s in states):
            stale_ev.append(rid)

    for rid, rec in (records.get("frr", {}) or {}).items():
        if rid in applicable_frr:
            _scan_freshness(rid, rec)
    for kid, rec in (records.get("ksi", {}) or {}).items():
        if kid in applicable_ksi:
            _scan_freshness(kid, rec)
    if expired_ev:
        msg = (f"{len(expired_ev)} applicable populated record(s) are backed only by "
               f"EXPIRED evidence (older than {policy_days * 2} days; FedRAMP: expired "
               f"exports/old evidence can cause rejection). Refresh the evidence before "
               f"submission: {', '.join(sorted(set(expired_ev))[:8])}"
               + (" ..." if len(set(expired_ev)) > 8 else ""))
        if cls in ("c", "d"):
            blockers.append(msg)
        else:
            warnings.append(msg + " (advisory at Class " + cls.upper() + ")")
    if stale_ev:
        warnings.append(
            f"{len(set(stale_ev))} applicable populated record(s) have STALE evidence "
            f"(older than {policy_days} days but not yet expired): "
            f"{', '.join(sorted(set(stale_ev))[:8])}"
            + (" ..." if len(set(stale_ev)) > 8 else ""))

    # Scan the GENERATED submission artifacts, not merely the input profile. A
    # generated CPO carrying template markers, placeholder IDs/URLs, or recorded
    # _cpoAssumptions must not reach "submission ready".
    cpo = load_json(os.path.join(BASE, "package", "cpo", "cpo.json")) or {}
    si = cpo.get("serviceIdentification", {}) or {}
    cpo_markers = []
    if str(si.get("fedRampPackageId", "")).startswith("TBD"):
        cpo_markers.append("fedRampPackageId is TBD-PACKAGE-ID")
    for field in ("website", "logo"):
        if "placeholder" in str(si.get(field, "")).lower():
            cpo_markers.append(f"CPO {field} is a placeholder URL")
    assessor = cpo.get("assessor", {}) or {}
    # Class A FedRAMP assessment is MAY (FRC-APP-FIA), so a placeholder assessor
    # id does not block Class A; it blocks B/C/D where the assessment is MUST.
    if assessor.get("assessorID") == "000000" and cls != "a":
        cpo_markers.append("CPO assessorID is the 000000 placeholder")
    sp = cpo.get("serviceProperties", {}) or {}
    for key in ("trustCenter", "secureConfigurationGuidance"):
        # The Secure Configuration Guide applies to Class B/C/D, not A.
        if key == "secureConfigurationGuidance" and cls == "a":
            continue
        url = (sp.get(key) or {}).get("url", "")
        if "placeholder" in str(url).lower() or "example" in str(url).lower():
            cpo_markers.append(f"CPO {key} is a placeholder URL")
    if cpo.get("_cpoAssumptions"):
        cpo_markers.append(f"CPO contains {len(cpo['_cpoAssumptions'])} unresolved "
                           "generator assumption(s) (see _cpoAssumptions)")
    # CDS-CSO-PUB requires BOTH Sales Contact Information and Security Contact
    # Information. Assert directly on the GENERATED CPO contactInformation so
    # there is a single unambiguous check on the delivered artifact (not only via
    # the structured required-information map).
    for contact in (cpo.get("contactInformation") or []):
        ctype = contact.get("contactType", "?")
        if ctype in ("Sales", "Security") and _is_missing_required_identity(contact.get("contactName")):
            cpo_markers.append(f"CPO {ctype} contactName is unresolved (CDS-CSO-PUB "
                               "requires both Sales and Security contact information)")
    if cpo_markers:
        blockers.append(f"generated CPO carries {len(cpo_markers)} template "
                        f"marker(s)/assumption(s): {'; '.join(cpo_markers)}")

    # CPO semantic completeness (CPO-CSO-OVR / CPO-CSO-MTD): required-information
    # items and metadata must be resolved, not TBD.
    mtd = cpo.get("xCpoMetadata", {}) or {}
    # CPO-CSO-MTD is only required when it resolves for this class/type (Class A's
    # applicable CPO-CSO-OVR set is only CDS-CSO-PUB + MAS-CSO-IIR, so its CPO
    # carries no metadata block and must not be blocked on one).
    _applicable_rule_ids = {r["rule_id"] for r in (class_profile.get("rules") or [])}
    if "CPO-CSO-MTD" in _applicable_rule_ids:
        mtd_gaps = [f for f in ("responsible_official", "version", "last_updated", "source_of_update")
                    if _is_missing_required_identity(mtd.get(f))]
        if mtd_gaps:
            blockers.append(f"CPO metadata unresolved (CPO-CSO-MTD): {', '.join(mtd_gaps)}")
    req_info = (cpo.get("xCpoRequiredInformation", {}) or {}).get("items", [])

    # Structured semantic completeness. A bare non-TBD sentence like "Public
    # information is documented." must NOT satisfy a rule that enumerates
    # concrete required items (CDS-CSO-PUB, CDS-CSO-IRP, MAS-CSO-TPR). For those
    # rules we derive the required members from CR26 and require the provider
    # content to be a structured object/array actually covering them; for
    # single-statement rules we keep the resolved (non-TBD) check.
    import re as _re_cpo

    def _cr26_following(rid):
        ds = load_json(os.path.join(BASE, "references", "fedramp-consolidated-rules.json"))

        def _find(node, target):
            if isinstance(node, dict):
                if target in node:
                    return node[target]
                for v in node.values():
                    r = _find(v, target)
                    if r is not None:
                        return r
            elif isinstance(node, list):
                for v in node:
                    r = _find(v, target)
                    if r is not None:
                        return r
            return None

        rule = _find(ds, rid) if ds else None
        return (rule or {}).get("following_information", []) or []

    # Rules whose required information is a structured object keyed by the CR26
    # following_information items (checked member-by-member).
    OBJECT_RULES = {"CDS-CSO-PUB"}
    # Rules whose required information is a non-empty array of records, each
    # covering the CR26 per-record fields.
    ARRAY_RULES = {"CDS-CSO-IRP", "MAS-CSO-TPR"}

    def _norm_key(item_text):
        # Reduce a CR26 following_information phrase to a stable key: take the
        # text before any parenthetical, lowercase, non-alnum -> underscore.
        base = _re_cpo.split(r"\(", str(item_text))[0].strip().lower()
        return _re_cpo.sub(r"[^a-z0-9]+", "_", base).strip("_")

    req_gaps = []
    struct_gaps = []
    for i in req_info:
        rid = i.get("rule")
        content = i.get("provider_content")
        if rid in OBJECT_RULES:
            required = [_norm_key(x) for x in _cr26_following(rid)]
            if not isinstance(content, dict):
                struct_gaps.append(f"{rid} content must be a structured object "
                                   f"covering its {len(required)} required items, "
                                   "not a single string")
                continue
            have = {_norm_key(k): v for k, v in content.items()}
            missing = [r for r in required if _is_hollow(have.get(r))]
            if missing:
                struct_gaps.append(f"{rid} missing/unresolved required item(s): "
                                   f"{', '.join(missing[:6])}"
                                   f"{'...' if len(missing) > 6 else ''}")
        elif rid in ARRAY_RULES:
            if not isinstance(content, list) or not content:
                struct_gaps.append(f"{rid} content must be a non-empty array of "
                                   "records covering each required field per entry")
                continue
            per_fields = [_norm_key(x) for x in _cr26_following(rid)]
            for idx, rec in enumerate(content):
                if not isinstance(rec, dict):
                    struct_gaps.append(f"{rid}[{idx}] must be a record object")
                    continue
                rk = {_norm_key(k): v for k, v in rec.items()}
                miss = [f for f in per_fields if _is_hollow(rk.get(f))]
                if miss:
                    struct_gaps.append(f"{rid}[{idx}] missing field(s): "
                                       f"{', '.join(miss[:6])}")
        else:
            if _is_hollow(content):
                req_gaps.append(rid)

    if struct_gaps:
        blockers.append("CPO required information is not structurally complete "
                        "(CPO-CSO-OVR references CR26 enumerated items): "
                        f"{'; '.join(struct_gaps)}")
    if req_gaps:
        blockers.append(f"CPO required information unresolved (CPO-CSO-OVR): "
                        f"{', '.join(str(r) for r in req_gaps)}")

    # document_review_needed: an applicable rule whose upstream family document
    # is in an unfamiliar/placeholder lifecycle state must be human-reviewed
    # before submission (fail safe, not silently treated as ordinary content).
    decisions = load_json(os.path.join(BASE, "traceability", "applicability-decisions.json")) or {}
    needs_doc_review = [d.get("rule_id") for d in decisions.get("decisions", [])
                        if d.get("applicable") and d.get("document_review_needed")]
    if needs_doc_review:
        sample = ", ".join(str(r) for r in needs_doc_review[:8])
        blockers.append(f"{len(needs_doc_review)} applicable rule(s) are in a family "
                        f"with an unfamiliar/placeholder document lifecycle state and "
                        f"need human review before submission: {sample}"
                        + (" ..." if len(needs_doc_review) > 8 else ""))

    # Package component that is required but not implemented (from the manifest).
    manifest_pkg = load_json(os.path.join(BASE, "package",
                                          "certification-package-manifest.json")) or {}
    for name, comp in (manifest_pkg.get("certification_package", {}) or {}).items():
        req = comp.get("required_for_initial_package")
        required_here = req is True or (isinstance(req, str) and cls.upper() in req.upper())
        if not required_here:
            continue
        status = comp.get("status")
        if status in ("partial", "not_implemented"):
            blockers.append(f"required package component '{name}' is "
                            f"'{status}' (a required component must be "
                            "complete, or its missing portion proven non-applicable "
                            "to this class, before submission)")
        elif status == "scaffold_implemented":
            # A generated scaffold is a template, not a finished artifact. It only
            # counts when the provider has supplied the real completed artifact by
            # reference. For the SCG (SCG-CSO-RSC), that reference is
            # offering.secure_config_guide_uri; a scaffold with no real external
            # artifact is a false-ready condition and must block.
            ext_ref = None
            machine_ref = None
            if name == "secure_configuration_guide":
                ext_ref = offering.get("secure_config_guide_uri")
                machine_ref = offering.get("secure_config_guide_machine_uri")
            if _is_tbd(ext_ref):
                blockers.append(f"required package component '{name}' is only a "
                                "generated scaffold and no completed external artifact "
                                "is referenced (supply the real completed artifact - "
                                "for the SCG, set offering.secure_config_guide_uri to "
                                "the published guide - before submission)")
            elif name == "secure_configuration_guide" and _is_tbd(machine_ref):
                # SCG-CSO-RSC (MUST) is satisfied by a published human-readable
                # Secure Configuration Guide; its substantive normative content is
                # the guide itself, referenced by offering.secure_config_guide_uri.
                # Providing that same guide in a MACHINE-READABLE format is a
                # SEPARATE rule, SCG-ENH-MRG, whose force is SHOULD ("Providers
                # SHOULD also provide the Secure Configuration Guide in a
                # machine-readable format ..."). A missing machine-readable URI
                # must therefore be a SHOULD-level advisory, NOT a package
                # blocker - blocking it would turn a FedRAMP SHOULD into a MUST.
                warnings.append(
                    "SCG-ENH-MRG (SHOULD): the Secure Configuration Guide has a "
                    "human-readable URI but no machine-readable URI; FedRAMP "
                    "recommends also providing the guide in machine-readable "
                    "format (set offering.secure_config_guide_machine_uri). This "
                    "is a recommendation, not a submission blocker.")

    # Package-level signoff MUST reference the current release-manifest hash.
    # One approved node in the assurance review register is NOT package approval.
    register = load_json(os.path.join(BASE, "sdr", "reviews", "review-register.json")) or {}
    signoff = register.get("package_signoff")
    manifest_path = os.path.join(BASE, "artifacts", "release-manifest.json")
    manifest = load_json(manifest_path) or {}
    manifest_tag = manifest.get("release_tag")
    # Cryptographic binding: the SHA-256 of the exact manifest bytes the human
    # signed. The tag (v1.0.0-cr26-...) can stay identical while provider facts,
    # evidence, CPO, or SDR contents change; the hash cannot.
    import hashlib as _hashlib
    actual_manifest_sha = None
    if os.path.isfile(manifest_path):
        with open(manifest_path, "rb") as _mf:
            actual_manifest_sha = "sha256:" + _hashlib.sha256(_mf.read()).hexdigest()
    if not signoff or signoff.get("decision") != "approved":
        blockers.append("no package_signoff recorded as approved "
                        "(package-level provider signoff is required to submit; "
                        "a single approved assurance node is not package approval)")
    else:
        signed_tag = signoff.get("release_tag") or signoff.get("release_manifest_tag")
        if manifest_tag and signed_tag != manifest_tag:
            blockers.append(f"package_signoff is for a different release "
                            f"({signed_tag}) than the current manifest ({manifest_tag}); "
                            f"re-sign against the current package")
        # The binding check: the signed manifest hash MUST equal the current one.
        signed_sha = signoff.get("package_manifest_sha256")
        if _is_tbd(signed_sha):
            blockers.append("package_signoff.package_manifest_sha256 not set "
                            "(the signoff must be bound to the exact manifest bytes)")
        elif actual_manifest_sha and signed_sha != actual_manifest_sha:
            blockers.append("package_signoff.package_manifest_sha256 does not match "
                            "the current release manifest; a generated artifact "
                            "changed since signoff - re-review and re-sign")
        for req in ("reviewer", "timestamp"):
            if _is_tbd(signoff.get(req)):
                blockers.append(f"package_signoff.{req} not set")

    # Application-scope prerequisites (application-preflight only): FedRAMP's
    # applying rules require the provider to already be listed in the FedRAMP
    # Marketplace and to complete the FedRAMP Certification Application Form.
    # These are NOT properties of the generated package, so package-preflight
    # does not check them; application-preflight does.
    scope = getattr(args, "command", "preflight")
    application_scope = scope in ("application-preflight", "preflight")
    if application_scope:
        app = offering.get("application_prerequisites") or {}
        if _is_tbd(app.get("marketplace_listing_uri")):
            blockers.append("application: provider is not confirmed listed in the "
                            "FedRAMP Marketplace (set application_prerequisites."
                            "marketplace_listing_uri)")
        if _is_tbd(app.get("application_form_reference")):
            blockers.append("application: FedRAMP Certification Application Form not "
                            "referenced (set application_prerequisites.application_form_reference)")
        # FRC-APP-NTP (MUST NOT): "Providers MUST NOT use a third party to apply
        # for a FedRAMP Certification on their behalf; this includes independent
        # assessment services." The provider itself must be the applicant. A
        # third party may PREPARE materials, but not submit the application.
        # This is a MUST NOT, so the gate is an AFFIRMATIVE boolean: the provider
        # must positively assert it is the applicant (provider_is_applicant ==
        # true). A free-form string cannot gate a MUST NOT - a truthful "No, our
        # assessor is submitting" is a non-empty string and would falsely pass an
        # existence-only check, admitting the exact case FRC-APP-NTP forbids. The
        # optional provider_is_applicant_attestation string stays as a human
        # evidence note but is no longer the gating condition.
        applicant_flag = app.get("provider_is_applicant")
        if applicant_flag is not True:
            if applicant_flag is False:
                blockers.append("application: provider_is_applicant is false - a third "
                                "party (incl. an assessor) MUST NOT apply on the "
                                "provider's behalf (FRC-APP-NTP). The CSP itself must "
                                "be the applicant; set application_prerequisites."
                                "provider_is_applicant: true")
            else:
                blockers.append("application: no affirmative provider-is-applicant "
                                "attestation (FRC-APP-NTP MUST NOT use a third party, "
                                "incl. an assessor, to apply on the provider's behalf; "
                                "set application_prerequisites.provider_is_applicant: "
                                "true - a boolean, not a description)")

    out()
    label = ("FedRAMP APPLICATION preflight" if scope == "application-preflight"
             else "FedRAMP PACKAGE preflight" if scope == "package-preflight"
             else "FedRAMP submission preflight")
    out(f"{label} (Class {cls.upper()})")
    out(RULE)
    if blockers:
        out(f"SUBMISSION BLOCKERS ({len(blockers)}):")
        for b in blockers:
            out(f"    [BLOCK] {b}")
    if warnings:
        out(f"Warnings ({len(warnings)}):")
        for w in warnings:
            out(f"    [WARN]  {w}")
    out()
    if blockers:
        out("NOT ready. Resolve the blockers above. This is a readiness check, "
            "not a compliance determination; FedRAMP and its recognized assessor "
            "determine compliance.")
        return 1
    if scope == "package-preflight":
        out("Package ready: the generated Certification Package has no blockers "
            "(required fields filled, fresh provider verification, package-level "
            "signoff bound to the current manifest). This is NOT an application-"
            "readiness statement - run `sdr.py application-preflight` to also "
            "check Marketplace listing and the application form. Not a compliance "
            "or certification claim.")
    else:
        out("Application ready: no blockers found - the package is complete and "
            "the FedRAMP application prerequisites (Marketplace listing, "
            "application form) are referenced. This does NOT mean compliant or "
            "certified; that is FedRAMP's determination.")
    return 0


def cmd_clean(args):
    """Remove regenerable local clutter only.

    Deliberately does not delete generated deliverables. They are committed on
    purpose, because the repository ships as a working template that someone
    should be able to read before they can run anything.
    """
    removed = []
    for root, dirs, _files in os.walk(BASE):
        if ".git" in root.split(os.sep):
            continue
        for d in list(dirs):
            if d == "__pycache__":
                shutil.rmtree(os.path.join(root, d), ignore_errors=True)
                removed.append(os.path.relpath(os.path.join(root, d), BASE))
                dirs.remove(d)
    scan_dir = os.path.dirname(SCAN_REPORT_GLOB)
    if os.path.isdir(scan_dir):
        shutil.rmtree(scan_dir, ignore_errors=True)
        removed.append(os.path.relpath(scan_dir, BASE))
    for log in glob.glob(os.path.join(BASE, "*.log")):
        os.remove(log)
        removed.append(os.path.relpath(log, BASE))

    if removed:
        out(f"Removed {len(removed)} items:")
        for item in sorted(removed):
            out(f"    {item}")
    else:
        out("Nothing to remove.")
    out()
    out("Generated deliverables were left in place. They are committed on "
        "purpose. To prove they are reproducible, run `python sdr.py build` "
        "and then `git diff`; an empty diff is the guarantee.")
    return 0


def summary():
    """Print what a reader actually wants after a run: am I ready, and how far off."""
    out()
    out("Readiness summary")
    out(RULE)
    cls = current_class()
    out(f"Certification class          Class {cls}")

    report = load_json(VALIDATION_REPORT)
    if report is None:
        out("Build gate                   no report found")
    else:
        hard = report.get("hard_failures", "?")
        checks = report.get("checks", [])
        passed = sum(1 for c in checks if c.get("result") == "PASS")
        # The report now labels non-hard shortfalls ADVISORY (hard failures are
        # FAIL), so severity is explicit rather than inferred from the hard count.
        soft = [c["check"] for c in checks if c.get("result") == "ADVISORY"]
        # "Ready" is reserved for submission preflight. The build gate answers
        # only "is this structurally valid and faithful to the dataset", so it
        # reports a structural verdict, not a shippability one.
        verdict = ("BUILD PASS - structurally valid" if hard == 0
                   else "BUILD BLOCKED")
        out(f"Build gate                   {verdict}, hard failures: {hard}")
        out(f"Checks                       {passed} of {len(checks)} passing")
        if hard == 0 and soft:
            out(f"Advisory failures            {', '.join(soft)}")
        if hard == 0:
            out("Submission readiness         run `python sdr.py package-preflight` "
                "(structural pass is not submission-ready)")
        out(f"Dataset                      {report.get('generated', 'unknown')}")

    scan_files = sorted(glob.glob(SCAN_REPORT_GLOB))
    if not scan_files:
        out("Assessment readiness         not scanned")
    else:
        scan = load_json(scan_files[-1]) or {}
        s = scan.get("summary", {})
        if s:
            out(f"Assessment readiness         {s.get('readiness_percent', '?')}% "
                f"({s.get('pass', '?')} pass, {s.get('fail', '?')} fail, "
                f"{s.get('manual', '?')} manual of {s.get('total', '?')} findings)")
    out()
    out("Next step: open sdr/records/records-store.json and replace the "
        "placeholders for the rules and indicators you own. "
        "See docs/implementation-guide.md.")


def cmd_all(args):
    code = cmd_build(args)
    if code != 0:
        return code
    out()
    code = cmd_validate(args)
    validate_failed = code != 0
    out()
    scan_code = cmd_scan(args)
    summary()
    if validate_failed:
        return 1
    return 0 if scan_code == 0 else 1


def build_parser():
    p = argparse.ArgumentParser(
        prog="sdr.py",
        description="Build, validate and scan a FedRAMP 20x Security Decision Record.",
        epilog="Run `python sdr.py all` first. Everything else is a subset of it.",
    )
    sub = p.add_subparsers(dest="command")

    init_p = sub.add_parser(
        "init", help="fill the offering profile by answering plain questions")
    init_p.add_argument("--non-interactive", action="store_true",
                        help="do not prompt; only apply --set values")
    init_p.add_argument("--set", action="append", metavar="KEY=VALUE",
                        help="set a profile field non-interactively (repeatable)")

    sub.add_parser("build", help="regenerate every deliverable from the record store")
    val_p = sub.add_parser("validate", help="run the full gate + offline test suite (CI parity)")
    val_p.add_argument("--no-tests", action="store_true",
                       help="run validators only, skip the offline test suite (faster)")

    scan = sub.add_parser("scan", help="run the readiness scanner (reports, does not gate)")
    scan.add_argument("--only-fails", action="store_true",
                      help="report only open findings, omitting what already passes")

    all_p = sub.add_parser("all", help="build, validate, scan, then summarize")
    all_p.add_argument("--only-fails", action="store_true",
                       help="passed through to the scanner")
    all_p.add_argument("--no-tests", action="store_true",
                       help="skip the offline test suite in the validate step")

    sub.add_parser("clean", help="remove caches and scanner reports")

    explain_p = sub.add_parser(
        "explain", help="explain one rule or KSI in plain language (grounded in the dataset)")
    explain_p.add_argument("identifier", help="a rule id (FRC-CSO-PKG) or KSI id (KSI-CNA-RNT)")

    diff_p = sub.add_parser("diff", help="show what a dataset change would affect (read-only)")
    diff_p.add_argument("old", nargs="?", help="old dataset JSON (optional)")
    diff_p.add_argument("new", nargs="?", help="new dataset JSON (optional)")
    review_p = sub.add_parser(
        "review",
        help="report the human review register (default, read-only), or decide pending "
             "field proposals (--list / --walk / --decisions / --accept-all prefill)")
    review_p.add_argument("--list", action="store_true",
                          help="list pending proposals from the prefill and AI-draft sidecars "
                               "and the template's labelled examples (read-only)")
    review_p.add_argument("--walk", action="store_true",
                          help="decide each pending proposal interactively: accept, edit, "
                               "reject or skip (needs --reviewer and --role)")
    review_p.add_argument("--decisions", metavar="FILE",
                          help="apply decisions from a JSON file "
                               "{\"frr/<ID>.implementation\": {\"decision\": \"accepted\"}, ...}")
    review_p.add_argument("--accept-all", metavar="SOURCE", dest="accept_all",
                          help="accept every pending proposal from one source; only "
                               "'prefill' (deterministic collector facts) is allowed")
    review_p.add_argument("--source", choices=["prefill", "ai-draft", "template-example"],
                          help="restrict to proposals from one source")
    review_p.add_argument("--only", metavar="PREFIX",
                          help="restrict to field keys starting with PREFIX, e.g. frr/AFC-")
    review_p.add_argument("--reviewer", help="the named human making the decisions")
    review_p.add_argument("--role", help="that person's role")
    rel_p = sub.add_parser("release", help="build, run the full gate + reproducibility, print the tag")
    sub.add_parser("preflight", help="alias for application-preflight (read-only)")
    sub.add_parser("package-preflight", help="check the generated package for submission blockers (read-only)")
    sub.add_parser("application-preflight", help="package checks PLUS FedRAMP application prerequisites (read-only)")
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    if not hasattr(args, "only_fails"):
        args.only_fails = False
    if not hasattr(args, "no_tests"):
        args.no_tests = False
    handlers = {
        "build": cmd_build,
        "init": cmd_init,
        "validate": cmd_validate,
        "scan": cmd_scan,
        "all": cmd_all,
        "clean": cmd_clean,
        "explain": cmd_explain,
        "diff": cmd_diff,
        "review": cmd_review,
        "release": cmd_release,
        "preflight": cmd_preflight,
        "package-preflight": cmd_preflight,
        "application-preflight": cmd_preflight,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())







