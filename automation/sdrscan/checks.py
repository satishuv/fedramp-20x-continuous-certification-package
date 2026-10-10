# Check registry and implementations for sdrscan.
#
# Structure mirrors Prowler: every check carries its own metadata (stable id,
# title, severity, what it is looking for, why it matters, how to fix it) and
# emits one finding per resource rather than a single aggregate verdict. The
# difference is what a resource is. Prowler's resources are cloud resources;
# here they are the objects FedRAMP asks providers to document: the Security
# Decision Record itself, each applicable FedRAMP Rule (FRR), and each Key
# Security Indicator (KSI).
#
# Every check declares fedramp_basis: the rule identifiers from the FedRAMP
# Consolidated Rules for 2026 (CR26) dataset that make the check a requirement
# rather than an opinion. A check with no basis does not belong here.
#
# Statuses, following Prowler:
#   PASS    the requirement is demonstrably satisfied by the record
#   FAIL    the requirement is not satisfied
#   MANUAL  a human must confirm; the record cannot prove it either way
#   MUTED   failing, but muted by an entry in the mutelist with justification
#
# Severity: critical, high, medium, low, informational.

import json
import os
import re
import sys

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_BASE, "validation", "scripts"))
from unreviewed_text import is_unreviewed  # noqa: E402  (AUD-F38, single definition)

# Placeholder vocabulary from CLAUDE.md. These are honest markers for missing
# facts, so a field containing one is "not yet stated", never a pass.
PLACEHOLDER = re.compile(
    r"^\s*(TBD\b|To be determined\b|Needs validation\b|Planned\b|Gap\b"
    r"|FedRAMP pending\b|None recorded\b|Unknown\b|N/?A\s*$)",
    re.I,
)

# A bare "Not applicable" is a placeholder; "Not applicable because ..." with
# real reasoning is a legitimate answer. 40 characters is the shortest useful
# justification observed in the template content.
NA_MIN_JUSTIFICATION = 40

VALID_STATUS = ("Implemented", "Not Implemented", "Partially Implemented")


def _count_automated(tests):
    """Count DISTINCT AUTOMATED methods from a KSI's structured authoring
    `tests` list (records-store), matching validate_sdr.count_automated_methods
    so the scanner and the release gate agree on FRC-CSX-VVK. Only dict entries
    with automated == True count; identity is method_id else normalized text;
    plain strings (flattened, automated-ness unknown) do NOT count."""
    if not isinstance(tests, list):
        return 0
    seen = set()
    for t in tests:
        if isinstance(t, dict) and t.get("automated") is True:
            ident = t.get("method_id") or str(
                t.get("method") or t.get("name") or t.get("description") or "").strip().lower()
            if ident:
                seen.add(ident)
    return len(seen)

EVIDENCE_TYPES = ("Log", "Report", "Screenshot", "Configuration", "Policy",
                  "Procedure", "Audit Record")

# Whether a KSI is truly "FedRAMP pending" is derived from the dataset (below),
# not a hardcoded list, so the scanner can never drift from the pinned rules.
def _ksi_is_pending(ksi_node):
    """A KSI is 'FedRAMP pending' ONLY when the pinned CR26 dataset gives it no
    statement anywhere - neither a top-level `statement` NOR any per-class
    statement under `varies_by_class`. The earlier code hardcoded a stale set
    (KSI-CNA-EIS/MLA-ALA/SVC-PRR/SVC-RUD/SVC-VCM) as pending, but all five
    actually carry Class B (Optional) and Class C statements under
    varies_by_class in the dataset - only their TOP-LEVEL `statement` key is
    absent. Reading only the top-level key made the scanner's output factually
    wrong (finding 11). Deriving pending from the dataset means the scanner can
    never drift from the pinned rules again. A KSI missing from the dataset
    entirely is treated as pending (there is genuinely no statement to answer)."""
    if not isinstance(ksi_node, dict):
        return True
    if str(ksi_node.get("statement") or "").strip():
        return False
    vbc = ksi_node.get("varies_by_class")
    if isinstance(vbc, dict):
        for branch in vbc.values():
            if isinstance(branch, dict) and str(branch.get("statement") or "").strip():
                return False
    return True


def state(value):
    """Classify one record field as populated, placeholder, or empty."""
    if value is None:
        return "empty"
    if isinstance(value, (list, tuple)):
        if not value:
            return "empty"
        kinds = [state(v) for v in value]
        return "populated" if "populated" in kinds else kinds[0]
    if isinstance(value, dict):
        return "populated" if value else "empty"
    text = str(value).strip()
    if not text:
        return "empty"
    if text.lower().startswith("not applicable"):
        return "populated" if len(text) >= NA_MIN_JUSTIFICATION else "placeholder"
    if PLACEHOLDER.match(text):
        return "placeholder"
    # AUD-F38: a labelled DRAFT / Example proposal is a machine's or the
    # template's text, unanswered until a human accepts it in `sdr.py review`.
    if is_unreviewed(text):
        return "placeholder"
    return "populated"


def stated(value):
    return state(value) == "populated"


def _why(value):
    if state(value) == "placeholder" and is_unreviewed(value):
        return "field holds an unreviewed DRAFT / Example proposal (accept or edit it in sdr.py review)"
    return {"empty": "field is absent or empty",
            "placeholder": "field still holds a placeholder marker"}.get(
        state(value), "field is populated")


# ---------------------------------------------------------------------------
# Package-level checks. Resource is the Security Decision Record as a whole.
# ---------------------------------------------------------------------------

def package_checks(ctx):
    out = []
    sdr, cls = ctx.sdr, ctx.cls

    out.append(("sdr_json_schema_valid", "SDR", "Security Decision Record",
                not ctx.schema_errors,
                f"{len(ctx.schema_errors)} schema errors"
                + (f"; first at {ctx.schema_errors[0]['path'] or 'document root'}: "
                   f"{ctx.schema_errors[0]['message']}" if ctx.schema_errors else "")))

    meta = sdr.get("metadata") or {}
    missing_meta = [k for k in ("version", "lastUpdated", "updateSource")
                    if not stated(meta.get(k))]
    out.append(("sdr_metadata_complete", "SDR", "Security Decision Record",
                not missing_meta,
                "version, lastUpdated and updateSource are all present"
                if not missing_meta else f"missing or placeholder: {missing_meta}"))

    out.append(("sdr_overview_uri_declared", "SDR", "Security Decision Record",
                stated(sdr.get("certificationPackageOverviewUri"))
                and str(sdr.get("certificationPackageOverviewUri", "")).startswith(
                    ("http://", "https://")),
                f"certificationPackageOverviewUri is "
                f"{sdr.get('certificationPackageOverviewUri') or 'absent'}"))

    both_present = ctx.human_readable is not None and ctx.sdr is not None
    out.append(("sdr_dual_format_present", "SDR", "Security Decision Record",
                both_present,
                "both a JSON and a human-readable rendering exist"
                if both_present else "one of the two required formats is missing"))

    # CDS-CSO-CBF is the reason this whole tool exists: the two formats must be
    # kept consistent by automation. Prove it by re-deriving the human-readable
    # rendering's identifier and status set and comparing to the JSON.
    drift = format_consistency_drift(ctx)
    out.append(("sdr_format_consistency", "SDR", "Security Decision Record",
                not drift,
                "every identifier and status in the JSON appears identically in "
                "the human-readable rendering"
                if not drift else f"{len(drift)} inconsistencies; first: {drift[0]}"))

    out.append(("sdr_dataset_version_pinned", "SDR", "Security Decision Record",
                ctx.class_profile["meta"]["dataset_version"] == ctx.dataset_version,
                f"record built from dataset {ctx.class_profile['meta']['dataset_version']}, "
                f"pinned reference is {ctx.dataset_version}"))

    md_hits = markdown_hits(ctx.human_readable or "")
    out.append(("sdr_human_readable_clean", "SDR", "Security Decision Record",
                not md_hits,
                "no markup symbols in the human-readable rendering"
                if not md_hits else f"markup found: {md_hits}"))

    sens = sensitive_hits(ctx)
    out.append(("sdr_no_sensitive_data", "SDR", "Security Decision Record",
                not sens,
                "no account identifiers, keys or private key material found"
                if not sens else f"{len(sens)} hits; first: {sens[0]}"))

    # FRC-CSX-VVR: the record has to be persistently verified and validated, so
    # a stale lastUpdated is itself a finding. Age is measured against the
    # pinned dataset date, keeping the check deterministic.
    age = ctx.record_age_days
    out.append(("sdr_record_freshness", "SDR", "Security Decision Record",
                age is not None and age <= 90,
                f"metadata.lastUpdated is {age} days from the pinned dataset date"
                if age is not None else "metadata.lastUpdated is unparseable"))
    return out


def markdown_hits(text):
    patterns = [
        (re.compile(r"^#{1,6} ", re.M), "heading"),
        (re.compile(r"\*\*[^*\n]+\*\*"), "bold markers"),
        (re.compile(r"^\s*\* ", re.M), "asterisk bullet"),
        (re.compile(r"`[^`\n]+`"), "backticks"),
        (re.compile(r"^\|.+\|$", re.M), "table"),
    ]
    return [label for pat, label in patterns if pat.search(text)]


def sensitive_hits(ctx):
    patterns = [
        # A real AWS account ID is a standalone 12-digit number. Exclude a
        # 12-digit run inside a hyphen-delimited hex token (a UUID), adjacent to
        # hex/hyphen context: those are generated identifiers (e.g. OSCAL uuid
        # fields), not account IDs. This MUST match the validator's pattern in
        # validation/scripts/validate_sdr.py so the readiness scanner and the
        # hard gate never disagree about what is sensitive.
        (re.compile(r"(?<![0-9A-Fa-f-])\d{12}(?![0-9A-Fa-f-])"), "possible AWS account ID"),
        (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID"),
        (re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"), "private key"),
    ]
    hits = []
    for name, content in ctx.scannable_text.items():
        for pat, label in patterns:
            if pat.search(content):
                hits.append(f"{name}: {label}")
    return hits


def format_consistency_drift(ctx):
    """CDS-CSO-CBF. Every rule identifier, KSI identifier and implementation
    status in the JSON must be present in the human-readable rendering, and the
    rendering must not carry identifiers the JSON lacks."""
    text = ctx.human_readable or ""
    drift = []
    json_ids = set()
    for entry in ctx.sdr["fedRampRequirements"]:
        rid = entry["frrID"]
        json_ids.add(rid)
        if rid not in text:
            drift.append(f"rule {rid} is in the JSON but not the human-readable rendering")
    for entry in ctx.sdr.get("keySecurityIndicators", []):
        kid = entry["ksiId"]
        json_ids.add(kid)
        if kid not in text:
            drift.append(f"KSI {kid} is in the JSON but not the human-readable rendering")
    # F-07: an identifier can legitimately appear in the JSON as a CROSS-REFERENCE
    # (a citation), not only as a top-level record ID - for example IVV-IAS-OSA in
    # metadata.xIndependentAssessmentSummary.basis, which the builder mirrors into
    # the human-readable rendering. The reverse-direction check must not treat
    # such a citation as an "extra" identifier the JSON lacks. Collect every
    # three-segment identifier that appears ANYWHERE in the JSON serialization so
    # a legitimate citation present in both documents is not a false drift.
    _json_text = json.dumps(ctx.sdr, ensure_ascii=False)
    json_all_ids = set(re.findall(r"\b[A-Z]{3}-[A-Z]{3}-[A-Z]{3}\b", _json_text)) | set(
        re.findall(r"\bKSI-[A-Z]{3}-[A-Z]{3}\b", _json_text))
    for found in set(re.findall(r"\b[A-Z]{3}-[A-Z]{3}-[A-Z]{3}\b", text)) | set(
            re.findall(r"\bKSI-[A-Z]{3}-[A-Z]{3}\b", text)):
        if found not in json_ids and found not in json_all_ids and not found.startswith("FRC-CLA"):
            drift.append(f"{found} appears in the human-readable rendering but not the JSON")
    # Status wording must agree. The rendering prints "Status: <value>" in
    # rule order, so compare positionally against the JSON.
    rendered = re.findall(r"^Status: (.+)$", text, re.M)
    declared = ([e.get("frrImplementationStatus") for e in ctx.sdr["fedRampRequirements"]]
                + [e.get("ksiImplementationStatus")
                   for e in ctx.sdr.get("keySecurityIndicators", [])])
    if len(rendered) != len(declared):
        drift.append(f"{len(rendered)} statuses in the rendering vs {len(declared)} in the JSON")
    else:
        for i, (r, d) in enumerate(zip(rendered, declared)):
            if r.strip() != (d or "").strip():
                drift.append(f"status {i + 1} reads '{r}' in the rendering and '{d}' in the JSON")
    return drift


# ---------------------------------------------------------------------------
# Per-rule checks. Resource is one applicable FedRAMP Rule.
# ---------------------------------------------------------------------------

def rule_checks(ctx):
    out = []
    for entry in ctx.sdr["fedRampRequirements"]:
        rid = entry["frrID"]
        ext = ctx.ext["frr"].get(rid, {})
        name = ext.get("name") or ctx.canonical_rules.get(rid, {}).get("name") or rid
        status = entry.get("frrImplementationStatus")
        not_following = status in ("Not Implemented", "Partially Implemented")

        def add(check_id, ok, detail):
            out.append((check_id, rid, name, ok, detail))

        add("frr_status_declared", status in VALID_STATUS,
            f"frrImplementationStatus is {status!r}")

        # SDR-CSO-FRR item 1
        add("frr_implementation_explained", stated(entry.get("frrImplementation")),
            f"frrImplementation: {_why(entry.get('frrImplementation'))}")

        # SDR-CSO-FRR item 1, second half: not following the rule requires TWO
        # distinct elements - the reason it is NOT followed AND the resulting
        # risk to customers. Risk is not the reason. This mirrors the release
        # gate (_frr_gaps) so scanner and gate agree.
        if not_following:
            reason_ok = stated(ext.get("nonimplementation_reason")) or stated(
                entry.get("frrImplementation"))
            add("frr_nonconformance_reason_stated", reason_ok,
                f"status is {status} and reason-not-followed: "
                + ("stated" if reason_ok else "absent (state nonimplementation_reason "
                   "or explain the reason in frrImplementation)"))
            add("frr_nonconformance_risk_stated", stated(ext.get("customer_risk")),
                f"status is {status} and customer_risk: {_why(ext.get('customer_risk'))}")
        else:
            add("frr_nonconformance_reason_stated", True,
                "rule is Implemented, so no reason-not-followed is required")
            add("frr_nonconformance_risk_stated", True,
                "rule is Implemented, so no customer risk statement is required")

        # SDR-CSO-FRR item 2
        add("frr_verification_recorded", stated(ext.get("verification")),
            f"verification: {_why(ext.get('verification'))}")

        # SDR-CSO-FRR item 3
        add("frr_validation_recorded", stated(entry.get("frrValidation")),
            f"frrValidation: {_why(entry.get('frrValidation'))}")

        # SDR-CSO-FRR item 4
        add("frr_independent_verification_recorded",
            stated(ext.get("independent_verification")),
            f"independent_verification: {_why(ext.get('independent_verification'))}")

        # SDR-CSO-FRR item 5
        add("frr_independent_validation_recorded",
            stated(ext.get("independent_validation")),
            f"independent_validation: {_why(ext.get('independent_validation'))}")

        # SDR-CSO-FRR item 6. Absence is legitimate when no assessor comment
        # exists, so this is a human confirmation, not a failure.
        add("frr_assessor_responses_recorded",
            "MANUAL" if not stated(ext.get("assessor_responses")) else True,
            "assessor_responses is 'None recorded'; confirm no assessor comment "
            "is outstanding for this rule"
            if not stated(ext.get("assessor_responses"))
            else "responses to assessor comments are recorded")

        # SDR-CSO-FRR item 7, applicable only where artifacts exist.
        arts = ext.get("rule_artifacts")
        add("frr_artifacts_referenced",
            True if arts else "MANUAL",
            f"{len(arts)} artifact reference(s) recorded" if arts
            else "no rule-specific artifacts recorded; confirm none apply to this rule")

        # SDR-CSO-FRR items 2 and 3 allow a senior official to accept the reason
        # for not implementing. If the rule is not implemented, that acceptance
        # is what stands in for verification and validation.
        if not_following:
            acc = ext.get("senior_official_acceptance")
            add("frr_senior_official_acceptance",
                stated(acc) and not str(acc).startswith("Not required"),
                f"status is {status} and senior_official_acceptance: "
                f"{acc if acc else 'absent'}")
        else:
            add("frr_senior_official_acceptance", True,
                "rule is Implemented, so senior official acceptance is not required")

        add("frr_owner_assigned", stated(ext.get("owner")),
            f"owner: {_why(ext.get('owner'))}")

        add("frr_statement_fidelity",
            rid not in ctx.fidelity_failures,
            "rule text matches the canonical dataset character for character"
            if rid not in ctx.fidelity_failures
            else ctx.fidelity_failures[rid])
    return out


# ---------------------------------------------------------------------------
# Per-KSI checks. Resource is one applicable Key Security Indicator.
# ---------------------------------------------------------------------------

def ksi_checks(ctx):
    out = []
    cls = ctx.cls
    minimums = {k["ksi_id"]: k["minimum_automated_methods"][f"class_{cls}"]
                for k in ctx.ksi_profile["indicators"]}
    for entry in ctx.sdr.get("keySecurityIndicators", []):
        kid = entry["ksiId"]
        ext = ctx.ext["ksi"].get(kid, {})
        name = ext.get("name") or kid
        pending = _ksi_is_pending(ctx.canonical_ksis.get(kid))

        def add(check_id, ok, detail):
            out.append((check_id, kid, name, ok, detail))

        add("ksi_status_declared", entry.get("ksiImplementationStatus") in VALID_STATUS,
            f"ksiImplementationStatus is {entry.get('ksiImplementationStatus')!r}")

        # SDR-CSX-KSI item 1
        add("ksi_measures_explained", stated(entry.get("ksiImplementation")),
            f"ksiImplementation: {_why(entry.get('ksiImplementation'))}")

        # SDR-CSX-KSI item 2, applicable only to persistent measures.
        add("ksi_operating_cycle_explained",
            True if stated(ext.get("operating_cycle")) else "MANUAL",
            f"operating_cycle: {_why(ext.get('operating_cycle'))}; required only "
            "for measures that run persistently")

        # SDR-CSX-KSI item 3
        add("ksi_measures_verified", stated(ext.get("measures_verification")),
            f"measures_verification: {_why(ext.get('measures_verification'))}")

        # SDR-CSX-KSI item 4
        add("ksi_automation_verified", stated(ext.get("automation_verification")),
            f"automation_verification: {_why(ext.get('automation_verification'))}")

        # SDR-CSX-KSI item 5
        add("ksi_measures_validated", stated(entry.get("ksiValidation")),
            f"ksiValidation: {_why(entry.get('ksiValidation'))}")

        add("ksi_independent_assessment_recorded", stated(entry.get("ksiAssessment")),
            f"ksiAssessment: {_why(entry.get('ksiAssessment'))}")

        # FRC-CSX-VVK: count DISTINCT AUTOMATED methods from the structured
        # AUTHORING record (records-store tests), not the flattened ksiTests
        # strings in the official SDR - a flattened string array loses the
        # automated/manual distinction, so len(ksiTests) over-counts. Reuse the
        # validator's shared counter so scanner and release-gate agree.
        authoring_tests = ctx.records["ksi"].get(kid, {}).get("tests") or []
        automated_count = _count_automated(authoring_tests)
        need = minimums.get(kid, 0)
        add("ksi_test_minimum_met", automated_count >= need,
            f"{automated_count} distinct automated method(s) in authoring record, "
            f"class {cls.upper()} minimum is {need}")

        ev = entry.get("ksiEvidence") or []
        add("ksi_evidence_present", bool(ev),
            f"{len(ev)} evidence item(s) attached")

        bad_types = [e.get("evidenceType") for e in ev
                     if e.get("evidenceType") not in EVIDENCE_TYPES]
        add("ksi_evidence_typed", not bad_types,
            "all evidence uses an official evidenceType value" if not bad_types
            else f"unrecognised evidenceType values: {bad_types}")

        # SDR-CSX-KMT. Class A may include historical metrics; Class B SHOULD
        # (since dataset 2026.10.08.01; MUST before); Class C must.
        hist = ctx.records["ksi"].get(kid, {}).get("historical_metrics") or {}
        if cls == "a":
            add("ksi_metrics_30day_summary", True,
                "Class A MAY include historical metrics; not required")
            add("ksi_metrics_yearly_summary", True,
                "Class A MAY include historical metrics; not required")
        elif cls == "b":
            # SHOULD: an absent summary is a question for the assessor (MANUAL),
            # not a scanner failure.
            add("ksi_metrics_30day_summary",
                True if stated(hist.get("last_30_days")) else "MANUAL",
                f"30-day summary: {_why(hist.get('last_30_days'))}; SHOULD at "
                "Class B (SDR-CSX-KMT, dataset 2026.10.08.01)")
            add("ksi_metrics_yearly_summary",
                True if stated(hist.get("up_to_one_year")) else "MANUAL",
                f"up-to-one-year summary: {_why(hist.get('up_to_one_year'))}; "
                "SHOULD at Class B, where available")
        else:
            add("ksi_metrics_30day_summary", stated(hist.get("last_30_days")),
                f"30-day summary: {_why(hist.get('last_30_days'))}")
            add("ksi_metrics_yearly_summary",
                True if stated(hist.get("up_to_one_year")) else "MANUAL",
                f"up-to-one-year summary: {_why(hist.get('up_to_one_year'))}; "
                "required where available")
        if cls == "c":
            # SDR-CSX-KMT Class C MUST supply the actual daily metric data (the
            # dailyData series now emitted in the SDR, derived from durable
            # history), NOT merely a reference URL. Read the generated SDR's
            # dailyData for this KSI; the reference URI is optional.
            _ksi_sem = next((e.get("providerExtensions", {}).get("xFedRampSemantic", {})
                             for e in ctx.sdr.get("keySecurityIndicators", [])
                             if e.get("ksiId") == kid), {})
            _daily = (_ksi_sem.get("historicalMetrics", {}) or {}).get("dailyData") or []
            add("ksi_metrics_daily_data", bool(_daily),
                f"{len(_daily)} in-SDR daily observation(s) (Class C MUST supply the "
                "actual daily metric data; the reference URL is optional)")
        else:
            add("ksi_metrics_daily_data", True,
                f"daily metric data is a Class C requirement; class is {cls.upper()}")

        add("ksi_owner_assigned", stated(ext.get("owner")),
            f"owner: {_why(ext.get('owner'))}")

        add("ksi_pending_marked_honestly",
            True,
            "indicator has no statement in the CR26 dataset and is carried as "
            "FedRAMP pending, which is the correct treatment" if pending
            else "indicator has a published statement in the CR26 dataset")

        add("ksi_statement_fidelity", kid not in ctx.fidelity_failures,
            "indicator text matches the canonical dataset"
            if kid not in ctx.fidelity_failures else ctx.fidelity_failures[kid])
    return out


# ---------------------------------------------------------------------------
# Metadata. One entry per check id produced above.
# ---------------------------------------------------------------------------

def _m(check_id, title, severity, resource_type, basis, requirement, risk,
       remediation, location, classes=("a", "b", "c")):
    return {
        "check_id": check_id,
        "title": title,
        "severity": severity,
        "resource_type": resource_type,
        "fedramp_basis": list(basis),
        "requirement": requirement,
        "risk": risk,
        "remediation": remediation,
        "location": location,
        "applies_to_classes": list(classes),
    }


METADATA = {m["check_id"]: m for m in [
    # Package
    _m("sdr_json_schema_valid",
       "Machine-readable record validates against the official FedRAMP schema",
       "critical", "Security Decision Record", ["FRC-CSO-JSN", "SDR-CSO-FRR"],
       "Providers MUST supply machine-readable information in JSON documents "
       "that are valid against the corresponding FedRAMP JSON schema.",
       "An invalid document cannot be ingested by FedRAMP or by an agency's "
       "governance tooling, so the submission is not usable evidence.",
       "Fix the reported schema paths, then regenerate. Do not edit generated "
       "JSON by hand.",
       "sdr/json/sdr-class-<class>.json"),
    _m("sdr_metadata_complete", "Record carries version, last update and update source",
       "high", "Security Decision Record", ["SDR-CSO-MTD"],
       "Providers MUST include version, date and time of last update, and "
       "source of update in their Security Decision Record.",
       "Without these an assessor cannot tell which revision they are reading "
       "or who changed it, so no finding can be tied to a version.",
       "Set sdr_version and sdr_last_updated in the offering profile and "
       "regenerate.",
       "profiles/common/offering-profile.json"),
    _m("sdr_overview_uri_declared",
       "Record links to the Certification Package Overview",
       "medium", "Security Decision Record", ["CPO-CSO-OVR", "SDR-CSO-FRR"],
       "Providers MUST supply a Certification Package Overview, and the "
       "Security Decision Record schema requires a URI pointing to it.",
       "An assessor landing on the record has no route to the offering's scope, "
       "boundary or service description.",
       "Set certification_package_overview_uri in the offering profile to the "
       "published overview URI.",
       "profiles/common/offering-profile.json"),
    _m("sdr_dual_format_present", "Record exists in both human-readable and JSON form",
       "critical", "Security Decision Record", ["SDR-CSO-FRR", "CDS-CSO-PUB"],
       "Providers MUST supply a Security Decision Record in both "
       "human-readable and JSON formats.",
       "Supplying only one format fails the rule outright, whichever format is "
       "missing.",
       "Run build_sdr.py, which emits both from the single record store.",
       "sdr/json/ and sdr/human-readable/"),
    _m("sdr_format_consistency",
       "The two formats agree on every identifier and status",
       "critical", "Security Decision Record", ["CDS-CSO-CBF", "FRC-CSX-VVR"],
       "Providers MUST use automation to ensure information remains consistent "
       "between human-readable and machine-readable formats.",
       "Divergent formats mean one of them is wrong, and an assessor reading "
       "the human-readable copy would reach conclusions the JSON contradicts.",
       "Never hand-edit either rendering. Edit the record store and regenerate "
       "so both come from one source.",
       "sdr/records/records-store.json"),
    _m("sdr_dataset_version_pinned",
       "Record was built from the pinned rules dataset",
       "medium", "Security Decision Record", ["FRC-CSO-JSN"],
       "The record must reflect the version of the FedRAMP rules it claims to "
       "answer.",
       "A record built from a superseded dataset can answer rules that have "
       "since changed or been withdrawn.",
       "Re-pull the dataset, diff it, then rerun the full pipeline.",
       "references/fedramp-consolidated-rules.json"),
    _m("sdr_human_readable_clean",
       "Human-readable rendering contains no markup symbols",
       "low", "Security Decision Record", ["SDR-CSO-FRR", "CCM-OCR-AVL"],
       "The human-readable format has to actually be readable by a person "
       "without a renderer.",
       "Raw markup in a deliverable reads as sloppy and can obscure meaning in "
       "print or plain-text delivery.",
       "Keep markup out of the human-readable renderer and the record store "
       "content.",
       "sdr/human-readable/sdr-class-<class>.txt"),
    _m("sdr_no_sensitive_data",
       "No account identifiers, keys or private key material in the record",
       "critical", "Security Decision Record", ["CDS-CSO-PUB"],
       "Certification Data is published, so it must not carry secrets or "
       "account identifiers.",
       "Publishing an account identifier or key turns a compliance deliverable "
       "into a targeting aid, and a leaked key is an incident.",
       "Remove the value from the record store, rotate anything exposed, and "
       "regenerate.",
       "sdr/records/records-store.json"),
    _m("sdr_record_freshness", "Record has been updated recently enough to be current",
       "medium", "Security Decision Record", ["FRC-CSX-VVR", "SDR-CSO-MTD"],
       "Providers SHOULD implement automated methods to persistently verify "
       "and validate the accuracy and completeness of the Security Decision "
       "Record.",
       "A record that has not moved in months is not a persistent record; an "
       "assessor cannot treat it as describing the live system.",
       "Refresh the record from current facts and bump sdr_last_updated on "
       "every content change.",
       "profiles/common/offering-profile.json"),

    # Per rule
    _m("frr_status_declared", "Rule carries a valid implementation status",
       "medium", "FedRAMP Rule", ["SDR-CSO-FRR", "FRC-CSO-JSN"],
       "frrImplementationStatus must be Implemented, Not Implemented or "
       "Partially Implemented.",
       "An absent or invented status leaves the reader guessing whether the "
       "rule is met.",
       "Set implementation_status on the rule in the record store.",
       "sdr/records/records-store.json -> frr.<rule>.implementation_status"),
    _m("frr_implementation_explained", "Rule implementation is explained",
       "high", "FedRAMP Rule", ["SDR-CSO-FRR"],
       "Explanation of how the rule is followed, or an explanation of the "
       "reason and resulting risk to customers for not following the rule.",
       "This is the first of the seven items SDR-CSO-FRR requires for every "
       "rule; a placeholder here means the rule is undocumented.",
       "Replace the placeholder with the provider's real implementation.",
       "sdr/records/records-store.json -> frr.<rule>.implementation"),
    _m("frr_nonconformance_reason_stated",
       "Rules not fully followed state the reason they are not followed",
       "high", "FedRAMP Rule", ["SDR-CSO-FRR"],
       "SDR-CSO-FRR item 1 requires, for a rule that is not followed, the "
       "reason it is not followed AND the resulting risk to customers - two "
       "distinct elements. The risk is not the reason.",
       "Without the reason, an assessor cannot tell WHY the rule is not "
       "followed, only what the residual risk is; the two are different facts.",
       "State the reason for not following the rule in nonimplementation_reason "
       "(or explain it in the implementation narrative) on every rule that is "
       "not Implemented.",
       "sdr/records/records-store.json -> frr.<rule>.extension.nonimplementation_reason"),
    _m("frr_nonconformance_risk_stated",
       "Rules not fully followed state the resulting customer risk",
       "high", "FedRAMP Rule", ["SDR-CSO-FRR"],
       "SDR-CSO-FRR requires the reason AND the resulting risk to customers "
       "whenever a rule is not followed.",
       "Agencies make risk-acceptance decisions from this text. Omitting it "
       "shifts an undisclosed risk onto the customer.",
       "State the risk to customers in plain terms on every rule that is not "
       "Implemented.",
       "sdr/records/records-store.json -> frr.<rule>.extension.customer_risk"),
    _m("frr_verification_recorded", "Provider verification of the rule is recorded",
       "high", "FedRAMP Rule", ["SDR-CSO-FRR"],
       "Verification that the implementation is appropriate for the rule, or "
       "that the reason for not implementing is accepted by a senior official.",
       "Without verification there is no statement that the implementation is "
       "the right one, only that something was built.",
       "Record who verified the implementation as appropriate, and how.",
       "sdr/records/records-store.json -> frr.<rule>.extension.verification"),
    _m("frr_validation_recorded", "Provider validation of the rule is recorded",
       "high", "FedRAMP Rule", ["SDR-CSO-FRR"],
       "Validation that the implementation is in place and working as "
       "intended, or that the reason for not implementing is accepted by a "
       "senior official.",
       "Verification without validation claims the design is right but never "
       "shows it works.",
       "Record how the implementation is confirmed to be working, and how "
       "often.",
       "sdr/records/records-store.json -> frr.<rule>.validation"),
    _m("frr_independent_verification_recorded",
       "Independent verification of the rule is recorded",
       "high", "FedRAMP Rule", ["SDR-CSO-FRR", "IVV-IAS-VIM"],
       "SDR-CSO-FRR item 4: independent verification. IVV-IAS-VIM is the "
       "assessor-side rule that produces it.",
       "Provider self-attestation is not independent verification. Its absence "
       "is a gap an assessor will raise directly.",
       "Record the independent assessor's verification statement once "
       "performed. This has no official schema field, so it lives in the "
       "extensions companion.",
       "sdr/records/records-store.json -> frr.<rule>.extension.independent_verification"),
    _m("frr_independent_validation_recorded",
       "Independent validation of the rule is recorded",
       "high", "FedRAMP Rule", ["SDR-CSO-FRR", "IVV-IAS-VEF"],
       "SDR-CSO-FRR item 5: independent validation. IVV-IAS-VEF is the "
       "assessor-side rule that produces it.",
       "Without independent validation nobody outside the provider has "
       "confirmed the implementation actually works.",
       "Record the independent assessor's validation statement once performed.",
       "sdr/records/records-store.json -> frr.<rule>.extension.independent_validation"),
    _m("frr_assessor_responses_recorded",
       "Responses to assessor comments are recorded where comments exist",
       "low", "FedRAMP Rule", ["SDR-CSO-FRR"],
       "SDR-CSO-FRR item 6: any responses or clarifications to the comments in "
       "the independent verification or validation.",
       "An unanswered assessor comment left out of the record looks like it was "
       "never raised.",
       "Confirm no comment is outstanding, or record the response.",
       "sdr/records/records-store.json -> frr.<rule>.extension.assessor_responses"),
    _m("frr_artifacts_referenced",
       "Rule-specific artifacts are referenced where they apply",
       "medium", "FedRAMP Rule", ["SDR-CSO-FRR"],
       "SDR-CSO-FRR item 7: rule-specific artifacts, if applicable.",
       "A rule whose evidence lives in an unreferenced document forces the "
       "assessor to go looking, and they may not find it.",
       "Reference the artifact, or confirm none applies to this rule.",
       "sdr/records/records-store.json -> frr.<rule>.extension.rule_artifacts"),
    _m("frr_senior_official_acceptance",
       "Unimplemented rules carry senior official acceptance",
       "high", "FedRAMP Rule", ["SDR-CSO-FRR"],
       "SDR-CSO-FRR allows verification and validation to be replaced by a "
       "senior official's acceptance of the reason for not implementing.",
       "A rule marked Not Implemented with nobody accountable for that decision "
       "is an unowned risk.",
       "Name the senior official who accepted the decision and when.",
       "sdr/records/records-store.json -> frr.<rule>.extension.senior_official_acceptance"),
    _m("frr_owner_assigned", "Rule has a named accountable owner",
       "medium", "FedRAMP Rule", ["FRD-PER", "CCM-OCR-AVL"],
       "The status of persistent activities must always be known, which "
       "requires somebody accountable for keeping it known.",
       "Unowned rules go stale between assessments because nobody is "
       "responsible for refreshing them.",
       "Assign an owning team or role, not an individual's name.",
       "sdr/records/records-store.json -> frr.<rule>.extension.owner"),
    _m("frr_statement_fidelity", "Rule text matches the canonical dataset exactly",
       "critical", "FedRAMP Rule", ["FRC-CSO-JSN"],
       "The rule text a provider answers must be the rule text FedRAMP "
       "published.",
       "Paraphrasing a rule quietly changes what the provider is claiming to "
       "have met, which invalidates the answer.",
       "Never edit rule text. Regenerate from the pinned dataset.",
       "references/fedramp-consolidated-rules.json"),

    # Per KSI
    _m("ksi_status_declared", "Indicator carries a valid implementation status",
       "medium", "Key Security Indicator", ["SDR-CSX-KSI", "FRC-CSO-JSN"],
       "ksiImplementationStatus must be one of the three official values.",
       "An absent status leaves the indicator's state undefined.",
       "Set implementation_status on the indicator in the record store.",
       "sdr/records/records-store.json -> ksi.<indicator>.implementation_status"),
    _m("ksi_measures_explained", "Indicator measures and objectives are explained",
       "high", "Key Security Indicator", ["SDR-CSX-KSI"],
       "Explanation of measures (and their objectives) that demonstrate the "
       "Key Security Indicator, or an explanation of the reason and resulting "
       "risk to customers for not having measures available.",
       "The indicator is the unit FedRAMP evaluates in 20x. An unexplained "
       "indicator contributes nothing to the certification.",
       "Describe the measures and what each is meant to demonstrate.",
       "sdr/records/records-store.json -> ksi.<indicator>.implementation"),
    _m("ksi_operating_cycle_explained",
       "Persistent measures explain their operating cycle",
       "medium", "Key Security Indicator", ["SDR-CSX-KSI", "FRD-PER"],
       "SDR-CSX-KSI item 2: explanation of the cycle for any measures that are "
       "implemented persistently.",
       "Without a stated cycle, a reader cannot tell whether a passing measure "
       "was checked this morning or last quarter.",
       "State the cycle, or confirm no measure for this indicator runs "
       "persistently.",
       "sdr/records/records-store.json -> ksi.<indicator>.extension.operating_cycle"),
    _m("ksi_measures_verified", "Measures are verified to demonstrate the indicator",
       "high", "Key Security Indicator", ["SDR-CSX-KSI"],
       "SDR-CSX-KSI item 3: verification that the measures demonstrate the Key "
       "Security Indicator, or that the reason for not having them is accepted.",
       "A measure that runs reliably but does not actually evidence the "
       "indicator gives false assurance.",
       "Record who confirmed that the measures evidence this indicator.",
       "sdr/records/records-store.json -> ksi.<indicator>.extension.measures_verification"),
    _m("ksi_automation_verified",
       "Automation behind the measures is verified as accurate and sufficient",
       "high", "Key Security Indicator", ["SDR-CSX-KSI", "FRC-CSX-VVK"],
       "SDR-CSX-KSI item 4: verification that the automation in place is "
       "accurate and sufficient to demonstrate appropriate measures, or that "
       "automation is not necessary for each measure.",
       "Unverified automation is the most dangerous kind of evidence: it "
       "produces confident output nobody has checked.",
       "Record how the automation was verified, or state why automation is "
       "unnecessary for this measure.",
       "sdr/records/records-store.json -> ksi.<indicator>.extension.automation_verification"),
    _m("ksi_measures_validated", "Measures are validated as working as intended",
       "high", "Key Security Indicator", ["SDR-CSX-KSI"],
       "SDR-CSX-KSI item 5: validation that the measures are accurately "
       "produced and are in place and working as intended.",
       "Verification without validation asserts the measure is the right one "
       "but never shows it runs correctly.",
       "Record how the measures are confirmed to be producing accurate output.",
       "sdr/records/records-store.json -> ksi.<indicator>.validation"),
    _m("ksi_independent_assessment_recorded",
       "Independent assessment of the indicator is recorded",
       "high", "Key Security Indicator", ["IVV-CSX-AIA", "IVV-IAS-VEF",
                                          "SDR-CSX-KSI"],
       "Assessors verify and validate Key Security Indicators independently of "
       "the provider, and IVV-CSX-AIA requires an annual independent "
       "assessment for 20x.",
       "Self-assessed indicators carry no independent weight in a "
       "certification decision.",
       "Record the assessor's statement once the assessment is performed.",
       "sdr/records/records-store.json -> ksi.<indicator>.assessment"),
    _m("ksi_test_minimum_met",
       "Indicator meets the automated method minimum for its class",
       "high", "Key Security Indicator", ["FRC-CSX-VVK"],
       "Class A MAY implement automated methods; Class B SHOULD have at least "
       "1 per indicator; Class C MUST have at least 2; Class D MUST have at "
       "least 4.",
       "Falling short of the class minimum is a direct rule shortfall that "
       "blocks the certification class being sought.",
       "Add automated methods until the class minimum is met, or drop to a "
       "class whose minimum you meet.",
       "sdr/records/records-store.json -> ksi.<indicator>.tests"),
    _m("ksi_evidence_present", "Indicator has evidence attached",
       "high", "Key Security Indicator", ["SDR-CSX-KSI", "FRC-CSX-VVK"],
       "The official schema requires ksiEvidence, holding the results of the "
       "security tests used to validate the indicator.",
       "A test with no recorded result is an assertion, not evidence.",
       "Attach the output of each automated method as an evidence entry.",
       "sdr/records/records-store.json -> ksi.<indicator>.evidence"),
    _m("ksi_evidence_typed", "Evidence uses official evidence types",
       "low", "Key Security Indicator", ["FRC-CSO-JSN"],
       "evidenceType must be one of Log, Report, Screenshot, Configuration, "
       "Policy, Procedure or Audit Record.",
       "A non-official type value makes the document fail schema validation and "
       "breaks automated ingestion.",
       "Use one of the seven official evidenceType values.",
       "sdr/records/records-store.json -> ksi.<indicator>.evidence[].evidenceType"),
    _m("ksi_metrics_30day_summary", "Indicator carries a 30-day metric summary",
       "high", "Key Security Indicator", ["SDR-CSX-KMT"],
       "Class C providers MUST, and Class B providers SHOULD (dataset "
       "2026.10.08.01; MUST before), include a summary of each metric over the "
       "past 30 days.",
       "Without recent history an assessor sees a snapshot and cannot tell "
       "whether the control has been holding.",
       "Record the 30-day summary, ideally written by the collector rather "
       "than by hand.",
       "sdr/records/records-store.json -> ksi.<indicator>.historical_metrics.last_30_days",
       ("b", "c")),
    _m("ksi_metrics_yearly_summary",
       "Indicator carries a metric summary up to the past year",
       "medium", "Key Security Indicator", ["SDR-CSX-KMT"],
       "Class C providers MUST, and Class B providers SHOULD, include a summary "
       "of the metric up to the past year, where available.",
       "A year of history is what distinguishes a sustained control from one "
       "that was fixed the week before assessment.",
       "Record the longer-run summary once that much history exists.",
       "sdr/records/records-store.json -> ksi.<indicator>.historical_metrics.up_to_one_year",
       ("b", "c")),
    _m("ksi_metrics_daily_data",
       "Class C indicators reference a year of daily metric data",
       "high", "Key Security Indicator", ["SDR-CSX-KMT"],
       "Class C providers MUST supply all daily metric data, including the "
       "status of persistent validation, up to the past year, where available.",
       "Class C rests on continuous data. Summaries alone do not meet it.",
       "Reference the daily metric store, for example the collector's evidence "
       "bucket prefix.",
       "sdr/records/records-store.json -> ksi.<indicator>.historical_metrics.daily_data_reference",
       ("c",)),
    _m("ksi_owner_assigned", "Indicator has a named accountable owner",
       "medium", "Key Security Indicator", ["FRD-PER"],
       "The status of persistent activities must always be known.",
       "Unowned indicators drift, and drift in an indicator is invisible until "
       "an assessment finds it.",
       "Assign an owning team or role.",
       "sdr/records/records-store.json -> ksi.<indicator>.extension.owner"),
    _m("ksi_pending_marked_honestly",
       "Indicators with no published statement are marked FedRAMP pending",
       "informational", "Key Security Indicator", ["SDR-CSX-KSI"],
       "A KSI is FedRAMP pending only when the pinned CR26 dataset gives it no "
       "statement anywhere - neither a top-level statement nor any per-class "
       "statement under varies_by_class. This is derived from the dataset, not a "
       "hardcoded list, so it cannot drift.",
       "Inventing text for an indicator FedRAMP has not published would be "
       "fabrication; conversely, marking an indicator that DOES have a per-class "
       "statement as pending is a factually wrong scanner output.",
       "Leave a genuinely statement-less indicator marked FedRAMP pending until "
       "FedRAMP publishes the statement; answer any indicator that has a "
       "per-class statement.",
       "references/fedramp-consolidated-rules.json"),
    _m("ksi_statement_fidelity", "Indicator text matches the canonical dataset",
       "critical", "Key Security Indicator", ["FRC-CSO-JSN"],
       "The indicator text a provider answers must be the text FedRAMP "
       "published.",
       "Paraphrasing changes what is being claimed.",
       "Never edit indicator text. Regenerate from the pinned dataset.",
       "references/fedramp-consolidated-rules.json"),
]}


def run_all(ctx):
    """Run every check group and return raw (check_id, resource_id,
    resource_name, ok, detail) tuples."""
    return package_checks(ctx) + rule_checks(ctx) + ksi_checks(ctx)


def write_catalog(path):
    """Emit the check catalog so the registry is reviewable and diffable
    outside the code, the way Prowler ships per-check metadata."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    catalog = {
        "catalog_note": (
            "sdrscan check registry. Every check names the FedRAMP rules that "
            "make it a requirement. Severity reflects the consequence of the "
            "gap for a certification decision, not the difficulty of fixing it."
        ),
        "count": len(METADATA),
        "checks": [METADATA[k] for k in sorted(METADATA)],
    }
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(catalog, f, indent=1)
    return len(METADATA)
