#!/usr/bin/env python3
"""Build a fully-worked FICTIONAL Class C sample and drive it to submission
preflight, so the HARDEST gates are exercised end-to-end: >=2 automated methods
per KSI (FRC-CSX-VVK), a persistent-validation history spanning the up-to-one-year
reference period (SDR-CSX-KMT),
evidence linkage for every applicable MUST, a fresh FedRAMP Recognized
independent assessment (FRC-APP-FIA), availability reporting (CDS-CSO-AVR), a
structurally complete CPO, and a manifest-bound human signoff.

WHY: the Class B sample (examples/sample-offering) fills narrative only and
leaves status/tests/evidence as template, so it never exercises the Class C
readiness gates on POPULATED data. That is exactly where subtle bugs hide (e.g.
the series-vs-list MOT bug). This builder fills a realistic, messy, COMPLETE
Class C package and runs package-preflight against it.

Everything is FICTIONAL. No real PII, account IDs, assessors, or evidence. This
is illustrative example data, not an attestation and not evidence of compliance.
A green preflight here means the framework's readiness checks are SATISFIABLE by
complete input, NOT that anything is FedRAMP compliant.

Run:
    python examples/sample-offering-class-c/build_class_c_sample.py          # run preflight
    python examples/sample-offering-class-c/build_class_c_sample.py --attack # adversarial probes
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import datetime as dt

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
REAL_STORE = os.path.join(BASE, "sdr", "records", "records-store.json")
REAL_PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
REAL_HISTORY = os.path.join(BASE, "automation", "metrics", "metric-history.json")
# AUD-F36: the sample's build and preflight also overwrite the committed
# validation reports with Class C sample state; they are backed up and restored
# byte-for-byte like the inputs, instead of being left for the next commit.
REAL_REPORTS = (
    os.path.join(BASE, "validation", "reports", "validation-report.json"),
    os.path.join(BASE, "validation", "reports", "ksi-test-results.json"),
)
# The sample records its fictional sign-offs in the review register; it is
# backed up and restored byte-for-byte like the other inputs. A `git checkout`
# restore would discard a provider's own uncommitted sign-offs and needs a git
# checkout to exist (the sample also runs inside copied test trees).
REAL_REGISTER = os.path.join(BASE, "sdr", "reviews", "review-register.json")
BACKED_UP = (REAL_STORE, REAL_PROFILE, REAL_HISTORY, REAL_REGISTER) + REAL_REPORTS


def _backup(tmp):
    """Copy every file the sample run may overwrite into tmp. Returns {real: bak}."""
    baks = {}
    for real in BACKED_UP:
        if os.path.exists(real):
            b = os.path.join(tmp, os.path.basename(real) + ".bak")
            shutil.copy2(real, b)
            baks[real] = b
    return baks


def _restore_tree(baks, history_existed, tmp):
    """Leave the working tree exactly as found (AUD-F36).

    Restores every backed-up file (inputs, the review register whose sign-offs
    are sample-only, AND validation reports), removes the sample metric history
    if none existed before, then regenerates EVERY deliverable from the
    restored real inputs with the single build definition. `sdr.py build` now
    regenerates the inactive classes too (JSON, text AND Word document, see
    build_inactive_classes.py), so sample content cannot linger in a committed
    Class A/C artifact: the Class C .docx used to keep the fictional offering
    (409 occurrences) because only the active class's document was rebuilt.
    """
    for real, b in baks.items():
        shutil.copy2(b, real)
    if not history_existed and os.path.exists(REAL_HISTORY):
        os.remove(REAL_HISTORY)
    shutil.rmtree(tmp, ignore_errors=True)
    subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "build"],
                   cwd=BASE, capture_output=True, text=True)
MANIFEST = os.path.join(BASE, "artifacts", "release-manifest.json")

TODAY = dt.date.today()
FICT = "[SAMPLE - fictional, not an attestation]"


def _aws_method_ids(kid):
    """The two automated VVK method ids the AWS sample declares per KSI; the
    metric history keys its per-method telemetry by the same ids."""
    return (f"{kid}-config-rule", f"{kid}-api-collector")


def _impl(kid, aspect):
    return (f"{FICT} Beacon Federal Cloud (BFC) addresses {kid} for '{aspect}' via "
            "documented, version-controlled controls in the BFC boundary, deployed "
            "by CI/CD and continuously monitored in AWS Security Hub and Config. "
            "Illustrative example text only.")


def fill_ksi(kid, rec):
    """Fill a KSI record to Class C readiness: Implemented status, real
    narratives, TWO automated verification methods, and a resolvable evidence
    entry. Fictional but structurally complete."""
    rec["implementation_status"] = "Implemented"
    rec["implementation"] = [_impl(kid, "implementation")]
    rec["validation"] = [_impl(kid, "validation")]
    rec["assessment"] = [f"{FICT} Independently assessed by the fictional Recognized "
                         "assessor as part of the BFC FedRAMP 20x assessment."]
    # FRC-CSX-VVK Class C: >= 2 AUTOMATED methods per KSI. Record structured
    # authoring entries ({method_id, method, automated, cadence}) so the
    # validator counts genuine distinct automated methods; the official SDR
    # schema flattens these to strings on build.
    rec["tests"] = [
        {
            "method_id": f"{kid}-config-rule",
            "method": f"{FICT} AWS Config managed+custom rules evaluate {kid} "
                      "state; non-compliant results alarm to Security Hub.",
            "automated": True,
            "cadence": "continuous",
        },
        {
            "method_id": f"{kid}-api-collector",
            "method": f"{FICT} scheduled CodeBuild collector queries the relevant "
                      f"read-only AWS APIs for {kid} and records a datapoint.",
            "automated": True,
            "cadence": "daily",
        },
    ]
    # One resolvable evidence entry (has a real location + source fact + hash is
    # computed by the build; here we give a concrete non-placeholder location).
    rec["evidence"] = [{
        "evidenceType": "Configuration",
        "evidenceDescription": f"{FICT} Security Hub + Config evaluation history for {kid}.",
        "evidenceLocation": f"https://evidence.bfc-demo.invalid/{kid.lower()}/latest.json",
        "lastUpdated": TODAY.isoformat(),
    }]
    ext = rec.setdefault("extension", {})
    for f in list(ext.keys()):
        v = ext[f]
        if isinstance(v, str) and ("TBD" in v or not v.strip()):
            ext[f] = _impl(kid, f)
        elif isinstance(v, list) and (not v or all("TBD" in str(x) for x in v)):
            ext[f] = [_impl(kid, f)]
    ext["owner"] = "J. Rivera, BFC Security Engineering (fictional)"
    ext["measures_verification"] = _impl(kid, "measures_verification")
    ext["automation_verification"] = _impl(kid, "automation_verification")
    # SDR-CSX-KMT historical-metric summaries (Class C MUST): 30-day, up-to-one-
    # year, and a daily-data reference. Fictional sample values.
    hm = rec.setdefault("historical_metrics", {})
    hm["last_30_days"] = f"{FICT} {kid}: 30/30 days passing over the last 30 days."
    hm["up_to_one_year"] = f"{FICT} {kid}: >=99% passing across the available ~7-month window."
    hm["daily_data_reference"] = f"https://evidence.bfc-demo.invalid/{kid.lower()}/daily-metrics.json"
    return rec


def fill_frr(rid, rec):
    rec["implementation_status"] = "Implemented"
    rec["implementation"] = [_impl(rid, "implementation")]
    rec["validation"] = [_impl(rid, "validation")]
    rec["assessment"] = [f"{FICT} Independently verified and validated for {rid}."]
    ext = rec.setdefault("extension", {})
    for f in list(ext.keys()):
        v = ext[f]
        if isinstance(v, str) and ("TBD" in v or not v.strip()):
            ext[f] = _impl(rid, f)
        elif isinstance(v, list) and (not v or all("TBD" in str(x) for x in v)):
            ext[f] = [_impl(rid, f)]
    ext["owner"] = "J. Rivera, BFC Security Engineering (fictional)"
    ext["independent_verification"] = f"{FICT} Independent verification recorded for {rid}."
    ext["independent_validation"] = f"{FICT} Independent validation recorded for {rid}."
    # A resolvable rule artifact so evidence-linkage is satisfied for populated MUSTs.
    ext["rule_artifacts"] = [{
        "evidenceType": "Configuration",
        "evidenceDescription": f"{FICT} Control evidence for {rid}.",
        "evidenceLocation": f"https://evidence.bfc-demo.invalid/frr/{rid.lower()}.json",
        "lastUpdated": TODAY.isoformat(),
    }]
    return rec


def generate_store():
    with open(REAL_STORE, encoding="utf-8") as f:
        store = json.load(f)
    for kid, rec in store.get("ksi", {}).items():
        fill_ksi(kid, rec)
    for rid, rec in store.get("frr", {}).items():
        fill_frr(rid, rec)
    return store


def generate_history(store, method_ids=None):
    """A >=6-month daily-ish metric history per KSI, in the REAL production
    shape append_metrics writes: {"ksis": {kid: {"series": [...], "metrics": {...},
    "observations": [...]}}, "meta": {...}}.

    The per-method "metrics" map is keyed by the SAME method_ids the KSI declares
    in its records-store tests ({kid}-config-rule, {kid}-api-collector), so each
    declared automated VVK method is BOUND to observed telemetry. This satisfies
    the Class C/D method-to-telemetry binding gate: a declared automated method
    that produced no keyed telemetry is a false-ready path and must block.
    `method_ids(kid)` may be supplied by another sample platform (MCE-12); the
    default is the AWS sample's pair.

    AUD-F37: every series point has an observation behind it, and the
    observations are hash-chained with (fictional, labelled) run provenance, so
    the sample passes the chain-integrity gate the way a collector-produced
    history does. The digest is NOT signed: the sample declares the development
    profile, where an unsigned digest is an advisory; production-assurance would
    block it, which is the point."""
    sys.path.insert(0, os.path.join(BASE, "automation", "metrics"))
    import history_integrity as hi
    if method_ids is None:
        method_ids = _aws_method_ids
    ksis = list(store.get("ksi", {}).keys())
    hist = {"ksis": {}, "meta": {}}
    for kid in ksis:
        series = []
        observations = []
        per_method = {mid: [] for mid in method_ids(kid)}
        # 400 days back to today, weekly datapoints: past the up-to-one-year
        # reference period SDR-CSX-KMT names, so the fictional offering needs no
        # initial-certification commitment and the continuity bound is evaluated
        # across the whole reference period.
        d = TODAY - dt.timedelta(days=400)
        while d <= TODAY:
            iso = d.isoformat()
            series.append({"date": iso, "status": "pass"})
            observations.append({"observed_at": f"{iso}T06:00:00+00:00", "date": iso,
                                 "passing": 2, "total": 2})
            for mkey in per_method:
                per_method[mkey].append({"date": iso, "passing": 1, "total": 1})
            d += dt.timedelta(days=7)
        metrics = {mkey: {"series": s} for mkey, s in per_method.items()}
        hist["ksis"][kid] = {"series": series, "metrics": metrics, "observations": observations}
    # Fictional provenance, labelled as such in the run id itself.
    hi.rechain(hist, {"run_id": "run-SAMPLE-fictional", "facts_sha256": "sha256:" + "f1c7" * 16})
    return hist


def _norm_key(text):
    import re
    base = re.split(r"\(", str(text))[0].strip().lower()
    return re.sub(r"[^a-z0-9]+", "_", base).strip("_")


def _cr26_following(rid):
    import re
    ds = json.load(open(os.path.join(BASE, "references",
                                     "fedramp-consolidated-rules.json"), encoding="utf-8"))

    def find(node, target):
        if isinstance(node, dict):
            if target in node:
                return node[target]
            for v in node.values():
                r = find(v, target)
                if r is not None:
                    return r
        elif isinstance(node, list):
            for v in node:
                r = find(v, target)
                if r is not None:
                    return r
        return None

    return (find(ds, rid) or {}).get("following_information", []) or []


def _cpo_required_information(class_c_profile_rules):
    """Build the CPO-CSO-OVR required-information map for the applicable rules,
    derived from the dataset so it is correct by construction. Objects for
    CDS-CSO-PUB (keyed by its following_information items), arrays for
    CDS-CSO-IRP / MAS-CSO-TPR, scalars for the rest."""
    OBJECT_RULES = {"CDS-CSO-PUB"}
    ARRAY_RULES = {"CDS-CSO-IRP", "MAS-CSO-TPR"}
    # The full CPO-CSO-OVR referenced set; the CPO builder keeps only those
    # applicable to the class.
    OVR_RULES = ["CPO-CSO-MTD", "CDS-CSO-PUB", "CDS-CSO-SVC", "CDS-CSO-IRP",
                 "MAS-CSO-IIR", "MAS-CSO-FLO", "MAS-CSO-TPR", "CMU-CSO-CMD",
                 "IVV-CSO-ICP"]
    out = {"note": "CPO-CSO-OVR required information (fictional sample content)."}
    for rid in OVR_RULES:
        if rid in OBJECT_RULES:
            items = _cr26_following(rid)
            out[rid] = {_norm_key(x): f"{FICT} {rid}: {str(x)[:80]}"
                        for x in items} or {"summary": f"{FICT} {rid} content."}
        elif rid in ARRAY_RULES:
            fields = _cr26_following(rid)
            rec = {_norm_key(x): f"{FICT} {str(x)[:80]}" for x in fields}
            if not rec:
                rec = {"summary": f"{FICT} {rid} record."}
            out[rid] = [rec]
        else:
            out[rid] = f"{FICT} {rid}: provider information supplied in the CPO."
    return out


def generate_profile():
    with open(REAL_PROFILE, encoding="utf-8") as f:
        profile = json.load(f)
    recent = (TODAY - dt.timedelta(days=2)).isoformat()
    fia_done = (TODAY - dt.timedelta(days=40)).isoformat()  # < 3 months, no freshening needed
    profile.update({
        "organization_name": "Beacon Federal Cloud, Inc. (fictional)",
        "offering_name": "Beacon Federal Cloud",
        "offering_abbreviation": "BFC",
        "business_purpose": ("A fictional multi-tenant SaaS data-processing platform, "
                             "used to demonstrate a COMPLETE Class C package."),
        "service_model": "SaaS",
        "deployment_model": "Public Cloud",
        "certification_type": "20x",
        "certification_class": "C",
        "certification_path": "Program",
        "aws_partition": "aws",
        "primary_region": "us-east-1",
        "dr_region": "us-west-2",
        "certification_package_overview_uri": "https://trust.bfc-demo.invalid/cpo.json",
        "security_contact": "security@bfc-demo.invalid (fictional)",
        "incident_contact": "ir@bfc-demo.invalid (fictional)",
        "sales_contact": "sales@bfc-demo.invalid (fictional)",
        "assessor": "Cascade Assurance LLC (fictional Recognized assessor)",
        "assessor_id": "123456",
        # CDS-CSO-PUB public information with no other home in the profile.
        "uei_number": "ZQGGHJH74DW7 (fictional)",
        "business_category": ["Data Management", "Analytics"],
        "documentation_overview": (f"{FICT} User guide, API reference, Secure Configuration Guide "
                                   "and the trust-center certification data, all published at "
                                   "https://trust.bfc-demo.invalid/."),
        "provider_verified_at": recent + "T00:00:00+00:00",
        # MCE-09 / AUD-F73: the evidence store as attested PROPERTIES (fictional;
        # no product named, the package asks only what the store does).
        "evidence_store": {
            "versioned": True,
            "write_once": True,
            "separately_administered": True,
            "retention_days": 400,
            "access_logging": True,
            "implementation": f"{FICT} write-once versioned object store in a separately "
                              "administered audit account, access-logged to its own destination.",
        },
        # AUD-F79: a source binds only for an offering that declares it. The
        # MCE-03 probes below claim the Falcon adapter's declared pair, so the
        # fictional offering enables that source (export produced in its own
        # environment; the path is the committed example, no API client here).
        "evidence_sources": {
            "crowdstrike-falcon": {
                "enabled": True,
                "export_path": "examples/evidence-sources/falcon-export.example.json",
            },
            "wiz": {"enabled": False, "export_path": "automation/facts/wiz-export.json"},
        },
        "overall_assessment_summary": (f"{FICT} The independent assessor's overall summary: "
                                       "no unresolved high findings; all in-scope KSIs validated."),
        "fedramp_independent_assessment": {
            "assessor_name": "Cascade Assurance LLC (fictional)",
            "assessor_fedramp_id": "FR-RECOG-0142 (fictional)",
            "completed_at": fia_done,
        },
        "availability_reporting": {
            "human_readable_uri": "https://trust.bfc-demo.invalid/status",
            "machine_readable_uri": "https://trust.bfc-demo.invalid/status.json",
            "history_days": 120,
            "available_when_primary_unavailable": True,
        },
        "trust_center_uri": "https://trust.bfc-demo.invalid/",
        "secure_config_guide_uri": "https://trust.bfc-demo.invalid/scg",
        "secure_config_guide_machine_uri": "https://trust.bfc-demo.invalid/scg/machine-readable.json",
        "next_ocr_date": (TODAY + dt.timedelta(days=80)).isoformat(),
        # CPO metadata (CPO-CSO-MTD).
        "cpo_responsible_official": "D. Okafor, BFC Authorizing Official (fictional)",
        "cpo_version": "1.0.0",
        "cpo_last_updated": recent,
        "cpo_source_of_update": "BFC compliance engineering (fictional)",
        # CPO placeholder-driving fields (clear the CPO template markers).
        "fedramp_package_id": "FR-20X-BFC-0001 (fictional)",
        "offering_website": "https://www.bfc-demo.invalid/",
        "offering_logo_uri": "https://www.bfc-demo.invalid/logo.png",
        "cpo_required_information": _cpo_required_information(None),
    })
    # Fill any remaining TBD scalar fields.
    for k, v in list(profile.items()):
        if isinstance(v, str) and "TBD" in v:
            profile[k] = f"{FICT} {k} for Beacon Federal Cloud."
    profile["profile_note"] = f"{FICT} FICTIONAL Class C sample; illustrative only."
    return profile


def _preflight_rc(store, profile, history, post_sign=None, signoff=None):
    """Apply the given in-memory inputs, build, sign, run package-preflight,
    return (returncode, output). Always restores real inputs after. If post_sign
    is given, it is called after the (correct) signoff is written and before
    preflight runs, so a probe can tamper with the manifest-bound signoff.
    `signoff` is the (reviewer, note) pair the fictional signoff records; None
    is the AWS sample's."""
    tmp = tempfile.mkdtemp(prefix="sdr-attack-")
    baks = _backup(tmp)
    history_existed = os.path.exists(REAL_HISTORY)
    try:
        json.dump(store, open(REAL_STORE, "w", encoding="utf-8", newline="\n"), indent=1)
        json.dump(profile, open(REAL_PROFILE, "w", encoding="utf-8", newline="\n"), indent=1)
        json.dump(history, open(REAL_HISTORY, "w", encoding="utf-8", newline="\n"), indent=1)
        subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "build"],
                       cwd=BASE, capture_output=True, text=True)
        _record_signoff(*(signoff or ()))
        if post_sign is not None:
            post_sign()
        pf = subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "package-preflight"],
                            cwd=BASE, capture_output=True, text=True)
        return pf.returncode, (pf.stdout or "") + (pf.stderr or "")
    finally:
        _restore_tree(baks, history_existed, tmp)


class SamplePlatform:
    """The platform-specific half of the assessor-attack harness (MCE-12).

    attack() takes one of these. The AWS sample is the default and its
    behaviour is unchanged; the non-AWS Class C sample supplies its own so
    the SAME probe list, with the same gate pinned per probe, runs against a
    package whose evidence comes from adapters the profile enables on another
    platform. Everything a probe needs that differs by platform is here;
    everything else (the tampers, the pins, the backup and restore) is shared."""
    name = "aws"
    # Region segment and store base of the entries the harness derives itself.
    region = "us-east-1"
    location_base = "https://evidence.bfc-demo.invalid/store"
    # The pinned signer: the key reference the blocks record and the profile
    # field it is pinned under (key_arn for KMS, key_reference elsewhere).
    signer_key_ref = "arn:aws:kms:us-east-1:000000000000:key/SAMPLE-fictional-signer"
    signer_pin_field = "key_arn"
    # Service the derived FRR rule artifacts claim (no source map applies to
    # FRR artifacts; only the pointer check does).
    frr_source_service = "config"
    # Whether the sample's hand-written KSI evidence is replaced by entries
    # derived from the first source the offering registers for each KSI. A
    # platform whose store already carries adapter-derived entries keeps them.
    rebind_ksi_evidence = True
    # The MCE-03 Falcon probes and the AUD-F79 Wiz probe: this sample enables
    # the Falcon source and leaves Wiz off.
    adapter_probes = True
    signoff_reviewer = "D. Okafor, BFC Authorizing Official (fictional)"
    signoff_note = f"{FICT} Package-level provider signoff for the Class C sample."

    def generate_store(self):
        return generate_store()

    def generate_profile(self):
        return generate_profile()

    def generate_history(self, store):
        return generate_history(store, self.method_ids)

    def method_ids(self, kid):
        return _aws_method_ids(kid)

    def extra_probes(self, harness):
        """Platform-specific probes, run after the shared list. `harness`
        exposes probe, probe_ready, pin_signer, bind_evidence, resign and the
        base inputs."""
        return None


def attack(platform=None):
    """Assessor attack: start from the READY Class C package, apply one hollowing
    tamper at a time, and assert preflight BLOCKS each. A tamper that still
    reaches 'ready' is a framework gap. `platform` is a SamplePlatform; None is
    the AWS sample."""
    import copy
    plat = platform or SamplePlatform()
    sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
    import profile_contract as _pc  # the CDS-CSO-PUB source map (AUD-F39)
    base_store = plat.generate_store()
    base_profile = plat.generate_profile()
    base_history = plat.generate_history(base_store)
    signoff = (plat.signoff_reviewer, plat.signoff_note)
    passed = failed = 0

    def probe(name, mutate, post_sign=None, expect=None):
        """expect: a substring that must appear in preflight's output for the
        probe to pass, so a tamper is proven blocked for ITS reason and not by
        an unrelated blocker (a false pass otherwise)."""
        nonlocal passed, failed
        st, pr, hi = copy.deepcopy(base_store), copy.deepcopy(base_profile), copy.deepcopy(base_history)
        mutate(st, pr, hi)
        rc, out = _preflight_rc(st, pr, hi, post_sign=post_sign, signoff=signoff)
        blocked = rc != 0
        if blocked and expect is not None and expect not in (out or ""):
            failed += 1
            print(f"  FAIL (blocked, but not by the expected gate {expect!r}) {name}")
            return
        if blocked:
            passed += 1; print(f"  PASS (blocked) {name}")
        else:
            failed += 1; print(f"  FAIL (reached READY despite tamper) {name}")

    # Baseline: the unmutated package must be READY (else the probes are meaningless).
    rc0, _ = _preflight_rc(copy.deepcopy(base_store), copy.deepcopy(base_profile),
                           copy.deepcopy(base_history), signoff=signoff)
    if rc0 == 0:
        passed += 1; print("  PASS (ready) baseline complete package is READY")
    else:
        failed += 1; print("  FAIL baseline package is not READY (attack invalid)")

    # 1. Empty the KMT summaries -> must block (the gap this exercise found).
    def _empty_kmt(st, pr, hi):
        for rec in st["ksi"].values():
            rec["historical_metrics"] = {"last_30_days": "TBD: Information has not been provided.",
                                         "up_to_one_year": "TBD: Information has not been provided.",
                                         "daily_data_reference": "TBD: Information has not been provided."}
    probe("empty SDR-CSX-KMT summaries block at Class C", _empty_kmt)

    # 2. Point evidence at an sdr://placeholder/ location -> must block.
    def _placeholder_evidence(st, pr, hi):
        for rec in st["ksi"].values():
            for e in rec.get("evidence", []):
                e["evidenceLocation"] = "sdr://placeholder/replace-me"
    probe("placeholder evidence URI blocks", _placeholder_evidence)

    # 3. Drop to one automated method per KSI -> Class C requires 2, must block.
    def _one_method(st, pr, hi):
        for rec in st["ksi"].values():
            rec["tests"] = rec.get("tests", [])[:1]
    probe("< 2 automated methods per KSI blocks at Class C", _one_method)

    # 4. Stale FIA (> 9 months, no freshening) -> must block.
    def _stale_fia(st, pr, hi):
        pr["fedramp_independent_assessment"]["completed_at"] = (
            TODAY - dt.timedelta(days=400)).isoformat()
    probe("FIA older than 9 months blocks", _stale_fia)

    # 5. Availability service not survivable -> must block.
    def _avr_not_survivable(st, pr, hi):
        pr["availability_reporting"]["available_when_primary_unavailable"] = False
    probe("non-survivable availability service blocks", _avr_not_survivable)

    # 6. Provider verification older than 7 days -> FRC-APP-FCP freshness, block.
    def _stale_verification(st, pr, hi):
        pr["provider_verified_at"] = (
            TODAY - dt.timedelta(days=30)).isoformat() + "T00:00:00+00:00"
    probe("provider_verified_at older than 7 days blocks", _stale_verification)

    # 7. Provider verification dated in the FUTURE -> must not be accepted as
    #    "within the previous 7 days"; a future date is not a valid verification.
    def _future_verification(st, pr, hi):
        pr["provider_verified_at"] = (
            TODAY + dt.timedelta(days=5)).isoformat() + "T00:00:00+00:00"
    probe("future-dated provider_verified_at does not pass freshness", _future_verification)

    # 8. certification_path Agency -> the engine resolves Program-path only,
    #    so an Agency-path claim must block (wrong applicability scope).
    def _agency_path(st, pr, hi):
        pr["certification_path"] = "Agency"
    probe("Agency certification_path blocks (Program-path engine)", _agency_path)

    # 9. FIA completed_at in the FUTURE -> an assessment cannot complete in the
    #    future; must block rather than count as fresh.
    def _future_fia(st, pr, hi):
        pr["fedramp_independent_assessment"]["completed_at"] = (
            TODAY + dt.timedelta(days=20)).isoformat()
    probe("future-dated FIA completed_at blocks", _future_fia)

    # 10. Availability history < 30 days -> CDS-CSO-AVR requires >= 30, block.
    def _short_avr_history(st, pr, hi):
        pr["availability_reporting"]["history_days"] = 10
    probe("availability history < 30 days blocks (CDS-CSO-AVR)", _short_avr_history)

    # 11. A KSI "answered" with a hollow N/A instead of an honest Not-Implemented
    #     with rationale -> must be treated as unanswered and block. This is the
    #     "impossible to fool with a non-answer" property for a KSI.
    def _hollow_na_ksi(st, pr, hi):
        first = next(iter(st["ksi"].values()))
        first["implementation"] = ["N/A"]
        first.setdefault("extension", {})["measures"] = "N/A"
        first["extension"]["measures_verification"] = "N/A"
    probe("a KSI answered with bare 'N/A' is not accepted as answered", _hollow_na_ksi)

    # ---- Semantic-hollowness probes: structurally complete, content-free. ----
    # These attack the weakest failure mode: a package that is SHAPED right but
    # whose answers are non-answers. A presence/structure-only gate accepts them;
    # a semantic gate must reject them.

    def _fill_cpo(st, pr, hi, rid, value):
        """Set every member of a CPO required-information entry to a hollow
        non-answer, keeping the structure (all required keys present)."""
        cri = pr.get("cpo_required_information", {})
        entry = cri.get(rid)
        if isinstance(entry, dict):
            for k in list(entry.keys()):
                if k == "note":
                    continue
                entry[k] = value
        elif isinstance(entry, list):
            for rec in entry:
                if isinstance(rec, dict):
                    for k in list(rec.keys()):
                        rec[k] = value

    # Since AUD-F39 (#199) the published CDS-CSO-PUB object is DERIVED from the
    # profile fields that already carry each item (profile_contract.
    # PUBLIC_INFORMATION_SOURCES); a provider override under
    # cpo_required_information["CDS-CSO-PUB"] wins only when it is real, so a
    # hollow override is ignored and the derived real values are published.
    # Probes 12/13 therefore hollow the SOURCE fields (the earlier form hollowed
    # the ignored override and had quietly stopped testing anything).
    def _hollow_public_sources(pr, value):
        for path in _pc.PUBLIC_INFORMATION_SOURCES.values():
            if path[0] == "cpo_required_information":
                _fill_cpo(None, pr, None, path[1], value)
            else:
                for field in path:
                    if field in pr:
                        pr[field] = value

    # 12. Every CDS-CSO-PUB source field set to a bare "N/A" (structurally
    #     complete, semantically empty) -> must block.
    probe("CPO CDS-CSO-PUB sources all bare 'N/A' block (hollow but structured)",
          lambda st, pr, hi: _hollow_public_sources(pr, "N/A"))

    # 13. The same sources set to a single "." -> a one-char non-answer that is
    #     neither empty nor a TBD marker must not pass as resolved.
    probe("CPO CDS-CSO-PUB sources all '.' block (single-char non-answer)",
          lambda st, pr, hi: _hollow_public_sources(pr, "."))

    # 14. Array-rule (CDS-CSO-IRP) record fields all "N/A" -> the per-record
    #     fields are present but content-free; must block.
    probe("CPO CDS-CSO-IRP record fields all 'N/A' block (hollow array record)",
          lambda st, pr, hi: _fill_cpo(st, pr, hi, "CDS-CSO-IRP", "N/A"))

    # 15. overall_assessment_summary reduced to a bare "N/A" -> a required
    #     narrative that is a non-answer must not pass.
    def _hollow_summary(st, pr, hi):
        pr["overall_assessment_summary"] = "N/A"
    probe("overall_assessment_summary of bare 'N/A' blocks", _hollow_summary)

    # ---- end semantic-hollowness probes ----

    # 12. Manifest-bound signoff with the WRONG manifest SHA -> a signoff that
    #     does not bind the exact built manifest must block (tamper AFTER signing).
    def _noop(st, pr, hi):
        pass

    def _corrupt_signoff_sha():
        import json as _j
        reg_path = os.path.join(BASE, "sdr", "reviews", "review-register.json")
        reg = _j.load(open(reg_path, encoding="utf-8"))
        reg["package_signoff"]["package_manifest_sha256"] = "sha256:" + ("0" * 64)
        _j.dump(reg, open(reg_path, "w", encoding="utf-8", newline="\n"), indent=1)
    probe("signoff bound to the WRONG manifest SHA blocks", _noop,
          post_sign=_corrupt_signoff_sha)

    # 13. Signoff decision not 'approved' -> a rejected/pending signoff cannot
    #     make a package ready.
    def _reject_signoff():
        import json as _j
        reg_path = os.path.join(BASE, "sdr", "reviews", "review-register.json")
        reg = _j.load(open(reg_path, encoding="utf-8"))
        reg["package_signoff"]["decision"] = "rejected"
        _j.dump(reg, open(reg_path, "w", encoding="utf-8", newline="\n"), indent=1)
    probe("a non-approved package_signoff blocks", _noop, post_sign=_reject_signoff)

    # ---- Audit-coverage probes: the other content checks hardened to reject a
    #      bare non-answer (each was _is_tbd, now _is_hollow). ----

    # 16. A required offering-profile narrative reduced to bare "N/A".
    def _hollow_required_field(st, pr, hi):
        pr["business_purpose"] = "N/A"
    probe("a required profile field of bare 'N/A' blocks", _hollow_required_field)

    # 17. FIA assessor_name reduced to a bare "N/A".
    def _hollow_assessor_name(st, pr, hi):
        pr["fedramp_independent_assessment"]["assessor_name"] = "N/A"
    probe("FIA assessor_name of bare 'N/A' blocks", _hollow_assessor_name)

    # 18. FIA assessor_fedramp_id (the Recognition id) reduced to bare "N/A".
    def _hollow_assessor_id(st, pr, hi):
        pr["fedramp_independent_assessment"]["assessor_fedramp_id"] = "N/A"
    probe("FIA assessor_fedramp_id of bare 'N/A' blocks", _hollow_assessor_id)

    # 19. CPO metadata (CPO-CSO-MTD) responsible_official reduced to bare "N/A".
    def _hollow_mtd(st, pr, hi):
        pr["cpo_responsible_official"] = "N/A"
    probe("CPO metadata responsible_official of bare 'N/A' blocks", _hollow_mtd)

    # 20. Sales/Security contact reduced to a bare "N/A" (CPO contactName).
    def _hollow_contact(st, pr, hi):
        pr["security_contact"] = "N/A"
        pr["sales_contact"] = "N/A"
    probe("CPO Sales/Security contact of bare 'N/A' blocks", _hollow_contact)

    # ---- Multi-tamper combination probes: several hollowing edits at once.
    #      A real submission attempt hollows out many fields together; the
    #      package must still block (defence in depth, not a single tripwire). ----

    # 21. Hollow the ENTIRE CPO required-information map at once.
    def _hollow_whole_cpo(st, pr, hi):
        for rid in ("CDS-CSO-PUB", "CDS-CSO-IRP", "MAS-CSO-TPR", "CPO-CSO-MTD"):
            _fill_cpo(st, pr, hi, rid, "N/A")
    probe("[combo] the entire CPO required-information hollowed blocks", _hollow_whole_cpo)

    # 22. Hollow every content field this exercise hardened, all together:
    #     required narratives, assessor name+id, contacts, summary, CPO members,
    #     and the KSI metric summaries. A package this empty must never be ready.
    def _hollow_everything(st, pr, hi):
        pr["business_purpose"] = "N/A"
        pr["business_category"] = "N/A"
        pr["documentation_overview"] = "N/A"
        pr["overall_assessment_summary"] = "N/A"
        pr["security_contact"] = "N/A"
        pr["sales_contact"] = "N/A"
        pr["cpo_responsible_official"] = "N/A"
        pr["fedramp_independent_assessment"]["assessor_name"] = "N/A"
        pr["fedramp_independent_assessment"]["assessor_fedramp_id"] = "N/A"
        for rid in ("CDS-CSO-PUB", "CDS-CSO-IRP", "MAS-CSO-TPR"):
            _fill_cpo(st, pr, hi, rid, "N/A")
        for rec in st["ksi"].values():
            rec["historical_metrics"] = {"last_30_days": "N/A",
                                         "up_to_one_year": "N/A",
                                         "daily_data_reference": "N/A"}
    probe("[combo] every hardened content field hollowed at once blocks",
          _hollow_everything)

    # 23. A subtle combo: structurally perfect, but each hollow field uses a
    #     DIFFERENT non-answer token (N/A, '.', 'none', 'unknown') to test that
    #     the detector is not keyed to a single token.
    def _hollow_varied_tokens(st, pr, hi):
        pr["business_purpose"] = "."
        pr["overall_assessment_summary"] = "none"
        pr["cpo_responsible_official"] = "unknown"
        pr["fedramp_independent_assessment"]["assessor_name"] = "tbc"
        _fill_cpo(st, pr, hi, "CDS-CSO-PUB", "-")
    probe("[combo] varied non-answer tokens across fields all block",
          _hollow_varied_tokens)

    # 24. NEGATIVE combo: the SAME fields, but each carries a JUSTIFIED N/A
    #     with a real reason. This must still be READY - the detector rejects
    #     content-free tokens, not honest justified non-implementations, and a
    #     combination of justified answers must not be over-blocked. NOTE: only
    #     NARRATIVE fields belong here. Mandatory identity/contact fields are
    #     tested separately below (a justified N/A must NOT satisfy them).
    def _justified_combo(st, pr, hi):
        why = "N/A: not applicable to this fictional SaaS boundary, per assessor."
        pr["business_purpose"] = why
        pr["overall_assessment_summary"] = why
        _fill_cpo(st, pr, hi, "CDS-CSO-PUB", why)

    def _probe_ready(name, mutate):
        nonlocal passed, failed
        st, pr, hi = copy.deepcopy(base_store), copy.deepcopy(base_profile), copy.deepcopy(base_history)
        mutate(st, pr, hi)
        rc, _out = _preflight_rc(st, pr, hi, signoff=signoff)
        if rc == 0:
            passed += 1; print(f"  PASS (ready, not over-blocked) {name}")
        else:
            failed += 1; print(f"  FAIL (justified content wrongly BLOCKED) {name}")
    _probe_ready("[combo] justified 'N/A: <reason>' on NARRATIVE fields stays READY",
                 _justified_combo)

    # A hollow CDS-CSO-PUB OVERRIDE is ignored in favour of the derived real
    # values (AUD-F39 one-place-per-fact): the package stays READY. Pairs with
    # probes 12/13, which hollow the sources themselves.
    _probe_ready("hollow CDS-CSO-PUB override is ignored; derived real values keep the package READY",
                 lambda st, pr, hi: _fill_cpo(st, pr, hi, "CDS-CSO-PUB", "N/A"))

    # ---- Mandatory-identity probes: a JUSTIFIED 'N/A: <reason>' must still BLOCK
    #      for fields that MUST name a real entity. This is the false-ready edge
    #      the hollow-value hardening opened (justified N/A accepted for an
    #      identity), now closed with a stricter predicate. Each of these is a
    #      BLOCK probe, not a ready probe. ----
    JUST = "N/A: provider uses an alternate internal process (justification)."

    def _just_assessor_name(st, pr, hi):
        pr["fedramp_independent_assessment"]["assessor_name"] = JUST
    probe("justified 'N/A' assessor_name still blocks (FRC-APP-FIA identity)",
          _just_assessor_name)

    def _just_assessor_id(st, pr, hi):
        pr["fedramp_independent_assessment"]["assessor_fedramp_id"] = JUST
    probe("justified 'N/A' assessor_fedramp_id still blocks (Recognition id)",
          _just_assessor_id)

    def _just_contacts(st, pr, hi):
        pr["security_contact"] = JUST
        pr["sales_contact"] = JUST
    probe("justified 'N/A' Sales/Security contact still blocks (CDS-CSO-PUB)",
          _just_contacts)

    def _just_mtd_official(st, pr, hi):
        pr["cpo_responsible_official"] = JUST
    probe("justified 'N/A' CPO responsible_official still blocks (CPO-CSO-MTD)",
          _just_mtd_official)

    # ---- AUD-F37: the metric history is the collector's record, not a file
    # someone completed. Each tamper below is exactly what the delivery review
    # said was possible: fill the history in after the fact, or satisfy "two
    # working automated methods" by asserting a series. ----
    sys.path.insert(0, os.path.join(BASE, "automation", "metrics"))
    import history_integrity as _hint

    def _first_kid(hi_):
        return sorted(hi_["ksis"].keys())[0]

    def _backfill_observation(st, pr, hi_):
        # Insert a plausible, self-consistently hashed observation for a day
        # that was never collected, in the middle of the chain.
        kid = _first_kid(hi_)
        obs = hi_["ksis"][kid]["observations"]
        fake_date = (dt.date.fromisoformat(obs[3]["date"]) + dt.timedelta(days=1)).isoformat()
        fake = _hint.chain_observation({"observed_at": f"{fake_date}T06:00:00+00:00", "date": fake_date,
                                        "passing": 2, "total": 2}, obs[3]["hash"],
                                       {"run_id": "run-SAMPLE-fictional", "facts_sha256": "sha256:" + "f1c7" * 16})
        obs.insert(4, fake)
    probe("backfilled observation inserted mid-chain blocks (chain-break)", _backfill_observation)

    def _edit_observation(st, pr, hi_):
        kid = _first_kid(hi_)
        hi_["ksis"][kid]["observations"][5]["passing"] = 0  # rewrite history, keep the old hash
    probe("edited past observation blocks (bad-hash)", _edit_observation)

    def _delete_observation(st, pr, hi_):
        kid = _first_kid(hi_)
        del hi_["ksis"][kid]["observations"][7]  # a bad day vanishes; its series point stays
    probe("deleted observation blocks (chain-break and unbacked series point)", _delete_observation)

    def _stale_method(st, pr, hi_):
        # One declared method's series stopped 60 days ago: still "exists",
        # no longer working. Class C needs TWO working methods.
        kid = _first_kid(hi_)
        m = hi_["ksis"][kid]["metrics"][plat.method_ids(kid)[1]]
        cutoff = (TODAY - dt.timedelta(days=60)).isoformat()
        m["series"] = [p for p in m["series"] if p["date"] < cutoff]
    probe("declared method whose series went stale 60 days ago blocks (vvk binding freshness)",
          _stale_method)

    # Production-assurance probes. A throwaway EC key stands in for the separate
    # signer's KMS key; its public key is pinned the way a verifier would, which
    # makes evidence signing REQUIRED (the default once a key is pinned).
    sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))
    import evidence_wiring as _ew
    import sign_evidence as _se

    def _pin_signer_and_sign_history(pr, hi_):
        import base64
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key = ec.generate_private_key(ec.SECP256R1())
        pub_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        digest = _hint.record_heads(hi_)
        sig = key.sign(digest.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        key_arn = plat.signer_key_ref
        hi_["meta"]["history_signature"] = {"algorithm": "ECDSA_SHA_256", "keyId": key_arn,
                                            "signedHash": digest,
                                            "signature": base64.b64encode(sig).decode("ascii")}
        pr["evidence_store_profile"] = "production-assurance"
        pr["expected_evidence_signer"] = {plat.signer_pin_field: key_arn, "public_key_pem": pub_pem,
                                          "signer_kind": "managed-key-service"}
        return key, key_arn

    def _bind_sample_evidence(st, sign_with=None):
        """Replace the sample's hand-written (hashless) evidence with entries
        derived by the canonical factory, so the integrity gate can recompute
        each digest from the entry's own bound fields; optionally sign each
        digest with the probe's key the way sign_evidence.py would. AUD-F62:
        each KSI's entry is derived from a source the OFFERING operates for
        that KSI (collector registry, config-rules manifest or an enabled
        adapter, AUD-F79), the same bindings the production gate checks; a
        fictional check name would be a valid digest over an observation
        nothing maps to the indicator. A platform whose store already carries
        adapter-derived entries (MCE-12) keeps them and only signs them."""
        import base64
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        import validate_evidence as _ve
        observed = f"{TODAY.isoformat()}T00:00:00+00:00"
        base = plat.location_base
        # The bindings the GATE will read for this offering: scoped to the
        # sources the sample profile declares it operates (AUD-F79), not to the
        # committed template on disk at this moment.
        bindings = _ve.load_source_bindings(profile=base_profile)

        def sign(ev):
            key, key_arn = sign_with
            h = ev["xEvidenceContentHash"]
            sig = key.sign(h.encode("ascii"), ec.ECDSA(hashes.SHA256()))
            # As sign_evidence.sign_hash records it: the key REFERENCE, never
            # the ARN (which would carry the account id into the scanned
            # package, AUD-F60); the profile pins the ARN.
            ev["xEvidenceSignature"] = {"algorithm": "ECDSA_SHA_256",
                                        "keyId": _se.key_reference(key_arn),
                                        "signedHash": h,
                                        "signature": base64.b64encode(sig).decode("ascii")}
            return ev

        def one(service, check, what):
            ev = _ew.fact_to_evidence(
                {"service": service, "check": check, "status": "PASS", "region": plat.region,
                 "detail": f"{FICT} {what} evaluation history", "collected_at": observed},
                location_base=base)
            if sign_with is not None:
                sign(ev)
            return ev

        for kid, rec in st["ksi"].items():
            if rec.get("evidence"):
                if plat.rebind_ksi_evidence:
                    source = _ve.first_bound_source(kid, bindings)
                    if source is None:
                        raise RuntimeError(f"{kid}: the offering operates no evidence source for it")
                    rec["evidence"] = [one(source[0], source[1], kid)]
                elif sign_with is not None:
                    for ev in rec["evidence"]:
                        if ev.get("xEvidenceContentHash"):
                            sign(ev)
        for rid, rec in st["frr"].items():
            ext = rec.get("extension") or {}
            if ext.get("rule_artifacts"):
                ext["rule_artifacts"] = [one(plat.frr_source_service, f"frr-{rid.lower()}", rid)]
        return one

    def _production_unsigned(st, pr, hi_):
        pr["evidence_store_profile"] = "production-assurance"
    probe("production-assurance profile with an UNSIGNED history digest blocks", _production_unsigned)

    def _rechained_tamper_with_forged_signature(st, pr, hi_):
        # The sophisticated attacker: edit, rechain (chain verifies again) and
        # attach a signature block that does not verify under the pinned signer.
        kid = _first_kid(hi_)
        hi_["ksis"][kid]["observations"][5]["passing"] = 0
        _hint.rechain(hi_, {"run_id": "run-SAMPLE-fictional", "facts_sha256": "sha256:" + "f1c7" * 16})
        hi_["meta"]["history_signature"] = {"algorithm": "ECDSA_SHA_256", "keyId": "arn:aws:kms:x:0:key/forged",
                                            "signedHash": hi_["meta"]["history_digest"],
                                            "signature": "AAAA"}
    probe("rechained tamper carrying a signature that does not verify blocks", _rechained_tamper_with_forged_signature)

    def _unknown_profile(st, pr, hi_):
        pr["evidence_store_profile"] = "prod"
    probe("unknown evidence_store_profile value blocks (no silent default)", _unknown_profile)

    # MCE-09 / AUD-F73: production-assurance is the provider's declaration of a
    # tamper-evident store. A store attested as neither versioned nor write-once
    # leaves that declaration with nothing behind it, so it must block; a
    # merely ABSENT attestation is a readiness finding, never a blocker.
    def _production_store_attests_no_tamper_evidence(st, pr, hi_):
        key, key_arn = _pin_signer_and_sign_history(pr, hi_)
        _bind_sample_evidence(st, sign_with=(key, key_arn))  # otherwise READY
        pr["evidence_store"]["versioned"] = False
        pr["evidence_store"]["write_once"] = False
    probe("production-assurance with a store attesting NEITHER versioning nor write-once blocks (AUD-F73)",
          _production_store_attests_no_tamper_evidence, expect="AUD-F73")

    # MCE-08 / AUD-F74: a software PEM key is held by the pipeline that runs
    # it, so it is not separately administered; declaring it under
    # production-assurance contradicts the declaration and must block.
    def _production_software_key_signer(st, pr, hi_):
        key, key_arn = _pin_signer_and_sign_history(pr, hi_)
        _bind_sample_evidence(st, sign_with=(key, key_arn))  # otherwise READY
        pr["expected_evidence_signer"]["signer_kind"] = "software-key"
    probe("production-assurance with a SOFTWARE-KEY signer declared blocks (AUD-F74, not separately administered)",
          _production_software_key_signer, expect="AUD-F74")

    # AUD-F57 / AUD-F59 end to end. With a signer pinned (signing required) the
    # sample's own hand-written evidence has no digest and no signature: that is
    # exactly the shape an editor leaves behind after deleting both, and it used
    # to reach READY (a soft "no content hash yet" finding before the
    # required-signer check, and a presence-only linkage gate).
    def _production_hashless_evidence(st, pr, hi_):
        _pin_signer_and_sign_history(pr, hi_)  # evidence left hashless
        # The AWS sample's hand-written entries carry no digest; a platform
        # whose entries are adapter-derived (MCE-12) is brought to the same
        # shape, so the probe tests what its name says on every platform.
        for rec in st["ksi"].values():
            for ev in rec.get("evidence") or []:
                ev.pop("xEvidenceContentHash", None)
                ev.pop("xEvidenceSignature", None)
    probe("production-assurance + pinned signer with HASHLESS evidence blocks (AUD-F57/F59)",
          _production_hashless_evidence)

    def _production_hashed_unsigned_evidence(st, pr, hi_):
        _pin_signer_and_sign_history(pr, hi_)
        _bind_sample_evidence(st)  # digests recompute, but no entry is signed
    probe("production-assurance + pinned signer with hashed but UNSIGNED evidence blocks (finding 8)",
          _production_hashed_unsigned_evidence)

    def _production_signed_evidence_one_digest_deleted(st, pr, hi_):
        key, key_arn = _pin_signer_and_sign_history(pr, hi_)
        _bind_sample_evidence(st, sign_with=(key, key_arn))
        kid = sorted(st["ksi"])[0]
        e = st["ksi"][kid]["evidence"][0]
        e.pop("xEvidenceContentHash")
        e.pop("xEvidenceSignature")  # the AUD-F57 downgrade on ONE entry
    probe("production-assurance: deleting ONE entry's digest + signature blocks (AUD-F57)",
          _production_signed_evidence_one_digest_deleted)

    # NEGATIVE: production-assurance IS satisfiable. Signed history digest,
    # pinned signer, and every evidence entry bound, hashed and signed.
    def _production_signed(st, pr, hi_):
        key, key_arn = _pin_signer_and_sign_history(pr, hi_)
        _bind_sample_evidence(st, sign_with=(key, key_arn))
    _probe_ready("production-assurance with a VALID signed digest, pinned signer and signed "
                 "evidence stays READY", _production_signed)

    # Orthogonal provenance tampers (AUD-F62/F63/F64). Each starts from the
    # READY production package above and tampers ONE semantic dimension of ONE
    # entry, then RECOMPUTES the digest and RE-SIGNS it with the pinned key, so
    # the cryptographic gate stays silent and only the semantic gate can block.
    def _resign(ev, key, key_arn):
        import base64
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        ev["xEvidenceContentHash"] = _ew.evidence_hash(_ew.canonical_payload(ev))
        sig = key.sign(ev["xEvidenceContentHash"].encode("ascii"), ec.ECDSA(hashes.SHA256()))
        ev["xEvidenceSignature"] = {"algorithm": "ECDSA_SHA_256", "keyId": _se.key_reference(key_arn),
                                    "signedHash": ev["xEvidenceContentHash"],
                                    "signature": base64.b64encode(sig).decode("ascii")}

    def _production_wrong_source(st, pr, hi_):
        key, key_arn = _pin_signer_and_sign_history(pr, hi_)
        one = _bind_sample_evidence(st, sign_with=(key, key_arn))
        import validate_evidence as _ve
        bindings = _ve.load_source_bindings(profile=base_profile)
        kids = sorted(st["ksi"])
        # A source the repository registers for ANOTHER KSI, derived and signed
        # exactly like the legitimate entries, attached to the first KSI.
        victim = kids[0]
        donor = next(k for k in kids[1:]
                     if _ve.first_bound_source(k, bindings) != _ve.first_bound_source(victim, bindings)
                     and _ve.classify_source_binding(victim, one(*_ve.first_bound_source(k, bindings), k), bindings)[0] == "unbound")
        st["ksi"][victim]["evidence"] = [one(*_ve.first_bound_source(donor, bindings), victim)]
    probe("production-assurance: a VALID signed entry from a source registered for a DIFFERENT KSI "
          "blocks (AUD-F62, query binding)", _production_wrong_source,
          expect="not PROVENANCE-BOUND (1 source (e.g.")

    def _production_pointer_swapped(st, pr, hi_):
        key, key_arn = _pin_signer_and_sign_history(pr, hi_)
        _bind_sample_evidence(st, sign_with=(key, key_arn))
        kids = sorted(st["ksi"])
        a, b = st["ksi"][kids[0]]["evidence"][0], st["ksi"][kids[1]]["evidence"][0]
        a["evidenceLocation"] = b["evidenceLocation"]  # another observation's pointer
        _resign(a, key, key_arn)
    probe("production-assurance: a pointer re-targeted to another observation, digest recomputed and "
          "re-signed, blocks (AUD-F63, source binding)", _production_pointer_swapped,
          expect="not PROVENANCE-BOUND (1 pointer (e.g.")

    def _production_stale_resigned(st, pr, hi_):
        key, key_arn = _pin_signer_and_sign_history(pr, hi_)
        _bind_sample_evidence(st, sign_with=(key, key_arn))
        old = (TODAY - dt.timedelta(days=400))
        kid = sorted(st["ksi"])[0]
        ev = st["ksi"][kid]["evidence"][0]
        ev["lastUpdated"] = old.isoformat()
        # The AWS collector stamps collected_at; adapter facts carry observed_at.
        for field in ("collected_at", "observed_at"):
            if field in ev["xSourceFact"]:
                ev["xSourceFact"][field] = f"{old.isoformat()}T00:00:00+00:00"
        _resign(ev, key, key_arn)
    probe("production-assurance: a 400-day-old observation with a recomputed, re-signed digest blocks "
          "at Class C (AUD-F64, freshness)", _production_stale_resigned,
          expect="backed only by EXPIRED evidence")

    # MCE-03: adapters bind exactly the (service, check) pairs they DECLARE,
    # per KSI target. The Falcon adapter declares open_detections for four
    # MLA/INR indicators; the same signed entry elsewhere, or an undeclared
    # check under its own target, is a valid digest over an observation that
    # maps to no indicator. These four probes belong to the AWS sample, which
    # enables the Falcon source and leaves Wiz off (plat.adapter_probes).
    _FALCON_TARGETS = ("KSI-MLA-OSM", "KSI-MLA-RVL", "KSI-MLA-LET", "KSI-INR-RIR")

    def _production_adapter_pair_wrong_ksi(st, pr, hi_):
        key, key_arn = _pin_signer_and_sign_history(pr, hi_)
        one = _bind_sample_evidence(st, sign_with=(key, key_arn))
        victim = next(k for k in sorted(st["ksi"])
                      if k not in _FALCON_TARGETS and st["ksi"][k].get("evidence"))
        st["ksi"][victim]["evidence"] = [one("crowdstrike", "open_detections", victim)]

    def _production_adapter_undeclared_check(st, pr, hi_):
        key, key_arn = _pin_signer_and_sign_history(pr, hi_)
        one = _bind_sample_evidence(st, sign_with=(key, key_arn))
        st["ksi"]["KSI-MLA-OSM"]["evidence"] = [one("crowdstrike", "made_up_check", "KSI-MLA-OSM")]

    def _production_adapter_declared_pair(st, pr, hi_):
        key, key_arn = _pin_signer_and_sign_history(pr, hi_)
        one = _bind_sample_evidence(st, sign_with=(key, key_arn))
        st["ksi"]["KSI-MLA-OSM"]["evidence"] = [one("crowdstrike", "open_detections", "KSI-MLA-OSM")]

    # AUD-F79: an adapter binds only for an offering that ENABLES it. The sample
    # enables Falcon and leaves Wiz off, so Wiz's declared pair under its own
    # target KSI names a source this offering does not operate: a valid digest
    # and signature over an observation the provider says it never collected.
    def _production_disabled_adapter_pair(st, pr, hi_):
        key, key_arn = _pin_signer_and_sign_history(pr, hi_)
        one = _bind_sample_evidence(st, sign_with=(key, key_arn))
        st["ksi"]["KSI-MLA-EVC"]["evidence"] = [one("wiz", "vulnerabilities", "KSI-MLA-EVC")]

    if plat.adapter_probes:
        probe("production-assurance: an ADAPTER's declared pair (crowdstrike:open_detections), signed, under a "
              "KSI the adapter does not target blocks (MCE-03, declared binding)", _production_adapter_pair_wrong_ksi,
              expect="not PROVENANCE-BOUND (1 source (e.g.")
        probe("production-assurance: an UNDECLARED check under the adapter's own service and target KSI, "
              "signed, blocks (MCE-03: nothing is inferred from a service name)", _production_adapter_undeclared_check,
              expect="not PROVENANCE-BOUND (1 source (e.g.")
        _probe_ready("production-assurance: the adapter's declared pair (crowdstrike:open_detections) under its "
                     "target KSI-MLA-OSM stays READY (MCE-03 positive control; MUT-F72 removes this binding)",
                     _production_adapter_declared_pair)
        probe("production-assurance: a DISABLED adapter's declared pair (wiz:vulnerabilities, evidence_sources.wiz "
              "off) under its own target KSI-MLA-EVC, signed, blocks (AUD-F79: not a source this offering operates)",
              _production_disabled_adapter_pair, expect="not PROVENANCE-BOUND (1 source (e.g.")

    # Platform-specific probes (MCE-12): the toolkit is the same closures the
    # shared probes use, so a platform's probe is pinned the same way.
    class _Harness:
        pass
    harness = _Harness()
    harness.probe = probe
    harness.probe_ready = _probe_ready
    harness.pin_signer = _pin_signer_and_sign_history
    harness.bind_evidence = _bind_sample_evidence
    harness.resign = _resign
    harness.base_store = base_store
    harness.base_profile = base_profile
    harness.base_history = base_history
    plat.extra_probes(harness)

    print(f"\n{passed}/{passed + failed} assessor-attack probes passed "
          "(each tamper must be BLOCKED; baseline + justified-narrative combo must be READY)")
    return 0 if failed == 0 else 1


def run(argv):
    tmp = tempfile.mkdtemp(prefix="sdr-classc-")
    baks = _backup(tmp)
    # Build ALL sample content in memory BEFORE any write, so a partial write
    # cannot corrupt a file a later generator reads.
    store = generate_store()
    profile = generate_profile()
    history = generate_history(store)
    history_existed = os.path.exists(REAL_HISTORY)
    try:
        with open(REAL_STORE, "w", encoding="utf-8", newline="\n") as f:
            json.dump(store, f, indent=1)
        with open(REAL_PROFILE, "w", encoding="utf-8", newline="\n") as f:
            json.dump(profile, f, indent=1)
        with open(REAL_HISTORY, "w", encoding="utf-8", newline="\n") as f:
            json.dump(history, f, indent=1)
        # Build first so generated artifacts + manifest reflect the sample.
        subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "build"],
                       cwd=BASE, capture_output=True, text=True)
        # Record a package signoff bound to the freshly-built manifest hash.
        _record_signoff()
        pf = subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "package-preflight"],
                            cwd=BASE, capture_output=True, text=True)
        print((pf.stdout or "") + (pf.stderr or ""))
        print(f"\nClass C package-preflight exit code: {pf.returncode} "
              f"({'READY' if pf.returncode == 0 else 'BLOCKED'})")
        return pf.returncode
    finally:
        _restore_tree(baks, history_existed, tmp)


def _record_signoff(reviewer=None, note=None):
    """Write a package_signoff into the review register, bound to the current
    release manifest's tag AND its exact SHA-256 (the binding preflight checks).
    Fictional signer; illustrative only. Another sample platform (MCE-12) names
    its own fictional reviewer; the defaults are the AWS sample's."""
    import hashlib
    register_path = os.path.join(BASE, "sdr", "reviews", "review-register.json")
    manifest = json.load(open(MANIFEST, encoding="utf-8"))
    with open(MANIFEST, "rb") as f:
        manifest_sha = "sha256:" + hashlib.sha256(f.read()).hexdigest()
    register = {}
    if os.path.exists(register_path):
        register = json.load(open(register_path, encoding="utf-8"))
    register["package_signoff"] = {
        "decision": "approved",
        "reviewer": reviewer or "D. Okafor, BFC Authorizing Official (fictional)",
        "timestamp": TODAY.isoformat(),
        "release_tag": manifest.get("release_tag"),
        "package_manifest_sha256": manifest_sha,
        "note": note or f"{FICT} Package-level provider signoff for the Class C sample.",
    }
    with open(register_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(register, f, indent=1)
    return None


if __name__ == "__main__":
    if "--attack" in sys.argv:
        sys.exit(attack())
    sys.exit(run(sys.argv))
