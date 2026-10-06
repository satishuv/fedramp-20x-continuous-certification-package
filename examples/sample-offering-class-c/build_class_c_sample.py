#!/usr/bin/env python3
"""Build a fully-worked FICTIONAL Class C sample and drive it to submission
preflight, so the HARDEST gates are exercised end-to-end: >=2 automated methods
per KSI (FRC-CSX-VVK), a >=6-month persistent-validation history (FRC-CSX-MOT),
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
BACKED_UP = (REAL_STORE, REAL_PROFILE, REAL_HISTORY) + REAL_REPORTS


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

    Restores every backed-up file (inputs AND validation reports), removes the
    sample metric history if none existed before, restores the review register
    (the signoff is sample-only), then regenerates EVERY deliverable from the
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
    subprocess.run(["git", "-C", BASE, "checkout", "--",
                    "sdr/reviews/review-register.json"], capture_output=True, text=True)
    shutil.rmtree(tmp, ignore_errors=True)
    subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "build"],
                   cwd=BASE, capture_output=True, text=True)
MANIFEST = os.path.join(BASE, "artifacts", "release-manifest.json")

TODAY = dt.date.today()
FICT = "[SAMPLE - fictional, not an attestation]"


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


def generate_history(store):
    """A >=6-month daily-ish metric history per KSI, in the REAL production
    shape append_metrics writes: {"ksis": {kid: {"series": [...], "metrics": {...},
    "observations": [...]}}, "meta": {...}}.

    The per-method "metrics" map is keyed by the SAME method_ids the KSI declares
    in its records-store tests ({kid}-config-rule, {kid}-api-collector), so each
    declared automated VVK method is BOUND to observed telemetry. This satisfies
    the Class C/D method-to-telemetry binding gate: a declared automated method
    that produced no keyed telemetry is a false-ready path and must block.

    AUD-F37: every series point has an observation behind it, and the
    observations are hash-chained with (fictional, labelled) run provenance, so
    the sample passes the chain-integrity gate the way a collector-produced
    history does. The digest is NOT signed: the sample declares the development
    profile, where an unsigned digest is an advisory; production-assurance would
    block it, which is the point."""
    sys.path.insert(0, os.path.join(BASE, "automation", "metrics"))
    import history_integrity as hi
    ksis = list(store.get("ksi", {}).keys())
    hist = {"ksis": {}, "meta": {}}
    for kid in ksis:
        series = []
        observations = []
        per_method = {f"{kid}-config-rule": [], f"{kid}-api-collector": []}
        # 200 days back to today, weekly datapoints (well over the 183-day min).
        d = TODAY - dt.timedelta(days=200)
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


def _preflight_rc(store, profile, history, post_sign=None):
    """Apply the given in-memory inputs, build, sign, run package-preflight,
    return (returncode, output). Always restores real inputs after. If post_sign
    is given, it is called after the (correct) signoff is written and before
    preflight runs, so a probe can tamper with the manifest-bound signoff."""
    tmp = tempfile.mkdtemp(prefix="sdr-attack-")
    baks = _backup(tmp)
    history_existed = os.path.exists(REAL_HISTORY)
    try:
        json.dump(store, open(REAL_STORE, "w", encoding="utf-8", newline="\n"), indent=1)
        json.dump(profile, open(REAL_PROFILE, "w", encoding="utf-8", newline="\n"), indent=1)
        json.dump(history, open(REAL_HISTORY, "w", encoding="utf-8", newline="\n"), indent=1)
        subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "build"],
                       cwd=BASE, capture_output=True, text=True)
        _record_signoff()
        if post_sign is not None:
            post_sign()
        pf = subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "package-preflight"],
                            cwd=BASE, capture_output=True, text=True)
        return pf.returncode, (pf.stdout or "") + (pf.stderr or "")
    finally:
        _restore_tree(baks, history_existed, tmp)


def attack():
    """Assessor attack: start from the READY Class C package, apply one hollowing
    tamper at a time, and assert preflight BLOCKS each. A tamper that still
    reaches 'ready' is a framework gap."""
    import copy
    base_store = generate_store()
    base_profile = generate_profile()
    base_history = generate_history(base_store)
    passed = failed = 0

    def probe(name, mutate, post_sign=None):
        nonlocal passed, failed
        st, pr, hi = copy.deepcopy(base_store), copy.deepcopy(base_profile), copy.deepcopy(base_history)
        mutate(st, pr, hi)
        rc, _out = _preflight_rc(st, pr, hi, post_sign=post_sign)
        blocked = rc != 0
        if blocked:
            passed += 1; print(f"  PASS (blocked) {name}")
        else:
            failed += 1; print(f"  FAIL (reached READY despite tamper) {name}")

    # Baseline: the unmutated package must be READY (else the probes are meaningless).
    rc0, _ = _preflight_rc(copy.deepcopy(base_store), copy.deepcopy(base_profile),
                           copy.deepcopy(base_history))
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

    # 12. CDS-CSO-PUB object with every required member set to a bare "N/A"
    #     (structurally complete, semantically empty) -> must block.
    probe("CPO CDS-CSO-PUB members all bare 'N/A' block (hollow but structured)",
          lambda st, pr, hi: _fill_cpo(st, pr, hi, "CDS-CSO-PUB", "N/A"))

    # 13. CDS-CSO-PUB members set to a single "." -> a one-char non-answer that
    #     is neither empty nor a TBD marker must not pass as resolved.
    probe("CPO CDS-CSO-PUB members all '.' block (single-char non-answer)",
          lambda st, pr, hi: _fill_cpo(st, pr, hi, "CDS-CSO-PUB", "."))

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
        rc, _out = _preflight_rc(st, pr, hi)
        if rc == 0:
            passed += 1; print(f"  PASS (ready, not over-blocked) {name}")
        else:
            failed += 1; print(f"  FAIL (justified content wrongly BLOCKED) {name}")
    _probe_ready("[combo] justified 'N/A: <reason>' on NARRATIVE fields stays READY",
                 _justified_combo)

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
        m = hi_["ksis"][kid]["metrics"][f"{kid}-api-collector"]
        cutoff = (TODAY - dt.timedelta(days=60)).isoformat()
        m["series"] = [p for p in m["series"] if p["date"] < cutoff]
    probe("declared method whose series went stale 60 days ago blocks (vvk binding freshness)",
          _stale_method)

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

    # NEGATIVE: production-assurance IS satisfiable. Sign the digest with a
    # throwaway EC key (standing in for the separate signer's KMS key), pin its
    # public key the way a verifier would, and the package is READY.
    def _production_signed(st, pr, hi_):
        import base64
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key = ec.generate_private_key(ec.SECP256R1())
        pub_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
        digest = _hint.record_heads(hi_)
        sig = key.sign(digest.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        key_arn = "arn:aws:kms:us-east-1:000000000000:key/SAMPLE-fictional-signer"
        hi_["meta"]["history_signature"] = {"algorithm": "ECDSA_SHA_256", "keyId": key_arn,
                                            "signedHash": digest,
                                            "signature": base64.b64encode(sig).decode("ascii")}
        pr["evidence_store_profile"] = "production-assurance"
        pr["expected_evidence_signer"] = {"key_arn": key_arn, "public_key_pem": pub_pem}
    _probe_ready("production-assurance with a VALID signed digest and pinned signer stays READY",
                 _production_signed)

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


def _record_signoff():
    """Write a package_signoff into the review register, bound to the current
    release manifest's tag AND its exact SHA-256 (the binding preflight checks).
    Fictional signer; illustrative only."""
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
        "reviewer": "D. Okafor, BFC Authorizing Official (fictional)",
        "timestamp": TODAY.isoformat(),
        "release_tag": manifest.get("release_tag"),
        "package_manifest_sha256": manifest_sha,
        "note": f"{FICT} Package-level provider signoff for the Class C sample.",
    }
    with open(register_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(register, f, indent=1)
    return None


if __name__ == "__main__":
    if "--attack" in sys.argv:
        sys.exit(attack())
    sys.exit(run(sys.argv))
