#!/usr/bin/env python3
"""End-to-end submission-readiness test.

Proves two things a green template build never exercised:
  1. A fully-filled Class C offering reaches "Submission ready" (preflight
     exits 0) - i.e. every preflight blocker is clearable by real provider
     input. This locks in the trust-center/SCG dead-end fix: those CPO URLs
     are now driven by trust_center_uri / secure_config_guide_uri.
  2. Changing a provider input AFTER a manifest-bound package signoff
     invalidates that signoff (preflight blocks on the manifest hash), proving
     the signoff is cryptographically bound to the exact package.

Operates entirely in a temp copy of the repo; the real tree is untouched.

    python validation/scripts/test_submission_readiness.py
"""

import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS {name}")
    else:
        FAIL += 1; print(f"  FAIL {name}")


def _fill(profile_path, now, cls="C"):
    prof = json.load(open(profile_path, encoding="utf-8"))
    prof.update({
        "certification_class": cls,
        "organization_name": "Contoso Federal Cloud LLC",
        "offering_name": "Contoso Secure Platform",
        "offering_abbreviation": "CSP",
        "deployment_model": "Government-Only Cloud",
        "service_model": "PaaS",
        "management_plane": "Provider-hosted control plane isolated from customer workloads.",
        "federal_information_types": "Moderate impact federal operational data.",
        "certification_package_overview_uri": "https://contoso.gov/cpo.json",
        "security_contact": "security@contoso.gov",
        "incident_contact": "soc@contoso.gov",
        "assessor": "Acme FedRAMP Assessors LLC",
        "evidence_retention": "3 years",
        "provider_verified_at": now.isoformat(),
        "fedramp_package_id": "FR-2026-CSP-0001",
        "offering_website": "https://contoso.gov",
        "offering_logo_uri": "https://contoso.gov/logo.png",
        "assessor_id": "482913",
        "sales_contact": "sales@contoso.gov",
        "next_ocr_date": (now.date() + datetime.timedelta(days=90)).isoformat(),
        "trust_center_uri": "https://contoso.gov/trust",
        "secure_config_guide_uri": "https://contoso.gov/scg",
        "secure_config_guide_machine_uri": "https://contoso.gov/scg/machine-readable.json",
        # FRC-APP-FIA (B/C MUST): fresh FedRAMP independent assessment < 3 months.
        "fedramp_independent_assessment": {
            "assessor_name": "Acme FedRAMP Assessors LLC",
            "assessor_fedramp_id": "FR-ASSESSOR-0007",
            "completed_at": (now.date() - datetime.timedelta(days=30)).isoformat(),
            "assessment_summary_uri": "https://contoso.gov/assessment-summary.pdf",
            "assessment_report_uri": "https://contoso.gov/assessment-report.pdf",
            "assessment_report_sha256": "sha256:" + "b" * 64,
        },
        # CPO-CSO-OSA (B/C MUST): assessor overall summary in the CPO.
        "overall_assessment_summary": "Assessor confirmed all in-scope KSIs "
                                       "verified and validated; no critical findings.",
        # CDS-CSO-AVR (B/C MUST): 30-day availability service, both formats.
        "availability_reporting": {
            "human_readable_uri": "https://contoso.gov/status",
            "machine_readable_uri": "https://contoso.gov/status.json",
            "history_days": 30,
            "available_when_primary_unavailable": True,
            "verified_at": now.date().isoformat(),
        },
        # CPO-CSO-MTD metadata + CPO-CSO-OVR required information.
        "cpo_responsible_official": "Jane Provider, VP Security, jane@contoso.gov",
        "cpo_version": "1.0.0",
        "cpo_last_updated": now.isoformat(),
        "cpo_source_of_update": "Initial certification package preparation",
        "cpo_required_information": {
            "CPO-CSO-MTD": "See metadata section.",
            "CDS-CSO-PUB": {
                "FedRAMP ID": "FR2026-CSP-0001",
                "Service Model": "SaaS",
                "Deployment Model": "Government Community Cloud",
                "Business Category": "IT Management",
                "UEI Number": "ABC123DEF456",
                "Sales Contact Information": "sales@contoso.gov",
                "Security Contact Information": "security@contoso.gov",
                "Product Website Link": "https://contoso.gov/product",
                "Link to Product Logo": "https://contoso.gov/logo.png",
                "Overall Service Description": "Contoso secure workflow platform.",
                "Detailed list of specific services and their security categories": "https://contoso.gov/services",
                "Link to Secure Configuration Guidance": "https://contoso.gov/scg",
                "Overview of documentation supplied by the provider for the cloud service offering": "https://contoso.gov/docs",
                "Link to Trust Center landing page that includes instructions on accessing information in the trust center": "https://contoso.gov/trust",
                "Next Ongoing Certification Report date": "2027-03-01",
                "Current FedRAMP Recognized independent assessment service": "Acme FedRAMP Assessors LLC (FR-ASSESSOR-0007)",
            },
            "CDS-CSO-SVC": "Service list published at https://contoso.gov/services.",
            "CDS-CSO-IRP": [
                {
                    "Name of policy or procedure": "Access Control Policy",
                    "Name of file document web page etc": "ac-policy.pdf",
                    "Brief summary of policy or procedure": "Governs least-privilege access.",
                    "Word count of document": "3200",
                    "Current version": "2.1",
                    "Date of last update": "2026-06-01",
                    "Related FedRAMP Practices": "KSI-IAM-AAM",
                },
            ],
            "MAS-CSO-IIR": "Information resources enumerated in the SDR scope.",
            "MAS-CSO-FLO": "Information flows and security categories documented.",
            "MAS-CSO-TPR": [
                {
                    "General usage and configuration": "Managed database service.",
                    "Explanation or justification for use": "Primary datastore.",
                    "Mitigation measures in place to reduce the potential impact to federal customer data": "Encryption at rest, VPC isolation.",
                    "Compensating controls in place to reduce the potential impact to federal customer data": "Continuous monitoring alerts.",
                },
            ],
            "CMU-CSO-CMD": "FIPS-validated cryptographic modules documented.",
            "IVV-CSO-ICP": "Independent assessment results included per FIA.",
        },
        "application_prerequisites": {
            "marketplace_listing_uri": "https://marketplace.fedramp.gov/offerings/CSP",
            "application_form_reference": "APP-FORM-2026-CSP-0001",
            "provider_is_applicant": True,
            "provider_is_applicant_attestation": "Confirmed: Contoso Cloud (the CSP) is the applicant; no third party is submitting on our behalf (FRC-APP-NTP).",
        },
    })
    if cls == "A":
        # Class A: alternative-framework external assessment (FRC-CLA-ASF/EAM),
        # within the past 12 months. FIA/SCG/AVR-MUST/MOT do not apply to A.
        prof["external_assessment"] = {
            "framework": "SOC 2 Type II",
            "assessment_date": (now.date() - datetime.timedelta(days=60)).isoformat(),
            "assessor": "Acme SOC 2 Auditors LLP",
            "materials": [
                {"type": "complete_report",
                 "uri": "https://contoso.gov/soc2-2026.pdf",
                 "sha256": "sha256:" + "a" * 64},
                {"type": "verified_audit_engagement",
                 "uri": "https://contoso.gov/soc2-engagement.pdf",
                 "sha256": "sha256:" + "b" * 64},
                {"type": "upcoming_report_schedule",
                 "uri": "https://contoso.gov/soc2-schedule.pdf",
                 "sha256": "sha256:" + "c" * 64},
            ],
        }
    json.dump(prof, open(profile_path, "w", encoding="utf-8", newline="\n"), indent=1)


def _preflight(root):
    return subprocess.run([sys.executable, "sdr.py", "preflight"], cwd=root,
                          capture_output=True, text=True)


def _fill_records(root):
    """Answer every applicable FRR/KSI record with real (fictional) content, so
    the package has actual implementation information, not placeholders."""
    import re
    rp = os.path.join(root, "sdr", "records", "records-store.json")
    recs = json.load(open(rp, encoding="utf-8"))
    prof = json.load(open(os.path.join(root, "profiles", "common", "offering-profile.json"),
                          encoding="utf-8"))
    cls = (prof.get("certification_class") or "b").lower()
    class_profile = json.load(open(os.path.join(root, "profiles", f"class-{cls}", "profile.json"),
                                   encoding="utf-8"))
    applicable_frr = {r["rule_id"] for r in class_profile.get("rules", [])}
    ksi_profile = json.load(open(os.path.join(root, "profiles", "common", "ksi-profile.json"),
                                 encoding="utf-8"))
    if cls == "a":
        # Match production preflight: Class A resolves only the 7 CLA-enumerated
        # KSIs. Filling only those proves the ~39 non-applicable KSIs are left
        # deliberately unanswered and still do not block (rather than the test
        # quietly answering all 46 and never exercising the scoping).
        applicable_ksi = set((class_profile.get("meta", {}) or {}).get("class_a_ksis", {}).keys())
    else:
        applicable_ksi = {k["ksi_id"] for k in ksi_profile.get("indicators", [])}

    def answer(rec, ident, is_ksi):
        rec["implementation_status"] = "Implemented"
        rec["implementation"] = [f"Fictional but complete implementation for {ident}."]
        rec["validation"] = [f"Validated {ident} via automated and manual checks."]
        rec["assessment"] = [f"Independent assessor confirmed {ident}."]
        ext = rec.setdefault("extension", {})
        ext["owner"] = "Jane Provider, VP Security"
        ext["customer_risk"] = "No residual customer risk identified."
        ext["failure_response"] = "Documented runbook and on-call escalation."
        ext["responsibility"] = "Provider"
        # SDR-CSO-FRR required items (FRR) / SDR-CSX-KSI required items (KSI).
        ext["verification"] = f"Verified the implementation of {ident} is appropriate."
        ext["independent_verification"] = f"Independent assessor verified {ident}."
        ext["independent_validation"] = f"Independent assessor validated {ident}."
        ext["assessor_responses"] = "No outstanding assessor comments."
        if is_ksi:
            ext["operating_cycle"] = "Continuous / daily persistent validation."
            ext["measures_verification"] = f"Measures demonstrate {ident}."
            ext["automation_verification"] = "Automation is accurate and sufficient."
        # Evidence in the PRODUCTION shape (evidence_wiring.fact_to_evidence):
        # digest over the bound canonical payload, resolvable inline source, so
        # the integrity gate can recompute AND the entry is what the real
        # collector -> evidence path emits (AUD-F26). A hand-built legacy
        # `source_fact` digest can no longer reach `verified`.
        sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))
        from evidence_wiring import fact_to_evidence as _f2e
        fact = {"service": "config", "check": ident.lower(), "status": "pass",
                "region": "us-east-1", "detail": f"{ident} evaluated compliant",
                "collected_at": "2026-09-01T00:00:00+00:00"}
        ev = _f2e(fact, "https://contoso.gov/ev")
        if is_ksi:
            rec["evidence"] = [ev]
            # FRC-CSX-VVK Class C: >= 2 DISTINCT AUTOMATED methods. Structured
            # authoring records ({method_id, automated, cadence}); string tests
            # no longer count toward the automated minimum.
            rec["tests"] = [
                {"method_id": f"{ident}-config", "method": f"Config rule for {ident}",
                 "automated": True, "cadence": "continuous"},
                {"method_id": f"{ident}-collector", "method": f"API collector for {ident}",
                 "automated": True, "cadence": "daily"},
            ]
            # SDR-CSX-KMT historical-metric summaries are a Class C MUST; fill
            # them so a complete Class C record is genuinely complete (the
            # preflight now gates unresolved KMT summaries at B/C/D).
            rec["historical_metrics"] = {
                "last_30_days": f"30/30 days passing for {ident} over the last 30 days.",
                "up_to_one_year": f">=99% passing for {ident} across the available window.",
                "daily_data_reference": f"https://contoso.gov/metrics/{ident}/daily.json",
            }
        else:
            ext["rule_artifacts"] = [ev]
        return rec

    for rid in list(recs.get("frr", {})):
        if rid in applicable_frr:
            recs["frr"][rid] = answer(recs["frr"][rid], rid, False)
    for kid in list(recs.get("ksi", {})):
        if kid in applicable_ksi:
            recs["ksi"][kid] = answer(recs["ksi"][kid], kid, True)
    json.dump(recs, open(rp, "w", encoding="utf-8", newline="\n"), indent=1)

    # FRC-CSX-MOT: Class C needs >= 6 months of persistent-validation history.
    import datetime as _d
    today = _d.date.today()
    hist = {"ksis": {}}
    for kid in applicable_ksi:
        pts = []
        # Two config-managed metrics per KSI so the aggregate observes total=2
        # (a genuinely multi-metric KSI). This exercises finding 5: a Class C
        # package with multiple metrics must carry the per-metric breakdown to
        # be READY, not just a collapsed aggregate.
        #
        # Key the per-metric map by the SAME method_ids the record declares in
        # its tests ({ident}-config, {ident}-collector) so each declared
        # automated VVK method is BOUND to observed telemetry (the method-to-
        # telemetry binding gate). Unbound declared methods are a false-ready
        # path and must block.
        m1 = f"{kid}-config"
        m2 = f"{kid}-collector"
        s1, s2 = [], []
        for m in range(0, 8):  # ~8 months of monthly datapoints
            d = (today - _d.timedelta(days=30 * m)).isoformat()
            pts.append({"date": d, "status": "pass", "passing": 2, "total": 2})
            s1.append({"date": d, "status": "pass", "passing": 1, "total": 1})
            s2.append({"date": d, "status": "pass", "passing": 1, "total": 1})
        # Use the REAL production shape append_metrics.py writes: each KSI is an
        # object with a "series" list (the aggregate) AND a per-metric "metrics"
        # map, not a bare list. A test-only bare-list shape previously masked a
        # preflight bug that read per[kid] as a list.
        hist["ksis"][kid] = {
            "series": pts,
            "metrics": {
                m1: {"series": s1, "objective": f"Rule A for {kid}",
                     "source": f"AWS Config rule {kid}-rule-a"},
                m2: {"series": s2, "objective": f"Rule B for {kid}",
                     "source": f"AWS Config rule {kid}-rule-b"},
            },
        }
    hp = os.path.join(root, "automation", "metrics", "metric-history.json")
    json.dump(hist, open(hp, "w", encoding="utf-8", newline="\n"), indent=1)


def _build(root):
    subprocess.run([sys.executable, "sdr.py", "build"], cwd=root,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    tmp = tempfile.mkdtemp(prefix="e2e-sub-")
    root = os.path.join(tmp, "repo")
    # Copy the tree minus .git and heavy caches.
    shutil.copytree(BASE, root, ignore=shutil.ignore_patterns(
        ".git", "__pycache__", "*.log", ".tmp"))
    try:
        now = datetime.datetime.now(datetime.timezone.utc)
        profile = os.path.join(root, "profiles", "common", "offering-profile.json")
        register = os.path.join(root, "sdr", "reviews", "review-register.json")
        manifest = os.path.join(root, "artifacts", "release-manifest.json")

        _fill(profile, now)
        _build(root)

        # Stage 1: profile filled but SDR record CONTENT still placeholder.
        # preflight must BLOCK on unanswered applicable content.
        r0 = _preflight(root)
        check("profile-only (empty SDR content) is NOT submission ready",
              r0.returncode == 1 and "no implementation information" in r0.stdout)

        # Stage 2: answer every applicable record, rebuild, sign, and expect ready.
        _fill_records(root)
        _build(root)
        mhash = "sha256:" + hashlib.sha256(open(manifest, "rb").read()).hexdigest()
        tag = json.load(open(manifest, encoding="utf-8")).get("release_tag")
        reg = json.load(open(register, encoding="utf-8"))
        reg["package_signoff"] = {
            "decision": "approved", "reviewer": "Jane Provider, VP Security",
            "timestamp": now.isoformat(), "release_tag": tag,
            "package_manifest_sha256": mhash, "notes": "Reviewed full Class C package.",
        }
        json.dump(reg, open(register, "w", encoding="utf-8", newline="\n"), indent=1)

        r = _preflight(root)
        check("fully-filled Class C offering reaches Submission ready (exit 0)", r.returncode == 0)
        check("preflight reports no blockers", "SUBMISSION BLOCKERS" not in r.stdout)
        check("TBD warning is scoped to applicable records",
              "applicable to Class" in r.stdout or r.returncode == 0)

        # SDR-CSX-KMT dailyData is DERIVED from the immutable metric history and
        # must reach the submitted SDR (Class C MUST supply the actual daily
        # data, not a URL). The ready-path history above has ~8 monthly points
        # per applicable KSI, so every applicable KSI's dailyData must be
        # non-empty in the generated SDR.
        _sdr_c = json.load(open(os.path.join(root, "sdr", "json", "sdr-class-c.json"), encoding="utf-8"))
        _empty_daily = [e["ksiId"] for e in _sdr_c["keySecurityIndicators"]
                        if not (e.get("providerExtensions", {}).get("xFedRampSemantic", {})
                                .get("historicalMetrics", {}).get("dailyData"))]
        check("Class C SDR carries derived dailyData for every applicable KSI (SDR-CSX-KMT)",
              not _empty_daily)

        # Adversarial: a Class C package whose durable metric history has NO
        # in-window daily observations must BLOCK on the daily-data gate, not
        # reach ready with an empty dailyData. Wipe the history to empty series
        # and re-check (the KSIs are still present in history, so this is the
        # "in history but no observations" path the KMT gate must catch).
        hp = os.path.join(root, "automation", "metrics", "metric-history.json")
        _h = json.load(open(hp, encoding="utf-8"))
        for _e in _h.get("ksis", {}).values():
            _e["series"] = []
        json.dump(_h, open(hp, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        r_daily = _preflight(root)
        check("empty daily metric history blocks a Class C package (SDR-CSX-KMT dailyData)",
              r_daily.returncode == 1 and "kmt_daily_data" in r_daily.stdout)
        # Finding 5: a Class C KSI whose durable history shows MULTIPLE metrics
        # (aggregate total>1) but carries NO per-metric breakdown must BLOCK on
        # kmt_per_metric. Restore the ~8-month multi-metric history, then strip
        # the per-metric "metrics" map while keeping the multi-metric aggregate,
        # rebuild, and confirm the gate bites. A genuinely multi-metric KSI
        # cannot reach READY as a collapsed aggregate.
        _fill(profile, now)
        _fill_records(root)
        _build(root)
        _hpm = json.load(open(hp, encoding="utf-8"))
        for _e in _hpm.get("ksis", {}).values():
            _e.pop("metrics", None)  # keep the total=2 aggregate series, drop per-metric
        json.dump(_hpm, open(hp, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        r_pm = _preflight(root)
        check("multi-metric Class C KSI with no per-metric breakdown blocks (SDR-CSX-KMT each metric)",
              r_pm.returncode == 1 and "kmt_per_metric" in r_pm.stdout)
        # Restore the ~8-month per-metric history (and profile) for the
        # subsequent stages; _fill rewrites metric-history.json for every
        # applicable KSI (now with the per-metric map that satisfies the gate).
        _fill(profile, now)
        _fill_records(root)
        _build(root)

        # FRC-CSX-VVK method-to-telemetry binding: a Class C KSI that DECLARES
        # automated verification methods must have those method_ids bound to
        # observed telemetry (keying an in-history per-method metrics series). A
        # declaration with no keyed telemetry is a false-ready path. Rename the
        # per-method metric keys so they no longer match the declared method_ids
        # ({ident}-config / {ident}-collector), rebuild, and confirm the gate
        # blocks on vvk_method_binding. Then restore for subsequent stages.
        _hb = json.load(open(hp, encoding="utf-8"))
        for _e in _hb.get("ksis", {}).values():
            _m = _e.get("metrics")
            if isinstance(_m, dict):
                _e["metrics"] = {("UNBOUND-" + k): v for k, v in _m.items()}
        json.dump(_hb, open(hp, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        r_bind = _preflight(root)
        check("declared automated VVK methods not bound to telemetry block a Class C package",
              r_bind.returncode == 1 and "vvk_method_binding" in r_bind.stdout)

        # Adversarial (regression for finding F-03, existential-not-set binding):
        # a Class C KSI declares TWO automated methods ({ident}-config /
        # {ident}-collector) and the class minimum is 2. Bind only ONE of them
        # (drop the -collector metric key). The OLD existential gate ("if not
        # bound") passed this - one bound method was enough - so a half-
        # implemented KSI reached ready while claiming two automated methods.
        # The set-based gate must BLOCK: 1 of 2 required bound.
        _hb1 = json.load(open(hp, encoding="utf-8"))
        for _e in _hb1.get("ksis", {}).values():
            _m = _e.get("metrics")
            if isinstance(_m, dict):
                _e["metrics"] = {k: v for k, v in _m.items()
                                 if not k.endswith("-collector")}
        json.dump(_hb1, open(hp, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        r_partial = _preflight(root)
        check("Class C KSI with 2 declared automated methods but only 1 bound "
              "to telemetry blocks (set-based binding, not existential)",
              r_partial.returncode == 1 and "vvk_method_binding" in r_partial.stdout)

        _fill(profile, now)
        _fill_records(root)
        _build(root)

        # Adversarial (regression for a real ready-but-hollow gap found by the
        # Class C end-to-end exercise): a Class C package whose KSI historical-
        # metric summaries (SDR-CSX-KMT, a Class C MUST) are all TBD must BLOCK,
        # not reach ready. Empty them on the otherwise-ready package and re-check.
        store_path = os.path.join(root, "sdr", "records", "records-store.json")
        _store = json.load(open(store_path, encoding="utf-8"))
        for _rec in _store.get("ksi", {}).values():
            _rec["historical_metrics"] = {
                "last_30_days": "TBD: Information has not been provided.",
                "up_to_one_year": "TBD: Information has not been provided.",
                "daily_data_reference": "TBD: Information has not been provided.",
            }
        json.dump(_store, open(store_path, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        r_kmt = _preflight(root)
        check("empty SDR-CSX-KMT summaries block a Class C package", r_kmt.returncode == 1)
        # Restore the filled records for the subsequent CPO adversarial stages.
        _fill_records(root)
        _build(root)
        reg2 = json.load(open(register, encoding="utf-8"))
        mhash2 = "sha256:" + hashlib.sha256(open(manifest, "rb").read()).hexdigest()
        reg2["package_signoff"]["package_manifest_sha256"] = mhash2
        reg2["package_signoff"]["release_tag"] = json.load(open(manifest, encoding="utf-8")).get("release_tag")
        json.dump(reg2, open(register, "w", encoding="utf-8", newline="\n"), indent=1)

        # Structured CPO semantics adversarial: a bare sentence for CDS-CSO-PUB
        # must NOT satisfy the rule (it enumerates 16 concrete items). This is
        # the "impossible to fool" property applied to the CPO.
        p = json.load(open(profile, encoding="utf-8"))
        good_pub = p["cpo_required_information"]["CDS-CSO-PUB"]
        p["cpo_required_information"]["CDS-CSO-PUB"] = "Public information is documented."
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        rpub = _preflight(root)
        check("a bare-string CDS-CSO-PUB does NOT satisfy the structured rule",
              "not structurally complete" in rpub.stdout and rpub.returncode == 1)
        # Dropping a single required CDS-CSO-PUB member (Sales Contact
        # Information) must also block - the structured check is member-level.
        import copy as _copy
        pub_missing_sales = _copy.deepcopy(good_pub)
        pub_missing_sales.pop("Sales Contact Information", None)
        p["cpo_required_information"]["CDS-CSO-PUB"] = pub_missing_sales
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        rsales = _preflight(root)
        check("a missing Sales Contact Information in CDS-CSO-PUB blocks",
              "not structurally complete" in rsales.stdout and rsales.returncode == 1)
        # Semantic-hollowness regression: every CDS-CSO-PUB member PRESENT but set
        # to a bare "N/A" (structurally complete, content-free) must block. A
        # presence-only check would accept this; the content check must reject it.
        pub_hollow = _copy.deepcopy(good_pub)
        for _k in list(pub_hollow.keys()):
            pub_hollow[_k] = "N/A"
        p["cpo_required_information"]["CDS-CSO-PUB"] = pub_hollow
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        rhollow = _preflight(root)
        check("a CDS-CSO-PUB with all members bare 'N/A' blocks (hollow but structured)",
              "not structurally complete" in rhollow.stdout and rhollow.returncode == 1)
        # A JUSTIFIED N/A ("N/A: <reason>") on a member is still acceptable - the
        # check rejects content-free non-answers, not honest justified ones.
        pub_justified = _copy.deepcopy(good_pub)
        for _k in list(pub_justified.keys()):
            pub_justified[_k] = "N/A: not applicable to this SaaS boundary (fictional)."
        p["cpo_required_information"]["CDS-CSO-PUB"] = pub_justified
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        rjust = _preflight(root)
        check("a justified 'N/A: <reason>' CDS-CSO-PUB member is accepted (not over-blocked)",
              "not structurally complete" not in rjust.stdout)
        p["cpo_required_information"]["CDS-CSO-PUB"] = good_pub
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)

        # A BARE "N/A" in a required FRR field must NOT count as answered - only
        # a justified N/A does. Tamper one applicable record and confirm it blocks.
        rp = os.path.join(root, "sdr", "records", "records-store.json")
        recs = json.load(open(rp, encoding="utf-8"))
        frr_id = next(iter(recs.get("frr", {})))
        saved_impl = recs["frr"][frr_id].get("implementation")
        recs["frr"][frr_id]["implementation"] = "N/A"
        json.dump(recs, open(rp, "w", encoding="utf-8", newline="\n"), indent=1)
        rna = _preflight(root)
        check("a bare 'N/A' in a required FRR field is NOT accepted as answered",
              rna.returncode == 1 and "SUBMISSION BLOCKERS" in rna.stdout)
        recs["frr"][frr_id]["implementation"] = saved_impl
        json.dump(recs, open(rp, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)

        # FRC-APP-USA freshening gate: a 4-month-old assessment must BLOCK unless
        # a Recognized-service freshening review (with a recognition id) is
        # recorded, then reach ready once it is.
        p = json.load(open(profile, encoding="utf-8"))
        fia = p["fedramp_independent_assessment"]
        fia["completed_at"] = (now.date() - datetime.timedelta(days=120)).isoformat()
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        rfa = _preflight(root)
        check("stale (4mo) assessment without a freshening review is blocked",
              "FRC-APP-USA freshening" in rfa.stdout and rfa.returncode == 1)
        fia["freshness_basis"] = "freshened"
        fia["freshening"] = {
            "reviewed_at": (now.date() - datetime.timedelta(days=10)).isoformat(),
            "reviewed_by": "Acme FedRAMP Assessors LLC",
            "reviewer_fedramp_id": "FR-ASSESSOR-0007",
            "changes_reviewed_reference": "change-log-2026-Q3",
        }
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        # Restore current-assessment state for the signoff flow below.
        fia_current = (now.date() - datetime.timedelta(days=30)).isoformat()
        _build(root)
        rfb = _preflight(root)
        check("stale assessment with a Recognized-service freshening review clears FIA",
              "FRC-APP-USA freshening" not in rfb.stdout)
        # Semantic-hollowness on an UNBLOCKING condition: a freshening whose
        # reviewer/recognition-id is a bare "N/A" must NOT clear the stale FIA -
        # a content-free freshening cannot loosen the gate.
        fia["freshening"]["reviewed_by"] = "N/A"
        fia["freshening"]["reviewer_fedramp_id"] = "N/A"
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        rfh = _preflight(root)
        check("a freshening with a bare 'N/A' reviewer does NOT clear FIA",
              "FRC-APP-USA freshening" in rfh.stdout and rfh.returncode == 1)
        fia["freshening"]["reviewed_by"] = "Acme FedRAMP Assessors LLC"
        fia["freshening"]["reviewer_fedramp_id"] = "FR-ASSESSOR-0007"
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        # A freshening dated BEFORE the original assessment is logically
        # impossible and must not clear FIA (reviewed_at >= completed_at).
        fia["freshening"]["reviewed_at"] = (now.date() - datetime.timedelta(days=200)).isoformat()
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        rfc = _preflight(root)
        check("a freshening dated before the original assessment does NOT clear FIA",
              "FRC-APP-USA freshening" in rfc.stdout and rfc.returncode == 1)
        fia["freshening"]["reviewed_at"] = (now.date() - datetime.timedelta(days=10)).isoformat()
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        p["fedramp_independent_assessment"]["completed_at"] = fia_current
        p["fedramp_independent_assessment"].pop("freshening", None)
        p["fedramp_independent_assessment"]["freshness_basis"] = "current"
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        # Mandatory-identity regression: a JUSTIFIED "N/A: <reason>" must NOT
        # satisfy the assessor name (FRC-APP-FIA requires a real Recognized
        # assessor identity, not an explanation of absence). Narrative fields
        # accept a justified N/A; identity fields do not.
        good_assessor = p["fedramp_independent_assessment"]["assessor_name"]
        p["fedramp_independent_assessment"]["assessor_name"] = "N/A: alternate internal process (justification)."
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        rid = _preflight(root)
        check("a justified 'N/A' assessor_name does NOT satisfy FRC-APP-FIA",
              "fedramp_independent_assessment" in rid.stdout and rid.returncode == 1)
        p["fedramp_independent_assessment"]["assessor_name"] = good_assessor
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        # Re-sign against the current manifest so the post-signoff test below is clean.
        mhash = "sha256:" + hashlib.sha256(open(manifest, "rb").read()).hexdigest()
        tag = json.load(open(manifest, encoding="utf-8")).get("release_tag")
        reg = json.load(open(register, encoding="utf-8"))
        reg["package_signoff"]["package_manifest_sha256"] = mhash
        reg["package_signoff"]["release_tag"] = tag
        json.dump(reg, open(register, "w", encoding="utf-8", newline="\n"), indent=1)

        # NO-REBUILD input tamper: edit an authoritative input but do NOT rebuild.
        # The manifest and the human signoff still match each other, but the
        # current input no longer matches the manifest. Package consistency must
        # catch this (manifest.inputs revalidation), so preflight must block.
        rp = os.path.join(root, "sdr", "records", "records-store.json")
        saved_rs = open(rp, encoding="utf-8").read()
        rs = json.loads(saved_rs)
        rs["store_note"] = str(rs.get("store_note", "")) + " (tampered, no rebuild)"
        json.dump(rs, open(rp, "w", encoding="utf-8", newline="\n"), indent=1)
        rtamp = _preflight(root)  # deliberately no _build
        rcons = subprocess.run(
            [sys.executable, "validation/scripts/validate_package_consistency.py"],
            cwd=root, capture_output=True, text=True)
        check("editing records-store without a rebuild is caught (manifest input hash)",
              rtamp.returncode == 1 and "validation gate does not pass" in rtamp.stdout
              and "input hash mismatch" in rcons.stdout and rcons.returncode == 1)
        open(rp, "w", encoding="utf-8", newline="\n").write(saved_rs)

        # Placeholder evidence: a ready package must not point at an
        # sdr://placeholder/ evidence URI in an applicable record.
        rs2 = json.loads(open(rp, encoding="utf-8").read())
        some_ksi = next(iter(rs2.get("ksi", {})))
        ev = rs2["ksi"][some_ksi].setdefault("evidence", [])
        ev.append({"evidenceType": "Report",
                   "evidenceLocation": "sdr://placeholder/replace-me"})
        json.dump(rs2, open(rp, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        rph = _preflight(root)
        check("placeholder evidence URI in an applicable record blocks submission",
              "sdr://placeholder/" in rph.stdout and rph.returncode == 1)
        open(rp, "w", encoding="utf-8", newline="\n").write(saved_rs)
        _build(root)

        # SCG scaffold-only: the generated SCG is a template. For Class B/C it is a
        # required component, so removing the real external SCG reference must block
        # (a scaffold does not satisfy a required component).
        psc = json.load(open(profile, encoding="utf-8"))
        saved_scg = psc.get("secure_config_guide_uri")
        psc["secure_config_guide_uri"] = "TBD: not yet published"
        json.dump(psc, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        rscg = _preflight(root)
        check("Class C blocks when the SCG is only a scaffold with no completed artifact",
              rscg.returncode == 1 and ("scaffold" in rscg.stdout or "secure_config_guide" in rscg.stdout
                                        or "trust center" in rscg.stdout.lower()))
        psc["secure_config_guide_uri"] = saved_scg
        json.dump(psc, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        # Re-sign against the restored manifest so the next test starts clean.
        mhash = "sha256:" + hashlib.sha256(open(manifest, "rb").read()).hexdigest()
        tag = json.load(open(manifest, encoding="utf-8")).get("release_tag")
        reg = json.load(open(register, encoding="utf-8"))
        reg["package_signoff"]["package_manifest_sha256"] = mhash
        reg["package_signoff"]["release_tag"] = tag
        json.dump(reg, open(register, "w", encoding="utf-8", newline="\n"), indent=1)

        # SCG-ENH-MRG is a SHOULD: providing the Secure Configuration Guide in a
        # machine-readable format is RECOMMENDED, not required. The MUST rule
        # SCG-CSO-RSC is satisfied by the published human-readable guide. So a
        # package that has a human SCG URI but no machine-readable URI must NOT
        # block; it must remain package-ready while emitting an SCG-ENH-MRG
        # advisory. Blocking it would turn a FedRAMP SHOULD into a MUST.
        psc2 = json.load(open(profile, encoding="utf-8"))
        saved_mach = psc2.get("secure_config_guide_machine_uri")
        psc2["secure_config_guide_machine_uri"] = "TBD: not yet published"
        json.dump(psc2, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        # Re-sign against the rebuilt manifest so signoff is not the blocker.
        mhash = "sha256:" + hashlib.sha256(open(manifest, "rb").read()).hexdigest()
        tag = json.load(open(manifest, encoding="utf-8")).get("release_tag")
        reg = json.load(open(register, encoding="utf-8"))
        reg["package_signoff"]["package_manifest_sha256"] = mhash
        reg["package_signoff"]["release_tag"] = tag
        json.dump(reg, open(register, "w", encoding="utf-8", newline="\n"), indent=1)
        rmach = _preflight(root)
        check("Class C remains package-ready without a machine-readable SCG URI "
              "(SCG-ENH-MRG is a SHOULD, not a package blocker)",
              rmach.returncode == 0
              and "SCG-ENH-MRG" in rmach.stdout
              and "human-readable and machine-readable data URLs" not in rmach.stdout)
        psc2["secure_config_guide_machine_uri"] = saved_mach
        json.dump(psc2, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        mhash = "sha256:" + hashlib.sha256(open(manifest, "rb").read()).hexdigest()
        tag = json.load(open(manifest, encoding="utf-8")).get("release_tag")
        reg = json.load(open(register, encoding="utf-8"))
        reg["package_signoff"]["package_manifest_sha256"] = mhash
        reg["package_signoff"]["release_tag"] = tag
        json.dump(reg, open(register, "w", encoding="utf-8", newline="\n"), indent=1)

        # Finding 2: a rule the pinned dataset marks with an UNCONDITIONAL MUST
        # artifact must actually carry a rule_artifact when followed. Stripping
        # rule_artifacts from one such applicable, Implemented rule must block on
        # the rule-artifact gap; restoring it must clear.
        rp2 = os.path.join(root, "sdr", "records", "records-store.json")
        recs2 = json.load(open(rp2, encoding="utf-8"))
        # AFC-CSO-INB is an unconditional-MUST artifact rule in every class
        # profile ("Email address to receive messages from FedRAMP").
        art_rid = "AFC-CSO-INB"
        saved_arts = None
        if art_rid in recs2.get("frr", {}):
            ext_a = recs2["frr"][art_rid].setdefault("extension", {})
            saved_arts = ext_a.get("rule_artifacts")
            ext_a["rule_artifacts"] = []
            json.dump(recs2, open(rp2, "w", encoding="utf-8", newline="\n"), indent=1)
            _build(root)
            rart = _preflight(root)
            check("Class C blocks a followed unconditional-MUST-artifact rule with no rule_artifact",
                  rart.returncode == 1 and "rule-artifact" in rart.stdout
                  and art_rid in rart.stdout)
            recs3 = json.load(open(rp2, encoding="utf-8"))
            recs3["frr"][art_rid].setdefault("extension", {})["rule_artifacts"] = saved_arts or []
            json.dump(recs3, open(rp2, "w", encoding="utf-8", newline="\n"), indent=1)
            _build(root)
            mhash = "sha256:" + hashlib.sha256(open(manifest, "rb").read()).hexdigest()
            tag = json.load(open(manifest, encoding="utf-8")).get("release_tag")
            reg = json.load(open(register, encoding="utf-8"))
            reg["package_signoff"]["package_manifest_sha256"] = mhash
            reg["package_signoff"]["release_tag"] = tag
            json.dump(reg, open(register, "w", encoding="utf-8", newline="\n"), indent=1)

        # Finding 4: a mandatory ONE-OF artifact ("a recent vulnerability report
        # OR a sample vulnerability report") is STILL required - a non-empty
        # rule_artifacts must be present, even though the alternative cannot be
        # machine-judged. The prior binary heuristic demoted any "or a sample"
        # wording to advisory, so an applicable one-of rule with NO artifact
        # reached READY. VER-TFR-MHR is a one-of artifact rule in every class
        # profile; stripping its artifact must now block, restoring must clear.
        oneof_rid = "VER-TFR-MHR"
        recs_oo = json.load(open(rp2, encoding="utf-8"))
        if oneof_rid in recs_oo.get("frr", {}):
            ext_oo = recs_oo["frr"][oneof_rid].setdefault("extension", {})
            saved_oo = ext_oo.get("rule_artifacts")
            ext_oo["rule_artifacts"] = []
            json.dump(recs_oo, open(rp2, "w", encoding="utf-8", newline="\n"), indent=1)
            _build(root)
            roo = _preflight(root)
            check("Class C blocks a followed one-of-artifact rule with no rule_artifact",
                  roo.returncode == 1 and "rule-artifact" in roo.stdout
                  and oneof_rid in roo.stdout)
            recs_oo2 = json.load(open(rp2, encoding="utf-8"))
            recs_oo2["frr"][oneof_rid].setdefault("extension", {})["rule_artifacts"] = saved_oo or []
            json.dump(recs_oo2, open(rp2, "w", encoding="utf-8", newline="\n"), indent=1)
            _build(root)
            mhash = "sha256:" + hashlib.sha256(open(manifest, "rb").read()).hexdigest()
            tag = json.load(open(manifest, encoding="utf-8")).get("release_tag")
            reg = json.load(open(register, encoding="utf-8"))
            reg["package_signoff"]["package_manifest_sha256"] = mhash
            reg["package_signoff"]["release_tag"] = tag
            json.dump(reg, open(register, "w", encoding="utf-8", newline="\n"), indent=1)

        # Change a provider input after signoff; the bound signoff must fail.
        p = json.load(open(profile, encoding="utf-8"))
        p["business_purpose"] = str(p.get("business_purpose", "")) + " (edited after signoff)"
        json.dump(p, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root)
        r2 = _preflight(root)
        check("post-signoff change invalidates the manifest-bound signoff",
              "package_manifest_sha256 does not match" in r2.stdout and r2.returncode == 1)

        # Class A end-to-end on a FRESH tree (not the Class-C-filled one), so the
        # ~39 non-applicable KSIs are genuinely never answered - proving they do
        # not block, rather than being quietly filled. Only the 7 enumerated KSIs
        # apply; FIA/SCG/AVR-MUST/MOT do not; the alternative-framework external
        # assessment does.
        root_a = os.path.join(tmp, "repo-a")
        shutil.copytree(BASE, root_a, ignore=shutil.ignore_patterns(
            ".git", "__pycache__", "*.log", ".tmp"))
        profile_a = os.path.join(root_a, "profiles", "common", "offering-profile.json")
        register_a = os.path.join(root_a, "sdr", "reviews", "review-register.json")
        manifest_a = os.path.join(root_a, "artifacts", "release-manifest.json")
        _fill(profile_a, now, cls="A")
        _fill_records(root_a)
        _build(root_a)
        # Prove the fixture left the non-applicable KSIs unanswered on this fresh
        # tree: exactly the 7 Class A KSIs carry implementation content.
        recs_a = json.load(open(os.path.join(root_a, "sdr", "records", "records-store.json"),
                                encoding="utf-8"))
        answered_ksi = [kid for kid, rec in (recs_a.get("ksi", {}) or {}).items()
                        if "Fictional but complete" in str(rec.get("implementation"))]
        check("Class A fixture answered ONLY the 7 applicable KSIs, not all 46",
              len(answered_ksi) == 7)
        mhash_a = "sha256:" + hashlib.sha256(open(manifest_a, "rb").read()).hexdigest()
        tag_a = json.load(open(manifest_a, encoding="utf-8")).get("release_tag")
        reg_a = json.load(open(register_a, encoding="utf-8"))
        reg_a["package_signoff"] = {
            "decision": "approved", "reviewer": "Jane Provider, VP Security",
            "timestamp": now.isoformat(), "release_tag": tag_a,
            "package_manifest_sha256": mhash_a, "notes": "Reviewed full Class A package.",
        }
        json.dump(reg_a, open(register_a, "w", encoding="utf-8", newline="\n"), indent=1)
        ra = _preflight(root_a)
        check("fully-filled Class A offering reaches Submission ready (exit 0)",
              ra.returncode == 0)
        check("Class A is not blocked on the ~39 non-applicable KSIs",
              "no implementation information" not in ra.stdout)
        # Class A CPO applicability: of the 9 OVR-referenced rules, only
        # CDS-CSO-PUB and MAS-CSO-IIR resolve for Class A, so the generated CPO
        # must carry exactly those two - not seven meaningless N/A entries.
        cpo_a = json.load(open(os.path.join(root_a, "package", "cpo", "cpo.json"), encoding="utf-8"))
        a_rules = {i.get("rule") for i in cpo_a.get("xCpoRequiredInformation", {}).get("items", [])}
        check("Class A CPO required-info is applicability-scoped to its 2 OVR rules",
              a_rules == {"CDS-CSO-PUB", "MAS-CSO-IIR"})
        # Class A CPO-CSO-MTD is NOT applicable, so TBD metadata must not block.
        pa = json.load(open(profile_a, encoding="utf-8"))
        for f in ("cpo_responsible_official", "cpo_version", "cpo_last_updated", "cpo_source_of_update"):
            pa[f] = "TBD: intentionally left unresolved for Class A"
        json.dump(pa, open(profile_a, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_a)
        rmtd = _preflight(root_a)
        check("Class A is NOT blocked on unresolved CPO-CSO-MTD (not applicable to A)",
              "CPO metadata unresolved" not in rmtd.stdout)

        # FRC-CLA-ASF: an unapproved alternative framework must block.
        pa["external_assessment"]["framework"] = "ISO 27001"
        json.dump(pa, open(profile_a, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_a)
        rfw = _preflight(root_a)
        check("Class A rejects an unapproved alternative framework (FRC-CLA-ASF)",
              "not a FedRAMP-approved alternative framework" in rfw.stdout and rfw.returncode == 1)
        pa["external_assessment"]["framework"] = "SOC 2 Type II"

        # FRC-CLA-EAM: dropping a required SOC 2 material must block.
        pa["external_assessment"]["materials"] = [
            m for m in pa["external_assessment"]["materials"]
            if m.get("type") != "verified_audit_engagement"
        ]
        json.dump(pa, open(profile_a, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_a)
        rmat = _preflight(root_a)
        check("Class A blocks when a required SOC 2 material is missing (FRC-CLA-EAM)",
              "Verified audit engagement documentation" in rmat.stdout and rmat.returncode == 1)
        # Restore the dropped material so the tree is otherwise-ready for the
        # FRC-APP-FIA opt-in probes below.
        pa["external_assessment"]["materials"].append(
            {"type": "verified_audit_engagement",
             "uri": "https://contoso.gov/soc2-engagement.pdf",
             "sha256": "sha256:" + "b" * 64})

        # FRC-APP-FIA is MAY (optional) at Class A: it must NOT be gated unless
        # the provider opts in via selected_optional_rules. Clear the FIA block
        # to TBD and confirm an UNSELECTED Class A still reaches ready - proving
        # the optional rule is not silently demanded.
        pa["selected_optional_rules"] = []
        pa["fedramp_independent_assessment"] = {
            "assessor_name": "TBD",
            "assessor_fedramp_id": "TBD",
            "completed_at": "TBD",
        }
        json.dump(pa, open(profile_a, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_a)
        # Re-sign the freshly built package so signoff matches (build changes
        # nothing about FIA gating, but the manifest hash must match the signoff).
        mhash_a2 = "sha256:" + hashlib.sha256(open(manifest_a, "rb").read()).hexdigest()
        tag_a2 = json.load(open(manifest_a, encoding="utf-8")).get("release_tag")
        reg_a2 = json.load(open(register_a, encoding="utf-8"))
        reg_a2["package_signoff"] = {
            "decision": "approved", "reviewer": "Jane Provider, VP Security",
            "timestamp": now.isoformat(), "release_tag": tag_a2,
            "package_manifest_sha256": mhash_a2, "notes": "Reviewed Class A package.",
        }
        json.dump(reg_a2, open(register_a, "w", encoding="utf-8", newline="\n"), indent=1)
        rfia_unsel = _preflight(root_a)
        check("Class A with FRC-APP-FIA NOT selected is not gated on FIA (MAY, unselected)",
              "fedramp_independent_assessment" not in rfia_unsel.stdout
              and rfia_unsel.returncode == 0)

        # Now OPT IN to FRC-APP-FIA while it is still TBD. FedRAMP fully reviews a
        # selected Class A MAY rule, so preflight MUST now block on the empty FIA.
        pa["selected_optional_rules"] = ["FRC-APP-FIA"]
        json.dump(pa, open(profile_a, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_a)
        rfia_sel = _preflight(root_a)
        check("Class A blocks on empty FIA once FRC-APP-FIA is selected (fully reviewed when included)",
              "fedramp_independent_assessment" in rfia_sel.stdout
              and "not populated" in rfia_sel.stdout and rfia_sel.returncode == 1)

        # Populate the selected FIA with a fresh Recognized-service assessment;
        # the block must clear.
        pa["fedramp_independent_assessment"] = {
            "assessor_name": "Acme FedRAMP Assessors LLC",
            "assessor_fedramp_id": "FR-ASSESSOR-0007",
            "completed_at": (now.date() - datetime.timedelta(days=30)).isoformat(),
            "assessment_summary_uri": "https://contoso.gov/assessment-summary.pdf",
            "assessment_report_uri": "https://contoso.gov/assessment-report.pdf",
            "assessment_report_sha256": "sha256:" + "b" * 64,
        }
        json.dump(pa, open(profile_a, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_a)
        mhash_a3 = "sha256:" + hashlib.sha256(open(manifest_a, "rb").read()).hexdigest()
        tag_a3 = json.load(open(manifest_a, encoding="utf-8")).get("release_tag")
        reg_a3 = json.load(open(register_a, encoding="utf-8"))
        reg_a3["package_signoff"] = {
            "decision": "approved", "reviewer": "Jane Provider, VP Security",
            "timestamp": now.isoformat(), "release_tag": tag_a3,
            "package_manifest_sha256": mhash_a3, "notes": "Reviewed Class A package with selected FIA.",
        }
        json.dump(reg_a3, open(register_a, "w", encoding="utf-8", newline="\n"), indent=1)
        rfia_ok = _preflight(root_a)
        check("Class A with a populated, selected FRC-APP-FIA reaches ready",
              "fedramp_independent_assessment" not in rfia_ok.stdout
              and rfia_ok.returncode == 0)

        # Unknown selected_optional_rules ID must be surfaced, not silently
        # ignored: a provider who names a bogus/misspelled optional rule believes
        # it entered the SDR when submitted_rule_ids never matches it. Add an
        # unknown ID alongside the valid FIA selection - preflight must block and
        # name the offending ID.
        pa["selected_optional_rules"] = ["FRC-APP-FIA", "FRC-CLA-BOGUS"]
        json.dump(pa, open(profile_a, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_a)
        mhash_a4 = "sha256:" + hashlib.sha256(open(manifest_a, "rb").read()).hexdigest()
        tag_a4 = json.load(open(manifest_a, encoding="utf-8")).get("release_tag")
        reg_a4 = json.load(open(register_a, encoding="utf-8"))
        reg_a4["package_signoff"] = {
            "decision": "approved", "reviewer": "Jane Provider, VP Security",
            "timestamp": now.isoformat(), "release_tag": tag_a4,
            "package_manifest_sha256": mhash_a4, "notes": "Reviewed Class A package (unknown-ID probe).",
        }
        json.dump(reg_a4, open(register_a, "w", encoding="utf-8", newline="\n"), indent=1)
        r_badid = _preflight(root_a)
        check("Class A blocks on an unknown selected_optional_rules ID (named, not ignored)",
              "FRC-CLA-BOGUS" in r_badid.stdout and r_badid.returncode == 1)
        # Restore the valid selection so the tree is left ready.
        pa["selected_optional_rules"] = ["FRC-APP-FIA"]
        json.dump(pa, open(profile_a, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_a)

        # --- Finding 6: selected Class A optional rules are fully reviewed ---
        def _resign_a(note):
            mh = "sha256:" + hashlib.sha256(open(manifest_a, "rb").read()).hexdigest()
            tg = json.load(open(manifest_a, encoding="utf-8")).get("release_tag")
            rr = json.load(open(register_a, encoding="utf-8"))
            rr["package_signoff"] = {
                "decision": "approved", "reviewer": "Jane Provider, VP Security",
                "timestamp": now.isoformat(), "release_tag": tg,
                "package_manifest_sha256": mh, "notes": note}
            json.dump(rr, open(register_a, "w", encoding="utf-8", newline="\n"), indent=1)

        # (a) Selecting optional IV&V (IVV-CSO-FIA) requires the CPO overall
        # assessment summary (CPO-CSO-OSA / IVV-IAS-OSA). With it hollow, the
        # selected optional rule must block; restoring it must clear. This proves
        # the OSA obligation is not skipped just because it is Class A.
        saved_osa = pa.get("overall_assessment_summary")
        pa["selected_optional_rules"] = ["FRC-APP-FIA", "IVV-CSO-FIA"]
        pa["overall_assessment_summary"] = "N/A"
        json.dump(pa, open(profile_a, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_a); _resign_a("IVV-OSA probe")
        r_ivv = _preflight(root_a)
        check("Class A selecting IVV-CSO-FIA blocks when the CPO overall assessment summary is hollow",
              "overall_assessment_summary" in r_ivv.stdout and r_ivv.returncode == 1)
        pa["overall_assessment_summary"] = saved_osa or (
            "Assessor confirmed all in-scope measures verified and validated; no critical findings.")
        json.dump(pa, open(profile_a, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_a); _resign_a("IVV-OSA cleared")
        r_ivv_ok = _preflight(root_a)
        check("Class A selecting IVV-CSO-FIA clears once the overall assessment summary is present",
              "overall_assessment_summary" not in r_ivv_ok.stdout and r_ivv_ok.returncode == 0)

        # Findings 6/7: a SELECTED Class A IVV-CSO-FIA is fully reviewed, so the
        # rule's OWN substance must be proven: a FedRAMP Recognized assessor
        # (name + recognition id), a completion date within the past year, AND
        # the IV&V Assessment Summary in the SDR (assessment_summary_uri).
        # pa currently selects IVV-CSO-FIA with a populated fedramp_independent_
        # assessment (the Class A fill sets it). Blank the summary URI -> block on
        # the assessment-summary requirement; restore -> clear.
        saved_fia_a = json.loads(json.dumps(pa.get("fedramp_independent_assessment") or {}))
        pa["selected_optional_rules"] = ["FRC-APP-FIA", "IVV-CSO-FIA"]
        fia_a = pa.setdefault("fedramp_independent_assessment", {})
        fia_a["assessment_summary_uri"] = "TBD"
        json.dump(pa, open(profile_a, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_a); _resign_a("IVV summary-uri probe")
        r_sum = _preflight(root_a)
        check("Class A selecting IVV-CSO-FIA blocks when the IV&V assessment summary URI is missing",
              "assessment_summary_uri" in r_sum.stdout and r_sum.returncode == 1)
        # A stale (older than 12 months) IVV assessment must block on the annual cadence.
        fia_a["assessment_summary_uri"] = saved_fia_a.get(
            "assessment_summary_uri", "https://contoso.gov/ev/ivv-summary")
        fia_a["completed_at"] = "2023-01-01"
        json.dump(pa, open(profile_a, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_a); _resign_a("IVV annual probe")
        r_ann = _preflight(root_a)
        check("Class A selecting IVV-CSO-FIA blocks when the assessment is older than 12 months",
              "at least once per year" in r_ann.stdout and r_ann.returncode == 1)
        # Restore a valid recent assessment -> clears.
        pa["fedramp_independent_assessment"] = saved_fia_a
        json.dump(pa, open(profile_a, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_a); _resign_a("IVV substance cleared")
        r_ivv_sub = _preflight(root_a)
        check("Class A selecting IVV-CSO-FIA clears with a recent Recognized assessment and summary",
              r_ivv_sub.returncode == 0)

        # Finding 5: selecting Class A SDR-CSX-KMT includes historical KSI metrics
        # in the SDR, so real in-window metric content must back it. The Class A
        # fill populates metric history, so with SDR-CSX-KMT selected AND real
        # history the package clears; wiping the history to empty must then block
        # on the missing-history requirement.
        mh_a = os.path.join(root_a, "automation", "metrics", "metric-history.json")
        saved_mh = None
        if os.path.exists(mh_a):
            saved_mh = open(mh_a, encoding="utf-8").read()
        pa["selected_optional_rules"] = ["FRC-APP-FIA", "SDR-CSX-KMT"]
        json.dump(pa, open(profile_a, "w", encoding="utf-8", newline="\n"), indent=1)
        # Empty the metric history so no applicable KSI has an in-window observation.
        os.makedirs(os.path.dirname(mh_a), exist_ok=True)
        json.dump({"ksis": {}}, open(mh_a, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_a); _resign_a("KMT-selected empty-history probe")
        r_kmt = _preflight(root_a)
        check("Class A selecting SDR-CSX-KMT blocks when no applicable KSI has in-window metrics",
              "SDR-CSX-KMT" in r_kmt.stdout and r_kmt.returncode == 1)
        # Restore history + drop the selection -> clears.
        if saved_mh is not None:
            open(mh_a, "w", encoding="utf-8", newline="\n").write(saved_mh)
        pa["selected_optional_rules"] = ["FRC-APP-FIA"]
        json.dump(pa, open(profile_a, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_a); _resign_a("KMT selection removed")
        r_kmt_ok = _preflight(root_a)
        check("Class A clears once SDR-CSX-KMT is not selected",
              "selected SDR-CSX-KMT includes historical" not in r_kmt_ok.stdout
              and r_kmt_ok.returncode == 0)

        # (b) Selecting an optional artifact-bearing rule (CMU-CSO-UVM, the
        # cryptographic-module list) with no rule_artifact must block on the
        # rule-artifact gap - a selected MAY rule's canonical artifact is required
        # once included. Uses the records store: strip artifacts from the rule.
        rp_a = os.path.join(root_a, "sdr", "records", "records-store.json")
        recs_a = json.load(open(rp_a, encoding="utf-8"))
        cmu = "CMU-CSO-UVM"
        if cmu in recs_a.get("frr", {}):
            saved_cmu = recs_a["frr"][cmu].get("extension", {}).get("rule_artifacts")
            recs_a["frr"][cmu].setdefault("extension", {})["rule_artifacts"] = []
            json.dump(recs_a, open(rp_a, "w", encoding="utf-8", newline="\n"), indent=1)
            pa["selected_optional_rules"] = ["FRC-APP-FIA", cmu]
            json.dump(pa, open(profile_a, "w", encoding="utf-8", newline="\n"), indent=1)
            _build(root_a); _resign_a("CMU artifact probe")
            r_cmu = _preflight(root_a)
            check("Class A selecting CMU-CSO-UVM blocks when its canonical artifact is missing",
                  "rule-artifact" in r_cmu.stdout and cmu in r_cmu.stdout and r_cmu.returncode == 1)
            recs_a2 = json.load(open(rp_a, encoding="utf-8"))
            recs_a2["frr"][cmu].setdefault("extension", {})["rule_artifacts"] = saved_cmu or [{
                "evidenceType": "Report", "evidenceLocation": "https://contoso.gov/ev/CMU-CSO-UVM",
                "lastUpdated": "2026-09-01T00:00:00Z"}]
            json.dump(recs_a2, open(rp_a, "w", encoding="utf-8", newline="\n"), indent=1)

        # Restore the baseline Class A selection so the tree is left ready.
        pa["selected_optional_rules"] = ["FRC-APP-FIA"]
        json.dump(pa, open(profile_a, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_a); _resign_a("finding-6 probes done")

        # FRC-CSX-MOT initial-certification EXCEPTION: a new Class C offering with
        # no long metric history but a valid metric_history_exception (both flags
        # true + descriptions + a current datapoint per KSI) must reach ready.
        root_m = os.path.join(tmp, "repo-mot")
        shutil.copytree(BASE, root_m, ignore=shutil.ignore_patterns(
            ".git", "__pycache__", "*.log", ".tmp"))
        profile_m = os.path.join(root_m, "profiles", "common", "offering-profile.json")
        register_m = os.path.join(root_m, "sdr", "reviews", "review-register.json")
        manifest_m = os.path.join(root_m, "artifacts", "release-manifest.json")
        _fill(profile_m, now, cls="C")
        _fill_records(root_m)
        # Overwrite history with a SINGLE current datapoint per applicable KSI
        # (not 8 months) - only the exception path can clear this.
        ksi_prof = json.load(open(os.path.join(root_m, "profiles", "common", "ksi-profile.json"),
                                  encoding="utf-8"))
        cur = now.date().isoformat()
        hist_m = {"ksis": {k["ksi_id"]: {"series": [{"date": cur, "status": "pass"}]}
                           for k in ksi_prof.get("indicators", [])}}
        json.dump(hist_m, open(os.path.join(root_m, "automation", "metrics", "metric-history.json"),
                               "w", encoding="utf-8", newline="\n"), indent=1)
        pm = json.load(open(profile_m, encoding="utf-8"))
        # Without the exception, one datapoint is NOT 6 months -> must block.
        _build(root_m)
        rmot0 = _preflight(root_m)
        check("Class C with only current datapoints (no exception) is blocked on MOT",
              "FRC-CSX-MOT" in rmot0.stdout and rmot0.returncode == 1)
        # Activate the exception with the explicit contract.
        pm["metric_history_exception"] = {
            "mechanisms_in_place": True,
            "mechanisms_description": "Persistent KSI validation mechanisms operational since launch.",
            "commitment_to_meet_mot": True,
            "commitment_reference": "Provider commitment approved by the CISO (2026-08).",
            "operating_since": (now.date() - datetime.timedelta(days=40)).isoformat(),
            "responsible_official": "Jane Provider, VP Security",
        }
        json.dump(pm, open(profile_m, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_m)
        mhash_m = "sha256:" + hashlib.sha256(open(manifest_m, "rb").read()).hexdigest()
        tag_m = json.load(open(manifest_m, encoding="utf-8")).get("release_tag")
        reg_m = json.load(open(register_m, encoding="utf-8"))
        reg_m["package_signoff"] = {
            "decision": "approved", "reviewer": "Jane Provider, VP Security",
            "timestamp": now.isoformat(), "release_tag": tag_m,
            "package_manifest_sha256": mhash_m, "notes": "Reviewed Class C initial-cert package.",
        }
        json.dump(reg_m, open(register_m, "w", encoding="utf-8", newline="\n"), indent=1)
        rmot1 = _preflight(root_m)
        check("Class C reaches ready via the FRC-CSX-MOT initial-certification exception",
              rmot1.returncode == 0)
        # Booleans-only (no descriptions) must NOT activate the exception.
        pm["metric_history_exception"]["mechanisms_description"] = "TBD"
        json.dump(pm, open(profile_m, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_m)
        rmot2 = _preflight(root_m)
        check("MOT exception with a missing description does not activate",
              "FRC-CSX-MOT" in rmot2.stdout and rmot2.returncode == 1)

        # --- from PR #110, hardened to an affirmative boolean ---
        # FRC-APP-NTP (MUST NOT third-party applicant): the gate is now an
        # affirmative boolean provider_is_applicant. Absent blocks; an explicit
        # false blocks (the exact "our assessor is submitting" case FRC-APP-NTP
        # forbids, which a free-form string would have falsely passed); true
        # clears. Uses the ready Class C initial-cert tree.
        pm2 = json.load(open(profile_m, encoding="utf-8"))
        pm2["metric_history_exception"]["mechanisms_description"] = (
            "Automated daily KSI collectors are deployed and producing telemetry.")
        ap2 = pm2.setdefault("application_prerequisites", {})
        # (a) boolean absent -> blocks.
        ap2.pop("provider_is_applicant", None)
        json.dump(pm2, open(profile_m, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_m)
        rntp = _preflight(root_m)
        check("missing FRC-APP-NTP affirmative provider-is-applicant boolean blocks",
              "FRC-APP-NTP" in rntp.stdout and rntp.returncode == 1)
        # (b) explicit false -> blocks (third party is applying); a non-empty
        # free-form attestation string must NOT rescue it.
        ap2["provider_is_applicant"] = False
        ap2["provider_is_applicant_attestation"] = "No - our assessor is submitting it."
        json.dump(pm2, open(profile_m, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_m)
        rntp_false = _preflight(root_m)
        check("provider_is_applicant=false blocks FRC-APP-NTP despite a filled string",
              "FRC-APP-NTP" in rntp_false.stdout and rntp_false.returncode == 1)
        # (c) affirmative true -> clears.
        ap2["provider_is_applicant"] = True
        ap2["provider_is_applicant_attestation"] = (
            "Confirmed: the CSP itself is the applicant (FRC-APP-NTP).")
        json.dump(pm2, open(profile_m, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_m)
        rntp_ok = _preflight(root_m)
        check("provider_is_applicant=true clears FRC-APP-NTP",
              "FRC-APP-NTP" not in rntp_ok.stdout)

        # SDR-CSO-FRR item 1 for a NOT-followed rule requires TWO distinct
        # elements, verbatim: "the reason AND resulting risk to customers for
        # not following the rule." Risk alone is NOT the reason.
        rp_m = os.path.join(root_m, "sdr", "records", "records-store.json")
        recs_m = json.load(open(rp_m, encoding="utf-8"))
        frr_m = next(iter(recs_m.get("frr", {})))
        saved_frr = json.loads(json.dumps(recs_m["frr"][frr_m]))
        # Make it a not-followed rule with the vv/independent items satisfied so
        # only item 1 is under test.
        recs_m["frr"][frr_m]["implementation_status"] = "Not Implemented"
        recs_m["frr"][frr_m]["implementation"] = "TBD: Information has not been provided."
        ext_m = recs_m["frr"][frr_m].setdefault("extension", {})
        ext_m["senior_official_acceptance"] = (
            "Accepted by the CISO on 2026-01-01: the reason for not implementing is "
            "documented and the residual risk is accepted.")
        ext_m["independent_verification"] = "Assessor confirmed the non-implementation."
        ext_m["independent_validation"] = "Assessor validated the residual risk."
        ext_m["assessor_responses"] = "No outstanding assessor comments."
        # Case A: BOTH reason and risk stated -> item 1 satisfied.
        ext_m["nonimplementation_reason"] = (
            "This rule is not followed because the boundary uses an equivalent "
            "compensating control X instead of the named mechanism.")
        ext_m["customer_risk"] = (
            "The resulting customer risk is limited exposure of Y, mitigated by "
            "compensating control X.")
        json.dump(recs_m, open(rp_m, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_m)
        rfrisk = _preflight(root_m)
        check("not-followed FRR with BOTH reason and risk is NOT flagged on item 1",
              f"{frr_m} (missing: reason-not-followed" not in rfrisk.stdout
              and f"{frr_m} (missing: resulting-customer-risk" not in rfrisk.stdout)
        # Case B: risk stated but reason MISSING -> flagged on reason (risk is
        # not the reason).
        ext_m["nonimplementation_reason"] = "TBD"
        json.dump(recs_m, open(rp_m, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_m)
        rfB = _preflight(root_m)
        check("not-followed FRR with risk but NO reason is flagged on reason-not-followed",
              "reason-not-followed (rule not followed)" in rfB.stdout and rfB.returncode == 1)
        # Case C: BOTH reason and risk empty -> both flagged.
        ext_m["customer_risk"] = "TBD"
        json.dump(recs_m, open(rp_m, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_m)
        rfC = _preflight(root_m)
        check("not-followed FRR with neither reason nor risk is flagged on both",
              "reason-not-followed (rule not followed)" in rfC.stdout
              and "resulting-customer-risk (rule not followed)" in rfC.stdout)
        recs_m["frr"][frr_m] = saved_frr
        json.dump(recs_m, open(rp_m, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_m)

        # Finding 1: an authoring status the builder normalizes to
        # "Not Implemented" (e.g. "Planned") must be evaluated by preflight as
        # not-followed too, or the readiness gate treats it as followed while the
        # submitted JSON says Not Implemented (a false-ready path). Set status
        # "Planned" with a filled implementation but TBD reason/risk: preflight
        # must now flag the not-followed reason/risk gaps rather than passing it.
        saved_frr2 = json.loads(json.dumps(recs_m["frr"][frr_m]))
        recs_m["frr"][frr_m]["implementation_status"] = "Planned"
        recs_m["frr"][frr_m]["implementation"] = "TBD"
        ext_p = recs_m["frr"][frr_m].setdefault("extension", {})
        ext_p["nonimplementation_reason"] = "TBD"
        ext_p["customer_risk"] = "TBD"
        json.dump(recs_m, open(rp_m, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_m)
        rfP = _preflight(root_m)
        check("Planned FRR (builder-normalized to Not Implemented) is gated as not-followed",
              "reason-not-followed (rule not followed)" in rfP.stdout
              and "resulting-customer-risk (rule not followed)" in rfP.stdout
              and rfP.returncode == 1)
        recs_m["frr"][frr_m] = saved_frr2
        json.dump(recs_m, open(rp_m, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_m)

        # --- from PR #111: evidence-freshness submission gate ---
        # Evidence freshness gate (Class C): a populated applicable record backed
        # ONLY by EXPIRED evidence (older than 2x the 90-day policy) must BLOCK;
        # refreshing the observation date to today clears it. Restore the MOT
        # exception first so freshness is the only variable. Never changes status.
        pm["metric_history_exception"]["mechanisms_description"] = (
            "Automated daily KSI collectors are deployed and producing telemetry.")
        json.dump(pm, open(profile_m, "w", encoding="utf-8", newline="\n"), indent=1)
        rp_ef = os.path.join(root_m, "sdr", "records", "records-store.json")
        recs_ef = json.load(open(rp_ef, encoding="utf-8"))
        # Pick a populated applicable KSI and give it a single expired evidence entry.
        ksi_prof_ef = json.load(open(os.path.join(root_m, "profiles", "common", "ksi-profile.json"),
                                     encoding="utf-8"))
        appl_ksi = {k["ksi_id"] for k in ksi_prof_ef.get("indicators", [])}
        target_ksi = None
        for kid, rec in recs_ef.get("ksi", {}).items():
            impl = rec.get("implementation")
            if kid in appl_ksi and impl and not any("TBD" in str(x) for x in
                                                    (impl if isinstance(impl, list) else [impl])):
                target_ksi = kid
                break
        expired_date = (now.date() - datetime.timedelta(days=400)).isoformat()
        fresh_date = now.date().isoformat()
        recs_ef["ksi"][target_ksi]["evidence"] = [{
            "evidenceType": "Report",
            "evidenceLocation": "https://evidence.bfc-demo.invalid/expired.json",
            "xEvidenceContentHash": "sha256:" + "a" * 64,
            "lastUpdated": expired_date,
        }]
        json.dump(recs_ef, open(rp_ef, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_m)
        # Re-sign so only the freshness gate (not a stale signoff) can block.
        mh_ef = "sha256:" + hashlib.sha256(open(manifest_m, "rb").read()).hexdigest()
        reg_ef = json.load(open(register_m, encoding="utf-8"))
        reg_ef["package_signoff"]["package_manifest_sha256"] = mh_ef
        reg_ef["package_signoff"]["release_tag"] = json.load(open(manifest_m, encoding="utf-8")).get("release_tag")
        json.dump(reg_ef, open(register_m, "w", encoding="utf-8", newline="\n"), indent=1)
        r_exp = _preflight(root_m)
        check("Class C populated record backed only by EXPIRED evidence blocks",
              "EXPIRED evidence" in r_exp.stdout and r_exp.returncode == 1)
        # Refresh the evidence date to today -> the expiry blocker clears.
        recs_ef["ksi"][target_ksi]["evidence"][0]["lastUpdated"] = fresh_date
        json.dump(recs_ef, open(rp_ef, "w", encoding="utf-8", newline="\n"), indent=1)
        _build(root_m)
        mh_ef2 = "sha256:" + hashlib.sha256(open(manifest_m, "rb").read()).hexdigest()
        reg_ef2 = json.load(open(register_m, encoding="utf-8"))
        reg_ef2["package_signoff"]["package_manifest_sha256"] = mh_ef2
        reg_ef2["package_signoff"]["release_tag"] = json.load(open(manifest_m, encoding="utf-8")).get("release_tag")
        json.dump(reg_ef2, open(register_m, "w", encoding="utf-8", newline="\n"), indent=1)
        r_fresh = _preflight(root_m)
        check("refreshing the evidence date clears the EXPIRED-evidence blocker",
              "EXPIRED evidence" not in r_fresh.stdout)

        # --- PR #115: MOT exception hardening ---
        # Restore a clean current-datapoint history + valid exception so the MOT
        # path is the only variable. Clear the expired evidence added above.
        recs_ef["ksi"][target_ksi]["evidence"] = []
        json.dump(recs_ef, open(rp_ef, "w", encoding="utf-8", newline="\n"), indent=1)
        cur2 = now.date().isoformat()
        hist_r = {"ksis": {k["ksi_id"]: {"series": [{"date": cur2, "status": "pass"}]}
                           for k in ksi_prof.get("indicators", [])}}
        json.dump(hist_r, open(os.path.join(root_m, "automation", "metrics", "metric-history.json"),
                               "w", encoding="utf-8", newline="\n"), indent=1)

        def _resign_m():
            _build(root_m)
            _mh = "sha256:" + hashlib.sha256(open(manifest_m, "rb").read()).hexdigest()
            _rg = json.load(open(register_m, encoding="utf-8"))
            _rg["package_signoff"]["package_manifest_sha256"] = _mh
            _rg["package_signoff"]["release_tag"] = json.load(open(manifest_m, encoding="utf-8")).get("release_tag")
            json.dump(_rg, open(register_m, "w", encoding="utf-8", newline="\n"), indent=1)

        pm_h = json.load(open(profile_m, encoding="utf-8"))
        # Invalid operating_since must fail the exception with a clear message.
        pm_h["metric_history_exception"]["operating_since"] = "not-a-date"
        json.dump(pm_h, open(profile_m, "w", encoding="utf-8", newline="\n"), indent=1)
        _resign_m()
        r_badop = _preflight(root_m)
        check("MOT exception with an invalid operating_since is rejected",
              "invalid operating_since" in r_badop.stdout and r_badop.returncode == 1)
        # An operating window LONGER than the required 6 months disqualifies the
        # exception (the full history is expected instead).
        pm_h["metric_history_exception"]["operating_since"] = (
            now.date() - datetime.timedelta(days=400)).isoformat()
        json.dump(pm_h, open(profile_m, "w", encoding="utf-8", newline="\n"), indent=1)
        _resign_m()
        r_longop = _preflight(root_m)
        check("MOT exception does not apply when the service operated 6+ months",
              "does not apply" in r_longop.stdout and r_longop.returncode == 1)
        # Valid short window, but the ONLY datapoint is stale (>45 days): the
        # exception path must still block on the missing CURRENT datapoint.
        pm_h["metric_history_exception"]["operating_since"] = (
            now.date() - datetime.timedelta(days=40)).isoformat()
        json.dump(pm_h, open(profile_m, "w", encoding="utf-8", newline="\n"), indent=1)
        stale_dp = (now.date() - datetime.timedelta(days=90)).isoformat()
        hist_stale = {"ksis": {k["ksi_id"]: {"series": [{"date": stale_dp, "status": "pass"}]}
                               for k in ksi_prof.get("indicators", [])}}
        json.dump(hist_stale, open(os.path.join(root_m, "automation", "metrics", "metric-history.json"),
                                   "w", encoding="utf-8", newline="\n"), indent=1)
        _resign_m()
        r_staledp = _preflight(root_m)
        check("MOT exception blocks when the only datapoint is not current (>45 days)",
              "no CURRENT validation datapoint" in r_staledp.stdout and r_staledp.returncode == 1)
        # A current datapoint under the valid short-window exception clears it.
        json.dump(hist_r, open(os.path.join(root_m, "automation", "metrics", "metric-history.json"),
                               "w", encoding="utf-8", newline="\n"), indent=1)
        _resign_m()
        r_curdp = _preflight(root_m)
        check("MOT exception clears with a valid short window and a current datapoint",
              "FRC-CSX-MOT" not in r_curdp.stdout or r_curdp.returncode == 0)

        # --- finding 6: future dates and metrics_available_since ---
        # (a) metrics_available_since is the PREFERRED eligibility field and a
        # valid short window on it clears the exception (parity with the
        # operating_since fallback).
        pm_h["metric_history_exception"]["operating_since"] = "TBD"
        pm_h["metric_history_exception"]["metrics_available_since"] = (
            now.date() - datetime.timedelta(days=40)).isoformat()
        json.dump(pm_h, open(profile_m, "w", encoding="utf-8", newline="\n"), indent=1)
        _resign_m()
        r_mas = _preflight(root_m)
        check("MOT exception clears on a valid short metrics_available_since window",
              "FRC-CSX-MOT" not in r_mas.stdout or r_mas.returncode == 0)
        # (b) a FUTURE metrics_available_since must block (cannot be in future).
        pm_h["metric_history_exception"]["metrics_available_since"] = (
            now.date() + datetime.timedelta(days=30)).isoformat()
        json.dump(pm_h, open(profile_m, "w", encoding="utf-8", newline="\n"), indent=1)
        _resign_m()
        r_futmas = _preflight(root_m)
        check("MOT exception with a FUTURE metrics_available_since is blocked",
              "FUTURE metrics_available_since" in r_futmas.stdout and r_futmas.returncode == 1)
        # (c) a valid short window but the only datapoint is FUTURE-dated: it must
        # NOT count as a current datapoint (future is not a real observation).
        pm_h["metric_history_exception"]["metrics_available_since"] = (
            now.date() - datetime.timedelta(days=40)).isoformat()
        json.dump(pm_h, open(profile_m, "w", encoding="utf-8", newline="\n"), indent=1)
        fut_dp = (now.date() + datetime.timedelta(days=10)).isoformat()
        hist_fut = {"ksis": {k["ksi_id"]: {"series": [{"date": fut_dp, "status": "pass"}]}
                             for k in ksi_prof.get("indicators", [])}}
        json.dump(hist_fut, open(os.path.join(root_m, "automation", "metrics", "metric-history.json"),
                                 "w", encoding="utf-8", newline="\n"), indent=1)
        _resign_m()
        r_futdp = _preflight(root_m)
        check("MOT exception blocks when the only datapoint is FUTURE-dated (not current)",
              "no CURRENT validation datapoint" in r_futdp.stdout and r_futdp.returncode == 1)
        # Restore a clean current history + valid short-window exception for the
        # later freshness probes (via operating_since, matching prior state).
        json.dump(hist_r, open(os.path.join(root_m, "automation", "metrics", "metric-history.json"),
                               "w", encoding="utf-8", newline="\n"), indent=1)
        pm_h["metric_history_exception"]["metrics_available_since"] = "TBD"
        pm_h["metric_history_exception"]["operating_since"] = (
            now.date() - datetime.timedelta(days=40)).isoformat()
        json.dump(pm_h, open(profile_m, "w", encoding="utf-8", newline="\n"), indent=1)
        _resign_m()

        # --- PR #115: evidence-freshness whole-set + FRR rule_artifacts ---
        recs_ws = json.load(open(rp_ef, encoding="utf-8"))
        # A populated KSI with ONE expired AND ONE current artifact has
        # sufficient current support -> must NOT be reported as expired-only.
        recs_ws["ksi"][target_ksi]["evidence"] = [
            {"evidenceType": "Report", "evidenceLocation": "https://e.invalid/old.json",
             "xEvidenceContentHash": "sha256:" + "a" * 64,
             "lastUpdated": (now.date() - datetime.timedelta(days=400)).isoformat()},
            {"evidenceType": "Report", "evidenceLocation": "https://e.invalid/new.json",
             "xEvidenceContentHash": "sha256:" + "b" * 64,
             "lastUpdated": now.date().isoformat()},
        ]
        json.dump(recs_ws, open(rp_ef, "w", encoding="utf-8", newline="\n"), indent=1)
        _resign_m()
        r_mix = _preflight(root_m)
        check("mixed fresh+expired evidence is NOT reported as expired-only (no false block)",
              "EXPIRED evidence" not in r_mix.stdout)
        # An FRR whose rule_artifacts are ALL expired must be caught (freshness
        # now scans extension.rule_artifacts, not only KSI evidence).
        frr_ws = next(iter(recs_ws.get("frr", {})))
        recs_ws["frr"][frr_ws].setdefault("extension", {})["rule_artifacts"] = [
            {"artifactId": "EV-OLD", "evidenceLocation": "https://e.invalid/frr-old.json",
             "lastUpdated": (now.date() - datetime.timedelta(days=400)).isoformat()}]
        # ensure the FRR is populated so freshness scans it
        if not recs_ws["frr"][frr_ws].get("implementation") or any(
                "TBD" in str(x) for x in (recs_ws["frr"][frr_ws].get("implementation") or [])):
            recs_ws["frr"][frr_ws]["implementation"] = ["Implemented for the boundary (fictional)."]
        json.dump(recs_ws, open(rp_ef, "w", encoding="utf-8", newline="\n"), indent=1)
        _resign_m()
        r_frrart = _preflight(root_m)
        check("expired FRR rule_artifacts on a populated rule are caught by the freshness gate",
              "EXPIRED evidence" in r_frrart.stdout and r_frrart.returncode == 1)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{PASS}/{PASS + FAIL} passed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
