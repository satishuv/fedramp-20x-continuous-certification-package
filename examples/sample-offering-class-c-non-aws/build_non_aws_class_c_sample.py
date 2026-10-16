"""Build a fully-worked FICTIONAL Class C sample for an offering that runs on a
platform OTHER than AWS, drive it to submission preflight under
production-assurance, and attack it with the SAME probe list as the AWS Class C
sample (MCE-12).

The fictional provider, Harborlight Civic Cloud (HCC), hosts its offering on
Google Cloud and scans its on-premises operator hosts against an XCCDF
benchmark. Every evidence entry behind every populated KSI comes through the
ADAPTER PATH a real provider uses: the offering profile enables three
mapping-driven sources (the Google Cloud Security Command Center reference
mapping, the OpenSCAP XCCDF reference mapping, and the provider's own
collector declared the same way), the apply driver reads their exports and
attaches each entry to exactly the KSIs its declared (service, check) pair
binds, and every entry is hashed and signed. Nothing is hand-written, and no
AWS source is declared or claimed: the profile carries no aws_partition, so
the provenance gate binds only the three enabled sources (AUD-F79).

The exports are produced in memory from the committed fixtures with today's
observation times (the fixtures carry fixed dates and the mappings a short
freshness policy) and written under a sample-owned folder for the length of
the apply step only. The signer is a throwaway key standing in for the
provider's managed key service, pinned by its label (key_reference), never an
ARN, URL or GUID.

Everything is FICTIONAL. No real organization, project, host, assessor or
evidence. A green preflight here means the framework's readiness checks are
SATISFIABLE by complete input on a non-AWS platform, NOT that anything is
FedRAMP compliant, and nothing here compares or evaluates any product.

Run:
    python examples/sample-offering-class-c-non-aws/build_non_aws_class_c_sample.py          # preflight
    python examples/sample-offering-class-c-non-aws/build_non_aws_class_c_sample.py --attack # probes
"""

import base64
import copy
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
AWS_SAMPLE = os.path.join(BASE, "examples", "sample-offering-class-c", "build_class_c_sample.py")
FIX_REL = "automation/collectors/fixtures/mapping"
EXPORTS_REL = "examples/sample-offering-class-c-non-aws/generated-exports"
EXPORTS_DIR = os.path.join(BASE, *EXPORTS_REL.split("/"))

sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))
sys.path.insert(0, os.path.join(BASE, "automation", "metrics"))
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))


def _load_aws_sample():
    """The AWS Class C sample module: the shared harness (attack, SamplePlatform,
    _preflight_rc, backup and restore) and the template-filling helpers."""
    if "build_class_c_sample" in sys.modules:
        return sys.modules["build_class_c_sample"]
    spec = importlib.util.spec_from_file_location("build_class_c_sample", AWS_SAMPLE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["build_class_c_sample"] = mod
    spec.loader.exec_module(mod)
    return mod


aws = _load_aws_sample()
TODAY = aws.TODAY
FICT = aws.FICT

PROVIDER = "Harborlight Civic Cloud"
ABBR = "HCC"
DOMAIN = "hcc-demo.invalid"
LOCATION_BASE = f"https://evidence.{DOMAIN}/store"
REGION = "us-central1"
# The signer's key reference is a LABEL (signers.check_key_reference shape),
# pinned under key_reference; never an ARN, URL, GUID or account id.
SIGNER_REF = "hcc-evidence-signer-2026"
# Deployment-private scope key: the raw project and host identifiers in the
# exports become opaque scope ids. Fictional, like everything else here.
SCOPE_KEY = b"SAMPLE-fictional-scope-key-not-a-secret"

# The three enabled sources: mapping fixture stem -> export file name.
SOURCES = {
    "example-google-cloud-scc": "scc-findings.json",
    "example-openscap-xccdf": "benchmark-results.xml",
    "example-provider-collector": "provider-collector.jsonl",
}


def _method_ids(kid):
    """The two automated VVK methods the fictional provider declares per KSI:
    its posture scanner and its own collector; the metric history keys its
    per-method telemetry by the same ids."""
    return (f"{kid}-posture-finding", f"{kid}-provider-collector")


def _impl(kid, aspect):
    return (f"{FICT} {PROVIDER} ({ABBR}) addresses {kid} for '{aspect}' via documented, "
            f"version-controlled controls in the {ABBR} boundary on Google Cloud, deployed by CI/CD "
            "and continuously measured by the provider's own collector and its posture scanner. "
            "Illustrative example text only.")


def fill_ksi(kid, rec):
    """Fill a KSI record to Class C readiness: Implemented status, real
    narratives, TWO automated verification methods. The evidence list is left
    EMPTY here: every entry is attached by the adapter path in generate_store,
    never written by hand."""
    rec["implementation_status"] = "Implemented"
    rec["implementation"] = [_impl(kid, "implementation")]
    rec["validation"] = [_impl(kid, "validation")]
    rec["assessment"] = [f"{FICT} Independently assessed by the fictional Recognized assessor as part "
                         f"of the {ABBR} FedRAMP 20x assessment."]
    posture, collector = _method_ids(kid)
    rec["tests"] = [
        {"method_id": posture,
         "method": f"{FICT} the posture scanner reports findings for {kid} continuously; each finding "
                   "is a record in the exported findings list.",
         "automated": True, "cadence": "continuous"},
        {"method_id": collector,
         "method": f"{FICT} the provider's scheduled collector queries the relevant read-only APIs for "
                   f"{kid} and records a datapoint.",
         "automated": True, "cadence": "daily"},
    ]
    rec["evidence"] = []
    ext = rec.setdefault("extension", {})
    for f in list(ext.keys()):
        v = ext[f]
        if isinstance(v, str) and ("TBD" in v or not v.strip()):
            ext[f] = _impl(kid, f)
        elif isinstance(v, list) and (not v or all("TBD" in str(x) for x in v)):
            ext[f] = [_impl(kid, f)]
    ext["owner"] = f"R. Okonkwo, {ABBR} Security Engineering (fictional)"
    ext["measures_verification"] = _impl(kid, "measures_verification")
    ext["automation_verification"] = _impl(kid, "automation_verification")
    hm = rec.setdefault("historical_metrics", {})
    hm["last_30_days"] = f"{FICT} {kid}: 30/30 days passing over the last 30 days."
    hm["up_to_one_year"] = f"{FICT} {kid}: >=99% passing across the available ~7-month window."
    hm["daily_data_reference"] = f"https://evidence.{DOMAIN}/{kid.lower()}/daily-metrics.json"
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
    ext["owner"] = f"R. Okonkwo, {ABBR} Security Engineering (fictional)"
    ext["independent_verification"] = f"{FICT} Independent verification recorded for {rid}."
    ext["independent_validation"] = f"{FICT} Independent validation recorded for {rid}."
    # A resolvable rule artifact so evidence linkage is satisfied for populated
    # MUSTs; under production-assurance the harness and run() derive these
    # through the factory and sign them (FRR artifacts have no source map,
    # only the pointer check applies).
    ext["rule_artifacts"] = [{
        "evidenceType": "Configuration",
        "evidenceDescription": f"{FICT} Control evidence for {rid}.",
        "evidenceLocation": f"https://evidence.{DOMAIN}/frr/{rid.lower()}.json",
        "lastUpdated": TODAY.isoformat(),
    }]
    return rec


def generate_exports(dirpath):
    """Write the three exports under dirpath, derived from the committed
    fixtures with every observation time moved to today (same shapes, same
    fictional records)."""
    fix = os.path.join(BASE, *FIX_REL.split("/"))
    os.makedirs(dirpath, exist_ok=True)
    scc = json.load(open(os.path.join(fix, "example-google-cloud-scc.export.json"), encoding="utf-8"))
    for item in scc["findings"]:
        item["finding"]["eventTime"] = f"{TODAY.isoformat()}T06:00:00Z"
    with open(os.path.join(dirpath, SOURCES["example-google-cloud-scc"]), "w", encoding="utf-8", newline="\n") as f:
        json.dump(scc, f, indent=1)
    xml = open(os.path.join(fix, "example-openscap-xccdf.results.xml"), encoding="utf-8").read()
    xml = re.sub(r'(time=")\d{4}-\d{2}-\d{2}', lambda m: m.group(1) + TODAY.isoformat(), xml)
    with open(os.path.join(dirpath, SOURCES["example-openscap-xccdf"]), "w", encoding="utf-8", newline="\n") as f:
        f.write(xml)
    lines = open(os.path.join(fix, "example-provider-collector.export.jsonl"), encoding="utf-8").read().splitlines()
    with open(os.path.join(dirpath, SOURCES["example-provider-collector"]), "w", encoding="utf-8", newline="\n") as f:
        for ln in lines:
            if not ln.strip():
                continue
            rec = json.loads(ln)
            rec["observed_at"] = f"{TODAY.isoformat()}T05:00:00Z"
            f.write(json.dumps(rec) + "\n")


def _evidence_sources():
    return {
        name: {"enabled": True,
               "mapping_path": f"{FIX_REL}/{name}.mapping.json",
               "export_path": f"{EXPORTS_REL}/{export}"}
        for name, export in SOURCES.items()
    }


def generate_profile(production=False, signer_public_key_pem=None):
    """The fictional non-AWS offering profile. No aws_partition, primary_region
    or dr_region (MCE-16: a provider on another platform declares none); the
    three adapter sources enabled; the evidence store as properties (MCE-09);
    the signer declared as a managed key service pinned by label (MCE-08).
    production=True pins the given public key and declares production-assurance
    (run()); the attack harness starts from the development variant and pins
    its own key in the production probes, like the AWS harness."""
    with open(aws.REAL_PROFILE, encoding="utf-8") as f:
        profile = json.load(f)
    recent = (TODAY - aws.dt.timedelta(days=2)).isoformat()
    fia_done = (TODAY - aws.dt.timedelta(days=40)).isoformat()
    for k in ("aws_partition", "primary_region", "dr_region"):
        profile.pop(k, None)
    profile.update({
        "organization_name": f"{PROVIDER}, Inc. (fictional)",
        "offering_name": PROVIDER,
        "offering_abbreviation": ABBR,
        "business_purpose": ("A fictional multi-tenant SaaS case-management platform hosted on Google Cloud, "
                             "with on-premises operator hosts scanned against an XCCDF benchmark, used to "
                             "demonstrate a COMPLETE Class C package on a platform other than AWS."),
        "service_model": "SaaS",
        "deployment_model": "Public Cloud",
        "certification_type": "20x",
        "certification_class": "C",
        "certification_path": "Program",
        "certification_package_overview_uri": f"https://trust.{DOMAIN}/cpo.json",
        "security_contact": f"security@{DOMAIN} (fictional)",
        "incident_contact": f"ir@{DOMAIN} (fictional)",
        "sales_contact": f"sales@{DOMAIN} (fictional)",
        "assessor": "Cascade Assurance LLC (fictional Recognized assessor)",
        "assessor_id": "123456",
        "uei_number": "ZQGGHJH74DW8 (fictional)",
        "business_category": ["Case Management", "Collaboration"],
        "documentation_overview": (f"{FICT} User guide, API reference, Secure Configuration Guide and the "
                                   "trust-center certification data, all published at "
                                   f"https://trust.{DOMAIN}/."),
        "provider_verified_at": recent + "T00:00:00+00:00",
        "evidence_store": {
            "versioned": True,
            "write_once": True,
            "separately_administered": True,
            "retention_days": 400,
            "access_logging": True,
            "implementation": f"{FICT} write-once versioned object store in a separately administered "
                              "audit project, access-logged to its own destination.",
        },
        "evidence_sources": _evidence_sources(),
        "overall_assessment_summary": (f"{FICT} The independent assessor's overall summary: no unresolved "
                                       "high findings; all in-scope KSIs validated."),
        "fedramp_independent_assessment": {
            "assessor_name": "Cascade Assurance LLC (fictional)",
            "assessor_fedramp_id": "FR-RECOG-0142 (fictional)",
            "completed_at": fia_done,
        },
        "availability_reporting": {
            "human_readable_uri": f"https://trust.{DOMAIN}/status",
            "machine_readable_uri": f"https://trust.{DOMAIN}/status.json",
            "history_days": 120,
            "available_when_primary_unavailable": True,
        },
        "trust_center_uri": f"https://trust.{DOMAIN}/",
        "secure_config_guide_uri": f"https://trust.{DOMAIN}/scg",
        "secure_config_guide_machine_uri": f"https://trust.{DOMAIN}/scg/machine-readable.json",
        "next_ocr_date": (TODAY + aws.dt.timedelta(days=80)).isoformat(),
        "cpo_responsible_official": f"M. Alvarez, {ABBR} Authorizing Official (fictional)",
        "cpo_version": "1.0.0",
        "cpo_last_updated": recent,
        "cpo_source_of_update": f"{ABBR} compliance engineering (fictional)",
        "fedramp_package_id": f"FR-20X-{ABBR}-0001 (fictional)",
        "offering_website": f"https://www.{DOMAIN}/",
        "offering_logo_uri": f"https://www.{DOMAIN}/logo.png",
        "cpo_required_information": aws._cpo_required_information(None),
    })
    if production:
        profile["evidence_store_profile"] = "production-assurance"
        profile["expected_evidence_signer"] = {
            "key_reference": SIGNER_REF,
            "public_key_pem": signer_public_key_pem,
            "signer_kind": "managed-key-service",
        }
    for k, v in list(profile.items()):
        if isinstance(v, str) and "TBD" in v:
            profile[k] = f"{FICT} {k} for {PROVIDER}."
    profile["profile_note"] = f"{FICT} FICTIONAL Class C sample on a platform other than AWS; illustrative only."
    return profile


def generate_store():
    """The record store with every KSI and FRR filled, and every KSI's evidence
    attached through the adapter path: exports written under the sample-owned
    folder for the length of the apply step, the three enabled sources applied
    by the real driver (apply_sources), the folder removed. Fails, naming the
    KSIs, if any populated KSI ends up without evidence: the three sources
    must cover all 46 or the sample is not honest about them."""
    import apply_third_party_evidence as ap
    with open(aws.REAL_STORE, encoding="utf-8") as f:
        store = json.load(f)
    for kid, rec in store.get("ksi", {}).items():
        fill_ksi(kid, rec)
    for rid, rec in store.get("frr", {}).items():
        fill_frr(rid, rec)
    profile = generate_profile()
    log = []
    if os.path.isdir(EXPORTS_DIR):
        shutil.rmtree(EXPORTS_DIR)
    generate_exports(EXPORTS_DIR)
    try:
        code, attached = ap.apply_sources(profile, store, base=BASE, scope_key=SCOPE_KEY,
                                          location_base=LOCATION_BASE, log=log.append)
    finally:
        shutil.rmtree(EXPORTS_DIR, ignore_errors=True)
    if code != 0 or attached == 0:
        raise RuntimeError("the adapter path attached nothing:\n" + "\n".join(log))
    missing = sorted(kid for kid, rec in store["ksi"].items() if not rec.get("evidence"))
    if missing:
        raise RuntimeError(f"{len(missing)} populated KSI(s) have no adapter-derived evidence: "
                           f"{', '.join(missing)}")
    return store


def generate_history(store):
    return aws.generate_history(store, _method_ids)


def _sign_entry(ev, key, ref):
    """Sign the entry's current digest the way sign_evidence.sign_hash records
    it: the key REFERENCE as keyId (here a label), never an identifier."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    h = ev["xEvidenceContentHash"]
    sig = key.sign(h.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    ev["xEvidenceSignature"] = {"algorithm": "ECDSA_SHA_256", "keyId": ref, "signedHash": h,
                                "signature": base64.b64encode(sig).decode("ascii")}
    return ev


def _throwaway_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    return key, pem


def sign_package(store, history, key):
    """Production-assurance: sign every adapter-derived KSI entry, derive and
    sign every FRR rule artifact through the factory, and sign the metric
    history digest, all with the stand-in managed key."""
    import evidence_wiring as ew
    import history_integrity as hi
    for rec in store["ksi"].values():
        for ev in rec.get("evidence") or []:
            _sign_entry(ev, key, SIGNER_REF)
    observed = f"{TODAY.isoformat()}T00:00:00+00:00"
    for rid, rec in store["frr"].items():
        ext = rec.get("extension") or {}
        if ext.get("rule_artifacts"):
            ev = ew.fact_to_evidence(
                {"service": "provider-collector", "check": f"frr-{rid.lower()}", "status": "PASS",
                 "region": REGION, "detail": f"{FICT} {rid} control evidence", "collected_at": observed},
                location_base=LOCATION_BASE)
            ext["rule_artifacts"] = [_sign_entry(ev, key, SIGNER_REF)]
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    digest = hi.record_heads(history)
    sig = key.sign(digest.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    history["meta"]["history_signature"] = {"algorithm": "ECDSA_SHA_256", "keyId": SIGNER_REF,
                                            "signedHash": digest,
                                            "signature": base64.b64encode(sig).decode("ascii")}


class NonAwsPlatform(aws.SamplePlatform):
    """The non-AWS half of the harness: same probes, this offering's inputs."""
    name = "non-aws"
    region = REGION
    location_base = LOCATION_BASE
    signer_key_ref = SIGNER_REF
    signer_pin_field = "key_reference"
    frr_source_service = "provider-collector"
    rebind_ksi_evidence = False   # the store already carries adapter-derived entries
    adapter_probes = False        # the AWS sample's Falcon and Wiz probes; this sample enables neither
    signoff_reviewer = f"M. Alvarez, {ABBR} Authorizing Official (fictional)"
    signoff_note = f"{FICT} Package-level provider signoff for the non-AWS Class C sample."

    def generate_store(self):
        return generate_store()

    def generate_profile(self):
        return generate_profile()

    def generate_history(self, store):
        return generate_history(store)

    def method_ids(self, kid):
        return _method_ids(kid)

    def extra_probes(self, h):
        import validate_evidence as ve
        manifest = json.load(open(ve.RULES_MANIFEST, encoding="utf-8"))
        rules = manifest.get("rules") if isinstance(manifest, dict) else manifest
        aws_rule = rules[0]

        # MCE-12 AC3: an adapter fact re-pointed at a KSI its source is not
        # registered for, digest recomputed and re-signed: the cryptographic
        # gate stays silent, the provenance gate blocks. The posture scanner's
        # network check binds KSI-CNA-RNT only; here it is attached under the
        # training indicator.
        def _adapter_entry_under_unbound_ksi(st, pr, hi):
            key, ref = h.pin_signer(pr, hi)
            h.bind_evidence(st, sign_with=(key, ref))
            donor = copy.deepcopy(st["ksi"]["KSI-CNA-RNT"]["evidence"][0])
            assert donor["xSourceFact"]["service"] == "google-cloud-scc", donor["xSourceFact"]
            st["ksi"]["KSI-CED-RAT"]["evidence"] = [donor]
            h.resign(donor, key, ref)
        h.probe("production-assurance: an ADAPTER fact (google-cloud-scc network check, bound to KSI-CNA-RNT) "
                "re-pointed at KSI-CED-RAT, digest recomputed and re-signed, blocks by the provenance gate "
                "(MCE-12 AC3; AUD-F62 on adapter evidence)", _adapter_entry_under_unbound_ksi,
                expect="not PROVENANCE-BOUND (1 source (e.g.")

        # AUD-F79 (platform half): a valid signed entry claiming an AWS Config
        # rule, a source this offering (no AWS platform declared) never ran,
        # under the KSI the AWS rules manifest binds it to. On the gate before
        # AUD-F79 this reached READY.
        def _aws_config_rule_claim(st, pr, hi):
            key, ref = h.pin_signer(pr, hi)
            one = h.bind_evidence(st, sign_with=(key, ref))
            st["ksi"][aws_rule["ksi_id"]]["evidence"] = [one("config", aws_rule["rule_name"], aws_rule["ksi_id"])]
        h.probe("production-assurance: a VALID signed entry claiming an AWS Config rule (a source this offering, "
                "with no AWS platform, does not operate) under the KSI the AWS manifest binds it to blocks "
                "(AUD-F79, platform scope)", _aws_config_rule_claim,
                expect="not PROVENANCE-BOUND (1 source (e.g.")

        # Every populated KSI MUST carry evidence at Class C (FRC-CSX-VVK): the
        # adapter path attached it; an editor removing it must block. The gate
        # is validate_sdr's evidence_linkage_for_populated_musts (hard at Class
        # C), surfaced by preflight as the validation-gate blocker.
        def _evidence_removed(st, pr, hi):
            kid = sorted(st["ksi"])[0]
            st["ksi"][kid]["evidence"] = []
        h.probe("a populated KSI whose adapter-derived evidence is removed blocks at Class C (FRC-CSX-VVK: "
                "every populated KSI carries evidence; validation gate)", _evidence_removed,
                expect="the validation gate does not pass")

        # Positive control for AC3: the same adapter entry under a KSI its
        # check DOES bind (the storage check binds both KSI-CNA-MAT and
        # KSI-MLA-EVC) stays READY under production-assurance.
        def _adapter_entry_under_second_bound_ksi(st, pr, hi):
            key, ref = h.pin_signer(pr, hi)
            h.bind_evidence(st, sign_with=(key, ref))
            storage = next(ev for ev in st["ksi"]["KSI-CNA-MAT"]["evidence"]
                           if ev["xSourceFact"]["service"] == "google-cloud-scc")
            twin = copy.deepcopy(storage)
            st["ksi"]["KSI-MLA-EVC"]["evidence"].append(twin)
            h.resign(twin, key, ref)
        h.probe_ready("production-assurance: the same adapter entry under the SECOND KSI its check binds "
                      "(storage check: KSI-CNA-MAT and KSI-MLA-EVC) stays READY (MCE-12 positive control)",
                      _adapter_entry_under_second_bound_ksi)


def run(argv):
    """Build the production-assurance package (AC1): adapter-derived, hashed,
    signed evidence behind every populated KSI; signed history; the signer
    pinned by label; preflight must be READY. Restores every file after."""
    key, pem = _throwaway_key()
    tmp = tempfile.mkdtemp(prefix="sdr-classc-nonaws-")
    baks = aws._backup(tmp)
    store = generate_store()
    profile = generate_profile(production=True, signer_public_key_pem=pem)
    history = generate_history(store)
    sign_package(store, history, key)
    history_existed = os.path.exists(aws.REAL_HISTORY)
    try:
        with open(aws.REAL_STORE, "w", encoding="utf-8", newline="\n") as f:
            json.dump(store, f, indent=1)
        with open(aws.REAL_PROFILE, "w", encoding="utf-8", newline="\n") as f:
            json.dump(profile, f, indent=1)
        with open(aws.REAL_HISTORY, "w", encoding="utf-8", newline="\n") as f:
            json.dump(history, f, indent=1)
        subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "build"],
                       cwd=BASE, capture_output=True, text=True)
        aws._record_signoff(NonAwsPlatform.signoff_reviewer, NonAwsPlatform.signoff_note)
        pf = subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "package-preflight"],
                            cwd=BASE, capture_output=True, text=True)
        print((pf.stdout or "") + (pf.stderr or ""))
        entries = sum(len(r.get("evidence") or []) for r in store["ksi"].values())
        print(f"\nNon-AWS Class C package: {entries} adapter-derived, hashed, signed evidence entries behind "
              f"{len(store['ksi'])} KSIs; evidence_store_profile production-assurance; signer pinned by label.")
        print(f"package-preflight exit code: {pf.returncode} ({'READY' if pf.returncode == 0 else 'BLOCKED'})")
        rc = pf.returncode
    finally:
        aws._restore_tree(baks, history_existed, tmp)
    if os.path.isdir(EXPORTS_DIR):
        print(f"FAIL: sample-owned exports folder still present: {EXPORTS_REL}")
        return 1
    return rc


def attack():
    rc = aws.attack(NonAwsPlatform())
    if os.path.isdir(EXPORTS_DIR):
        print(f"FAIL: sample-owned exports folder still present after the attack: {EXPORTS_REL}")
        return 1
    return rc


if __name__ == "__main__":
    if "--attack" in sys.argv:
        sys.exit(attack())
    sys.exit(run(sys.argv))
