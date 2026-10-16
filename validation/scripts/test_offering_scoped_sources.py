#!/usr/bin/env python3
"""AUD-F79 and AUD-F80, found while designing the non-AWS Class C sample
(MCE-12).

AUD-F79: the provenance gate bound every source the REPOSITORY knows (the AWS
collector registry, the Config-rules manifest, every registered adapter), not
the sources the OFFERING declares it operates. An offering with no AWS platform
could attach a valid, signed entry claiming `config:<rule>` and pass the
AUD-F62 binding check; any offering could claim a disabled adapter's check.
What this proves:
  1. a profile that declares no AWS platform binds none of the registry or
     manifest sources, so such an entry is unbound and the production
     preflight helper lists it; the same entry under the AWS template is bound
     (no over-block, parity with the pre-fix behaviour for AWS);
  2. an adapter the profile does not enable binds nothing; enabling it binds
     exactly its declared pairs; a mapping-driven source enabled by a non-AWS
     profile is bound while nothing AWS is;
  3. an injected registry still binds only under a declared AWS platform (the
     rule is about the offering, not the data);
  4. the signer pin accepts the neutral `key_reference` beside the AWS
     `key_arn` (a label for a managed key service on any platform).

AUD-F80: the adapter apply path (apply_third_party_evidence.py) never supplied
an evidence location base, so every adapter-derived pointer was an
sdr://placeholder/ pseudo-URI that package-preflight refuses at Class C, while
the collector path honours SDR_EVIDENCE_LOCATION_BASE. What this proves:
  5. apply_sources with a location base attaches concrete pointers under it
     that the AUD-F63 pointer check binds; without one it attaches placeholders
     and says so, naming the variable;
  6. the CLI honours --location-base and the environment variable, and
     apply_sources itself writes nothing to disk.

Run:
    python validation/scripts/test_offering_scoped_sources.py
"""

import io
import json
import os
import shutil
import sys
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))
import validate_evidence as ve  # noqa: E402
import evidence_wiring as ew  # noqa: E402
import thirdparty_adapters  # noqa: E402,F401  (registers Falcon and Wiz)
import apply_third_party_evidence as ap  # noqa: E402
sys.path.insert(0, BASE)
import sdr  # noqa: E402

FIX = os.path.join(BASE, "automation", "collectors", "fixtures", "mapping")
POSTURE_MAPPING_REL = "automation/collectors/fixtures/mapping/example-posture-scanner.mapping.json"
POSTURE_EXPORT_REL = "automation/collectors/fixtures/mapping/example-posture-scanner.export.jsonl"
_BASE_URI = "https://evidence.example.gov/store"
_KEY = "test-scope-key-not-a-secret"

AWS_TEMPLATE = ve.load(ve.OFFERING_PROFILE, {}) or {}
NON_AWS = {"offering_name": "fictional, no platform fields"}
AWS_PLAIN = {"aws_partition": "aws"}
AWS_WITH_FALCON = {"aws_partition": "aws",
                   "evidence_sources": {"crowdstrike-falcon": {"enabled": True}}}
NON_AWS_WITH_MAPPING = {"evidence_sources": {"example-posture-scanner": {
    "enabled": True, "mapping_path": POSTURE_MAPPING_REL, "export_path": POSTURE_EXPORT_REL}}}

failures = []


def check(name, cond):
    print(("PASS: " if cond else "FAIL: ") + name)
    if not cond:
        failures.append(name)


def _entry(service, check_name, region="us-east-1"):
    return ew.fact_to_evidence({"service": service, "check": check_name, "status": "PASS",
                                "detail": "unit fixture", "region": region,
                                "collected_at": "2026-10-10T00:00:00+00:00"}, location_base=_BASE_URI)


def _populated(evidence):
    return {"implementation": ["The provider does the thing, continuously, with the tool."],
            "evidence": list(evidence), "extension": {}}


def _manifest_rule():
    manifest = json.load(open(ve.RULES_MANIFEST, encoding="utf-8"))
    rules = manifest.get("rules") if isinstance(manifest, dict) else manifest
    return rules[0]["ksi_id"], rules[0]["rule_name"]


def test_1_non_aws_offering_binds_no_aws_source():
    check("declares_aws_platform: the AWS template declares one", ve.declares_aws_platform(AWS_TEMPLATE))
    check("declares_aws_platform: no field, or an empty one, declares none",
          not ve.declares_aws_platform(NON_AWS) and not ve.declares_aws_platform({"aws_partition": ""}))
    check("declares_aws_platform: a TBD value is a declared (unfilled) AWS platform",
          ve.declares_aws_platform({"aws_partition": "TBD: aws or aws-us-gov"}))
    kid, rule = _manifest_rule()
    non_aws = ve.load_source_bindings(profile=NON_AWS)
    check("a profile with no AWS platform and no sources binds nothing at all", non_aws == {})
    claim = _entry("config", rule)
    outcome, msg = ve.classify_source_binding(kid, claim, non_aws)
    check("an AWS Config-rule claim under a non-AWS offering is unbound, citing AUD-F79",
          outcome == "unbound" and "AUD-F79" in msg and "operates" in msg)
    aws = ve.load_source_bindings(profile=AWS_TEMPLATE)
    check("the same claim under the AWS template is bound (parity, no over-block)",
          ve.classify_source_binding(kid, claim, aws)[0] == "bound")
    reg = json.load(open(ve.REGISTRY, encoding="utf-8"))["ksis"]
    check("under the AWS template every registry KSI keeps a source (the production gate stays satisfiable)",
          all(ve.first_bound_source(k, aws) is not None for k in reg) and len(reg) == 46)
    listed = sdr.unbound_evidence_under_production(
        [(kid, _populated([claim]))], [], non_aws, ve.classify_source_binding, ve.classify_pointer_binding)
    check("the production preflight helper lists the non-AWS offering's AWS claim as a source finding",
          [(r, i, k) for r, i, k, _ in listed] == [(kid, 0, "source")])
    check("and lists nothing for the AWS template",
          sdr.unbound_evidence_under_production([(kid, _populated([claim]))], [], aws,
                                                ve.classify_source_binding, ve.classify_pointer_binding) == [])


def test_2_adapters_bind_only_when_the_offering_enables_them():
    falcon = _entry("crowdstrike", "open_detections", region="global")
    off = ve.load_source_bindings(profile=AWS_PLAIN)
    check("Falcon is registered but not enabled: its declared pair is unbound under its own target",
          ve.classify_source_binding("KSI-MLA-OSM", falcon, off)[0] == "unbound")
    check("the committed template enables no third-party source, so none of their pairs are bound",
          not any(k.split(":")[0] in ("crowdstrike", "wiz")
                  for slot in ve.load_source_bindings(profile=AWS_TEMPLATE).values() for k in slot["keys"]))
    on = ve.load_source_bindings(profile=AWS_WITH_FALCON)
    check("enabling Falcon binds exactly its declared pairs under its targets",
          ve.classify_source_binding("KSI-MLA-OSM", falcon, on)[0] == "bound"
          and ve.classify_source_binding("KSI-MLA-OSM", _entry("crowdstrike", "made_up", "global"), on)[0] == "unbound"
          and ve.classify_source_binding("KSI-MLA-OSM", _entry("wiz", "vulnerabilities", "global"), on)[0] == "unbound")
    check("enabled_source_names reads only enabled entries",
          ve.enabled_source_names(AWS_WITH_FALCON) == {"crowdstrike-falcon"}
          and ve.enabled_source_names(AWS_TEMPLATE) == set() and ve.enabled_source_names({}) == set())
    mapped = ve.load_source_bindings(profile=NON_AWS_WITH_MAPPING)
    check("a mapping-driven source enabled by a NON-AWS offering is bound",
          "example-posture:PUBLIC_BUCKET_ACL" in mapped.get("KSI-MLA-EVC", {}).get("keys", set()))
    check("and that offering binds nothing AWS (no config rules, no collector keys)",
          all(not slot["config"] and all(k.startswith("example-posture:") for k in slot["keys"])
              for slot in mapped.values()))
    kid, rule = _manifest_rule()
    check("the same non-AWS offering still refuses an AWS Config-rule claim",
          ve.classify_source_binding(kid, _entry("config", rule), mapped)[0] == "unbound")


def test_3_injected_registry_still_scoped_by_platform():
    synth = {"KSI-A": {"metric_service_keys": ["guardduty:detector"],
                       "checks": [{"type": "config_managed_rule", "target": "rule-a"}]}}
    with_aws = ve.load_source_bindings(synth, {"rules": []}, [], profile=AWS_PLAIN)
    check("an injected registry binds under a declared AWS platform",
          with_aws == {"KSI-A": {"keys": {"guardduty:detector"}, "config": {"rule-a"}}})
    without = ve.load_source_bindings(synth, {"rules": []}, [], profile=NON_AWS)
    check("the same injected registry binds nothing for an offering with no AWS platform", without == {})


def test_4_signer_pin_accepts_key_reference():
    pem = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----\n"
    by_ref = ve.load_trusted_signer({"expected_evidence_signer": {
        "key_reference": "civic-evidence-signer-2026", "public_key_pem": pem, "signer_kind": "managed-key-service"}})
    check("key_reference pins the label (returned in the historical key_arn slot)",
          by_ref and by_ref["key_arn"] == "civic-evidence-signer-2026" and by_ref["required"])
    by_arn = ve.load_trusted_signer({"expected_evidence_signer": {
        "key_arn": "arn:aws:kms:us-east-1:000000000000:key/abc", "public_key_pem": pem}})
    check("key_arn still pins the AWS form", by_arn and by_arn["key_arn"].startswith("arn:aws:kms:"))
    both = ve.load_trusted_signer({"expected_evidence_signer": {
        "key_reference": "label-wins", "key_arn": "arn:aws:kms:us-east-1:000000000000:key/abc",
        "public_key_pem": pem}})
    check("when both are set the neutral name wins", both and both["key_arn"] == "label-wins")
    tbd = ve.load_trusted_signer({"expected_evidence_signer": {
        "key_reference": "TBD: label", "key_arn": "arn:aws:kms:us-east-1:000000000000:key/abc",
        "public_key_pem": pem}})
    check("a TBD key_reference falls back to key_arn", tbd and tbd["key_arn"].startswith("arn:aws:kms:"))
    check("no profile argument reads the committed template (unpinned there)",
          ve.load_trusted_signer() is None)


def _records():
    return {"ksi": {"KSI-MLA-EVC": {"evidence": []}, "KSI-MLA-OSM": {"evidence": []}}}


def test_5_apply_sources_honours_the_location_base():
    log = []
    records = _records()
    code, attached = ap.apply_sources(NON_AWS_WITH_MAPPING, records, base=BASE, scope_key=_KEY,
                                      location_base=_BASE_URI, log=log.append)
    evs = records["ksi"]["KSI-MLA-EVC"]["evidence"] + records["ksi"]["KSI-MLA-OSM"]["evidence"]
    check("apply_sources attaches the mapping source's evidence", code == 0 and attached == 7 and len(evs) == 7)
    check("every attached pointer is a concrete URL under the evidence-store base, ending in .json",
          all(e["evidenceLocation"].startswith(_BASE_URI + "/") and e["evidenceLocation"].endswith(".json")
              for e in evs))
    check("no attached pointer is a placeholder", not any("sdr://placeholder/" in e["evidenceLocation"] for e in evs))
    check("every attached pointer is bound to its own source fact (AUD-F63)",
          all(ve.classify_pointer_binding(e)[0] == "bound" for e in evs))
    check("with a base the driver prints no placeholder note",
          not any(ap.LOCATION_BASE_ENV in line for line in log))
    log2 = []
    records2 = _records()
    code2, attached2 = ap.apply_sources(NON_AWS_WITH_MAPPING, records2, base=BASE, scope_key=_KEY,
                                        location_base=None, log=log2.append)
    evs2 = records2["ksi"]["KSI-MLA-EVC"]["evidence"] + records2["ksi"]["KSI-MLA-OSM"]["evidence"]
    check("without a base the pointers are placeholders (the pre-fix behaviour, now explicit)",
          code2 == 0 and attached2 == 7 and all(e["evidenceLocation"].startswith("sdr://placeholder/") for e in evs2))
    check("and the driver says so once, naming the variable and the Class C refusal",
          sum(1 for line in log2 if ap.LOCATION_BASE_ENV in line and "placeholder" in line
              and "Class C" in line) == 1)


def test_6_cli_honours_flag_and_environment_and_apply_sources_writes_nothing():
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(FIX, os.path.join(tmp, "fixtures"))
        rec_path = os.path.join(tmp, "records-store.json")
        prof_path = os.path.join(tmp, "offering-profile.json")
        with open(prof_path, "w", encoding="utf-8") as f:
            json.dump({"evidence_sources": {"example-posture-scanner": {
                "enabled": True, "export_path": "fixtures/example-posture-scanner.export.jsonl",
                "mapping_path": "fixtures/example-posture-scanner.mapping.json"}}}, f)
        saved = (ap.BASE, ap.PROFILE, ap.RECORDS,
                 os.environ.get(ap.SCOPE_KEY_ENV), os.environ.get(ap.LOCATION_BASE_ENV))
        ap.BASE, ap.PROFILE, ap.RECORDS = tmp, prof_path, rec_path
        os.environ[ap.SCOPE_KEY_ENV] = _KEY
        try:
            def run(argv, env_base):
                with open(rec_path, "w", encoding="utf-8") as f:
                    json.dump(_records(), f)
                if env_base is None:
                    os.environ.pop(ap.LOCATION_BASE_ENV, None)
                else:
                    os.environ[ap.LOCATION_BASE_ENV] = env_base
                out = io.StringIO()
                real = sys.stdout
                sys.stdout = out
                try:
                    rc = ap.main(argv)
                finally:
                    sys.stdout = real
                with open(rec_path, encoding="utf-8") as f:
                    after = json.load(f)
                locs = [e["evidenceLocation"] for k in after["ksi"].values() for e in k["evidence"]]
                return rc, locs, out.getvalue()

            rc, locs, _ = run(["--location-base", "https://flag.example.gov/store"], None)
            check("--location-base flows to every attached pointer",
                  rc == 0 and locs and all(loc.startswith("https://flag.example.gov/store/") for loc in locs))
            rc, locs, _ = run([], "https://env.example.gov/store")
            check(f"${ap.LOCATION_BASE_ENV} is the default when the flag is absent",
                  rc == 0 and locs and all(loc.startswith("https://env.example.gov/store/") for loc in locs))
            rc, locs, text = run([], None)
            check("with neither, pointers are placeholders and the NOTE is printed",
                  rc == 0 and locs and all(loc.startswith("sdr://placeholder/") for loc in locs)
                  and ap.LOCATION_BASE_ENV in text)
            # apply_sources itself never writes: the on-disk store is untouched.
            with open(rec_path, "w", encoding="utf-8") as f:
                json.dump(_records(), f)
            before = open(rec_path, encoding="utf-8").read()
            ap.apply_sources(json.load(open(prof_path, encoding="utf-8")), _records(), base=tmp,
                             scope_key=_KEY, location_base=_BASE_URI, log=lambda *_a: None)
            check("apply_sources writes nothing to disk (the caller owns the write)",
                  open(rec_path, encoding="utf-8").read() == before)
        finally:
            ap.BASE, ap.PROFILE, ap.RECORDS = saved[:3]
            for var, val in ((ap.SCOPE_KEY_ENV, saved[3]), (ap.LOCATION_BASE_ENV, saved[4])):
                if val is None:
                    os.environ.pop(var, None)
                else:
                    os.environ[var] = val


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    if failures:
        print(f"\nFAIL: offering-scoped sources ({len(failures)} failure(s))")
        return 1
    print("\nPASS: offering-scoped sources (0 failures)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
