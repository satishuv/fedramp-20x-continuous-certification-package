#!/usr/bin/env python3
"""MCE-03 / AUD-F72: source registry binding for adapter checks.

What this proves:
  AC1  when an adapter registers, every (service, check) pair it declares is
       recorded against each of its KSI targets in the bindings the AUD-F62
       provenance gate reads (validate_evidence.load_source_bindings); nothing
       is bound service-wide, so an undeclared check under a registered
       service binds nothing;
  AC2  evidence under a KSI citing a (service, check) pair not registered for
       that KSI is 'unbound' to the classifier, the production-assurance
       preflight helper lists it (a blocker there), and the same entry under
       its registered KSI is bound (no over-block);
  AC3  the mutation that removes one check's binding (MUT-F72 drops
       open_detections from Falcon's declared checks) turns this file red:
       the positive control below attaches crowdstrike:open_detections under
       KSI-MLA-OSM and requires it bound.
Also: the mapping-driven adapter's check_bindings narrow one check to one KSI;
a mapping that binds a check it does not declare, or an unknown KSI id in
check_bindings, is refused naming it; an export record whose check is not
declared is refused by to_evidence naming the check (nothing converted);
mapping adapters the offering profile enables are registered for the gate by
register_from_profile, and a key/name mismatch is refused.

Run:
    python validation/scripts/test_adapter_source_bindings.py
"""

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))
import validate_evidence as ve  # noqa: E402
import evidence_wiring as ew  # noqa: E402
import mapping_adapter as ma  # noqa: E402
import thirdparty_adapters  # noqa: E402,F401  (registers Falcon and Wiz)
sys.path.insert(0, BASE)
import sdr  # noqa: E402

FIX = os.path.join(BASE, "automation", "collectors", "fixtures", "mapping")
MAPPING = os.path.join(FIX, "example-posture-scanner.mapping.json")
JSONL = os.path.join(FIX, "example-posture-scanner.export.jsonl")
_BASE = "https://evidence.example.gov/store"
_KEY = b"test-scope-key-not-a-secret"

FALCON_CHECKS = ("sensor_coverage", "open_detections", "prevention_policy")
FALCON_TARGETS = ("KSI-MLA-OSM", "KSI-MLA-RVL", "KSI-MLA-LET", "KSI-INR-RIR")

failures = []


def check(name, cond):
    print(("PASS: " if cond else "FAIL: ") + name)
    if not cond:
        failures.append(name)


def _entry(service, check, region="global"):
    return ew.fact_to_evidence({"service": service, "check": check, "status": "PASS",
                                "detail": "probe", "region": region,
                                "observed_at": "2026-10-01T00:00:00Z"}, _BASE)


def _populated(evidence):
    return {"implementation": ["The provider does the thing, continuously, with the tool."],
            "evidence": list(evidence), "extension": {}}


def _mapping(**over):
    with open(MAPPING, encoding="utf-8") as f:
        m = json.load(f)
    m.update(over)
    return m


def test_ac1_declared_pairs_are_bound_per_ksi_and_nothing_service_wide():
    falcon = ew.get_adapter("crowdstrike-falcon")
    check("Falcon declares exactly its three checks", tuple(falcon.checks) == FALCON_CHECKS)
    sb = falcon.source_bindings()
    check("source_bindings: one key per declared check, each to every target",
          set(sb) == {f"crowdstrike:{c}" for c in FALCON_CHECKS}
          and all(v == set(FALCON_TARGETS) for v in sb.values()))
    wiz = ew.get_adapter("wiz")
    check("Wiz declares its three checks and binds them to its targets",
          set(wiz.source_bindings()) == {"wiz:issues_critical_high", "wiz:config_findings", "wiz:vulnerabilities"}
          and all(v == {"KSI-MLA-EVC", "KSI-MLA-OSM", "KSI-SCR-MON"} for v in wiz.source_bindings().values()))
    bindings = ve.load_source_bindings()
    check("the gate's bindings carry every Falcon pair under every Falcon target",
          all({f"crowdstrike:{c}" for c in FALCON_CHECKS} <= bindings[k]["keys"] for k in FALCON_TARGETS))
    check("no slot carries a service-wide binding any more",
          all("services" not in slot for slot in bindings.values()))
    check("an adapter with no declared checks binds nothing (no inference from its service)",
          ve.load_source_bindings({}, {"rules": []},
                                  [type("A", (), {"service": "x", "ksi_targets": lambda s: ["KSI-A"]})()]) == {})


def test_ac2_wrong_pair_is_unbound_blocks_under_production_and_bound_twin_passes():
    bindings = ve.load_source_bindings()
    # The positive control: this exact pair is what MUT-F72 removes.
    good = _entry("crowdstrike", "open_detections")
    check("POSITIVE CONTROL: crowdstrike:open_detections under KSI-MLA-OSM is bound",
          ve.classify_source_binding("KSI-MLA-OSM", good, bindings)[0] == "bound")
    check("the same adapter pair under a KSI the adapter does not target is unbound",
          ve.classify_source_binding("KSI-CNA-NET", good, bindings)[0] == "unbound")
    bad = _entry("crowdstrike", "made_up_check")
    o, m = ve.classify_source_binding("KSI-MLA-OSM", bad, bindings)
    check("an undeclared check under the adapter's own target is unbound, citing AUD-F62",
          o == "unbound" and "AUD-F62" in m and "declared checks" in m)
    # Preflight helper (production-assurance blocker input): lists the wrong one only.
    out = sdr.unbound_evidence_under_production(
        [("KSI-MLA-OSM", _populated([bad])), ("KSI-MLA-RVL", _populated([good]))], [],
        bindings, ve.classify_source_binding, ve.classify_pointer_binding)
    check("preflight helper lists the undeclared pair and not the bound twin",
          [(r, i, k) for r, i, k, _ in out] == [("KSI-MLA-OSM", 0, "source")])
    # The validator reports it as a finding in every profile; production turns
    # it into a blocker. classify_entry (integrity) stays verified: the digest
    # recomputes, so the hash tripwire is silent and only this gate speaks.
    o_int, _ = ve.classify_entry(bad, hash_fn=ve._evidence_hash)
    check("the undeclared-check entry is cryptographically verified (tripwire silent)",
          o_int == "verified")


def test_ac3_falcon_to_evidence_refuses_an_undeclared_check():
    falcon = ew.get_adapter("crowdstrike-falcon")
    original = falcon.collect

    def tampered(raw):
        for f in original(raw):
            yield dict(f, check="made_up_check")

    falcon.collect = tampered
    try:
        falcon.to_evidence({"observed_at": "2026-10-01T00:00:00Z", "detections_open": 1}, _BASE)
        check("an adapter yielding an undeclared check is refused", False)
    except ew.EvidenceExportError as e:
        check("an adapter yielding an undeclared check is refused naming it",
              "made_up_check" in str(e) and "MCE-03" in str(e))
    finally:
        falcon.collect = original
    evs = falcon.to_evidence({"observed_at": "2026-10-01T00:00:00Z", "detections_open": 1}, _BASE)
    check("Falcon's own output is bound under each of its targets",
          len(evs) == 1 and all(ve.classify_source_binding(k, evs[0], ve.load_source_bindings())[0] == "bound"
                                for k in FALCON_TARGETS))


def test_mapping_adapter_declares_checks_and_narrows_with_check_bindings():
    adapter = ma.build_adapter(_mapping())
    check("mapping adapter's declared checks are in slug form",
          set(adapter.checks) == {"PUBLIC_BUCKET_ACL", "OPEN_FIREWALL", "MFA_NOT_ENFORCED",
                                  ma.slug_for("policies/custom rule #7 (draft)")})
    sb = adapter.source_bindings()
    check("check_bindings narrows MFA_NOT_ENFORCED to one KSI, the rest use ksi_targets",
          sb["example-posture:MFA_NOT_ENFORCED"] == {"KSI-MLA-OSM"}
          and sb["example-posture:PUBLIC_BUCKET_ACL"] == {"KSI-MLA-EVC", "KSI-MLA-OSM"})
    bindings = ve.load_source_bindings({}, {"rules": []}, [adapter])
    check("the gate binds the narrowed pair only where declared",
          "example-posture:MFA_NOT_ENFORCED" in bindings["KSI-MLA-OSM"]["keys"]
          and "example-posture:MFA_NOT_ENFORCED" not in bindings["KSI-MLA-EVC"]["keys"])
    mfa = _entry("example-posture", "MFA_NOT_ENFORCED")
    check("the narrowed check is unbound on the KSI it was narrowed away from",
          ve.classify_source_binding("KSI-MLA-EVC", mfa, bindings)[0] == "unbound"
          and ve.classify_source_binding("KSI-MLA-OSM", mfa, bindings)[0] == "bound")
    # `checks` is required; a binding for an undeclared check, or an unknown KSI
    # id inside check_bindings, is refused naming it.
    m = _mapping()
    del m["checks"]
    try:
        ma.MappingAdapter(m)
        check("a mapping without checks is refused", False)
    except ma.MappingError as e:
        check("a mapping without checks is refused naming the field", "checks" in str(e))
    try:
        ma.build_adapter(_mapping(check_bindings={"NOT_DECLARED": ["KSI-MLA-OSM"]}))
        check("check_bindings for an undeclared check is refused", False)
    except ma.MappingError as e:
        check("check_bindings for an undeclared check is refused naming it", "NOT_DECLARED" in str(e))
    try:
        ma.build_adapter(_mapping(check_bindings={"OPEN_FIREWALL": ["KSI-ZZZ-NOP"]}))
        check("unknown KSI id in check_bindings is refused", False)
    except ma.MappingError as e:
        check("unknown KSI id in check_bindings is refused naming it", "KSI-ZZZ-NOP" in str(e))
    # An export record whose check is not declared: refused, nothing converted.
    with open(JSONL, encoding="utf-8") as f:
        text = f.read()
    extra = text + ('\n{"finding": {"type": "NEW_VENDOR_STATE", "state": "ACTIVE", '
                    '"event_time": "2026-10-01T06:00:00Z", "title": "t"}, '
                    '"resource": {"project": "p", "location": "l"}}\n')
    try:
        adapter.to_evidence(extra, _BASE, scope_key=_KEY)
        check("an undeclared check in the export is refused", False)
    except ew.EvidenceExportError as e:
        check("an undeclared check in the export is refused naming it",
              "NEW_VENDOR_STATE" in str(e) and "declared vocabulary" in str(e))
    evs = adapter.to_evidence(text, _BASE, scope_key=_KEY)
    check("the declared export converts and every entry is bound under a declared KSI",
          len(evs) == 4 and all(
              any(ve.classify_source_binding(k, ev, bindings)[0] == "bound" for k in ("KSI-MLA-EVC", "KSI-MLA-OSM"))
              for ev in evs))


def test_register_from_profile_registers_enabled_mapping_sources_for_the_gate():
    before = set(ew.list_adapters())
    rel = os.path.relpath(MAPPING, BASE).replace("\\", "/")
    prof = {"evidence_sources": {
        "example-posture-scanner": {"enabled": True, "mapping_path": rel, "export_path": "x"},
        "disabled-one": {"enabled": False, "mapping_path": rel},
        "crowdstrike-falcon": {"enabled": True, "export_path": "y"}}}
    out = ma.register_from_profile(prof, BASE)
    check("only the enabled mapping-driven source is registered",
          set(out) == {"example-posture-scanner"} and "example-posture-scanner" in ew.list_adapters())
    bindings = ve.load_source_bindings()
    check("the gate now binds the profile-declared adapter's pairs",
          "example-posture:PUBLIC_BUCKET_ACL" in bindings["KSI-MLA-EVC"]["keys"])
    check("re-registering the same mapping is idempotent",
          ma.register_from_profile(prof, BASE)["example-posture-scanner"] is out["example-posture-scanner"])
    try:
        ma.register_from_profile({"evidence_sources": {"other-name": {"enabled": True, "mapping_path": rel}}},
                                 BASE)
        check("key/name mismatch is refused", False)
    except ma.MappingError as e:
        check("key/name mismatch is refused naming both",
              "other-name" in str(e) and "example-posture-scanner" in str(e))
    try:
        ma.register_from_profile({"evidence_sources": {"ghost": {"enabled": True, "mapping_path": "no/such.json"}}},
                                 BASE)
        check("missing mapping file is refused", False)
    except ma.MappingError as e:
        check("missing mapping file is refused naming the source", "ghost" in str(e))
    check("the repository's own profile enables no mapping source (baseline unchanged)",
          ma.register_from_profile(ve.load(ve.OFFERING_PROFILE, {}) or {}, BASE) == {})
    check("nothing else was registered", set(ew.list_adapters()) - before == {"example-posture-scanner"})


def main():
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
    if failures:
        print(f"\nFAIL: adapter source bindings ({len(failures)} failure(s))")
        return 1
    print("\nPASS: adapter source bindings (0 failures)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
