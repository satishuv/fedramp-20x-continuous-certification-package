#!/usr/bin/env python3
"""MCE-02: declarative export adapter, offline, mapping-driven.

What this proves:
  AC1  from a mapping file and a customer export (JSON lines or CSV) the
       adapter yields facts that meet fact-contract.schema.json, with no
       network access: every socket constructor is made to raise for the
       duration of the collection and conversion;
  AC2  a mapping naming a KSI id that is not in the pinned KSI profile refuses
       to register, naming the id; nothing is registered;
  AC3  a source status with no entry in the normalization table becomes
       UNKNOWN, never PASS; a mapped value normalizes; the source's raw state
       is kept in detail;
  AC4  an empty export yields no facts and the adapter reports a collection
       outcome of not-run, so emptiness is never read as clean posture;
  AC5  describe() carries name, version, source_type, supported_evidence_types
       and freshness_policy_days from the mapping (contract v2).
Also: an invalid mapping is refused naming the field; a record with no
observation time is refused by the contract (never invented); the raw scope
identifier rides under its declared kind and is refused without a scope key;
a non-slug check id becomes a deterministic, collision-free slug; the CSV and
JSON lines exports of the same records yield identical facts; the facts match
the committed golden fixture byte for byte; nothing is written to disk.

Run:
    python automation/collectors/test_mapping_adapter.py
"""

import json
import os
import socket
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import evidence_wiring as ew  # noqa: E402
import mapping_adapter as ma  # noqa: E402

FIX = os.path.join(HERE, "fixtures", "mapping")
MAPPING = os.path.join(FIX, "example-posture-scanner.mapping.json")
JSONL = os.path.join(FIX, "example-posture-scanner.export.jsonl")
CSV = os.path.join(FIX, "example-posture-scanner.export.csv")
GOLDEN = os.path.join(FIX, "example-posture-scanner.expected-facts.json")
_KEY = b"test-scope-key-not-a-secret"
_BASE = "https://evidence.example.gov/store"


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _mapping(**over):
    m = json.loads(_read(MAPPING))
    m.update(over)
    return m


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class _NoNetwork:
    """Any attempt to construct a socket raises. Entered around the code under
    test so an adapter that reached for the network would fail the test."""

    def __enter__(self):
        self._real = socket.socket

        def boom(*a, **k):
            raise AssertionError("network access attempted by an offline adapter")

        socket.socket = boom
        return self

    def __exit__(self, *exc):
        socket.socket = self._real
        return False


def _snapshot_tree():
    out = {}
    for root, _dirs, files in os.walk(os.path.join(HERE, "fixtures")):
        for fn in files:
            p = os.path.join(root, fn)
            out[p] = os.path.getmtime(p)
    return out


# --- AC1 ----------------------------------------------------------------------

def test_ac1_no_network_trap_is_armed():
    # The offline proof is only as good as the trap: a socket constructed inside
    # the guard must raise, and the real constructor must come back after.
    real = socket.socket
    with _NoNetwork():
        raised = False
        try:
            socket.socket()
        except AssertionError as e:
            raised = "network access attempted" in str(e)
        assert raised, "the no-network trap did not fire"
    assert socket.socket is real


def test_ac1_mapping_schema_is_valid_and_fixture_mapping_conforms():
    import jsonschema
    jsonschema.Draft202012Validator.check_schema(ma.mapping_schema())
    assert ma.validate_mapping(_mapping()) == []


def test_ac1_jsonl_export_yields_contract_facts_offline():
    before = _snapshot_tree()
    with _NoNetwork():
        adapter = ma.build_adapter(_mapping())
        facts = list(adapter.collect(_read(JSONL)))
        evs = adapter.to_evidence(_read(JSONL), _BASE, scope_key=_KEY)
    assert len(facts) == 4 and len(evs) == 4
    for f in facts:
        assert ew.validate_fact(f) == [], f
        assert f["service"] == "example-posture"
    for ev in evs:
        assert ev["evidenceType"] == "Report"
        assert ev["xEvidenceContentHash"].startswith("sha256:")
        assert ew.evidence_hash(ew.canonical_payload(ev)) == ev["xEvidenceContentHash"]
        assert ev["lastUpdated"] == "2026-10-01"
    assert _snapshot_tree() == before, "the adapter must not write anything"


def test_ac1_csv_export_yields_the_same_facts_as_jsonl():
    csv_mapping = _mapping(export_format="csv", fields={
        "check": "finding_type", "status": "finding_state", "observed_at": "event_time",
        "location": "location", "detail": "title",
        "scope": {"path": "project", "kind": "project"}})
    with _NoNetwork():
        a = ma.build_adapter(_mapping())
        b = ma.build_adapter(csv_mapping)
        fa = list(a.collect(_read(JSONL)))
        fb = list(b.collect(_read(CSV)))
    assert _canon(fa) == _canon(fb)


def test_ac1_json_array_and_records_path_are_read():
    records = [json.loads(line) for line in _read(JSONL).splitlines() if line.strip()]
    arr = ma.build_adapter(_mapping(export_format="json"))
    obj = ma.build_adapter(_mapping(export_format="json", records_path="export.findings"))
    fa = list(arr.collect(json.dumps(records)))
    fb = list(obj.collect(json.dumps({"export": {"findings": records}})))
    assert _canon(fa) == _canon(fb) and len(fa) == 4
    # An object export with no records_path is refused, named.
    try:
        list(ma.build_adapter(_mapping(export_format="json")).collect(json.dumps({"x": records})))
        raise AssertionError("object export without records_path must be refused")
    except ma.MappingError as e:
        assert "records_path" in str(e)


def test_golden_facts_match_byte_for_byte():
    with open(GOLDEN, encoding="utf-8") as f:
        golden = json.load(f)
    facts = list(ma.build_adapter(_mapping()).collect(_read(JSONL)))
    assert _canon(facts) == _canon(golden["facts"]), "facts drifted from the golden fixture"


# --- AC2 ----------------------------------------------------------------------

def test_ac2_unknown_ksi_target_refuses_registration_naming_it():
    before = set(ew.list_adapters())
    try:
        ma.register_mapping_adapter(_mapping(name="probe-unknown-ksi",
                                             ksi_targets=["KSI-MLA-EVC", "KSI-ZZZ-NOP"]))
        raise AssertionError("must refuse")
    except ma.MappingError as e:
        assert "KSI-ZZZ-NOP" in str(e) and "KSI-MLA-EVC" not in str(e).split("profile:")[1]
    assert set(ew.list_adapters()) == before, "nothing may be registered on refusal"
    # Verified against the pinned profile itself, not a shape rule.
    ids = ma.load_ksi_ids()
    assert "KSI-MLA-EVC" in ids and len(ids) == 46
    # A valid mapping registers and is retrievable by name.
    inst = ma.register_mapping_adapter(_mapping(name="probe-valid"))
    assert ew.get_adapter("probe-valid") is inst
    assert inst.ksi_targets() == ["KSI-MLA-EVC", "KSI-MLA-OSM"]


def test_invalid_mapping_is_refused_naming_the_field():
    cases = [
        ("fields", {"check": "a", "status": "b"}),            # observed_at missing
        ("status_normalization", {"ACTIVE": "GOOD"}),           # not PASS/FAIL/UNKNOWN
        ("ksi_targets", []),                                    # none
        ("export_format", "xml"),
        ("name", "bad/name"),
        ("schema", "something-else/v9"),
    ]
    for field, value in cases:
        try:
            ma.MappingAdapter(_mapping(**{field: value}))
            raise AssertionError(field)
        except ma.MappingError as e:
            assert field in str(e), (field, str(e))
    try:
        ma.MappingAdapter(_mapping(unexpected_key=1))
        raise AssertionError("additional properties must be refused")
    except ma.MappingError as e:
        assert "unexpected_key" in str(e)


# --- AC3 ----------------------------------------------------------------------

def test_ac3_unmapped_status_is_unknown_never_pass():
    table = _mapping()["status_normalization"]
    assert ma.normalize_status("ACTIVE", table) == "FAIL"
    assert ma.normalize_status("inactive", table) == "PASS"      # case-insensitive fallback
    assert ma.normalize_status("needs_review", table) == "UNKNOWN"
    assert ma.normalize_status("", table) == "UNKNOWN"
    assert ma.normalize_status(None, table) == "UNKNOWN"
    assert ma.normalize_status("PASS", table) == "UNKNOWN", "a source saying PASS is still unmapped"
    assert ma.UNMAPPED_STATUS == "UNKNOWN"
    facts = list(ma.build_adapter(_mapping()).collect(_read(JSONL)))
    by_check = {f["check"]: f for f in facts}
    assert by_check["PUBLIC_BUCKET_ACL"]["status"] == "FAIL"
    assert by_check["OPEN_FIREWALL"]["status"] == "PASS"
    assert by_check["MFA_NOT_ENFORCED"]["status"] == "UNKNOWN"
    assert "source state: needs_review" in by_check["MFA_NOT_ENFORCED"]["detail"]
    for f in facts:
        assert f["status"] in ma.NORMALIZED


# --- AC4 ----------------------------------------------------------------------

def test_ac4_empty_export_yields_nothing_and_reports_not_run():
    for export_format, text in (("jsonl", ""), ("jsonl", "\n\n"), ("csv", "a,b\n"), ("json", "[]")):
        adapter = ma.build_adapter(_mapping(export_format=export_format))
        assert adapter.collection_outcome() == "not-run"
        with _NoNetwork():
            facts = list(adapter.collect(text))
            evs = adapter.to_evidence(text, _BASE)
        assert facts == [] and evs == [], (export_format, facts)
        assert adapter.collection_outcome() == "not-run", export_format
        h = adapter.health()
        assert h["status"] == "not-run" and "no records" in h["last_error"], h
        assert h["facts_yielded"] == 0
    # A real collection flips the outcome; a later empty one flips it back.
    adapter = ma.build_adapter(_mapping())
    list(adapter.collect(_read(JSONL)))
    assert adapter.collection_outcome() == "collected"
    assert adapter.health()["facts_yielded"] == 4
    list(adapter.collect(""))
    assert adapter.collection_outcome() == "not-run"


# --- AC5 ----------------------------------------------------------------------

def test_ac5_describe_carries_contract_v2_metadata_from_the_mapping():
    d = ma.build_adapter(_mapping()).describe()
    for key in ("name", "version", "source_type", "supported_evidence_types", "freshness_policy_days"):
        assert key in d, key
    assert d["name"] == "example-posture-scanner" and d["version"] == "1.0.0"
    assert d["source_type"] == "posture-findings"
    assert d["supported_evidence_types"] == ["Report"] and d["freshness_policy_days"] == 1
    assert d["export_format"] == "jsonl" and d["ksi_targets"] == ["KSI-MLA-EVC", "KSI-MLA-OSM"]


# --- contract and scope interplay --------------------------------------------------

def test_record_without_observation_time_is_refused_not_invented():
    rec = {"finding": {"type": "X", "state": "ACTIVE", "title": "t"},
           "resource": {"project": "p", "location": "l"}}
    adapter = ma.build_adapter(_mapping())
    fact = adapter.fact_for(0, rec)
    assert fact["observed_at"] is None
    try:
        adapter.to_evidence([rec], _BASE, scope_key=_KEY)
        raise AssertionError("must be refused by the fact contract")
    except ew.FactContractError as e:
        assert "'observed_at'" in str(e)


def test_raw_scope_identifier_rides_under_its_kind_and_is_never_exported_raw():
    adapter = ma.build_adapter(_mapping())
    facts = list(adapter.collect(_read(JSONL)))
    assert all(f["project"].startswith("fictional-project-") for f in facts)
    try:
        adapter.to_evidence(_read(JSONL), _BASE)  # no scope key
        raise AssertionError("raw project identifier without a key must be refused")
    except ew.EvidenceExportError as e:
        assert "project" in str(e) and "scope" in str(e)
    evs = adapter.to_evidence(_read(JSONL), _BASE, scope_key=_KEY)
    blob = _canon(evs)
    assert "fictional-project" not in blob
    scopes = {ev["xSourceFact"]["scope"] for ev in evs}
    assert len(scopes) == 2 and all(s.startswith("scope-") for s in scopes)


def test_non_slug_check_and_location_become_deterministic_collision_free_slugs():
    assert ma.slug_for("PUBLIC_BUCKET_ACL") == "PUBLIC_BUCKET_ACL"
    a = ma.slug_for("policies/custom rule #7 (draft)")
    b = ma.slug_for("policies/custom rule #7 (final)")
    assert a != b and ew.validate_fact({"service": "s", "check": a, "status": "x", "detail": "",
                                        "region": "global", "observed_at": "2026-10-01"}) == []
    assert a == ma.slug_for("policies/custom rule #7 (draft)")  # deterministic
    assert ma.slug_for("a/b") != ma.slug_for("a-b")             # no collapse
    assert ma.slug_for("") is None and ma.slug_for(None) is None
    assert ma.slug_for("../etc") is not None and ".." not in ma.slug_for("../etc")
    facts = list(ma.build_adapter(_mapping()).collect(_read(JSONL)))
    odd = [f for f in facts if f["check"].startswith("policies-custom-rule-7")][0]
    assert odd["region"] == "global"  # empty location -> global, never invented


def test_record_without_check_value_is_refused_not_unknown():
    adapter = ma.build_adapter(_mapping())
    rec = {"finding": {"state": "ACTIVE", "event_time": "2026-10-01T00:00:00Z"}, "resource": {}}
    try:
        adapter.fact_for(3, rec)
        raise AssertionError("a record with no check id must be refused")
    except ew.EvidenceExportError as e:
        assert "record 3" in str(e) and "unknown" in str(e)


def test_service_evidence_type_registration_is_consistent():
    ma.register_mapping_adapter(_mapping(name="probe-type-a", service="probe-svc", evidence_type="Log"))
    try:
        ma.register_mapping_adapter(_mapping(name="probe-type-b", service="probe-svc",
                                             evidence_type="Configuration"))
        raise AssertionError("two adapters may not disagree about one service's evidenceType")
    except ew.EvidenceExportError as e:
        assert "probe-svc" in str(e)
    ev = ew.fact_to_evidence({"service": "probe-svc", "check": "c", "status": "PASS", "detail": "",
                              "region": "global", "observed_at": "2026-10-01"}, _BASE)
    assert ev["evidenceType"] == "Log"


def test_fixtures_are_fictional_and_name_no_vendor():
    import re
    text = _read(MAPPING) + _read(JSONL) + _read(CSV) + _read(GOLDEN)
    assert not re.search(r"(?<!\d)\d{12}(?!\d)", text)
    for forbidden in ("arn:aws", "AKIA", "amazonaws.com", "@"):
        assert forbidden not in text, forbidden
    assert "fictional" in _read(MAPPING).lower()


def test_apply_driver_end_to_end_with_a_mapping_source():
    """The offering profile declares the source with mapping_path + export_path;
    the driver registers the adapter from the mapping, attaches evidence to the
    mapped KSIs, reports an empty export as not-run, refuses a name mismatch,
    and refuses raw scope identifiers without a scope key. Runs in a temp copy
    of the three files; the repository's own profile and store are untouched."""
    import shutil
    import tempfile
    import apply_third_party_evidence as ap

    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(FIX, os.path.join(tmp, "fixtures"))
        records = {"ksi": {"KSI-MLA-EVC": {"evidence": []}, "KSI-MLA-OSM": {"evidence": []},
                           "KSI-SCR-MON": {"evidence": []}}}
        rec_path = os.path.join(tmp, "records-store.json")
        prof_path = os.path.join(tmp, "offering-profile.json")

        def write_profile(name="example-posture-scanner", export="fixtures/example-posture-scanner.export.jsonl"):
            with open(prof_path, "w", encoding="utf-8") as f:
                json.dump({"evidence_sources": {name: {
                    "enabled": True, "export_path": export,
                    "mapping_path": "fixtures/example-posture-scanner.mapping.json"}}}, f)

        with open(rec_path, "w", encoding="utf-8") as f:
            json.dump(records, f)
        saved = (ap.BASE, ap.PROFILE, ap.RECORDS, os.environ.get("SDR_EVIDENCE_SCOPE_KEY"))
        ap.BASE, ap.PROFILE, ap.RECORDS = tmp, prof_path, rec_path
        try:
            # 1. Raw project identifiers with no scope key: refused, store untouched.
            write_profile()
            os.environ.pop("SDR_EVIDENCE_SCOPE_KEY", None)
            with _NoNetwork():
                assert ap.main() == 1
            with open(rec_path, encoding="utf-8") as f:
                assert json.load(f) == records
            # 2. With a scope key: evidence attached to exactly the mapped KSIs.
            os.environ["SDR_EVIDENCE_SCOPE_KEY"] = "test-scope-key-not-a-secret"
            with _NoNetwork():
                assert ap.main() == 0
            with open(rec_path, encoding="utf-8") as f:
                after = json.load(f)
            # Attached by DECLARED binding (MCE-03): MFA_NOT_ENFORCED is narrowed
            # to KSI-MLA-OSM by check_bindings, the other three go to both.
            assert len(after["ksi"]["KSI-MLA-EVC"]["evidence"]) == 3
            assert len(after["ksi"]["KSI-MLA-OSM"]["evidence"]) == 4
            assert not any("MFA_NOT_ENFORCED" in e["evidenceText"]
                           for e in after["ksi"]["KSI-MLA-EVC"]["evidence"])
            assert after["ksi"]["KSI-SCR-MON"]["evidence"] == []
            blob = json.dumps(after)
            assert "fictional-project" not in blob and "scope-" in blob
            assert all(e["evidenceType"] == "Report" and e["xEvidenceContentHash"]
                       for e in after["ksi"]["KSI-MLA-EVC"]["evidence"])
            # 3. Empty export: not-run, nothing more attached, exit 0.
            empty = os.path.join(tmp, "fixtures", "empty.jsonl")
            with open(empty, "w", encoding="utf-8") as f:
                f.write("")
            write_profile(export="fixtures/empty.jsonl")
            with open(rec_path, "w", encoding="utf-8") as f:
                json.dump(records, f)
            with _NoNetwork():
                assert ap.main() == 0
            with open(rec_path, encoding="utf-8") as f:
                assert json.load(f) == records, "an empty export must attach nothing"
            # 4. Key does not match the mapping's name: refused.
            write_profile(name="some-other-name")
            with _NoNetwork():
                assert ap.main() == 1
        finally:
            ap.BASE, ap.PROFILE, ap.RECORDS = saved[0], saved[1], saved[2]
            if saved[3] is None:
                os.environ.pop("SDR_EVIDENCE_SCOPE_KEY", None)
            else:
                os.environ["SDR_EVIDENCE_SCOPE_KEY"] = saved[3]


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
