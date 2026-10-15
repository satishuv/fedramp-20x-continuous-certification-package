"""MCE-06: Oracle Cloud Infrastructure Cloud Guard problems adapter, offline,
through the mapping-driven adapter (export_format "json", records_path "items").

What this proves:
  AC1  the fixture export yields facts byte-identical to the committed golden
       fixture; a bare array of the same ProblemSummary records yields the
       identical facts; no socket is opened;
  AC2  every KSI id the mapping binds exists in the pinned KSI profile, and
       registration is refused naming the id when a profile no longer carries
       a targeted id;
  AC3  a DISMISSED or RESOLVED problem never yields a failing fact (it is
       UNKNOWN with the substate in detail); DELETED is UNKNOWN too; only OPEN
       is FAIL; nothing is ever PASS, because a problems export states no pass;
       a substate outside the published enum is UNKNOWN; the coarse
       lifecycleState is never read (a record whose state contradicts its
       substate follows the substate);
  AC4  the fixture header records the documentation URLs and capture dates,
       the mapping cites its documentation, and the fixture carries no real
       compartment or tenancy identifier (every OCID is of the fictional form,
       every name is fictional-; the public-package scrubber flags an OCID in
       free text).
Also (AUD-F77 applied): two problems of one detector rule in one compartment
and region keep distinct pointers through the problem id; without record_id the
batch is refused as a pointer collision; the raw problem id and compartment
OCID never reach an evidence object; the undeclared activity-detector rule is
skipped, counted and named in health(); an empty export reports not-run; a
problem with no region (an identity resource) lands in region "global"; the
apply driver attaches each problem's evidence to exactly the KSIs its binding
declares and writes no raw identifier into the store.

Run:
    python automation/collectors/test_oci_cloud_guard_adapter.py
"""

import json
import os
import re
import socket
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import evidence_wiring as ew  # noqa: E402
import mapping_adapter as ma  # noqa: E402

FIX = os.path.join(HERE, "fixtures", "mapping")
MAPPING = os.path.join(FIX, "example-oci-cloud-guard.mapping.json")
EXPORT = os.path.join(FIX, "example-oci-cloud-guard.export.json")
GOLDEN = os.path.join(FIX, "example-oci-cloud-guard.expected-facts.json")
_KEY = b"test-scope-key-not-a-secret"
_BASE = "https://evidence.example.gov/store"
CMP_1 = "ocid1.compartment.oc1..fictional0001"
BUCKET_RULE = "FICTIONAL_BUCKET_IS_PUBLIC"


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _mapping(**over):
    m = json.loads(_read(MAPPING))
    m.update(over)
    return m


def _records():
    return json.loads(_read(EXPORT))["items"]


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class _NoNetwork:
    def __enter__(self):
        self._real = socket.socket

        def boom(*a, **k):
            raise AssertionError("network access attempted by an offline adapter")

        socket.socket = boom
        return self

    def __exit__(self, *exc):
        socket.socket = self._real
        return False


def _problem(num, rule, detail, state=None, compartment=CMP_1, regions=("us-ashburn-1",),
             last="2026-10-01T06:00:00.000Z"):
    """One fictional ProblemSummary record in the published shape."""
    if state is None:
        state = "ACTIVE" if detail == "OPEN" else "INACTIVE"
    return {
        "id": f"ocid1.cloudguardproblem.oc1..fictional{num:04d}",
        "compartmentId": compartment,
        "detectorId": "IAAS_CONFIGURATION_DETECTOR",
        "detectorRuleId": rule,
        "riskLevel": "HIGH",
        "riskScore": 70,
        "resourceId": f"ocid1.bucket.oc1..fictional{num:04d}",
        "resourceName": f"fictional-bucket-{num:04d}",
        "resourceType": "Bucket",
        "regions": list(regions),
        "lifecycleState": state,
        "lifecycleDetail": detail,
        "timeFirstDetected": "2026-09-20T06:00:00.000Z",
        "timeLastDetected": last,
    }


# --- AC1 ----------------------------------------------------------------------

def test_ac1_no_network_trap_is_armed():
    real = socket.socket
    with _NoNetwork():
        raised = False
        try:
            socket.socket()
        except AssertionError as e:
            raised = "network access attempted" in str(e)
        assert raised
    assert socket.socket is real


def test_ac1_mapping_conforms_and_facts_match_the_golden_fixture():
    import jsonschema
    jsonschema.Draft202012Validator.check_schema(ma.mapping_schema())
    assert ma.validate_mapping(_mapping()) == []
    with _NoNetwork():
        adapter = ma.build_adapter(_mapping())
        facts = list(adapter.collect(_read(EXPORT)))
    golden = json.loads(_read(GOLDEN))
    assert _canon(facts) == _canon(golden["facts"])
    assert len(facts) == 8
    for f in facts:
        assert ew.validate_fact(f) == [], f
        assert f["service"] == "oci-cloud-guard"
        assert f["compartment"].startswith("ocid1.compartment.oc1..fictional")
        assert f["record_id"].startswith("ocid1.cloudguardproblem.oc1..fictional")
    assert adapter.collection_outcome() == "collected"


def test_ac1_bare_array_export_yields_identical_facts():
    adapter = ma.build_adapter(_mapping())
    enveloped = list(adapter.collect(_read(EXPORT)))
    bare = list(adapter.collect(json.dumps(_records())))
    assert _canon(enveloped) == _canon(bare)
    assert len(bare) == 8


# --- AC2 ----------------------------------------------------------------------

def test_ac2_every_bound_ksi_exists_and_a_changed_profile_refuses_registration():
    m = _mapping()
    known = ma.load_ksi_ids()
    bound = set(m["ksi_targets"])
    for ids in m["check_bindings"].values():
        bound |= set(ids)
    assert bound <= known, sorted(bound - known)
    assert len(bound) >= 6
    for gone in ("KSI-CNA-RNT", "KSI-MLA-EVC"):
        refused = False
        try:
            ma.build_adapter(m, ksi_ids=known - {gone})
        except ma.MappingError as e:
            refused = gone in str(e) and "refusing to register" in str(e)
        assert refused, gone
    assert ew.get_adapter("example-oci-cloud-guard") is None


# --- AC3 ----------------------------------------------------------------------

def test_ac3_dismissed_and_resolved_never_yield_a_failing_fact():
    adapter = ma.build_adapter(_mapping())
    facts = list(adapter.collect(_read(EXPORT)))
    by_detail = {}
    for f in facts:
        detail = f["detail"].split("source state: ", 1)[1].split(".", 1)[0]
        by_detail.setdefault(detail, []).append(f)
    assert {f["status"] for f in by_detail["RESOLVED"]} == {"UNKNOWN"}
    assert {f["status"] for f in by_detail["DISMISSED"]} == {"UNKNOWN"}
    assert {f["status"] for f in by_detail["DELETED"]} == {"UNKNOWN"}
    assert {f["status"] for f in by_detail["OPEN"]} == {"FAIL"}
    assert not any(f["status"] == "PASS" for f in facts), "a problems export states no pass"
    assert all(f["status"] in ("FAIL", "UNKNOWN") for f in facts)


def test_ac3_substates_outside_the_enum_are_unknown_and_the_coarse_state_is_never_read():
    adapter = ma.build_adapter(_mapping(checks=[BUCKET_RULE], check_bindings={}))
    recs = [_problem(1, BUCKET_RULE, "UNKNOWN_VALUE"),
            _problem(2, BUCKET_RULE, ""),
            _problem(3, BUCKET_RULE, "open"),
            _problem(4, BUCKET_RULE, "Resolved")]
    facts = list(adapter.collect(json.dumps(recs)))
    assert [f["status"] for f in facts] == ["UNKNOWN", "UNKNOWN", "FAIL", "UNKNOWN"]
    assert "source state: UNKNOWN_VALUE" in facts[0]["detail"]
    assert "source state: (none)" in facts[1]["detail"]
    # The coarse lifecycleState contradicts the substate here; the substate wins.
    lying = [_problem(5, BUCKET_RULE, "OPEN", state="INACTIVE"),
             _problem(6, BUCKET_RULE, "RESOLVED", state="ACTIVE")]
    out = list(adapter.collect(json.dumps(lying)))
    assert [f["status"] for f in out] == ["FAIL", "UNKNOWN"]


# --- AC4 ----------------------------------------------------------------------

def test_ac4_fixture_header_cites_documentation_and_carries_no_real_identifiers():
    doc = json.loads(_read(EXPORT))
    head = doc["_fixture"]
    assert len(head["documentation"]) >= 3
    for d in head["documentation"]:
        assert d["url"].startswith("https://"), d
        assert re.match(r"^\d{4}-\d{2}-\d{2}$", d["captured"]), d
    m = _mapping()
    assert m["documentation"]["url"].startswith("https://")
    assert re.match(r"^\d{4}-\d{2}-\d{2}$", m["documentation"]["captured"])
    text = _read(EXPORT)
    ocids = re.findall(r"ocid1\.[a-z]+\.[a-z0-9-]+\.[a-z0-9-]*\.[A-Za-z0-9]+", text)
    assert ocids, "fixture must exercise OCID-shaped identifiers"
    for o in ocids:
        assert re.fullmatch(r"ocid1\.[a-z]+\.oc1\.\.fictional\d{4}", o), o
    for rec in doc["items"]:
        assert rec["detectorRuleId"].startswith("FICTIONAL_")
        assert rec["resourceName"].startswith("fictional-")
        assert rec["compartmentId"].startswith("ocid1.compartment.oc1..fictional")
        assert "tenantId" not in rec and "targetId" not in rec
    # The public-package scrubber would catch an OCID in free text (second
    # line of defense, exercised here).
    assert ew.scrub_hits(CMP_1)
    assert ew.scrub_hits("ocid1.tenancy.oc1..fictional0001")


# --- AUD-F77 applied ----------------------------------------------------------------

def test_two_problems_of_one_rule_keep_distinct_pointers_and_raw_ids_never_leave():
    adapter = ma.build_adapter(_mapping())
    with _NoNetwork():
        evs = adapter.to_evidence(_read(EXPORT), _BASE, scope_key=_KEY)
    assert len(evs) == 8
    assert ew.pointer_collisions(evs) == {}
    buckets = [e for e in evs if f"/{BUCKET_RULE}/" in e["evidenceLocation"]]
    assert len(buckets) == 3 and len({e["evidenceLocation"] for e in buckets}) == 3
    ashburn = [e for e in buckets if "/us-ashburn-1/" in e["evidenceLocation"]]
    assert len(ashburn) == 2
    assert ashburn[0]["xSourceFact"]["scope"] == ashburn[1]["xSourceFact"]["scope"]
    assert ashburn[0]["xSourceFact"]["record"] != ashburn[1]["xSourceFact"]["record"]
    blob = _canon(evs)
    assert "ocid1." not in blob and "fictional" not in blob
    for e in evs:
        assert "record_id" not in e["xSourceFact"] and "compartment" not in e["xSourceFact"]
        assert re.fullmatch(r"rec-[0-9a-f]{16}", e["xSourceFact"]["record"])
        assert e["xEvidenceContentHash"] == ew.evidence_hash(ew.canonical_payload(e))
    # Without record_id the two Ashburn bucket problems share a pointer: refused.
    fields = dict(_mapping()["fields"])
    del fields["record_id"]
    refused = False
    try:
        ma.build_adapter(_mapping(fields=fields)).to_evidence(_read(EXPORT), _BASE, scope_key=_KEY)
    except ew.EvidenceExportError as e:
        refused = "share an evidence pointer" in str(e) and f"/{BUCKET_RULE}/" in str(e) and "AUD-F77" in str(e)
    assert refused
    # Without a scope key the raw compartment and problem id are refused.
    refused = False
    try:
        adapter.to_evidence(_read(EXPORT), _BASE)
    except ew.EvidenceExportError as e:
        refused = "compartment" in str(e) or "record_id" in str(e)
    assert refused


# --- skipping, emptiness, location -------------------------------------------------

def test_undeclared_rule_is_skipped_counted_and_named():
    adapter = ma.build_adapter(_mapping())
    facts = list(adapter.collect(_read(EXPORT)))
    assert all(f["check"] != "FICTIONAL_SUSPICIOUS_LOGIN" for f in facts)
    h = adapter.health()
    assert h["records"] == 9 and h["facts_yielded"] == 8
    assert h["skipped_undeclared"] == 1 and h["undeclared_checks"] == ["FICTIONAL_SUSPICIOUS_LOGIN"]
    strict = ma.build_adapter(_mapping(undeclared_checks="refuse"))
    refused = False
    try:
        strict.to_evidence(_read(EXPORT), _BASE, scope_key=_KEY)
    except ew.EvidenceExportError as e:
        refused = "FICTIONAL_SUSPICIOUS_LOGIN" in str(e)
    assert refused


def test_empty_export_reports_not_run():
    adapter = ma.build_adapter(_mapping())
    assert list(adapter.collect("[]")) == []
    assert adapter.collection_outcome() == "not-run"
    assert list(adapter.collect(json.dumps({"items": []}))) == []
    assert adapter.collection_outcome() == "not-run"


def test_problem_with_no_region_is_global():
    adapter = ma.build_adapter(_mapping())
    facts = list(adapter.collect(_read(EXPORT)))
    mfa = [f for f in facts if f["check"] == "FICTIONAL_MFA_NOT_ENABLED"]
    assert len(mfa) == 1 and mfa[0]["region"] == "global" and mfa[0]["status"] == "FAIL"


def test_apply_driver_end_to_end_with_the_cloud_guard_source():
    import io
    import shutil
    import tempfile
    from contextlib import redirect_stdout
    import apply_third_party_evidence as ap

    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(FIX, os.path.join(tmp, "fixtures"))
        kids = ["KSI-MLA-EVC", "KSI-CNA-MAT", "KSI-CNA-RNT", "KSI-IAM-APM", "KSI-MLA-LET",
                "KSI-SVC-ASM", "KSI-IAM-SNU", "KSI-MLA-OSM"]
        records = {"ksi": {k: {"evidence": []} for k in kids}}
        rec_path = os.path.join(tmp, "records-store.json")
        prof_path = os.path.join(tmp, "offering-profile.json")
        with open(prof_path, "w", encoding="utf-8") as f:
            json.dump({"evidence_sources": {"example-oci-cloud-guard": {
                "enabled": True, "export_path": "fixtures/example-oci-cloud-guard.export.json",
                "mapping_path": "fixtures/example-oci-cloud-guard.mapping.json"}}}, f)
        with open(rec_path, "w", encoding="utf-8") as f:
            json.dump(records, f)
        saved = (ap.BASE, ap.PROFILE, ap.RECORDS, os.environ.get("SDR_EVIDENCE_SCOPE_KEY"))
        ap.BASE, ap.PROFILE, ap.RECORDS = tmp, prof_path, rec_path
        try:
            os.environ.pop("SDR_EVIDENCE_SCOPE_KEY", None)
            with _NoNetwork(), redirect_stdout(io.StringIO()):
                assert ap.main() == 1
            with open(rec_path, encoding="utf-8") as f:
                assert json.load(f) == records, "refused: store must be untouched"
            os.environ["SDR_EVIDENCE_SCOPE_KEY"] = "test-scope-key-not-a-secret"
            with _NoNetwork(), redirect_stdout(io.StringIO()) as out:
                assert ap.main() == 0
            printed = out.getvalue()
            assert "FICTIONAL_SUSPICIOUS_LOGIN" in printed and "undeclared_checks: skip" in printed
            with open(rec_path, encoding="utf-8") as f:
                after = json.load(f)
            n = {k: len(after["ksi"][k]["evidence"]) for k in kids}
            # bucket x3 -> MAT + EVC; security list -> RNT; mfa -> APM; audit
            # retention -> LET; key -> ASM; api key -> SNU; OSM none.
            assert n == {"KSI-MLA-EVC": 3, "KSI-CNA-MAT": 3, "KSI-CNA-RNT": 1, "KSI-IAM-APM": 1,
                         "KSI-MLA-LET": 1, "KSI-SVC-ASM": 1, "KSI-IAM-SNU": 1, "KSI-MLA-OSM": 0}, n
            blob = json.dumps(after)
            assert "ocid1." not in blob and "fictional" not in blob
            assert "scope-" in blob and "rec-" in blob
            assert "FICTIONAL_SUSPICIOUS_LOGIN" not in blob
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
