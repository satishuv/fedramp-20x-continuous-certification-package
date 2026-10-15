"""MCE-04: Google Cloud Security Command Center findings adapter, offline,
through the mapping-driven adapter (export_format "json", one mapping file).

What this proves:
  AC1  the fixture export yields facts byte-identical to the committed golden
       fixture; a bare array of the same ListFindingsResult elements (what the
       command-line listing prints) yields the identical facts; no socket is
       opened;
  AC2  every KSI id the mapping binds exists in the pinned KSI profile, and
       registration is refused naming the id when a profile no longer carries
       a targeted id;
  AC3  an INACTIVE finding never yields a FAIL (it is UNKNOWN, with the state
       in detail); an ACTIVE finding is FAIL whether or not it is muted; a
       state outside the published enum is UNKNOWN, never PASS;
  AC4  the fixture header records the documentation URLs and capture dates,
       the mapping cites its documentation, and the fixture carries no real
       organization, project or account identifier (all-zero numbers and
       fictional- names only; the public-package scrubber flags the raw ids).
AUD-F77 (found building this story): a findings export has one record PER
RESOURCE, so two findings of one category in one project and region resolved
to ONE evidence pointer and the record store kept only the later observation:
a resolved finding replaced a still-active one. Proven here: without
fields.record_id the batch is refused naming the shared pointer; with it, the
two findings keep distinct pointers, the raw finding name (which carries the
organization id) never reaches an evidence object, and the same finding keeps
the same opaque record id across exports so a later observation of it still
replaces the earlier one. The AWS pointer form is unchanged (no record
segment when no record_id is present).
Also: the undeclared category is skipped, counted and named in health(); an
empty export reports not-run; a 9-digit fractional eventTime classifies as a
dated observation in the freshness classifier; the apply driver attaches each
finding's evidence to exactly the KSIs its binding declares and writes no raw
identifier into the store.

Run:
    python automation/collectors/test_scc_adapter.py
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
MAPPING = os.path.join(FIX, "example-google-cloud-scc.mapping.json")
EXPORT = os.path.join(FIX, "example-google-cloud-scc.export.json")
GOLDEN = os.path.join(FIX, "example-google-cloud-scc.expected-facts.json")
_KEY = b"test-scope-key-not-a-secret"
_BASE = "https://evidence.example.gov/store"
ORG_ID = "000000000000"
PROJECT_IDS = ("fictional-project-0001", "fictional-project-0002")


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _mapping(**over):
    m = json.loads(_read(MAPPING))
    m.update(over)
    return m


def _records():
    return json.loads(_read(EXPORT))["findings"]


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


def _finding(num, category, state, event_time, project=PROJECT_IDS[0], location="us-central1",
             mute="UNDEFINED"):
    """One fictional ListFindingsResult element in the published shape."""
    fid = f"{num:032d}"
    return {
        "finding": {
            "name": f"organizations/{ORG_ID}/sources/0000000000000000000/findings/{fid}",
            "parent": f"organizations/{ORG_ID}/sources/0000000000000000000",
            "resourceName": f"//storage.googleapis.com/projects/_/buckets/fictional-bucket-{num:04d}",
            "state": state, "category": category, "severity": "HIGH",
            "findingClass": "MISCONFIGURATION", "mute": mute, "eventTime": event_time,
            "canonicalName": f"projects/{ORG_ID}/sources/0000000000000000000/findings/{fid}",
            "description": "Fictional description.",
        },
        "resource": {
            "name": f"//storage.googleapis.com/projects/_/buckets/fictional-bucket-{num:04d}",
            "projectName": f"//cloudresourcemanager.googleapis.com/projects/{ORG_ID}",
            "projectDisplayName": project, "location": location,
        },
        "stateChange": "UNUSED",
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
    assert len(facts) == 9
    for f in facts:
        assert ew.validate_fact(f) == [], f
        assert f["service"] == "google-cloud-scc"
        assert f["record_id"].startswith(f"organizations/{ORG_ID}/sources/")
        assert f["project"] in PROJECT_IDS
    assert adapter.collection_outcome() == "collected"


def test_ac1_bare_array_export_yields_identical_facts():
    """The envelope is this repository's fixture header; the command-line
    listing prints the bare array, and the mapping reads both the same."""
    adapter = ma.build_adapter(_mapping())
    enveloped = list(adapter.collect(_read(EXPORT)))
    bare = list(adapter.collect(json.dumps(_records())))
    assert _canon(enveloped) == _canon(bare)
    assert len(bare) == 9


# --- AC2 ----------------------------------------------------------------------

def test_ac2_every_bound_ksi_exists_and_a_changed_profile_refuses_registration():
    m = _mapping()
    known = ma.load_ksi_ids()
    bound = set(m["ksi_targets"])
    for ids in m["check_bindings"].values():
        bound |= set(ids)
    assert bound <= known, sorted(bound - known)
    assert len(bound) >= 8
    # A profile that no longer carries one targeted id refuses registration,
    # naming the id, and registers nothing.
    for gone in ("KSI-CNA-RNT", "KSI-MLA-EVC"):
        refused = False
        try:
            ma.build_adapter(m, ksi_ids=known - {gone})
        except ma.MappingError as e:
            refused = gone in str(e) and "refusing to register" in str(e)
        assert refused, gone
    assert ew.get_adapter("example-google-cloud-scc") is None


# --- AC3 ----------------------------------------------------------------------

def test_ac3_inactive_is_never_fail_active_is_fail_even_when_muted():
    adapter = ma.build_adapter(_mapping())
    facts = list(adapter.collect(_read(EXPORT)))
    by_record = {f["record_id"][-2:]: f for f in facts}
    for suffix in ("02", "05", "09"):
        f = by_record[suffix]
        assert f["status"] != "FAIL", f
        assert f["status"] == "UNKNOWN"
        assert "source state: INACTIVE" in f["detail"]
    # 03 is ACTIVE and MUTED: the state decides, the mute does not launder it.
    assert by_record["03"]["status"] == "FAIL"
    assert "source state: ACTIVE" in by_record["03"]["detail"]
    assert all(f["status"] in ("FAIL", "UNKNOWN") for f in facts)
    assert not any(f["status"] == "PASS" for f in facts), "a findings export states no pass"


def test_ac3_states_outside_the_published_enum_are_unknown_never_pass():
    adapter = ma.build_adapter(_mapping(checks=["PUBLIC_BUCKET_ACL"], check_bindings={}))
    recs = [_finding(1, "PUBLIC_BUCKET_ACL", "STATE_UNSPECIFIED", "2026-10-01T06:00:00Z"),
            _finding(2, "PUBLIC_BUCKET_ACL", "RESOLVED", "2026-10-01T06:00:00Z"),
            _finding(3, "PUBLIC_BUCKET_ACL", "", "2026-10-01T06:00:00Z"),
            _finding(4, "PUBLIC_BUCKET_ACL", "active", "2026-10-01T06:00:00Z")]
    facts = list(adapter.collect(json.dumps(recs)))
    assert [f["status"] for f in facts] == ["UNKNOWN", "UNKNOWN", "UNKNOWN", "FAIL"]
    assert "source state: RESOLVED" in facts[1]["detail"]
    assert "source state: (none)" in facts[2]["detail"]


# --- AC4 ----------------------------------------------------------------------

def test_ac4_fixture_header_cites_documentation_and_carries_no_real_identifiers():
    doc = json.loads(_read(EXPORT))
    head = doc["_fixture"]
    assert len(head["documentation"]) >= 2
    for d in head["documentation"]:
        assert d["url"].startswith("https://"), d
        assert re.match(r"^\d{4}-\d{2}-\d{2}$", d["captured"]), d
    m = _mapping()
    assert m["documentation"]["url"].startswith("https://")
    assert re.match(r"^\d{4}-\d{2}-\d{2}$", m["documentation"]["captured"])
    # Every organization / project / source number is all zeros (or the
    # all-zeros-plus-one second project); every id is fictional- or a counter.
    for num in re.findall(r"/(?:organizations|projects)/(\d+)", _read(EXPORT)):
        assert set(num[:-1]) == {"0"}, num
    for rec in doc["findings"]:
        assert rec["resource"]["projectDisplayName"].startswith("fictional-")
        assert re.fullmatch(r"0+[0-9]{2}", rec["finding"]["name"].rsplit("/", 1)[1])
    # The public-package scrubber would catch the raw identifiers if they ever
    # reached free text (second line of defense, exercised here).
    assert "account" in ew.scrub_hits(f"projects/{ORG_ID}")
    assert "host" in ew.scrub_hits("//storage.googleapis.com/projects/_/buckets/x")


# --- AUD-F77: one record per resource ------------------------------------------------

def test_f77_two_findings_of_one_category_keep_distinct_pointers():
    adapter = ma.build_adapter(_mapping())
    with _NoNetwork():
        evs = adapter.to_evidence(_read(EXPORT), _BASE, scope_key=_KEY)
    assert len(evs) == 9
    assert ew.pointer_collisions(evs) == {}
    buckets = [e for e in evs if "/PUBLIC_BUCKET_ACL/" in e["evidenceLocation"]]
    assert len(buckets) == 2
    assert buckets[0]["evidenceLocation"] != buckets[1]["evidenceLocation"]
    # Same category, same opaque scope, same region: only the record differs.
    for e in buckets:
        sf = e["xSourceFact"]
        assert sf["scope"].startswith("scope-") and sf["record"].startswith("rec-")
        assert e["evidenceLocation"].endswith(f"/us-central1/{sf['record']}.json")
    assert buckets[0]["xSourceFact"]["scope"] == buckets[1]["xSourceFact"]["scope"]
    assert "= FAIL" in buckets[0]["evidenceDescription"]
    assert "= UNKNOWN" in buckets[1]["evidenceDescription"]


def test_f77_without_record_id_the_batch_is_refused_naming_the_pointer():
    fields = dict(_mapping()["fields"])
    del fields["record_id"]
    adapter = ma.build_adapter(_mapping(fields=fields))
    refused = False
    try:
        adapter.to_evidence(_read(EXPORT), _BASE, scope_key=_KEY)
    except ew.EvidenceExportError as e:
        msg = str(e)
        refused = ("share an evidence pointer" in msg and "/PUBLIC_BUCKET_ACL/" in msg
                   and "record_id" in msg and "AUD-F77" in msg)
    assert refused, "a batch with two facts at one pointer must be refused"


def test_f77_raw_finding_name_never_reaches_evidence_and_record_is_keyed():
    adapter = ma.build_adapter(_mapping())
    evs = adapter.to_evidence(_read(EXPORT), _BASE, scope_key=_KEY)
    blob = _canon(evs)
    assert "organizations/" not in blob and "/findings/" not in blob
    assert ORG_ID not in blob
    for p in PROJECT_IDS:
        assert p not in blob
    for e in evs:
        assert "record_id" not in e["xSourceFact"]
        assert re.fullmatch(r"rec-[0-9a-f]{16}", e["xSourceFact"]["record"])
        assert e["xEvidenceContentHash"] == ew.evidence_hash(ew.canonical_payload(e))
    # Without a scope key the raw record id is refused, not dropped or exported.
    recs = [_finding(1, "PUBLIC_BUCKET_ACL", "ACTIVE", "2026-10-01T06:00:00Z", project="")]
    adapter2 = ma.build_adapter(_mapping(checks=["PUBLIC_BUCKET_ACL"], check_bindings={}))
    facts = list(adapter2.collect(json.dumps(recs)))
    assert "project" not in facts[0] and facts[0]["record_id"]
    refused = False
    try:
        adapter2.to_evidence(json.dumps(recs), _BASE)
    except ew.EvidenceExportError as e:
        refused = "record_id" in str(e) and "scope_key" in str(e)
    assert refused
    # Keyed: two keys give two ids; the same key and name give the same id.
    name = recs[0]["finding"]["name"]
    assert ew.record_ref(name, _KEY) == ew.record_ref(name, _KEY)
    assert ew.record_ref(name, _KEY) != ew.record_ref(name, b"another-key")
    assert ew.record_ref(name, _KEY) != ew.record_ref(name + "1", _KEY)
    # A caller-stamped record must already be opaque.
    bad = dict(facts[0])
    bad.pop("record_id")
    bad["record"] = "finding-0001"
    refused = False
    try:
        ew.fact_to_evidence(bad, _BASE, scope_key=_KEY)
    except ew.EvidenceExportError as e:
        refused = "opaque rec-" in str(e)
    assert refused


def test_f77_same_finding_across_exports_replaces_itself_only():
    """Export 1: finding A ACTIVE and finding B ACTIVE. Export 2: A INACTIVE
    (resolved), B still ACTIVE. After both upserts the store holds TWO
    entries, B still FAIL, instead of one entry saying INACTIVE."""
    import apply_third_party_evidence as ap
    adapter = ma.build_adapter(_mapping(checks=["PUBLIC_BUCKET_ACL"], check_bindings={}))
    first = [_finding(1, "PUBLIC_BUCKET_ACL", "ACTIVE", "2026-10-01T06:00:00Z"),
             _finding(2, "PUBLIC_BUCKET_ACL", "ACTIVE", "2026-10-01T06:00:00Z")]
    second = [_finding(1, "PUBLIC_BUCKET_ACL", "INACTIVE", "2026-10-03T09:00:00Z"),
              _finding(2, "PUBLIC_BUCKET_ACL", "ACTIVE", "2026-10-01T06:00:00Z")]
    store, n1 = ap._upsert_evidence([], adapter.to_evidence(json.dumps(first), _BASE, scope_key=_KEY))
    store, n2 = ap._upsert_evidence(store, adapter.to_evidence(json.dumps(second), _BASE, scope_key=_KEY))
    assert (n1, n2) == (2, 1)
    assert len(store) == 2
    by_record = {e["xSourceFact"]["record"]: e for e in store}
    rec_a = ew.record_ref(first[0]["finding"]["name"], _KEY)
    rec_b = ew.record_ref(first[1]["finding"]["name"], _KEY)
    assert "= UNKNOWN" in by_record[rec_a]["evidenceDescription"]
    assert "= FAIL" in by_record[rec_b]["evidenceDescription"]


def test_f77_aws_pointer_form_is_unchanged_without_a_record():
    fact = {"service": "config", "check": "rule-x", "status": "COMPLIANT", "detail": "",
            "region": "us-east-1", "observed_at": "2026-10-01T00:00:00Z",
            "account": "111122223333"}
    ev = ew.fact_to_evidence(fact, _BASE, scope_key=_KEY)
    scope = ew.scope_id("111122223333", _KEY)
    assert ev["evidenceLocation"] == f"{_BASE}/config/rule-x/{scope}/us-east-1.json"
    assert "record" not in ev["xSourceFact"]
    plain = ew.fact_to_evidence({k: v for k, v in fact.items() if k != "account"}, _BASE)
    assert plain["evidenceLocation"] == f"{_BASE}/config/rule-x/us-east-1.json"


# --- skipping, emptiness, freshness ------------------------------------------------------

def test_undeclared_category_is_skipped_counted_and_named():
    adapter = ma.build_adapter(_mapping())
    facts = list(adapter.collect(_read(EXPORT)))
    assert all(f["check"] != "DEFAULT_NETWORK" for f in facts)
    h = adapter.health()
    assert h["records"] == 10 and h["facts_yielded"] == 9
    assert h["skipped_undeclared"] == 1 and h["undeclared_checks"] == ["DEFAULT_NETWORK"]
    strict = ma.build_adapter(_mapping(undeclared_checks="refuse"))
    refused = False
    try:
        strict.to_evidence(_read(EXPORT), _BASE, scope_key=_KEY)
    except ew.EvidenceExportError as e:
        refused = "DEFAULT_NETWORK" in str(e)
    assert refused


def test_empty_export_reports_not_run():
    adapter = ma.build_adapter(_mapping())
    assert list(adapter.collect("[]")) == []
    assert adapter.collection_outcome() == "not-run"
    assert list(adapter.collect(json.dumps({"findings": []}))) == []
    assert adapter.collection_outcome() == "not-run"


def test_fractional_event_times_classify_as_dated_observations():
    """The freshness classifier reads the full timestamp (not only its date)
    for every fractional form the protobuf JSON mapping produces."""
    import datetime as dt
    sys.path.insert(0, os.path.join(HERE, "..", ".."))
    import sdr
    now = dt.datetime(2026, 10, 1, 12, 0, tzinfo=dt.timezone.utc)
    for ts in ("2026-10-01T06:05:00.123456789Z", "2026-10-01T06:00:01.000000Z",
               "2026-10-01T06:00:00.250Z", "2026-10-01T06:00:00Z"):
        assert sdr.classify_evidence_freshness(ts, now, policy_days=1) == "current", ts
    # 9 fractional digits, observed 30 hours earlier than `now`: expired under a
    # 1-day policy only if the TIME is read; the date-only fallback would say
    # 'stale' (the calendar day is one day back).
    assert sdr.classify_evidence_freshness("2026-09-30T05:00:00.123456789Z", now,
                                           policy_days=1) == "stale"
    assert sdr.classify_evidence_freshness("2026-09-29T05:00:00.123456789Z", now,
                                           policy_days=1) == "expired"
    parsed = dt.datetime.fromisoformat("2026-10-01T06:05:00.123456789Z".replace("Z", "+00:00"))
    assert parsed.microsecond == 123456 and parsed.tzinfo is not None


def test_apply_driver_end_to_end_with_the_scc_source():
    """The offering profile enables the source with mapping_path and
    export_path; the driver refuses the raw project and finding ids without a
    key, then attaches each finding's evidence to exactly the KSIs its binding
    declares, skips the undeclared category, and writes no organization,
    project or finding identifier into the store."""
    import io
    import shutil
    import tempfile
    from contextlib import redirect_stdout
    import apply_third_party_evidence as ap

    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(FIX, os.path.join(tmp, "fixtures"))
        kids = ["KSI-MLA-EVC", "KSI-CNA-MAT", "KSI-CNA-RNT", "KSI-IAM-APM", "KSI-IAM-AAM",
                "KSI-IAM-SNU", "KSI-MLA-LET", "KSI-SVC-ASM", "KSI-MLA-OSM"]
        records = {"ksi": {k: {"evidence": []} for k in kids}}
        rec_path = os.path.join(tmp, "records-store.json")
        prof_path = os.path.join(tmp, "offering-profile.json")
        with open(prof_path, "w", encoding="utf-8") as f:
            json.dump({"evidence_sources": {"example-google-cloud-scc": {
                "enabled": True, "export_path": "fixtures/example-google-cloud-scc.export.json",
                "mapping_path": "fixtures/example-google-cloud-scc.mapping.json"}}}, f)
        with open(rec_path, "w", encoding="utf-8") as f:
            json.dump(records, f)
        saved = (ap.BASE, ap.PROFILE, ap.RECORDS, os.environ.get("SDR_EVIDENCE_SCOPE_KEY"))
        ap.BASE, ap.PROFILE, ap.RECORDS = tmp, prof_path, rec_path
        try:
            os.environ.pop("SDR_EVIDENCE_SCOPE_KEY", None)
            with _NoNetwork(), redirect_stdout(io.StringIO()) as out:
                assert ap.main() == 1
            assert "scope_key" in out.getvalue()
            with open(rec_path, encoding="utf-8") as f:
                assert json.load(f) == records, "refused: store must be untouched"
            os.environ["SDR_EVIDENCE_SCOPE_KEY"] = "test-scope-key-not-a-secret"
            with _NoNetwork(), redirect_stdout(io.StringIO()) as out:
                assert ap.main() == 0
            printed = out.getvalue()
            assert "DEFAULT_NETWORK" in printed and "undeclared_checks: skip" in printed
            with open(rec_path, encoding="utf-8") as f:
                after = json.load(f)
            n = {k: len(after["ksi"][k]["evidence"]) for k in kids}
            # bucket x2 -> MAT + EVC; firewall -> RNT; MFA -> APM; audit + flow
            # logs -> LET; KMS -> ASM; API key -> SNU; OS Login -> AAM; OSM none.
            assert n == {"KSI-MLA-EVC": 2, "KSI-CNA-MAT": 2, "KSI-CNA-RNT": 1, "KSI-IAM-APM": 1,
                         "KSI-IAM-AAM": 1, "KSI-IAM-SNU": 1, "KSI-MLA-LET": 2, "KSI-SVC-ASM": 1,
                         "KSI-MLA-OSM": 0}, n
            blob = json.dumps(after)
            assert "organizations/" not in blob and "/findings/" not in blob
            assert ORG_ID not in blob and "fictional-project" not in blob
            assert "scope-" in blob and "rec-" in blob
            assert "DEFAULT_NETWORK" not in blob
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
