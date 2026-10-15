"""MCE-05: Microsoft Azure Policy compliance-states adapter, offline, through the
mapping-driven adapter (export_format "json", records_path "value").

What this proves:
  AC1  the fixture export yields facts byte-identical to the committed golden
       fixture; a bare array of the same PolicyState records yields the
       identical facts; no socket is opened;
  AC2  every KSI id the mapping binds exists in the pinned KSI profile, and
       registration is refused naming the id when a profile no longer carries
       a targeted id;
  AC3  Exempt and Conflict are UNKNOWN with the state in detail, never PASS;
       every other published state (Error, Protected, Unknown, Not registered,
       Not started) is UNKNOWN by the unmapped rule; only Compliant is PASS and
       only NonCompliant is FAIL; the deprecated isCompliant flag is never read
       (a record whose flag contradicts its complianceState follows the state);
  AC4  the fixture header records the documentation URLs and capture dates,
       the mapping cites its documentation, and the fixture carries no real
       subscription, tenant or management group identifier (all-zero and
       all-one GUIDs and fictional- names only; the public-package scrubber
       flags a GUID in free text).
Composite record identity (built for this story): a policy state has no single
id field; one definition is evaluated against one resource once per assignment
and once per reference inside a policy set, so fields.record_id is the ordered
list [assignment, definition, reference id, resource]. Proven here: the two
states of one definition on one resource under two assignments keep distinct
pointers; an absent component is kept as an empty string so components keep
their positions and two different identities can never join to the same
string; a single-path record_id still behaves as before; dropping record_id
collapses the batch to a refused pointer collision (AUD-F77); the raw
composite (which carries the subscription id) never reaches an evidence
object.
Also: the undeclared definition is skipped, counted and named in health(); an
empty export reports not-run; a subscription-scoped state with a null location
lands in region "global"; the apply driver attaches each state's evidence to
exactly the KSIs its binding declares and writes no raw identifier into the
store.

Run:
    python automation/collectors/test_azure_policy_adapter.py
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
MAPPING = os.path.join(FIX, "example-azure-policy-states.mapping.json")
EXPORT = os.path.join(FIX, "example-azure-policy-states.export.json")
GOLDEN = os.path.join(FIX, "example-azure-policy-states.expected-facts.json")
_KEY = b"test-scope-key-not-a-secret"
_BASE = "https://evidence.example.gov/store"
SUB_ID = "00000000-0000-0000-0000-000000000000"
_ASSIGN_BASE = f"/subscriptions/{SUB_ID}/providers/Microsoft.Authorization/policyAssignments/"
ASSIGN_1 = _ASSIGN_BASE + "00000000-0000-0000-0000-000000000001"
ASSIGN_2 = _ASSIGN_BASE + "00000000-0000-0000-0000-000000000002"
STORAGE_DEF = "fictional-storage-public-network-access-denied"


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _mapping(**over):
    m = json.loads(_read(MAPPING))
    m.update(over)
    return m


def _records():
    return json.loads(_read(EXPORT))["value"]


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


def _state(definition, state, resource, assignment=ASSIGN_1, reference=None, location="eastus",
           timestamp="2026-10-01T06:00:00Z", is_compliant=None):
    """One fictional PolicyState record in the published shape."""
    return {
        "complianceState": state,
        "isCompliant": (state == "Compliant") if is_compliant is None else is_compliant,
        "policyAssignmentId": assignment,
        "policyDefinitionAction": "audit",
        "policyDefinitionId": f"/providers/Microsoft.Authorization/policyDefinitions/{definition}",
        "policyDefinitionName": definition,
        "policyDefinitionReferenceId": reference,
        "resourceId": f"/subscriptions/{SUB_ID}/resourceGroups/fictional-rg-01/providers/{resource}",
        "resourceLocation": location,
        "subscriptionId": SUB_ID,
        "timestamp": timestamp,
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
        assert f["service"] == "azure-policy"
        assert f["subscription"] == SUB_ID
        assert f["record_id"].count("|") == 3, f["record_id"]
    assert adapter.collection_outcome() == "collected"


def test_ac1_bare_array_export_yields_identical_facts():
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
    assert len(bound) >= 6
    for gone in ("KSI-CNA-RNT", "KSI-MLA-EVC"):
        refused = False
        try:
            ma.build_adapter(m, ksi_ids=known - {gone})
        except ma.MappingError as e:
            refused = gone in str(e) and "refusing to register" in str(e)
        assert refused, gone
    assert ew.get_adapter("example-azure-policy-states") is None


# --- AC3 ----------------------------------------------------------------------

def test_ac3_exempt_and_conflict_are_unknown_never_pass():
    adapter = ma.build_adapter(_mapping())
    facts = list(adapter.collect(_read(EXPORT)))
    by_state = {}
    for f in facts:
        state = f["detail"].split("source state: ", 1)[1].split(".", 1)[0]
        by_state.setdefault(state, []).append(f)
    assert {f["status"] for f in by_state["Exempt"]} == {"UNKNOWN"}
    assert {f["status"] for f in by_state["Conflict"]} == {"UNKNOWN"}
    assert {f["status"] for f in by_state["Error"]} == {"UNKNOWN"}
    assert {f["status"] for f in by_state["Compliant"]} == {"PASS"}
    assert {f["status"] for f in by_state["NonCompliant"]} == {"FAIL"}
    assert all("source state: " in f["detail"] for f in facts)


def test_ac3_every_other_published_state_is_unknown_and_the_flag_is_never_read():
    adapter = ma.build_adapter(_mapping(checks=[STORAGE_DEF], check_bindings={}))
    recs = [_state(STORAGE_DEF, s, f"Microsoft.Storage/storageAccounts/fictionalsa{i:04d}")
            for i, s in enumerate(["Error", "Protected", "Unknown", "Not registered", "Not started",
                                   "Conflict", "Exempt", "", "NONCOMPLIANT", "compliant"], start=1)]
    facts = list(adapter.collect(json.dumps(recs)))
    assert [f["status"] for f in facts] == ["UNKNOWN"] * 8 + ["FAIL", "PASS"]
    assert "source state: Not registered" in facts[3]["detail"]
    assert "source state: (none)" in facts[7]["detail"]
    # The deprecated isCompliant flag contradicts the state here; the state wins.
    lying = [_state(STORAGE_DEF, "NonCompliant", "Microsoft.Storage/storageAccounts/fictionalsa0100",
                    is_compliant=True),
             _state(STORAGE_DEF, "Exempt", "Microsoft.Storage/storageAccounts/fictionalsa0101",
                    is_compliant=True)]
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
    guids = set(re.findall(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", text))
    assert guids, "fixture must exercise GUID-shaped identifiers"
    for g in guids:
        # Every GUID is all zeros, all ones, or zeros / ones with a trailing
        # two-digit counter: never a real tenant, subscription or definition.
        assert re.fullmatch(r"(0{8}-0{4}-0{4}-0{4}-0{10}[0-9]{2})|(1{8}-1{4}-1{4}-1{4}-1{10}[0-9]{2})", g), g
    for rec in doc["value"]:
        assert rec["policyDefinitionName"].startswith("fictional-")
        assert rec["subscriptionId"] == SUB_ID
        assert "fictional" in rec["resourceId"] or rec["resourceId"] == f"/subscriptions/{SUB_ID}"
        assert "tenantId" not in rec and "managementGroupIds" not in rec
    # The public-package scrubber would catch a GUID and a subscription path in
    # free text (second line of defense, exercised here).
    assert "token" in ew.scrub_hits(SUB_ID)
    assert ew.scrub_hits(f"/subscriptions/{SUB_ID}/resourceGroups/x")


# --- composite record identity ----------------------------------------------------

def test_composite_two_assignments_of_one_definition_on_one_resource_keep_distinct_pointers():
    adapter = ma.build_adapter(_mapping())
    with _NoNetwork():
        evs = adapter.to_evidence(_read(EXPORT), _BASE, scope_key=_KEY)
    assert len(evs) == 9
    assert ew.pointer_collisions(evs) == {}
    storage = [e for e in evs if f"/{STORAGE_DEF}/" in e["evidenceLocation"]]
    assert len(storage) == 4
    assert len({e["evidenceLocation"] for e in storage}) == 4
    # Same definition, same opaque scope, same region for three of them: only
    # the record segment differs.
    east = [e for e in storage if "/eastus/" in e["evidenceLocation"]]
    assert len(east) == 3
    scopes = {e["xSourceFact"]["scope"] for e in east}
    assert len(scopes) == 1 and next(iter(scopes)).startswith("scope-")
    for e in east:
        assert re.search(r"/eastus/rec-[0-9a-f]{16}\.json$", e["evidenceLocation"])
    statuses = sorted(e["evidenceDescription"].split(" = ")[1].split(".")[0] for e in east)
    assert statuses == ["FAIL", "FAIL", "PASS"]


def test_composite_absent_component_keeps_its_position():
    inside = _state(STORAGE_DEF, "Compliant", "Microsoft.Storage/storageAccounts/fictionalsa0001",
                    reference="11111111-1111-1111-1111-111111111111")
    outside = _state(STORAGE_DEF, "NonCompliant", "Microsoft.Storage/storageAccounts/fictionalsa0001",
                     reference=None)
    spec = _mapping()["fields"]["record_id"]
    rid_in = ma.composite_record_id(inside, spec)
    rid_out = ma.composite_record_id(outside, spec)
    assert rid_in != rid_out
    assert rid_out.split("|")[2] == "" and rid_in.split("|")[2] == "11111111-1111-1111-1111-111111111111"
    assert rid_out.count("|") == 3, "an absent component is never dropped"
    # Positions matter: a record with a null reference and resource R must not
    # join to the same string as a record whose reference is R and whose
    # resource is absent. Dropping absent components would make them equal.
    spec2 = ["policyAssignmentId", "policyDefinitionReferenceId", "resourceId"]
    a = ma.composite_record_id({"policyAssignmentId": "A", "policyDefinitionReferenceId": None,
                                "resourceId": "R"}, spec2)
    b = ma.composite_record_id({"policyAssignmentId": "A", "policyDefinitionReferenceId": "R",
                                "resourceId": None}, spec2)
    assert a == "A||R" and b == "A|R|" and a != b
    adapter = ma.build_adapter(_mapping(checks=[STORAGE_DEF], check_bindings={}))
    evs = adapter.to_evidence(json.dumps([inside, outside]), _BASE, scope_key=_KEY)
    assert len(evs) == 2 and ew.pointer_collisions(evs) == {}
    # A record with every component absent has no identity at all.
    assert ma.composite_record_id({}, spec) is None
    # A single path behaves as before.
    assert ma.composite_record_id(inside, "policyAssignmentId") == ASSIGN_1
    assert ma.composite_record_id({"policyAssignmentId": ""}, "policyAssignmentId") is None


def test_composite_without_record_id_the_batch_is_refused_as_a_pointer_collision():
    fields = dict(_mapping()["fields"])
    del fields["record_id"]
    adapter = ma.build_adapter(_mapping(fields=fields))
    refused = False
    try:
        adapter.to_evidence(_read(EXPORT), _BASE, scope_key=_KEY)
    except ew.EvidenceExportError as e:
        msg = str(e)
        refused = ("share an evidence pointer" in msg and f"/{STORAGE_DEF}/" in msg
                   and "record_id" in msg and "AUD-F77" in msg)
    assert refused, "two states of one definition at one pointer must be refused"


def test_composite_raw_identity_never_reaches_evidence():
    adapter = ma.build_adapter(_mapping())
    evs = adapter.to_evidence(_read(EXPORT), _BASE, scope_key=_KEY)
    blob = _canon(evs)
    assert SUB_ID not in blob
    assert "/subscriptions/" not in blob and "policyAssignments" not in blob
    assert "fictional-rg" not in blob and "fictionalsa" not in blob
    assert "|" not in blob
    for e in evs:
        assert "record_id" not in e["xSourceFact"] and "subscription" not in e["xSourceFact"]
        assert re.fullmatch(r"rec-[0-9a-f]{16}", e["xSourceFact"]["record"])
        assert e["xEvidenceContentHash"] == ew.evidence_hash(ew.canonical_payload(e))
    # Without a scope key the raw composite (and the subscription) are refused.
    refused = False
    try:
        adapter.to_evidence(_read(EXPORT), _BASE)
    except ew.EvidenceExportError as e:
        refused = "subscription" in str(e) or "record_id" in str(e)
    assert refused


# --- skipping, emptiness, location -------------------------------------------------

def test_undeclared_definition_is_skipped_counted_and_named():
    adapter = ma.build_adapter(_mapping())
    facts = list(adapter.collect(_read(EXPORT)))
    assert all(f["check"] != "fictional-allowed-locations" for f in facts)
    h = adapter.health()
    assert h["records"] == 10 and h["facts_yielded"] == 9
    assert h["skipped_undeclared"] == 1 and h["undeclared_checks"] == ["fictional-allowed-locations"]
    strict = ma.build_adapter(_mapping(undeclared_checks="refuse"))
    refused = False
    try:
        strict.to_evidence(_read(EXPORT), _BASE, scope_key=_KEY)
    except ew.EvidenceExportError as e:
        refused = "fictional-allowed-locations" in str(e)
    assert refused


def test_empty_export_reports_not_run():
    adapter = ma.build_adapter(_mapping())
    assert list(adapter.collect("[]")) == []
    assert adapter.collection_outcome() == "not-run"
    assert list(adapter.collect(json.dumps({"value": []}))) == []
    assert adapter.collection_outcome() == "not-run"


def test_subscription_scoped_state_with_null_location_is_global():
    adapter = ma.build_adapter(_mapping())
    facts = list(adapter.collect(_read(EXPORT)))
    mfa = [f for f in facts if f["check"] == "fictional-mfa-required-for-owner-role"]
    assert len(mfa) == 1 and mfa[0]["region"] == "global"
    assert mfa[0]["status"] == "UNKNOWN" and "source state: Conflict" in mfa[0]["detail"]


def test_apply_driver_end_to_end_with_the_azure_policy_source():
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
            json.dump({"evidence_sources": {"example-azure-policy-states": {
                "enabled": True, "export_path": "fixtures/example-azure-policy-states.export.json",
                "mapping_path": "fixtures/example-azure-policy-states.mapping.json"}}}, f)
        with open(rec_path, "w", encoding="utf-8") as f:
            json.dump(records, f)
        saved = (ap.BASE, ap.PROFILE, ap.RECORDS, os.environ.get("SDR_EVIDENCE_SCOPE_KEY"))
        ap.BASE, ap.PROFILE, ap.RECORDS = tmp, prof_path, rec_path
        try:
            os.environ.pop("SDR_EVIDENCE_SCOPE_KEY", None)
            with _NoNetwork(), redirect_stdout(io.StringIO()) as out:
                assert ap.main() == 1
            with open(rec_path, encoding="utf-8") as f:
                assert json.load(f) == records, "refused: store must be untouched"
            os.environ["SDR_EVIDENCE_SCOPE_KEY"] = "test-scope-key-not-a-secret"
            with _NoNetwork(), redirect_stdout(io.StringIO()) as out:
                assert ap.main() == 0
            printed = out.getvalue()
            assert "fictional-allowed-locations" in printed and "undeclared_checks: skip" in printed
            with open(rec_path, encoding="utf-8") as f:
                after = json.load(f)
            n = {k: len(after["ksi"][k]["evidence"]) for k in kids}
            # storage x4 -> MAT + EVC; nsg -> RNT; mfa -> APM; logs -> LET;
            # key rotation -> ASM; managed identity -> SNU; OSM none.
            assert n == {"KSI-MLA-EVC": 4, "KSI-CNA-MAT": 4, "KSI-CNA-RNT": 1, "KSI-IAM-APM": 1,
                         "KSI-MLA-LET": 1, "KSI-SVC-ASM": 1, "KSI-IAM-SNU": 1, "KSI-MLA-OSM": 0}, n
            blob = json.dumps(after)
            assert SUB_ID not in blob and "/subscriptions/" not in blob
            assert "fictional-rg" not in blob and "policyAssignments" not in blob
            assert "scope-" in blob and "rec-" in blob
            assert "fictional-allowed-locations" not in blob
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
