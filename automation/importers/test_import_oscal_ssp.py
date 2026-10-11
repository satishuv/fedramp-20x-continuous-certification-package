#!/usr/bin/env python3
"""Offline tests for the Rev5 OSCAL SSP importer.

Fixtures follow NIST OSCAL SSP v1.1.x field names (system-security-plan,
metadata.last-modified, system-implementation.components[].title,
control-implementation.implemented-requirements[].control-id, statements[].
statement-id, by-components[].description / implementation-status.state) and
FedRAMP's implementation-status prop. Run:
    python automation/importers/test_import_oscal_ssp.py
"""
import copy
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(BASE, "automation", "ai"))
import import_oscal_ssp as ssp  # noqa: E402
import draft_narratives as dn  # noqa: E402

DATASET = json.load(open(ssp.DATASET, encoding="utf-8"))
MAPPING = ssp.ksi_controls()
RECORD_STORE = json.load(open(os.path.join(BASE, "sdr", "records", "records-store.json"),
                              encoding="utf-8"))

COMP_IAM = "11111111-1111-4111-8111-111111111111"
COMP_SIEM = "22222222-2222-4222-8222-222222222222"
PARTY_SECRET = "Jane Q. Public, CISO, 555-0100, jane@acme.example"
SYSTEM_ID_SECRET = "F00000001"


def fixture(last_modified="2026-09-30T12:00:00Z", reqs=None):
    return {"system-security-plan": {
        "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "metadata": {"title": "Acme Cloud SSP", "last-modified": last_modified,
                     "version": "5.2", "oscal-version": "1.1.3",
                     "parties": [{"uuid": "p1", "type": "person", "name": PARTY_SECRET}]},
        "system-characteristics": {
            "system-ids": [{"identifier-type": "https://fedramp.gov", "id": SYSTEM_ID_SECRET}],
            "system-name": "Acme Cloud Platform",
            "description": "x", "security-sensitivity-level": "moderate",
            "system-information": {"information-types": []},
            "security-impact-level": {}, "status": {"state": "operational"},
            "authorization-boundary": {"description": "x"}},
        "system-implementation": {
            "users": [], "components": [
                {"uuid": COMP_IAM, "type": "service", "title": "Identity Service",
                 "description": "x", "status": {"state": "operational"}},
                {"uuid": COMP_SIEM, "type": "software", "title": "Central SIEM",
                 "description": "x", "status": {"state": "operational"}}]},
        "control-implementation": {
            "description": "x",
            "implemented-requirements": reqs if reqs is not None else default_reqs()},
    }}


def default_reqs():
    return [
        {"uuid": "r1", "control-id": "ac-2.2",
         "props": [{"name": "implementation-status", "ns": "https://fedramp.gov/ns/oscal",
                    "value": "implemented"}],
         "statements": [{"statement-id": "ac-2.2_smt", "uuid": "s1", "by-components": [
             {"component-uuid": COMP_IAM, "uuid": "b1",
              "description": "Temporary and emergency accounts are disabled automatically "
                             "after 24 hours by a scheduled Lambda that reads the account "
                             "tag expiry.",
              "implementation-status": {"state": "implemented"}}]}]},
        {"uuid": "r2", "control-id": "AC-02(03)",  # human form, must normalise to ac-2.3
         "statements": [{"statement-id": "ac-2.3_smt", "uuid": "s2", "by-components": [
             {"component-uuid": COMP_IAM, "uuid": "b2",
              "description": "Inactive accounts are disabled after 35 days of no sign-in.",
              "implementation-status": {"state": "partial",
                                        "remarks": "service accounts pending"}}]}]},
        {"uuid": "r3", "control-id": "au-6",  # requirement-level by-component, no statements
         "by-components": [{"component-uuid": COMP_SIEM, "uuid": "b3",
                            "description": "Audit records are reviewed weekly in the SIEM."}]},
        {"uuid": "r4", "control-id": "pe-3",  # a control no KSI lists
         "by-components": [{"component-uuid": COMP_SIEM, "uuid": "b4",
                            "description": "Physical access is the IaaS provider's."}]},
        {"uuid": "r5", "control-id": "ia-12",  # implemented but no text anywhere
         "statements": [{"statement-id": "ia-12_smt", "uuid": "s5", "by-components": [
             {"component-uuid": COMP_IAM, "uuid": "b5", "description": "   "}]}]},
        {"uuid": "r6", "control-id": "not a control"},
    ]


def write(tmp, doc, name="ssp.json"):
    p = os.path.join(tmp, name)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    return p


def test_dataset_controls_are_oscal_ids_and_cover_every_ksi():
    assert len(MAPPING) == 46
    for kid, controls in MAPPING.items():
        assert kid.startswith("KSI-"), kid
        for c in controls:
            assert ssp._CONTROL_ID.match(c), (kid, c)
    assert "ac-2.2" in MAPPING["KSI-IAM-AAM"]  # read from the dataset earlier


def test_normalize_control_id_accepts_human_forms():
    for raw, want in (("ac-2", "ac-2"), ("AC-2", "ac-2"), ("AC-02", "ac-2"), ("ac-2.2", "ac-2.2"),
                      ("AC-2(2)", "ac-2.2"), ("AC-02(02)", "ac-2.2"), (" ia-12 ", "ia-12")):
        assert ssp.normalize_control_id(raw) == want, raw
    for bad in ("", None, "not a control", "ac", "2-ac", "ac-2.2.1"):
        assert ssp.normalize_control_id(bad) is None, bad


def test_refuses_non_ssp_and_missing_requirements():
    with tempfile.TemporaryDirectory() as tmp:
        for doc in ({"catalog": {}}, {"system-security-plan": {"metadata": {}}}, [1]):
            p = write(tmp, doc)
            try:
                ssp.load_ssp(p)
                raised = False
            except ssp.RefusedInput:
                raised = True
            assert raised, doc


def test_texts_extracted_from_both_levels_with_component_titles():
    doc = fixture()
    texts, skipped = ssp.extract_control_texts(doc["system-security-plan"])
    assert skipped == ["not a control"]
    assert set(texts) == {"ac-2.2", "ac-2.3", "au-6", "pe-3", "ia-12"}
    assert texts["ac-2.2"]["status"] == "implemented"  # FedRAMP prop at requirement level
    t = texts["ac-2.2"]["texts"][0]
    assert t["component"] == "Identity Service" and t["where"] == "ac-2.2_smt"
    assert texts["ac-2.3"]["texts"][0]["status"] == "partial"  # OSCAL state at by-component
    assert texts["au-6"]["texts"][0]["where"] == "au-6"  # requirement-level by-component
    assert texts["ia-12"]["texts"] == []  # blank description skipped


def test_observations_follow_the_dataset_mapping_only():
    with tempfile.TemporaryDirectory() as tmp:
        store = ssp.build_store(write(tmp, fixture()))
    obs = store["ksi_observations"]
    # ac-2.2 and ac-2.3 both feed KSI-IAM-AAM in the dataset.
    aam = obs["KSI-IAM-AAM"]
    assert {o["control"] for o in aam} == {"ac-2.2", "ac-2.3"}
    assert all(o["source"] == ssp.SOURCE for o in aam)
    assert all(o["observed_at"] == "2026-09-30T12:00:00+00:00" for o in aam)
    first = [o for o in aam if o["control"] == "ac-2.2"][0]
    assert first["text"].startswith("ac-2.2 (ac-2.2_smt; Identity Service; Rev5 SSP declares: implemented): ")
    assert "disabled automatically after 24 hours" in first["text"]
    # Every KSI that received text lists at least one of the SSP's controls.
    for kid, items in obs.items():
        for o in items:
            assert o["control"] in MAPPING[kid], (kid, o["control"])
    # pe-3 is implemented but no KSI lists it: reported, not mapped.
    assert "pe-3" in store["meta"]["unmapped_controls"]
    assert not any(o["control"] == "pe-3" for items in obs.values() for o in items)
    cov = store["meta"]["ksi_coverage"]["KSI-IAM-AAM"]
    assert cov["dataset_controls"] == len(MAPPING["KSI-IAM-AAM"])
    assert cov["ssp_implemented"] == 3 and cov["ssp_with_text"] == 2  # ia-12 has no text
    assert "ia-4.4" in cov["missing_from_ssp"]
    assert store["meta"]["ssp"]["unparseable_control_ids"] == ["not a control"]


def test_nothing_identifying_leaves_the_ssp():
    with tempfile.TemporaryDirectory() as tmp:
        store = ssp.build_store(write(tmp, fixture()))
    blob = json.dumps(store)
    assert PARTY_SECRET not in blob and "jane@acme.example" not in blob
    assert SYSTEM_ID_SECRET not in blob
    assert COMP_IAM not in blob  # component uuids replaced by titles
    assert store["meta"]["ssp"]["system_name"] == "Acme Cloud Platform"  # kept, by design
    assert store["facts"] == [] and store["posture_facts"] == []
    assert store["meta"]["collection_outcome"]["status"] == "NARRATIVE_ONLY"


def test_status_is_text_only_never_a_record_status():
    with tempfile.TemporaryDirectory() as tmp:
        store = ssp.build_store(write(tmp, fixture()))
    rec = copy.deepcopy(RECORD_STORE["ksi"]["KSI-IAM-AAM"])
    rec["implementation"] = ["TBD: Information has not been provided."]
    rec["validation"] = ["TBD: Information has not been provided."]
    before_status = rec["implementation_status"]
    entry = {"services": [], "fill_guidance": {"what_it_looks_for": "Automated account lifecycle."}}
    changed, notes = dn.draft_ksi("KSI-IAM-AAM", rec, entry, {}, dn.TemplateDrafter(), {},
                                  store["ksi_observations"]["KSI-IAM-AAM"])
    assert changed and notes[0].endswith("(template + imported observations)")
    text = rec["implementation"][0]
    assert text.startswith(dn.DRAFT_LABEL)
    assert "[rev5-oscal-ssp, 2026-09-30] ac-2.2 (ac-2.2_smt; Identity Service; Rev5 SSP declares: implemented)" in text
    assert "not a 20x status" in text
    assert rec["implementation_status"] == before_status
    for field in dn.FORBIDDEN_FIELDS:
        assert rec.get(field) == RECORD_STORE["ksi"]["KSI-IAM-AAM"].get(field)


def test_long_texts_are_clipped_and_quoting_is_bounded():
    long = "word " * 400
    reqs = [{"uuid": f"r{i}", "control-id": "ac-2.2",
             "by-components": [{"component-uuid": COMP_IAM, "uuid": f"b{i}", "description": long}]}
            for i in range(9)]
    with tempfile.TemporaryDirectory() as tmp:
        store = ssp.build_store(write(tmp, fixture(reqs=reqs)))
    items = store["ksi_observations"]["KSI-IAM-AAM"]
    assert len(items) == 9
    assert all(len(o["text"]) <= ssp.MAX_TEXT + 120 for o in items)
    block = dn._ksi_observations_block(items)
    assert len(block) <= dn.MAX_KSI_OBSERVATION_CHARS + 400
    assert "more imported statement(s) not quoted" in block


def test_observed_time_from_metadata_or_flag():
    with tempfile.TemporaryDirectory() as tmp:
        doc = fixture(last_modified=None)
        del doc["system-security-plan"]["metadata"]["last-modified"]
        p = write(tmp, doc)
        assert ssp.build_store(p) is None
        store = ssp.build_store(p, observed_at="2026-10-01")
        assert store["meta"]["collected_at"] == "2026-10-01T00:00:00+00:00"
        assert store["meta"]["observed_at_source"] == "explicit"
        try:
            ssp.build_store(p, observed_at="last spring")
            raised = False
        except ssp.RefusedInput:
            raised = True
        assert raised


def _run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = ssp.main(argv)
    return code, buf.getvalue()


def test_cli_exit_codes_and_write():
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "facts")
        p = write(tmp, fixture())
        code, text = _run([p, "--out-dir", out])
        assert code == 0 and "dry run" in text and not os.path.exists(out)
        code, text = _run([p, "--out-dir", out, "--write"])
        assert code == 0
        saved = json.load(open(ssp.out_path(out), encoding="utf-8"))
        assert saved["meta"]["run_id"].startswith("import-ssp-")
        assert saved["meta"]["import_files"][0]["kind"] == "oscal-ssp"
        # Nothing mapped: only a control no KSI lists.
        p2 = write(tmp, fixture(reqs=[{"uuid": "r", "control-id": "pe-3", "by-components": [
            {"component-uuid": COMP_SIEM, "uuid": "b", "description": "x"}]}]), "ssp2.json")
        code, text = _run([p2, "--out-dir", out])
        assert code == ssp.EXIT_NOTHING_MAPPED
        code, text = _run([write(tmp, {"catalog": {}}, "c.json"), "--out-dir", out])
        assert code == 1 and "Import refused" in text


def test_drafter_loads_ksi_observations_from_facts_dir():
    with tempfile.TemporaryDirectory() as tmp:
        store = ssp.build_store(write(tmp, fixture()))
        facts = os.path.join(tmp, "facts")
        os.makedirs(facts)
        json.dump(store, open(ssp.out_path(facts), "w", encoding="utf-8"))
        saved = dn.FACTS_DIR
        dn.FACTS_DIR = facts
        try:
            got = dn.load_ksi_observations()
            assert dn.load_all_posture_facts() == {}
        finally:
            dn.FACTS_DIR = saved
    assert set(got) == set(store["ksi_observations"])


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
