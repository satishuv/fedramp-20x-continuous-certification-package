"""MCE-07: on-prem XCCDF results adapter, offline, through the mapping-driven
adapter (export_format "xccdf").

What this proves:
  AC1  an XCCDF results document yields one fact per rule-result whose rule the
       mapping declares, with the rule id as the check and the result mapped
       through the standard's normalization (pass, fail, error, unknown,
       notapplicable, notchecked, notselected, informational, fixed); the same
       TestResult wrapped in an ARF result data stream, and the same document
       in the XCCDF 1.1 namespace, yield identical facts; no socket is opened;
  AC2  notchecked, error, unknown, notapplicable, notselected, informational
       and fixed all become UNKNOWN, never PASS; a mapping whose table relabels
       any standard value is refused naming the key; a value outside the
       standard's vocabulary becomes UNKNOWN;
  AC3  the scan target rides on the fact only as a raw `host` scope: it never
       appears in detail, conversion without a scope key is refused naming
       `host`, and with a scope key no evidence object, pointer or source fact
       carries the host name or the target address; two hosts never share a
       scope and a host never shares a scope with an account of equal literal;
  AC4  the facts match the committed golden fixture byte for byte, and the
       fixture header records the documentation URL and capture date.
Also: an undeclared rule-result yields no fact and is counted and named in
health(); a results document with no rule-results reports not-run; a DOCTYPE
is refused; a non-XCCDF document is refused naming its root; a rule-result
without @time inherits the TestResult @end-time (never an invented time);
the fixture's host and address are refused by the public-package scrubber.

Run:
    python automation/collectors/test_xccdf_adapter.py
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
import xccdf_reader as xr  # noqa: E402

FIX = os.path.join(HERE, "fixtures", "mapping")
MAPPING = os.path.join(FIX, "example-openscap-xccdf.mapping.json")
RESULTS = os.path.join(FIX, "example-openscap-xccdf.results.xml")
GOLDEN = os.path.join(FIX, "example-openscap-xccdf.expected-facts.json")
_KEY = b"test-scope-key-not-a-secret"
_BASE = "https://evidence.example.gov/store"
TARGET = "lab-host-01.example"
ADDRESS = "203.0.113.10"
XCCDF_12 = "http://checklists.nist.gov/xccdf/1.2"
XCCDF_11 = "http://checklists.nist.gov/xccdf/1.1"
ARF_NS = "http://scap.nist.gov/schema/asset-reporting-format/1.1"


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
    def __enter__(self):
        self._real = socket.socket

        def boom(*a, **k):
            raise AssertionError("network access attempted by an offline adapter")

        socket.socket = boom
        return self

    def __exit__(self, *exc):
        socket.socket = self._real
        return False


def _results_with(result_values, time_attr=True, target=TARGET):
    """A minimal XCCDF 1.2 results document: one TestResult, one rule-result
    per (rule_id, result) pair. Fictional ids only."""
    rows = []
    for i, (rule, value) in enumerate(result_values):
        t = f' time="2026-10-02T03:00:{i:02d}+00:00"' if time_attr else ""
        rows.append(f'<rule-result idref="{rule}" severity="medium" weight="1.0"{t}>'
                    f'<result>{value}</result></rule-result>')
    tgt = f"<target>{target}</target>" if target else ""
    return (f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<TestResult xmlns="{XCCDF_12}" id="xccdf_com.example_testresult_t1" '
            f'end-time="2026-10-02T03:05:00+00:00">'
            f'<benchmark id="xccdf_com.example_benchmark_b1"/>'
            f'<profile idref="xccdf_com.example_profile_p1"/>{tgt}'
            + "".join(rows) + "</TestResult>")


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


def test_ac1_schema_accepts_xccdf_format_and_fixture_mapping_conforms():
    import jsonschema
    jsonschema.Draft202012Validator.check_schema(ma.mapping_schema())
    assert "xccdf" in ma.mapping_schema()["properties"]["export_format"]["enum"]
    assert ma.validate_mapping(_mapping()) == []


def test_ac1_one_fact_per_declared_rule_result_offline():
    with _NoNetwork():
        adapter = ma.build_adapter(_mapping())
        facts = list(adapter.collect(_read(RESULTS)))
    # 8 rule-results in the fixture; 7 declared.
    assert len(facts) == 7, [f["check"] for f in facts]
    for f in facts:
        assert ew.validate_fact(f) == [], f
        assert f["service"] == "openscap"
        assert f["check"].startswith("xccdf_com.example_rule_"), f["check"]
        assert f["status"] in ("PASS", "FAIL", "UNKNOWN")
    by_check = {f["check"]: f for f in facts}
    assert by_check["xccdf_com.example_rule_audit_logging_enabled"]["status"] == "PASS"
    assert by_check["xccdf_com.example_rule_password_min_length"]["status"] == "FAIL"
    # The rule-result without @time inherits the TestResult end-time.
    assert by_check["xccdf_com.example_rule_kernel_module_denylist"]["observed_at"] == \
        "2026-10-01T02:04:30+00:00"
    # Every other fact carries its own rule-result time.
    assert by_check["xccdf_com.example_rule_audit_logging_enabled"]["observed_at"] == \
        "2026-10-01T02:01:10+00:00"
    assert adapter.collection_outcome() == "collected"


def test_ac1_arf_wrapped_and_xccdf_11_documents_yield_identical_facts():
    text12 = _read(RESULTS)
    text11 = text12.replace(XCCDF_12, XCCDF_11)
    assert XCCDF_11 in text11 and XCCDF_12 not in text11
    # Strip the XML declaration before wrapping (it may only appear first).
    body = re.sub(r"^\s*<\?xml[^>]*\?>", "", text12, count=1)
    body = re.sub(r"<!--.*?-->", "", body, count=1, flags=re.S)
    arf = (f'<?xml version="1.0" encoding="UTF-8"?>'
           f'<arf:asset-report-collection xmlns:arf="{ARF_NS}">'
           f'<arf:reports><arf:report id="xccdf1"><arf:content>{body}</arf:content>'
           f'</arf:report></arf:reports></arf:asset-report-collection>')
    with _NoNetwork():
        adapter = ma.build_adapter(_mapping())
        f12 = list(adapter.collect(text12))
        f11 = list(adapter.collect(text11))
        farf = list(adapter.collect(arf))
    assert _canon(f12) == _canon(f11) == _canon(farf)
    assert len(f12) == 7


# --- AC2 ----------------------------------------------------------------------

def test_ac2_every_non_pass_standard_value_is_unknown_never_pass():
    pairs = [(f"xccdf_com.example_rule_r{i}", v) for i, v in enumerate(xr.XCCDF_RESULT_NORMALIZATION)]
    checks = [r for r, _ in pairs]
    m = _mapping(checks=checks, check_bindings={})
    adapter = ma.build_adapter(m)
    facts = list(adapter.collect(_results_with(pairs)))
    got = {v: f["status"] for (_, v), f in zip(pairs, facts)}
    assert got["pass"] == "PASS"
    assert got["fail"] == "FAIL"
    for v in ("error", "unknown", "notapplicable", "notchecked", "notselected",
              "informational", "fixed"):
        assert got[v] == "UNKNOWN", (v, got[v])
    # The raw state is kept in detail so a reader sees what the scanner said.
    for (_, v), f in zip(pairs, facts):
        assert f"source state: {v}" in f["detail"]
    # Upper-case in the document still normalizes (the reader lower-cases).
    facts_uc = list(adapter.collect(_results_with([
        ("xccdf_com.example_rule_r0", "PASS"),
        ("xccdf_com.example_rule_r1", "FIXED"),
    ])))
    assert [f["status"] for f in facts_uc] == ["PASS", "UNKNOWN"]


def test_ac2_mapping_that_relabels_a_standard_value_is_refused_naming_it():
    for key, bad in (("notchecked", "PASS"), ("error", "PASS"), ("fixed", "PASS"),
                     ("fail", "UNKNOWN"), ("notapplicable", "PASS")):
        table = xr.canonical_normalization()
        table[key] = bad
        problems = ma.validate_mapping(_mapping(status_normalization=table))
        assert problems and any(key in p and "status_normalization" in p for p in problems), \
            (key, problems)
        refused = False
        try:
            ma.build_adapter(_mapping(status_normalization=table))
        except ma.MappingError as e:
            refused = key in str(e)
        assert refused, key
    # A key outside the closed vocabulary is a typo, refused too.
    table = xr.canonical_normalization()
    table["passed"] = "PASS"
    assert any("passed" in p for p in ma.validate_mapping(_mapping(status_normalization=table)))
    # A partial table that agrees is accepted, and the standard's full table
    # applies: an omitted `fail` is still FAIL, never UNKNOWN.
    partial = {"pass": "PASS"}
    assert ma.validate_mapping(_mapping(status_normalization=partial)) == []
    adapter = ma.build_adapter(_mapping(status_normalization=partial,
                                        checks=["xccdf_com.example_rule_r0"], check_bindings={}))
    facts = list(adapter.collect(_results_with([("xccdf_com.example_rule_r0", "fail")])))
    assert facts[0]["status"] == "FAIL"


def test_ac2_value_outside_the_vocabulary_is_unknown():
    adapter = ma.build_adapter(_mapping(checks=["xccdf_com.example_rule_r0"], check_bindings={}))
    facts = list(adapter.collect(_results_with([("xccdf_com.example_rule_r0", "compliant")])))
    assert facts[0]["status"] == "UNKNOWN"
    assert "source state: compliant" in facts[0]["detail"]


# --- AC3 ----------------------------------------------------------------------

def test_ac3_target_rides_only_as_raw_host_scope():
    adapter = ma.build_adapter(_mapping())
    facts = list(adapter.collect(_read(RESULTS)))
    for f in facts:
        assert f["host"] == TARGET
        assert TARGET not in f["detail"], f["detail"]
        assert ADDRESS not in _canon(f)
    # `host` is a raw scope kind of the fact contract.
    assert "host" in ew.raw_scope_fields()
    # Without a scope key the conversion is refused, naming the field.
    refused = False
    try:
        adapter.to_evidence(_read(RESULTS), _BASE)
    except ew.EvidenceExportError as e:
        refused = "host" in str(e) and "scope" in str(e)
    assert refused, "a host-tagged fact must be refused without a scope key"


def test_ac3_evidence_never_carries_the_host_name_or_address():
    adapter = ma.build_adapter(_mapping())
    with _NoNetwork():
        evs = adapter.to_evidence(_read(RESULTS), _BASE, scope_key=_KEY)
    assert len(evs) == 7
    blob = _canon(evs)
    assert TARGET not in blob
    assert "lab-host" not in blob
    assert ADDRESS not in blob
    for ev in evs:
        sf = ev["xSourceFact"]
        assert "host" not in sf
        assert sf["scope"].startswith("scope-")
        assert sf["scope"] in ev["evidenceLocation"]
        assert ev["evidenceLocation"].startswith(_BASE + "/openscap/")
        # The content hash binds the scoped payload.
        assert ev["xEvidenceContentHash"] == ew.evidence_hash(ew.canonical_payload(ev))
    # Two different hosts never share a scope; a host never shares a scope with
    # an account of the same literal (the HMAC message is kind-prefixed).
    s1 = ew.scope_id("lab-host-01.example", _KEY, kind="host")
    s2 = ew.scope_id("lab-host-02.example", _KEY, kind="host")
    assert s1 != s2
    assert ew.scope_id("111122223333", _KEY, kind="host") != ew.scope_id("111122223333", _KEY)
    # The public-package scrubber would catch the fixture's identifiers if they
    # ever reached free text (second line of defense, exercised here).
    assert "host" in ew.scrub_hits(TARGET)
    assert "ip" in ew.scrub_hits(ADDRESS)


def test_ac3_results_without_a_target_yield_facts_with_no_scope_field():
    adapter = ma.build_adapter(_mapping(checks=["xccdf_com.example_rule_r0"], check_bindings={}))
    facts = list(adapter.collect(_results_with([("xccdf_com.example_rule_r0", "pass")], target=None)))
    assert "host" not in facts[0]
    # No raw scope: conversion needs no key and produces no scope segment.
    evs = ew.facts_to_evidence(facts, _BASE)
    assert "scope" not in evs[0]["xSourceFact"]


# --- AC4 ----------------------------------------------------------------------

def test_ac4_facts_match_the_golden_fixture_byte_for_byte():
    adapter = ma.build_adapter(_mapping())
    facts = list(adapter.collect(_read(RESULTS)))
    golden = json.loads(_read(GOLDEN))
    assert _canon(facts) == _canon(golden["facts"])
    assert len(golden["facts"]) == 7


def test_ac4_fixture_header_records_documentation_url_and_capture_date():
    head = _read(RESULTS)[:2500]
    assert "https://csrc.nist.gov/schema/xccdf/1.2/xccdf_1.2.xsd" in head
    assert re.search(r"captured 20\d\d-\d\d-\d\d", head)
    m = _mapping()
    assert m["documentation"]["url"].startswith("https://")
    assert re.match(r"^\d{4}-\d{2}-\d{2}$", m["documentation"]["captured"])
    # Fictional identifiers only: reserved example namespace, reserved TLD,
    # documentation address range.
    text = _read(RESULTS)
    assert "com.example" in text and ".example<" in text and "203.0.113." in text


# --- undeclared rules, emptiness, refusals -----------------------------------------

def test_undeclared_rule_result_is_skipped_counted_and_named():
    adapter = ma.build_adapter(_mapping())
    facts = list(adapter.collect(_read(RESULTS)))
    assert all(f["check"] != "xccdf_com.example_rule_login_banner_present" for f in facts)
    h = adapter.health()
    assert h["records"] == 8 and h["facts_yielded"] == 7
    assert h["skipped_undeclared"] == 1
    assert h["undeclared_checks"] == ["xccdf_com.example_rule_login_banner_present"]
    assert adapter.describe()["undeclared_checks"] == "skip"
    # With the default policy (refuse) the same document is refused by
    # to_evidence, naming the undeclared check; nothing converts.
    strict = ma.build_adapter(_mapping(undeclared_checks="refuse"))
    refused = False
    try:
        strict.to_evidence(_read(RESULTS), _BASE, scope_key=_KEY)
    except ew.EvidenceExportError as e:
        refused = "login_banner_present" in str(e)
    assert refused
    # A mapping without the key defaults to refuse (MCE-02 behaviour unchanged).
    m = _mapping()
    del m["undeclared_checks"]
    assert ma.build_adapter(m).describe()["undeclared_checks"] == "refuse"


def test_results_with_no_rule_results_report_not_run():
    adapter = ma.build_adapter(_mapping())
    facts = list(adapter.collect(_results_with([])))
    assert facts == []
    assert adapter.collection_outcome() == "not-run"
    assert adapter.health()["last_error"] == "export contained no records"


def test_doctype_and_non_xccdf_documents_are_refused():
    adapter = ma.build_adapter(_mapping())
    doc = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]>' + _results_with([])[38:]
    for bad, needle in ((doc, "DOCTYPE"),
                        ("<root/>", "no TestResult"),
                        ("not xml at all", "not well-formed"),
                        ('<Benchmark xmlns="urn:other"><TestResult/></Benchmark>', "no TestResult")):
        refused = False
        try:
            list(adapter.collect(bad))
        except ma.MappingError as e:
            refused = needle in str(e)
        assert refused, (bad[:40], needle)


def test_rule_result_without_any_time_is_refused_by_the_contract_never_invented():
    doc = (f'<TestResult xmlns="{XCCDF_12}" id="xccdf_com.example_testresult_t2">'
           f'<rule-result idref="xccdf_com.example_rule_r0"><result>pass</result></rule-result>'
           f'</TestResult>')
    adapter = ma.build_adapter(_mapping(checks=["xccdf_com.example_rule_r0"], check_bindings={}))
    facts = list(adapter.collect(doc))
    assert facts[0]["observed_at"] is None
    refused = False
    try:
        adapter.to_evidence(doc, _BASE, scope_key=_KEY)
    except ew.FactContractError as e:
        refused = "observed_at" in str(e)
    assert refused


def test_reader_records_carry_the_documented_fields():
    recs = xr.read_xccdf_results(_read(RESULTS))
    assert len(recs) == 8
    for r in recs:
        assert tuple(sorted(r)) == tuple(sorted(xr.RECORD_FIELDS))
        assert r["target"] == TARGET
        assert r["benchmark"] == "xccdf_com.example_benchmark_baseline-os"
        assert r["profile"] == "xccdf_com.example_profile_hardened"
        assert r["test_result"] == "xccdf_com.example_testresult_hardened-20261001"
        assert TARGET not in (r["summary"] or "")


def test_apply_driver_end_to_end_with_the_xccdf_source():
    """The offering profile enables the XCCDF source with mapping_path and
    export_path; the driver reads the results file as text, refuses the host
    scope without a key, attaches each rule's evidence to exactly the KSIs its
    binding declares, skips the undeclared rule, and writes no host name or
    address into the store. Temp copies only; the repository's own profile and
    store are untouched."""
    import io
    import shutil
    import tempfile
    from contextlib import redirect_stdout
    import apply_third_party_evidence as ap

    with tempfile.TemporaryDirectory() as tmp:
        shutil.copytree(FIX, os.path.join(tmp, "fixtures"))
        kids = ["KSI-MLA-EVC", "KSI-MLA-LET", "KSI-SVC-VRI", "KSI-CNA-MAT", "KSI-PIY-GIV",
                "KSI-MLA-OSM"]
        records = {"ksi": {k: {"evidence": []} for k in kids}}
        rec_path = os.path.join(tmp, "records-store.json")
        prof_path = os.path.join(tmp, "offering-profile.json")
        with open(prof_path, "w", encoding="utf-8") as f:
            json.dump({"evidence_sources": {"example-openscap-xccdf": {
                "enabled": True, "export_path": "fixtures/example-openscap-xccdf.results.xml",
                "mapping_path": "fixtures/example-openscap-xccdf.mapping.json"}}}, f)
        with open(rec_path, "w", encoding="utf-8") as f:
            json.dump(records, f)
        saved = (ap.BASE, ap.PROFILE, ap.RECORDS, os.environ.get("SDR_EVIDENCE_SCOPE_KEY"))
        ap.BASE, ap.PROFILE, ap.RECORDS = tmp, prof_path, rec_path
        try:
            os.environ.pop("SDR_EVIDENCE_SCOPE_KEY", None)
            with _NoNetwork(), redirect_stdout(io.StringIO()) as out:
                assert ap.main() == 1
            assert "host" in out.getvalue()
            with open(rec_path, encoding="utf-8") as f:
                assert json.load(f) == records, "refused: store must be untouched"
            os.environ["SDR_EVIDENCE_SCOPE_KEY"] = "test-scope-key-not-a-secret"
            with _NoNetwork(), redirect_stdout(io.StringIO()) as out:
                assert ap.main() == 0
            printed = out.getvalue()
            assert "login_banner_present" in printed and "undeclared_checks: skip" in printed
            with open(rec_path, encoding="utf-8") as f:
                after = json.load(f)
            n = {k: len(after["ksi"][k]["evidence"]) for k in kids}
            # audit logging -> LET + EVC; password + denylist -> EVC (default);
            # file integrity -> VRI; unused services + legacy protocol -> MAT;
            # package inventory -> GIV; nothing to OSM.
            assert n == {"KSI-MLA-EVC": 3, "KSI-MLA-LET": 1, "KSI-SVC-VRI": 1,
                         "KSI-CNA-MAT": 2, "KSI-PIY-GIV": 1, "KSI-MLA-OSM": 0}, n
            blob = json.dumps(after)
            assert TARGET not in blob and ADDRESS not in blob and "scope-" in blob
            assert "login_banner" not in blob
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
