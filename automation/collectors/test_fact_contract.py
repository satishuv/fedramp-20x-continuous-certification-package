#!/usr/bin/env python3
"""MCE-01 / AUD-F68: the neutral collector fact contract.

What this proves:
  AC1  the contract is a committed, valid JSON Schema at the path
       evidence_wiring references, with exactly the required fields the story
       names and an optional scope;
  AC2  an adapter fact missing a required field (or carrying a wrong type) is
       rejected NAMING the field, and fact_to_evidence is never called for that
       batch;
  AC3  a fact carrying a raw account / tenant / subscription / compartment /
       project / organization identifier and no scope_key is refused with an
       explicit error naming the field; with a scope_key the raw value appears
       nowhere in the evidence; the AWS account derivation is byte-identical
       to the pre-MCE-01 HMAC;
  AC4  the existing adapters (Falcon, Wiz, csv-count) produce evidence
       byte-identical to the golden fixture captured from the unmodified code,
       and the AWS collector path (collected_at facts, not routed through the
       adapter contract) is unchanged.

Offline, no network. Run:
    python automation/collectors/test_fact_contract.py
"""

import hashlib
import hmac
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import evidence_wiring as ew  # noqa: E402
import thirdparty_adapters  # noqa: E402,F401  (registers falcon and wiz)

GOLDEN = os.path.join(HERE, "fixtures", "adapter-golden-evidence.json")
_KEY = b"test-scope-key-not-a-secret"
_BASE = "https://evidence.example.gov/store"


def _good_fact(**over):
    f = {"service": "scan", "check": "patch-coverage", "status": "98.0%",
         "detail": "98 of 100", "region": "global",
         "observed_at": "2026-09-08T00:00:00+00:00"}
    f.update(over)
    return f


class _Adapter(ew.EvidenceAdapter):
    """Test adapter: yields whatever facts the raw payload carries."""
    name = "contract-probe"
    service = "scan"

    def collect(self, raw):
        for f in raw["facts"]:
            yield f


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


# --- AC1 ----------------------------------------------------------------------

def test_ac1_contract_is_committed_valid_json_schema():
    import jsonschema
    assert os.path.exists(ew.FACT_CONTRACT_PATH), ew.FACT_CONTRACT_PATH
    assert ew.FACT_CONTRACT_PATH.endswith(os.path.join("collectors", "fact-contract.schema.json"))
    schema = ew.fact_contract()
    jsonschema.Draft202012Validator.check_schema(schema)
    assert tuple(schema["required"]) == ("service", "check", "status", "detail",
                                         "region", "observed_at")
    assert ew.required_fact_fields() == tuple(schema["required"])
    assert "scope" in schema["properties"] and "scope" not in schema["required"]
    assert set(ew.raw_scope_fields()) == {"account", "tenant", "subscription",
                                          "compartment", "project", "organization",
                                          "host"}
    # Every raw scope field is declared in the schema as an input property.
    for k in ew.raw_scope_fields():
        assert k in schema["properties"], k
    assert ew.validate_fact(_good_fact()) == []


# --- AC2 ----------------------------------------------------------------------

def test_ac2_missing_required_field_is_rejected_naming_it():
    for name in ew.required_fact_fields():
        f = _good_fact()
        del f[name]
        problems = ew.validate_fact(f)
        assert problems and f"'{name}'" in problems[0], (name, problems)


def test_ac2_wrong_type_is_rejected_naming_the_field():
    cases = [
        ("observed_at", None),          # an invented or absent timestamp
        ("observed_at", "yesterday"),   # not a calendar date prefix
        ("status", 3),                  # a number is not an observation string
        ("detail", ["x"]),              # not a string
        ("service", "bad/slug"),        # not slug-safe (would reach the object key)
        ("region", ""),                 # empty slug
    ]
    for field, value in cases:
        problems = ew.validate_fact(_good_fact(**{field: value}))
        assert problems and any(f"'{field}'" in p for p in problems), (field, problems)
    assert ew.validate_fact("not a dict") == ["fact is not an object"]
    # A raw scope identifier is a legitimate INPUT field (export decides).
    assert ew.validate_fact(_good_fact(tenant="t-1")) == []
    # scope is optional but, when present, must be opaque and slug-safe.
    assert ew.validate_fact(_good_fact(scope="scope-abc")) == []
    assert ew.validate_fact(_good_fact(scope="111122223333"))
    assert ew.validate_fact(_good_fact(scope="a/b"))


def test_ac2_adapter_batch_with_a_bad_fact_never_reaches_fact_to_evidence():
    calls = []
    real = ew.fact_to_evidence

    def spy(fact, location_base=None, scope_key=None):
        calls.append(fact)
        return real(fact, location_base, scope_key=scope_key)

    ew.fact_to_evidence = spy
    try:
        bad = _good_fact()
        del bad["observed_at"]
        caught = None
        try:
            _Adapter().to_evidence({"facts": [_good_fact(), bad]}, _BASE)
            raise AssertionError("a non-conforming fact must be refused")
        except ew.FactContractError as e:
            caught = e
        assert "fact[1]" in str(caught) and "'observed_at'" in str(caught), str(caught)
        assert caught.problems == ["fact[1] missing required field 'observed_at'"]
        assert "contract-probe" in str(caught)
        # The GOOD fact in the same batch was not converted either: nothing is
        # exported from a batch whose shape is wrong.
        assert calls == [], calls
        assert isinstance(caught, ew.EvidenceExportError)  # existing handlers catch it
        # A conforming batch converts normally.
        evs = _Adapter().to_evidence({"facts": [_good_fact()]}, _BASE)
        assert len(evs) == 1 and len(calls) == 1
    finally:
        ew.fact_to_evidence = real


# --- AC3 ----------------------------------------------------------------------

def test_ac3_raw_scope_identifier_without_scope_key_is_refused_naming_the_field():
    for field in ew.raw_scope_fields():
        f = _good_fact(**{field: "raw-identifier-0001"})
        try:
            ew.fact_to_evidence(f, _BASE)  # no scope, no key
            raise AssertionError(f"{field}: must refuse, never export or drop")
        except ew.EvidenceExportError as e:
            msg = str(e)
            assert field in msg and "scope" in msg and "refusing" in msg, (field, msg)
        # The same refusal reaches an adapter caller through to_evidence.
        try:
            _Adapter().to_evidence({"facts": [f]}, _BASE)
            raise AssertionError(field)
        except ew.EvidenceExportError as e:
            assert field in str(e)


def test_ac3_with_scope_key_the_raw_value_never_enters_the_evidence():
    raw_value = "raw-identifier-0001"
    seen_scopes = set()
    for field in ew.raw_scope_fields():
        ev = ew.fact_to_evidence(_good_fact(**{field: raw_value}), _BASE, scope_key=_KEY)
        blob = _canon(ev)
        assert raw_value not in blob, (field, blob)
        assert field not in ev["xSourceFact"], (field, ev["xSourceFact"])
        scope = ev["xSourceFact"]["scope"]
        assert scope.startswith("scope-") and f"/{scope}/" in ev["evidenceLocation"]
        seen_scopes.add(scope)
        # Recompute of the bound payload still matches (the scope is signed in).
        assert ew.evidence_hash(ew.canonical_payload(ev)) == ev["xEvidenceContentHash"]
    # Different identifier KINDS with the same literal value never share a scope.
    assert len(seen_scopes) == len(ew.raw_scope_fields()), seen_scopes
    # Two raw fields on one fact derive one stable composite scope.
    a = ew.fact_to_evidence(_good_fact(tenant="t1", subscription="s1"), _BASE, scope_key=_KEY)
    b = ew.fact_to_evidence(_good_fact(subscription="s1", tenant="t1"), _BASE, scope_key=_KEY)
    assert a["xSourceFact"]["scope"] == b["xSourceFact"]["scope"]
    assert "t1" not in _canon(a) and "s1" not in _canon(a)
    # An explicit opaque alias is still accepted in place of a key.
    ev = ew.fact_to_evidence(_good_fact(tenant="t1", scope="prod-east"), _BASE)
    assert ev["xSourceFact"]["scope"] == "prod-east" and "t1" not in _canon(ev)


def test_ac3_aws_account_scope_derivation_is_byte_identical_to_pre_mce01():
    # The pre-MCE-01 derivation: HMAC-SHA256(key, account)[:16], 'scope-' prefix.
    acct = "111122223333"
    expected = "scope-" + hmac.new(_KEY, acct.encode("utf-8"), hashlib.sha256).hexdigest()[:16]
    assert ew.scope_id(acct, _KEY) == expected
    assert ew.scope_id(acct, _KEY, kind="account") == expected
    assert ew.scope_id(acct, _KEY, kind="tenant") != expected
    ev = ew.fact_to_evidence(_good_fact(service="s3", check="public_access_block",
                                        account=acct), _BASE, scope_key=_KEY)
    assert ev["xSourceFact"]["scope"] == expected
    assert acct not in _canon(ev)


# --- AC4 ----------------------------------------------------------------------

def test_ac4_existing_adapters_match_the_golden_fixture_byte_for_byte():
    with open(GOLDEN, encoding="utf-8") as f:
        golden = json.load(f)
    base = golden["location_base"]
    for name, case in sorted(golden["adapters"].items()):
        adapter = ew.get_adapter(name)
        assert adapter is not None, name
        actual = adapter.to_evidence(case["raw"], base)
        assert _canon(actual) == _canon(case["expected"]), name
        assert len(actual) > 0, name
    assert set(golden["adapters"]) == {"crowdstrike-falcon", "wiz", "csv-count"}


def test_ac4_aws_collector_fact_path_is_unchanged():
    # The live AWS collectors emit collected_at (no observed_at) and are not
    # routed through the adapter contract; fact_to_evidence keeps converting
    # them exactly as before, including the lastUpdated derivation.
    f = {"service": "config", "check": "s3-bucket-public-read-prohibited",
         "status": "COMPLIANT", "detail": "0 non-compliant resources",
         "region": "us-east-1", "collected_at": "2026-09-06T00:00:00+00:00"}
    ev = ew.fact_to_evidence(f, _BASE)
    assert ev["lastUpdated"] == "2026-09-06"
    assert ev["xSourceFact"]["collected_at"] == f["collected_at"]
    assert ew.evidence_hash(ew.canonical_payload(ev)) == ev["xEvidenceContentHash"]
    # An ERROR fact is still simply not evidence.
    assert ew.fact_to_evidence(dict(f, status="ERROR:AccessDenied"), _BASE) is None


def test_fixture_is_fictional():
    with open(GOLDEN, encoding="utf-8") as f:
        text = f.read()
    for forbidden in ("arn:aws", "AKIA", "amazonaws.com"):
        assert forbidden not in text, forbidden
    import re
    assert not re.search(r"(?<!\d)\d{12}(?!\d)", text), "no 12-digit identifiers in the fixture"


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
