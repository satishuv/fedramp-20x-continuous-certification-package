#!/usr/bin/env python3
"""Offline tests for evidence_wiring.

No AWS, no network. Runs under pytest or directly:
    python automation/collectors/test_evidence_wiring.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence_wiring as ew  # noqa: E402

# The official SDR evidence schema enum, reproduced so the test is self-contained.
_EVIDENCE_TYPES = {"Log", "Report", "Screenshot", "Configuration",
                   "Policy", "Procedure", "Audit Record"}


def _fact(service="s3", check="public_access_block", status="OBSERVED",
          detail="All buckets block public access", region="us-east-1",
          observed_at="2026-09-08T12:00:00+00:00"):
    return {"service": service, "check": check, "status": status,
            "detail": detail, "region": region, "observed_at": observed_at}


def test_fact_becomes_valid_evidence():
    ev = ew.fact_to_evidence(_fact())
    assert ev["evidenceType"] in _EVIDENCE_TYPES
    assert ev["evidenceType"] == "Configuration"  # s3 -> Configuration
    assert "s3:public_access_block" in ev["evidenceDescription"]
    assert ev["evidenceLocation"]
    assert ev["lastUpdated"] == "2026-09-08"  # date only, not datetime


def test_error_fact_is_not_evidence():
    assert ew.fact_to_evidence(_fact(status="ERROR:AccessDenied")) is None


def test_placeholder_is_honest_not_fake_https():
    ev = ew.fact_to_evidence(_fact())
    # With no real store base, the pointer must be an obvious placeholder,
    # never a fabricated https URL implying a real artifact.
    assert ev["evidenceLocation"].startswith("sdr://placeholder/")
    assert not ev["evidenceLocation"].startswith("http")


def test_real_location_base_produces_concrete_uri():
    ev = ew.fact_to_evidence(_fact(), location_base="https://evidence.example.gov/store")
    assert ev["evidenceLocation"] == \
        "https://evidence.example.gov/store/s3/public_access_block/us-east-1.json"


def test_cloudtrail_maps_to_audit_record():
    ev = ew.fact_to_evidence(_fact(service="cloudtrail", check="trail_status"))
    assert ev["evidenceType"] == "Audit Record"


def test_attach_does_not_touch_status():
    rec = {
        "implementation_status": "Not Implemented",
        "implementation": ["TBD"],
        "validation": ["TBD"],
        "assessment": ["TBD"],
        "evidence": [],
    }
    before = dict(rec)
    added = ew.attach_evidence(rec, [_fact(), _fact(service="config", check="recorder")])
    assert added == 2
    # every non-evidence field is byte-identical
    assert rec["implementation_status"] == before["implementation_status"]
    assert rec["implementation"] == before["implementation"]
    assert rec["validation"] == before["validation"]
    assert rec["assessment"] == before["assessment"]
    assert len(rec["evidence"]) == 2


def test_attach_dedupes_by_location():
    rec = {"evidence": []}
    ew.attach_evidence(rec, [_fact()])
    added = ew.attach_evidence(rec, [_fact()])  # same fact again
    assert added == 0
    assert len(rec["evidence"]) == 1


def test_attach_replace_mode():
    rec = {"evidence": [{"evidenceLocation": "sdr://placeholder/old", "evidenceType": "Report"}]}
    ew.attach_evidence(rec, [_fact()], replace=True)
    assert len(rec["evidence"]) == 1
    assert rec["evidence"][0]["evidenceType"] == "Configuration"


def test_error_facts_dropped_in_bulk():
    facts = [_fact(), _fact(status="ERROR:Timeout"), _fact(service="config")]
    out = ew.facts_to_evidence(facts)
    assert len(out) == 2


def test_evidence_carries_content_hash():
    ev = ew.fact_to_evidence(_fact())
    assert ev["xEvidenceContentHash"].startswith("sha256:")
    assert len(ev["xEvidenceContentHash"]) == len("sha256:") + 64


def test_hash_is_deterministic_and_order_independent():
    # Same logical content, different key order -> same digest.
    h1 = ew.evidence_hash({"a": 1, "b": [2, 3]})
    h2 = ew.evidence_hash({"b": [2, 3], "a": 1})
    assert h1 == h2
    # Different content -> different digest.
    assert ew.evidence_hash({"a": 1}) != ew.evidence_hash({"a": 2})
    # Bytes and str inputs are accepted.
    assert ew.evidence_hash(b"x") == ew.evidence_hash("x")


def test_hash_detects_tampering():
    ev = ew.fact_to_evidence(_fact())
    original = ev["xEvidenceContentHash"]
    tampered = ew.evidence_hash(_fact(detail="All buckets block public access!!"))
    assert tampered != original


def test_adapter_registry_has_reference_adapter():
    assert "csv-count" in ew.list_adapters()
    assert ew.get_adapter("csv-count") is not None


def test_csv_count_adapter_produces_hashed_evidence():
    adapter = ew.get_adapter("csv-count")
    raw = {"check": "patch-coverage", "observed": 98, "total": 100,
           "observed_at": "2026-09-08T00:00:00+00:00"}
    evs = adapter.to_evidence(raw)
    assert len(evs) == 1
    ev = evs[0]
    assert "98.0%" in ev["evidenceText"] or "98.0%" in ev["evidenceDescription"]
    assert ev["xEvidenceContentHash"].startswith("sha256:")


def test_register_rejects_non_adapter():
    class NotAnAdapter:
        pass
    try:
        ew.register_adapter(NotAnAdapter)
    except TypeError:
        return
    raise AssertionError("register_adapter should reject a non-adapter")


def test_real_collector_fact_shape_preserves_timestamp():
    # REGRESSION: the live AWS collector (collectors._fact) emits collected_at,
    # NOT observed_at. Feed the ACTUAL collector fact shape through
    # fact_to_evidence and confirm the collection timestamp survives - both as
    # a populated lastUpdated and inside the sanitized xSourceFact. Before the
    # fix, collected_at was dropped by the allowlist, so lastUpdated came back
    # empty and the digest did not cover the timestamp.
    try:
        import collectors as col
        real_fact = col._fact("s3", "public_access_block", "OBSERVED",
                               "All buckets block public access", "us-east-1")
    except Exception:
        # Fall back to the documented shape if collectors can't import offline.
        real_fact = {"service": "s3", "check": "public_access_block",
                     "status": "OBSERVED", "detail": "x", "region": "us-east-1",
                     "collected_at": "2026-09-14T00:00:00+00:00"}
    assert "collected_at" in real_fact and "observed_at" not in real_fact
    ev = ew.fact_to_evidence(real_fact)
    assert ev is not None
    assert ev["lastUpdated"], "lastUpdated must be populated from collected_at"
    assert ev["lastUpdated"] == str(real_fact["collected_at"])[:10]
    # collected_at must be carried in the sanitized source fact so the digest
    # covers it and a reviewer can recompute.
    assert ev["xSourceFact"].get("collected_at") == real_fact["collected_at"]


# --- AUD-F27: account scopes never collide and the account never leaks --------

_KEY = b"test-deployment-scope-key"
_BASE = "https://evidence.example.gov/store"


def _two_accounts():
    fact = {"service": "s3", "check": "tls", "status": "PASS", "region": "us-east-1",
            "detail": "observed one resource", "collected_at": "2026-09-26T12:00:00+00:00"}
    return [dict(fact, account="111122223333", status="PASS"),
            dict(fact, account="444455556666", status="FAIL")]


def test_f27_two_accounts_opposite_findings_both_kept():
    rec = {}
    added = ew.attach_evidence(rec, _two_accounts(), _BASE, scope_key=_KEY)
    assert added == 2, added
    statuses = sorted(e["xSourceFact"]["status"] for e in rec["evidence"])
    assert statuses == ["FAIL", "PASS"], statuses
    locs = {e["evidenceLocation"] for e in rec["evidence"]}
    assert len(locs) == 2, "two scopes must never share an evidence pointer"
    hashes = {e["xEvidenceContentHash"] for e in rec["evidence"]}
    assert len(hashes) == 2
    # replace=True keeps both as well, still with distinct pointers.
    rec2 = {}
    assert ew.attach_evidence(rec2, _two_accounts(), _BASE, replace=True, scope_key=_KEY) == 2
    assert len({e["evidenceLocation"] for e in rec2["evidence"]}) == 2


def test_f27_account_never_enters_the_entry():
    import json as _j
    for ev in ew.facts_to_evidence(_two_accounts(), _BASE, scope_key=_KEY):
        blob = _j.dumps(ev)
        assert "111122223333" not in blob and "444455556666" not in blob, blob
        assert "account" not in ev["xSourceFact"]
        assert ev["xSourceFact"]["scope"].startswith("scope-")
        assert ev["xSourceFact"]["scope"] in ev["evidenceLocation"]


def test_f27_scope_is_keyed_and_deterministic():
    a = ew.scope_id("111122223333", _KEY)
    assert a == ew.scope_id("111122223333", _KEY)  # stable across runs
    assert a != ew.scope_id("444455556666", _KEY)  # distinct per account
    assert a != ew.scope_id("111122223333", b"another-key")  # keyed, not a plain hash
    assert "111122223333" not in a
    try:
        ew.scope_id("111122223333", None)
        assert False, "no key must be refused"
    except ew.EvidenceExportError:
        pass


def test_f27_account_tagged_fact_without_scope_is_refused_not_dropped():
    fact = dict(_two_accounts()[0])
    try:
        ew.fact_to_evidence(fact, _BASE)  # no scope, no key
        assert False, "must refuse, never silently export or drop"
    except ew.EvidenceExportError as e:
        assert "scope" in str(e)
    # A caller-supplied opaque alias is accepted...
    ev = ew.fact_to_evidence(dict(fact, scope="prod-east"), _BASE)
    assert ev["xSourceFact"]["scope"] == "prod-east"
    assert "/prod-east/" in ev["evidenceLocation"]
    # ...but the account itself is not an acceptable "alias".
    try:
        ew.fact_to_evidence(dict(fact, scope="111122223333"), _BASE)
        assert False
    except ew.EvidenceExportError:
        pass
    # An ERROR fact is still simply not evidence (checked before scope).
    assert ew.fact_to_evidence(dict(fact, status="ERROR:AccessDenied"), _BASE) is None


def test_f27_run_id_scopes_the_pointer_and_dedup_identity():
    fact = _two_accounts()[0]
    r1 = ew.fact_to_evidence(dict(fact, run_id="run-a"), _BASE, scope_key=_KEY)
    r2 = ew.fact_to_evidence(dict(fact, run_id="run-b"), _BASE, scope_key=_KEY)
    assert r1["evidenceLocation"] != r2["evidenceLocation"]
    assert r1["evidenceLocation"].endswith("/run-a.json")
    # Two runs of one scope are two observations (both kept); the identical
    # observation attached twice is kept once.
    rec = {}
    assert ew.attach_evidence(rec, [dict(fact, run_id="run-a")], _BASE, scope_key=_KEY) == 1
    assert ew.attach_evidence(rec, [dict(fact, run_id="run-a")], _BASE, scope_key=_KEY) == 0
    assert ew.attach_evidence(rec, [dict(fact, run_id="run-b")], _BASE, scope_key=_KEY) == 1
    assert len(rec["evidence"]) == 2


def test_f27_no_account_no_scope_stays_backward_compatible():
    ev = ew.fact_to_evidence(_fact(), location_base=_BASE)
    assert "scope" not in ev["xSourceFact"] and "scope=" not in ev["evidenceText"]
    assert ev["evidenceLocation"] == f"{_BASE}/s3/public_access_block/us-east-1.json"


# --- AUD-F28: free-form detail cannot carry identifiers into the package ------

def test_f28_hostname_and_ip_in_detail_are_scrubbed():
    import json as _j
    ev = ew.fact_to_evidence(_fact(
        detail="host prod-db-01.internal.corp reachable at 10.23.45.67"))
    blob = _j.dumps(ev)
    assert "prod-db-01" not in blob and "10.23.45.67" not in blob, blob
    assert "[redacted:host]" in ev["evidenceDescription"]
    assert "[redacted:ip]" in ev["evidenceDescription"]
    assert "[redacted:" in ev["xSourceFact"]["summary"]


def test_f28_arn_account_key_email_url_token_are_scrubbed():
    bad = ("arn:aws:iam::111122223333:role/Admin AKIAIOSFODNN7EXAMPLE "
           "ops@corp.example.com https://internal.example.com/x "
           "fe80::1 2001:db8::ff00:42:8329 111122223333 "
           "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcd")
    out = ew.scrub_text(bad)
    for token in ("111122223333", "AKIAIOSFODNN7EXAMPLE", "ops@", "example.com",
                  "fe80::1", "2001:db8", "AbCdEfGhIjKlMnOpQrStUvWxYz"):
        assert token not in out, (token, out)
    assert set(ew.scrub_hits(bad)) >= {"arn", "access-key", "email", "url", "ip",
                                       "account", "token"}


def test_f28_first_party_details_are_untouched():
    # What the real collectors emit: counts and plain phrases. None of it may
    # be redacted, or the scrub would be hiding evidence rather than identifiers.
    for detail in ("12 of 12 bucket(s) have default encryption configured (12 total, 0 unmeasured)",
                   "Falcon sensor on 40 of 42 hosts", "3 trail(s), 1 multi-region",
                   "Enumeration incomplete (page cap); 7 of 9 evaluated", "57.14%",
                   "0 critical / 2 high", "e.g. rotation enabled at 12:00:00"):
        assert ew.scrub_text(detail) == detail, detail
        assert ew.scrub_hits(detail) == [], detail


def test_f28_detail_and_status_are_bounded():
    long = "x " * 400
    ev = ew.fact_to_evidence(_fact(detail=long, status="OBSERVED " * 30))
    assert len(ev["xSourceFact"]["summary"]) <= ew.SUMMARY_MAX
    # "<service>:<check> = <status>. <detail>" with each free-text part bounded.
    assert len(ev["evidenceDescription"]) <= ew.DETAIL_MAX + ew.STATUS_MAX + 64
    assert len(ev["xSourceFact"]["status"]) <= ew.STATUS_MAX


def test_f28_key_segments_must_be_slug_safe():
    for bad in ({"check": "../../etc/passwd"}, {"service": "s3 bucket"},
                {"region": "us-east-1/../x"}, {"run_id": "a/b"}):
        f = _fact()
        f.update(bad)
        try:
            ew.fact_to_evidence(f, _BASE)
            assert False, f"unsafe identifier accepted: {bad}"
        except ew.EvidenceExportError:
            pass


def test_f28_csv_adapter_check_from_raw_is_slug_checked():
    ad = ew.get_adapter("csv-count")
    try:
        ad.to_evidence({"check": "../escape", "observed": 1, "total": 1})
        assert False
    except ew.EvidenceExportError:
        pass
    ok = ad.to_evidence({"check": "patch-coverage", "observed": 9, "total": 10})
    assert ok and ok[0]["xSourceFact"]["status"] == "90.0%"


def _run_direct():
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_direct())
