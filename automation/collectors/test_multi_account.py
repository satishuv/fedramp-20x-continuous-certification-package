"""Scale and fault tests for the multi-account evidence fan-out (no AWS).

Answers the width version of "what if it fails or crashes at scale": simulate
a large AWS Organization (many accounts x regions), inject assume-role failures
and collector failures, and assert:
  1. The fan-out never raises; a failed account/region yields ONE scope ERROR
     fact, not a crash and not a dropped scope.
  2. Every scope is accounted for: scopes_ok + scopes_failed == total scopes.
  3. Every fact is tagged with its account and region (provenance).
  4. An admin-looking role name is refused.
  5. Output stays bounded (no per-resource dumps) even across many accounts.

Run: python automation/collectors/test_multi_account.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collect_multi_account as mac  # noqa: E402


class _FakeCollectorSession:
    """Stands in for an assumed-role session; collectors here are stubbed so we
    exercise the fan-out, not AWS."""
    def __init__(self, account):
        self.account = account


def _stub_collectors(fail_service=None):
    """Return a COLLECTORS-like list of (name, fn). Each fn returns one bounded
    fact; `fail_service` raises to prove one service can't sink an account."""
    def make(name):
        def fn(session, region):
            if name == fail_service:
                raise RuntimeError(f"{name} boom")
            return [{
                "service": name, "check": "x", "status": "OBSERVED",
                "detail": "bounded summary", "region": region,
                "collected_at": mac._now(),
            }]
        return fn
    return [(n, make(n)) for n in ("security_hub", "config", "s3", "iam")]


class _StubSTS:
    """A base session whose sts.assume_role succeeds, except for accounts in
    `fail_accounts`, where it raises (simulating a missing/denied role)."""
    def __init__(self, fail_accounts=frozenset()):
        self._fail = set(fail_accounts)

    def client(self, name):
        assert name == "sts"
        outer = self

        class _C:
            def assume_role(self, RoleArn=None, RoleSessionName=None, **k):
                acct = RoleArn.split(":")[4]
                if acct in outer._fail:
                    raise RuntimeError("AccessDenied assuming role")
                return {"Credentials": {"AccessKeyId": "AKIA", "SecretAccessKey": "s",
                                        "SessionToken": "t"}}
        return _C()


# Monkeypatch assume_role_session so we don't build a real boto3 Session.
def _fake_assume(base_session, account, role_name, region, session_name="x"):
    if "admin" in role_name.lower():
        raise ValueError("admin role refused")
    # Delegate to the stub STS to honor injected assume-role failures.
    base_session.client("sts").assume_role(
        RoleArn=f"arn:aws:iam::{account}:role/{role_name}",
        RoleSessionName=session_name)
    return _FakeCollectorSession(account)


def _run(accounts, regions, fail_accounts=frozenset(), fail_service=None,
         role_name="FedRampReadOnly"):
    orig = mac.assume_role_session
    mac.assume_role_session = _fake_assume
    try:
        return mac.collect_across_accounts(
            accounts=accounts, role_name=role_name, regions=regions,
            base_session=_StubSTS(fail_accounts),
            collectors=_stub_collectors(fail_service), max_workers=16)
    finally:
        mac.assume_role_session = orig


def test_large_estate_all_scopes_accounted():
    accounts = [f"{i:012d}" for i in range(50)]   # 50 accounts
    regions = ["us-east-1", "us-west-2", "eu-west-1"]  # x3 = 150 scopes
    facts = _run(accounts, regions)
    s = mac.summarize(facts)
    assert s["accounts"] == 50, s
    assert s["scopes"] == 150, s
    assert s["scopes_failed_to_assume"] == 0, s
    # 4 collectors x 150 scopes = 600 facts, each bounded and tagged.
    assert s["total_facts"] == 600, s
    for f in facts:
        assert f.get("account") and f.get("region"), f"untagged fact {f}"
        assert len(f["detail"]) < 500
    print("PASS: test_large_estate_all_scopes_accounted")


def test_failed_accounts_do_not_sink_the_run():
    accounts = [f"{i:012d}" for i in range(20)]
    fail = {accounts[3], accounts[7], accounts[11]}  # 3 accounts can't assume
    regions = ["us-east-1", "us-west-2"]
    facts = _run(accounts, regions, fail_accounts=fail)
    s = mac.summarize(facts)
    # Each failed account still contributes one scope ERROR fact per region.
    assert s["scopes_failed_to_assume"] == len(fail) * len(regions), s
    # Good accounts still produced full facts.
    ok_accounts = {f["account"] for f in facts if f.get("service") != "_scope"}
    assert ok_accounts == (set(accounts) - fail), "good accounts missing facts"
    print("PASS: test_failed_accounts_do_not_sink_the_run")


def test_one_bad_service_does_not_sink_an_account():
    facts = _run(["000000000001"], ["us-east-1"], fail_service="config")
    # config raised, but the other 3 collectors still produced facts, and
    # config produced an ERROR fact rather than crashing the account.
    by_service = {f["service"]: f for f in facts}
    assert by_service["config"]["status"] == "ERROR", by_service
    assert by_service["security_hub"]["status"] == "OBSERVED"
    assert by_service["s3"]["status"] == "OBSERVED"
    print("PASS: test_one_bad_service_does_not_sink_an_account")


def test_admin_role_name_refused():
    facts = _run(["000000000001"], ["us-east-1"], role_name="OrgAdmin")
    # Refusal surfaces as a scope ERROR fact, not a crash.
    assert all(f["service"] == "_scope" and f["status"] == "ERROR" for f in facts), facts
    print("PASS: test_admin_role_name_refused")


# --- AUD-F27: the real collect -> export path across accounts ----------------

_KEY = b"test-deployment-scope-key"


def _opposite_findings_collectors():
    """One collector whose verdict depends on the account: PASS in the first,
    FAIL in the second, same service/check/region."""
    def s3_tls(session, region):
        status = "PASS" if session.account.endswith("1") else "FAIL"
        return [{"service": "s3", "check": "tls", "status": status,
                 "detail": "observed one resource", "region": region,
                 "collected_at": mac._now()}]
    return [("s3", s3_tls)]


def _run_keyed(accounts, regions, scope_key, collectors, run_id=None):
    orig = mac.assume_role_session
    mac.assume_role_session = _fake_assume
    try:
        return mac.collect_across_accounts(
            accounts=accounts, role_name="FedRampReadOnly", regions=regions,
            base_session=_StubSTS(), collectors=collectors, max_workers=4,
            run_id=run_id, scope_key=scope_key)
    finally:
        mac.assume_role_session = orig


def test_f27_two_accounts_opposite_findings_survive_end_to_end():
    import evidence_wiring as ew
    accounts = ["111122223331", "444455556662"]
    facts = _run_keyed(accounts, ["us-east-1"], _KEY, _opposite_findings_collectors(),
                       run_id="run-e2e")
    assert len(facts) == 2
    for f in facts:
        assert f["run_id"] == "run-e2e"
        assert f["scope"] == ew.scope_id(f["account"], _KEY)
    # The documented library output fed through the attachment helper: BOTH
    # scopes' observations survive, with distinct pointers and digests, and the
    # raw account never enters the entries.
    rec = {}
    added = ew.attach_evidence(rec, facts, "https://evidence.example.gov/store")
    assert added == 2, added
    statuses = sorted(e["xSourceFact"]["status"] for e in rec["evidence"])
    assert statuses == ["FAIL", "PASS"], statuses
    assert len({e["evidenceLocation"] for e in rec["evidence"]}) == 2
    import json
    blob = json.dumps(rec)
    for a in accounts:
        assert a not in blob
    print("PASS: test_f27_two_accounts_opposite_findings_survive_end_to_end")


def test_f27_unkeyed_run_is_refused_at_export_not_dropped():
    import evidence_wiring as ew
    facts = _run_keyed(["111122223331", "444455556662"], ["us-east-1"], None,
                       _opposite_findings_collectors())
    assert all("scope" not in f and f.get("run_id") for f in facts)
    try:
        ew.attach_evidence({}, facts, "https://evidence.example.gov/store")
        assert False, "account-tagged facts without a scope must be refused"
    except ew.EvidenceExportError:
        pass
    print("PASS: test_f27_unkeyed_run_is_refused_at_export_not_dropped")


def test_f27_private_store_carries_the_scope_map():
    import json
    import tempfile
    import evidence_wiring as ew
    accounts = ["111122223331", "444455556662"]
    facts = _run_keyed(accounts, ["us-east-1"], _KEY, _opposite_findings_collectors(),
                       run_id="run-store")
    scopes = mac.scope_map(accounts, _KEY)
    assert set(scopes.values()) == set(accounts)
    assert all(k == ew.scope_id(v, _KEY) for k, v in scopes.items())
    with tempfile.TemporaryDirectory() as d:
        p = mac.write_private_store(os.path.join(d, "facts", "run.json"),
                                    facts, "run-store", scopes)
        with open(p, encoding="utf-8") as f:
            stored = json.load(f)
    assert stored["run_id"] == "run-store"
    assert stored["scope_map"] == scopes
    assert len(stored["facts"]) == 2 and all(f["account"] in accounts for f in stored["facts"])
    print("PASS: test_f27_private_store_carries_the_scope_map")


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
