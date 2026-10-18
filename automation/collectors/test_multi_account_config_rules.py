"""AUD-F85: the multi-account fan-out must collect the registry's Config rule
checks for every scope, and must write a store the pipeline actually reads.

Found by the first live run against a real AWS Organization (one management
account plus one member account, 2026-10-17). ``collect_multi_account.py``
iterated only the posture ``COLLECTORS``; the 34 registry Config managed-rule
checks, the ones AUD-F84 had just taught to resolve deployed names, lived
inline in ``collect_facts.py main()`` and never ran for a member account. Its
output, ``multi-account.json``, was one flat list under a name no downstream
reader opens: the appender, prefill, drafters and roll-up all consume
``facts-*.json`` files in the ``{meta, facts, posture_facts}`` shape. So the
fan-out's facts never reached a metric or a proposal, although the appender
was built to aggregate per (rule, region, account) scope.

Asserts, with no AWS:
  AC1  one scope's collection yields the registry Config facts (resolved
       through the shared module, deployed names and worst-wins intact) AND
       the posture facts, each tagged with account and region;
  AC2  a denied ``describe_config_rules`` degrades to exact-name-only for that
       scope, never sinks it;
  AC3  the private store is written as ``facts-multi-account.json`` in the
       pipeline shape, and the appender's own loader returns the Config facts
       from it keyed by rule, one per scope;
  AC4  the old flat shape is still readable by ``summarize`` (no caller breaks).

Run: python automation/collectors/test_multi_account_config_rules.py
"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), "automation", "metrics"))
import collect_multi_account as mac  # noqa: E402

FAILS = []


def check(name, cond):
    print(("PASS: " if cond else "FAIL: ") + name)
    if not cond:
        FAILS.append(name)


# ---- fixtures -----------------------------------------------------------------
KNOWN = {"encrypted-volumes", "restricted-ssh", "cloudtrail-enabled"}
RULES = [
    {"ConfigRuleName": "securityhub-encrypted-volumes-47a7969b",
     "Source": {"Owner": "AWS", "SourceIdentifier": "ENCRYPTED_VOLUMES"}},
    {"ConfigRuleName": "encrypted-volumes",
     "Source": {"Owner": "AWS", "SourceIdentifier": "ENCRYPTED_VOLUMES"}},
    {"ConfigRuleName": "restricted-ssh-conformance-pack-abc123",
     "Source": {"Owner": "AWS", "SourceIdentifier": "INCOMING_SSH_DISABLED"}},
    {"ConfigRuleName": "some-custom-rule",
     "Source": {"Owner": "CUSTOM_LAMBDA", "SourceIdentifier": "arn:aws:lambda:x"}},
]
COMPLIANCE = {
    "securityhub-encrypted-volumes-47a7969b": "NON_COMPLIANT",
    "encrypted-volumes": "COMPLIANT",
    "restricted-ssh-conformance-pack-abc123": "COMPLIANT",
}


class _Denied(Exception):
    def __init__(self, code="AccessDeniedException"):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class _Config:
    def __init__(self, deny_list=False):
        self.deny_list = deny_list

    def describe_config_rules(self, **kw):
        if self.deny_list:
            raise _Denied()
        return {"ConfigRules": RULES}

    def describe_compliance_by_config_rule(self, ConfigRuleNames):
        assert len(ConfigRuleNames) <= 25
        return {"ComplianceByConfigRules": [
            {"ConfigRuleName": n, "Compliance": {"ComplianceType": COMPLIANCE[n]}}
            for n in ConfigRuleNames if n in COMPLIANCE]}


class _ScopeSession:
    """Stands in for the assumed-role session of one account."""
    def __init__(self, account, deny_list=False):
        self.account = account
        self._config = _Config(deny_list=deny_list)
        self.region_name = "us-east-1"

    def client(self, name):
        assert name == "config", name
        return self._config


DENY_ACCOUNTS = set()


def _fake_assume(base_session, account, role_name, region, session_name="x"):
    return _ScopeSession(account, deny_list=account in DENY_ACCOUNTS)


def _posture_collectors():
    def guardduty(session, region):
        return [{"service": "guardduty", "check": "detector", "status": "ENABLED",
                 "detail": "1 detector", "region": region, "collected_at": mac._now()}]
    return [("guardduty", guardduty)]


REGISTRY = {"meta": {"dataset_version": "test"}, "ksis": {"KSI-T": {"checks": [
    {"type": "config_managed_rule", "target": r, "check_id": f"KSI-T:{r}",
     "collectable_now": True} for r in sorted(KNOWN)]}}}


def _run(accounts, deny=frozenset()):
    global DENY_ACCOUNTS
    DENY_ACCOUNTS = set(deny)
    orig = mac.assume_role_session
    mac.assume_role_session = _fake_assume
    try:
        return mac.collect_across_accounts(
            accounts=accounts, role_name="FedRampReadOnly", regions=["us-east-1"],
            base_session=object(), collectors=_posture_collectors(), max_workers=4,
            run_id="run-f85", registry=REGISTRY)
    finally:
        mac.assume_role_session = orig


# ---- AC1: Config rule facts come out of the fan-out, resolved ------------------
has_registry_kw = "registry" in mac.collect_across_accounts.__code__.co_varnames
check("collect_across_accounts accepts the registry (the Config rule checks to run)",
      has_registry_kw)
if not has_registry_kw:
    print("\nFAIL: the fan-out has no Config-rule path; remaining checks cannot run")
    sys.exit(1)

facts = _run(["111122223331", "444455556662"])
cfg = [f for f in facts if "rule" in f]
posture = [f for f in facts if "rule" not in f and f.get("service") != "_scope"]
check("3 registry rules x 2 scopes = 6 Config facts", len(cfg) == 6)
check("1 posture collector x 2 scopes = 2 posture facts", len(posture) == 2)
check("every Config fact is tagged with account, region and run id",
      all(f.get("account") and f.get("region") == "us-east-1" and f.get("run_id") == "run-f85"
          for f in cfg))
by = {(f["account"], f["rule"]): f for f in cfg}
ev = by[("111122223331", "encrypted-volumes")]
check("encrypted-volumes resolves its exact and Security Hub instances worst-wins to "
      "NON_COMPLIANT in a member account",
      ev["compliance_type"] == "NON_COMPLIANT" and ev["instances"] == 2
      and ev["resolution"] == "deployed-names")
check("restricted-ssh, deployed only under a conformance-pack name, is COMPLIANT, not "
      "RULE_NOT_DEPLOYED",
      by[("444455556662", "restricted-ssh")]["compliance_type"] == "COMPLIANT")
check("cloudtrail-enabled, deployed nowhere, is RULE_NOT_DEPLOYED",
      by[("444455556662", "cloudtrail-enabled")]["compliance_type"] == "RULE_NOT_DEPLOYED")

# ---- AC2: a denied listing degrades to exact-name-only for that scope ----------
facts2 = _run(["111122223331", "444455556662"], deny={"444455556662"})
cfg2 = {(f["account"], f["rule"]): f for f in facts2 if "rule" in f}
check("the denied scope still yields all 3 Config facts (never sunk)",
      sum(1 for k in cfg2 if k[0] == "444455556662") == 3)
check("the denied scope's facts record exact-name-only; the other scope keeps deployed-names",
      cfg2[("444455556662", "encrypted-volumes")]["resolution"] == "exact-name-only"
      and cfg2[("111122223331", "encrypted-volumes")]["resolution"] == "deployed-names")
check("under exact-name-only the bare deployed name still evaluates (COMPLIANT) while the "
      "conformance-pack-only rule reads RULE_NOT_DEPLOYED",
      cfg2[("444455556662", "encrypted-volumes")]["compliance_type"] == "COMPLIANT"
      and cfg2[("444455556662", "restricted-ssh")]["compliance_type"] == "RULE_NOT_DEPLOYED")

# ---- AC3: the private store is in the pipeline's shape and name, and is read ---
import append_metrics as am  # noqa: E402

with tempfile.TemporaryDirectory() as d:
    facts_dir = os.path.join(d, "facts")
    path = mac.write_private_store(os.path.join(facts_dir, mac.DEFAULT_STORE_NAME),
                                   facts, "run-f85", {})
    check("default store name is facts-multi-account.json (the facts-*.json glob)",
          os.path.basename(path) == "facts-multi-account.json")
    with open(path, encoding="utf-8") as fh:
        stored = json.load(fh)
    check("store carries meta.collected_at, meta.run_id and meta.collection_outcome",
          isinstance(stored.get("meta"), dict) and stored["meta"].get("collected_at")
          and stored["meta"].get("run_id") == "run-f85"
          and isinstance(stored["meta"].get("collection_outcome"), dict))
    check("store splits Config facts from posture facts the way collect_facts.py does",
          len(stored.get("facts", [])) == 6 and len(stored.get("posture_facts", [])) == 2)
    check("the scope map stays in the store (private, never packaged)",
          "scope_map" in stored)
    saved = am.FACTS_DIR
    am.FACTS_DIR = facts_dir
    try:
        config_by_rule, posture_by_service = am.load_facts()
    finally:
        am.FACTS_DIR = saved
    check("the appender loads the fan-out's Config facts keyed by rule, one per scope",
          sorted(config_by_rule) == sorted(KNOWN)
          and all(len(v) == 2 for v in config_by_rule.values()))
    check("the appender keeps both scopes' observations (no last-writer-wins)",
          sorted(f["compliance_type"] for f in config_by_rule["encrypted-volumes"])
          == ["NON_COMPLIANT", "NON_COMPLIANT"])
    check("the appender loads the fan-out's posture facts by service",
          len(posture_by_service.get("guardduty", [])) == 2)

# ---- AC4: summarize still works over the flat fact list ------------------------
s = mac.summarize(facts)
check("summarize counts 2 accounts, 2 scopes, 0 failed, 8 facts over the combined list",
      s == {"accounts": 2, "scopes": 2, "scopes_failed_to_assume": 0, "total_facts": 8})

if FAILS:
    print(f"\n{len(FAILS)} FAILED")
    sys.exit(1)
print("\nall checks passed")
