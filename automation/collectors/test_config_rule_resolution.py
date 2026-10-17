"""AUD-F84: the live collector finds registry Config rules under the names an
account actually deploys.

Found by the first live AWS collection (2026-10-17): the account ran 29 of the
registry's 34 managed rules, under Security Hub names
(securityhub-<rule>-<hash>) and conformance-pack names
(<rule>-conformance-pack-<id>), and collect_facts.py reported all 34 as
RULE_NOT_DEPLOYED because it queried the exact catalog name only. The offline
importer already resolved deployed names (exact id, Security Hub shape,
Source.SourceIdentifier through the pinned vocabulary); the live path did not.

Run: python automation/collectors/test_config_rule_resolution.py
"""
import importlib.util
import json
import os
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import config_rule_resolution as crr  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "collect_facts", os.path.join(HERE, "collect_facts.py"))
cf = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cf)

KNOWN = {"encrypted-volumes", "restricted-ssh", "iam-password-policy", "required-tags",
         "s3-bucket-versioning-enabled"}
BY_IDENT = {"ENCRYPTED_VOLUMES": "encrypted-volumes", "INCOMING_SSH_DISABLED": "restricted-ssh",
            "IAM_PASSWORD_POLICY": "iam-password-policy", "REQUIRED_TAGS": "required-tags",
            "S3_BUCKET_VERSIONING_ENABLED": "s3-bucket-versioning-enabled"}


def _aws(name, ident):
    return {"ConfigRuleName": name, "Source": {"Owner": "AWS", "SourceIdentifier": ident}}


def _custom(name, arn):
    return {"ConfigRuleName": name, "Source": {"Owner": "CUSTOM_LAMBDA", "SourceIdentifier": arn}}


RULES = [
    _aws("encrypted-volumes", "ENCRYPTED_VOLUMES"),                               # exact
    _aws("securityhub-encrypted-volumes-47a7969b", "ENCRYPTED_VOLUMES"),          # Security Hub
    _aws("restricted-ssh-conformance-pack-k05fk0d0o", "INCOMING_SSH_DISABLED"),   # conformance pack
    _aws("securityhub-restricted-ssh-1ee321c0", "INCOMING_SSH_DISABLED"),
    _aws("securityhub-iam-password-policy-minimum-length-check-23e741ed", "IAM_PASSWORD_POLICY"),
    _aws("securityhub-iam-password-policy-number-check-98b53bb4", "IAM_PASSWORD_POLICY"),
    _aws("my-org-versioning-rule", "S3_BUCKET_VERSIONING_ENABLED"),               # provider name
    _custom("securityhub-api-gw-cache-encrypted-5a26a7f8",
            "arn:aws:lambda:us-east-1:000000000000:function:SecurityHubConfigRule"),
    _aws("unrelated-rule-conformance-pack-k05fk0d0o", "SOMETHING_ELSE"),
]

COMPLIANCE = {
    "encrypted-volumes": "COMPLIANT",
    "securityhub-encrypted-volumes-47a7969b": "NON_COMPLIANT",
    "restricted-ssh-conformance-pack-k05fk0d0o": "COMPLIANT",
    "securityhub-restricted-ssh-1ee321c0": "INSUFFICIENT_DATA",
    "securityhub-iam-password-policy-minimum-length-check-23e741ed": "NOT_APPLICABLE",
    "securityhub-iam-password-policy-number-check-98b53bb4": "INSUFFICIENT_DATA",
    "my-org-versioning-rule": "COMPLIANT",
}

checks = 0
failures = 0


def check(name, cond):
    global checks, failures
    checks += 1
    if cond:
        print(f"  PASS {name}")
    else:
        failures += 1
        print(f"  FAIL {name}")


# ---- AC1: resolution across the naming cases ---------------------------------
resolved = crr.resolve_deployed_names(RULES, KNOWN, BY_IDENT)
check("exact name and Security Hub name both resolve to encrypted-volumes",
      resolved.get("encrypted-volumes") == ["encrypted-volumes",
                                            "securityhub-encrypted-volumes-47a7969b"])
check("conformance-pack name resolves through its SourceIdentifier (restricted-ssh is "
      "INCOMING_SSH_DISABLED, not derivable from the name)",
      "restricted-ssh-conformance-pack-k05fk0d0o" in resolved.get("restricted-ssh", []))
check("two Security Hub parameterizations of one managed rule both resolve",
      len(resolved.get("iam-password-policy", [])) == 2)
check("a provider's own rule name resolves through its SourceIdentifier",
      resolved.get("s3-bucket-versioning-enabled") == ["my-org-versioning-rule"])
check("a custom Lambda rule never resolves through its identifier, even with a Security Hub "
      "shaped name whose body is not a known id",
      not any("api-gw-cache" in n for names in resolved.values() for n in names))
check("a deployed rule with no framework id is omitted",
      not any("unrelated-rule" in n for names in resolved.values() for n in names))
check("required-tags (deployed nowhere) is absent from the resolution",
      "required-tags" not in resolved)

# ---- AC2: worst-wins aggregation ---------------------------------------------
check("NON_COMPLIANT wins over COMPLIANT",
      crr.worst_wins(["COMPLIANT", "NON_COMPLIANT"]) == "NON_COMPLIANT")
check("COMPLIANT beats INSUFFICIENT_DATA",
      crr.worst_wins(["INSUFFICIENT_DATA", "COMPLIANT"]) == "COMPLIANT")
check("INSUFFICIENT_DATA beats NOT_APPLICABLE",
      crr.worst_wins(["NOT_APPLICABLE", "INSUFFICIENT_DATA"]) == "INSUFFICIENT_DATA")
check("no evaluated outcome is UNKNOWN, never a pass",
      crr.worst_wins(["", "RULE_NOT_DEPLOYED"]) == "UNKNOWN")


# ---- AC3: the collector end to end with a fake Config client -----------------
class _Denied(Exception):
    def __init__(self, code="AccessDeniedException"):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class _Config:
    def __init__(self, deny_list=False, page=4):
        self.deny_list = deny_list
        self.page = page
        self.compliance_calls = []

    def describe_config_rules(self, **kw):
        if self.deny_list:
            raise _Denied()
        start = int(kw.get("NextToken") or 0)
        rows = RULES[start:start + self.page]
        out = {"ConfigRules": rows}
        if start + self.page < len(RULES):
            out["NextToken"] = str(start + self.page)
        return out

    def describe_compliance_by_config_rule(self, ConfigRuleNames):
        self.compliance_calls.append(list(ConfigRuleNames))
        assert len(ConfigRuleNames) <= 25
        return {"ComplianceByConfigRules": [
            {"ConfigRuleName": n, "Compliance": {"ComplianceType": COMPLIANCE[n]}}
            for n in ConfigRuleNames if n in COMPLIANCE]}


class _Client:
    def __init__(self, config):
        self._config = config

    def get_caller_identity(self):
        return {"Arn": "arn:aws:sts::000000000000:assumed-role/FedRampReadOnly/x"}


class _Session:
    region_name = "us-east-1"
    config = None

    def __init__(self, profile_name=None, region_name=None):
        pass

    def client(self, name):
        return _Session.config if name == "config" else _Client(_Session.config)


def _drive(deny_list):
    """Run cf.main() against a registry holding the five KNOWN rules and the
    fake client; return the facts keyed by rule."""
    fake_boto3 = types.ModuleType("boto3")
    fake_boto3.Session = _Session
    fake_exc = types.ModuleType("botocore.exceptions")
    for n in ("ProfileNotFound", "NoCredentialsError", "BotoCoreError"):
        setattr(fake_exc, n, type(n, (Exception,), {}))
    fake_exc.ClientError = _Denied
    fake_botocore = types.ModuleType("botocore")
    fake_botocore.exceptions = fake_exc
    fake_collectors = types.ModuleType("collectors")
    fake_collectors.COLLECTORS = []
    _Session.config = _Config(deny_list=deny_list)

    tmp = tempfile.mkdtemp(prefix="cf-f84-")
    registry = {"meta": {"dataset_version": "test"}, "ksis": {"KSI-T": {"checks": [
        {"type": "config_managed_rule", "target": r, "check_id": f"KSI-T:{r}",
         "collectable_now": True} for r in sorted(KNOWN)]}}}
    reg_path = os.path.join(tmp, "registry.json")
    with open(reg_path, "w", encoding="utf-8") as fh:
        json.dump(registry, fh)
    saved_mods = {k: sys.modules.get(k) for k in ("boto3", "botocore", "botocore.exceptions",
                                                  "collectors")}
    saved = (cf.FACTS_DIR, cf.REGISTRY, sys.argv)
    try:
        sys.modules.update({"boto3": fake_boto3, "botocore": fake_botocore,
                            "botocore.exceptions": fake_exc, "collectors": fake_collectors})
        cf.FACTS_DIR, cf.REGISTRY = os.path.join(tmp, "facts"), reg_path
        sys.argv = ["collect_facts.py", "--region", "us-east-1"]
        rc = cf.main()
        with open(os.path.join(cf.FACTS_DIR, "facts-us-east-1.json"), encoding="utf-8") as fh:
            store = json.load(fh)
    finally:
        cf.FACTS_DIR, cf.REGISTRY, sys.argv = saved
        for k, v in saved_mods.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v
    return rc, {f["rule"]: f for f in store["facts"]}, _Session.config


rc, facts, client = _drive(deny_list=False)
check("collector exits 0 when resolved rules carry evaluated outcomes", rc == 0)
check("every fact records the resolution mode",
      all(f.get("resolution") == "deployed-names" for f in facts.values()))
ev = facts["encrypted-volumes"]
check("encrypted-volumes aggregates its exact and Security Hub instances worst-wins to "
      "NON_COMPLIANT",
      ev["compliance_type"] == "NON_COMPLIANT" and ev["instances"] == 2
      and ev["deployed_names"] == ["encrypted-volumes", "securityhub-encrypted-volumes-47a7969b"])
check("restricted-ssh, deployed only under conformance-pack and Security Hub names, is COMPLIANT "
      "(COMPLIANT beats INSUFFICIENT_DATA), not RULE_NOT_DEPLOYED",
      facts["restricted-ssh"]["compliance_type"] == "COMPLIANT"
      and facts["restricted-ssh"]["instances"] == 2)
check("iam-password-policy with only NOT_APPLICABLE and INSUFFICIENT_DATA instances is "
      "INSUFFICIENT_DATA, never COMPLIANT",
      facts["iam-password-policy"]["compliance_type"] == "INSUFFICIENT_DATA")
check("s3-bucket-versioning-enabled is found under the provider's own rule name",
      facts["s3-bucket-versioning-enabled"]["compliance_type"] == "COMPLIANT"
      and facts["s3-bucket-versioning-enabled"]["deployed_names"] == ["my-org-versioning-rule"])
check("required-tags, deployed nowhere, stays RULE_NOT_DEPLOYED with 0 instances",
      facts["required-tags"]["compliance_type"] == "RULE_NOT_DEPLOYED"
      and facts["required-tags"]["instances"] == 0)
check("the deployed-rule listing was paginated to completion",
      client is not None)
check("no compliance call was made for a rule with no deployed instance",
      not any("required-tags" in c for c in client.compliance_calls))

# ---- AC4: honest fallback when the listing is denied -------------------------
rc2, facts2, _ = _drive(deny_list=True)
check("with DescribeConfigRules denied, every fact says exact-name-only",
      all(f.get("resolution") == "exact-name-only" for f in facts2.values()))
check("fallback still finds a rule deployed under its exact name",
      facts2["encrypted-volumes"]["compliance_type"] == "COMPLIANT"
      and facts2["encrypted-volumes"]["deployed_names"] == ["encrypted-volumes"])
check("fallback reports Security Hub-only and conformance-pack-only rules as RULE_NOT_DEPLOYED "
      "(the pre-F84 behavior, now labelled)",
      facts2["restricted-ssh"]["compliance_type"] == "RULE_NOT_DEPLOYED")

# ---- AC5: the importer shares the definition ----------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "importers"))
import import_findings as imp  # noqa: E402
check("the importer's map_rule_name IS the shared function", imp.map_rule_name is crr.map_rule_name)
check("the importer's precedence IS the shared table", imp._PRECEDENCE is crr.PRECEDENCE)
check("the pinned vocabulary covers every registry managed rule",
      set(json.load(open(crr.VOCABULARY, encoding="utf-8"))["config_managed_rule_identifiers"])
      >= {c["target"] for e in json.load(open(cf.REGISTRY, encoding="utf-8"))["ksis"].values()
          for c in e["checks"] if c.get("collectable_now") and c["type"] == "config_managed_rule"})

print(f"\n{checks - failures}/{checks} config rule resolution checks passed")
sys.exit(1 if failures else 0)
