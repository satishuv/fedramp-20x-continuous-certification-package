# Config-rule vocabulary gate test.
#
# Finding: the registry generator extracted every backtick token from guidance
# prose as an AWS Config managed rule. "aurora" (not a real managed rule; AWS
# has specific rules such as rds-cluster-multi-az-enabled) leaked in this way.
# The generator now rejects any extracted token not on the pinned allowlist
# automation/config-rules/known-config-managed-rules.json, and "aurora" is gone.
#
# Run: python validation/scripts/test_config_rule_vocabulary.py

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
import build_collector_registry as bcr  # noqa: E402

_fail = 0


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def main():
    known = bcr.load_known_config_rules()
    check("allowlist loads and is non-empty", len(known) >= 30)
    check("allowlist does NOT contain the bogus 'aurora'", "aurora" not in known)
    check("allowlist contains the real rules aurora was standing in for",
          {"rds-multi-az-support", "elb-cross-zone-load-balancing-enabled"} <= known)

    # Every config_managed_rule target in the generated registry is on the
    # allowlist (the fail-closed gate guarantees this at build time).
    reg = json.load(open(os.path.join(BASE, "automation", "collectors", "registry.json"),
                         encoding="utf-8"))
    targets = {c["target"] for k in reg["ksis"].values() for c in k["checks"]
               if c.get("type") == "config_managed_rule"}
    off_list = targets - known
    check("no registry config-rule target is outside the allowlist",
          not off_list)
    check("aurora is not a rule target in the registry", "aurora" not in targets)

    # The pinned catalog identifiers (Source.SourceIdentifier of each managed
    # rule, read from the AWS Config Developer Guide) stay aligned with the id
    # list: one identifier per id, no extras, no duplicates. The export
    # importer resolves deployed rules through this map rather than guessing
    # an identifier from the name (restricted-ssh is INCOMING_SSH_DISABLED).
    vocab = json.load(open(os.path.join(BASE, "automation", "config-rules",
                                        "known-config-managed-rules.json"),
                           encoding="utf-8"))
    idents = vocab.get("config_managed_rule_identifiers") or {}
    check("every allowlisted id has exactly one pinned catalog identifier",
          set(idents) == set(vocab["config_managed_rule_ids"]) == known)
    check("catalog identifiers are unique", len(set(idents.values())) == len(idents))
    check("the four irregular identifiers are pinned as documented",
          idents.get("restricted-ssh") == "INCOMING_SSH_DISABLED"
          and idents.get("restricted-common-ports") == "RESTRICTED_INCOMING_TRAFFIC"
          and idents.get("cloudtrail-enabled") == "CLOUD_TRAIL_ENABLED"
          and idents.get("multi-region-cloudtrail-enabled") == "MULTI_REGION_CLOUD_TRAIL_ENABLED")
    check("meta.count matches the id list", vocab["meta"]["count"] == len(known))

    print(f"\n{'PASS' if not _fail else 'FAIL'}: config-rule vocabulary "
          f"({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
