# Layer 1 facts collector: execute the collectable checks in registry.json
# against an AWS account, read-only, and write a timestamped facts store.
#
# Read-only by construction: every AWS call is a describe/list/get enumerated in
# automation/collectors/collectors.py READ_ONLY_ACTIONS (Security Hub, Access
# Analyzer, Inspector, GuardDuty, Config, CloudTrail, S3, IAM, and more), plus
# sts:GetCallerIdentity. The deployed CollectorRole grants exactly that set and
# is what enforces read-only behavior in the AWS path. Run with ReadOnly or
# least-privilege credentials; never with admin credentials.
#
# Facts are telemetry, not statuses. This script never writes to the record
# store and never marks anything Implemented; it produces evidence for a
# human (or a gated pipeline step) to act on. The facts store carries real
# run timestamps because it is telemetry; it is excluded from git.
#
# Usage: python automation/collectors/collect_facts.py [--profile NAME] [--region REGION]

import argparse
import json
import os
import sys
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REGISTRY = os.path.join(BASE, "automation", "collectors", "registry.json")
FACTS_DIR = os.path.join(BASE, "automation", "facts")

# AUD-F29: a collection run that produced NO evaluated outcome is a FAILED run,
# not an empty success. Exit code 4 is distinct from the publisher's 3 (CAS
# conflict, retried by the AWS buildspec) so the scheduled loops fail loudly
# instead of recording an empty day as a valid day of evidence.
EXIT_NO_EVALUATED = 4

# Config compliance types that are an EVALUATED outcome (the rule exists and
# AWS Config returned a result for it). RULE_NOT_DEPLOYED, ERROR:* and UNKNOWN
# carry no evaluation.
EVALUATED_CONFIG = {"COMPLIANT", "NON_COMPLIANT", "INSUFFICIENT_DATA"}


def collection_outcome(facts, posture_facts):
    """Tally one run's facts into {evaluated, unevaluated, errors}.

    evaluated: Config facts with a compliance result, plus posture facts whose
    status is not an ERROR* / UNKNOWN. unevaluated: everything else (rule not
    deployed, collector errors, unknown). errors: the subset of unevaluated that
    is an explicit ERROR. A run with evaluated == 0 observed NOTHING about the
    boundary (wrong region, expired credentials, every service denied) and must
    be reported as a failed collection (EXIT_NO_EVALUATED), never as success.
    """
    evaluated = unevaluated = errors = 0
    for fact in facts or []:
        ct = str(fact.get("compliance_type") or "")
        if ct in EVALUATED_CONFIG:
            evaluated += 1
        else:
            unevaluated += 1
            if ct.startswith("ERROR"):
                errors += 1
    for pf in posture_facts or []:
        st = str(pf.get("status") or "")
        if st.startswith("ERROR") or st in ("UNKNOWN", ""):
            unevaluated += 1
            errors += 1 if st.startswith("ERROR") else 0
        else:
            evaluated += 1
    return {"evaluated": evaluated, "unevaluated": unevaluated, "errors": errors}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default=None, help="AWS profile (use a ReadOnly one)")
    ap.add_argument("--region", default=None, help="AWS region (defaults to profile/env region)")
    args = ap.parse_args()

    try:
        import boto3
        import botocore.exceptions
    except ImportError:
        print("boto3 is required: pip install boto3")
        return 1

    registry = json.load(open(REGISTRY, encoding="utf-8"))
    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        ident = session.client("sts").get_caller_identity()
    except (botocore.exceptions.ProfileNotFound,
            botocore.exceptions.NoCredentialsError,
            botocore.exceptions.ClientError,
            botocore.exceptions.BotoCoreError) as e:
        print(f"No usable AWS credentials ({type(e).__name__}); nothing collected. "
              "Configure a ReadOnly profile and re-run.")
        return 1
    arn = ident.get("Arn", "")
    if "admin" in arn.lower():
        print(f"Refusing to run with an admin-looking identity: {arn}. "
              "Use ReadOnly or least-privilege credentials.")
        return 1

    config = session.client("config")
    region = session.region_name or "unknown-region"
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # Gather the unique Config managed rule names across all KSIs.
    rule_to_checks = {}
    for kid, entry in registry["ksis"].items():
        for check in entry["checks"]:
            if check.get("collectable_now") and check["type"] == "config_managed_rule":
                rule_to_checks.setdefault(check["target"], []).append(check["check_id"])

    facts = []
    for rule, check_ids in sorted(rule_to_checks.items()):
        fact = {"rule": rule, "check_ids": check_ids, "collected_at": now,
                "region": region}
        try:
            resp = config.describe_compliance_by_config_rule(ConfigRuleNames=[rule])
            results = resp.get("ComplianceByConfigRules", [])
            if results:
                comp = results[0].get("Compliance", {})
                fact["compliance_type"] = comp.get("ComplianceType", "UNKNOWN")
            else:
                fact["compliance_type"] = "RULE_NOT_DEPLOYED"
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "ClientError")
            fact["compliance_type"] = ("RULE_NOT_DEPLOYED"
                                       if code == "NoSuchConfigRuleException" else f"ERROR:{code}")
        facts.append(fact)
        print(f"  {rule}: {fact['compliance_type']}")

    # Broadened read-only posture collectors (Security Hub, Access Analyzer,
    # Inspector, GuardDuty, Backup, KMS). Each is read-only and self-contained;
    # a single service failure yields an ERROR fact rather than sinking the run.
    posture_facts = []
    try:
        from collectors import COLLECTORS
    except ImportError:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "collectors", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                       "collectors.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        COLLECTORS = mod.COLLECTORS
    print("posture collectors:")
    for name, fn in COLLECTORS:
        try:
            svc_facts = fn(session, region)
        except Exception as e:  # noqa: BLE001 - one service must not sink the run
            svc_facts = [{"service": name, "check": "collector", "status": "ERROR",
                          "detail": type(e).__name__, "region": region,
                          "collected_at": now}]
        posture_facts.extend(svc_facts)
        for f in svc_facts:
            print(f"  {f['service']}.{f['check']}: {f['status']}")

    os.makedirs(FACTS_DIR, exist_ok=True)
    out = os.path.join(FACTS_DIR, f"facts-{region}.json")
    outcome = collection_outcome(facts, posture_facts)
    outcome["status"] = "OK" if outcome["evaluated"] else "FAILED_NO_EVALUATED_OUTCOME"
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump({
            "meta": {
                "collected_at": now,
                "region": region,
                "identity_arn": arn,
                "registry_dataset_version": registry["meta"]["dataset_version"],
                # AUD-F29: the run's own verdict travels with its facts, so a
                # downstream reader can tell an empty failed run from a quiet
                # healthy one without re-deriving it.
                "collection_outcome": outcome,
                "note": ("Facts are read-only telemetry, not statuses. "
                         "Never commit this file; it may identify a real account."),
            },
            "facts": facts,
            "posture_facts": posture_facts,
        }, f, indent=1)
    deployed = sum(1 for x in facts if x["compliance_type"] in EVALUATED_CONFIG)
    print(f"wrote {out}: {len(facts)} config rules checked ({deployed} deployed), "
          f"{len(posture_facts)} posture facts across "
          f"{len({p['service'] for p in posture_facts})} services; "
          f"evaluated outcomes: {outcome['evaluated']}, unevaluated: "
          f"{outcome['unevaluated']} (errors: {outcome['errors']})")
    if outcome["evaluated"] == 0:
        # AUD-F29: nothing about the boundary was actually observed. Every
        # check errored, was denied, or found no deployed rule. Reporting
        # success here would let the appender stamp an empty day and the
        # scheduled loops stay green for weeks on no evidence at all.
        print("FAIL. Collection produced NO evaluated outcome (every check errored, "
              "was denied or found nothing deployed). This is a failed collection, "
              "not an empty success: check credentials, region and the collector "
              "role's read-only grants. Facts were written for diagnosis only.")
        return EXIT_NO_EVALUATED
    return 0


if __name__ == "__main__":
    sys.exit(main())
