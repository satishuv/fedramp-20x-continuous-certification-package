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


def _import_resolution():
    try:
        import config_rule_resolution as crr
    except ImportError:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "config_rule_resolution",
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "config_rule_resolution.py"))
        crr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(crr)
    return crr


def resolve_deployed_rules(config, known_ids, client_error):
    """AUD-F84: {framework id: [deployed names]} for the account's Config rules,
    via one paginated config:DescribeConfigRules read. Returns (mapping,
    resolution) where resolution is "deployed-names" on success or
    "exact-name-only" when the listing was denied (a role predating the
    DescribeConfigRules grant): the caller then falls back to the exact-name
    lookup and the facts say so, rather than reporting every rule as not
    deployed with no hint why."""
    crr = _import_resolution()
    rules = []
    try:
        token = None
        while True:
            kw = {"NextToken": token} if token else {}
            resp = config.describe_config_rules(**kw)
            rules.extend(resp.get("ConfigRules", []))
            token = resp.get("NextToken")
            if not token:
                break
    except Exception as e:  # noqa: BLE001 - a failed listing must not sink the run
        code = (getattr(e, "response", None) or {}).get("Error", {}).get("Code") \
            or type(e).__name__
        print(f"  (config:DescribeConfigRules {code}: resolving registry rules by "
              "exact ConfigRuleName only; deployed Security Hub or conformance-pack "
              "names are invisible until the collector role grants it)")
        return {}, "exact-name-only"
    mapping = crr.resolve_deployed_names(rules, known_ids, crr.catalog_identifiers())
    return mapping, "deployed-names"


def _compliance_for_names(config, names, client_error):
    """{deployed name: ComplianceType} for up to any number of names, in the
    API's chunks of 25. A name AWS does not return is absent from the result."""
    out = {}
    for i in range(0, len(names), 25):
        chunk = names[i:i + 25]
        resp = config.describe_compliance_by_config_rule(ConfigRuleNames=chunk)
        for row in resp.get("ComplianceByConfigRules", []):
            name = row.get("ConfigRuleName")
            if name:
                out[name] = (row.get("Compliance") or {}).get("ComplianceType", "UNKNOWN")
    return out


def registry_rule_checks(registry):
    """{Config managed-rule catalog name: [check ids]} for every collectable
    config_managed_rule check in the registry, across all KSIs."""
    rule_to_checks = {}
    for kid, entry in registry["ksis"].items():
        for check in entry["checks"]:
            if check.get("collectable_now") and check["type"] == "config_managed_rule":
                rule_to_checks.setdefault(check["target"], []).append(check["check_id"])
    return rule_to_checks


def _client_error_code(e):
    """The AWS error code of a ClientError-shaped exception, else its type."""
    resp = getattr(e, "response", None) or {}
    return (resp.get("Error") or {}).get("Code") or type(e).__name__


def collect_config_rule_facts(session, registry, region, now=None, echo=print):
    """One account-region scope's registry Config rule facts, read-only.

    This is the per-scope unit the single-account driver and the multi-account
    fan-out share (AUD-F85): before it existed the loop lived inline in main()
    and the fan-out ran only the posture collectors, so a member account's
    Config rules never reached a metric. Resolves catalog names to deployed
    names once per scope (AUD-F84), evaluates each resolved name, aggregates
    worst-wins. Never raises: a failed Config client yields one ERROR fact per
    registry rule rather than sinking the scope. ``echo`` receives one line per
    rule (pass a no-op to run quietly)."""
    now = now or datetime.now(timezone.utc).isoformat(timespec="seconds")
    rule_to_checks = registry_rule_checks(registry)
    try:
        config = session.client("config")
    except Exception as e:  # noqa: BLE001 - one scope must not sink a run
        code = _client_error_code(e)
        return [{"rule": rule, "check_ids": check_ids, "collected_at": now,
                 "region": region, "resolution": "exact-name-only",
                 "compliance_type": f"ERROR:{code}", "instances": 0}
                for rule, check_ids in sorted(rule_to_checks.items())]

    facts = []
    # AUD-F84: resolve the registry's catalog names to the names the account
    # actually deploys (Security Hub, conformance packs, provider templates).
    crr = _import_resolution()
    deployed, resolution = resolve_deployed_rules(config, set(rule_to_checks), Exception)
    for rule, check_ids in sorted(rule_to_checks.items()):
        fact = {"rule": rule, "check_ids": check_ids, "collected_at": now,
                "region": region, "resolution": resolution}
        names = deployed.get(rule, []) if resolution == "deployed-names" else [rule]
        if not names:
            fact["compliance_type"] = "RULE_NOT_DEPLOYED"
            fact["instances"] = 0
        else:
            try:
                by_name = _compliance_for_names(config, names, Exception)
                found = {n: ct for n, ct in by_name.items() if n in names}
                if found:
                    fact["compliance_type"] = crr.worst_wins(found.values())
                    fact["instances"] = len(found)
                    fact["deployed_names"] = sorted(found)
                else:
                    fact["compliance_type"] = "RULE_NOT_DEPLOYED"
                    fact["instances"] = 0
            except Exception as e:  # noqa: BLE001 - one rule must not sink the scope
                code = _client_error_code(e)
                fact["compliance_type"] = ("RULE_NOT_DEPLOYED"
                                           if code == "NoSuchConfigRuleException"
                                           else f"ERROR:{code}")
        facts.append(fact)
        suffix = f" ({fact.get('instances', 0)} deployed)" if fact.get("instances") else ""
        echo(f"  {rule}: {fact['compliance_type']}{suffix}")
    return facts


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

    region = session.region_name or "unknown-region"
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    facts = collect_config_rule_facts(session, registry, region, now=now)

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
    imported = os.path.join(FACTS_DIR, f"facts-{region}-import.json")
    if os.path.exists(imported):
        # One source per region. The appender sums posture facts per route
        # across files, so a live collection beside an import of the same
        # region would count that scope twice. The import is now superseded.
        print(f"WARNING: an export import exists for {region} "
              f"({os.path.relpath(imported, BASE)}). Remove it; this live collection "
              "supersedes it, and keeping both double-counts the region's posture.")
    outcome = collection_outcome(facts, posture_facts)
    outcome["status"] = "OK" if outcome["evaluated"] else "FAILED_NO_EVALUATED_OUTCOME"
    # AUD-F37: one id per collection run, derived from when/where/who collected
    # (no account id in the clear: the identity is hashed). The appender stamps
    # it, with the facts store digest, on every observation this run produces.
    import hashlib
    run_id = "run-" + hashlib.sha256(f"{now}|{region}|{arn}".encode("utf-8")).hexdigest()[:16]
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        json.dump({
            "meta": {
                "collected_at": now,
                "run_id": run_id,
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
