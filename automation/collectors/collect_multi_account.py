"""Multi-account, multi-region evidence fan-out (read-only).

The width lever for a large FedRAMP boundary: a 400-service estate is almost
always many AWS accounts across an AWS Organization. This module assumes a
READ-ONLY role into each target account and runs every collector across the
chosen regions in parallel, tagging each fact with its account and region.

Read-only by construction:
  - The only privileged call is sts:AssumeRole into a role the operator names;
    that role must itself grant only the READ_ONLY_ACTIONS the collectors use.
  - Admin-looking role names are refused, mirroring the single-account driver.
  - One account or region failing yields an ERROR fact for that scope, never a
    crash and never a sunk aggregate: partial evidence is still evidence.

This module builds sessions and fans out; it does not decide statuses and never
writes the record store. Facts are telemetry.

Scope identity (AUD-F27). Every fact is tagged with its raw `account` (private
store only) and with a `run_id` for this collection. When a scope key is
available (SDR_EVIDENCE_SCOPE_KEY, or `scope_key=`) each fact also carries the
OPAQUE `scope` id evidence_wiring derives from the account, and `scope_map()`
returns the private scope -> account map an assessor needs. The export
boundary (evidence_wiring.fact_to_evidence) refuses an account-tagged fact that
has no scope, so two accounts' observations can never collide on one evidence
pointer and the raw account never reaches the package.

Usage (library):
    from collect_multi_account import collect_across_accounts
    facts = collect_across_accounts(
        accounts=["111122223333", "444455556666"],
        role_name="FedRampReadOnly",
        regions=["us-east-1", "us-west-2"],
        base_session=boto3.Session(),
        scope_key=os.environ["SDR_EVIDENCE_SCOPE_KEY"],
        registry=json.load(open("automation/collectors/registry.json")),
    )

Usage (CLI):
    python collect_multi_account.py --accounts 111122223333,444455556666 \
        --role-name FedRampReadOnly --regions us-east-1,us-west-2
    # writes automation/facts/facts-multi-account.json (git-excluded private
    # store, in the shape the appender and prefill read; AUD-F85)
"""
import argparse
import concurrent.futures as cf
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collectors as _collectors  # noqa: E402
import collect_facts as _cf  # noqa: E402
import evidence_wiring as _ew  # noqa: E402

# Default worker cap: enough to fan out a large estate without hammering the
# host or tripping API rate limits. Tunable per call.
DEFAULT_MAX_WORKERS = 16

SCOPE_KEY_ENV = "SDR_EVIDENCE_SCOPE_KEY"

# AUD-F85: the private store is a facts-*.json in the same {meta, facts,
# posture_facts} shape collect_facts.py writes, because that glob and shape are
# what every downstream reader opens (append_metrics, prefill_from_facts, the
# drafters, rollup_evidence). The earlier flat multi-account.json was never read.
DEFAULT_STORE_NAME = "facts-multi-account.json"


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _scope_error_fact(account, region, detail):
    """A single account/region scope failed to even start: record it as one
    ERROR fact rather than dropping the scope silently."""
    return {
        "service": "_scope",
        "check": "assume_role",
        "status": "ERROR",
        "detail": detail[:480],
        "region": region,
        "account": account,
        "collected_at": _now(),
    }


def assume_role_session(base_session, account, role_name, region,
                        session_name="fedramp-sdr-collector"):
    """Return a boto3 Session for `account` via sts:AssumeRole into `role_name`.

    Refuses admin-looking role names: evidence collection must use a read-only
    role, not an administrative one. Raises on failure; callers convert that
    into a scope ERROR fact so one bad account cannot sink the run.
    """
    if "admin" in role_name.lower():
        raise ValueError(f"Refusing an admin-looking role name: {role_name}. "
                         "Use a read-only role.")
    import boto3
    sts = base_session.client("sts")
    # Derive the partition from the caller's own identity ARN rather than
    # hardcoding "aws": GovCloud is "aws-us-gov", China is "aws-cn". A hardcoded
    # commercial partition makes the assume-role ARN invalid in those regions.
    try:
        caller_arn = sts.get_caller_identity().get("Arn", "")
        partition = caller_arn.split(":")[1] if caller_arn.startswith("arn:") else "aws"
    except Exception:  # noqa: BLE001
        partition = "aws"
    role_arn = f"arn:{partition}:iam::{account}:role/{role_name}"
    creds = sts.assume_role(RoleArn=role_arn,
                            RoleSessionName=session_name)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )


def _collect_one_scope(base_session, account, role_name, region, collectors,
                       registry=None):
    """Assume into one account and run, for one region, the registry's Config
    rule checks (when a registry is given; AUD-F85) and every posture collector.
    Returns a list of account-tagged facts; never raises."""
    try:
        session = assume_role_session(base_session, account, role_name, region)
    except Exception as e:  # noqa: BLE001 - a bad account must not sink the run
        return [_scope_error_fact(account, region,
                                  f"{type(e).__name__}: {e}")]
    facts = []
    if registry is not None:
        # The same per-scope unit the single-account driver runs, so a member
        # account's Config rules resolve (AUD-F84) and reach the appender
        # exactly as the management account's do. Quiet: one fan-out can span
        # hundreds of scopes, and the summary line reports the totals.
        try:
            rule_facts = _cf.collect_config_rule_facts(session, registry, region,
                                                       echo=lambda _line: None)
        except Exception as e:  # noqa: BLE001 - contract: it does not raise,
            # but a scope's Config outage must not sink its posture facts.
            rule_facts = [{
                "service": "config", "check": "registry_rules", "status": "ERROR",
                "detail": type(e).__name__, "region": region,
                "collected_at": _now(),
            }]
        for f in rule_facts:
            f["account"] = account
            facts.append(f)
    for name, fn in collectors:
        try:
            svc_facts = fn(session, region)
        except Exception as e:  # noqa: BLE001 - contract: collectors don't raise,
            # but defend anyway so one service cannot sink the account.
            svc_facts = [{
                "service": name, "check": "collector", "status": "ERROR",
                "detail": type(e).__name__, "region": region,
                "collected_at": _now(),
            }]
        for f in svc_facts:
            f["account"] = account  # tag provenance
            facts.append(f)
    return facts


def scope_map(accounts, scope_key):
    """The PRIVATE opaque-scope -> account map for this deployment. Written
    beside the facts in the git-excluded store so an assessor can reconstruct
    account-level coverage; it must never enter the package."""
    return {_ew.scope_id(a, scope_key): a for a in accounts}


def collect_across_accounts(accounts, role_name, regions, base_session=None,
                            collectors=None, max_workers=DEFAULT_MAX_WORKERS,
                            run_id=None, scope_key=None, registry=None):
    """Fan every collector across every (account, region) scope in parallel.

    Returns a flat list of account+region-tagged facts. Deterministic in
    membership (every scope contributes either facts or one ERROR fact), so a
    caller can always compute coverage as scopes_ok / scopes_total.

    Every fact is stamped with `run_id` (generated when not supplied) and, when
    `scope_key` is given, with the opaque `scope` derived from its account.

    `registry` (the loaded registry.json) switches on the registry Config rule
    checks per scope (AUD-F85); the CLI always passes it. Library callers that
    want posture facts only may leave it None.
    """
    if base_session is None:
        import boto3
        base_session = boto3.Session()
    collectors = collectors or _collectors.COLLECTORS
    run_id = run_id or _ew.new_run_id()
    scopes_by_account = scope_map(accounts, scope_key) if scope_key else {}
    account_to_scope = {a: s for s, a in scopes_by_account.items()}

    scopes = [(a, r) for a in accounts for r in regions]
    results = []
    with cf.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {
            ex.submit(_collect_one_scope, base_session, a, role_name, r, collectors,
                      registry): (a, r)
            for (a, r) in scopes
        }
        for fut in cf.as_completed(futs):
            for f in fut.result():
                f["run_id"] = run_id
                s = account_to_scope.get(f.get("account"))
                if s:
                    f["scope"] = s
                results.append(f)
    return results


def summarize(facts):
    """Aggregate stats over a multi-account fact list, for a run summary."""
    accounts = {f.get("account") for f in facts if f.get("account")}
    scopes = {(f.get("account"), f.get("region")) for f in facts}
    scope_errors = {(f["account"], f["region"]) for f in facts
                    if f.get("service") == "_scope" and f["status"] == "ERROR"}
    return {
        "accounts": len(accounts),
        "scopes": len(scopes),
        "scopes_failed_to_assume": len(scope_errors),
        "total_facts": len(facts),
    }


def split_facts(facts):
    """(config_rule_facts, posture_facts): a Config rule fact carries ``rule``
    (collect_facts.py shape); everything else, including a scope ERROR, is a
    posture fact. The appender tallies the two lists differently."""
    rule_facts = [f for f in facts if "rule" in f]
    posture = [f for f in facts if "rule" not in f]
    return rule_facts, posture


def write_private_store(path, facts, run_id, scopes, registry_dataset_version=None):
    """Persist a run to the git-excluded private facts store in the same shape
    collect_facts.py writes (AUD-F85): ``meta`` with the run id and the run's
    own collection outcome, Config rule facts under ``facts``, posture facts
    under ``posture_facts``, plus the PRIVATE scope -> account map. Name it
    facts-*.json (DEFAULT_STORE_NAME) so the appender and prefill read it.
    This file identifies real accounts and must never be committed or packaged."""
    rule_facts, posture = split_facts(facts)
    outcome = _cf.collection_outcome(rule_facts, posture)
    outcome["status"] = "OK" if outcome["evaluated"] else "FAILED_NO_EVALUATED_OUTCOME"
    payload = {
        "meta": {
            "collected_at": _now(),
            "run_id": run_id,
            "registry_dataset_version": registry_dataset_version,
            "collection_outcome": outcome,
            "note": ("Multi-account facts are read-only telemetry, not statuses. "
                     "Never commit this file; it names real accounts."),
        },
        "scope_map": scopes,
        "facts": rule_facts,
        "posture_facts": posture,
    }
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(payload, f, indent=1)
    return path


def main():
    ap = argparse.ArgumentParser(
        description="Read-only multi-account, multi-region evidence collection.")
    ap.add_argument("--accounts", required=True,
                    help="comma-separated account IDs")
    ap.add_argument("--role-name", required=True,
                    help="read-only role to assume in each account (NOT admin)")
    ap.add_argument("--regions", default="us-east-1",
                    help="comma-separated regions (default us-east-1)")
    ap.add_argument("--profile", default=None,
                    help="base profile used to assume the per-account roles")
    ap.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS)
    ap.add_argument("--out", default=None,
                    help="write the facts store (Config rule facts, posture facts, "
                         "run id, PRIVATE scope map) to this git-excluded path; the "
                         "file name must match facts-*.json so the appender and "
                         f"prefill read it (default automation/facts/{DEFAULT_STORE_NAME})")
    ap.add_argument("--no-config-rules", action="store_true",
                    help="skip the registry Config rule checks (posture collectors only)")
    ap.add_argument("--scope-key-env", default=SCOPE_KEY_ENV,
                    help=f"environment variable holding the deployment-private "
                         f"scope key (default {SCOPE_KEY_ENV})")
    args = ap.parse_args()

    try:
        import boto3
    except ImportError:
        print("boto3 is required: pip install boto3")
        return 1

    out = args.out or os.path.join(_cf.FACTS_DIR, DEFAULT_STORE_NAME)
    base_name = os.path.basename(out)
    if not (base_name.startswith("facts-") and base_name.endswith(".json")):
        # AUD-F85: the earlier default, multi-account.json, was written and never
        # read by anything downstream. Refuse a name that would repeat that.
        print(f"Refusing --out {out}: the file name must match facts-*.json, the glob "
              "every downstream reader (append_metrics, prefill_from_facts) opens. "
              f"Use for example automation/facts/{DEFAULT_STORE_NAME}.")
        return 1

    accounts = [a.strip() for a in args.accounts.split(",") if a.strip()]
    regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    base = boto3.Session(profile_name=args.profile)
    scope_key = os.environ.get(args.scope_key_env) or None
    if not scope_key:
        print(f"NOTE: {args.scope_key_env} is not set. Facts carry the raw account "
              "and NO opaque scope; evidence_wiring.fact_to_evidence will refuse "
              "to export them until a scope key is supplied (AUD-F27).")

    registry = None
    if not args.no_config_rules:
        with open(_cf.REGISTRY, encoding="utf-8") as fh:
            registry = json.load(fh)

    run_id = _ew.new_run_id()
    facts = collect_across_accounts(accounts, args.role_name, regions,
                                    base_session=base, max_workers=args.max_workers,
                                    run_id=run_id, scope_key=scope_key, registry=registry)
    s = summarize(facts)
    rule_facts, posture = split_facts(facts)
    deployed = sum(1 for f in rule_facts
                   if f.get("compliance_type") in _cf.EVALUATED_CONFIG)
    print(f"run={run_id} accounts={s['accounts']} scopes={s['scopes']} "
          f"failed_assume={s['scopes_failed_to_assume']} facts={s['total_facts']} "
          f"(config rules checked={len(rule_facts)}, deployed={deployed}, "
          f"posture={len(posture)})")
    scopes = scope_map(accounts, scope_key) if scope_key else {}
    write_private_store(out, facts, run_id, scopes,
                        registry_dataset_version=(registry or {}).get("meta", {})
                        .get("dataset_version"))
    print(f"Private facts store written: {out} (contains real account ids "
          "and the scope map; git-excluded, never packaged).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
