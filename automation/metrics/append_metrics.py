# Metric-history appender (SDR-CSX-KMT accumulation).
#
# SDR-CSX-KMT requires, per applicable Key Security Indicator (verified against
# the pinned CR26 dataset):
#   Class B: a 30-day summary and an up-to-one-year summary.
#   Class C: those two PLUS all daily metric data up to the past year.
# None of that can be produced retroactively, so it has to accumulate. This
# script appends exactly one dated datapoint per KSI per run to a history store
# and recomputes the summaries from it.
#
# Boundary, same as every other automation layer:
#   - It reads collected facts (telemetry) and writes a history store. It never
#     touches implementation_status, assessment, or a compliance conclusion.
#   - The datapoint is a count of passing vs total observed automated checks for
#     that KSI on that day: a metric, not a verdict.
#   - The history store is git-excluded (it derives from a real account).
#
# Deterministic given a fixed `today`, which is injectable so the offline tests
# do not depend on the wall clock.
#
# Usage: python automation/metrics/append_metrics.py [--profile NAME] is NOT
# how this runs; it consumes an already-collected facts store. Run the collector
# first, then this. In the scheduled loop the workflow chains them.

import argparse
import json
import os
import sys
from datetime import datetime, timezone, timedelta

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REGISTRY = os.path.join(BASE, "automation", "collectors", "registry.json")
FACTS_DIR = os.path.join(BASE, "automation", "facts")
HISTORY = os.path.join(BASE, "automation", "metrics", "metric-history.json")

# Route posture telemetry to KSI metrics using the SINGLE canonical collector
# service registry, the same source prefill and AI use, so metric history cannot
# ignore a service the collectors emit (a stale local whitelist previously
# routed only six of the seventeen collected services - CloudFormation, WAF,
# EC2, ECR, DynamoDB, EventBridge, Config, CloudTrail, S3, and IAM posture was
# silently dropped from the metric even when a KSI named them).
sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))
try:
    from service_registry import SERVICE_DISPLAY_NAMES as POSTURE_SERVICE_KEYS
except Exception as exc:  # fail loud: unrouted telemetry is the failure to prevent
    raise RuntimeError(
        "append_metrics could not import the canonical service registry "
        "(automation/collectors/service_registry.py); refusing to run with an "
        "unknown posture-service routing set: " + str(exc)
    )

RETAIN_DAYS = 400  # a little over a year, so "up to the past year" is covered

# AUD-F18: one identity for a metric across the metric engine, prefill, and the
# VVK binding gate. Same directory as this module.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from method_ids import (  # noqa: E402
    config_method_id, posture_method_id, parse_service_key, assert_check_scoped)
import history_integrity as hi  # noqa: E402  (AUD-F37: chained, attested observations)


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def load_facts():
    """Merge config-rule and posture facts from the store into per-KSI-relevant
    signals. Returns (config_by_rule, posture_by_service).

    config_by_rule maps a rule name to a LIST of that rule's facts, one per
    (region[, account]) scope observed. Finding F04: keying by rule name alone
    let a later region's file silently OVERWRITE an earlier region's result for
    the same rule (files load in sorted order), so a us-east-1 NON_COMPLIANT
    could vanish behind a us-west-2 COMPLIANT and the KSI read fully passing.
    Retaining every scope's fact lets datapoint_for_ksi aggregate across scopes
    (a failure in ANY scope counts) instead of last-writer-wins."""
    config_by_rule = {}
    posture_by_service = {}
    if not os.path.isdir(FACTS_DIR):
        return config_by_rule, posture_by_service
    # De-duplicate identical (rule, region, account) observations so re-reading
    # the same file, or two files for the same scope, does not double-count.
    seen_scopes = {}
    for fn in sorted(os.listdir(FACTS_DIR)):
        if not fn.startswith("facts-") or not fn.endswith(".json"):
            continue
        store = load(os.path.join(FACTS_DIR, fn), {})
        store_ts = (store.get("meta") or {}).get("collected_at")
        for fact in store.get("facts", []):
            # F05: ensure an observation timestamp is present so the appender can
            # tell a fresh measurement from a replayed stale one. Config facts
            # carry collected_at; fall back to the store's meta timestamp.
            if not fact.get("collected_at") and store_ts:
                fact = {**fact, "collected_at": store_ts}
            rule = fact.get("rule")
            scope = (rule, fact.get("region"), fact.get("account"))
            # Latest file wins for the SAME exact scope; different scopes are
            # all retained.
            seen_scopes[scope] = fact
        for pf in store.get("posture_facts", []):
            if not pf.get("collected_at") and store_ts:
                pf = {**pf, "collected_at": store_ts}
            posture_by_service.setdefault(pf.get("service"), []).append(pf)
    for (rule, _region, _account), fact in seen_scopes.items():
        config_by_rule.setdefault(rule, []).append(fact)
    return config_by_rule, posture_by_service


GOOD_CONFIG = {"COMPLIANT"}
# A posture status that is itself a binary good/bad signal (no ratio needed).
# NOTE: "OBSERVED" is deliberately NOT here. OBSERVED means "we successfully
# measured something", not "the measured thing passed". An OBSERVED fact scores
# ONLY through its structured measured/total ratio; an OBSERVED fact with no
# measured/total contributes NOTHING to the passing/total tally (it is an
# observation, not a pass). See finding: OBSERVED-counts-as-passing.
GOOD_POSTURE = {"ENABLED", "PRESENT", "ACTIVE"}
# A posture status that is an explicit EVALUATED NEGATIVE: the control was
# checked and found absent/off. These are definite failures and MUST enter the
# tally as (0, 1) - dropping them (as the old code did, returning None for every
# non-good status) created survivor bias where known failures vanished from the
# denominator while passing observations stayed in it, so an aggregate could
# read fully passing even though a routed collector reported a definite negative.
# NOTE: this is distinct from "no resource to evaluate" (NO_KEYS / NO_REPOS /
# NO_STACKS) and from "unmeasured" (ERROR* / UNKNOWN): those carry no evaluated
# outcome and stay skipped (None). See finding F-04.
BAD_POSTURE = {"NOT_ENABLED", "NOT_CONFIGURED", "NONE", "DISABLED", "INACTIVE",
               "ABSENT"}
# No-resource states: the check ran but there was nothing to evaluate (e.g. no
# KMS keys exist, so key-rotation is vacuously not a failure). No evaluated
# outcome -> skip, do NOT score as a failure.
NO_RESOURCE = {"NO_KEYS", "NO_REPOS", "NO_STACKS"}

# AUD-F17: minimum EVALUATED coverage for a ratio fact to score. A collector
# that could read 10 of 50 in-scope resources (AccessDenied on the rest) may
# report 10/10 = 100 percent; that is a statement about the readable tenth, not
# about the control. Below this fraction the fact is treated as unmeasured for
# scoring (never as a failure: unknown coverage is not adverse telemetry) and
# the gap is surfaced in the datapoint's coverage fields. Project policy, not a
# FedRAMP number; an offering may tighten it via the OFFERING profile's
# `telemetry_min_coverage` (0 < x <= 1) which the collection pipeline passes in.
MIN_EVALUATED_COVERAGE = 0.95


def run_provenance(facts_dir=None):
    """AUD-F37: the provenance stamped on every observation this run appends.

    facts_sha256: digest over the raw bytes of every facts-*.json consumed (the
    exact inputs the datapoints were derived from); run_id: the collector's run
    id from the store meta (one store: its id; several: ids joined), falling
    back to the collected_at timestamp for stores from before the collector
    stamped run ids. Returns None when no facts store exists.
    """
    facts_dir = facts_dir or FACTS_DIR
    if not os.path.isdir(facts_dir):
        return None
    paths = sorted(os.path.join(facts_dir, fn) for fn in os.listdir(facts_dir)
                   if fn.startswith("facts-") and fn.endswith(".json"))
    if not paths:
        return None
    run_ids = []
    for p in paths:
        meta = (load(p, {}) or {}).get("meta") or {}
        rid = meta.get("run_id") or meta.get("collected_at")
        if rid:
            run_ids.append(str(rid))
    return {"run_id": "+".join(sorted(set(run_ids))) or None,
            "facts_sha256": hi.facts_store_digest(paths)}


def _coverage(pf):
    """(scope_total, evaluated_total, unknown_total) for a fact, or None when
    the fact carries no scope information (older facts / binary checks)."""
    scope = pf.get("scope_total")
    if scope is None:
        return None
    evaluated = pf.get("evaluated_total", pf.get("total")) or 0
    unknown = pf.get("unknown_total")
    if unknown is None:
        unknown = max(scope - evaluated, 0)
    return scope, evaluated, unknown


def _posture_score(pf, min_coverage=MIN_EVALUATED_COVERAGE):
    """Score one posture fact as (passing, total) contribution, or None to skip.

    - ERROR / UNKNOWN statuses: skip (unmeasured, not an evaluated outcome).
    - OBSERVED_PARTIAL or partial:true (AUD-F15): skip. The enumeration was cut
      short, so no ratio over it describes the boundary.
    - No-resource statuses (NO_KEYS/NO_REPOS/NO_STACKS): skip (nothing to
      evaluate; not a failure).
    - Evaluated coverage below policy (AUD-F17): skip. A ratio over the readable
      subset must not become a confident pass for the whole scope.
    - A structured ratio (measured/total): use it directly - this is the real
      fraction in good posture (e.g. 0 of 50 keys rotating = 0/50, NOT a pass).
    - A binary good status in GOOD_POSTURE: 1 of 1.
    - An explicit evaluated negative in BAD_POSTURE: 0 of 1 - a definite failure
      that MUST count against the passing fraction (finding F-04).
    - A bare OBSERVED (or any other non-good, non-negative status) with no ratio:
      skip. An observation that something was measured is not evidence it passed
      or failed, so it must not inflate the passing count OR the total.
    """
    status = pf.get("status", "")
    if status.startswith("ERROR") or status == "UNKNOWN":
        return None
    if status == "OBSERVED_PARTIAL" or pf.get("partial") is True:
        return None
    if status in NO_RESOURCE:
        return None
    if "measured" in pf and "total" in pf:
        total = pf.get("total") or 0
        if total <= 0:
            return None
        cov = _coverage(pf)
        if cov is not None:
            scope, evaluated, _unknown = cov
            if scope > 0 and (evaluated / scope) < min_coverage:
                return None
        return (pf.get("measured") or 0, total)
    if status in GOOD_POSTURE:
        return (1, 1)
    if status in BAD_POSTURE:
        # Explicit evaluated negative: definite fail, counts as 0 of 1.
        return (0, 1)
    # Bare OBSERVED / other count-only observation with no ratio: not an
    # evaluated pass or fail - carries no outcome, so it is neither passing
    # nor a denominator.
    return None


def _coverage_gap(pf, min_coverage=MIN_EVALUATED_COVERAGE):
    """A short reason when a ratio fact was withheld from scoring for coverage
    reasons (partial enumeration or evaluated coverage below policy), else None.
    Recorded on the datapoint so the gap is visible, not silent."""
    if pf.get("status") == "OBSERVED_PARTIAL" or pf.get("partial") is True:
        return "partial-enumeration"
    cov = _coverage(pf)
    if cov is None or "measured" not in pf:
        return None
    scope, evaluated, _unknown = cov
    if scope > 0 and (evaluated / scope) < min_coverage:
        return f"coverage {evaluated}/{scope} below {min_coverage:g}"
    return None


def _route(ksi_entry):
    """The KSI's posture routes as (service, check) pairs. AUD-F16: every entry
    must be check-scoped; a bare service key would score every fact of that
    service, so it is refused loudly rather than silently widened."""
    routes = []
    for key in ksi_entry.get("metric_service_keys", []) or []:
        service, check = parse_service_key(key)
        if not check:
            raise ValueError(
                f"metric_service_keys entry {key!r} routes a whole service; "
                "use service:check (see automation/metrics/method_ids.py)")
        routes.append((service, check))
    return routes


def _config_scope_score(facts):
    """Aggregate a Config rule's per-scope facts (one per region/account) into
    (passing, total) where each evaluated scope is one unit. Finding F04: a
    NON_COMPLIANT in ANY scope must count as a failure and must NOT be hidden by
    a COMPLIANT in another scope. ERROR/RULE_NOT_DEPLOYED/UNKNOWN scopes carry
    no evaluated outcome and are skipped (not scored as failures). `facts` is
    the list stored under config_by_rule[rule]; a bare dict is tolerated for
    backward compatibility."""
    if isinstance(facts, dict):
        facts = [facts]
    passing = 0
    total = 0
    for fact in facts or []:
        ct = fact.get("compliance_type", "")
        if ct.startswith("ERROR") or ct in ("RULE_NOT_DEPLOYED", "UNKNOWN", ""):
            continue
        total += 1
        if ct in GOOD_CONFIG:
            passing += 1
    return passing, total


def datapoint_for_ksi(ksi_entry, config_by_rule, posture_by_service,
                      min_coverage=MIN_EVALUATED_COVERAGE):
    """One day's metric for a KSI: passing vs total observed automated checks.
    Returns None if nothing was observed (no datapoint rather than a zero, so a
    day the collector could not see a service is not recorded as a failure).

    The datapoint also carries coverage (AUD-F17): scope_total / evaluated_total
    / unknown_total summed over the ratio facts that scored, and coverage_gaps
    naming any routed fact withheld from scoring because its enumeration was
    partial or its evaluated coverage fell below policy. passing/total are
    unchanged in meaning, so every existing consumer still reads them."""
    passing = 0
    total = 0
    scope_total = evaluated_total = unknown_total = 0
    gaps = []
    for check in ksi_entry.get("checks", []):
        if check.get("type") != "config_managed_rule":
            continue
        facts = config_by_rule.get(check.get("target"))
        if not facts:
            continue
        # F04: aggregate across every region/account scope, not last-writer-wins.
        p, t = _config_scope_score(facts)
        total += t
        passing += p
    # Posture routing is by the EXPLICIT per-KSI allowlist (metric_service_keys),
    # every entry check-scoped ("service:check"), AUD-F16. Finding F03 showed a
    # bare service key let an UNRELATED check of a shared service score a KSI
    # (IAM password_policy scoring KSI-IAM-JIT); AUD-F16 showed the same shape
    # let Access Analyzer PRESENT lift KSI-IAM-ELP while active findings were
    # open. A KSI with no allowlist (document/process KSI) accrues no posture
    # metric.
    for service, check_filter in _route(ksi_entry):
        for pf in posture_by_service.get(service, []):
            if check_filter and pf.get("check") != check_filter:
                continue  # F03: check-scoped key rejects other checks
            score = _posture_score(pf, min_coverage)
            if score is None:
                gap = _coverage_gap(pf, min_coverage)
                if gap:
                    gaps.append(f"{posture_method_id(service, pf.get('check'))}: {gap}")
                continue
            p, t = score
            total += t
            passing += p
            cov = _coverage(pf)
            if cov is not None:
                scope_total += cov[0]
                evaluated_total += cov[1]
                unknown_total += cov[2]
    if total == 0:
        return None
    dp = {"passing": passing, "total": total}
    if scope_total or gaps:
        dp["scope_total"] = scope_total
        dp["evaluated_total"] = evaluated_total
        dp["unknown_total"] = unknown_total
    if gaps:
        dp["coverage_gaps"] = sorted(gaps)
    return dp


def per_metric_datapoints_for_ksi(ksi_entry, config_by_rule, posture_by_service,
                                  min_coverage=MIN_EVALUATED_COVERAGE):
    """One day's metric PER METRIC for a KSI, preserving each metric's identity
    (finding 3). FedRAMP SDR-CSX-KMT says "Summary of EACH metric", but the
    aggregate datapoint_for_ksi collapses every check/service into a single
    passing/total for the whole KSI, losing which metric contributed what.

    Returns {metric_id: {"passing": p, "total": t, "objective": str, "source": str}}
    for every metric that was actually observed that day, or {} if none. A
    metric is one config-managed rule (keyed by config_method_id) or one
    observed posture check (keyed by posture_method_id). Those two functions in
    method_ids.py are the SAME identity prefill writes into a structured test's
    method_id and the VVK binding gate compares (AUD-F18), so the real
    collector -> prefill -> preflight path binds. The KSI-level aggregate remains
    the sum of these; this is emitted ALONGSIDE the aggregate, never replacing it.
    """
    out = {}
    for check in ksi_entry.get("checks", []):
        if check.get("type") != "config_managed_rule":
            continue
        target = check.get("target")
        facts = config_by_rule.get(target)
        if not facts:
            continue
        # F04: aggregate across every observed region/account scope.
        p, t = _config_scope_score(facts)
        if t == 0:
            continue
        mid = config_method_id(check)
        out[mid] = {
            "passing": p,
            "total": t,
            "objective": check.get("description") or check.get("objective") or "",
            "source": f"AWS Config rule {target}",
        }
    for service, check_filter in _route(ksi_entry):
        svc_label = POSTURE_SERVICE_KEYS.get(service, service)
        # F03: preserve per-CHECK metric identity. Group the service's observed
        # facts by their check name and emit one metric per check, so distinct
        # checks (e.g. iam password_policy vs role_session_duration) never
        # collapse into a single posture:<service> number. A check-scoped key
        # (service:check) only admits that check.
        by_check = {}
        for pf in posture_by_service.get(service, []):
            chk = pf.get("check") or "posture"
            if check_filter and chk != check_filter:
                continue
            score = _posture_score(pf, min_coverage)
            if score is None:
                continue
            sp, st = score
            acc = by_check.setdefault(chk, [0, 0])
            acc[0] += sp
            acc[1] += st
        for chk, (p, t) in by_check.items():
            if not t:
                continue
            out[posture_method_id(service, chk)] = {
                "passing": p, "total": t,
                "objective": f"Posture check {chk} of {svc_label}",
                "source": f"Security posture telemetry for {svc_label} ({chk})",
            }
    return out


def summarize(points):
    """A summary is the average passing-fraction across the points and the
    count of days observed. Deterministic and simple on purpose: the assessor
    reads the daily series; this is the human-facing rollup."""
    if not points:
        return {"days_observed": 0, "avg_passing_fraction": None}
    fracs = [p["passing"] / p["total"] for p in points if p["total"]]
    avg = round(sum(fracs) / len(fracs), 4) if fracs else None
    return {"days_observed": len(points), "avg_passing_fraction": avg}


# SDR-CSX-KMT historical-metric reference period, per class, verified verbatim
# against the pinned dataset (2026.10.08.01): Class A MAY include historical
# metrics; Class B SHOULD (MUST before 2026.10.08.01); Class C MUST supply "All
# daily metric data (including status of persistent validation) up to the past
# year (where available)"; Class D MUST significantly supersede lower classes,
# specifics pending. FRC-CSX-MOT, which carried a 6/18-month minimum, was
# removed from the dataset in 2026.10.08.01 as duplicative; no minimum duration
# remains, so the window below MEASURES coverage of the up-to-one-year reference
# period and reports it. It is not a pass/fail verdict.
KMT_REFERENCE_MONTHS = 12
KMT_REFERENCE_DAYS = 365  # informative approximation only
KMT_FORCE = {"a": "MAY", "b": "SHOULD", "c": "MUST", "d": "MUST"}


def _months_before(ref, n):
    """The date exactly n CALENDAR months before ref, clamping to month-end.

    FedRAMP states the reference period in calendar terms ("up to the past
    year"), not fixed days; a day approximation is wrong at month boundaries.
    """
    y = ref.year + (ref.month - 1 - n) // 12
    m = (ref.month - 1 - n) % 12 + 1
    if m == 12:
        last = 31
    else:
        last = (datetime(y, m + 1, 1).date() - timedelta(days=1)).day
    return datetime(y, m, min(ref.day, last)).date()


def kmt_window(series, cls, today):
    """Measure one KSI's coverage of the SDR-CSX-KMT reference period.

    Reports the span the observed series actually covers and whether it reaches
    back the full "up to the past year". This is a coverage measurement, not a
    determination: a covered period says validation status exists over that
    period, not that the control passed, and a shorter span is the provider's
    "where available" statement for the assessor, not a shortfall the appender
    judges. An empty series reports covered=0. The period is measured in
    CALENDAR MONTHS (the dataset's unit); covered_days is informative.
    """
    cls = cls.lower()
    force = KMT_FORCE.get(cls, "SHOULD")
    if series:
        earliest = min(datetime.fromisoformat(p["date"]).date() for p in series)
        covered = (today - earliest).days
        covers = earliest <= _months_before(today, KMT_REFERENCE_MONTHS)
    else:
        earliest = None
        covered = 0
        covers = False
    return {
        "class": cls.upper(),
        "force": force,
        "reference_months": KMT_REFERENCE_MONTHS,
        "reference_days": KMT_REFERENCE_DAYS,
        "covered_days": covered,
        "covers_reference_period": covers,
        "note": ("Coverage of the SDR-CSX-KMT reference period (up to the past "
                 "year), not a pass/fail verdict. Measured in calendar months. "
                 "No minimum duration is mandated: the data is supplied 'where "
                 "available'. MUST at Class C and D; SHOULD at B; MAY at A."),
    }


# Pre-2026.10.08.01 name, kept so a deployed caller that imported it keeps
# working; the measurement is the same function.
mot_window = kmt_window


def prune(series, today):
    cutoff = today - timedelta(days=RETAIN_DAYS)
    return [p for p in series if datetime.fromisoformat(p["date"]).date() >= cutoff]


def _obs_date(ts):
    """Parse a fact's collected_at into a date, or None if unparseable."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return datetime.fromisoformat(str(ts)[:10]).date()
        except ValueError:
            return None


def _ksi_observed_today(ksi_entry, config_by_rule, posture_by_service, today):
    """True if ANY fact contributing to this KSI was actually OBSERVED on
    `today` (finding F05). Prevents a stale/replayed fact (an old observation
    re-read on a later run) from being stamped as a fresh datapoint and
    manufacturing persistence/history it did not earn. A fact with no parseable
    observation timestamp is treated as NOT fresh (fail-closed for replay)."""
    for check in ksi_entry.get("checks", []):
        if check.get("type") != "config_managed_rule":
            continue
        facts = config_by_rule.get(check.get("target"))
        if isinstance(facts, dict):
            facts = [facts]
        for fact in facts or []:
            if _obs_date(fact.get("collected_at")) == today:
                return True
    allowed = set(ksi_entry.get("metric_service_keys", []))
    for svc_key in allowed:
        for pf in posture_by_service.get(svc_key, []):
            if _obs_date(pf.get("collected_at")) == today:
                return True
    return False


def _fraction(p):
    return (p.get("passing") or 0) / p["total"] if p.get("total") else None


def merge_daily_point(existing, new):
    """Fold a second same-day observation into the day's rollup WITHOUT losing
    the first (AUD-F19). The rollup is CONSERVATIVE: the day's passing/total
    are those of the WORST observed run (lowest passing fraction), so a morning
    failure followed by an evening pass reads as the failure, never as the pass.
    The rollup also records runs, min_fraction and max_fraction so an assessor
    can see that the day was not uniform. Coverage fields follow the worst run.
    `existing` may be None (first observation of the day)."""
    if existing is None:
        out = dict(new)
        out["runs"] = 1
        f = _fraction(new)
        out["min_fraction"] = out["max_fraction"] = round(f, 4) if f is not None else None
        return out
    f_old = _fraction(existing)
    f_new = _fraction(new)
    worst = existing if (f_old is not None and (f_new is None or f_old <= f_new)) else new
    out = {k: v for k, v in worst.items()
           if k not in ("runs", "min_fraction", "max_fraction")}
    out["date"] = existing.get("date") or new.get("date")
    out["runs"] = (existing.get("runs") or 1) + 1
    fr = [x for x in (existing.get("min_fraction"), existing.get("max_fraction"),
                      f_old, f_new) if x is not None]
    out["min_fraction"] = round(min(fr), 4) if fr else None
    out["max_fraction"] = round(max(fr), 4) if fr else None
    return out


def _roll_into_series(series, point, today):
    """Return series with `point` folded into its date's rollup (worst-of),
    sorted and pruned. Never drops an earlier same-day observation."""
    date_str = point["date"]
    existing = next((p for p in series if p["date"] == date_str), None)
    rest = [p for p in series if p["date"] != date_str]
    rest.append(merge_daily_point(existing, point))
    rest.sort(key=lambda p: p["date"])
    return prune(rest, today)


def prune_observations(observations, today, anchor_sink=None, kid=None):
    """Drop observations older than the retention window.

    AUD-F37: pruning must not break the hash chain. When observations are
    dropped, the newest dropped observation's hash becomes the KSI's pruning
    anchor (recorded by the caller in meta.chain_anchor[kid] via anchor_sink),
    so the first retained observation still verifies against something. The
    old code dropped silently and a verifier would have seen a broken chain
    start after the first prune.
    """
    cutoff = (today - timedelta(days=RETAIN_DAYS)).isoformat()
    kept, dropped = [], []
    for o in observations:
        (kept if (o.get("observed_at") or "")[:10] >= cutoff else dropped).append(o)
    if dropped and anchor_sink is not None and kid is not None:
        newest = dropped[-1]
        if newest.get("hash"):
            anchor_sink[kid] = newest["hash"]
    return kept


def append_run(history, registry, config_by_rule, posture_by_service, today,
               cls="b", require_fresh=False, observed_at=None,
               min_coverage=MIN_EVALUATED_COVERAGE, provenance=None):
    """Append today's datapoint per KSI to the history and recompute summaries.
    One ROLLUP per KSI per calendar day. A second run the same day does NOT
    replace the first (AUD-F19): every run is appended as an immutable,
    timestamped observation under the KSI's `observations`, and the day's
    series point is the conservative rollup of all of that day's runs (worst
    passing fraction, with runs/min/max recorded). Per-metric series roll up the
    same way (runs/min/max, no per-metric observation log, which would be
    unbounded).

    F05: when require_fresh is set (production main() sets it), a KSI datapoint
    is recorded for `today` only if at least one contributing observation was
    actually collected on `today`. This stops a replayed stale fact from
    advancing the history/MOT clock with a measurement that never happened that
    day. The library default is False so callers computing summaries over
    explicitly-dated synthetic series are unaffected; the collection pipeline
    (main) always enforces freshness.

    AUD-F37: every observation is hash-chained to its predecessor (or the KSI's
    pruning anchor) and stamped with the run's provenance (`run_id`,
    `facts_sha256` from the facts store it was derived from, passed in as
    `provenance`). main() always passes provenance; a library caller that passes
    none produces chained-but-UNATTESTED observations, which preflight reports.

    observed_at: ISO timestamp for this run's observations (default: now, UTC).
    Injectable so tests are deterministic."""
    date_str = today.isoformat()
    if observed_at is None:
        observed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    ksis = history.setdefault("ksis", {})
    anchors = history.setdefault("meta", {}).setdefault("chain_anchor", {})
    appended = 0
    for kid, ksi_entry in registry.get("ksis", {}).items():
        dp = datapoint_for_ksi(ksi_entry, config_by_rule, posture_by_service, min_coverage)
        if dp is None:
            continue
        if require_fresh and not _ksi_observed_today(
                ksi_entry, config_by_rule, posture_by_service, today):
            # Stale/replayed observation only: do not manufacture a fresh point.
            continue
        entry = ksis.setdefault(kid, {"series": []})
        # Immutable run-level record first: this is what the rollup is derived
        # from and what a reviewer replays when the rollup is questioned.
        # AUD-F37: linked to the KSI's chain head (or pruning anchor) and
        # stamped with the run provenance; hash computed last.
        obs = entry.setdefault("observations", [])
        linked = hi.chain_observation(
            {"observed_at": observed_at, "date": date_str, **dp},
            hi.chain_head(entry, anchors.get(kid)), provenance)
        obs.append(linked)
        entry["observations"] = prune_observations(obs, today, anchor_sink=anchors, kid=kid)
        entry["series"] = _roll_into_series(entry["series"], {"date": date_str, **dp}, today)
        appended += 1
        # Recompute the SDR-CSX-KMT summaries. Storage keeps RETAIN_DAYS (~400)
        # of history, but each summary MUST slice the retained series to the
        # EXACT window FedRAMP names, not the whole retained span:
        #   - "past 30 days"  = the 30 calendar dates today-29 .. today
        #     (an inclusive `date >= today-30` window spans 31 dates, so it is
        #      wrong by one; use today-29 for exactly 30).
        #   - "up to the past year" = the >= 12-calendar-months window
        #     (today back to _months_before(today, 12)); summarizing the whole
        #      ~400-day retained series over-counts beyond a year.
        cutoff30 = (today - timedelta(days=29)).isoformat()
        last30 = [p for p in entry["series"] if p["date"] >= cutoff30]
        entry["last_30_days"] = summarize(last30)
        year_start = _months_before(today, 12).isoformat()
        last_year = [p for p in entry["series"] if p["date"] >= year_start]
        entry["up_to_one_year"] = summarize(last_year)
        # SDR-CSX-KMT reference-period coverage for this class (measurement).
        entry["persistent_validation_window"] = kmt_window(entry["series"], cls, today)
        # Per-metric identity (finding 3): FedRAMP asks for a summary of EACH
        # metric, so accumulate a per-metric daily series ALONGSIDE the KSI
        # aggregate above (never replacing it). Each metric keeps its own
        # series, 30-day and 1-year summaries, objective, and source, sliced to
        # the same exact windows. The KSI aggregate remains the sum, so every
        # existing consumer is unchanged.
        pm = per_metric_datapoints_for_ksi(ksi_entry, config_by_rule, posture_by_service,
                                           min_coverage)
        metrics = entry.setdefault("metrics", {})
        for mid, mdp in pm.items():
            m = metrics.setdefault(mid, {"series": []})
            m["series"] = _roll_into_series(
                m["series"],
                {"date": date_str, "passing": mdp["passing"], "total": mdp["total"]},
                today)
            m["objective"] = mdp.get("objective", "")
            m["source"] = mdp.get("source", "")
            m["last_30_days"] = summarize(
                [p for p in m["series"] if p["date"] >= cutoff30])
            m["up_to_one_year"] = summarize(
                [p for p in m["series"] if p["date"] >= year_start])
    _update_meta(history, appended, date_str, observed_at, registry, min_coverage)
    return appended


def _update_meta(history, appended, date_str, observed_at, registry, min_coverage):
    """Record this run in history['meta'] (AUD-F30).

    `last_run` / `last_observed_at` mean "the last run that appended at least
    one datapoint" and advance ONLY when appended > 0. `last_attempt` records
    every run, including an empty one, with its outcome. The old code stamped
    last_run on every run, so a collection that observed nothing (all checks
    errored) still made the history look freshly maintained.
    """
    prev = history.get("meta") or {}
    meta = {
        "last_run": prev.get("last_run"),
        "last_observed_at": prev.get("last_observed_at"),
        "last_attempt": {
            "date": date_str,
            "observed_at": observed_at,
            "appended": appended,
            "outcome": "OK" if appended else "NO_DATAPOINTS",
        },
        "retain_days": RETAIN_DAYS,
        "min_evaluated_coverage": min_coverage,
        "dataset_version": registry.get("meta", {}).get("dataset_version"),
        # AUD-F37: pruning anchors survive every run (they are what the first
        # retained observation of each KSI links to).
        "chain_anchor": prev.get("chain_anchor") or {},
        "note": ("Per-KSI daily metric history for SDR-CSX-KMT. A datapoint is "
                 "passing vs total observed automated checks that day, a metric, "
                 "not a compliance verdict. A day with several runs keeps every "
                 "run under `observations` and rolls up to the WORST run. "
                 "last_run is the last run that appended a datapoint; "
                 "last_attempt records every run including empty ones. "
                 "Observations are hash-chained and carry run provenance; "
                 "history_digest is the signable head of the whole log. "
                 "Git-excluded: derives from a real account."),
    }
    if appended:
        meta["last_run"] = date_str
        meta["last_observed_at"] = observed_at
    history["meta"] = meta
    hi.record_heads(history)


# AUD-F30: exit code when the run appended nothing. Distinct from the
# publisher's 3 (CAS conflict, retried) so the scheduled loops fail loudly.
EXIT_NO_DATAPOINTS = 4


def load_history_safe(path):
    """Load existing metric history, distinguishing three cases (finding F07):
      - file ABSENT  -> ({}, None): a legitimate first run, start fresh.
      - file PRESENT and valid history object -> (history, None).
      - file PRESENT but unreadable / invalid JSON / wrong shape -> ({}, error):
        the caller MUST abort rather than overwrite. The old code ran the file
        through load(), which turned a JSON decode error into {} and then
        rewrote a fresh one-day history over the corrupt (but real) durable
        state - silent data loss. Corruption is not a first run.
    """
    if not os.path.exists(path):
        return {}, None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        return {}, f"metric history unreadable: {e}"
    except ValueError as e:
        return {}, f"metric history is not valid JSON: {e}"
    if not isinstance(data, dict):
        return {}, f"metric history root is {type(data).__name__}, expected object"
    ksis = data.get("ksis")
    if ksis is not None and not isinstance(ksis, dict):
        return {}, "metric history 'ksis' is present but not an object"
    return data, None


def main():
    ap = argparse.ArgumentParser(
        description="Append one dated metric datapoint per KSI (SDR-CSX-KMT).")
    ap.add_argument("--today", default=None,
                    help="ISO date override for deterministic runs/tests")
    args = ap.parse_args()

    registry = load(REGISTRY)
    if registry is None:
        print("Could not load the collector registry.")
        return 2
    # AUD-F16: refuse to run against a registry that routes whole services.
    try:
        assert_check_scoped(registry)
    except ValueError as e:
        print(f"FAIL: {e}")
        return 2
    config_by_rule, posture_by_service = load_facts()
    if not config_by_rule and not posture_by_service:
        print("No facts found in automation/facts/. Run the collector first.")
        return 1

    today = (datetime.fromisoformat(args.today).date() if args.today
             else datetime.now(timezone.utc).date())
    # F07: fail closed on a corrupt existing history rather than overwriting it.
    history, hist_err = load_history_safe(HISTORY)
    if hist_err:
        print(f"FAIL: refusing to overwrite metric history - {hist_err}. "
              "The existing durable history is present but not safely readable; "
              "fix or restore it before appending (aborting to prevent data loss, "
              "finding F07).")
        return 1
    # Class drives the SDR-CSX-KMT force (MAY A, SHOULD B, MUST C/D) recorded
    # with each KSI's reference-period coverage.
    offering = load(os.path.join(BASE, "profiles", "common", "offering-profile.json"), {})
    cls = (offering.get("certification_class") or "b").lower()
    # AUD-F17: an offering may TIGHTEN the evaluated-coverage policy, never
    # loosen it below the project floor.
    min_cov = MIN_EVALUATED_COVERAGE
    try:
        declared = float(offering.get("telemetry_min_coverage") or 0)
    except (TypeError, ValueError):
        declared = 0.0
    if MIN_EVALUATED_COVERAGE < declared <= 1.0:
        min_cov = declared
    appended = append_run(history, registry, config_by_rule, posture_by_service,
                          today, cls, require_fresh=True, min_coverage=min_cov,
                          provenance=run_provenance())

    os.makedirs(os.path.dirname(HISTORY), exist_ok=True)
    with open(HISTORY, "w", encoding="utf-8", newline="\n") as f:
        json.dump(history, f, indent=1)
    if appended == 0:
        # AUD-F30: the attempt is recorded (meta.last_attempt) but the run is a
        # FAILURE: no KSI received a datapoint, so this day adds nothing to the
        # SDR-CSX-KMT history (daily data and the status of persistent
        # validation). Returning 0 here let
        # the scheduled loops report success on an empty day.
        print(f"FAIL. Appended {today.isoformat()} datapoint for 0 KSI(s): no fact "
              "produced an evaluated, fresh outcome (collection failed, stale facts, "
              "or no routed check observed). last_run was NOT advanced. History: "
              f"{os.path.relpath(HISTORY, BASE)}.")
        return EXIT_NO_DATAPOINTS
    print(f"Appended {today.isoformat()} datapoint for {appended} KSI(s). "
          f"History: {os.path.relpath(HISTORY, BASE)} "
          f"({len(history.get('ksis', {}))} KSIs tracked).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
