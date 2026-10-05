# Offline tests for the metric-history appender. Exercises append_run directly
# with synthetic registry/facts, no files or account. Run:
#   python automation/metrics/test_append_metrics.py

import os
import sys
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import append_metrics as am  # noqa: E402

REGISTRY = {"meta": {"dataset_version": "test"}, "ksis": {
    "KSI-A": {"services": ["AWS Config"], "metric_service_keys": [],
              "checks": [{"type": "config_managed_rule", "target": "r1"}]},
    "KSI-B": {"services": ["Amazon GuardDuty"], "metric_service_keys": ["guardduty:detector"],
              "checks": []},
}}


def config(ct):
    return {"r1": {"rule": "r1", "compliance_type": ct}}


def guardduty(status):
    return {"guardduty": [{"service": "guardduty", "check": "detector", "status": status}]}


def test_datapoint_counts_passing_and_total():
    dp = am.datapoint_for_ksi(REGISTRY["ksis"]["KSI-A"], config("COMPLIANT"), {})
    assert dp == {"passing": 1, "total": 1}
    dp2 = am.datapoint_for_ksi(REGISTRY["ksis"]["KSI-A"], config("NON_COMPLIANT"), {})
    assert dp2 == {"passing": 0, "total": 1}


def test_no_observation_yields_no_datapoint():
    # RULE_NOT_DEPLOYED is not an observation, so no datapoint (not a zero).
    assert am.datapoint_for_ksi(REGISTRY["ksis"]["KSI-A"], config("RULE_NOT_DEPLOYED"), {}) is None


def test_f04_region_failure_not_hidden_by_another_region():
    # Finding F04: a NON_COMPLIANT in us-east-1 must NOT be overwritten by a
    # COMPLIANT in us-west-2. Both scopes count: 1 passing of 2 total.
    facts = {"r1": [
        {"rule": "r1", "compliance_type": "NON_COMPLIANT", "region": "us-east-1"},
        {"rule": "r1", "compliance_type": "COMPLIANT", "region": "us-west-2"},
    ]}
    dp = am.datapoint_for_ksi(REGISTRY["ksis"]["KSI-A"], facts, {})
    assert dp == {"passing": 1, "total": 2}, dp


def test_f04_load_facts_retains_every_region_scope(tmp_path=None):
    # load_facts must keep one fact per (rule, region, account), not last-wins.
    import json
    import tempfile
    d = tempfile.mkdtemp()
    for i, (region, ct) in enumerate([("us-east-1", "NON_COMPLIANT"),
                                      ("us-west-2", "COMPLIANT")]):
        with open(os.path.join(d, f"facts-{i}.json"), "w") as f:
            json.dump({"facts": [{"rule": "r1", "compliance_type": ct,
                                  "region": region}]}, f)
    orig = am.FACTS_DIR
    am.FACTS_DIR = d
    try:
        cbr, _ = am.load_facts()
    finally:
        am.FACTS_DIR = orig
    assert isinstance(cbr["r1"], list) and len(cbr["r1"]) == 2, cbr


def test_append_is_idempotent_per_day():
    hist = {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6))
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6))
    series = hist["ksis"]["KSI-A"]["series"]
    assert len(series) == 1, "same-day re-run must replace, not duplicate"


def test_append_accumulates_across_days():
    hist = {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 5))
    am.append_run(hist, REGISTRY, config("NON_COMPLIANT"), {}, date(2026, 9, 6))
    series = hist["ksis"]["KSI-A"]["series"]
    assert len(series) == 2
    assert hist["ksis"]["KSI-A"]["up_to_one_year"]["days_observed"] == 2
    # avg of 1.0 and 0.0 = 0.5
    assert hist["ksis"]["KSI-A"]["up_to_one_year"]["avg_passing_fraction"] == 0.5


def test_posture_datapoint_for_guardduty_ksi():
    dp = am.datapoint_for_ksi(REGISTRY["ksis"]["KSI-B"], {}, guardduty("ENABLED"))
    assert dp == {"passing": 1, "total": 1}


# --- OBSERVED-is-not-passing regression tests -------------------------------
# Finding: append_metrics previously put "OBSERVED" in GOOD_POSTURE, so a fact
# emitted as OBSERVED counted as a passing metric regardless of the underlying
# count. OBSERVED must score ONLY through a structured measured/total ratio; a
# bare OBSERVED with no ratio must contribute nothing to passing OR total.

_CHECK_FOR = {"kms": "key_rotation", "securityhub": "enabled", "guardduty": "detector",
              "cloudformation": "drift", "s3": "encryption"}


def _posture(service, status, measured=None, total=None):
    pf = {"service": service, "check": _CHECK_FOR.get(service, "c"), "status": status}
    if measured is not None:
        pf["measured"] = measured
    if total is not None:
        pf["total"] = total
    return {service: [pf]}


def test_observed_zero_ratio_scores_zero_not_pass():
    # 0 of 50 keys rotating, collected as OBSERVED, must be 0/50, never a pass.
    kms_ksi = {"metric_service_keys": ["kms:key_rotation"], "checks": []}
    dp = am.datapoint_for_ksi(kms_ksi, {}, _posture("kms", "OBSERVED", 0, 50))
    assert dp == {"passing": 0, "total": 50}, dp


def test_observed_full_ratio_scores_full():
    kms_ksi = {"metric_service_keys": ["kms:key_rotation"], "checks": []}
    dp = am.datapoint_for_ksi(kms_ksi, {}, _posture("kms", "OBSERVED", 50, 50))
    assert dp == {"passing": 50, "total": 50}, dp


def test_bare_observed_without_ratio_is_not_a_datapoint():
    # A count-only OBSERVED (e.g. "25 failed findings") carries no evaluated
    # outcome: it must not become 1/1 passing and must not inflate the total.
    kms_ksi = {"metric_service_keys": ["kms:key_rotation"], "checks": []}
    dp = am.datapoint_for_ksi(kms_ksi, {}, _posture("kms", "OBSERVED"))
    assert dp is None, dp


def test_posture_score_helper():
    assert am._posture_score({"status": "OBSERVED", "measured": 0, "total": 50}) == (0, 50)
    assert am._posture_score({"status": "OBSERVED"}) is None
    assert am._posture_score({"status": "ENABLED"}) == (1, 1)
    assert am._posture_score({"status": "ERROR:X"}) is None
    assert am._posture_score({"status": "OBSERVED", "measured": 3, "total": 0}) is None


# --- F-04: explicit evaluated negatives are recorded, not dropped ------------
# Finding: every non-good status returned None, so explicit evaluated negatives
# (NONE, NOT_ENABLED, NOT_CONFIGURED) - definite failures the collectors emit -
# vanished from the tally, inflating the passing fraction (survivor bias). They
# must score (0, 1). Errors/unknown and no-resource states still skip.

def test_evaluated_negatives_score_zero_of_one():
    for bad in ("NOT_ENABLED", "NOT_CONFIGURED", "NONE", "DISABLED",
                "INACTIVE", "ABSENT"):
        assert am._posture_score({"status": bad}) == (0, 1), bad


def test_error_and_unknown_still_skip():
    assert am._posture_score({"status": "ERROR:AccessDenied"}) is None
    assert am._posture_score({"status": "UNKNOWN"}) is None


def test_no_resource_states_skip_not_fail():
    # Nothing to evaluate (no keys/repos/stacks) is NOT a failure.
    for nr in ("NO_KEYS", "NO_REPOS", "NO_STACKS"):
        assert am._posture_score({"status": nr}) is None, nr


def test_negative_posture_enters_datapoint_as_failing():
    # A routed collector reporting NOT_ENABLED must count as 0/1, not disappear.
    ksi = {"metric_service_keys": ["securityhub:enabled"], "checks": []}
    dp = am.datapoint_for_ksi(ksi, {}, _posture("securityhub", "NOT_ENABLED"))
    assert dp == {"passing": 0, "total": 1}, dp


def test_negative_does_not_get_masked_by_a_positive_sibling():
    # F-04 core: one source ENABLED (1/1) and another NOT_ENABLED (0/1) on the
    # same KSI must aggregate to 1/2, NOT 1/1 (the old drop-the-negative bug
    # made a known failure invisible so the KSI read fully passing).
    ksi = {"metric_service_keys": ["guardduty:detector", "securityhub:enabled"], "checks": []}
    posture = {
        "guardduty": [{"service": "guardduty", "check": "detector", "status": "ENABLED"}],
        "securityhub": [{"service": "securityhub", "check": "enabled", "status": "NOT_ENABLED"}],
    }
    dp = am.datapoint_for_ksi(ksi, {}, posture)
    assert dp == {"passing": 1, "total": 2}, dp


# --- Explicit metric-source allowlist (no service-name fan-out) --------------
# Finding: routing posture to every KSI whose prose named a service let generic
# posture manufacture metric history for unrelated KSIs. Posture now routes ONLY
# via the KSI's explicit metric_service_keys allowlist.

def test_no_allowlist_means_no_posture_metric():
    # A KSI with an empty allowlist (e.g. a document/process KSI like CED-RAT)
    # accrues NO posture metric even when posture for that service was collected.
    doc_ksi = {"metric_service_keys": [], "checks": []}
    # s3/config/kms posture present, all with good ratios:
    posture = {
        "s3": [{"service": "s3", "status": "OBSERVED", "measured": 10, "total": 10}],
        "config": [{"service": "config", "status": "ENABLED"}],
        "kms": [{"service": "kms", "status": "OBSERVED", "measured": 5, "total": 5}],
    }
    assert am.datapoint_for_ksi(doc_ksi, {}, posture) is None


def test_posture_routes_only_to_allowlisted_service():
    # A KSI allowlisted for cloudformation must NOT pick up unrelated s3 posture.
    eis_ksi = {"metric_service_keys": ["cloudformation:drift"], "checks": []}
    posture = {
        "cloudformation": [{"service": "cloudformation", "check": "drift", "status": "OBSERVED",
                            "measured": 8, "total": 10}],
        "s3": [{"service": "s3", "status": "OBSERVED", "measured": 0, "total": 100}],
    }
    dp = am.datapoint_for_ksi(eis_ksi, {}, posture)
    # only the cloudformation 8/10 counts; the 0/100 s3 leak is excluded
    assert dp == {"passing": 8, "total": 10}, dp



def test_history_persists_across_ephemeral_runs():
    # Simulate the collector buildspec: each daily run is EPHEMERAL, so it must
    # restore the prior history (from S3), append one datapoint, and persist it.
    # If persistence works, day 2 sees day 1's datapoint; a run that started
    # empty each time (the bug) would only ever hold one point.
    import json
    import tempfile
    store = os.path.join(tempfile.mkdtemp(prefix="mh-"), "metric-history.json")

    # Run 1: no prior history on disk (fresh ephemeral container) -> "restore"
    # finds nothing -> start empty, append, persist.
    hist = am.load(store, {}) or {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 5))
    with open(store, "w", encoding="utf-8", newline="\n") as f:
        json.dump(hist, f, indent=1)

    # Run 2: a NEW ephemeral container restores the persisted history, appends
    # the next day, and persists again.
    hist2 = am.load(store, {}) or {}
    assert hist2.get("ksis"), "run 2 must restore run 1's persisted history"
    am.append_run(hist2, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6))
    with open(store, "w", encoding="utf-8", newline="\n") as f:
        json.dump(hist2, f, indent=1)

    final = am.load(store, {})
    assert len(final["ksis"]["KSI-A"]["series"]) == 2, \
        "history must accumulate across ephemeral runs, not reset each run"


def test_pruning_drops_old_points():
    hist = {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2024, 1, 1))
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6))
    dates = [p["date"] for p in hist["ksis"]["KSI-A"]["series"]]
    assert "2024-01-01" not in dates, "points older than RETAIN_DAYS must be pruned"
    assert "2026-09-06" in dates


def test_30_day_window():
    hist = {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 7, 1))
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6))
    # Only the recent point is inside the 30-day window ending 2026-09-06.
    assert hist["ksis"]["KSI-A"]["last_30_days"]["days_observed"] == 1
    assert hist["ksis"]["KSI-A"]["up_to_one_year"]["days_observed"] == 2


def test_mot_window_class_c_short_and_met():
    today = date(2026, 9, 6)
    # A single point today: 0 days covered, Class C requires 183 -> not met.
    short = am.mot_window([{"date": "2026-09-06", "passing": 1, "total": 1}], "c", today)
    assert short["force"] == "MUST"
    assert short["required_days"] == 183
    assert short["covered_days"] == 0
    assert short["meets_window"] is False
    # A point 200 days ago: covered >= 183 -> met.
    met = am.mot_window([{"date": "2026-02-18", "passing": 1, "total": 1}], "c", today)
    assert met["covered_days"] >= 183
    assert met["meets_window"] is True


def test_mot_window_class_d_needs_18_months():
    today = date(2026, 9, 6)
    w = am.mot_window([{"date": "2025-09-06", "passing": 1, "total": 1}], "d", today)
    # ~365 days covered is short of the 548-day (18 month) Class D requirement.
    assert w["required_days"] == 548
    assert w["meets_window"] is False


def test_mot_window_class_b_is_should_not_gated():
    today = date(2026, 9, 6)
    w = am.mot_window([], "b", today)
    assert w["force"] == "SHOULD"
    assert w["required_days"] == 0
    assert w["meets_window"] is True  # no minimum at B


def test_mot_window_calendar_month_boundary():
    # Regression for the day-approximation bug: a series whose earliest point is
    # exactly 6 CALENDAR months before today must MEET the Class C window, even
    # when that span is fewer than 183 days. 2026-03-16 -> 2026-09-16 is exactly
    # 6 calendar months but only 184 days; pick a span that a days>=183 rule
    # would still pass, and a case a day rule would WRONGLY fail.
    today = date(2026, 9, 16)
    # Exactly 6 calendar months back = 2026-03-16 (184 days) -> meets.
    at_boundary = am.mot_window([{"date": "2026-03-16", "passing": 1, "total": 1}], "c", today)
    assert at_boundary["meets_window"] is True
    # The Feb-boundary case that exposes the bug: today 2026-05-31, 6 months
    # back clamps to 2025-11-30. A point on 2025-11-30 is exactly 6 calendar
    # months (182 days, SHORT of 183) but must still MEET the window.
    today2 = date(2026, 5, 31)
    short_days = am.mot_window([{"date": "2025-11-30", "passing": 1, "total": 1}], "c", today2)
    assert short_days["covered_days"] < 183  # a day rule would call this short
    assert short_days["meets_window"] is True  # calendar months: exactly 6 -> met
    # And a point one day inside the window (later) must FAIL.
    inside = am.mot_window([{"date": "2025-12-01", "passing": 1, "total": 1}], "c", today2)
    assert inside["meets_window"] is False


def test_append_run_records_mot_window():
    hist = {}
    am.append_run(hist, REGISTRY, config("COMPLIANT"), {}, date(2026, 9, 6), cls="c")
    w = hist["ksis"]["KSI-A"]["persistent_validation_window"]
    assert w["class"] == "C" and w["force"] == "MUST"


def test_f05_replayed_stale_fact_is_not_recorded_as_fresh():
    # Finding F05: a fact observed in the past, re-read on a later run, must NOT
    # be stamped as a fresh datapoint under require_fresh (production path).
    stale = {"r1": [{"rule": "r1", "compliance_type": "COMPLIANT",
                     "collected_at": "2025-01-01T00:00:00Z"}]}
    hist = {}
    for d in (date(2026, 9, 23), date(2026, 9, 24)):
        am.append_run(hist, REGISTRY, stale, {}, d, require_fresh=True)
    series = hist.get("ksis", {}).get("KSI-A", {}).get("series", [])
    assert series == [], f"replayed 2025 fact must not create 2026 points, got {series}"


def test_f05_fact_observed_today_is_recorded():
    # No over-block: a fact actually collected on the run day IS recorded.
    fresh = {"r1": [{"rule": "r1", "compliance_type": "COMPLIANT",
                     "collected_at": "2026-09-24T00:00:00Z"}]}
    hist = {}
    am.append_run(hist, REGISTRY, fresh, {}, date(2026, 9, 24), require_fresh=True)
    series = hist["ksis"]["KSI-A"]["series"]
    assert len(series) == 1 and series[0]["date"] == "2026-09-24"


def test_f05_main_enforces_freshness_end_to_end():
    # Covers the PRODUCTION path: main() must call append_run with
    # require_fresh=True. Flipping that literal (mutation MUT-F05) must make this
    # test fail. Drive main() with a temp facts store holding one STALE fact and
    # a temp history; assert no datapoint was recorded for the run day.
    import json as _json
    import tempfile
    import types as _types
    d = tempfile.mkdtemp()
    facts_dir = os.path.join(d, "facts")
    os.makedirs(facts_dir)
    # A registry with one config-rule KSI (KSI-A -> rule r1).
    reg = {"meta": {"dataset_version": "test"}, "ksis": {
        "KSI-A": {"metric_service_keys": [],
                  "checks": [{"type": "config_managed_rule", "target": "r1"}]}}}
    reg_path = os.path.join(d, "registry.json")
    with open(reg_path, "w") as f:
        _json.dump(reg, f)
    # One STALE fact (observed a year before the run day).
    with open(os.path.join(facts_dir, "facts-us-east-1.json"), "w") as f:
        _json.dump({"meta": {"collected_at": "2025-09-24T00:00:00Z"},
                    "facts": [{"rule": "r1", "compliance_type": "COMPLIANT",
                               "region": "us-east-1",
                               "collected_at": "2025-09-24T00:00:00Z"}]}, f)
    hist_path = os.path.join(d, "metric-history.json")

    orig = (am.FACTS_DIR, am.HISTORY, am.REGISTRY)
    am.FACTS_DIR, am.HISTORY, am.REGISTRY = facts_dir, hist_path, reg_path
    # Stub argparse so main() sees --today = the run day, not the stale date.
    import argparse as _ap
    real_parse = _ap.ArgumentParser.parse_args

    def fake_parse(self, *a, **k):
        return _types.SimpleNamespace(today="2026-09-24")
    _ap.ArgumentParser.parse_args = fake_parse
    try:
        am.main()
    finally:
        am.FACTS_DIR, am.HISTORY, am.REGISTRY = orig
        _ap.ArgumentParser.parse_args = real_parse
    written = _json.load(open(hist_path)) if os.path.exists(hist_path) else {}
    series = written.get("ksis", {}).get("KSI-A", {}).get("series", [])
    assert series == [], f"main() must not record a stale replayed fact; got {series}"


def test_f07_corrupt_history_is_not_treated_as_first_run():
    # Finding F07: an existing but invalid-JSON history must NOT be silently
    # read as {} (a first run) and then overwritten. load_history_safe returns
    # an error the caller must honor.
    import tempfile
    fd = tempfile.mkdtemp()
    p = os.path.join(fd, "metric-history.json")
    with open(p, "w", encoding="utf-8") as f:
        f.write("{ this is not valid json ")
    data, err = am.load_history_safe(p)
    assert err is not None and data == {}, (data, err)


def test_f07_absent_history_is_a_clean_first_run():
    import tempfile
    p = os.path.join(tempfile.mkdtemp(), "metric-history.json")
    data, err = am.load_history_safe(p)
    assert err is None and data == {}, (data, err)


def test_f07_wrong_shape_history_is_rejected():
    import tempfile
    p = os.path.join(tempfile.mkdtemp(), "metric-history.json")
    with open(p, "w", encoding="utf-8") as f:
        f.write("[1, 2, 3]")  # valid JSON, wrong root type
    data, err = am.load_history_safe(p)
    assert err is not None and data == {}, (data, err)


# --- F03: check-scoped posture routing -------------------------------------
_JIT = {"metric_service_keys": ["iam:role_session_duration"], "checks": []}


def test_f03_unrelated_check_does_not_score_check_scoped_ksi():
    # An IAM password_policy fact must NOT score a KSI scoped to a different IAM
    # check (the audit's KSI-IAM-JIT reproduction).
    dp = am.datapoint_for_ksi(_JIT, {}, {"iam": [
        {"service": "iam", "check": "password_policy", "status": "PRESENT"}]})
    assert dp is None, dp


def test_f03_matching_check_scores():
    dp = am.datapoint_for_ksi(_JIT, {}, {"iam": [
        {"service": "iam", "check": "role_session_duration",
         "status": "OBSERVED", "measured": 2, "total": 5}]})
    assert dp == {"passing": 2, "total": 5}, dp


def test_f03_per_metric_keeps_per_check_identity():
    ksi = {"metric_service_keys": ["s3:encryption", "s3:public_access"], "checks": []}
    pm = am.per_metric_datapoints_for_ksi(ksi, {}, {"s3": [
        {"service": "s3", "check": "encryption", "status": "OBSERVED",
         "measured": 1, "total": 1},
        {"service": "s3", "check": "public_access", "status": "OBSERVED",
         "measured": 0, "total": 1}]})
    assert "posture:s3:encryption" in pm and "posture:s3:public_access" in pm, pm
    assert pm["posture:s3:encryption"]["passing"] == 1
    assert pm["posture:s3:public_access"]["passing"] == 0


# --- AUD-F16: never route a whole service ------------------------------------

def test_f16_bare_service_key_is_refused():
    ksi = {"metric_service_keys": ["accessanalyzer"], "checks": []}
    raised = False
    try:
        am.datapoint_for_ksi(ksi, {}, {"accessanalyzer": [
            {"service": "accessanalyzer", "check": "analyzer", "status": "PRESENT"}]})
    except ValueError:
        raised = True
    assert raised, "a bare service key must be refused, not widened to every check"


def test_f16_analyzer_presence_cannot_lift_elp_while_findings_are_open():
    # The audit case: analyzer PRESENT (1/1) must not improve least privilege
    # when active findings say it is failing. Routed by the real check only.
    ksi = {"metric_service_keys": ["accessanalyzer:active_findings"], "checks": []}
    posture = {"accessanalyzer": [
        {"service": "accessanalyzer", "check": "analyzer", "status": "PRESENT"},
        {"service": "accessanalyzer", "check": "active_findings", "status": "OBSERVED",
         "measured": 0, "total": 1}]}
    dp = am.datapoint_for_ksi(ksi, {}, posture)
    assert dp["passing"] == 0 and dp["total"] == 1, dp


def test_f16_real_registry_has_no_bare_service_routes():
    import json as _j
    reg = _j.load(open(os.path.join(am.BASE, "automation", "collectors", "registry.json"),
                       encoding="utf-8"))
    from method_ids import bare_service_keys
    assert bare_service_keys(reg) == [], bare_service_keys(reg)


# --- AUD-F15 / AUD-F17: partial enumeration and low coverage never score ----

def test_f15_partial_flag_never_scores_even_with_a_ratio():
    pf = {"service": "kms", "check": "key_rotation", "status": "OBSERVED",
          "measured": 10, "total": 10, "scope_total": 10, "partial": True}
    assert am._posture_score(pf) is None
    pf2 = {"service": "kms", "check": "key_rotation", "status": "OBSERVED_PARTIAL",
           "measured": 10, "total": 10}
    assert am._posture_score(pf2) is None


def test_f17_low_evaluated_coverage_is_not_a_confident_pass():
    # 10 readable of 50 in scope, all 10 pass: NOT 100%. Withheld, and the gap
    # is recorded on the datapoint so it is visible rather than silent.
    ksi = {"metric_service_keys": ["kms:key_rotation"], "checks": []}
    pf = {"service": "kms", "check": "key_rotation", "status": "OBSERVED",
          "measured": 10, "total": 10, "evaluated_total": 10,
          "scope_total": 50, "unknown_total": 40}
    assert am._posture_score(pf) is None
    dp = am.datapoint_for_ksi(ksi, {}, {"kms": [pf]})
    assert dp is None, dp  # nothing else scored -> no datapoint, not a pass
    # With a second, fully covered metric the KSI still gets a point, and the
    # withheld one is named in coverage_gaps.
    ksi2 = {"metric_service_keys": ["kms:key_rotation", "s3:encryption"], "checks": []}
    ok = {"service": "s3", "check": "encryption", "status": "OBSERVED",
          "measured": 3, "total": 4, "evaluated_total": 4, "scope_total": 4,
          "unknown_total": 0}
    dp2 = am.datapoint_for_ksi(ksi2, {}, {"kms": [pf], "s3": [ok]})
    assert dp2["passing"] == 3 and dp2["total"] == 4, dp2
    assert dp2["scope_total"] == 4 and dp2["evaluated_total"] == 4, dp2
    assert any("posture:kms:key_rotation" in g and "coverage 10/50" in g
               for g in dp2["coverage_gaps"]), dp2


def test_f17_one_readable_bucket_of_100_does_not_score():
    pf = {"service": "s3", "check": "encryption", "status": "OBSERVED",
          "measured": 1, "total": 1, "evaluated_total": 1,
          "scope_total": 100, "unknown_total": 99}
    assert am._posture_score(pf) is None


def test_f17_full_coverage_scores_and_carries_coverage():
    ksi = {"metric_service_keys": ["kms:key_rotation"], "checks": []}
    pf = {"service": "kms", "check": "key_rotation", "status": "OBSERVED",
          "measured": 48, "total": 50, "evaluated_total": 50,
          "scope_total": 50, "unknown_total": 0}
    dp = am.datapoint_for_ksi(ksi, {}, {"kms": [pf]})
    assert dp["passing"] == 48 and dp["total"] == 50
    assert dp["scope_total"] == 50 and dp["unknown_total"] == 0
    assert "coverage_gaps" not in dp


def test_f17_no_scope_info_still_scores_legacy_facts():
    # Older facts / binary checks carry no scope; they keep scoring as before.
    pf = {"service": "kms", "check": "key_rotation", "status": "OBSERVED",
          "measured": 2, "total": 2}
    assert am._posture_score(pf) == (2, 2)


# --- AUD-F19: same-day runs are never destructive ---------------------------

def _reg_one(kid="KSI-X"):
    return {"ksis": {kid: {"metric_service_keys": ["kms:key_rotation"], "checks": []}},
            "meta": {"dataset_version": "t"}}


def _kms(measured, total, at):
    return {"kms": [{"service": "kms", "check": "key_rotation", "status": "OBSERVED",
                     "measured": measured, "total": total, "collected_at": at}]}


def test_f19_morning_failure_survives_evening_pass():
    today = date(2026, 9, 25)
    h = {}
    am.append_run(h, _reg_one(), {}, _kms(0, 10, "2026-09-25T06:00:00+00:00"), today,
                  observed_at="2026-09-25T06:00:00+00:00")
    am.append_run(h, _reg_one(), {}, _kms(10, 10, "2026-09-25T18:00:00+00:00"), today,
                  observed_at="2026-09-25T18:00:00+00:00")
    e = h["ksis"]["KSI-X"]
    assert len(e["series"]) == 1, e["series"]
    pt = e["series"][0]
    # Conservative rollup: the day reads as the WORST run.
    assert pt["passing"] == 0 and pt["total"] == 10, pt
    assert pt["runs"] == 2 and pt["min_fraction"] == 0.0 and pt["max_fraction"] == 1.0, pt
    # Both runs are preserved verbatim as immutable observations.
    assert [o["observed_at"] for o in e["observations"]] == [
        "2026-09-25T06:00:00+00:00", "2026-09-25T18:00:00+00:00"]
    assert [o["passing"] for o in e["observations"]] == [0, 10]
    # Per-metric series rolls up the same way.
    m = e["metrics"]["posture:kms:key_rotation"]["series"][0]
    assert m["passing"] == 0 and m["runs"] == 2, m


def test_f19_evening_failure_after_morning_pass_also_reads_as_failure():
    today = date(2026, 9, 25)
    h = {}
    am.append_run(h, _reg_one(), {}, _kms(10, 10, "2026-09-25T06:00:00+00:00"), today,
                  observed_at="2026-09-25T06:00:00+00:00")
    am.append_run(h, _reg_one(), {}, _kms(3, 10, "2026-09-25T18:00:00+00:00"), today,
                  observed_at="2026-09-25T18:00:00+00:00")
    pt = h["ksis"]["KSI-X"]["series"][0]
    assert pt["passing"] == 3 and pt["runs"] == 2, pt


def test_f19_single_run_day_is_unchanged_in_meaning():
    today = date(2026, 9, 25)
    h = {}
    am.append_run(h, _reg_one(), {}, _kms(7, 10, "2026-09-25T06:00:00+00:00"), today,
                  observed_at="2026-09-25T06:00:00+00:00")
    pt = h["ksis"]["KSI-X"]["series"][0]
    assert pt["passing"] == 7 and pt["total"] == 10 and pt["runs"] == 1
    assert am.summarize(h["ksis"]["KSI-X"]["series"])["avg_passing_fraction"] == 0.7


def test_f19_observations_are_pruned_with_retention():
    old = date(2025, 1, 1)
    h = {}
    am.append_run(h, _reg_one(), {}, _kms(1, 1, "2025-01-01T06:00:00+00:00"), old,
                  observed_at="2025-01-01T06:00:00+00:00")
    later = date(2026, 9, 25)
    am.append_run(h, _reg_one(), {}, _kms(1, 1, "2026-09-25T06:00:00+00:00"), later,
                  observed_at="2026-09-25T06:00:00+00:00")
    obs = h["ksis"]["KSI-X"]["observations"]
    assert [o["date"] for o in obs] == ["2026-09-25"], obs


def test_f30_empty_run_does_not_advance_last_run():
    """AUD-F30: a run that appends NO datapoint (every fact errored or was
    stale) must not stamp meta.last_run, or the history looks freshly
    maintained after a failed collection. The attempt is still recorded."""
    h = {}
    d1 = date(2026, 9, 24)
    n = am.append_run(h, _reg_one(), {}, _kms(1, 1, "2026-09-24T06:00:00+00:00"), d1,
                      observed_at="2026-09-24T06:00:00+00:00")
    assert n == 1
    assert h["meta"]["last_run"] == "2026-09-24"
    assert h["meta"]["last_attempt"]["outcome"] == "OK"
    # Next day: the collector produced only ERROR facts -> nothing scores.
    d2 = date(2026, 9, 25)
    errored = {"kms": [{"service": "kms", "check": "key_rotation", "status": "ERROR:AccessDenied",
                        "collected_at": "2026-09-25T06:00:00+00:00"}]}
    n2 = am.append_run(h, _reg_one(), {}, errored, d2, observed_at="2026-09-25T06:00:00+00:00")
    assert n2 == 0
    assert h["meta"]["last_run"] == "2026-09-24", h["meta"]
    assert h["meta"]["last_observed_at"] == "2026-09-24T06:00:00+00:00"
    assert h["meta"]["last_attempt"] == {
        "date": "2026-09-25", "observed_at": "2026-09-25T06:00:00+00:00",
        "appended": 0, "outcome": "NO_DATAPOINTS"}, h["meta"]["last_attempt"]
    # The series itself is untouched by the empty run.
    assert [p["date"] for p in h["ksis"]["KSI-X"]["series"]] == ["2026-09-24"]


def test_f30_main_exits_nonzero_when_nothing_appended():
    """AUD-F30: the CLI must FAIL (exit 4) on an empty run so the scheduled
    loops fail loudly instead of reporting a healthy day."""
    import json
    import tempfile
    tmp = tempfile.mkdtemp(prefix="am-f30-")
    facts_dir = os.path.join(tmp, "facts")
    os.makedirs(facts_dir)
    # A facts store whose every posture fact errored.
    with open(os.path.join(facts_dir, "facts-us-east-1.json"), "w", encoding="utf-8") as f:
        json.dump({"meta": {"collected_at": "2026-09-25T06:00:00+00:00"},
                   "facts": [],
                   "posture_facts": [{"service": "kms", "check": "key_rotation",
                                      "status": "ERROR:AccessDenied", "region": "us-east-1",
                                      "collected_at": "2026-09-25T06:00:00+00:00"}]}, f)
    registry_path = os.path.join(tmp, "registry.json")
    with open(registry_path, "w", encoding="utf-8") as f:
        json.dump(_reg_one(), f)
    history_path = os.path.join(tmp, "metric-history.json")
    saved = (am.REGISTRY, am.FACTS_DIR, am.HISTORY, sys.argv)
    try:
        am.REGISTRY, am.FACTS_DIR, am.HISTORY = registry_path, facts_dir, history_path
        sys.argv = ["append_metrics.py", "--today", "2026-09-25"]
        rc = am.main()
        assert rc == am.EXIT_NO_DATAPOINTS == 4, rc
        with open(history_path, encoding="utf-8") as f:
            h = json.load(f)
        assert h["meta"]["last_run"] is None
        assert h["meta"]["last_attempt"]["appended"] == 0
    finally:
        am.REGISTRY, am.FACTS_DIR, am.HISTORY, sys.argv = saved


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
