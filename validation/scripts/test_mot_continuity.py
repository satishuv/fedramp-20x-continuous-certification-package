# Offline tests for the FRC-CSX-MOT continuity (persistent-validation) helper.
#
# The MOT age check proves the oldest datapoint reaches back far enough. That is
# necessary but not sufficient: a series of [6-months-ago, today] passes the age
# check yet is not "status from persistent validation over at least the past 6
# months". mot_continuity() bounds the largest gap (and the leading/trailing
# gaps) against an explicit REPOSITORY POLICY tolerance (sdr.mot_max_gap_days:
# default 45 days, offering-declared override reviewable by the assessor). The
# rule states no cadence and no maximum gap; the observed median cadence is
# reported for context, never used as the bound.
#
# Run: python validation/scripts/test_mot_continuity.py

import os
import sys
import datetime as dt

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE)
import sdr  # noqa: E402

_fail = 0


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def _daily(today, n):
    """n consecutive daily dates ending today."""
    return [today - dt.timedelta(days=i) for i in range(n)]


def main():
    today = dt.date(2026, 9, 17)

    # Continuous daily series across ~6 months: NOT gappy.
    daily = _daily(today, 190)
    gappy, largest, median, trailing = sdr.mot_continuity(daily, today)
    check("continuous daily 6-month series is not gappy", gappy is False)
    check("continuous daily series median gap is 1 day", median == 1)
    check("continuous daily series trailing gap is 0", trailing == 0)

    # The classic hollow case: exactly two points, 6 months apart. GAPPY.
    two = [dt.date(2026, 3, 17), today]
    gappy2, largest2, _m2, _t2 = sdr.mot_continuity(two, today)
    check("two-points-6-months-apart is gappy", gappy2 is True)
    check("two-point largest gap is the whole window", largest2 and largest2 > 45)

    # A single in-window point is not persistent validation.
    one = [dt.date(2026, 6, 1)]
    g1, l1, m1, t1 = sdr.mot_continuity(one, today)
    check("single in-window point is gappy", g1 is True)
    check("single point returns None gap metrics", l1 is None and m1 is None)

    # Honest WEEKLY cadence with one occasional miss (14-day gap once): the
    # median is ~7, tolerance is max(4*7, 45)=45, so a single 14-day gap is fine.
    weekly = []
    d = today
    for i in range(28):  # ~6.5 months of weekly points
        weekly.append(d)
        d = d - dt.timedelta(days=7)
    # introduce one 14-day gap by dropping a point
    weekly = [x for x in weekly if x != weekly[10]]
    gw, lw, mw, tw = sdr.mot_continuity(sorted(weekly), today)
    check("honest weekly cadence with one miss is NOT gappy", gw is False)
    check("weekly median gap is ~7 days", 6 <= mw <= 8)

    # A monthly-then-silent series: monthly for 3 months then a 90-day silence
    # at the end -> trailing gap trips the tolerance.
    monthly = [today - dt.timedelta(days=k) for k in (185, 155, 125, 95)]
    gm, lm, mm, tm = sdr.mot_continuity(sorted(monthly), today)
    check("stale trailing gap (95 days since last point) is gappy", gm is True)
    check("stale series reports the trailing gap", tm == 95)

    # A big mid-window gap (100 days) between otherwise-daily runs trips it.
    a = _daily(today, 30)
    b = [today - dt.timedelta(days=k) for k in range(150, 180)]
    mixed = sorted(a + b)
    gmix, lmix, _mmix, _tmix = sdr.mot_continuity(mixed, today)
    check("100+ day mid-window gap is gappy", gmix is True and lmix > 45)

    # Finding F06: LEADING-gap enforcement. window_start is the 6-month cutoff.
    # A series that only STARTS near today (e.g. the in-window part is just the
    # last two daily points) leaves nearly the whole window unobserved. Without
    # window_start this passed; with it, the leading gap must trip.
    cutoff = today - dt.timedelta(days=183)
    recent_only = [today - dt.timedelta(days=1), today]
    glead, llead, _ml, _tl = sdr.mot_continuity(recent_only, today, window_start=cutoff)
    check("F06: in-window points only near today -> gappy (leading gap)",
          glead is True and llead > 45)

    # F06 no-over-block: a series that genuinely covers the window from the
    # cutoff onward (daily from cutoff to today) is NOT gappy even with
    # window_start enforced.
    covered = [cutoff + dt.timedelta(days=i)
               for i in range((today - cutoff).days + 1)]
    gcov, _lc, _mc, _tc = sdr.mot_continuity(covered, today, window_start=cutoff)
    check("F06: full-window daily coverage is NOT gappy (no over-block)",
          gcov is False)

    # F06 boundary: the classic three-point bypass [300d ago, yesterday, today]
    # after the caller filters to >= cutoff leaves [yesterday, today]; with
    # window_start the leading void from cutoff is measured -> gappy.
    three_in_window = [d for d in [today - dt.timedelta(days=300),
                                   today - dt.timedelta(days=1), today]
                       if d >= cutoff]
    g3, l3, _m3, _t3 = sdr.mot_continuity(three_in_window, today, window_start=cutoff)
    check("F06: 300d-ago+two-recent (filtered) -> gappy via leading gap",
          g3 is True and l3 > 45)

    # --- AUD-F21: the tolerance is explicit project policy with a bounded,
    #     reviewable offering override; never presented as a FedRAMP figure.
    d, src = sdr.mot_max_gap_days({})
    check("F21: no declaration -> project default 45 from project-default",
          d == sdr.MOT_MAX_GAP_DAYS_DEFAULT == 45 and src == "project-default")
    d, src = sdr.mot_max_gap_days({"mot_max_gap_days": 14})
    check("F21: declared 14 -> 14 from offering-profile",
          d == 14 and src == "offering-profile")
    d, src = sdr.mot_max_gap_days({"mot_max_gap_days": "30"})
    check("F21: declared as a numeric string is accepted", d == 30)
    d, src = sdr.mot_max_gap_days({"mot_max_gap_days": 400})
    check("F21: a tolerance above the ceiling is INVALID, not accepted",
          d is None and src.startswith("invalid"))
    d, src = sdr.mot_max_gap_days({"mot_max_gap_days": 0})
    check("F21: zero is invalid", d is None)
    d, src = sdr.mot_max_gap_days({"mot_max_gap_days": "weekly"})
    check("F21: a non-integer is invalid", d is None and "not an integer" in src)
    # The declared tolerance actually drives mot_continuity: a steady 20-day
    # cadence across the whole window is fine at 45 but gappy at 14.
    series = [cutoff + dt.timedelta(days=20 * i) for i in range(10)] + [today]
    g45, _l, _m, _t = sdr.mot_continuity(series, today, max_gap_days=45, window_start=cutoff)
    g14, _l, _m, _t = sdr.mot_continuity(series, today, max_gap_days=14, window_start=cutoff)
    check("F21: declared tolerance changes the verdict (45 ok, 14 gappy)",
          g45 is False and g14 is True)
    src_text = open(os.path.join(BASE, "sdr.py"), encoding="utf-8").read()
    check("F21: preflight passes the policy tolerance to mot_continuity",
          "max_gap_days=mot_gap_days" in src_text)
    check("F21: preflight messages call the tolerance a project policy",
          "a project policy, not a FedRAMP figure" in src_text)

    # AUD-F33: a stalled collection is reported as an ADVISORY well inside the
    # 45-day hard bound, instead of staying silent until it becomes a blocker.
    fresh = [today - dt.timedelta(days=i) for i in range(0, 60)]
    check("F33: a series observed today is not stale",
          sdr.mot_stale_days(fresh, today) is None)
    threshold = sdr.MOT_STALE_ADVISORY_DAYS
    check("F33: the advisory threshold sits well inside the continuity bound",
          0 < threshold < sdr.MOT_MAX_GAP_DAYS_DEFAULT)
    at_threshold = [today - dt.timedelta(days=threshold)]
    check("F33: exactly at the threshold is not yet stale",
          sdr.mot_stale_days(at_threshold, today) is None)
    stalled = [today - dt.timedelta(days=d) for d in range(20, 200)]  # stopped 20 days ago
    g_st, _l, _m, _t = sdr.mot_continuity(sorted(stalled), today, max_gap_days=45,
                                          window_start=cutoff)
    check("F33: a 20-day stall is NOT yet a continuity blocker at the 45-day bound",
          g_st is False)
    check("F33: ...but IS reported stale by the advisory helper (20 days)",
          sdr.mot_stale_days(stalled, today) == 20)
    check("F33: an empty series is not reported stale (handled as missing elsewhere)",
          sdr.mot_stale_days([], today) is None)
    stale_start = src_text.find("if stale:")
    stale_block = src_text[stale_start:src_text.find("if missing:", stale_start)]
    check("F33: preflight reports staleness through warnings (advisory), never blockers",
          "mot_stale_days(dates, today)" in src_text
          and "warnings.append(" in stale_block and "blockers.append(" not in stale_block)

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: mot_continuity ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
