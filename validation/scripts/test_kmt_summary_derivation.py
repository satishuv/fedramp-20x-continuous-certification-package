#!/usr/bin/env python3
"""Offline tests for SDR-CSX-KMT summary derivation (findings 1 and 2).

Finding 1: the 30-day and 1-year summaries emitted into the SDR must be DERIVED
from the immutable metric-history.json series (the same store dailyData comes
from), not read from a hand-authored records-store field that could contradict
the real history.

Finding 2: those summaries must slice the retained history to the EXACT FedRAMP
windows (last30 = the 30 dates today-29..today; lastYear = >= 12 calendar
months), even though storage keeps ~400 days.

No AWS, no boto3, no disk. Run:
    python validation/scripts/test_kmt_summary_derivation.py
"""

import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_sdr as bs  # noqa: E402

PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"PASS: {name}")
    else:
        FAIL += 1
        print(f"FAIL: {name}")


def _series(n_days, frac_fn, end=None):
    """Build n_days of daily {date,passing,total} ending today (or `end`).

    'Today' is the UTC calendar day: _window_summaries slices on _utc_today()
    (finding F10/F11), so a fixture ending on the host's LOCAL date is one day
    short of the 30-date window whenever local time is west of UTC and past
    UTC midnight (every US evening). Same clock as production, or the test
    measures the host's timezone instead of the derivation."""
    end = end or bs._utc_today()
    out = []
    for i in range(n_days):
        d = end - datetime.timedelta(days=i)
        passing, total = frac_fn(i)
        out.append({"date": d.isoformat(), "passing": passing, "total": total})
    out.sort(key=lambda p: p["date"])
    return out


def test_window_summaries_exact_30_and_year():
    # 400 days of all-passing data. The 30-day window must summarize exactly 30
    # dates; the year window must summarize the >=12-calendar-month slice, both
    # strictly fewer than the 400 stored.
    series = _series(400, lambda i: (1, 1))
    s30, syr = bs._window_summaries(series)
    check("30-day window summarizes exactly 30 dates",
          s30 is not None and s30["days_observed"] == 30)
    check("year window summarizes fewer than the full 400 stored",
          syr is not None and syr["days_observed"] < 400)
    check("year window covers roughly a calendar year (>= 360 dates)",
          syr["days_observed"] >= 360)
    check("all-passing 30-day average is 1.0", s30["avg_passing_fraction"] == 1.0)


def test_recent_failures_not_diluted_out_of_30day():
    # First 100 days (oldest) fail, rest pass. 30-day window is all-recent -> 1.0;
    # year window is dragged below 1.0 by the older failures.
    def frac(i):  # i counts back from today; large i == older
        return (0, 1) if i >= 300 else (1, 1)
    series = _series(400, frac)
    s30, syr = bs._window_summaries(series)
    check("recent 30-day window is all-passing despite old failures",
          s30["avg_passing_fraction"] == 1.0)
    check("year window average is below 1.0 (old failures counted)",
          syr["avg_passing_fraction"] is not None and syr["avg_passing_fraction"] < 1.0)


def test_ksi_semantic_prefers_derived_over_handauthored():
    # A record hand-authors a bogus '100% passing' summary; a real history with
    # failures is threaded in. ksi_semantic must EMIT the derived summary, not
    # the hand-authored string.
    rec = {
        "extension": {"measures": "Real measures.", "owner": "Team"},
        "historical_metrics": {
            "last_30_days": "100% passing, trust me",
            "up_to_one_year": "100% passing, trust me",
            "daily_data_reference": "https://x.invalid/d.json",
        },
    }
    series = _series(120, lambda i: (0, 1) if i % 2 else (1, 1))
    block = bs.ksi_semantic(rec, daily_series=series)["historicalMetrics"]
    check("derived last30Days is a computed summary dict, not the hand string",
          isinstance(block["last30Days"], dict)
          and "avg_passing_fraction" in block["last30Days"])
    check("derived upToOneYear is a computed summary dict",
          isinstance(block["upToOneYear"], dict))
    check("derived 30-day average reflects the real ~0.5 pattern, not the bogus claim",
          abs((block["last30Days"]["avg_passing_fraction"] or 0) - 0.5) <= 0.15)
    check("dailyData is the threaded durable series",
          block["dailyData"] == series)


def test_ksi_semantic_falls_back_when_no_history():
    # No history threaded in -> fall back to the hand-authored value (a KSI
    # genuinely absent from history), never fabricate a series.
    rec = {"extension": {"measures": "m"},
           "historical_metrics": {"last_30_days": "hand summary",
                                  "up_to_one_year": "hand summary"}}
    block = bs.ksi_semantic(rec, daily_series=None)["historicalMetrics"]
    check("falls back to hand-authored last30Days when no history",
          block["last30Days"] == "hand summary")
    check("dailyData is empty when no history and no hand daily_data",
          block["dailyData"] == [])


def main():
    tests = [(k, v) for k, v in globals().items()
             if k.startswith("test_") and callable(v)]
    for _, fn in sorted(tests, key=lambda kv: kv[0]):
        fn()
    print(f"\n{PASS}/{PASS + FAIL} passed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
