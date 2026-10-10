#!/usr/bin/env python3
"""AUD-F42: a record-store entry whose rule or KSI the dataset no longer defines
is reported, never silently kept with hollowed guidance and never pruned.

The 2026.10.08.01 adoption removed FRC-CSX-MOT from the dataset. The drift
workflow regenerated every derived artifact, but the record store is authored
content, so the FRC-CSX-MOT record stayed behind: its fill_guidance collapsed
to "See rule catalog." and nothing said so. These checks pin the helper that
finds such orphans and the two places that report them (the build's output and
preflight's advisory), against the committed catalogs and a synthetic store.

Run: python validation/scripts/test_orphan_records.py
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import build_sdr as bs  # noqa: E402

FAILURES = []


def check(name, cond, detail=""):
    print(("  PASS " if cond else "  FAIL ") + name + (f" :: {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def main():
    rules, ksis = bs.dataset_universe()
    check("dataset universe is non-empty (rules)", len(rules) > 200, f"{len(rules)}")
    check("dataset universe is non-empty (KSIs)", len(ksis) == 46, f"{len(ksis)}")
    check("the removed rule is NOT in the universe", "FRC-CSX-MOT" not in rules)
    check("a live rule IS in the universe", "SDR-CSX-KMT" in rules)

    # Synthetic store: one live rule, one orphan rule, one live KSI, one orphan KSI.
    live_ksi = sorted(ksis)[0]
    store = {"frr": {"SDR-CSX-KMT": {}, "FRC-CSX-MOT": {}},
             "ksi": {live_ksi: {}, "KSI-ZZZ-GONE": {}}}
    o_rules, o_ksis = bs.orphan_record_ids(store, rules, ksis)
    check("orphan rule is found", o_rules == ["FRC-CSX-MOT"], str(o_rules))
    check("orphan KSI is found", o_ksis == ["KSI-ZZZ-GONE"], str(o_ksis))
    check("live ids are not reported", "SDR-CSX-KMT" not in o_rules and live_ksi not in o_ksis)
    # An empty universe (catalog unreadable) must not flag everything as orphaned.
    check("unreadable catalog reports nothing rather than everything",
          bs.orphan_record_ids(store, set(), set()) == ([], []))

    # The committed template store carries no orphan after the adoption.
    with open(bs.RECORDS, encoding="utf-8") as f:
        records = json.load(f)
    o_rules, o_ksis = bs.orphan_record_ids(records, rules, ksis)
    check("committed record store has no orphaned rule record", o_rules == [], str(o_rules))
    check("committed record store has no orphaned KSI record", o_ksis == [], str(o_ksis))

    # Both reporters exist in source and say ORPHAN / AUD-F42 (the build prints,
    # preflight warns); the mutation MUT-F42 disables the helper and expects red.
    build_src = open(os.path.join(HERE, "build_sdr.py"), encoding="utf-8").read()
    sdr_src = open(os.path.join(BASE, "sdr.py"), encoding="utf-8").read()
    check("build reports orphans", "ORPHANED record(s)" in build_src)
    check("preflight reports orphans as an advisory (AUD-F42)",
          "orphan_record_ids" in sdr_src and "Remove or archive them (AUD-F42)" in sdr_src)

    print()
    if FAILURES:
        print(f"FAIL: orphan_records ({len(FAILURES)} failures)")
        return 1
    print("PASS: orphan_records (0 failures)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
