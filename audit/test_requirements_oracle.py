#!/usr/bin/env python3
"""Self-test for the requirements-differential oracle (AUD-F22).

An oracle is only worth having if it can be wrong loudly. This feeds the FRR
reconciliation deliberately tampered profiles and asserts it reports each
tamper: a dropped rule, an added rule, a demoted force (MUST -> SHOULD), a
changed statement, a changed timeframe, and an EMPTY profile (RULE 7: an
empty-vs-empty reconciliation must never read as clean). It also checks the
oracle's own counts against the pinned anchors so a traversal that silently
finds nothing cannot pass.

    python audit/test_requirements_oracle.py
"""
import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import requirements_oracle as ro  # noqa: E402

_fail = 0


def check(name, cond, detail=""):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}" + (f" -- {detail}" if detail else ""))


def _names(findings):
    return [f[0] for f in findings]


def main():
    with open(ro.DATASET, encoding="utf-8") as f:
        dataset = json.load(f)
    profiles = {}
    for cls in ("a", "b", "c"):
        with open(os.path.join(BASE, "profiles", f"class-{cls}", "profile.json"),
                  encoding="utf-8") as f:
            profiles[cls] = json.load(f)["rules"]

    # Baseline: the committed profiles reconcile, with the anchored counts.
    for cls in ("a", "b", "c"):
        findings, n = ro.reconcile_frr(dataset, cls, profiles[cls])
        check(f"class {cls.upper()}: committed profile reconciles clean", findings == [],
              json.dumps(findings[:2]))
        check(f"class {cls.upper()}: oracle count equals pinned anchor {ro.EXPECTED_COUNTS[cls]}",
              n == ro.EXPECTED_COUNTS[cls], f"n={n}")

    b = profiles["b"]
    # Tamper 1: drop a rule.
    findings, _ = ro.reconcile_frr(dataset, "b", b[1:])
    check("dropped rule is reported as a set mismatch",
          any("rule set mismatch" in x for x in _names(findings)))
    # Tamper 2: add a rule that the dataset does not give Class B.
    extra = copy.deepcopy(b[0]); extra["rule_id"] = "ZZZ-ZZZ-ZZZ"
    findings, _ = ro.reconcile_frr(dataset, "b", b + [extra])
    check("added rule is reported as a set mismatch",
          any("rule set mismatch" in x for x in _names(findings)))
    # Tamper 3: demote a MUST to SHOULD.
    t = copy.deepcopy(b)
    victim = next(r for r in t if r.get("force") == "MUST")
    victim["force"] = "SHOULD"
    findings, _ = ro.reconcile_frr(dataset, "b", t)
    check("MUST -> SHOULD demotion is reported",
          any(f"{victim['rule_id']} force mismatch" in x for x in _names(findings)),
          json.dumps(_names(findings)[:3]))
    # Tamper 4: change a statement.
    t = copy.deepcopy(b); t[5]["statement"] = t[5]["statement"] + " (edited)"
    findings, _ = ro.reconcile_frr(dataset, "b", t)
    check("statement edit is reported",
          any(f"{t[5]['rule_id']} statement mismatch" in x for x in _names(findings)))
    # Tamper 5: change a timeframe on a rule that has one.
    t = copy.deepcopy(profiles["c"])
    timed = next(r for r in t if r.get("timeframe_num") is not None)
    timed["timeframe_num"] = (timed["timeframe_num"] or 0) + 1
    findings, _ = ro.reconcile_frr(dataset, "c", t)
    check("timeframe edit is reported (class C)",
          any(f"{timed['rule_id']} timeframe_num mismatch" in x for x in _names(findings)))
    # Tamper 6: class-variant force. Pick a rule whose force differs between B
    # and C in the profiles and swap C's force to B's; the oracle must notice.
    by_b = {r["rule_id"]: r for r in b}
    swapped = None
    t = copy.deepcopy(profiles["c"])
    for r in t:
        rb = by_b.get(r["rule_id"])
        if rb and rb.get("force") != r.get("force"):
            r["force"] = rb.get("force"); swapped = r["rule_id"]; break
    check("a class-variant force exists between B and C to test with", swapped is not None)
    if swapped:
        findings, _ = ro.reconcile_frr(dataset, "c", t)
        check("class-variant force swap (C given B's force) is reported",
              any(f"{swapped} force mismatch" in x for x in _names(findings)))
    # RULE 7: empty profile must not reconcile.
    findings, n = ro.reconcile_frr(dataset, "b", [])
    check("empty profile is NOT clean (RULE 7)", bool(findings) and n == 157)
    # Class A tamper: drop one enumerated rule.
    findings, _ = ro.reconcile_frr(dataset, "a", profiles["a"][:-1])
    check("class A dropped rule is reported",
          any("Class A rule set mismatch" in x for x in _names(findings)))

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: requirements_oracle self-test ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
