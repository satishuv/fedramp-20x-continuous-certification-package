#!/usr/bin/env python3
"""Per-artifact obligation classification (AUD-F54).

A rule's artifacts are listed as separate items in the CR26 dataset and one
rule can mix a mandatory item with an "if applicable" one. The gate decides per
obligation: a rule is hard-gated as soon as any obligation demands an artifact
and is advisory only when every obligation has a no-artifact branch. The
synthetic mixed rule the audit asked for ("Provide A" + "Provide B if
applicable") must gate; and the one real instance in dataset 2026.10.08.01,
CDS-CSO-SVC, must be in the hard-gated set at every class.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, BASE)
import sdr  # noqa: E402

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}" + (f": {detail}" if detail else ""))


def find_rule(node, rid):
    if isinstance(node, dict):
        if rid in node and isinstance(node[rid], dict):
            return node[rid]
        for v in node.values():
            r = find_rule(v, rid)
            if r is not None:
                return r
    return None


def main():
    print("== synthetic obligations")
    obl = sdr.artifact_obligations(["Provide A", "Provide B if applicable."])
    check("a mixed rule yields one obligation per item, classified on its own",
          [k for _t, k in obl] == ["REQUIRED", "CONDITIONAL"])
    check("mixed mandatory + 'if applicable' rule is REQUIRED (hard-gated), not CONDITIONAL",
          sdr._classify_artifact(["Provide A", "Provide B if applicable."]) == "REQUIRED")
    check("order does not matter: 'if applicable' first, mandatory second still gates",
          sdr._classify_artifact(["Provide B if applicable.", "Provide A"]) == "REQUIRED")
    check("all-conditional rule stays CONDITIONAL (advisory)",
          sdr._classify_artifact(["Provide B if applicable.", "Provide C where available."]) == "CONDITIONAL")
    check("one-of beside a conditional is REQUIRED_ONE_OF (hard-gated)",
          sdr._classify_artifact(["Report or a sample report.", "Provide C if applicable."]) == "REQUIRED_ONE_OF")
    check("one-of beside a mandatory item is REQUIRED",
          sdr._classify_artifact(["Report or a sample report.", "Provide A"]) == "REQUIRED")
    check("an 'or ...' item continues the previous obligation (one deliverable with an alternative)",
          sdr.artifact_obligations(["Explanation of how to access this information",
                                    "or explanation why this functionality is not available"])
          == [("Explanation of how to access this information or explanation why this "
               "functionality is not available", "REQUIRED_ONE_OF")])
    check("empty / blank wording yields no obligations and no verdict",
          sdr.artifact_obligations([]) == [] and sdr.artifact_obligations(["", "  "]) == []
          and sdr._classify_artifact([]) is None)
    check("a bare descriptive 'or' inside a noun phrase is still unconditional",
          sdr._classify_artifact(["Evidence that modules are validated or are update streams of such modules."])
          == "REQUIRED")

    print("== dataset 2026.10.08.01: the real mixed rule")
    ds = json.load(open(os.path.join(BASE, "references", "fedramp-consolidated-rules.json"), encoding="utf-8"))
    svc = find_rule(ds, "CDS-CSO-SVC")
    arts = [s for v in (svc.get("artifacts") or {}).values() for s in (v or [])]
    kinds = [k for _t, k in sdr.artifact_obligations(arts)]
    check("CDS-CSO-SVC lists a mandatory human-readable URL and an 'if applicable' machine-readable one",
          kinds == ["REQUIRED", "CONDITIONAL"], str(arts))
    check("CDS-CSO-SVC is MUST with no class variation", svc.get("force") == "MUST"
          and not svc.get("varies_by_class"))
    for cls in ("a", "b", "c", "d"):
        sdr._ARTIFACT_REQUIRED_RULES_CACHE.clear()
        gated = sdr.artifact_required_rule_ids(cls)
        check(f"CDS-CSO-SVC is in the hard-gated artifact set at Class {cls.upper()}",
              "CDS-CSO-SVC" in gated)
        check(f"a rule whose only artifact is conditional stays out at Class {cls.upper()} "
              "(SCN-CSO-... 'if no' wording is advisory)",
              all(sdr._classify_artifact(
                  [s for v in ((find_rule(ds, rid) or {}).get("artifacts") or {}).values() for s in (v or [])])
                  != "CONDITIONAL" for rid in gated))
    sdr._ARTIFACT_REQUIRED_RULES_CACHE.clear()
    # Every rule node with artifacts: the rule-level verdict must agree with the
    # per-obligation rule (any mandatory obligation -> gated).
    disagreements = []

    def walk(node, rid=None):
        if not isinstance(node, dict):
            return
        for k, v in node.items():
            if k == "varies_by_class" and isinstance(v, dict):
                for cv in v.values():
                    if isinstance(cv, dict):
                        _compare(rid, cv)
                continue
            if isinstance(v, dict):
                if "artifacts" in v:
                    _compare(k, v)
                walk(v, k)

    def _compare(rid, node):
        arts = node.get("artifacts")
        strs = []
        if isinstance(arts, dict):
            for av in arts.values():
                strs.extend(str(x) for x in (av or []))
        elif isinstance(arts, list):
            strs.extend(str(x) for x in arts)
        if not strs:
            return
        kinds = {k for _t, k in sdr.artifact_obligations(strs)}
        verdict = sdr._classify_artifact(strs)
        gated = verdict in ("REQUIRED", "REQUIRED_ONE_OF")
        if gated != bool(kinds & {"REQUIRED", "REQUIRED_ONE_OF"}):
            disagreements.append(rid)

    walk(ds)
    check("every artifact-bearing rule's verdict follows its obligations across the whole dataset",
          disagreements == [], str(disagreements[:5]))

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
