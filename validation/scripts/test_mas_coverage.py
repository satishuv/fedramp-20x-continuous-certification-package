#!/usr/bin/env python3
"""MAS-by-KSI coverage report (FRC-CSX-MAS, AUD-F56).

Pure-function tests on fixtures: a cell is demonstrated only when the provider's
reference resolves to a tests[].method_id or evidence[].evidenceLocation of the
KSI record; a reason-less exclusion, a non-resolving reference or a missing
declaration never counts as covered; an out-of-scope resource needs a reason;
the report is deterministic; the preflight advisory is a warning in every case
and absent only when nothing is open. Plus the built artifacts on the template
tree: one JSON and one Markdown per class, applicable KSI counts 7 / 41 / 46,
and the empty-inventory statement.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, BASE)
import build_mas_coverage as bmc  # noqa: E402
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


RECORDS = {"ksi": {
    "KSI-CNA-RNT": {"tests": [{"method_id": "KSI-CNA-RNT:verify:config:restricted-ssh", "automated": True}],
                    "evidence": [{"evidenceType": "Configuration",
                                  "evidenceLocation": "https://evidence.example.invalid/cna-rnt.json"}]},
    "KSI-IAM-AAM": {"tests": [{"method_id": "KSI-IAM-AAM:verify:config:access-keys-rotated"}], "evidence": []},
    "KSI-CED-RAT": {"tests": [], "evidence": []},
}}
APPLICABLE = ["KSI-CED-RAT", "KSI-CNA-RNT", "KSI-IAM-AAM"]
RULE = {"force": "SHOULD", "statement": "Providers SHOULD apply ALL Key Security Indicators ..."}


def inventory(*resources):
    return {"resources": list(resources)}


def cell(report, res, ksi):
    return next(c for c in report["cells"] if c["resource"] == res and c["ksi"] == ksi)


def main():
    print("== cells")
    inv = inventory({
        "id": "ecs-api", "name": "ECS workload", "kind": "aws-service", "aws_service": "Amazon ECS",
        "in_mas": True, "handles_federal_data": True,
        "ksi_coverage": {
            "KSI-CNA-RNT": {"demonstrated_by": ["KSI-CNA-RNT:verify:config:restricted-ssh",
                                                "https://evidence.example.invalid/cna-rnt.json"]},
            "KSI-IAM-AAM": {"demonstrated_by": ["KSI-IAM-AAM:verify:config:does-not-exist"]},
            "KSI-CED-RAT": {"not_applicable": "Workforce indicator; demonstrated at the organization level"},
        }},
        {"id": "rds-main", "name": "RDS cluster", "in_mas": True,
         "ksi_coverage": {"KSI-CNA-RNT": {"not_applicable": ""},
                          "KSI-IAM-AAM": {"something_else": True},
                          "KSI-XXX-YYY": {"not_applicable": "not a KSI"}}},
        {"id": "docs-site", "name": "Public docs site", "in_mas": False,
         "exclusion_reason": "Static content; handles no federal customer data"},
        {"id": "unexplained", "name": "Thing", "in_mas": False},
        {"id": "undecided", "name": "Thing 2"},
    )
    rep = bmc.coverage_for_class(inv, RECORDS, APPLICABLE, "b", "2026.10.08.01", RULE)
    check("a reference that resolves to a method_id AND one to an evidenceLocation: demonstrated",
          cell(rep, "ecs-api", "KSI-CNA-RNT")["status"] == "demonstrated")
    check("a reference that does not resolve: unresolved, naming the missing reference",
          cell(rep, "ecs-api", "KSI-IAM-AAM")["status"] == "unresolved"
          and "does-not-exist" in cell(rep, "ecs-api", "KSI-IAM-AAM")["note"])
    check("a reasoned exclusion: not_applicable with the reason",
          cell(rep, "ecs-api", "KSI-CED-RAT")["status"] == "not_applicable"
          and "organization level" in cell(rep, "ecs-api", "KSI-CED-RAT")["note"])
    check("a reason-less exclusion is unresolved, not covered",
          cell(rep, "rds-main", "KSI-CNA-RNT")["status"] == "unresolved")
    check("a declaration with neither key is unresolved",
          cell(rep, "rds-main", "KSI-IAM-AAM")["status"] == "unresolved")
    check("an undeclared cell is a gap",
          cell(rep, "rds-main", "KSI-CED-RAT")["status"] == "gap")
    check("a ksi_coverage key that is not a submitted KSI is reported, not silently used",
          any("KSI-XXX-YYY" in p for p in rep["problems"]))
    check("an excluded resource with a reason is listed outside the MAS and gets no cells",
          [r["id"] for r in rep["resources_excluded"]] == ["docs-site", "unexplained"]
          and not any(c["resource"] == "docs-site" for c in rep["cells"]))
    check("an excluded resource without a reason is a problem",
          any("unexplained" in p and "exclusion_reason" in p for p in rep["problems"]))
    check("a resource with no in_mas decision is a problem and gets no cells",
          any("undecided" in p for p in rep["problems"])
          and not any(c["resource"] == "undecided" for c in rep["cells"]))
    s = rep["summary"]
    check("summary counts add up (2 resources x 3 KSIs = 6 cells)",
          s["cells"] == 6 and s["demonstrated"] == 1 and s["not_applicable"] == 1
          and s["unresolved"] == 3 and s["gap"] == 1 and s["resources_in_mas"] == 2
          and s["resources_excluded"] == 2 and s["ksis_applicable"] == 3, str(s))
    check("the report never carries a status for the KSI record itself",
          "implementation_status" not in json.dumps(rep))

    print("== default declaration")
    inv2 = inventory({"id": "org", "name": "Organization-level controls", "in_mas": True,
                      "ksi_coverage": {"*": {"not_applicable": "Not a workload; see each KSI record"},
                                       "KSI-CNA-RNT": {"demonstrated_by": ["KSI-CNA-RNT:verify:config:restricted-ssh"]}}})
    rep2 = bmc.coverage_for_class(inv2, RECORDS, APPLICABLE, "c", "2026.10.08.01", RULE)
    check("a '*' default covers every KSI not listed and is counted separately",
          rep2["summary"]["not_applicable"] == 2 and rep2["summary"]["by_default"] == 2
          and cell(rep2, "org", "KSI-CNA-RNT")["by_default"] is False
          and cell(rep2, "org", "KSI-CED-RAT")["by_default"] is True)
    md = bmc.render_md(rep2)
    check("the Markdown marks default-declared cells", "(default declaration)" in md
          and "covered by a resource's default declaration: 2" in md)

    print("== determinism and empty inventory")
    a = json.dumps(bmc.coverage_for_class(inv, RECORDS, APPLICABLE, "b", "v", RULE), sort_keys=True)
    b = json.dumps(bmc.coverage_for_class(json.loads(json.dumps(inv)), RECORDS, APPLICABLE, "b", "v", RULE), sort_keys=True)
    check("identical input renders identical output", a == b)
    empty = bmc.coverage_for_class({"resources": []}, RECORDS, APPLICABLE, "b", "v", RULE)
    check("an empty inventory is reported as not declared, with zero cells",
          empty["meta"]["inventory_declared"] is False and empty["summary"]["cells"] == 0
          and "No MAS inventory is declared" in bmc.render_md(empty))

    print("== preflight advisory (never a blocker)")
    check("no report: advisory names the build", "no MAS-by-KSI coverage report" in sdr.mas_coverage_advisory(None, "b"))
    check("empty inventory: advisory asks for the MAS resources",
          "no MAS inventory declared" in sdr.mas_coverage_advisory(empty, "b"))
    adv = sdr.mas_coverage_advisory(rep, "b")
    check("gaps and unresolved cells: advisory carries the counts and names cells",
          adv is not None and "1 gap(s)" in adv and "3 unresolved" in adv
          and "rds-main/KSI-CED-RAT" in adv and adv.endswith("advisory)"))
    full = inventory({"id": "ecs-api", "name": "ECS", "in_mas": True,
                      "ksi_coverage": {"KSI-CNA-RNT": {"demonstrated_by": ["KSI-CNA-RNT:verify:config:restricted-ssh"]},
                                       "KSI-IAM-AAM": {"demonstrated_by": ["KSI-IAM-AAM:verify:config:access-keys-rotated"]},
                                       "KSI-CED-RAT": {"not_applicable": "Workforce indicator"}}})
    rep_full = bmc.coverage_for_class(full, RECORDS, APPLICABLE, "b", "v", RULE)
    check("fully covered inventory: no advisory", sdr.mas_coverage_advisory(rep_full, "b") is None)
    check("the advisory functions never raise a blocker (they return text or None only)",
          all(isinstance(x, (str, type(None))) for x in
              (sdr.mas_coverage_advisory(None, "a"), sdr.mas_coverage_advisory(rep, "c"))))

    print("== built artifacts on this tree")
    for cls, expected in (("a", 7), ("b", 41), ("c", 46)):
        path = os.path.join(BASE, "artifacts", f"mas-ksi-coverage-class-{cls}.json")
        ok = os.path.exists(path) and os.path.exists(path[:-5] + ".md")
        check(f"Class {cls.upper()} coverage JSON and Markdown exist", ok)
        if ok:
            rpt = json.load(open(path, encoding="utf-8"))
            check(f"Class {cls.upper()} report resolves {expected} submitted KSIs and quotes FRC-CSX-MAS as SHOULD",
                  rpt["summary"]["ksis_applicable"] == expected and rpt["meta"]["force"] == "SHOULD"
                  and rpt["meta"]["rule"] == "FRC-CSX-MAS", str(rpt["summary"]))
    ksi_profile = json.load(open(bmc.KSI_PROFILE, encoding="utf-8"))
    class_a = json.load(open(os.path.join(BASE, "profiles", "class-a", "profile.json"), encoding="utf-8"))
    check("the Class A KSI set is the FRC-CLA-MFR enumeration the SDR builder uses",
          set(bmc.applicable_ksis_for_class("a", ksi_profile, class_a, {}))
          == set(class_a["meta"]["class_a_ksis"].keys()))
    check("the Class B KSI set honours selected_optional_ksis (41 + 1 selected)",
          len(bmc.applicable_ksis_for_class("b", ksi_profile, {}, {"selected_optional_ksis": ["KSI-CNA-EIS"]})) == 42)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
