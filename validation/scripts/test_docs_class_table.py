#!/usr/bin/env python3
"""docs/certification-classes.md states the class model from the canonical data
(AUD-F55): the comparison table equals class_table.render_table(), and the
prose anchors that quote a count carry the same numbers. A hand edit that
disagrees with the generated profiles, the Class D register, the KSI profile or
the dataset's SDR-CSX-KMT forces fails here.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
import class_table as ct  # noqa: E402

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}" + (f": {detail}" if detail else ""))


def main():
    facts = ct.class_facts()
    with open(ct.DOC, encoding="utf-8") as fh:
        text = fh.read()
    span = ct.doc_table(text)
    check("the doc has a table after the 'What differs between classes' heading", span is not None)
    if span:
        lines = text.split("\n")
        current = "\n".join(lines[span[0]:span[1]])
        check("the table equals the one rendered from the canonical data "
              "(python validation/scripts/class_table.py --write to regenerate)",
              current == ct.render_table(facts))
    check("class_table --check agrees", ct.main(["--check"]) == 0)

    r = facts["rules"]
    total, mand_a, base_b = facts["ksi_total"], facts["ksi_mandatory_a"], facts["ksi_baseline_b"]
    opt_b = facts["ksi_optional_b"]
    check("canonical anchors hold (41 / 157 / 157 / 156 rules; 46 KSIs, 7 mandatory at A, 5 optional at B)",
          (r["a"], r["b"], r["c"], r["d"]) == (41, 157, 157, 156) and total == 46
          and mand_a == 7 and len(opt_b) == 5, str(facts))
    check("the five optional Class B indicators are the Class-C-specific ones",
          opt_b == ["KSI-CNA-EIS", "KSI-MLA-ALA", "KSI-SVC-PRR", "KSI-SVC-RUD", "KSI-SVC-VCM"], str(opt_b))
    check("SDR-CSX-KMT forces per class read from the dataset are MAY / SHOULD / MUST / MUST",
          facts["kmt_force"] == {"a": "MAY", "b": "SHOULD", "c": "MUST", "d": "MUST"}, str(facts["kmt_force"]))
    # Prose anchors: every sentence that quotes a count uses the canonical one.
    check("Class A prose quotes the enumerated rule count",
          f"so the {r['a']} rules are the ones FedRAMP named" in text)
    check("Class A prose quotes the mandatory and the remaining indicator counts",
          f"{mand_a} are mandatory at Class A and the other {total - mand_a} carry" in text)
    check("the A-to-B jump quotes rules and the Class B baseline indicators",
          f"{r['a']} rules to {r['b']}, and {mand_a} indicators to {base_b}" in text)
    check("the Class D section quotes the register count",
          f"holds {r['d']} rules resolved against the class D variants" in text)
    # No other row or sentence may still say Class B KMT is MUST, or that Class B
    # has all indicators in scope by default.
    kmt_rows = [l for l in text.split("\n") if "SDR-CSX-KMT" in l and l.startswith("|")]
    check("exactly one table row describes SDR-CSX-KMT, and it says SHOULD at Class B",
          len(kmt_rows) == 1 and "`SHOULD` include" in kmt_rows[0])
    check("no prose says Class B has all indicators in scope by default",
          not re.search(r"Class B[^.\n]*\ball 46\b", text))

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
