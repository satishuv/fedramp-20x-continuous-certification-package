# Adversarial tests for the Class A submitted-scope filter shared by the SDR
# builder (build_sdr.py) and package-preflight (sdr.py cmd_preflight).
#
# Defect locked here (found at e24308a): build_sdr.py excluded
# unselected FRC-CLA-OFR optional (MAY) rules from the submitted Class A SDR, but
# preflight computed its applicable-record set from the FULL 42-rule Class A
# profile. The readiness gate therefore evaluated a different rule set than the
# SDR it was gating - it would demand implementation records for the 9 optional
# rules the SDR does not include. The earlier submission-readiness test masked
# this because it filled records for all 42 profile rules before preflight.
#
# The fix routes BOTH consumers through sdr.submitted_rule_ids(); these tests
# assert that helper against the real Class A profile so builder and gate agree.
#
# Run: python validation/scripts/test_class_a_applicable_scope.py

import json
import os
import sys

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


def main():
    prof = json.load(open(os.path.join(BASE, "profiles", "class-a", "profile.json")))
    rules = prof["rules"]
    optional = [r["rule_id"] for r in rules if r.get("class_a_obligation") == "optional"]
    all_a = {r["rule_id"] for r in rules}

    check("Class A profile still carries all 42 rules (catalog intact)",
          len(all_a) == 42)
    check("exactly 9 optional (MAY) rules in the Class A profile",
          len(optional) == 9)

    # Default (empty selection): the 9 optional rules are NOT submitted, so
    # preflight must not treat them as applicable.
    submitted = sdr.submitted_rule_ids(rules, "a", None)
    check("default: submitted scope is 42 - 9 = 33 rules", len(submitted) == 33)
    check("default: no optional rule is in the submitted/applicable scope",
          all(rid not in submitted for rid in optional))
    check("default: every mandatory/recommended rule stays in scope",
          all(rid in submitted for rid in all_a if rid not in set(optional)))

    # Explicit selection: a selected optional rule IS submitted and gated.
    one = optional[0]
    submitted_sel = sdr.submitted_rule_ids(rules, "a", [one])
    check("selected: chosen optional rule enters the submitted scope",
          one in submitted_sel and len(submitted_sel) == 34)
    check("selected: the other 8 optional rules stay excluded",
          all(rid not in submitted_sel for rid in optional if rid != one))

    # Non-Class-A classes submit all profile rules (filter is Class A only).
    check("Class C submits all profile rules (no optional filter)",
          sdr.submitted_rule_ids(rules, "c", None) == all_a)

    # Builder/gate agreement: mirror build_sdr.py's own filter expression and
    # confirm it yields the identical set the helper (and thus preflight) uses.
    selected = set()
    builder_set = {
        r["rule_id"] for r in rules
        if r.get("class_a_obligation") != "optional" or r["rule_id"] in selected
    }
    check("builder filter == preflight submitted_rule_ids (default)",
          builder_set == sdr.submitted_rule_ids(rules, "a", None))

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: class A applicable scope "
          f"({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
