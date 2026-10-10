#!/usr/bin/env python3
"""Requirements-differential oracle (HARD-MODE RULE 5 / RULE 6).

INDEPENDENT of the production applicability engine. This walks the RAW pinned
FedRAMP dataset with its own traversal to derive the expected KSI universe and
the Class-B-optional set, then compares against what the production code
(sdr.submitted_ksi_ids / optional_at_class_b_ksis) claims. The two derivations
must reconcile EXACTLY; any discrepancy is a finding and this exits non-zero.

It deliberately does NOT import the production function to compute the expected
set (that would be circular). It parses the dataset structure directly.

    python audit/requirements_oracle.py
"""
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")


def _find_ksi_indicators(node, out):
    """Independent walk of the REAL dataset shape: KSI.<family>.indicators.<ID>
    where the KSI ID is the LEAF KEY (CR26 nests IDs as keys, not an 'id'
    field). Returns list of (ksi_id, indicator_obj). Does not use the production
    loader."""
    ksi = node.get("KSI") if isinstance(node, dict) else None
    if not isinstance(ksi, dict):
        return
    for fam, famobj in ksi.items():
        if not isinstance(famobj, dict):
            continue
        inds = famobj.get("indicators")
        if not isinstance(inds, dict):
            continue
        for kid, ind in inds.items():
            if isinstance(ind, dict):
                out.append((kid, ind))


def oracle_sets(dataset):
    """Return (all_ksi_ids, optional_at_b) derived independently from raw JSON."""
    inds = []
    _find_ksi_indicators(dataset, inds)
    all_ids, optional_b = set(), set()
    for kid, ind in inds:
        all_ids.add(kid)
        # Independent optional-at-B detection: the class-B statement under
        # varies_by_class carries the Optional marker for KSIs optional at B.
        vbc = ind.get("varies_by_class")
        if isinstance(vbc, dict):
            b = vbc.get("b")
            if isinstance(b, dict):
                stmt = str(b.get("statement", ""))
                if "**Optional:**" in stmt[:40]:
                    optional_b.add(kid)
    return all_ids, optional_b


def _frr_rules(dataset):
    """Independent walk of the RAW FRR shape:
        FRR.<process>.data.<applicability-bucket>.<subset>.<RULE-ID>
    where the rule id is the LEAF KEY. Yields (process, bucket, subset, rule_id,
    rule_obj, subset_applicability) with the subset's applicability block read
    from FRR.<process>.info.subsets.<subset>.applicability. Does not touch the
    production catalog builder or its derived rule-catalog file."""
    frr = dataset.get("FRR") or {}
    for proc, pobj in frr.items():
        if not isinstance(pobj, dict):
            continue
        subsets_meta = ((pobj.get("info") or {}).get("subsets") or {})
        for bucket, subsets in (pobj.get("data") or {}).items():
            if not isinstance(subsets, dict):
                continue
            for subset, rules in subsets.items():
                if not isinstance(rules, dict):
                    continue
                app = (subsets_meta.get(subset) or {}).get("applicability") or {}
                for rid, rule in rules.items():
                    if isinstance(rule, dict) and "name" in rule:
                        yield proc, bucket, subset, rid, rule, app


def _resolve(rule, cls):
    """Force/statement/timeframes for one class, by the dataset's own model: a
    class variant's statement wins; otherwise the top-level statement (with the
    top-level timing); otherwise the rule has no text at that class."""
    vbc = rule.get("varies_by_class") or {}
    variant = vbc.get(cls) if isinstance(vbc, dict) else None
    if isinstance(variant, dict) and variant.get("statement"):
        src = variant
    elif rule.get("statement"):
        src = rule
    else:
        return None
    return {
        "force": src.get("force"),
        "statement": src["statement"],
        "timeframe_type": src.get("timeframe_type"),
        "timeframe_num": src.get("timeframe_num"),
        "timeframe_num_min": src.get("timeframe_num_min"),
        "timeframe_num_max": src.get("timeframe_num_max"),
    }


def _subset_admits(app, cls, check_class=True):
    """Subset applicability from the dataset: this framework is 20x Program
    Certification, so a subset must list type 20x and path Program, and (for B/C)
    the class. A subset with no applicability block admits everything."""
    if not app:
        return True
    types = app.get("types")
    if types and "20x" not in types:
        return False
    paths = app.get("paths")
    if paths and "Program" not in paths:
        return False
    if check_class:
        classes = app.get("classes")
        if classes and cls.upper() not in [str(c).upper() for c in classes]:
            return False
    return True


def oracle_frr_class(dataset, cls):
    """Expected {rule_id: resolved} for Class B or C, independently derived:
    provider-affecting rules from the 20x and all buckets (never rev5), in a
    subset whose applicability admits 20x / Program / the class, excluding the
    Class-A-only CLA subset, resolved by the class-variant model."""
    out = {}
    for _proc, bucket, subset, rid, rule, app in _frr_rules(dataset):
        if bucket == "rev5":
            continue
        if "Providers" not in (rule.get("affects") or []):
            continue
        if subset == "CLA":
            continue
        if not _subset_admits(app, cls):
            continue
        resolved = _resolve(rule, cls)
        if resolved is None:
            continue
        out[rid] = resolved
    return out


def oracle_frr_class_a(dataset):
    """Expected {rule_id: resolved} for Class A: every CLA-subset rule plus the
    rules FRC-CLA-MFR / RFR / OFR enumerate in their following_information
    (parsed here with our own regex), each admitted by subset type/path (class
    check skipped: the enumeration IS the class-A governing text) and resolved
    for class a."""
    import re
    all_rules = {rid: (rule, app, subset, bucket)
                 for _p, bucket, subset, rid, rule, app in _frr_rules(dataset)}
    cla = ((dataset.get("FRR") or {}).get("FRC") or {}).get("data", {}).get("all", {}).get("CLA", {})
    rule_pat = re.compile(r"\b([A-Z]{3}-[A-Z]{3}-[A-Z]{3})\b")
    wanted = {rid for rid, (_r, _a, subset, _b) in all_rules.items() if subset == "CLA"}
    for code in ("FRC-CLA-MFR", "FRC-CLA-RFR", "FRC-CLA-OFR"):
        for item in (cla.get(code) or {}).get("following_information") or []:
            text = item if isinstance(item, str) else json.dumps(item)
            for m in rule_pat.findall(text):
                if not m.startswith("KSI"):
                    wanted.add(m)
    out = {}
    for rid in sorted(wanted):
        if rid not in all_rules:
            continue
        rule, app, _subset, bucket = all_rules[rid]
        if bucket == "rev5" or not _subset_admits(app, "a", check_class=False):
            continue
        resolved = _resolve(rule, "a")
        if resolved is not None:
            out[rid] = resolved
    return out


# Pinned anchors: the counts an independent reconciliation of the 2026.10.08.01
# dataset produced (41 / 157 / 157; 158 at B and C before FRC-CSX-MOT was
# removed in that release). An oracle that reconciles 0 against 0 is not an
# oracle (RULE 7), so these guard against a silent empty-set pass. They move
# only with a dataset adoption, by hand, after the recount.
EXPECTED_COUNTS = {"a": 41, "b": 157, "c": 157}
COMPARED_FIELDS = ("force", "statement", "timeframe_type", "timeframe_num",
                   "timeframe_num_min", "timeframe_num_max")


def reconcile_frr(dataset, cls, profile_rules):
    """Diff the oracle's expected rule map for `cls` against the committed
    profile. Returns a list of (finding, detail)."""
    expected = oracle_frr_class_a(dataset) if cls == "a" else oracle_frr_class(dataset, cls)
    actual = {r["rule_id"]: r for r in profile_rules}
    findings = []
    if len(expected) != EXPECTED_COUNTS[cls]:
        findings.append((f"Class {cls.upper()} oracle count != pinned anchor",
                         {"oracle": len(expected), "anchor": EXPECTED_COUNTS[cls]}))
    if set(expected) != set(actual):
        findings.append((f"Class {cls.upper()} rule set mismatch",
                         {"only_profile": sorted(set(actual) - set(expected)),
                          "only_oracle": sorted(set(expected) - set(actual))}))
    for rid in sorted(set(expected) & set(actual)):
        for field in COMPARED_FIELDS:
            if expected[rid].get(field) != actual[rid].get(field):
                findings.append((f"Class {cls.upper()} {rid} {field} mismatch",
                                 {"oracle": expected[rid].get(field),
                                  "profile": actual[rid].get(field)}))
    return findings, len(expected)


def main():
    with open(DATASET, encoding="utf-8") as f:
        dataset = json.load(f)
    all_oracle, optional_oracle = oracle_sets(dataset)

    # The derived KSI profile is what the production pipeline ACTUALLY consumes
    # (build_profiles.py generates it from the dataset). Diffing the raw dataset
    # against this derived profile catches source->profile drift independently.
    prof_path = os.path.join(BASE, "profiles", "common", "ksi-profile.json")
    with open(prof_path, encoding="utf-8") as f:
        indicators = json.load(f)["indicators"]
    profile_ids = {k["ksi_id"] for k in indicators}

    # Production side (the thing under test) applied to its own profile.
    sys.path.insert(0, BASE)
    import sdr  # noqa: E402
    prod_all_c = sdr.submitted_ksi_ids(indicators, "c")
    prod_all_b = sdr.submitted_ksi_ids(indicators, "b")
    prod_optional = sdr.optional_at_class_b_ksis(indicators)

    findings = []
    # 1. The derived profile must contain exactly the dataset's KSI universe.
    if profile_ids != all_oracle:
        findings.append(("Derived ksi-profile != dataset KSI universe",
                         {"only_profile": sorted(profile_ids - all_oracle),
                          "only_dataset": sorted(all_oracle - profile_ids)}))
    # 2. Production Class C submits the whole universe.
    if prod_all_c != all_oracle:
        findings.append(("Production Class C != dataset universe",
                         {"only_prod": sorted(prod_all_c - all_oracle),
                          "only_oracle": sorted(all_oracle - prod_all_c)}))
    # 3. Optional-at-B set reconciles (dataset-derived vs production).
    if prod_optional != optional_oracle:
        findings.append(("Class-B-optional set mismatch",
                         {"only_prod": sorted(prod_optional - optional_oracle),
                          "only_oracle": sorted(optional_oracle - prod_optional)}))
    # 4. Class B baseline = universe minus optional (independent arithmetic).
    expected_baseline_b = all_oracle - optional_oracle
    if prod_all_b != expected_baseline_b:
        findings.append(("Class B baseline mismatch",
                         {"only_prod": sorted(prod_all_b - expected_baseline_b),
                          "only_oracle": sorted(expected_baseline_b - prod_all_b)}))
    # 5. AUD-F22: the 158 provider FRRs per class (set, force, statement,
    #    timeframes) and the enumerated Class A set, independently re-derived from
    #    the raw dataset and diffed against the committed profiles. Before this
    #    the oracle was independent for KSIs only; the FRR side was
    #    build_profiles vs. its own output (internal consistency, not an oracle).
    frr_counts = {}
    for cls in ("a", "b", "c"):
        prof = os.path.join(BASE, "profiles", f"class-{cls}", "profile.json")
        with open(prof, encoding="utf-8") as f:
            profile_rules = json.load(f).get("rules") or []
        frr_findings, n = reconcile_frr(dataset, cls, profile_rules)
        frr_counts[cls] = (n, len(profile_rules))
        findings.extend(frr_findings)

    print("Requirements-differential oracle")
    print("-" * 60)
    print(f"Oracle KSI universe (dataset): {len(all_oracle)}")
    print(f"Oracle optional-at-B: {len(optional_oracle)} {sorted(optional_oracle)}")
    print(f"Derived profile KSIs: {len(profile_ids)}")
    print(f"Production C: {len(prod_all_c)}  B-baseline: {len(prod_all_b)}  "
          f"optional: {len(prod_optional)}")
    for cls, (n_oracle, n_profile) in frr_counts.items():
        print(f"FRR Class {cls.upper()}: oracle {n_oracle} rules, profile {n_profile} rules "
              f"(anchor {EXPECTED_COUNTS[cls]}); force/statement/timeframes compared")
    if not findings:
        print("\nRECONCILED: dataset == derived profile == production applicability "
              "(KSIs and FRRs, classes A/B/C). EMPTY discrepancy report.")
        return 0
    print(f"\nDISCREPANCIES ({len(findings)}):")
    for name, detail in findings:
        print(f"  [FINDING] {name}: {json.dumps(detail)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
