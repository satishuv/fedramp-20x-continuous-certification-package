#!/usr/bin/env python3
"""Validate the Assurance Graph.

Proves that for every applicable rule and KSI, the graph resolves the full
chain: requirement -> applicability -> provider claim -> verification ->
evidence -> validation -> reviewer -> generated SDR location. Also checks the
graph is consistent with the current profile and generated SDR (no drift
between the graph and the artifacts it joins).

Presence and consistency, not truth: a TBD claim or a pending review is present
and valid structurally; the check fails only when a required chain link is
ABSENT or the graph disagrees with the profile/SDR it was built from.

    python validation/scripts/validate_assurance_graph.py

Exit 1 on any structural or consistency failure.
"""

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import class_support  # noqa: E402  (AUD-F65: the one class-support state)
OFFERING = os.path.join(BASE, "profiles", "common", "offering-profile.json")
GRAPH = os.path.join(BASE, "traceability", "assurance-graph.json")

RULE_CHAIN = ["applicability", "provider_claim", "verification", "evidence",
              "structural_linkage", "review", "outputs"]
KSI_CHAIN = ["provider_claim", "verification", "evidence", "structural_linkage",
             "review", "outputs"]


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    cls = (load(OFFERING).get("certification_class") or "b").lower()
    _unsupported = class_support.unsupported_class_message(cls, 'assurance graph validation')
    if _unsupported:
        print(_unsupported)
        return 1
    if not os.path.exists(GRAPH):
        print(f"FAIL: assurance graph missing at {os.path.relpath(GRAPH, BASE)} "
              "(run build_assurance_graph.py)")
        return 1
    graph = load(GRAPH)
    class_profile = load(os.path.join(BASE, "profiles", f"class-{cls}", "profile.json"))
    ksi_profile = load(os.path.join(BASE, "profiles", "common", "ksi-profile.json"))
    sdr = load(os.path.join(BASE, "sdr", "json", f"sdr-class-{cls}.json"))

    problems = []

    # 1. Class agreement.
    if graph.get("certification_class") != cls.upper():
        problems.append(f"graph class {graph.get('certification_class')} != profile class {cls.upper()}")

    nodes = graph.get("nodes", [])
    rule_nodes = {n["rule_id"]: n for n in nodes if n.get("node_kind") == "rule"}
    ksi_nodes = {n["ksi_id"]: n for n in nodes if n.get("node_kind") == "ksi"}

    # 2. Coverage: the graph rule nodes must match the SDR's FRR set. The Class
    # A SDR omits FRC-CLA-OFR optional (MAY) rules the provider did not opt into,
    # so the graph legitimately omits them too; comparing against the full class
    # profile (all 41 for A) would falsely flag those as missing. The SDR is the
    # authoritative filtered set.
    profile_rules = {e["frrID"] for e in sdr.get("fedRampRequirements", [])}
    if profile_rules != set(rule_nodes):
        missing = sorted(profile_rules - set(rule_nodes))[:5]
        extra = sorted(set(rule_nodes) - profile_rules)[:5]
        problems.append(f"rule node coverage mismatch (missing {missing}, extra {extra})")
    # The SDR is the authoritative KSI set too: Class A carries only the 7
    # CLA-enumerated KSIs and Class B omits unselected optional-at-B KSIs, so the
    # graph legitimately omits them. Comparing against the full profile would
    # falsely flag those as missing. Mirror the rule-node coverage check above.
    ksi_ids = {e["ksiId"] for e in sdr.get("keySecurityIndicators", [])}
    if ksi_ids != set(ksi_nodes):
        problems.append("KSI node coverage mismatch with the applicable KSI set")

    # 3. Full chain present on every node.
    for rid, n in rule_nodes.items():
        for link in RULE_CHAIN:
            if link not in n:
                problems.append(f"rule {rid}: missing chain link '{link}'")
        if n.get("outputs", {}).get("sdr_json_pointer") is None:
            problems.append(f"rule {rid}: no SDR output pointer")
    for kid, n in ksi_nodes.items():
        for link in KSI_CHAIN:
            if link not in n:
                problems.append(f"ksi {kid}: missing chain link '{link}'")
        if n.get("outputs", {}).get("sdr_json_pointer") is None:
            problems.append(f"ksi {kid}: no SDR output pointer")

    # 4. SDR pointer consistency: the pointer index actually resolves in the SDR.
    frrs = sdr.get("fedRampRequirements", [])
    ksis = sdr.get("keySecurityIndicators", [])
    for rid, n in rule_nodes.items():
        ptr = n.get("outputs", {}).get("sdr_json_pointer") or ""
        idx = _index(ptr)
        if idx is None or idx >= len(frrs) or frrs[idx].get("frrID") != rid:
            problems.append(f"rule {rid}: SDR pointer {ptr} does not resolve to this rule")
    for kid, n in ksi_nodes.items():
        ptr = n.get("outputs", {}).get("sdr_json_pointer") or ""
        idx = _index(ptr)
        if idx is None or idx >= len(ksis) or ksis[idx].get("ksiId") != kid:
            problems.append(f"ksi {kid}: SDR pointer {ptr} does not resolve to this KSI")

    if problems:
        print(f"FAIL: assurance graph has {len(problems)} problem(s):")
        for p in problems[:20]:
            print(f"    - {p}")
        return 1
    print(f"PASS: assurance graph resolves the full chain for all "
          f"{len(rule_nodes)} rules and {len(ksi_nodes)} KSIs, and agrees with "
          "the profile and generated SDR.")
    return 0


def _index(pointer):
    # "$.fedRampRequirements[12]" -> 12
    if "[" in pointer and pointer.endswith("]"):
        try:
            return int(pointer[pointer.rindex("[") + 1:-1])
        except ValueError:
            return None
    return None


if __name__ == "__main__":
    sys.exit(main())
