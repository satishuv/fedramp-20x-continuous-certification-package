#!/usr/bin/env python3
"""Generate reviewer-facing reports from the assurance graph:

  validation/reports/evidence-coverage.json  coverage metrics (NOT a
      compliance percentage): which rules/KSIs have evidence, verification
      coverage, template-TBD state, and pending review counts.
  validation/reports/reviewer-package.md  an assessor-facing summary: package
      metadata, applicable/excluded counts, KSI verification coverage, open
      TBDs, and where to look, without needing to read raw JSON.

Deterministic (no run timestamps). Reads only generated artifacts.

    python validation/scripts/build_reports.py
"""

import json
import os
import sys

import profile_contract as _pc  # noqa: E402  (offering_title: honest title while the name is TBD)

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OFFERING = os.path.join(BASE, "profiles", "common", "offering-profile.json")
GRAPH = os.path.join(BASE, "traceability", "assurance-graph.json")
DECISIONS = os.path.join(BASE, "traceability", "applicability-decisions.json")
COVERAGE_OUT = os.path.join(BASE, "validation", "reports", "evidence-coverage.json")
REVIEWER_OUT = os.path.join(BASE, "validation", "reports", "reviewer-package.md")


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _is_tbd(node):
    impl = node.get("provider_claim", {}).get("implementation", []) or []
    return any("TBD" in str(s) for s in impl)


def coverage(graph):
    nodes = graph.get("nodes", [])
    rules = [n for n in nodes if n["node_kind"] == "rule"]
    ksis = [n for n in nodes if n["node_kind"] == "ksi"]
    ksis_with_evidence = sum(1 for n in ksis if n.get("evidence"))
    rules_with_evidence = sum(1 for n in rules if n.get("evidence"))
    ksis_meeting_min = sum(1 for n in ksis
                           if n.get("verification", {}).get("meets_minimum") is True)
    tbd_rules = sum(1 for n in rules if _is_tbd(n))
    tbd_ksis = sum(1 for n in ksis if _is_tbd(n))
    pending_review = sum(1 for n in nodes
                         if n.get("review", {}).get("review_status") != "approved")

    # Aggregate evidence lifecycle state across all evidence entries, so
    # coverage reflects current/stale/expired/collection-error, not merely
    # "has evidence / doesn't."
    lifecycle = {"current": 0, "stale": 0, "expired": 0, "missing": 0,
                 "collection-error": 0, "integrity-failed": 0,
                 "superseded": 0, "unknown": 0}
    total_evidence = 0
    for n in nodes:
        for e in (n.get("evidence") or []):
            total_evidence += 1
            fs = e.get("freshness_status")
            cs = e.get("collection_status")
            if cs and cs != "success":
                lifecycle["collection-error"] += 1
            elif fs in lifecycle:
                lifecycle[fs] += 1
            else:
                lifecycle["unknown"] += 1
    return {
        "coverage_note": (
            "Coverage metrics, NOT a compliance percentage. 'evidence coverage' "
            "and 'verification coverage' describe completeness of the record, "
            "not whether the provider meets a requirement. A human assessor "
            "determines compliance. Lifecycle counts describe evidence freshness "
            "state; stale/expired/missing evidence is a readiness signal, never "
            "an automatic compliance failure."),
        "certification_class": graph.get("certification_class"),
        "rules_total": len(rules),
        "rules_with_evidence": rules_with_evidence,
        "rules_template_tbd": tbd_rules,
        "ksis_total": len(ksis),
        "ksis_with_evidence": ksis_with_evidence,
        "ksis_meeting_verification_minimum": ksis_meeting_min,
        "ksis_template_tbd": tbd_ksis,
        "nodes_pending_review": pending_review,
        "evidence_total": total_evidence,
        "evidence_lifecycle": lifecycle,
    }


def reviewer_md(graph, decisions, offering, cov):
    cls = graph.get("certification_class", "?")
    L = []
    a = L.append
    a(f"# Reviewer package summary: {_pc.offering_title(offering)} (Class {cls})")
    a("")
    a("Assessor-facing summary generated from the assurance graph. It is not a "
      "compliance determination; it points a reviewer at what to examine.")
    a("")
    a("## Package metadata")
    a(f"- Certification class: {cls}")
    a(f"- Dataset version: {graph.get('dataset_version')}")
    a(f"- Offering: {_pc.offering_title(offering)}")
    a("")
    a("## Requirement scope")
    if decisions:
        a(f"- Applicable rules: {decisions.get('included')}")
        a(f"- Excluded rules (with recorded reasons): {decisions.get('excluded')}")
        a(f"- Total rules in dataset: {decisions.get('total_rules')}")
    a(f"- KSIs in scope: {cov['ksis_total']}")
    a("")
    a("## Coverage (not compliance)")
    a(f"- Rules with evidence: {cov['rules_with_evidence']} of {cov['rules_total']}")
    a(f"- KSIs with evidence: {cov['ksis_with_evidence']} of {cov['ksis_total']}")
    a(f"- KSIs meeting verification-method minimum: "
      f"{cov['ksis_meeting_verification_minimum']} of {cov['ksis_total']}")
    a(f"- Rules still in template TBD state: {cov['rules_template_tbd']}")
    a(f"- KSIs still in template TBD state: {cov['ksis_template_tbd']}")
    a(f"- Nodes pending human review: {cov['nodes_pending_review']}")
    a("")
    a("## Where to look")
    a("- Full traceability: `traceability/assurance-graph.json`")
    a("- Why each rule is in or out of scope: `traceability/applicability-decisions.json`")
    a("- Human signoff: `sdr/reviews/review-register.json`")
    a("- Package fingerprint: `artifacts/release-manifest.json`")
    a("")
    a("Nothing here is approved, assessed, or certified by the tool. Those are "
      "human and authorized-body determinations.")
    return "\n".join(L)


def main():
    offering = load(OFFERING, {})
    cls = (offering.get("certification_class") or "b").lower()
    if cls == "d":
        print("Class D is FedRAMP pending; no reports generated.")
        return 1
    graph = load(GRAPH)
    if graph is None:
        print("Assurance graph not found; run build_assurance_graph.py first.")
        return 1
    decisions = load(DECISIONS)
    cov = coverage(graph)

    os.makedirs(os.path.dirname(COVERAGE_OUT), exist_ok=True)
    with open(COVERAGE_OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cov, f, indent=1)
    with open(REVIEWER_OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(reviewer_md(graph, decisions, offering, cov))
    print(f"Reports written: {os.path.relpath(COVERAGE_OUT, BASE)} and "
          f"{os.path.relpath(REVIEWER_OUT, BASE)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
