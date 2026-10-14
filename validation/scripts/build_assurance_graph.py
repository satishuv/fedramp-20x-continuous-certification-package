#!/usr/bin/env python3
"""Build the Assurance Graph: one first-class artifact that unifies, per
applicable requirement and KSI, the whole chain from FedRAMP rule through
applicability, provider claim, verification, hashed evidence, validation,
review, and the generated SDR location.

This DUPLICATES NOTHING. Every field is read from data the pipeline already
produces: the per-class profile (applicability + force), the KSI profile
(minimums, families), the record store (claims, evidence, owners), and the
generated SDR JSON (output pointers). The graph is a join over those, so it is
always consistent with them by construction.

Honest edge: FedRAMP does not link individual FedRAMP Rules (FRRs) to specific
KSIs in the dataset. KSIs carry related NIST controls, not FRR ids. So this
graph has two node kinds, `rule` and `ksi`, each fully resolved; it does not
fabricate FRR->KSI edges that the source data does not contain.

Pipeline position: after build_sdr.py (needs the generated SDR to point into).

    python validation/scripts/build_assurance_graph.py

Output: traceability/assurance-graph.json
"""

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Single source of truth for FRC-CSX-VVK automated-method counting, shared with
# validate_sdr.py so this reviewer-facing report agrees with the authoritative
# validator by construction (no independent len(tests) counter).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import class_support  # noqa: E402  (AUD-F65: the one class-support state)
from verification_methods import count_automated_methods  # noqa: E402

# Reuse the evidence lifecycle model rather than duplicating it, so the graph's
# evidence nodes carry real freshness/expiry/collection state.
sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))
try:
    from evidence_lifecycle import lifecycle_record as _lifecycle_record
except Exception:
    _lifecycle_record = None
PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
KSI_PROFILE = os.path.join(BASE, "profiles", "common", "ksi-profile.json")
RECORDS = os.path.join(BASE, "sdr", "records", "records-store.json")
REGISTER = os.path.join(BASE, "sdr", "reviews", "review-register.json")
OUT = os.path.join(BASE, "traceability", "assurance-graph.json")

# FRC-CSX-VVK force per class, verified against the dataset.
# FRC-CSX-VVK force per class comes from the single canonical constants module
# so this file cannot disagree with the validators about a MUST vs SHOULD.
from fedramp_constants import VVK_FORCE


def _review_index():
    """Map assurance_id -> the real recorded review, so the graph reflects
    actual human decisions instead of a hardcoded 'pending'. Reads the review
    register the pipeline never writes to. Returns {} when nothing is reviewed
    (the correct template state)."""
    reg = load(REGISTER, {}) or {}
    idx = {}
    for r in reg.get("reviews", []):
        aid = r.get("assurance_id")
        if not aid:
            continue
        # Accept an ASR- wrapper or the bare rule/ksi id.
        key = aid.split("ASR-")[-1] if str(aid).startswith("ASR-") else aid
        idx[key] = r
    return idx


def _review_for(review_idx, ident, owner):
    """Return the review block for one node id: the recorded human review if
    present, else the honest pending default (reviewer = record owner)."""
    r = review_idx.get(ident)
    if not r:
        return {"reviewer": owner, "review_status": "pending",
                "reviewed_evidence_hashes": []}
    return {
        "reviewer": r.get("reviewer", owner),
        "review_status": r.get("decision", "pending"),
        "reviewed_at": r.get("reviewed_at"),
        "reviewed_evidence_hashes": r.get("evidence_hashes_reviewed", []),
    }


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _evidence_nodes(evidence):
    """Normalize a record's evidence list into graph evidence nodes, enriched
    with lifecycle state (freshness, expiry, collection status, evidence id,
    supersession) via evidence_lifecycle.lifecycle_record, so the graph carries
    the real lifecycle - not merely source/type/location/hash/date."""
    out = []
    for e in evidence or []:
        if not isinstance(e, dict):
            continue
        node = {
            "source": (e.get("evidenceText", "").split(":")[0] or "unknown"),
            "type": e.get("evidenceType"),
            "location": e.get("evidenceLocation"),
            "sha256": e.get("xEvidenceContentHash"),
            "observed_at": e.get("lastUpdated"),
        }
        if _lifecycle_record is not None:
            try:
                lc = _lifecycle_record(e)
                node["evidence_id"] = lc.get("evidence_id")
                node["freshness_status"] = lc.get("freshness_status")
                node["fresh_until"] = lc.get("fresh_until")
                node["expires_at"] = lc.get("expires_at")
                node["collection_status"] = lc.get("collection_status")
                node["supersedes"] = lc.get("supersedes")
            except Exception:
                # Never let lifecycle enrichment break the graph build.
                node["freshness_status"] = "unknown"
        out.append(node)
    return out


def build_graph(cls):
    class_profile = load(os.path.join(BASE, "profiles", f"class-{cls}", "profile.json"))
    if class_profile is None:
        return None
    ksi_profile = load(KSI_PROFILE, {"indicators": []})
    records = load(RECORDS, {"frr": {}, "ksi": {}})
    sdr = load(os.path.join(BASE, "sdr", "json", f"sdr-class-{cls}.json"), {})
    # The SUBMITTED SDR is the authoritative applicable set for every class: the
    # Class A SDR omits the 39 non-CLA KSIs and the Class B SDR omits unselected
    # optional-at-B KSIs. Deriving from the SDR keeps the graph in lockstep with
    # what was actually submitted, so no node is built without an SDR pointer.
    _applicable_ksi_ids = {e["ksiId"] for e in sdr.get("keySecurityIndicators", [])}
    if not _applicable_ksi_ids:
        # Fallback only when no SDR exists yet (first build): every KSI.
        _applicable_ksi_ids = {k["ksi_id"] for k in ksi_profile["indicators"]}
    sdr_frr_index = {e["frrID"]: i for i, e in enumerate(sdr.get("fedRampRequirements", []))}
    sdr_ksi_index = {e["ksiId"]: i for i, e in enumerate(sdr.get("keySecurityIndicators", []))}
    review_idx = _review_index()

    nodes = []

    # Rule nodes. Build a node only for a rule that is actually in the SDR. The
    # Class A SDR omits FRC-CLA-OFR optional (MAY) rules the provider did not
    # opt into (offering selected_optional_rules), so building nodes for absent
    # rules would leave each without an SDR output pointer (a false "problem").
    # The SDR is the authoritative filtered set for every class.
    for r in class_profile["rules"]:
        rid = r["rule_id"]
        if rid not in sdr_frr_index:
            continue
        rec = records.get("frr", {}).get(rid, {})
        ext = rec.get("extension", {})
        i = sdr_frr_index.get(rid)
        nodes.append({
            "node_kind": "rule",
            "rule_id": rid,
            "certification_class": cls.upper(),
            "force": r.get("force"),
            "family": r.get("family"),
            "applicability": {
                "type": "20x",
                "path": class_profile.get("meta", {}).get("path", "Program"),
                "class": cls.upper(),
                "subset": r.get("subset"),
                "resolution": r.get("resolution"),
                "applicable": True,
            },
            "provider_claim": {
                "status": rec.get("implementation_status", "Not Implemented"),
                "implementation": rec.get("implementation", []),
                "owner": ext.get("owner", "TBD"),
            },
            "verification": {
                "verification": ext.get("verification", "TBD"),
                "independent_verification": ext.get("independent_verification", "TBD"),
            },
            "evidence": _evidence_nodes(ext.get("rule_artifacts")),
            "structural_linkage": {
                # PRESENT means the requirement is present in the generated SDR
                # (structural traceability), NOT a compliance pass. A generic
                # "validation: PASS" was easy for a downstream consumer to
                # misread as a determination; this framework makes none.
                "result": "PRESENT" if rid in sdr_frr_index else "MISSING",
                "checker": "deterministic-structural",
            },
            "review": dict(_review_for(review_idx, rid, ext.get("owner", "TBD")),
                           responses=ext.get("assessor_responses", "None recorded")),
            "outputs": {
                "sdr_json_pointer": f"$.fedRampRequirements[{i}]" if i is not None else None,
            },
        })

    # KSI nodes.
    for k in ksi_profile["indicators"]:
        kid = k["ksi_id"]
        if kid not in _applicable_ksi_ids:
            continue
        rec = records.get("ksi", {}).get(kid, {})
        ext = rec.get("extension", {})
        i = sdr_ksi_index.get(kid)
        min_methods = k.get("minimum_automated_methods", {}).get(f"class_{cls}")
        tests = rec.get("tests", []) or []
        # FRC-CSX-VVK counts DISTINCT AUTOMATED methods, not raw test entries.
        # Use the exact shared counter validate_sdr.py uses, and apply the same
        # populated-vs-template rule, so this reviewer-facing report agrees with
        # the authoritative validator by construction.
        automated_methods, string_tests, _tot = count_automated_methods(tests)
        is_populated = not any(
            "TBD" in s for s in rec.get("implementation", []) or [])
        effective_methods = (automated_methods if is_populated
                             else max(automated_methods, len(tests)))
        meets_minimum = (effective_methods >= min_methods
                         if isinstance(min_methods, int) else None)
        nodes.append({
            "node_kind": "ksi",
            "ksi_id": kid,
            "certification_class": cls.upper(),
            "force": VVK_FORCE.get(cls),
            "family": k.get("family"),
            "related_nist_controls": k.get("controls", []),
            "provider_claim": {
                "status": rec.get("implementation_status", "Not Implemented"),
                "implementation": rec.get("implementation", []),
                "owner": ext.get("owner", "TBD"),
            },
            "verification": {
                "methods": tests,
                "minimum_required": min_methods,
                "automated_methods": automated_methods,
                "unclassified_string_tests": string_tests,
                "meets_minimum": meets_minimum,
                "measures_verification": ext.get("measures_verification", "TBD"),
                "automation_verification": ext.get("automation_verification", "TBD"),
            },
            "evidence": _evidence_nodes(rec.get("evidence")),
            "structural_linkage": {
                # PRESENT = present in the generated SDR (traceability), not a
                # compliance pass; this framework makes no determination.
                "result": "PRESENT" if kid in sdr_ksi_index else "MISSING",
                "checker": "deterministic-structural",
            },
            "review": _review_for(review_idx, kid, ext.get("owner", "TBD")),
            "outputs": {
                "sdr_json_pointer": f"$.keySecurityIndicators[{i}]" if i is not None else None,
            },
        })

    return {
        "graph_note": (
            "Assurance Graph: a deterministic join over the class profile, KSI "
            "profile, record store, and generated SDR. It duplicates no source "
            "data and is regenerated by build_assurance_graph.py. It records "
            "traceability, never a compliance determination; a human owns every "
            "status and review."),
        "certification_class": cls.upper(),
        "dataset_version": class_profile.get("meta", {}).get("dataset_version"),
        "node_count": len(nodes),
        "rule_nodes": sum(1 for n in nodes if n["node_kind"] == "rule"),
        "ksi_nodes": sum(1 for n in nodes if n["node_kind"] == "ksi"),
        "nodes": nodes,
    }


def main():
    profile = load(PROFILE, {})
    cls = (profile.get("certification_class") or "b").lower()
    _unsupported = class_support.unsupported_class_message(cls, 'assurance graph generation')
    if _unsupported:
        print(_unsupported)
        return 1
    graph = build_graph(cls)
    if graph is None:
        print(f"Could not build the assurance graph for class {cls.upper()}.")
        return 1
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(graph, f, indent=1)
    print(f"Assurance graph written: {os.path.relpath(OUT, BASE)} "
          f"({graph['node_count']} nodes: {graph['rule_nodes']} rules, "
          f"{graph['ksi_nodes']} KSIs).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
