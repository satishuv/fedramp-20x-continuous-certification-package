#!/usr/bin/env python3
"""MAS-by-KSI coverage report (FRC-CSX-MAS, SHOULD), one file per class.

FRC-CSX-MAS: "Providers SHOULD apply ALL Key Security Indicators to ALL aspects
of their cloud service offering that are within the FedRAMP Minimum Assessment
Scope." The per-KSI record shows that evidence exists for each indicator; it
cannot show that no information resource inside the MAS was simply forgotten.
This report turns the provider's own MAS inventory into that surface: for every
in-scope information resource and every KSI applicable at the class, one cell
that is either DEMONSTRATED (the provider names the test method or evidence in
the KSI record that covers this resource, and it resolves), NOT APPLICABLE (the
provider states why the indicator does not apply to this resource), UNRESOLVED
(a declaration that does not resolve, or a reason left empty) or a GAP (nothing
declared). Nothing is inferred: a cell is covered only because a human said so
and the reference exists.

Input (optional, provider-authored): profiles/common/mas-inventory.json
  {
    "resources": [
      {"id": "ecs-case-api", "name": "ECS workload (case manager API)",
       "kind": "aws-service", "aws_service": "Amazon ECS",
       "in_mas": true, "handles_federal_data": true,
       "ksi_coverage": {
         "KSI-CNA-RNT": {"demonstrated_by": ["KSI-CNA-RNT:verify:config:restricted-ssh"]},
         "KSI-CED-RAT": {"not_applicable": "Training is a workforce indicator; see the KSI-CED-RAT record"},
         "*": {"not_applicable": "<a default for every KSI not listed; counted separately>"}
       }},
      {"id": "marketing-site", "name": "Public marketing website", "in_mas": false,
       "exclusion_reason": "Static site; handles no federal customer data"}
    ]
  }
A demonstrated_by reference resolves when it equals a tests[].method_id or an
evidence[].evidenceLocation of that KSI's record. An out-of-scope resource must
carry an exclusion_reason. The report never changes a status and never blocks
submission (the rule is SHOULD); preflight surfaces its counts as an advisory.

Outputs (deterministic, all three classes every build so the committed files
never drift): artifacts/mas-ksi-coverage-class-{a,b,c}.json and .md
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.abspath(os.path.join(HERE, "..", ".."))
if BASE not in sys.path:
    sys.path.insert(0, BASE)
from sdr import submitted_ksi_ids  # noqa: E402
import class_support  # noqa: E402  (AUD-F65: the one class-support state)

INVENTORY = os.path.join(BASE, "profiles", "common", "mas-inventory.json")
OFFERING = os.path.join(BASE, "profiles", "common", "offering-profile.json")
RECORDS = os.path.join(BASE, "sdr", "records", "records-store.json")
KSI_PROFILE = os.path.join(BASE, "profiles", "common", "ksi-profile.json")
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
OUT_DIR = os.path.join(BASE, "artifacts")
RULE_ID = "FRC-CSX-MAS"
CLASSES = ("a", "b", "c")
STATUSES = ("demonstrated", "not_applicable", "unresolved", "gap")


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _find_rule(node, rid):
    if isinstance(node, dict):
        if rid in node and isinstance(node[rid], dict):
            return node[rid]
        for v in node.values():
            r = _find_rule(v, rid)
            if r is not None:
                return r
    return None


def _text(v):
    return str(v).strip() if v is not None else ""


def applicable_ksis_for_class(cls, ksi_profile, class_profile, offering):
    """The KSI ids the package submits at `cls`, resolved exactly as build_sdr
    and preflight resolve them (Class A: the FRC-CLA-MFR enumeration in the
    class-a profile meta; Class B: the shared opt-in resolver; Class C: all).
    AUD-F65: an unsupported class raises instead of falling into the Class C
    branch (everything that was not a or b used to resolve to all KSIs)."""
    cls = class_support.require_supported_class(cls, "MAS coverage")
    indicators = ksi_profile.get("indicators") or []
    if cls == "a":
        tier = ((class_profile or {}).get("meta") or {}).get("class_a_ksis") or {}
        return sorted(k for k in tier if isinstance(k, str))
    if cls == "b":
        return sorted(submitted_ksi_ids(indicators, cls, list(offering.get("selected_optional_ksis") or [])))
    return sorted(k.get("ksi_id") for k in indicators if k.get("ksi_id"))


def record_references(rec):
    """Every reference a demonstrated_by entry may resolve to in one KSI record:
    tests[].method_id and evidence[].evidenceLocation."""
    refs = set()
    for t in (rec or {}).get("tests") or []:
        if isinstance(t, dict) and _text(t.get("method_id")):
            refs.add(_text(t["method_id"]))
    for e in (rec or {}).get("evidence") or []:
        if isinstance(e, dict):
            loc = e.get("evidenceLocation") or e.get("evidence_location")
            if _text(loc):
                refs.add(_text(loc))
    return refs


def coverage_for_class(inventory, records, applicable, cls, dataset_version, rule=None):
    """The report for one class. Pure: no file access."""
    resources = (inventory or {}).get("resources") or []
    ksi_records = (records or {}).get("ksi") or {}
    problems = []
    in_scope, excluded = [], []
    cells = []
    for res in resources:
        if not isinstance(res, dict):
            problems.append("a resource entry is not an object")
            continue
        rid = _text(res.get("id"))
        if not rid:
            problems.append("a resource has no id")
            continue
        if res.get("in_mas") is False:
            reason = _text(res.get("exclusion_reason"))
            excluded.append({"id": rid, "name": _text(res.get("name")) or rid,
                             "exclusion_reason": reason or None})
            if not reason:
                problems.append(f"{rid}: in_mas is false but no exclusion_reason is given")
            continue
        if res.get("in_mas") is not True:
            problems.append(f"{rid}: in_mas must be true or false")
            continue
        in_scope.append({"id": rid, "name": _text(res.get("name")) or rid,
                         "kind": _text(res.get("kind")) or None,
                         "aws_service": _text(res.get("aws_service")) or None,
                         "handles_federal_data": res.get("handles_federal_data")})
        cov = res.get("ksi_coverage") or {}
        if not isinstance(cov, dict):
            problems.append(f"{rid}: ksi_coverage must be an object keyed by KSI id")
            cov = {}
        for key in cov:
            if key != "*" and key not in applicable:
                problems.append(f"{rid}: ksi_coverage names {key}, which is not a KSI "
                                f"submitted at Class {cls.upper()} (ignored)")
        default = cov.get("*") if isinstance(cov.get("*"), dict) else None
        for kid in applicable:
            decl = cov.get(kid) if isinstance(cov.get(kid), dict) else None
            by_default = decl is None and default is not None
            decl = decl if decl is not None else default
            cell = {"resource": rid, "ksi": kid, "status": "gap", "references": [],
                    "note": None, "by_default": by_default}
            if decl is not None:
                refs = decl.get("demonstrated_by")
                na = decl.get("not_applicable")
                if refs:
                    refs = [_text(r) for r in (refs if isinstance(refs, list) else [refs]) if _text(r)]
                    known = record_references(ksi_records.get(kid))
                    missing = [r for r in refs if r not in known]
                    cell["references"] = refs
                    if refs and not missing:
                        cell["status"] = "demonstrated"
                    else:
                        cell["status"] = "unresolved"
                        cell["note"] = ("demonstrated_by does not resolve to a tests[].method_id or "
                                        "evidence[].evidenceLocation of the " + kid + " record: "
                                        + ", ".join(missing or ["(empty)"]))
                elif "not_applicable" in decl:
                    if _text(na):
                        cell["status"] = "not_applicable"
                        cell["note"] = _text(na)
                    else:
                        cell["status"] = "unresolved"
                        cell["note"] = "not_applicable requires a reason"
                else:
                    cell["status"] = "unresolved"
                    cell["note"] = "declaration has neither demonstrated_by nor not_applicable"
            cells.append(cell)
    summary = {s: sum(1 for c in cells if c["status"] == s) for s in STATUSES}
    summary["cells"] = len(cells)
    summary["by_default"] = sum(1 for c in cells if c["by_default"])
    summary["resources_in_mas"] = len(in_scope)
    summary["resources_excluded"] = len(excluded)
    summary["ksis_applicable"] = len(applicable)
    return {
        "meta": {
            "title": "MAS-by-KSI coverage",
            "rule": RULE_ID,
            "force": (rule or {}).get("force"),
            "statement": (rule or {}).get("statement"),
            "certification_class": cls.upper(),
            "dataset_version": dataset_version,
            "generated": f"deterministic build from dataset {dataset_version}",
            "inventory_declared": bool(resources),
            "note": ("Advisory surface for FRC-CSX-MAS (SHOULD). A cell is demonstrated only "
                     "because the provider named a test method or evidence in the KSI record "
                     "that covers this resource and it resolves; nothing is inferred. This "
                     "report sets no status and is not a compliance determination."),
        },
        "summary": summary,
        "resources_in_mas": in_scope,
        "resources_excluded": excluded,
        "problems": problems,
        "cells": cells,
    }


def render_md(report):
    m, s = report["meta"], report["summary"]
    L = [f"MAS-by-KSI coverage, Class {m['certification_class']} (dataset {m['dataset_version']})", ""]
    L.append(f"{m['rule']} ({m['force']}): {m['statement']}")
    L.append("")
    if not m["inventory_declared"]:
        L.append("No MAS inventory is declared (profiles/common/mas-inventory.json has no "
                 "resources). FRC-CSX-MAS coverage cannot be shown per information resource "
                 "until the provider lists the resources inside the Minimum Assessment Scope.")
        return "\n".join(L) + "\n"
    L.append(f"Information resources in the MAS: {s['resources_in_mas']}; excluded with a "
             f"reason: {s['resources_excluded']}; indicators submitted at this class: "
             f"{s['ksis_applicable']}.")
    L.append(f"Cells: {s['cells']}; demonstrated {s['demonstrated']}; not applicable "
             f"{s['not_applicable']}; unresolved {s['unresolved']}; gaps {s['gap']}"
             + (f"; covered by a resource's default declaration: {s['by_default']}" if s["by_default"] else "")
             + ".")
    if report["problems"]:
        L.append("")
        L.append("Problems with the inventory:")
        for p in report["problems"]:
            L.append(f"- {p}")
    L.append("")
    L.append("| MAS resource | KSI | Status | Reference or reason |")
    L.append("|---|---|---|---|")
    for c in report["cells"]:
        detail = ", ".join(c["references"]) if c["references"] else (c["note"] or "")
        if c["by_default"]:
            detail = (detail + " (default declaration)").strip()
        L.append(f"| {c['resource']} | {c['ksi']} | {c['status']} | {detail} |")
    if report["resources_excluded"]:
        L.append("")
        L.append("Resources declared outside the MAS:")
        for r in report["resources_excluded"]:
            L.append(f"- {r['name']}: {r['exclusion_reason'] or 'NO REASON GIVEN'}")
    return "\n".join(L) + "\n"


def build_all():
    inventory = load(INVENTORY, {"resources": []})
    offering = load(OFFERING, {})
    records = load(RECORDS, {})
    ksi_profile = load(KSI_PROFILE, {"indicators": []})
    dataset_version = (ksi_profile.get("meta") or {}).get("dataset_version")
    rule = _find_rule(load(DATASET, {}), RULE_ID)
    os.makedirs(OUT_DIR, exist_ok=True)
    for cls in CLASSES:
        class_profile = load(os.path.join(BASE, "profiles", f"class-{cls}", "profile.json"), {})
        applicable = applicable_ksis_for_class(cls, ksi_profile, class_profile, offering)
        report = coverage_for_class(inventory, records, applicable, cls, dataset_version, rule)
        with open(os.path.join(OUT_DIR, f"mas-ksi-coverage-class-{cls}.json"), "w",
                  encoding="utf-8", newline="\n") as f:
            json.dump(report, f, indent=1)
            f.write("\n")
        with open(os.path.join(OUT_DIR, f"mas-ksi-coverage-class-{cls}.md"), "w",
                  encoding="utf-8", newline="\n") as f:
            f.write(render_md(report))
        s = report["summary"]
        print(f"Class {cls.upper()}: {s['resources_in_mas']} MAS resource(s) x "
              f"{s['ksis_applicable']} KSI(s) = {s['cells']} cell(s); demonstrated "
              f"{s['demonstrated']}, not applicable {s['not_applicable']}, unresolved "
              f"{s['unresolved']}, gaps {s['gap']}"
              + (f"; {len(report['problems'])} inventory problem(s)" if report["problems"] else ""))


if __name__ == "__main__":
    build_all()
