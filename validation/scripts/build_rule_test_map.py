"""Reverse traceability: rule -> gate -> regression test -> mutation (AUD-F66).

The repository already answers "what does the record claim for rule X" (the
assurance graph) and "which defect did test Y close" (the defect ledger). It
could not answer the reverse question an auditor of the FRAMEWORK asks: for a
given FedRAMP rule or KSI, which automated check enforces anything about it,
which regression test protects that check, and which killed mutation proves
the test can detect the defect it guards. Those facts lived in four places
(validation gate list, scanner check catalog, defect ledger, mutation runner)
with no join.

This generator joins them DETERMINISTICALLY into traceability/rule-test-map.json
from machine-readable inputs only. Nothing is curated or inferred from prose:

  - readiness scanner checks (automation/sdrscan/check-catalog.json): each
    check names its `fedramp_basis` rule ids and classes; mode "readiness-scan"
    (advisory, per resource).
  - the defect ledger (audit/defect-ledger.json): a CLOSED defect's
    `requirement` text names the rule / KSI ids it was raised under, its
    `regression_test` text names test files, its `mutation` names the runner
    id; mode "regression-test+mutation" when the mutation is verified,
    otherwise "regression-test".
  - the mutation runner (audit/mutation_tests.py): id -> mutated file -> test.
  - the evidence adapters (automation/collectors: the registered Python
    adapters and every fixtures/mapping/*.mapping.json): each is a gate
    `adapter.<name>` with its declared source bindings (service:check -> KSI),
    the validate-suite tests whose source names it, and the runner mutations
    whose test is one of those; mode "evidence-adapter". Only a source the
    offering profile ENABLES contributes per-KSI entries (MCE-13).
  - the validation gate and test suite (sdr.py VALIDATION_GATE, TEST_SUITE)
    and the release gate sections (audit/release_gate.py SECTIONS): the gate
    registry every gate_id must resolve to.

Identifiers are only emitted when they resolve: a rule id must exist in the
pinned rule catalog or KSI catalog, a test path must exist, a mutation id must
exist in the runner. Anything that does not resolve is listed under
`unresolved_references`, never silently dropped and never invented.

WHAT THE MAP DOES NOT SAY. An entry means "an automated check in this
repository enforces something about this rule and here is its protection".
It never means the provider complies with the rule; the check proves the
record has the shape and content the rule requires, and a human still
decides every status and an assessor still assesses. Rules with no automated
disposition are listed per class as `human_review_only`: that is an honest
coverage figure, not a gap to be closed by inventing checks for rules that
need provider, FedRAMP or assessor judgment.

    python validation/scripts/build_rule_test_map.py          # write
    python validation/scripts/build_rule_test_map.py --check  # compare, exit 1 on drift
"""

import glob
import importlib.util
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.abspath(os.path.join(HERE, "..", ".."))
if BASE not in sys.path:
    sys.path.insert(0, BASE)

LEDGER = os.path.join(BASE, "audit", "defect-ledger.json")
MUTATIONS = os.path.join(BASE, "audit", "mutation_tests.py")
RELEASE_GATE = os.path.join(BASE, "audit", "release_gate.py")
CHECK_CATALOG = os.path.join(BASE, "automation", "sdrscan", "check-catalog.json")
RULE_CATALOG = os.path.join(BASE, "traceability", "rule-catalog.json")
KSI_CATALOG = os.path.join(BASE, "traceability", "ksi-catalog.json")
OFFERING = os.path.join(BASE, "profiles", "common", "offering-profile.json")
OUT = os.path.join(BASE, "traceability", "rule-test-map.json")

SCHEMA = "fedramp-rule-test-trace/v1"
# CR26 rule ids (FRC-CSX-VVK, SDR-CSX-KMT, CDS-CSO-PUB, ...) and KSI ids
# (KSI-MLA-OSM). Wildcards such as FRC-CSX-* are deliberately not matched.
_ID_RE = re.compile(r"\b[A-Z]{3}-[A-Z]{3}-[A-Z]{3}\b")
_TEST_RE = re.compile(r"[\w./-]*test_\w+\.py")
_MUT_RE = re.compile(r"\bMUT-F\d+\b")

MODE_NOTE = {
    "readiness-scan": "advisory per-resource scanner check; reports what is still missing before an "
                      "assessor signs, never gates the build",
    "regression-test+mutation": "a closed defect raised under this rule, guarded by a regression test "
                                "that a re-introduced mutation turns red (anti-circular proof)",
    "regression-test": "a closed defect raised under this rule, guarded by a regression test; no "
                       "mutation verified yet",
    "evidence-adapter": "an evidence source adapter whose declared checks the source registry binds to "
                        "this indicator; its facts are proven against a golden export by the adapter "
                        "conformance suite and its own regression test. Counted toward a class's "
                        "automated disposition only when the offering profile enables the source; a "
                        "disabled or example source is listed under gates but counts for nothing",
}

CONFORMANCE_TEST = "automation/collectors/test_adapter_conformance.py"
MAPPING_FIXTURES = os.path.join(BASE, "automation", "collectors", "fixtures", "mapping")


def adapter_gates(sdr_mod, runner, suite, offering):
    """Every evidence adapter as a gate (MCE-13 AC2): the Python adapters the
    repository registers and every mapping fixture under fixtures/mapping.
    Deterministic from machine-readable inputs only: the adapter's declared
    source bindings (service:check -> KSI ids), the test files in the validate
    suite whose source names the adapter (its registered name or its mapping
    fixture stem), the runner mutations whose test is one of those files, and
    whether the offering profile enables the source. Returns
    ({gate_id: gate}, {gate_id: set(ksi_ids)}, [enabled gate_ids])."""
    sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))
    import evidence_wiring as ew  # noqa: E402
    import mapping_adapter as ma  # noqa: E402
    try:
        import thirdparty_adapters  # noqa: E402,F401
    except Exception:
        pass
    enabled = {name for name, cfg in ((offering.get("evidence_sources") or {}).items())
               if isinstance(cfg, dict) and cfg.get("enabled") is True}
    known_ksis = ma.load_ksi_ids()
    adapters = {}  # name -> (adapter, kind, fixture_stem)
    for name in sorted(ew.list_adapters()):
        adapters[name] = (ew.get_adapter(name), "python", None)
    for mp in sorted(glob.glob(os.path.join(MAPPING_FIXTURES, "*.mapping.json"))):
        stem = os.path.basename(mp)[: -len(".mapping.json")]
        mapping = load(mp, {}) or {}
        try:
            adapter = ma.build_adapter(mapping, ksi_ids=known_ksis)
        except Exception:
            continue  # an invalid fixture is the conformance suite's finding, not a gate
        adapters[adapter.name] = (adapter, "mapping", stem)
    suite_sources = {}
    for t in sorted(suite):
        p = os.path.join(BASE, t)
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                suite_sources[t] = f.read()
    gates, targets = {}, {}
    for name, (adapter, kind, stem) in sorted(adapters.items()):
        bindings = adapter.source_bindings() if callable(getattr(adapter, "source_bindings", None)) else {}
        kids = sorted({k for ks in bindings.values() for k in (ks or [])})
        needles = [name] + ([stem] if stem else [])
        tests = sorted(t for t, src in suite_sources.items()
                       if any(n in src for n in needles) or t == CONFORMANCE_TEST)
        mutations = sorted(m for m, r in runner.items() if r["test"] in tests)
        gid = f"adapter.{name}"
        gates[gid] = {
            "kind": "evidence-adapter", "adapter_kind": kind, "service": getattr(adapter, "service", None),
            "mode": "evidence-adapter", "enabled_in_profile": name in enabled,
            "illustrative": getattr(adapter, "illustrative", False) is True,
            "checks": sorted(adapter.checks or ()) if getattr(adapter, "checks", None) else [],
            "ksi_targets": kids, "tests": tests, "mutations": mutations,
            "mutated_files": sorted({runner[m]["file"] for m in mutations}),
            "fixture": f"automation/collectors/fixtures/mapping/{stem}.mapping.json" if stem else None,
        }
        targets[gid] = set(kids)
    return gates, targets, sorted(g for g in gates if gates[g]["enabled_in_profile"])


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")


def known_ids():
    rules = {r["rule_id"]: r for r in (load(RULE_CATALOG, {}) or {}).get("rules", [])}
    ksis = {k["ksi_id"]: k for k in (load(KSI_CATALOG, {}) or {}).get("indicators", [])}
    # FRD definitions (FRD-PER "Persistently", ...) are legitimate bases a
    # scanner check may cite; they live in the dataset's FRD section, not in
    # the rule catalog.
    frd = {}
    for scope in ((load(DATASET, {}) or {}).get("FRD", {}) or {}).get("data", {}).values():
        for fid, body in (scope or {}).items():
            if isinstance(body, dict):
                frd[fid] = {"name": body.get("term")}
    return rules, ksis, frd


def gate_registry(sdr_mod, rg_mod):
    """Every gate_id the map may reference, with what it is."""
    gates = {}
    for path, desc in sdr_mod.VALIDATION_GATE:
        gates[f"validate.{os.path.splitext(os.path.basename(path))[0]}"] = {
            "kind": "validation-gate", "path": path, "description": desc}
    for section, steps in rg_mod.SECTIONS.items():
        for name, argv in steps:
            gates[f"{section}.{name}"] = {"kind": "release-gate-step", "section": section,
                                         "argv": [a if a != sys.executable else "python" for a in argv]}
    for chk in (load(CHECK_CATALOG, {}) or {}).get("checks", []):
        gates[f"scan.{chk['check_id']}"] = {"kind": "readiness-scan", "severity": chk.get("severity"),
                                            "classes": list(chk.get("applies_to_classes") or [])}
    return gates


def build():
    sdr_mod = _module("sdr_for_map", os.path.join(BASE, "sdr.py"))
    rg_mod = _module("release_gate_for_map", RELEASE_GATE)
    mut_mod = _module("mutation_tests_for_map", MUTATIONS)
    rules, ksis, frd = known_ids()
    known = set(rules) | set(ksis) | set(frd)
    gates = gate_registry(sdr_mod, rg_mod)
    runner = {m[0]: {"file": m[1], "test": m[4]} for m in mut_mod.MUTATIONS}
    suite = set(sdr_mod.TEST_SUITE)
    unresolved = {"rule_ids": [], "tests": [], "mutations": []}
    per_rule = {}

    def add(rid, entry):
        per_rule.setdefault(rid, []).append(entry)

    # 1. Scanner checks: fedramp_basis -> check.
    for chk in (load(CHECK_CATALOG, {}) or {}).get("checks", []):
        for rid in sorted(set(chk.get("fedramp_basis") or [])):
            if rid not in known:
                unresolved["rule_ids"].append({"id": rid, "source": f"scan.{chk['check_id']}"})
                continue
            add(rid, {"gate_id": f"scan.{chk['check_id']}", "mode": "readiness-scan",
                      "classes": sorted(chk.get("applies_to_classes") or []),
                      "severity": chk.get("severity")})

    # 2. Ledger defects: requirement ids -> regression tests -> mutation.
    for d in (load(LEDGER, {}) or {}).get("defects", []):
        if d.get("status") != "CLOSED":
            continue
        ids = sorted(set(_ID_RE.findall(str(d.get("requirement") or ""))))
        tests = []
        for t in sorted(set(_TEST_RE.findall(str(d.get("regression_test") or "")))):
            t = t.lstrip("./")
            if os.path.exists(os.path.join(BASE, t)):
                tests.append(t)
            else:
                unresolved["tests"].append({"path": t, "source": d.get("id")})
        mids = sorted(set(_MUT_RE.findall(str(d.get("mutation") or ""))))
        mutations = []
        for mid in mids:
            if mid in runner:
                mutations.append(mid)
            else:
                unresolved["mutations"].append({"id": mid, "source": d.get("id")})
        mode = ("regression-test+mutation"
                if mutations and d.get("mutation_verified") is True else "regression-test")
        entry = {"gate_id": f"ledger.{d.get('id')}", "mode": mode, "severity": d.get("severity"),
                 "tests": tests, "mutations": mutations,
                 "mutated_files": sorted({runner[m]["file"] for m in mutations}),
                 "in_test_suite": all(t in suite or t.startswith("examples/") or t.startswith("audit/")
                                      for t in tests)}
        for rid in ids:
            if rid not in known:
                unresolved["rule_ids"].append({"id": rid, "source": d.get("id")})
                continue
            add(rid, entry)
        gates[f"ledger.{d.get('id')}"] = {"kind": "closed-defect", "severity": d.get("severity"),
                                           "component": d.get("component")}

    # 2b. Evidence adapters (MCE-13): every adapter is a gate, listed with its
    #     mode, tests and mutations. Only a source the offering profile ENABLES
    #     contributes a per-KSI entry, so an example or disabled source never
    #     inflates the coverage figure.
    offering = load(OFFERING, {}) or {}
    a_gates, a_targets, a_enabled = adapter_gates(sdr_mod, runner, suite, offering)
    gates.update(a_gates)
    for gid in a_enabled:
        g = a_gates[gid]
        entry = {"gate_id": gid, "mode": "evidence-adapter", "tests": g["tests"],
                 "mutations": g["mutations"], "mutated_files": g["mutated_files"],
                 "in_test_suite": all(t in suite for t in g["tests"])}
        for kid in sorted(a_targets[gid]):
            if kid not in known:
                unresolved["rule_ids"].append({"id": kid, "source": gid})
                continue
            add(kid, entry)
    for gid, g in a_gates.items():
        for t in g["tests"]:
            if not os.path.exists(os.path.join(BASE, t)):
                unresolved["tests"].append({"path": t, "source": gid})
        for m in g["mutations"]:
            if m not in runner:
                unresolved["mutations"].append({"id": m, "source": gid})

    # 3. Coverage per class: applicable rule ids (class profiles) and all KSIs
    #    at the classes that submit them, split into automated-disposition and
    #    human-review-only. KSI scope follows the one resolver (sdr.submitted_ksi_ids).
    coverage = {}
    ksi_inds = (load(os.path.join(BASE, "profiles", "common", "ksi-profile.json"), {}) or {}).get("indicators", [])
    for cls in sdr_mod.class_support.SUPPORTED_CLASSES:
        prof = load(os.path.join(BASE, "profiles", f"class-{cls}", "profile.json"), {}) or {}
        rule_ids = sorted({r.get("rule_id") for r in prof.get("rules", []) if r.get("rule_id")})
        if cls == "a":
            tier = ((prof.get("meta") or {}).get("class_a_ksis") or {})
            ksi_ids = sorted(k for k in tier if isinstance(k, str))
        else:
            ksi_ids = sorted(sdr_mod.submitted_ksi_ids(ksi_inds, cls, None))
        with_disp = [i for i in rule_ids + ksi_ids
                     if any(cls in (e.get("classes") or ["a", "b", "c"]) for e in per_rule.get(i, []))]
        without = [i for i in rule_ids + ksi_ids if i not in with_disp]
        coverage[cls] = {
            "applicable_rules": len(rule_ids), "applicable_ksis": len(ksi_ids),
            "with_automated_disposition": len(with_disp),
            "human_review_only": without,
        }

    rule_block = {}
    for rid in sorted(per_rule):
        entries = sorted(per_rule[rid], key=lambda e: e["gate_id"])
        rule_block[rid] = {
            "kind": "ksi" if rid in ksis else ("definition" if rid in frd else "rule"),
            "name": (ksis.get(rid) or rules.get(rid) or frd.get(rid) or {}).get("name"),
            "enforcement": entries,
        }

    return {
        "schema": SCHEMA,
        "dataset_version": offering.get("dataset_version"),
        "note": ("Reverse traceability for the FRAMEWORK: rule -> gate -> regression test -> killed "
                 "mutation, joined deterministically from the scanner check catalog, the defect "
                 "ledger, the mutation runner and the gate registries. An entry means an automated "
                 "check enforces something about the rule and names its protection. It never means "
                 "the provider complies with the rule: a human decides every status and an assessor "
                 "assesses. human_review_only lists applicable identifiers with no automated "
                 "disposition; that is a coverage figure, not a defect list. unresolved_references "
                 "lists identifiers a source cites that the pinned dataset does not carry: a ledger "
                 "entry raised under a rule a later dataset release retired keeps its historical "
                 "citation and is reported here rather than rewritten."),
        "modes": MODE_NOTE,
        "gates": {k: gates[k] for k in sorted(gates)},
        "rules": rule_block,
        "coverage": coverage,
        "unresolved_references": {k: sorted(v, key=lambda x: json.dumps(x, sort_keys=True))
                                  for k, v in unresolved.items()},
    }


def render(doc):
    return json.dumps(doc, indent=1, sort_keys=False, ensure_ascii=False) + "\n"


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    doc = build()
    text = render(doc)
    if "--check" in argv:
        current = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
        if current != text:
            print(f"FAIL: {os.path.relpath(OUT, BASE)} is out of date; run "
                  "python validation/scripts/build_rule_test_map.py")
            return 1
        print(f"OK: {os.path.relpath(OUT, BASE)} is current.")
        return 0
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    n_rules = len(doc["rules"])
    n_unres = sum(len(v) for v in doc["unresolved_references"].values())
    cov = "; ".join(f"Class {c.upper()}: {v['with_automated_disposition']} of "
                    f"{v['applicable_rules'] + v['applicable_ksis']} with an automated disposition"
                    for c, v in doc["coverage"].items())
    print(f"Rule-test map written: {os.path.relpath(OUT, BASE)} ({n_rules} identifiers mapped, "
          f"{len(doc['gates'])} gates, {n_unres} unresolved references). {cov}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
