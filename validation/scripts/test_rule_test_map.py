# Reverse traceability map: rule -> gate -> regression test -> mutation
# (validation/scripts/build_rule_test_map.py, AUD-F66).
#
# What this test proves about traceability/rule-test-map.json:
#   - it is deterministic (two builds, identical bytes) and current (--check);
#   - every identifier it maps exists in the pinned rule catalog, KSI catalog or
#     the dataset's FRD definitions; nothing is invented;
#   - every gate_id resolves to a registered gate (validation gate script,
#     release-gate step, scanner check or ledgered defect);
#   - every regression test path exists, every mutation id exists in the runner
#     and in the ledger as CLOSED + mutation_verified, and a "+mutation" mode is
#     claimed only then;
#   - every CLOSED, mutation-verified ledger defect that names a resolvable rule
#     appears in the map with at least one existing test;
#   - the coverage block recomputes from the class profiles and the ONE KSI
#     resolver, and lists human_review_only honestly (no automated disposition
#     is ever fabricated to shrink it);
#   - identifiers a source cites that the dataset does not carry are reported
#     under unresolved_references rather than dropped.
#
# Run: python validation/scripts/test_rule_test_map.py

import importlib.util
import json
import os
import re
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
import build_rule_test_map as brm  # noqa: E402

_fail = 0


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def test_deterministic_and_current():
    a = brm.render(brm.build())
    b = brm.render(brm.build())
    check("two builds render identical bytes", a == b)
    rc = subprocess.run([sys.executable, os.path.join(BASE, "validation", "scripts", "build_rule_test_map.py"),
                         "--check"], cwd=BASE, capture_output=True, text=True).returncode
    check("the committed map is current (--check exit 0)", rc == 0)
    doc = json.loads(a)
    check("schema and dataset version are stated",
          doc["schema"] == brm.SCHEMA and doc["dataset_version"])
    for volatile in ("generated", "timestamp", "duration", "recorded_at"):
        check(f"no volatile key {volatile!r} in the map", f'"{volatile}":' not in a)


def test_every_reference_resolves():
    doc = brm.build()
    rules, ksis, frd = brm.known_ids()
    known = set(rules) | set(ksis) | set(frd)
    check("every mapped identifier exists in the pinned catalogs or FRD definitions",
          all(rid in known for rid in doc["rules"]))
    check("kind matches the catalog the identifier came from",
          all((v["kind"] == "ksi") == (rid in ksis) and (v["kind"] == "definition") == (rid in frd)
              for rid, v in doc["rules"].items()))
    gates = doc["gates"]
    check("every enforcement gate_id is a registered gate",
          all(e["gate_id"] in gates for v in doc["rules"].values() for e in v["enforcement"]))
    spec = importlib.util.spec_from_file_location("mt_for_test", os.path.join(BASE, "audit", "mutation_tests.py"))
    mt = importlib.util.module_from_spec(spec); spec.loader.exec_module(mt)
    runner = {m[0] for m in mt.MUTATIONS}
    ledger = {d["id"]: d for d in _load(os.path.join(BASE, "audit", "defect-ledger.json"))["defects"]}
    verified = {re.match(r"MUT-F\d+", str(d.get("mutation") or "")).group(0)
                for d in ledger.values()
                if d.get("status") == "CLOSED" and d.get("mutation_verified") is True
                and re.match(r"MUT-F\d+", str(d.get("mutation") or ""))}
    ok_tests = ok_muts = ok_mode = True
    for v in doc["rules"].values():
        for e in v["enforcement"]:
            for t in e.get("tests", []):
                ok_tests &= os.path.exists(os.path.join(BASE, t))
            for m in e.get("mutations", []):
                ok_muts &= (m in runner and m in verified)
            if e["mode"] == "regression-test+mutation":
                ok_mode &= bool(e.get("mutations")) and bool(e.get("tests"))
            if e["mode"] == "readiness-scan":
                ok_mode &= e["gate_id"].startswith("scan.") and bool(e.get("classes"))
    check("every regression test path exists", ok_tests)
    check("every mutation exists in the runner AND the ledger (CLOSED, mutation_verified)", ok_muts)
    check("a '+mutation' mode is claimed only with a mutation and a test; scan entries carry classes", ok_mode)
    # Every closed, mutation-verified defect naming a resolvable rule is in the map.
    missing = []
    for did, d in ledger.items():
        if d.get("status") != "CLOSED" or d.get("mutation_verified") is not True:
            continue
        ids = [i for i in set(brm._ID_RE.findall(str(d.get("requirement") or ""))) if i in known]
        for rid in ids:
            ents = [e for e in doc["rules"].get(rid, {}).get("enforcement", []) if e["gate_id"] == f"ledger.{did}"]
            if not ents or not ents[0].get("tests"):
                missing.append((did, rid))
    check(f"every closed mutation-verified defect under a known rule is mapped with a test: missing={missing}",
          missing == [])
    check("gate registry includes every validation gate script, release-gate step and scanner check",
          any(k.startswith("validate.") for k in gates) and any(k.startswith("audit.") for k in gates)
          and any(k.startswith("attack.") for k in gates) and any(k.startswith("scan.") for k in gates))


def test_coverage_is_honest():
    doc = brm.build()
    sdr_mod = brm._module("sdr_for_cov_test", os.path.join(BASE, "sdr.py"))
    ksi_inds = _load(os.path.join(BASE, "profiles", "common", "ksi-profile.json"))["indicators"]
    for cls, cov in doc["coverage"].items():
        prof = _load(os.path.join(BASE, "profiles", f"class-{cls}", "profile.json"))
        rule_ids = sorted({r["rule_id"] for r in prof["rules"]})
        if cls == "a":
            ksi_ids = sorted(k for k in (prof.get("meta") or {}).get("class_a_ksis", {}) if isinstance(k, str))
        else:
            ksi_ids = sorted(sdr_mod.submitted_ksi_ids(ksi_inds, cls, None))
        check(f"class {cls}: applicable counts recompute from the profile and the one KSI resolver",
              cov["applicable_rules"] == len(rule_ids) and cov["applicable_ksis"] == len(ksi_ids))
        check(f"class {cls}: with_automated_disposition + human_review_only == applicable",
              cov["with_automated_disposition"] + len(cov["human_review_only"]) == len(rule_ids) + len(ksi_ids))
        check(f"class {cls}: human_review_only identifiers have no entry applying at this class",
              all(not any(cls in (e.get("classes") or ["a", "b", "c"]) for e in doc["rules"].get(i, {}).get("enforcement", []))
                  for i in cov["human_review_only"]))
    check("Class C: FRC-CSX-VVK has an automated disposition (its regression family is ledgered)",
          "FRC-CSX-VVK" in doc["rules"] and "FRC-CSX-VVK" not in doc["coverage"]["c"]["human_review_only"])
    check("the note states what the map does NOT say (never a compliance determination)",
          "never means the provider complies" in doc["note"])


def test_unresolved_are_reported_not_dropped():
    doc = brm.build()
    unres = doc["unresolved_references"]
    check("unresolved block has the three categories", set(unres) == {"rule_ids", "tests", "mutations"})
    check("no dangling test or mutation references", unres["tests"] == [] and unres["mutations"] == [])
    # FRC-CSX-MOT was retired from the dataset in 2026.10.08.01; the ledger
    # entries raised under it keep their historical citation and the map
    # reports them rather than rewriting history.
    rules, ksis, frd = brm.known_ids()
    ids = {u["id"] for u in unres["rule_ids"]}
    check("every unresolved rule id is genuinely absent from the catalogs",
          all(i not in rules and i not in ksis and i not in frd for i in ids))
    check("the retired FRC-CSX-MOT citations are reported, not silently dropped",
          "FRC-CSX-MOT" in ids and all(u["source"].startswith("AUD-F") for u in unres["rule_ids"] if u["id"] == "FRC-CSX-MOT"))


def main():
    for t in (test_deterministic_and_current, test_every_reference_resolves,
              test_coverage_is_honest, test_unresolved_are_reported_not_dropped):
        print(t.__name__)
        t()
    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: rule-test map ({_fail} failures)")
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
