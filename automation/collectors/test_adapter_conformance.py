"""MCE-13 AC1: adapter conformance suite. Every evidence adapter this repository
ships is proven against its golden export, by DISCOVERY, so a source cannot be
added without conformance:

  - every mapping fixture under fixtures/mapping/*.mapping.json must have an
    export (.export.json, .export.jsonl, .export.csv or .results.xml) and a
    golden .expected-facts.json; the mapping is validated against the schema,
    built, run offline against its export, and the facts must equal the golden
    byte for byte (canonical JSON); every fact must meet the fact contract;
    every KSI the mapping binds must exist in the pinned KSI profile; the
    mapping must cite documentation when its service is a third party's;
  - every Python adapter registered by thirdparty_adapters must have a case in
    fixtures/adapter-golden-evidence.json and its evidence must equal that
    golden byte for byte; a registered adapter without a case fails, naming it;
  - every registered adapter (both kinds) declares a non-empty check vocabulary
    and binds every declared check to at least one KSI (MCE-03), so nothing
    it yields can be evidence for no indicator; the one exception is an adapter
    that declares itself `illustrative = True` (the csv-count reference
    adapter), which binds nothing by design and is reported as such.

A mismatch fails naming the adapter and the first differing fact. Goldens are
regenerated deliberately by the adapter's own story, never here.

Run:
    python automation/collectors/test_adapter_conformance.py
"""

import glob
import json
import os
import socket
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import evidence_wiring as ew  # noqa: E402
import mapping_adapter as ma  # noqa: E402
import thirdparty_adapters  # noqa: E402,F401  (registers the Python adapters on import)

FIX = os.path.join(HERE, "fixtures", "mapping")
PY_GOLDEN = os.path.join(HERE, "fixtures", "adapter-golden-evidence.json")
EXPORT_SUFFIXES = (".export.json", ".export.jsonl", ".export.csv", ".results.xml")
FIRST_PARTY_SERVICES = {"example-posture", "openscap"}


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class _NoNetwork:
    def __enter__(self):
        self._real = socket.socket

        def boom(*a, **k):
            raise AssertionError("network access attempted by an offline adapter")

        socket.socket = boom
        return self

    def __exit__(self, *exc):
        socket.socket = self._real
        return False


def mapping_fixtures():
    """[(stem, mapping_path, export_path, golden_path)] for every mapping
    fixture; export or golden may be None when missing (the suite fails on it)."""
    out = []
    for mp in sorted(glob.glob(os.path.join(FIX, "*.mapping.json"))):
        stem = os.path.basename(mp)[: -len(".mapping.json")]
        exports = [os.path.join(FIX, stem + s) for s in EXPORT_SUFFIXES
                   if os.path.exists(os.path.join(FIX, stem + s))]
        golden = os.path.join(FIX, stem + ".expected-facts.json")
        out.append((stem, mp, exports[0] if exports else None, golden if os.path.exists(golden) else None))
    return out


def first_difference(actual, expected):
    for i, (a, e) in enumerate(zip(actual, expected)):
        if _canon(a) != _canon(e):
            return f"fact {i}: got {_canon(a)[:200]} expected {_canon(e)[:200]}"
    if len(actual) != len(expected):
        return f"count: got {len(actual)} expected {len(expected)}"
    return None


def check_mapping_fixture(stem, mapping_path, export_path, golden_path, known_ksis):
    problems = []
    if export_path is None:
        problems.append(f"{stem}: no export fixture ({', '.join(EXPORT_SUFFIXES)})")
    if golden_path is None:
        problems.append(f"{stem}: no golden {stem}.expected-facts.json")
    if problems:
        return problems
    mapping = json.loads(_read(mapping_path))
    schema_problems = ma.validate_mapping(mapping)
    if schema_problems:
        return [f"{stem}: mapping refused: {'; '.join(schema_problems)[:300]}"]
    bound = set(mapping.get("ksi_targets") or [])
    for ids in (mapping.get("check_bindings") or {}).values():
        bound |= set(ids or [])
    unknown = sorted(bound - known_ksis)
    if unknown:
        problems.append(f"{stem}: binds KSI ids not in the pinned profile: {', '.join(unknown)}")
    if mapping.get("service") not in FIRST_PARTY_SERVICES and not (mapping.get("documentation") or {}).get("url"):
        problems.append(f"{stem}: a third-party source must cite its documentation (THIRD_PARTY_NOTICE.md)")
    if not mapping.get("checks"):
        problems.append(f"{stem}: declares no checks (MCE-03)")
    with _NoNetwork():
        adapter = ma.build_adapter(mapping, ksi_ids=known_ksis)
        facts = list(adapter.collect(_read(export_path)))
    golden = json.loads(_read(golden_path))
    expected = golden.get("facts")
    if not isinstance(expected, list) or not expected:
        problems.append(f"{stem}: golden carries no facts")
        return problems
    diff = first_difference(facts, expected)
    if diff:
        problems.append(f"{stem}: facts differ from golden: {diff}")
    for i, f in enumerate(facts):
        bad = ew.validate_fact(f)
        if bad:
            problems.append(f"{stem}: fact {i} violates the contract: {bad}")
            break
    for key, kids in adapter.source_bindings().items():
        if not kids:
            problems.append(f"{stem}: declared check {key} binds to no KSI (MCE-03)")
    return problems


def check_python_adapters():
    problems = []
    golden = json.loads(_read(PY_GOLDEN))
    base = golden["location_base"]
    cases = golden.get("adapters") or {}
    registered = sorted(ew.list_adapters())
    python_adapters = [n for n in registered if n not in _mapping_adapter_names()]
    for name in python_adapters:
        adapter = ew.get_adapter(name)
        case = cases.get(name)
        if case is None:
            problems.append(f"{name}: registered adapter has no case in fixtures/adapter-golden-evidence.json")
            continue
        with _NoNetwork():
            actual = adapter.to_evidence(case["raw"], base)
        if _canon(actual) != _canon(case["expected"]):
            problems.append(f"{name}: evidence differs from golden: {first_difference(actual, case['expected'])}")
        if getattr(adapter, "illustrative", False) is True:
            # Declared illustrative: binds nothing by design and says so. The
            # provenance gate treats its evidence as unbound; the suite only
            # requires the declaration to be explicit.
            print(f"NOTE {name}: declared illustrative, declares no checks, binds no KSI")
        else:
            if not getattr(adapter, "checks", None):
                problems.append(f"{name}: declares no checks and is not declared illustrative (MCE-03)")
            for key, kids in (adapter.source_bindings() or {}).items():
                if not kids:
                    problems.append(f"{name}: declared check {key} binds to no KSI (MCE-03)")
    for name in sorted(set(cases) - set(registered)):
        problems.append(f"{name}: golden case for an adapter that is not registered")
    return problems, python_adapters


def _mapping_adapter_names():
    return {json.loads(_read(mp)).get("name") for _, mp, _, _ in mapping_fixtures()}


def main():
    known = ma.load_ksi_ids()
    fixtures = mapping_fixtures()
    problems = []
    for stem, mp, ex, gd in fixtures:
        p = check_mapping_fixture(stem, mp, ex, gd, known)
        problems.extend(p)
        print(("FAIL " if p else "PASS ") + f"mapping fixture {stem}")
    py_problems, py_names = check_python_adapters()
    problems.extend(py_problems)
    for name in py_names:
        print(("FAIL " if any(x.startswith(name + ":") for x in py_problems) else "PASS ") + f"python adapter {name}")
    if not fixtures:
        problems.append("no mapping fixtures discovered under fixtures/mapping")
    if not py_names:
        problems.append("no Python adapters registered by thirdparty_adapters")
    for p in problems:
        print("  - " + p)
    print(f"\nadapter conformance: {len(fixtures)} mapping fixture(s), {len(py_names)} Python adapter(s), "
          f"{len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
