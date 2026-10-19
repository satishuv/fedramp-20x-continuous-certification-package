#!/usr/bin/env python3
"""Hash-locked dependency closure (AUD-F25).

CI and the AWS builds install with `pip install --require-hashes -r
requirements.lock`, so the lock IS the supply chain. This test pins the
properties that make that honest:
  - the lock exists, is non-trivial, and every entry carries at least one hash;
  - every direct `name==version` pin in requirements.txt / requirements-ci.txt
    appears in the lock at the SAME version (a bump without a re-lock fails);
  - the committed SBOM is built from the resolved closure (component count equals
    the lock's package count, scope resolved-closure-with-hashes), not from the
    top-level pins alone;
  - every workflow and buildspec that installs dependencies does so from the
    lock with --require-hashes.

    python validation/scripts/test_lock_closure.py
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
LOCK = os.path.join(BASE, "requirements.lock")
PIN_RE = re.compile(r"^([A-Za-z0-9._-]+)==([A-Za-z0-9._!+-]+)")
_fail = 0


def check(name, cond, detail=""):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}" + (f" -- {detail}" if detail else ""))


def _direct_pins(path):
    pins = {}
    for line in open(path, encoding="utf-8"):
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("-"):
            continue
        m = PIN_RE.match(s)
        if m:
            pins[m.group(1).lower().replace("_", "-")] = m.group(2)
    return pins


def _lock_entries(path):
    entries = {}
    name = None
    for line in open(path, encoding="utf-8"):
        s = line.rstrip("\n")
        st = s.strip()
        if not st or st.startswith("#"):
            continue
        m = PIN_RE.match(st)
        if m:
            name = m.group(1).lower().replace("_", "-")
            entries[name] = {"version": m.group(2), "hashes": len(re.findall(r"--hash=", st))}
        elif name and "--hash=" in st:
            entries[name]["hashes"] += st.count("--hash=")
    return entries


def main():
    check("requirements.lock is committed", os.path.exists(LOCK))
    if not os.path.exists(LOCK):
        print(f"\nFAIL: lock closure ({_fail} failures)")
        return 1
    lock = _lock_entries(LOCK)
    check("lock resolves a real closure (more packages than the direct pins)",
          len(lock) >= 15, f"{len(lock)} entries")
    unhashed = sorted(n for n, e in lock.items() if e["hashes"] == 0)
    check("every lock entry carries at least one sha256 hash", not unhashed, str(unhashed))

    direct = {}
    for rel in ("requirements.txt", "requirements-ci.txt"):
        direct.update(_direct_pins(os.path.join(BASE, rel)))
    check("direct pins were found in the requirements files", len(direct) >= 3, str(direct))
    drift = {n: (v, (lock.get(n) or {}).get("version"))
             for n, v in direct.items() if (lock.get(n) or {}).get("version") != v}
    check("every direct pin is in the lock at the same version (no drift)",
          not drift, str(drift))

    # Rebuild the SBOM with the CURRENT builder (output redirected to a temp
    # path) so this compares the builder's behavior, not a committed file that
    # a regressed builder would leave stale until the next build.
    import importlib.util
    import tempfile
    spec = importlib.util.spec_from_file_location("build_sbom", os.path.join(HERE, "build_sbom.py"))
    bs = importlib.util.module_from_spec(spec); spec.loader.exec_module(bs)
    tmp_out = os.path.join(tempfile.mkdtemp(prefix="sbom-"), "sbom.cdx.json")
    bs.OUT = tmp_out
    rc = bs.build()
    check("SBOM builder runs against the committed lock", rc == 0 and os.path.exists(tmp_out))
    sbom = json.load(open(tmp_out, encoding="utf-8"))
    committed = json.load(open(os.path.join(BASE, "artifacts", "sbom.cdx.json"), encoding="utf-8"))
    check("committed SBOM equals a fresh build from the lock (no stale artifact)",
          committed.get("components") == sbom.get("components"))
    comps = sbom.get("components") or []
    props = {p.get("name"): p.get("value")
             for p in ((sbom.get("metadata") or {}).get("properties") or [])}
    check("SBOM scope is the resolved closure with hashes",
          props.get("sbom:scope") == "resolved-closure-with-hashes", str(props))
    check("SBOM component count equals the lock's package count",
          len(comps) == len(lock), f"sbom={len(comps)} lock={len(lock)}")
    sbom_names = {(c.get("name") or "").lower().replace("_", "-") for c in comps}
    check("every lock package is an SBOM component",
          set(lock) <= sbom_names, str(sorted(set(lock) - sbom_names)[:5]))
    hashed = sum(1 for c in comps if c.get("hashes"))
    check("every SBOM component carries hashes", hashed == len(comps),
          f"{hashed}/{len(comps)}")

    installers = [
        ".github/workflows/validate.yml", ".github/workflows/release.yml",
        ".github/workflows/drift-check.yml", ".github/workflows/living-sdr-loop.yml",
        "automation/pipeline/buildspec-validate.yml", "automation/pipeline/buildspec-collect.yml",
    ]
    for rel in installers:
        text = open(os.path.join(BASE, rel), encoding="utf-8").read()
        check(f"{rel} installs from the hash-locked closure",
              "--require-hashes -r requirements.lock" in text
              and "-r requirements-ci.txt" not in text)

    # AUD-F92: the security-gate tools have their own hash-locked closure, the
    # two installers that run the security section use it, and no path installs
    # a scanner by bare version pin any more.
    sec_lock_path = os.path.join(BASE, "requirements-security.lock")
    check("requirements-security.lock is committed", os.path.exists(sec_lock_path))
    if os.path.exists(sec_lock_path):
        sec_lock = _lock_entries(sec_lock_path)
        sec_unhashed = sorted(n for n, e in sec_lock.items() if e["hashes"] == 0)
        check("every security-lock entry carries at least one sha256 hash", not sec_unhashed, str(sec_unhashed))
        sec_direct = _direct_pins(os.path.join(BASE, "requirements-security.txt"))
        sec_drift = {n: (v, (sec_lock.get(n) or {}).get("version"))
                     for n, v in sec_direct.items() if (sec_lock.get(n) or {}).get("version") != v}
        check("every security-tool pin is in its lock at the same version", not sec_drift, str(sec_drift))
        shared_drift = {n: (sec_lock[n]["version"], lock[n]["version"])
                        for n in set(sec_lock) & set(lock) if sec_lock[n]["version"] != lock[n]["version"]}
        check("security lock and runtime lock agree on every shared package", not shared_drift, str(shared_drift))
    for rel in (".github/workflows/validate.yml", "automation/pipeline/buildspec-validate.yml"):
        text = open(os.path.join(BASE, rel), encoding="utf-8").read()
        check(f"{rel} installs the security tools from requirements-security.lock with hashes",
              "--require-hashes -r requirements-security.lock" in text
              and not re.search(r"pip install[^\n]*\b(bandit|pip-audit)==", text))

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: lock closure ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
