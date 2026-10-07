#!/usr/bin/env python3
"""Class-matrix validation (AUD-F23) and validator report contract (AUD-F24).

The repository ships Class A, B and C artifacts but the authoritative validator
used to run only against the offering profile's class, so the inactive classes
had weaker checks; when first run against Class C, the committed template
failed two MUST-level checks (three populated example KSIs with plain-string
tests and no evidence). This test asserts the override exists and behaves:
SDR_VALIDATE_CLASS=a validates the Class A artifacts, writes its reports under
the gitignored matrix directory, leaves the canonical active-class reports
untouched, and `sdr.py validate` drives the matrix for every inactive class. It
also pins the validator's report shape ("results"), which a parity test once
misread as "ksi_results" and therefore compared 0 against 0.

AUD-F39: the matrix renders ONE record store under every class's rules, so a
content minimum that only a higher class mandates (FRC-CSX-VVK's two automated
methods at Class C; evidence linkage for populated MUST work) must be advisory
in an inactive-class run and hard only at the class the offering submits. The
end-to-end check below proves both halves on the populated Class B sample.

    python validation/scripts/test_validate_class_matrix.py
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
REPORTS = os.path.join(BASE, "validation", "reports")
_fail = 0


def check(name, cond, detail=""):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}" + (f" -- {detail}" if detail else ""))


def _populated_class_b_root():
    """A temp copy of the tree with the Class B sample (Acme: every KSI narrative
    populated, no tests or evidence, exactly a provider mid-way through
    authoring) swapped in, and its Class C artifacts regenerated from that
    store the way `sdr.py build` does for an inactive class."""
    import shutil
    import tempfile
    tmp = tempfile.mkdtemp(prefix="matrix-f39-")
    root = os.path.join(tmp, "repo")
    shutil.copytree(BASE, root, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.log", ".tmp"))
    sample = os.path.join(root, "examples", "sample-offering")
    shutil.copy2(os.path.join(sample, "records-store.sample.json"),
                 os.path.join(root, "sdr", "records", "records-store.json"))
    shutil.copy2(os.path.join(sample, "offering-profile.sample.json"),
                 os.path.join(root, "profiles", "common", "offering-profile.json"))
    scripts = os.path.join(root, "validation", "scripts")
    b = subprocess.run([sys.executable, os.path.join(scripts, "build_sdr.py")], cwd=root,
                       env=dict(os.environ, SDR_BUILD_CLASS="c"), capture_output=True,
                       text=True, timeout=600)
    check("Class C artifacts regenerate from the populated Class B store", b.returncode == 0,
          (b.stdout + b.stderr)[-400:])
    return tmp, root


def test_f39_content_force_binds_at_the_submitted_class():
    """AUD-F39. FRC-CSX-VVK (>= 2 automated methods at Class C, MUST) and the
    evidence-linkage expectation bind the offering at the class it submits. A
    populated Class B offering rendered at Class C by the matrix is short on
    both; that is ADVISORY there (exit 0), because the offering is not
    submitting at Class C. Flip the SAME store to Class C active and the same
    shortfalls are hard failures (exit 1): the relaxation is scoped to the
    inactive-class run, not to the check."""
    import shutil
    tmp, root = _populated_class_b_root()
    try:
        scripts = os.path.join(root, "validation", "scripts")
        prof_path = os.path.join(root, "profiles", "common", "offering-profile.json")
        prof = json.load(open(prof_path, encoding="utf-8"))
        check("fixture is a Class B offering", prof["certification_class"].lower() == "b")
        r = subprocess.run([sys.executable, os.path.join(scripts, "validate_sdr.py")], cwd=root,
                           env=dict(os.environ, SDR_VALIDATE_CLASS="c"), capture_output=True,
                           text=True, timeout=600)
        lines = r.stdout.splitlines()
        check("populated Class B offering validated at inactive Class C exits 0",
              r.returncode == 0, "; ".join(ln for ln in lines if ln.startswith("FAIL:"))[:400])
        check("the VVK minimum shortfall is reported as ADVISORY at the inactive class",
              any(ln.startswith("ADVISORY: ksi_test_minimums") and "populated KSIs short" in ln
                  for ln in lines))
        check("the evidence-linkage gap is reported as ADVISORY at the inactive class",
              any(ln.startswith("ADVISORY: evidence_linkage_for_populated_musts") for ln in lines))
        check("the advisory names the class the offering submits at",
              any("the offering submits at class B" in ln for ln in lines))
        # Same store, Class C active: now it IS the submitted class.
        prof["certification_class"] = "c"
        with open(prof_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(prof, f, indent=1)
        r2 = subprocess.run([sys.executable, os.path.join(scripts, "validate_sdr.py")], cwd=root,
                            capture_output=True, text=True, timeout=600)
        lines2 = r2.stdout.splitlines()
        check("the same store with Class C ACTIVE exits 1", r2.returncode == 1)
        check("the VVK minimum shortfall is a hard FAIL at the active class",
              any(ln.startswith("FAIL: ksi_test_minimums") for ln in lines2))
        check("the evidence-linkage gap is a hard FAIL at the active class",
              any(ln.startswith("FAIL: evidence_linkage_for_populated_musts") for ln in lines2))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    offering = json.load(open(os.path.join(BASE, "profiles", "common", "offering-profile.json"),
                              encoding="utf-8"))
    active = offering["certification_class"].lower()
    inactive = [c for c in ("a", "b", "c") if c != active]
    canon = os.path.join(REPORTS, "validation-report.json")
    canon_before = open(canon, "rb").read() if os.path.exists(canon) else None

    import shutil
    for cls in inactive:
        # Start from nothing: a stale matrix report from an earlier run must not
        # be able to satisfy the checks below (that is how a validator that
        # ignored the override once slipped past this test).
        shutil.rmtree(os.path.join(REPORTS, "matrix", f"class-{cls}"), ignore_errors=True)
        env = dict(os.environ, SDR_VALIDATE_CLASS=cls)
        r = subprocess.run([sys.executable, os.path.join(HERE, "validate_sdr.py")],
                           cwd=BASE, env=env, capture_output=True, text=True, timeout=600)
        fails = [ln for ln in r.stdout.splitlines() if ln.startswith("FAIL:")]
        check(f"class {cls.upper()} artifacts pass the authoritative validator",
              r.returncode == 0, "; ".join(fails[:3]) or r.stderr[-300:])
        rep_path = os.path.join(REPORTS, "matrix", f"class-{cls}", "validation-report.json")
        check(f"class {cls.upper()} report written under the matrix directory",
              os.path.exists(rep_path))
        if os.path.exists(rep_path):
            rep = json.load(open(rep_path, encoding="utf-8"))
            check(f"class {cls.upper()} report is stamped with class {cls.upper()}",
                  rep.get("class") == cls.upper(), str(rep.get("class")))
        res_path = os.path.join(REPORTS, "matrix", f"class-{cls}", "ksi-test-results.json")
        if os.path.exists(res_path):
            res = json.load(open(res_path, encoding="utf-8"))
            # AUD-F24: the per-KSI list lives under "results" and is non-empty.
            check(f"class {cls.upper()} ksi-test-results carries a non-empty 'results' list",
                  isinstance(res.get("results"), list) and len(res["results"]) > 0,
                  f"keys={sorted(res)}")

    canon_after = open(canon, "rb").read() if os.path.exists(canon) else None
    check("canonical active-class report is untouched by matrix runs",
          canon_before == canon_after)

    sdr_src = open(os.path.join(BASE, "sdr.py"), encoding="utf-8").read()
    m = re.search(r"^def cmd_validate\(.*?(?=^def )", sdr_src, re.MULTILINE | re.DOTALL)
    body = m.group(0) if m else ""
    check("sdr.py validate drives the class matrix via SDR_VALIDATE_CLASS",
          "SDR_VALIDATE_CLASS" in body and 'for cls in ("a", "b", "c")' in body)
    gi = open(os.path.join(BASE, ".gitignore"), encoding="utf-8").read()
    check("matrix reports are gitignored", "validation/reports/matrix/" in gi)

    print("AUD-F39: content-force checks bind at the submitted class")
    test_f39_content_force_binds_at_the_submitted_class()

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: class matrix ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
