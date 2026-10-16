#!/usr/bin/env python3
"""MCE-14: docs/quickstart-non-aws.md is executable documentation.

  AC1  every path the quickstart names under automation/ or examples/ exists
       in the repository (the commands run against committed fixtures);
  AC2  every command in a ```bash fence is executed from the repository root
       (the leading `python` replaced by this interpreter) and must exit 0;
       the sample command must report READY; the tree must be clean after
       (the sample restores what it touches), judged by `git diff --exit-code`
       on the tracked files the sample overwrites;
  AC3  the document states that its outputs are expectations and readiness
       findings, never compliance determinations, and names no credential
       (no access-key-looking token, no literal secret value in a fence).

Commands the quickstart shows as `text` fences (environment variables, the
twenty-minute attack run, the editing steps) are deliberately not executed.

Run:
    python validation/scripts/test_quickstart_non_aws.py
"""

import os
import re
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOC = os.path.join(BASE, "docs", "quickstart-non-aws.md")
# What the sample overwrites and must restore (its own BACKED_UP set).
RESTORED = ["sdr/records/records-store.json", "profiles/common/offering-profile.json",
            "sdr/reviews/review-register.json", "validation/reports/validation-report.json",
            "validation/reports/ksi-test-results.json"]

failures = []


def check(name, cond):
    print(("PASS: " if cond else "FAIL: ") + name)
    if not cond:
        failures.append(name)


def fences(text, lang):
    return re.findall(r"```" + lang + r"\n(.*?)```", text, flags=re.DOTALL)


def main():
    text = open(DOC, encoding="utf-8").read()
    bash = fences(text, "bash")
    commands = [ln.strip() for block in bash for ln in block.splitlines()
                if ln.strip() and not ln.strip().startswith("#")]
    check("the quickstart has executable bash fences", len(commands) >= 4)
    check("every executable command is a python invocation (runnable on every platform)",
          all(c.startswith("python ") for c in commands))
    # AC1: named repository paths exist.
    paths = sorted(set(re.findall(r"(?:automation|examples|validation|profiles)/[A-Za-z0-9_./-]+", text)))
    missing = [p for p in paths if not os.path.exists(os.path.join(BASE, p))]
    check(f"every repository path the quickstart names exists ({len(paths)} paths): missing={missing}",
          not missing)
    # AC3: the advisory statement and no credentials.
    flat = " ".join(text.split()).lower()
    check("the quickstart states its outputs are expectations and readiness findings, never compliance "
          "determinations",
          "never a compliance determination" in flat and "readiness finding" in flat)
    fence_text = "\n".join(bash + fences(text, "json") + fences(text, "text") + fences(text, "python"))
    secret_shapes = (r"AKIA[0-9A-Z]{16}|BEGIN (RSA |EC )?PRIVATE KEY|password\s*[:=]\s*\S"
                     r"|token\s*[:=]\s*[A-Za-z0-9]{8,}")
    check("no fence carries an access-key-looking token or a literal secret value",
          re.search(secret_shapes, fence_text) is None)
    check("the scope key is shown as a placeholder for a value private to the deployment, not a value",
          "SDR_EVIDENCE_SCOPE_KEY=<" in text)
    # AC2: execute every bash command from the repository root.
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    for cmd in commands:
        argv = [sys.executable] + cmd.split()[1:]
        r = subprocess.run(argv, cwd=BASE, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", env=env)
        out = (r.stdout or "") + (r.stderr or "")
        check(f"exit 0: {cmd[:110]}", r.returncode == 0)
        if "build_non_aws_class_c_sample.py" in cmd:
            check("the sample reports READY under production-assurance",
                  "package-preflight exit code: 0 (READY)" in out and "production-assurance" in out)
        if "mapping_adapter.py" in cmd:
            check(f"the dry run prints facts and a collected outcome: {cmd.split()[-1].rsplit('/', 1)[-1]}",
                  '"facts"' in out and '"outcome": "collected"' in out)
        if "test_adapter_conformance.py" in cmd:
            check("the conformance suite reports 0 problems", "0 problem(s)" in out)
    r = subprocess.run(["git", "diff", "--exit-code", "--"] + RESTORED, cwd=BASE,
                       capture_output=True, text=True)
    check("the files the sample overwrites are restored byte for byte (tree clean)", r.returncode == 0)
    check("the sample's exports folder did not outlive the run",
          not os.path.isdir(os.path.join(BASE, "examples", "sample-offering-class-c-non-aws", "generated-exports")))
    if failures:
        print(f"\nFAIL: quickstart non-aws ({len(failures)} failure(s))")
        return 1
    print("\nPASS: quickstart non-aws (0 failures)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
