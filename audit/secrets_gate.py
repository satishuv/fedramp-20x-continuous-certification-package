#!/usr/bin/env python3
"""Secret scan gate: detect-secrets-hook over every git-tracked file against the
audited baseline (.secrets.baseline).

Fails on a NEW secret, on a baseline entry a human marked as real, or on an
entry nobody audited. Every current baseline entry is audited false-positive
with a stated reason (sha256 digests, redaction fixtures, the word "secret" in
AWS Config rule names); re-audit with `detect-secrets audit .secrets.baseline`
after a new finding. Lock files and the SBOM are excluded: they are hashes by
construction and are covered by sources_lock_consistency and the SBOM test.

Run: python audit/secrets_gate.py
"""
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASELINE = os.path.join(BASE, ".secrets.baseline")
EXCLUDE = (r"\.lock$|requirements.*\.lock|sbom\.cdx\.json|\.git/|\.venv-checkov/|"
           r"__pycache__/|\.secrets\.baseline")


def main():
    if not os.path.isfile(BASELINE):
        print("FAIL: .secrets.baseline is missing; the secret gate cannot run without its audited baseline.")
        return 1
    files = subprocess.run(["git", "ls-files", "-z"], cwd=BASE, capture_output=True, text=True,  # nosec B603 B607 - fixed git argv
                           encoding="utf-8").stdout.split("\0")
    files = [f for f in files if f]
    if not files:
        print("FAIL: git ls-files returned nothing; refusing to pass an empty scan.")
        return 1
    argv = [sys.executable, "-m", "detect_secrets.pre_commit_hook", "--baseline", BASELINE,
            "--exclude-files", EXCLUDE] + files
    r = subprocess.run(argv, cwd=BASE)  # nosec B603 - fixed interpreter and module, file list from git
    if r.returncode == 0:
        print(f"PASS: secret scan over {len(files)} tracked files; no finding outside the audited baseline.")
    else:
        print("FAIL: detect-secrets found a secret not in the audited baseline (or an entry marked real). "
              "If it is a false positive, run `detect-secrets audit .secrets.baseline`, state the reason, "
              "and commit the baseline; never add a real secret to the baseline.")
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
