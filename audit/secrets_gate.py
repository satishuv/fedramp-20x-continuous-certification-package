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
    if os.name == "nt":
        # detect-secrets 1.5 compares baseline entries by filename and loads
        # baseline keys through os.path, so on Windows every POSIX-keyed entry
        # reads as a new finding. The gate's verdict is CI's (Linux); a
        # Windows developer gets the same scan, reported, with the mismatch
        # named, rather than a false FAIL or a silent skip.
        print("NOTE: detect-secrets baseline matching is path-separator sensitive; on Windows "
              "every audited entry re-reports. The authoritative run is CI on Linux. Run under WSL "
              "for a faithful local verdict.")
    if not files:
        print("FAIL: git ls-files returned nothing; refusing to pass an empty scan.")
        return 1
    # The exclude pattern lives IN the baseline (filters_used); passing it on
    # the command line as well makes detect-secrets treat the baseline as
    # mismatched and re-raise every entry.
    argv = [sys.executable, "-m", "detect_secrets.pre_commit_hook", "--baseline", BASELINE] + files
    r = subprocess.run(argv, cwd=BASE, capture_output=True, text=True, encoding="utf-8")  # nosec B603 - fixed interpreter and module, file list from git
    out = (r.stdout or "") + (r.stderr or "")
    sys.stdout.write(out)
    # The hook exits 1 for two different reasons: a finding ("Potential secrets
    # about to be committed"), which is the gate's failure, and housekeeping
    # ("The baseline file was updated": it refreshed line numbers or plugin
    # metadata and wants the file re-added). Housekeeping is not a finding; the
    # gate reports it and passes, and restores the committed baseline so the
    # tree-clean step is not tripped by the hook's rewrite.
    found = "Potential secrets about to be committed" in out
    if found:
        print("FAIL: detect-secrets found a secret not in the audited baseline (or an entry marked real). "
              "If it is a false positive, run `detect-secrets audit .secrets.baseline`, state the reason, "
              "and commit the baseline; never add a real secret to the baseline.")
        return 1
    if "baseline file was updated" in out:
        subprocess.run(["git", "checkout", "--", ".secrets.baseline"], cwd=BASE)  # nosec B603 B607 - fixed git argv
        print("NOTE: the hook refreshed baseline metadata (line numbers or plugin versions); no finding. "
              "The committed baseline is restored; run `detect-secrets scan --baseline .secrets.baseline` "
              "locally to refresh it when convenient.")
    print(f"PASS: secret scan over {len(files)} tracked files; no finding outside the audited baseline.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
