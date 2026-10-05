#!/usr/bin/env python3
"""The ONE release gate (audit finding AUD-F12).

Before this module existed there were three different definitions of
"release-ready": the GitHub Actions `validate` job (the only REQUIRED status
check on main), the separate `audit-gate` and `security-scan` jobs (advisory in
practice, because a red one did not block a merge), the AWS CodeBuild
RELEASE_MODE path (ran the mutation runner and oracle but not Bandit), and
`python sdr.py release` (ran neither the audit gate nor Bandit). v1.4.0 was
published from a commit whose audit-gate was red. That is exactly the failure a
single gate definition prevents.

Every release path now executes THIS list. GitHub Actions runs the sections as
separate jobs for parallelism and then requires ONE aggregate job (release-gate)
that succeeds only when every section succeeded; the AWS RELEASE_MODE build and
`sdr.py release` run every section in-process. A step is a subprocess with an
explicit argv, run from the repository root, and the gate FAILS CLOSED on any
non-zero exit, on a missing tool, or on a section name it does not know.

    python audit/release_gate.py                 # every section
    python audit/release_gate.py audit           # one section
    python audit/release_gate.py audit security  # several

Sections
  audit     requirements-differential oracle; mutation-runner self-test; the
            mutation runner (every ledgered defect re-introduced and killed);
            working tree clean after the runner restored every mutation.
  security  Bandit static analysis over all executable Python, medium-or-higher
            severity AND confidence, hard failure on any finding.

The build/validate/reproducibility/preflight steps are not listed here because
`sdr.py release` runs them natively and CI's validate job runs them as explicit
steps; test_release_gate.py asserts both still do.
"""
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BANDIT_REPORT = "bandit-report.txt"  # gitignored; CI uploads it as an artifact

# Ordered (step name, argv). argv is relative to the repository root.
SECTIONS = {
    "audit": [
        ("requirements-oracle-selftest",
         [sys.executable, "audit/test_requirements_oracle.py"]),
        ("requirements-oracle",
         [sys.executable, "audit/requirements_oracle.py"]),
        ("mutation-runner-selftest",
         [sys.executable, "audit/test_mutation_runner.py"]),
        ("mutation-runner",
         [sys.executable, "audit/mutation_tests.py"]),
        # The runner restores every mutated file; a dirty tree here means a
        # mutation was left in place and nothing downstream may trust the tree.
        ("tree-clean-after-mutation",
         ["git", "diff", "--exit-code"]),
    ],
    "security": [
        ("bandit",
         [sys.executable, "-m", "bandit", "-r", ".",
          "--exclude", "./automation/collectors/testdata,./.git",
          "--skip", "B101",
          "--severity-level", "medium", "--confidence-level", "medium",
          "--format", "txt", "--output", BANDIT_REPORT]),
        # AUD-F34: known-vulnerability audit of the EXACT hash-locked closure
        # the gates install (requirements.lock, every transitive pin). A hit is
        # a hard failure: bump the pin, re-lock (make lock) and re-run. Without
        # this the lock proved integrity (the bytes are what we pinned) but
        # nothing proved the pinned bytes were free of published advisories;
        # the first run of this step found 14 advisories across two pins.
        ("pip-audit",
         [sys.executable, "-m", "pip_audit", "-r", "requirements.lock",
          "--require-hashes", "--strict", "--progress-spinner", "off"]),
    ],
}

# Tools the security section needs beyond the runtime closure, pinned so every
# path installs the same auditor (CI workflow, AWS buildspec, local release).
SECURITY_TOOL_PINS = {"bandit": "1.8.6", "pip-audit": "2.10.1"}

SECTION_ORDER = ["audit", "security"]


def run_step(name, argv, cwd=BASE):
    """Run one step; return its exit code (non-zero on any failure, including a
    tool that cannot be started)."""
    print(f"--- release-gate step: {name}")
    print("    " + " ".join(argv))
    try:
        r = subprocess.run(argv, cwd=cwd)
    except OSError as e:
        print(f"FAIL release-gate step {name}: cannot run {argv[0]!r}: {e}")
        return 1
    if r.returncode != 0:
        print(f"FAIL release-gate step {name}: exit {r.returncode}")
    return r.returncode


def run(sections=None, cwd=BASE):
    """Run the named sections (default: all, in SECTION_ORDER). Returns 0 only
    when every step of every requested section exited 0. Unknown section names
    fail closed: a typo must never silently run nothing and pass."""
    wanted = list(sections) if sections else list(SECTION_ORDER)
    unknown = [s for s in wanted if s not in SECTIONS]
    if unknown:
        print(f"FAIL release-gate: unknown section(s) {unknown}; "
              f"known: {SECTION_ORDER}")
        return 2
    failed = []
    for section in wanted:
        print(f"=== release-gate section: {section}")
        for name, argv in SECTIONS[section]:
            if run_step(name, argv, cwd=cwd) != 0:
                failed.append(f"{section}/{name}")
                # Stop within the section: later steps assume earlier ones held
                # (e.g. tree-clean assumes the runner ran to completion).
                break
    if failed:
        print("\nrelease-gate: FAIL -- " + ", ".join(failed))
        return 1
    print("\nrelease-gate: PASS -- " + ", ".join(wanted))
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:] or None))
