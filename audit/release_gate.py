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
  attack    assessor-attack harness (AUD-F61): the fictional Class C package
            driven to READY, then tampered one hollowing edit at a time; every
            tamper must be BLOCKED, the justified baseline must stay READY;
            working tree clean after the harness restored every file.
  security  Bandit static analysis over all executable Python, medium-or-higher
            severity AND confidence, hard failure on any finding.

The build/validate/reproducibility/preflight steps are not listed here because
`sdr.py release` runs them natively and CI's validate job runs them as explicit
steps; test_release_gate.py asserts both still do.

Results (AUD-F66). Every run writes validation/reports/gate-results.json: the
executed steps as records (gate_id `<section>.<name>`, argv, exit code, status),
the steps a failure stopped, the overall verdict, the active class and dataset
version, and nothing volatile, so identical runs write identical bytes. When
GitHub Actions facts are in the environment a separate gate-results.run.json
envelope records commit, run id, job and time. Both are gitignored run
evidence (CI uploads them per section as artifacts); the exit code remains the
verdict. The gate_id is the id traceability/rule-test-map.json registers.
"""
import json
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
    # AUD-F61: the assessor-attack harness. A fully populated fictional Class C
    # package is driven to READY, then tampered one hollowing edit at a time;
    # every tamper must be BLOCKED and the justified baseline must stay READY.
    # It was a manual run until two of its probes silently stopped testing
    # anything for 18 merged PRs (CHANGELOG, AUD-F57..F60). Its own section
    # (not a step of `audit`) so CI runs it in parallel: ~20 minutes locally.
    "attack": [
        ("class-c-attack-harness",
         [sys.executable,
          "examples/sample-offering-class-c/build_class_c_sample.py", "--attack"]),
        # The harness backs up and restores every file it overwrites (AUD-F36);
        # a dirty tree here means sample residue reached the checkout.
        ("tree-clean-after-attack",
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

SECTION_ORDER = ["audit", "attack", "security"]

# AUD-F66: machine-readable results. The deterministic file carries only what
# the run decided (gate ids, argv, exit codes, statuses, the active class and
# dataset version); the envelope carries the volatile CI facts (commit, run id,
# runner, timestamps) when GitHub Actions provides them. Both are gitignored:
# a gate result is evidence of a run, not a generated deliverable.
RESULTS = os.path.join(BASE, "validation", "reports", "gate-results.json")
RESULTS_ENVELOPE = os.path.join(BASE, "validation", "reports", "gate-results.run.json")
RESULTS_SCHEMA = "fedramp-gate-results/v1"


def run_step(name, argv, cwd=BASE, section=None):
    """Run one step; return its result record. `exit_code` is non-zero on any
    failure, including a tool that cannot be started. The record's gate_id
    (`<section>.<name>`) is the id traceability/rule-test-map.json registers."""
    print(f"--- release-gate step: {name}")
    print("    " + " ".join(argv))
    record = {"gate_id": f"{section}.{name}" if section else name, "section": section,
              "name": name,
              "argv": [("python" if a == sys.executable else a) for a in argv]}
    try:
        r = subprocess.run(argv, cwd=cwd)
        code = r.returncode
    except OSError as e:
        print(f"FAIL release-gate step {name}: cannot run {argv[0]!r}: {e}")
        code = 1
        record["error"] = f"cannot run {argv[0]!r}: {e}"
    if code != 0 and "error" not in record:
        print(f"FAIL release-gate step {name}: exit {code}")
    record["exit_code"] = code
    record["status"] = "PASS" if code == 0 else "FAIL"
    return record


def _step_code(record):
    """Exit code of a run_step record (0 only on PASS)."""
    return record["exit_code"] if isinstance(record, dict) else int(record)


def _offering_facts():
    try:
        with open(os.path.join(BASE, "profiles", "common", "offering-profile.json"),
                  encoding="utf-8") as f:
            prof = json.load(f)
    except (OSError, ValueError):
        return {"certification_class": None, "dataset_version": None}
    return {"certification_class": str(prof.get("certification_class") or "").upper() or None,
            "dataset_version": prof.get("dataset_version")}


def write_results(records, wanted, overall, path=None, envelope_path=None):
    """Write the deterministic results document and, when CI facts exist in
    the environment, the volatile envelope beside it. Never raises on a write
    failure: the gate's verdict is its exit code, the file is evidence of it."""
    path = path or RESULTS
    envelope_path = envelope_path or RESULTS_ENVELOPE
    doc = {"schema": RESULTS_SCHEMA, **_offering_facts(), "sections": list(wanted),
           "overall": overall,
           "gates": [{k: r[k] for k in ("gate_id", "section", "name", "argv", "exit_code", "status")}
                     | ({"error": r["error"]} if "error" in r else {}) for r in records],
           "skipped": [f"{s}.{n}" for s in wanted for n, _ in SECTIONS.get(s, [])
                       if f"{s}.{n}" not in {r["gate_id"] for r in records}]}
    envelope = {k: os.environ.get(v) for k, v in (
        ("commit", "GITHUB_SHA"), ("run_id", "GITHUB_RUN_ID"), ("run_attempt", "GITHUB_RUN_ATTEMPT"),
        ("job", "GITHUB_JOB"), ("workflow", "GITHUB_WORKFLOW"), ("repository", "GITHUB_REPOSITORY"),
        ("ref", "GITHUB_REF"), ("runner_os", "RUNNER_OS"))}
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(doc, f, indent=1)
            f.write("\n")
        if any(envelope.values()):
            import datetime as _dt
            envelope["recorded_at"] = _dt.datetime.now(_dt.timezone.utc).isoformat()
            envelope["results_file"] = os.path.relpath(path, BASE)
            with open(envelope_path, "w", encoding="utf-8", newline="\n") as f:
                json.dump(envelope, f, indent=1)
                f.write("\n")
    except OSError as e:
        print(f"WARN release-gate: could not write {path}: {e}")
    return doc


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
    records = []
    for section in wanted:
        print(f"=== release-gate section: {section}")
        for name, argv in SECTIONS[section]:
            record = run_step(name, argv, cwd=cwd, section=section)
            records.append(record)
            if _step_code(record) != 0:
                failed.append(f"{section}/{name}")
                # Stop within the section: later steps assume earlier ones held
                # (e.g. tree-clean assumes the runner ran to completion).
                break
    overall = "FAIL" if failed else "PASS"
    write_results(records, wanted, overall)
    if failed:
        print("\nrelease-gate: FAIL -- " + ", ".join(failed))
        return 1
    print("\nrelease-gate: PASS -- " + ", ".join(wanted))
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:] or None))
