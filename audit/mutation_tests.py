#!/usr/bin/env python3
"""Mutation tests -- the anti-circular-verification gate (HARD-MODE protocol).

A passing regression test proves nothing if the test cannot actually detect the
defect it claims to guard. This runner RE-INTRODUCES each closed defect into the
PRODUCTION code by textual patch, runs the named regression test, and asserts the
test goes RED. If a mutation SURVIVES (test still green), that is a test-coverage
defect and this runner exits non-zero.

Every mutation restores the file afterward via `git checkout --`, so the tree is
left clean.

    python audit/mutation_tests.py

A mutation whose target text is not present on this commit is reported SKIP and
SKIP FAILS THE GATE (AUD-F13). The earlier behaviour let a skip pass, which meant
a harmless refactor that changed the target text silently switched off the
protection for a closed defect while the ledger still said mutation_verified. A
skip now has exactly two honest resolutions: retarget the mutation to the
refactored code, or (if the defect is on an unmerged branch) run the gate on that
branch. The runner also cross-checks the defect ledger: every CLOSED,
mutation_verified defect must map to exactly one runner entry, every runner
entry must map to such a defect, and each must be KILLED, or the gate fails.

Bytecode cache. Python validates a cached `__pycache__/*.pyc` by source SIZE and
source mtime in WHOLE SECONDS only. A mutation whose replacement has the same
length as the text it replaces (MUT-F10 is exactly 50 -> 50 characters) leaves
the size unchanged, so if an earlier step compiled the ORIGINAL module and the
mutated file lands in the same wall-clock second, the interpreter loads the
original bytecode and the regression "passes" against unmutated code. That is a
false SURVIVED that has nothing to do with the test. CI hit it on main twice
(validate-sdr run 35993242564). The runner therefore purges every __pycache__
before each mutated test run and forbids pyc writes during it
(PYTHONDONTWRITEBYTECODE), so a test can only ever exercise the source on disk.
`-B` alone is NOT enough: it stops writing pycs but still READS a stale one.
"""
import json
import os
import shutil
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def _write(p, s):
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)


def _read_bytes(p):
    with open(p, "rb") as f:
        return f.read()


def _restore(rel, original_bytes=None):
    """Put the pre-mutation source back. The saved original bytes are the
    authoritative restore: writing them back returns the file to EXACTLY what it
    was, committed or not. `git checkout --` is only the fallback when no bytes
    were saved or the write-back somehow did not take: on a tree with
    uncommitted edits (a developer running the self-test locally) a blind
    checkout would replace those edits with HEAD, which is data loss, not a
    restore. Verify loudly either way."""
    path = os.path.join(BASE, rel)
    if original_bytes is not None:
        with open(path, "wb") as f:
            f.write(original_bytes)
        if _read_bytes(path) == original_bytes:
            return
    subprocess.run(["git", "checkout", "--", rel], cwd=BASE,
                   capture_output=True, text=True)
    if original_bytes is not None and _read_bytes(path) != original_bytes:
        raise RuntimeError(f"restore of {rel} failed: working tree still differs "
                           "from the saved original")


def _purge_bytecode(root=BASE):
    """Remove every __pycache__ under root so no cached bytecode can stand in
    for the source on disk. .git is skipped; nothing there is ours to touch."""
    for dirpath, dirnames, _files in os.walk(root):
        if ".git" in dirnames:
            dirnames.remove(".git")
        if "__pycache__" in dirnames:
            shutil.rmtree(os.path.join(dirpath, "__pycache__"), ignore_errors=True)
            dirnames.remove("__pycache__")


def _no_bytecode_env():
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


MUTATIONS = [
    ("MUT-F04",
     "automation/metrics/append_metrics.py",
     'scope = (rule, fact.get("region"), fact.get("account"))',
     'scope = (rule,)  # MUTATION',
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F01",
     "validation/scripts/validate_evidence.py",
     "    signer_required = bool(trusted_signer",
     "    source, kind = _resolve_source(e)\n    if source is None:\n        return ('finding', 'MUT unverifiable')\n    signer_required = bool(trusted_signer",
     "validation/scripts/test_evidence_integrity.py"),
    ("MUT-F06",
     "sdr.py",
     "    gappy = (largest > max_gap_days or trailing > max_gap_days\n             or leading > max_gap_days)",
     "    gappy = (largest > max_gap_days or trailing > max_gap_days)  # MUTATION",
     "validation/scripts/test_mot_continuity.py"),
    ("MUT-F05",
     "automation/metrics/append_metrics.py",
     "                          today, cls, require_fresh=True, min_coverage=min_cov)",
     "                          today, cls, require_fresh=False, min_coverage=min_cov)  # MUTATION",
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F07",
     "automation/metrics/append_metrics.py",
     '    except ValueError as e:\n        return {}, f"metric history is not valid JSON: {e}"',
     '    except ValueError as e:\n        return {}, None  # MUTATION',
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F02",
     "validation/scripts/verification_methods.py",
     "            if not ident:\n                # F02: an automated method with no method_id is uncountable and\n                # unbindable; surface it informationally, do not count it.\n                strings += 1\n                continue",
     "            if not ident:\n                seen.add(str(id(t)))  # MUTATION count id-less automated\n                continue",
     "validation/scripts/test_vvk_automated_methods.py"),
    ("MUT-F03",
     "automation/metrics/append_metrics.py",
     '            if check_filter and pf.get("check") != check_filter:\n                continue  # F03: check-scoped key rejects other checks',
     '            if False:  # MUTATION drop check filter\n                continue',
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F08",
     "automation/collectors/collectors.py",
     '            if "ServerSideEncryptionConfigurationNotFound" in name:\n                checked += 1  # evaluated: no encryption configured\n            else:\n                unmeasured += 1',
     '            checked += 1  # MUTATION count any error as evaluated\n            if False:\n                unmeasured += 1',
     "automation/collectors/test_collectors.py"),
    ("MUT-F09",
     "automation/collectors/collectors.py",
     '        if more:\n            # Bounded sample: report the enabling signal WITHOUT a full-coverage',
     '        if False:  # MUTATION ignore bounded-sample partial\n            # Bounded sample: report the enabling signal WITHOUT a full-coverage',
     "automation/collectors/test_collectors.py"),
    ("MUT-F10",
     "sdr.py",
     "    return _d.datetime.now(_d.timezone.utc).date()",
     "    return _d.date.today()  # MUTATION local clock",
     "validation/scripts/test_utc_clock.py"),
    ("MUT-F11",
     "validation/scripts/build_sdr.py",
     "    _u = _utc_today()\n    cutoff = (_u - _dd.timedelta(days=365)).isoformat()\n    _today = _u.isoformat()",
     "    cutoff = (_dd.date.today() - _dd.timedelta(days=365)).isoformat()  # MUTATION local clock\n    _today = _dd.date.today().isoformat()",
     "validation/scripts/test_build_sdr_utc_window.py"),
    ("MUT-F12",
     "audit/release_gate.py",
     '        ("mutation-runner",\n         [sys.executable, "audit/mutation_tests.py"]),\n',
     '        # MUTATION: mutation runner dropped from the release gate\n',
     "automation/pipeline/test_release_gate.py"),
    ("MUT-F13",
     "audit/mutation_tests.py",
     "    if skipped:\n        # AUD-F13",
     "    if False:  # MUTATION skips pass\n        # AUD-F13",
     "audit/test_mutation_runner.py"),
    ("MUT-F14",
     "audit/mutation_tests.py",
     "    problems = []\n    runner_ids = [m[0] for m in mutations]",
     "    return []  # MUTATION ledger never reconciled\n    runner_ids = [m[0] for m in mutations]",
     "audit/test_mutation_runner.py"),
    ("MUT-F15",
     "automation/collectors/collectors.py",
     "        if token is None:\n            return items, False\n        params[param] = token",
     "        return items, False  # MUTATION first page only\n        params[param] = token",
     "automation/collectors/test_collectors.py"),
    ("MUT-F16",
     "automation/metrics/append_metrics.py",
     "        if not check:\n            raise ValueError(",
     "        if False:  # MUTATION accept bare service routes\n            raise ValueError(",
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F17",
     "automation/metrics/append_metrics.py",
     "            if scope > 0 and (evaluated / scope) < min_coverage:\n                return None",
     "            if False:  # MUTATION ignore evaluated coverage\n                return None",
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F18",
     "automation/prefill/prefill_from_facts.py",
     '                "method_id": posture_method_id(pf["service"], pf["check"]),',
     '                "method_id": f"{pf[\'service\']}-collector",  # MUTATION own id scheme',
     "automation/prefill/test_binding_e2e.py"),
    ("MUT-F19",
     "automation/metrics/append_metrics.py",
     '    existing = next((p for p in series if p["date"] == date_str), None)',
     '    existing = None  # MUTATION same-day point replaces earlier run',
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F20",
     "automation/metrics/publish_history.py",
     '    if etag:\n        params["IfMatch"] = etag\n    else:\n        params["IfNoneMatch"] = "*"',
     '    if False:  # MUTATION unconditional overwrite\n        params["IfMatch"] = etag',
     "automation/metrics/test_publish_history.py"),
    ("MUT-F21",
     "sdr.py",
     "    if not 1 <= days <= MOT_MAX_GAP_DAYS_CEILING:\n        return None,",
     "    if False:  # MUTATION any tolerance accepted\n        return None,",
     "validation/scripts/test_mot_continuity.py"),
    ("MUT-F22",
     "audit/requirements_oracle.py",
     "            if expected[rid].get(field) != actual[rid].get(field):",
     "            if False:  # MUTATION field differences ignored",
     "audit/test_requirements_oracle.py"),
    ("MUT-F23",
     "validation/scripts/validate_sdr.py",
     '    cls = (os.environ.get("SDR_VALIDATE_CLASS") or active_cls).lower()',
     '    cls = active_cls  # MUTATION always the active class',
     "validation/scripts/test_validate_class_matrix.py"),
    ("MUT-F24",
     "validation/scripts/validate_sdr.py",
     '        json.dump({"generated": stamp, "class": cls.upper(), "results": ksi_results}, f, indent=1)',
     '        json.dump({"generated": stamp, "class": cls.upper(), "ksi_results": ksi_results}, f, indent=1)  # MUTATION',
     "validation/scripts/test_assurance_graph_method_count.py"),
    ("MUT-F25",
     "validation/scripts/build_sbom.py",
     "    lock = _parse_lock(LOCK)",
     "    lock = None  # MUTATION ignore the committed lock",
     "validation/scripts/test_lock_closure.py"),
    ("MUT-F26",
     "automation/collectors/evidence_wiring.py",
     '    evidence["xEvidenceContentHash"] = evidence_hash(canonical_payload(evidence))',
     '    evidence["xEvidenceContentHash"] = evidence_hash(evidence["xSourceFact"])  # MUTATION unbound digest',
     "validation/scripts/test_evidence_integrity.py"),
    ("MUT-F27",
     "automation/collectors/evidence_wiring.py",
     "    parts = [service, check]\n    if scope:\n        parts.append(scope)",
     "    parts = [service, check]\n    if False:  # MUTATION scope dropped from the pointer\n        parts.append(scope)",
     "automation/collectors/test_evidence_wiring.py"),
    ("MUT-F28",
     "automation/collectors/evidence_wiring.py",
     '        out["summary"] = scrub_text(detail, SUMMARY_MAX)',
     '        out["summary"] = detail[:SUMMARY_MAX]  # MUTATION verbatim detail',
     "automation/collectors/test_evidence_wiring.py"),
]


def run_one(mid, rel, find, repl, test):
    """Apply one mutation, run its regression test against the source on disk,
    restore. Returns 'killed', 'survived' or 'skipped'."""
    path = os.path.join(BASE, rel)
    original_bytes = _read_bytes(path)
    src = _read(path)
    if find not in src:
        print(f"SKIP {mid}: target code not present on this commit")
        return "skipped"
    _write(path, src.replace(find, repl, 1))
    try:
        # No cached bytecode may answer for the mutated source (see module doc).
        _purge_bytecode()
        r = subprocess.run([sys.executable, test], cwd=BASE, env=_no_bytecode_env(),
                           capture_output=True, text=True, timeout=1800)
    finally:
        _restore(rel, original_bytes)
        _purge_bytecode()
    if r.returncode != 0:
        print(f"KILLED {mid}: mutation detected (test red, rc={r.returncode})")
        return "killed"
    print(f"SURVIVED {mid}: NOT DETECTED -- test-coverage DEFECT")
    return "survived"


LEDGER = os.path.join(BASE, "audit", "defect-ledger.json")


def _ledger_mutation_ids(ledger):
    """Return {mutation_id: defect_id} for every CLOSED defect the ledger claims
    is mutation_verified. The ledger's `mutation` field is free text that starts
    with the runner id ("MUT-F04: scope key -> ..."); the id is the first token
    up to the colon. A CLOSED + mutation_verified defect with no parseable id is
    itself a ledger defect and is reported under the empty id."""
    out = {}
    for d in (ledger or {}).get("defects", []):
        if d.get("status") != "CLOSED" or d.get("mutation_verified") is not True:
            continue
        text = str(d.get("mutation") or "")
        mid = text.split(":", 1)[0].strip()
        if not mid.startswith("MUT-"):
            mid = ""
        out.setdefault(mid, []).append(d.get("id"))
    return out


def reconcile_ledger(outcomes, mutations=None, ledger=None):
    """Cross-check the ledger against what the runner actually executed.

    outcomes: {mutation_id: 'killed'|'survived'|'skipped'} from this run.
    Returns a list of problem strings; empty means the ledger and the runner
    agree and every claimed mutation was executed and killed. The invariant:
    CLOSED + mutation_verified  <=>  exactly one runner entry, executed, KILLED.
    """
    mutations = MUTATIONS if mutations is None else mutations
    if ledger is None:
        with open(LEDGER, encoding="utf-8") as f:
            ledger = json.load(f)
    problems = []
    runner_ids = [m[0] for m in mutations]
    counts = {}
    for mid in runner_ids:
        counts[mid] = counts.get(mid, 0) + 1
    for mid, n in counts.items():
        if n > 1:
            problems.append(f"{mid}: {n} runner entries share one id (must be exactly one)")
    claimed = _ledger_mutation_ids(ledger)
    for mid, defect_ids in sorted(claimed.items()):
        if not mid:
            problems.append(f"{defect_ids}: CLOSED + mutation_verified but no MUT- id in "
                            "the `mutation` field")
            continue
        if mid not in counts:
            problems.append(f"{mid}: ledger says mutation_verified for {defect_ids} but the "
                            "runner has no such mutation (false claim)")
            continue
        outcome = outcomes.get(mid)
        if outcome != "killed":
            problems.append(f"{mid}: ledger says mutation_verified for {defect_ids} but this "
                            f"run's outcome was {outcome!r} (must be 'killed')")
    for mid in counts:
        if mid not in claimed:
            problems.append(f"{mid}: runner entry has no CLOSED + mutation_verified ledger "
                            "defect (unledgered mutation)")
    return problems


def gate_verdict(survived, skipped, problems):
    """The gate's exit code from the three failure classes. Pure, so each rule
    is testable on its own: survivors fail (coverage hole), skips fail
    (AUD-F13: the mutation did not run), ledger problems fail (AUD-F14)."""
    rc = 0
    if survived:
        print("FAIL: surviving mutations mean the regression tests are insufficient.")
        rc = 1
    if skipped:
        # AUD-F13: a skip is a mutation that did NOT run. Passing here would let
        # a refactor silently disarm a closed defect's protection.
        print("FAIL: skipped mutations did not execute: " + ", ".join(skipped)
              + ". Retarget them to the current code (or run on the branch that "
                "carries the defect fix).")
        rc = 1
    if problems:
        print("FAIL: defect ledger and mutation runner disagree:")
        for p in problems:
            print("  - " + p)
        rc = 1
    return rc


def run(mutations=None, ledger=None):
    mutations = MUTATIONS if mutations is None else mutations
    survived, killed, skipped = [], [], []
    outcomes = {}
    for mid, rel, find, repl, test in mutations:
        outcome = run_one(mid, rel, find, repl, test)
        outcomes[mid] = outcome
        {"killed": killed, "survived": survived, "skipped": skipped}[outcome].append(mid)
    print("\n--- mutation summary ---")
    print(f"killed={len(killed)} survived={len(survived)} skipped={len(skipped)}")
    problems = reconcile_ledger(outcomes, mutations=mutations, ledger=ledger)
    rc = gate_verdict(survived, skipped, problems)
    if rc == 0:
        print("All mutations executed and detected; ledger reconciled.")
    return rc


if __name__ == "__main__":
    sys.exit(run())
