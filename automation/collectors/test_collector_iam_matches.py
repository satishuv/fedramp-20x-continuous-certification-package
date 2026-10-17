#!/usr/bin/env python3
"""Collector IAM parity test.

The scheduled collector pipeline (automation/pipeline/sdr-pipeline.yaml) deploys
a CollectorRole. That role's granted actions MUST be a superset of the actions
the collectors actually call (automation/collectors/collectors.py
READ_ONLY_ACTIONS); otherwise a deployed collector produces AccessDenied for
everything the grant omits. This test fails if the collector adds an API call
that the deployed role does not grant.

    python automation/collectors/test_collector_iam_matches.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)

import collectors  # noqa: E402

PIPELINE = os.path.join(BASE, "automation", "pipeline", "sdr-pipeline.yaml")


def _collector_role_block():
    """Return the text of ONLY the CollectorRole resource block, from its
    'CollectorRole:' header to the next top-level (2-space-indented) resource.
    Parsing the whole file would let CollectorRole appear to inherit actions
    that are actually granted to CodeBuildRole or the pipeline role - which is
    exactly the bug that hid the missing first-run s3:ListBucket grant."""
    lines = open(PIPELINE, encoding="utf-8").read().splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.rstrip() == "  CollectorRole:":
            start = i
            break
    if start is None:
        raise AssertionError("CollectorRole not found in the pipeline template")
    block = [lines[start]]
    for line in lines[start + 1:]:
        # A new top-level resource is a 2-space-indented 'Name:' line.
        import re as _re
        if _re.match(r"^  [A-Za-z][A-Za-z0-9]*:\s*$", line):
            break
        block.append(line)
    return "\n".join(block)


def granted_collector_actions():
    """Extract the IAM actions the CollectorRole grants, scoped to that role's
    block ONLY (not the whole file)."""
    import re
    # AUD-F83: IAM prefixes may carry a hyphen (access-analyzer); the earlier
    # [a-z0-9]+ silently dropped such grants from the comparison.
    action_re = re.compile(r"^\s*-\s+([a-z0-9-]+:[A-Za-z0-9*]+)\s*$")
    actions = set()
    for line in _collector_role_block().splitlines():
        m = action_re.match(line)
        if m:
            actions.add(m.group(1))
    return actions


def main():
    needed = set(collectors.READ_ONLY_ACTIONS)
    granted = granted_collector_actions()
    missing = sorted(needed - granted)
    passed = failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1; print(f"  PASS {name}")
        else:
            failed += 1; print(f"  FAIL {name}")

    check("the pipeline grants a non-trivial set of collector actions",
          len(granted) >= len(needed))
    check("every collector READ_ONLY_ACTION is granted by the deployed role",
          not missing)
    if missing:
        print(f"    missing grants: {missing}")

    # First-run metric-history restore: CollectorRole MUST have bucket-level
    # s3:ListBucket so a missing metric-history.json returns 404 (not 403), or
    # the fail-closed restore aborts the first legitimate collection. This is
    # asserted against the CollectorRole block ONLY - the grant on CodeBuildRole
    # does not help the collector, which runs as CollectorRole.
    check("CollectorRole grants bucket-level s3:ListBucket (first-run 404 not 403)",
          "s3:ListBucket" in granted)

    print(f"\n{passed}/{passed + failed} collector IAM parity checks passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
