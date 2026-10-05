#!/usr/bin/env python3
"""Regenerate the INACTIVE certification classes' SDR outputs.

The repository commits Class A, B and C artifacts, but `build_sdr.py` and
`build_docx.py` regenerate only the class the offering profile selects. Before
this step existed, the CI workflow looped over the inactive classes itself (JSON
and text only), the AWS buildspec did not, and nobody regenerated the inactive
Word documents at all. That is how a fictional sample offering stayed inside
the committed Class C .docx (409 occurrences) after the sample builder restored
every other artifact (AUD-F36), and why the Class A/C .docx could never be
covered by the regenerate-and-diff gate.

Runs as a step of `python sdr.py build`, BEFORE the active class is built, so
the active class is always built last (the release manifest and the
records-store backfill must reflect it). Honours nothing from the environment:
SDR_BUILD_CLASS is set per inactive class here and never leaks.

    python validation/scripts/build_inactive_classes.py
"""

import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPTS = os.path.join(BASE, "validation", "scripts")
OFFERING = os.path.join(BASE, "profiles", "common", "offering-profile.json")

CLASSES = ("a", "b", "c")
# Per inactive class, in order: the JSON/text record, then the Word document.
PER_CLASS_STEPS = ("build_sdr.py", "build_docx.py")


def active_class():
    with open(OFFERING, encoding="utf-8") as f:
        return (json.load(f).get("certification_class") or "b").lower()


def inactive_classes(active):
    return [c for c in CLASSES if c != active]


def main():
    active = active_class()
    if active not in CLASSES:
        print(f"Active class {active!r} is not A/B/C; nothing to regenerate.")
        return 0
    for cls in inactive_classes(active):
        env = dict(os.environ, SDR_BUILD_CLASS=cls)
        for script in PER_CLASS_STEPS:
            r = subprocess.run([sys.executable, os.path.join(SCRIPTS, script)],
                               cwd=BASE, env=env, capture_output=True, text=True)
            if r.returncode != 0:
                sys.stdout.write(r.stdout)
                sys.stderr.write(r.stderr)
                print(f"FAIL. {script} for inactive Class {cls.upper()} exited {r.returncode}.")
                return 1
        print(f"Class {cls.upper()} (inactive): SDR JSON, text and Word document regenerated.")
    print(f"Inactive classes regenerated; active Class {active.upper()} builds next.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
