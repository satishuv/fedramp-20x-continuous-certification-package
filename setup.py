#!/usr/bin/env python3
"""One-command onboarding for the FedRAMP 20x SDR framework.

Turns first-run setup from a multi-step checklist facing a blank template into a
single command that ends with a validated, and optionally pre-filled, record.

What it does, in order:
  1. Check Python and install the Python dependencies the pipeline needs.
  2. Ask once for the certification class (A, B, or C) and set it in the
     offering profile, preserving every other field.
  3. Ask once for an optional ReadOnly AWS profile. If given, run the read-only
     collectors, append today's metric datapoint, and produce a pre-fill diff so
     the record starts populated from telemetry instead of blank. If not given,
     skip cleanly: the framework still builds as a template.
  4. Build every deliverable, run the validate gate, and print the readiness
     summary.

Nothing here crosses the trust boundary: collection is read-only, pre-fill is a
reviewable proposal, and no status is ever set. Non-interactive use is supported
with flags so continuous integration or a scripted setup does not hang on a
prompt.

Usage:
  python setup.py                        # interactive
  python setup.py --class C --profile ro # non-interactive, with collection
  python setup.py --class B --no-collect # non-interactive, template only
"""

import argparse
import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
OFFERING = os.path.join(BASE, "profiles", "common", "offering-profile.json")
DEPS = ["jsonschema", "referencing", "python-docx", "cryptography", "PyYAML"]
VALID_CLASSES = {"A", "B", "C"}


def out(line=""):
    print(line, flush=True)


def run(args, label):
    out(f"  running: {label}")
    code = subprocess.run([sys.executable] + args, cwd=BASE).returncode
    if code != 0:
        out(f"  WARNING: {label} exited {code}")
    return code


def install_deps():
    out("[1/4] Python dependencies")
    if sys.version_info < (3, 10):
        out(f"  FAIL: Python 3.10+ required; this is {sys.version.split()[0]}.")
        return False
    missing = []
    for mod in ("jsonschema", "referencing", "docx", "cryptography", "yaml"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if not missing:
        out("  all present.")
        return True
    out("  installing from requirements.txt (pinned)")
    req = os.path.join(BASE, "requirements.txt")
    code = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--quiet", "-r", req]).returncode
    if code != 0:
        out("  FAIL: could not install dependencies. Install them by hand:")
        out("    python -m pip install -r requirements.txt")
        return False
    return True


def set_class(cls, interactive):
    out("[2/4] Certification class")
    if cls is None and interactive:
        cls = input("  Which certification class? [A/B/C] (default B): ").strip().upper() or "B"
    cls = (cls or "B").upper()
    if cls not in VALID_CLASSES:
        out(f"  '{cls}' is not A, B, or C. Class D is a future readiness "
            "register, not a buildable class. Defaulting to B.")
        cls = "B"
    with open(OFFERING, encoding="utf-8") as f:
        profile = json.load(f)
    if profile.get("certification_class") != cls:
        profile["certification_class"] = cls
        with open(OFFERING, "w", encoding="utf-8", newline="\n") as f:
            json.dump(profile, f, indent=2)
        out(f"  set certification_class to {cls} (other fields untouched).")
    else:
        out(f"  already {cls}.")
    return cls


def collect(profile, region, interactive, no_collect):
    out("[3/4] Read-only collection and pre-fill (optional)")
    if no_collect:
        out("  skipped (--no-collect). The framework builds as a template.")
        return
    if profile is None and interactive:
        ans = input("  ReadOnly AWS profile to collect facts from "
                    "(blank to skip): ").strip()
        profile = ans or None
    if profile is None:
        out("  no AWS profile given; skipping collection. The record stays a "
            "template you fill by hand, which is a valid path.")
        return
    try:
        import boto3  # noqa: F401
    except ImportError:
        out("  boto3 not installed; skipping collection. To collect: "
            "pip install boto3, then re-run.")
        return
    args = ["automation/collectors/collect_facts.py", "--profile", profile]
    if region:
        args += ["--region", region]
    if run(args, "collect_facts.py") != 0:
        out("  collection did not complete; continuing to build as a template.")
        return
    run(["automation/metrics/append_metrics.py"], "append_metrics.py")
    run(["automation/prefill/prefill_from_facts.py", "--write"],
        "prefill_from_facts.py (writes a git-excluded sidecar)")
    out("  Pre-fill proposal written to sdr/records/records-store.prefilled.json.")
    out("  Diff it against sdr/records/records-store.json and apply what is "
        "correct by hand. A collected fact is telemetry, not a status.")


def build_and_validate():
    out("[4/4] Build and validate")
    return run(["sdr.py", "all"], "sdr.py all")


def main():
    ap = argparse.ArgumentParser(description="One-command SDR onboarding.")
    ap.add_argument("--class", dest="cls", default=None, help="A, B, or C")
    ap.add_argument("--profile", default=None, help="ReadOnly AWS profile name")
    ap.add_argument("--region", default=None, help="AWS region for collection")
    ap.add_argument("--no-collect", action="store_true",
                    help="skip collection and pre-fill; build as a template")
    ap.add_argument("--yes", action="store_true",
                    help="non-interactive: never prompt, use flags and defaults")
    args = ap.parse_args()

    interactive = sys.stdin.isatty() and not args.yes

    out("FedRAMP 20x SDR onboarding")
    out("=" * 42)
    if not install_deps():
        return 1
    set_class(args.cls, interactive)
    collect(args.profile, args.region, interactive, args.no_collect)
    code = build_and_validate()
    out()
    out("Done. Next: open sdr/records/records-store.json and replace the "
        "remaining TBDs with your facts, then re-run `python sdr.py all`.")
    if code == 0:
        out("The build gate passed (0 hard failures). Open items are expected "
            "on a fresh record; they are your fill-in list, not errors.")
        return 0
    # A genuine build or validation failure must NOT be masked as success.
    # Open readiness findings do not raise this code (cmd_all returns 1 only on
    # a build error or a validation HARD failure), so a nonzero here is real.
    out("The build/validation step FAILED. Fix the cause above before relying "
        "on the generated package.")
    return code


if __name__ == "__main__":
    sys.exit(main())
