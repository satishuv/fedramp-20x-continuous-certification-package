#!/usr/bin/env python3
"""Build a fully-worked SAMPLE offering and run the gate against it.

WHY a script and not just files: sdr.py reads fixed input paths
(sdr/records/records-store.json and profiles/common/offering-profile.json), so
there is no override flag. This script therefore:
  1. Backs up the real record store and offering profile.
  2. Generates a FILLED sample record store (fictional 'Acme Cloud Widgets')
     from the real template, replacing every TBD marker with plausible sample
     prose, and writes a filled sample offering profile.
  3. Swaps the sample inputs into place, runs `python sdr.py all` (build +
     validate + scan), and captures the gate result.
  4. ALWAYS restores the real inputs in a finally block, so the real record
     store is never left modified even if the build fails.

Everything is FICTIONAL. No real PII, no real account IDs. The sample exists so
a reviewer can see a populated record and a green gate instead of TBD markers.

Run: python examples/sample-offering/build_sample.py
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
REAL_STORE = os.path.join(BASE, "sdr", "records", "records-store.json")
REAL_PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
SAMPLE_STORE = os.path.join(HERE, "records-store.sample.json")
SAMPLE_PROFILE = os.path.join(HERE, "offering-profile.sample.json")

SAMPLE_IDENTITY = {
    "organization_name": "Acme Cloud Systems, Inc. (fictional)",
    "offering_name": "Acme Cloud Widgets",
    "offering_abbreviation": "ACW",
    "business_purpose": ("A fictional multi-tenant SaaS widget-processing "
                         "platform used to demonstrate a populated SDR."),
    "service_model": "SaaS",
    "deployment_model": "Public Cloud",
    "aws_partition": "aws",
    "primary_region": "us-east-1",
    "dr_region": "us-west-2",
    "iac_technology": "AWS CloudFormation",
    "certification_class": "B",
    "sdr_last_updated": "2026-09-07",
    "management_plane": "Provider-hosted control plane, isolated from customer workloads (fictional).",
    "federal_information_types": "None; illustrative example only.",
    "security_contact": "security@example-acme.invalid (fictional)",
    "incident_contact": "ir@example-acme.invalid (fictional)",
    "assessor": "Example 3PAO (fictional)",
    "evidence_retention": "12 months rolling (fictional sample policy).",
}


def generate_sample_profile():
    """Start from the real profile so no generator-required field is missing,
    then overlay the fictional Acme identity and fill any remaining TBDs."""
    with open(REAL_PROFILE, encoding="utf-8") as f:
        profile = json.load(f)
    profile.update(SAMPLE_IDENTITY)
    for key, val in list(profile.items()):
        if isinstance(val, str) and "TBD" in val:
            profile[key] = f"[SAMPLE - fictional] {key} for Acme Cloud Widgets."
    profile["profile_note"] = ("FICTIONAL sample profile for the worked example. "
                               "Illustrative only; not a real offering.")
    return profile


def _fill_value(value, kid, field):
    """Replace a TBD string (or list of them) with plausible sample prose.
    Non-TBD values are returned unchanged (nothing real is overwritten)."""
    sample = (f"[SAMPLE - fictional] Acme Cloud Widgets addresses {kid} for the "
              f"'{field}' aspect via documented, reviewed controls in the ACW "
              f"boundary. This is illustrative example text, not a real "
              f"attestation, and must not be treated as evidence of compliance.")

    def is_tbd(v):
        return isinstance(v, str) and ("TBD" in v or v.strip() == "")

    if isinstance(value, list):
        if not value or all(is_tbd(v) for v in value):
            return [sample]
        return value
    if is_tbd(value):
        return sample
    return value


def generate_sample_store():
    with open(REAL_STORE, encoding="utf-8") as f:
        store = json.load(f)
    for kid, rec in store.get("ksi", {}).items():
        # Fill narrative fields only. Leave implementation_status,
        # assessment, tests, evidence as the template set them: a sample must
        # NOT fabricate a status or an assessment (same trust boundary).
        for field in ("implementation", "validation"):
            if field in rec:
                rec[field] = _fill_value(rec[field], kid, field)
        ext = rec.get("extension", {})
        for field, val in list(ext.items()):
            ext[field] = _fill_value(val, kid, field)
    return store


def write_sample_artifacts():
    store = generate_sample_store()
    with open(SAMPLE_STORE, "w", encoding="utf-8", newline="\n") as f:
        json.dump(store, f, indent=1)
    with open(SAMPLE_PROFILE, "w", encoding="utf-8", newline="\n") as f:
        json.dump(generate_sample_profile(), f, indent=1)


def run_gate_with_sample(emit_dir=None):
    """Swap sample inputs in, run the gate, restore originals. Returns (rc, out).

    If emit_dir is given, the generated sample package (SDR JSON, human-readable,
    CPO, OCR, SCG, event artifacts) is copied there BEFORE the real inputs are
    restored, so a reviewer can read a populated example without running the
    build. Only committed-safe text artifacts are copied."""
    tmp = tempfile.mkdtemp(prefix="sdr-sample-")
    store_bak = os.path.join(tmp, "store.bak")
    profile_bak = os.path.join(tmp, "profile.bak")
    shutil.copy2(REAL_STORE, store_bak)
    profile_exists = os.path.exists(REAL_PROFILE)
    if profile_exists:
        shutil.copy2(REAL_PROFILE, profile_bak)
    # AUD-F36: `sdr.py all` below also rewrites the committed validation reports
    # with sample state; back them up so the tree is left exactly as found.
    report_baks = {}
    for rel in ("validation/reports/validation-report.json",
                "validation/reports/ksi-test-results.json"):
        real = os.path.join(BASE, rel.replace("/", os.sep))
        if os.path.exists(real):
            b = os.path.join(tmp, os.path.basename(real) + ".bak")
            shutil.copy2(real, b)
            report_baks[real] = b
    try:
        shutil.copy2(SAMPLE_STORE, REAL_STORE)
        shutil.copy2(SAMPLE_PROFILE, REAL_PROFILE)
        proc = subprocess.run(
            [sys.executable, os.path.join(BASE, "sdr.py"), "all"],
            cwd=BASE, capture_output=True, text=True)
        if emit_dir:
            _emit_generated(emit_dir)
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    finally:
        shutil.copy2(store_bak, REAL_STORE)
        if profile_exists:
            shutil.copy2(profile_bak, REAL_PROFILE)
        for real, b in report_baks.items():
            shutil.copy2(b, real)
        shutil.rmtree(tmp, ignore_errors=True)
        # Running the gate above wrote the SAMPLE content into the real
        # generated output paths (sdr/json, package/, ...). Restoring the input
        # files is not enough: regenerate from the restored real inputs so the
        # committed generated outputs are never left holding sample content.
        # `sdr.py build` regenerates every class (JSON, text and Word document).
        subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "build"],
                       cwd=BASE, capture_output=True, text=True)


# Generated artifacts copied into the emit dir. Text/JSON only; the Word
# document stays with the real tree (it is fingerprinted there since AUD-F35).
_EMIT_ARTIFACTS = [
    "sdr/json/sdr-class-b.json",
    "sdr/human-readable/sdr-class-b.txt",
    "package/cpo/cpo.json",
    "package/cpo/cpo.md",
    "package/ocr/ocr-example.json",
    "package/scg/secure-configuration-guide.md",
    "package/events/incident-report-initial-example.json",
    "package/events/incident-report-ongoing-example.json",
    "package/events/incident-report-final-example.json",
    "package/events/significant-change-notification-example.json",
    "package/events/significant-change-notification-example.md",
    "package/events/accepted-vulnerabilities-example.json",
    "package/events/vulnerability-detail-report-example.json",
    "package/events/historical-ver-activity-example.json",
]


def _emit_generated(emit_dir):
    os.makedirs(emit_dir, exist_ok=True)
    copied = 0
    for rel in _EMIT_ARTIFACTS:
        src = os.path.join(BASE, rel)
        if os.path.exists(src):
            dst = os.path.join(emit_dir, os.path.basename(rel))
            shutil.copy2(src, dst)
            copied += 1
    with open(os.path.join(emit_dir, "README.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(
            "# Generated sample package (Acme Cloud Widgets, fictional)\n\n"
            "These files are the ACTUAL output of running the sample build "
            "(`python examples/sample-offering/build_sample.py --emit`) against "
            "the fictional Acme Cloud Widgets inputs, committed so a reviewer "
            "can read a populated Class B Certification Package without running "
            "anything.\n\n"
            "Everything here is FICTIONAL and illustrative. It is not a real "
            "offering, not an attestation, and not evidence of compliance. "
            "Narrative fields are filled with clearly-labelled sample prose; "
            "implementation status, assessment, tests, and evidence are left as "
            "the template sets them, because those are reserved for human "
            "judgment and an accredited assessor.\n\n"
            "Regenerate with:\n\n"
            "```bash\npython examples/sample-offering/build_sample.py --emit\n```\n")
    return copied


def main():
    emit_dir = None
    if "--emit" in sys.argv:
        emit_dir = os.path.join(HERE, "generated")
    print("Generating fictional sample offering (Acme Cloud Widgets)...")
    write_sample_artifacts()
    print(f"  wrote {os.path.relpath(SAMPLE_STORE, BASE)}")
    print(f"  wrote {os.path.relpath(SAMPLE_PROFILE, BASE)}")
    print("Running the gate against the sample (real inputs are restored after)...")
    rc, out = run_gate_with_sample(emit_dir)
    tail = "\n".join(out.splitlines()[-25:])
    print(tail)
    print(f"\nGate exit code: {rc} ({'PASS' if rc == 0 else 'non-zero'})")
    if emit_dir:
        print(f"Generated sample package emitted to {os.path.relpath(emit_dir, BASE)}")
    print("Real record store and profile have been restored.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
