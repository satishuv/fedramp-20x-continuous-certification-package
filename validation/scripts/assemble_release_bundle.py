#!/usr/bin/env python3
"""Assemble the customer release bundle from EXACTLY what the release manifest
fingerprints, plus the manifest and attestation themselves.

Why this exists: the release manifest already fingerprints exactly the ACTIVE
certification class (e.g. only sdr-class-b.* for a Class B offering) plus the
shared package artifacts. Publishing from a wildcard (sdr/json/**/*) instead
would ship the inactive Class A and C SDRs the repository keeps current for
traceability, and could drift from what the manifest attests. Copying precisely
the fingerprinted set makes the bundle active-class-only AND manifest-consistent
by construction.

Included since AUD-F35: the active-class authoring .docx, now byte-reproducible
and fingerprinted, so the Word document a consultant hands over is the exact
bytes the gate checked. Not included, deliberately: the OSCAL export
(experimental/reference-only) and any inactive-class SDR.

    python validation/scripts/assemble_release_bundle.py

Writes artifacts/release-bundle/ mirroring each artifact's repo-relative path.
The directory is release-only and git-excluded.
"""

import json
import os
import shutil
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MANIFEST = os.path.join(BASE, "artifacts", "release-manifest.json")
ATTESTATION = os.path.join(BASE, "artifacts", "release-attestation.json")
BUNDLE = os.path.join(BASE, "artifacts", "release-bundle")


def assemble():
    if not os.path.exists(MANIFEST):
        print("FAIL. No release-manifest.json; run the build first.")
        return None
    manifest = json.load(open(MANIFEST, encoding="utf-8"))
    fingerprinted = sorted((manifest.get("artifacts") or {}).keys())
    # The manifest and attestation describe the bundle, so they ride along even
    # though the manifest does not fingerprint itself.
    extra = ["artifacts/release-manifest.json"]
    if os.path.exists(ATTESTATION):
        extra.append("artifacts/release-attestation.json")
    to_copy = fingerprinted + extra

    if os.path.isdir(BUNDLE):
        shutil.rmtree(BUNDLE)
    copied, missing = [], []
    for rel in to_copy:
        src = os.path.join(BASE, rel.replace("/", os.sep))
        if not os.path.exists(src):
            missing.append(rel)
            continue
        dst = os.path.join(BUNDLE, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)
        copied.append(rel)
    return {"active_class": manifest.get("certification_class"),
            "copied": copied, "missing": missing}


def main():
    result = assemble()
    if result is None:
        return 1
    if result["missing"]:
        print("FAIL. Fingerprinted artifact(s) missing from the tree: "
              + ", ".join(result["missing"]))
        return 1
    print(f"Release bundle assembled for Class {result['active_class']}: "
          f"{len(result['copied'])} artifacts -> "
          f"{os.path.relpath(BUNDLE, BASE)}")
    # Guardrail: no inactive-class SDR may be in the bundle.
    active = (result["active_class"] or "").lower()
    stray = [p for p in result["copied"]
             if p.startswith("sdr/") and f"sdr-class-{active}" not in p]
    if stray:
        print("FAIL. Inactive-class SDR leaked into the bundle: " + ", ".join(stray))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
