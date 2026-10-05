#!/usr/bin/env python3
"""Build the release manifest: one cryptographic fingerprint of the whole
generated Certification Package.

Records, for the current class, a SHA-256 of every generated artifact plus the
pinned dataset version and hash, the pinned schema versions and hashes, and a
framework version. A reviewer can verify a delivered package matches this
manifest hash-for-hash, and a package can be reconstructed from the recorded
versions.

Deterministic on purpose: no run timestamps, so two builds of unchanged inputs
produce a byte-identical manifest (the reproducibility gate depends on this).
The manifest fingerprints the active-class Word document too (byte-reproducible
since AUD-F35; it was excluded while its zip container embedded save times, which
left the one document an assessor reads outside every integrity check) and
excludes only itself.

    python validation/scripts/build_release_manifest.py

Output: artifacts/release-manifest.json
"""

import hashlib
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OFFERING = os.path.join(BASE, "profiles", "common", "offering-profile.json")
LOCK = os.path.join(BASE, "references", "sources.lock.json")
OUT = os.path.join(BASE, "artifacts", "release-manifest.json")

FRAMEWORK_VERSION = "1.5.0"


def _sha256_file(path):
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return "sha256:" + hashlib.sha256(f.read()).hexdigest()


def _source_provenance():
    """Bind the manifest to the exact SOURCE that produced it, via deterministic
    requirements hashes only. Git commit/tree are NOT recorded here: doing so
    would either be circular (the commit hash cannot be known before the commit
    that contains the manifest) or would mutate the manifest AFTER a human has
    signed off against its hash, invalidating the signoff. Exact git source
    provenance lives in a SEPARATE artifacts/release-attestation.json emitted by
    build_release_attestation.py at release time, which binds this manifest's
    SHA-256 to the git commit/tree without changing the signed manifest."""
    return {
        "requirements_sha256": _sha256_file(os.path.join(BASE, "requirements.txt")),
        "requirements_ci_sha256": _sha256_file(os.path.join(BASE, "requirements-ci.txt")),
        "source_commit": None,
        "source_tree": None,
        "provenance_note": ("Exact git commit/tree are recorded in "
                            "artifacts/release-attestation.json at release time, "
                            "not here, so this manifest stays byte-stable and a "
                            "human signoff bound to its hash is never invalidated "
                            "by adding provenance."),
    }

# Generated artifacts fingerprinted, per class. Every entry is byte-deterministic
# (the .docx since AUD-F35).
ARTIFACT_GLOBS = [
    "sdr/json/sdr-class-{c}.json",
    "sdr/json/sdr-class-{c}-extensions.json",
    # The OSCAL export (sdr-class-{c}.oscal.json) is experimental/reference-only
    # and excluded from the customer bundle, so it is NOT fingerprinted here.
    "sdr/human-readable/sdr-class-{c}.txt",
    # The authoring Word document is what a consultant and an assessor read;
    # fingerprinting it means the bundle assembler ships the exact bytes the
    # gate checked, and a hand-edited copy no longer matches the manifest.
    "sdr/human-readable/sdr-class-{c}-authoring.docx",
    "package/cpo/cpo.json",
    "package/cpo/cpo.md",
    "package/ocr/ocr-example.json",
    "package/ocr/ocr-example.md",
    "package/scg/secure-configuration-guide.md",
    "package/events/incident-report-initial-example.json",
    "package/events/incident-report-ongoing-example.json",
    "package/events/incident-report-final-example.json",
    "package/events/significant-change-notification-example.json",
    "package/events/significant-change-notification-example.md",
    "package/events/accepted-vulnerabilities-example.json",
    "package/events/vulnerability-detail-report-example.json",
    "package/events/historical-ver-activity-example.json",
    "traceability/assurance-graph.json",
    "traceability/applicability-decisions.json",
    "traceability/rev5-to-20x-crosswalk.csv",
    "artifacts/sbom.cdx.json",
]


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def build(cls):
    offering = load(OFFERING, {})
    lock = load(LOCK, {"sources": {}})
    sources = lock.get("sources", {})

    artifacts = {}
    missing = []
    expected = [g.format(c=cls) for g in ARTIFACT_GLOBS]
    # The package-scope manifest is a real customer-facing artifact and must be
    # covered by the cryptographic release manifest too.
    expected.append("package/certification-package-manifest.json")
    for rel in expected:
        path = os.path.join(BASE, rel)
        if os.path.exists(path):
            artifacts[rel] = sha256_file(path)
        else:
            missing.append(rel)
    if missing:
        # A missing EXPECTED artifact must not be silently skipped: the manifest
        # would then attest to an incomplete package. Fail the build.
        raise SystemExit(
            "release manifest: expected artifact(s) missing from the package; "
            "the package is incomplete, refusing to fingerprint it: "
            + ", ".join(missing))

    schemas = {}
    for key, entry in sources.items():
        if key.endswith("_schema"):
            schemas[key] = {
                "version": entry.get("schema_version"),
                "sha256": entry.get("sha256"),
            }

    dataset = sources.get("cr26_consolidated_rules", {})

    # Submission-critical AUTHORITATIVE INPUTS. Some values here (provider
    # verification date, assessment references, availability assertions) affect
    # preflight without necessarily changing a generated artifact, so a signoff
    # bound only to generated outputs could miss a post-signoff input change.
    # Hashing them here folds them into the manifest hash the signoff binds to.
    # The review register is deliberately EXCLUDED to avoid a circular hash.
    input_files = [
        "profiles/common/offering-profile.json",
        "sdr/records/records-store.json",
    ]
    # For Class C/D, the durable per-KSI metric history is a readiness-CRITICAL
    # input: FRC-CSX-MOT READY/NOT-READY turns on it, yet it is not a generated
    # artifact. A signoff bound only to generated outputs + profile/records would
    # miss a post-signoff change to the history, so fold it into the manifest
    # hash the human signoff binds to. It is gitignored (derived from a real
    # account), so it is hashed ONLY when present - in the AWS release path it is
    # restored from the evidence bucket before this runs; in a clean clone with
    # no history (A/B, or a not-yet-collected C/D) it is simply absent and not
    # hashed, keeping the manifest byte-stable for the reproducibility gate.
    if cls in ("c", "d"):
        input_files.append("automation/metrics/metric-history.json")
    inputs = {}
    for rel in input_files:
        p = os.path.join(BASE, rel)
        if os.path.exists(p):
            inputs[rel] = sha256_file(p)

    return {
        "manifest_note": (
            "Cryptographic fingerprint of the generated Certification Package. "
            "Deterministic (no run timestamps); a delivered package can be "
            "verified against these hashes and reconstructed from the recorded "
            "versions. This is a build-provenance record, not a compliance "
            "determination."),
        "framework_version": FRAMEWORK_VERSION,
        "certification_class": cls.upper(),
        "dataset_version": offering.get("dataset_version"),
        "dataset_sha256": dataset.get("sha256"),
        "schemas": dict(sorted(schemas.items())),
        "inputs": dict(sorted(inputs.items())),
        "artifacts": dict(sorted(artifacts.items())),
        "artifact_count": len(artifacts),
        "release_tag": f"v{FRAMEWORK_VERSION}-cr26-{offering.get('dataset_version')}",
        "source_provenance": _source_provenance(),
        "build": {"deterministic": True, "generator": "build_release_manifest.py"},
    }


def main():
    cls = (load(OFFERING, {}).get("certification_class") or "b").lower()
    if cls == "d":
        print("Class D is FedRAMP pending; no release manifest generated.")
        return 1
    manifest = build(cls)
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=1)
    print(f"Release manifest written: {os.path.relpath(OUT, BASE)} "
          f"({manifest['artifact_count']} artifacts, tag {manifest['release_tag']}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
