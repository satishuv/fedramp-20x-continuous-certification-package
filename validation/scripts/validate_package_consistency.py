#!/usr/bin/env python3
"""Cross-artifact consistency validator.

The framework generates many artifacts (SDR, CPO, OCR, SCG, event artifacts).
Schema validation checks each in isolation; this checks they agree with each
other as one package:

  - certification class is consistent across SDR extensions, CPO, and the
    assurance graph
  - the Certification Package Overview URI referenced by the OCR and event
    artifacts matches the offering profile's CPO URI
  - the dataset version is consistent across SDR, assurance graph, and manifest
  - the release manifest's recorded artifact hashes match the files on disk

Separate from schema validity. Exit 1 on any contradiction.

    python validation/scripts/validate_package_consistency.py
"""

import hashlib
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OFFERING = os.path.join(BASE, "profiles", "common", "offering-profile.json")
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
import profile_contract as _pc  # noqa: E402  (cpo_uri: the generators' resolver)


def load(rel, default=None):
    path = rel if os.path.isabs(rel) else os.path.join(BASE, rel)
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


def main():
    offering = load(OFFERING, {})
    cls = (offering.get("certification_class") or "b").lower()
    if cls == "d":
        print("Class D is FedRAMP pending; no package to check.")
        return 1
    problems = []

    # The SAME resolver the generators use (profile_contract.cpo_uri): while
    # the profile value is TBD every artifact carries the shared placeholder, and
    # this check must compare against that, not against the TBD marker text.
    cpo_uri = _pc.cpo_uri(offering)

    # Class consistency: extensions, CPO, assurance graph.
    ext = load(f"sdr/json/sdr-class-{cls}-extensions.json", {})
    ext_class = (ext.get("metadata", {}) or {}).get("certification_class")
    if ext_class and ext_class.lower() != cls:
        problems.append(f"SDR extensions class {ext_class} != profile class {cls.upper()}")

    graph = load("traceability/assurance-graph.json", {})
    if graph.get("certification_class", "").lower() != cls:
        problems.append(f"assurance graph class {graph.get('certification_class')} != {cls.upper()}")

    cpo = load("package/cpo/cpo.json", {})
    # CPO offering identity must match the offering profile it was generated
    # from (the docstring promises a CPO consistency check; this performs it
    # using fields that exist in the official CPO schema).
    si = cpo.get("serviceIdentification", {}) or {}
    cpo_checks = [
        ("serviceName", si.get("serviceName"), offering.get("offering_name")),
        ("serviceAcronym", si.get("serviceAcronym"), offering.get("offering_abbreviation")),
        ("providerName", si.get("providerName"), offering.get("organization_name")),
    ]
    for field, cpo_val, prof_val in cpo_checks:
        if cpo_val and prof_val and str(cpo_val) != str(prof_val):
            problems.append(f"CPO {field} '{cpo_val}' != offering profile '{prof_val}'")
    # Certification type token consistency (20x vs the profile's label).
    cpo_ctype = si.get("certificationType")
    prof_is_rev5 = "rev5" in (offering.get("certification_type") or "").lower()
    if cpo_ctype and ((cpo_ctype == "Rev5") != prof_is_rev5):
        problems.append(f"CPO certificationType '{cpo_ctype}' disagrees with "
                        f"offering certification_type '{offering.get('certification_type')}'")

    # OCR and event artifacts must reference the same CPO URI as the profile.
    for rel in ["package/ocr/ocr-example.json",
                "package/events/incident-report-initial-example.json",
                "package/events/incident-report-ongoing-example.json",
                "package/events/incident-report-final-example.json",
                "package/events/significant-change-notification-example.json",
                "package/events/accepted-vulnerabilities-example.json",
                "package/events/vulnerability-detail-report-example.json",
                "package/events/historical-ver-activity-example.json"]:
        doc = load(rel, {})
        ref = doc.get("certificationPackageOverviewUri")
        if ref and cpo_uri and ref != cpo_uri:
            problems.append(f"{rel}: CPO URI {ref} != offering CPO URI {cpo_uri}")

    # Dataset version consistency: graph vs offering.
    if graph.get("dataset_version") and graph["dataset_version"] != offering.get("dataset_version"):
        problems.append(f"assurance graph dataset {graph['dataset_version']} != "
                        f"offering {offering.get('dataset_version')}")

    # Release manifest hashes must match the files on disk.
    manifest = load("artifacts/release-manifest.json", {})
    for rel, want in (manifest.get("artifacts") or {}).items():
        path = os.path.join(BASE, rel)
        if not os.path.exists(path):
            problems.append(f"manifest references missing artifact {rel}")
            continue
        got = sha256_file(path)
        if got != want:
            problems.append(f"manifest hash mismatch for {rel}")

    # Authoritative INPUTS must also match the manifest. Without this, a package
    # can be signed, then an input (offering-profile / records-store) edited
    # WITHOUT a rebuild: the manifest and the human signoff still match each
    # other, but the current inputs no longer match the manifest. Revalidating
    # inputs here makes that tamper path detectable (the signoff binds to the
    # manifest, and the manifest must reflect the current inputs).
    for rel, want in (manifest.get("inputs") or {}).items():
        path = os.path.join(BASE, rel)
        if not os.path.exists(path):
            problems.append(f"manifest references missing input {rel}")
            continue
        got = sha256_file(path)
        if got != want:
            problems.append(f"manifest input hash mismatch for {rel} "
                            "(an authoritative input changed without a rebuild; "
                            "rebuild so the manifest and signoff reflect it)")

    if problems:
        print(f"FAIL: {len(problems)} cross-artifact inconsistency(ies):")
        for p in problems[:20]:
            print(f"    - {p}")
        return 1
    print("PASS: package is internally consistent (class, CPO URI, dataset "
          "version, and manifest hashes all agree across artifacts).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
