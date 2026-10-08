#!/usr/bin/env python3
"""Generate an example Ongoing Certification Report (OCR).

CCM-OCR-AVL requires providers to supply an Ongoing Certification Report every
3 months, covering the entire period since the previous summary, in a
consistent human-readable format, with high-level summaries of the required
information. FRC-CSO-PKG requires a real or example OCR in the initial package.

This builds an EXAMPLE OCR against the official
fedramp-ongoing-certification-report-schema, plus a plain-text rendering. It is
explicitly an example scaffold: report period and summaries are honest
placeholders, empty arrays attest "none this period" exactly as the schema
intends, and nothing here asserts a real reporting event occurred.

    python validation/scripts/build_ocr.py

Pipeline position: after build_cpo.py. Outputs:
    package/ocr/ocr-example.json   schema-valid example Ongoing Certification Report
    package/ocr/ocr-example.md     human-readable rendering
"""

import datetime
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
from fedramp_time import add_calendar_months  # noqa: E402
import profile_contract as _pc  # noqa: E402  (cpo_uri: one resolver shared with the validator)
PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
OUT_JSON = os.path.join(BASE, "package", "ocr", "ocr-example.json")
OUT_MD = os.path.join(BASE, "package", "ocr", "ocr-example.md")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def dump_json(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=1)


def build_ocr(profile):
    # Deterministic example period derived from the pinned dataset date, never
    # a run timestamp, so the example is byte-stable across builds. CCM-OCR-AVL
    # states the cadence in calendar months ("every 3 months"), so use real
    # calendar-month arithmetic, not a 90-day approximation.
    dataset_date = "-".join(profile["dataset_version"].split(".")[:3])
    to_d = datetime.date.fromisoformat(dataset_date)
    from_d = add_calendar_months(to_d, -3)
    horizon = add_calendar_months(to_d, 3)
    # One resolver for the CPO URI (profile_contract.cpo_uri), shared with the
    # events builder and the consistency validator. Preflight blocks on TBD.
    cpo_uri = _pc.cpo_uri(profile)
    doc = {
        "certificationPackageOverviewUri": cpo_uri,
        "reportPeriod": {"from": from_d.isoformat(), "to": to_d.isoformat()},
        # Example summaries. Empty arrays are meaningful: they attest "none this
        # period" per the schema, not "unknown".
        "certificationDataChanges": [
            "EXAMPLE: no changes to FedRAMP Certification Data during this period."
        ],
        "plannedCertificationDataChanges": {
            "planningHorizonThrough": horizon.isoformat(),
            "changes": [
                "EXAMPLE: no planned changes to Certification Data in the next 3 months."
            ],
        },
        "acceptedVulnerabilities": (
            "EXAMPLE: summary of accepted vulnerabilities this period. Replace "
            "with the provider's real summary; see the VER/accepted-vulnerability "
            "artifacts."
        ),
        "transformativeChanges": [
            "EXAMPLE: no transformative changes during this period."
        ],
        "updatedRecommendations": [
            "EXAMPLE: no updated recommendations during this period."
        ],
        "activeAgencies": [
            "EXAMPLE: list of agencies actively using the offering this period."
        ],
        "reportableIncidents": {
            # Empty array attests no FedRAMP Reportable Incidents occurred.
            "incidents": []
        },
        "_ocrNote": (
            "EXAMPLE Ongoing Certification Report scaffold. Required by "
            "CCM-OCR-AVL every 3 months and as a real-or-example artifact in the "
            "initial package (FRC-CSO-PKG). Every value prefixed EXAMPLE is a "
            "placeholder; empty arrays attest none-this-period. Not a real report "
            "and not a compliance claim."
        ),
    }
    return doc


def render_md(doc):
    L = []
    a = L.append
    a("Ongoing Certification Report (EXAMPLE)")
    a("")
    a(f"Certification Package Overview: {doc['certificationPackageOverviewUri']}")
    rp = doc["reportPeriod"]
    a(f"Report period: {rp['from']} to {rp['to']}")
    a("")
    a("Changes to FedRAMP Certification Data")
    for c in doc["certificationDataChanges"]:
        a(f"  - {c}")
    a("")
    a("Planned changes to FedRAMP Certification Data")
    a(f"  Planning horizon through: {doc['plannedCertificationDataChanges']['planningHorizonThrough']}")
    for c in doc["plannedCertificationDataChanges"]["changes"]:
        a(f"  - {c}")
    a("")
    a(f"Accepted vulnerabilities: {doc['acceptedVulnerabilities']}")
    a("")
    a("Transformative changes")
    for c in doc["transformativeChanges"]:
        a(f"  - {c}")
    a("")
    a("Updated recommendations")
    for c in doc["updatedRecommendations"]:
        a(f"  - {c}")
    a("")
    a("Active agencies")
    for c in doc["activeAgencies"]:
        a(f"  - {c}")
    a("")
    incidents = doc["reportableIncidents"]["incidents"]
    a(f"FedRAMP reportable incidents: "
      f"{len(incidents) if incidents else 'none this period (empty attests none)'}")
    a("")
    a("This is an EXAMPLE Ongoing Certification Report required by CCM-OCR-AVL. "
      "Values prefixed EXAMPLE are placeholders. A schema-valid document is not "
      "a compliance determination.")
    return "\n".join(L)


def main():
    profile = load(PROFILE)
    cls = (profile.get("certification_class") or "b").lower()
    if cls == "d":
        print("Class D is FedRAMP pending; no OCR is generated.")
        return 1
    doc = build_ocr(profile)
    dump_json(doc, OUT_JSON)
    os.makedirs(os.path.dirname(OUT_MD), exist_ok=True)
    with open(OUT_MD, "w", encoding="utf-8", newline="\n") as f:
        f.write(render_md(doc))
    print(f"OCR written: {os.path.relpath(OUT_JSON, BASE)} and .md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
