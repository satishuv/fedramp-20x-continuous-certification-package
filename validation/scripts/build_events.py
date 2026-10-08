#!/usr/bin/env python3
"""Generate example event-driven Certification Package artifacts.

These are the CR26 artifacts a provider files when an event occurs (or attests
none): the Incident Report (IEC-CSO-*), the Significant Change Notification
(SCN family), and the vulnerability set - Accepted Vulnerability Information,
Vulnerability Detail Report, and Historical VER Activity (VDR/VER families).

Each is generated as an EXAMPLE scaffold, validated against its official
FedRAMP schema. Empty arrays are meaningful per the schemas: they attest
"none this period", not "unknown". Nothing here is a real filing or a
compliance claim; a provider replaces the EXAMPLE values with real ones when an
actual event occurs.

    python validation/scripts/build_events.py

Outputs under package/events/:
    incident-report-initial-example.json    (IEC-CSO-IIR, reportType Initial)
    incident-report-ongoing-example.json    (IEC-CSO-OIR, reportType Ongoing)
    incident-report-final-example.json       (IEC-CSO-FIR, reportType Final)
    significant-change-notification-example.json
    significant-change-notification-example.md   (SCN-CSO-HRM: human-readable)
    accepted-vulnerabilities-example.json
    vulnerability-detail-report-example.json
    historical-ver-activity-example.json
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
OUT_DIR = os.path.join(BASE, "package", "events")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def dump_json(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=1)


def build_all(profile):
    # One resolver for the CPO URI (profile_contract.cpo_uri): a TBD profile value
    # becomes the shared placeholder, so events, OCR, CPO and the consistency
    # validator agree. Preflight blocks on the TBD field.
    cpo_uri = _pc.cpo_uri(profile)
    # Deterministic period derived from the pinned dataset date, never a run
    # clock, so examples are byte-stable across builds.
    dataset_date = "-".join(profile["dataset_version"].split(".")[:3])
    to_d = datetime.date.fromisoformat(dataset_date)
    from_d = add_calendar_months(to_d, -3)
    from_dt = from_d.isoformat() + "T00:00:00Z"
    to_dt = to_d.isoformat() + "T00:00:00Z"

    note = ("EXAMPLE {kind} scaffold. Validated against the official FedRAMP "
            "schema. Empty arrays attest none-this-period. Replace EXAMPLE "
            "values with real data when an actual event occurs. Not a real "
            "filing and not a compliance claim.")

    # The official incident-report schema is one unified schema covering three
    # report types via the reportType enum: Initial (IEC-CSO-IIR), Ongoing
    # (IEC-CSO-OIR), Final (IEC-CSO-FIR). The same providerTrackingId ties the
    # three reports for one incident together. Final requires resolvedAt.
    incident_base = {
        "certificationPackageOverviewUri": cpo_uri,
        "providerTrackingId": "EXAMPLE-INC-0001",
    }
    incident_initial = dict(incident_base, reportType="Initial",
                            _eventNote=note.format(kind="Initial Incident Report (IEC-CSO-IIR)"))
    incident_ongoing = dict(incident_base, reportType="Ongoing",
                            _eventNote=note.format(kind="Ongoing Incident Report (IEC-CSO-OIR)"))
    incident_final = dict(incident_base, reportType="Final",
                          resolvedAt=to_dt,
                          _eventNote=note.format(kind="Final Incident Report (IEC-CSO-FIR)"))

    scn = {
        "certificationPackageOverviewUri": cpo_uri,
        "changeType": "Adaptive",
        "changeDescription": (
            "EXAMPLE: describe the significant change here. Adaptive changes "
            "keep the certification; Transformative changes may require "
            "re-certification (SCN family / FRD-CCC)."),
        "_eventNote": note.format(kind="Significant Change Notification (SCN)"),
    }

    return {
        "incident-report-initial-example.json": incident_initial,
        "incident-report-ongoing-example.json": incident_ongoing,
        "incident-report-final-example.json": incident_final,
        "significant-change-notification-example.json": scn,
        "accepted-vulnerabilities-example.json": {
            "certificationPackageOverviewUri": cpo_uri,
            "reportPeriod": {"from": from_dt, "to": to_dt},
            "acceptedVulnerabilities": [],
            "_eventNote": note.format(kind="Accepted Vulnerability Information (VER)"),
        },
        "vulnerability-detail-report-example.json": {
            "certificationPackageOverviewUri": cpo_uri,
            "reportPeriod": {"from": from_dt, "to": to_dt},
            "vulnerabilities": [],
            "_eventNote": note.format(kind="Vulnerability Detail Report (VDR)"),
        },
        "historical-ver-activity-example.json": {
            "certificationPackageOverviewUri": cpo_uri,
            "generatedAt": to_dt,
            "activeVulnerabilities": [],
            "acceptedVulnerabilities": [],
            "_eventNote": note.format(kind="Historical VER Activity (VER)"),
        },
    }


def scn_markdown(scn):
    """Human-readable rendering of the SCN. SCN-CSO-HRM (MUST): all Significant
    Change Notifications and related audit records MUST be available in
    human-readable AND JSON formats. This is the human-readable half; the JSON
    is the paired significant-change-notification-example.json."""
    L = []
    L.append("# Significant Change Notification (EXAMPLE)")
    L.append("")
    L.append("Human-readable rendering required by SCN-CSO-HRM (available in "
             "both human-readable and JSON formats). The paired machine format "
             "is `significant-change-notification-example.json`.")
    L.append("")
    L.append(f"- Certification Package Overview: {scn['certificationPackageOverviewUri']}")
    L.append(f"- Change type: {scn['changeType']}")
    L.append("")
    L.append("## Change description")
    L.append("")
    L.append(scn["changeDescription"])
    L.append("")
    L.append("This is an EXAMPLE scaffold, not a real filing and not a "
             "compliance claim. Replace with real data when a significant "
             "change occurs.")
    return "\n".join(L) + "\n"


def main():
    profile = load(PROFILE)
    cls = (profile.get("certification_class") or "b").lower()
    if cls == "d":
        print("Class D is FedRAMP pending; no event artifacts are generated.")
        return 1
    artifacts = build_all(profile)
    for fn, doc in artifacts.items():
        dump_json(doc, os.path.join(OUT_DIR, fn))
    # SCN-CSO-HRM: SCNs MUST also be available in human-readable format.
    scn_md_path = os.path.join(OUT_DIR, "significant-change-notification-example.md")
    with open(scn_md_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(scn_markdown(artifacts["significant-change-notification-example.json"]))
    print(f"event artifacts written: {len(artifacts)} JSON files + 1 "
          f"human-readable SCN (SCN-CSO-HRM) under {os.path.relpath(OUT_DIR, BASE)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
