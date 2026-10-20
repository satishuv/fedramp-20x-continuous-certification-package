# OSCAL export

The framework can emit any generated Security Decision Record as an OSCAL
document, so the same verified facts are available in the machine-readable
interchange format that agency governance, risk, and compliance (GRC) tools
ingest. This makes the provider's SDR **also available as OSCAL** alongside the
native SDR JSON.

OSCAL (Open Security Controls Assessment Language, from NIST) is a structured
representation of security assessment information. Emitting the SDR in OSCAL
lets a GRC tool consume it without a bespoke parser.

## Run it

```bash
# export every generated SDR (sdr/json/sdr-class-*.json)
python automation/exporters/oscal_export.py

# export one
python automation/exporters/oscal_export.py sdr/json/sdr-class-a.json
```

Output lands next to the source as `sdr/json/sdr-class-<x>.oscal.json`.

## What it produces

An OSCAL **Assessment Results** document:

- each FedRAMP Requirement (FRR) and Key Security Indicator (KSI) becomes an
  OSCAL `finding`,
- each concrete piece of KSI evidence becomes an `observation` plus a
  `back-matter` resource whose `rlink` carries the `evidenceLocation`,
- any NIST 800-53 control IDs present in the SDR are carried as a control
  selection so control-keyed tools can join on them.

The Assessment Results model is used because an SDR is fundamentally a set of
verified findings and evidence about requirements and indicators.

## Honesty boundary

The exporter is a pure read - transform - write adapter. It:

- **never** changes a status: `Not Implemented` maps to `not-satisfied`,
  `Implemented` to `satisfied`, and the raw SDR status is preserved verbatim in
  a property on every finding,
- **never** invents satisfaction: a finding is `satisfied` only when the SDR
  already said `Implemented`,
- **never** emits placeholder evidence: a `TBD` evidence entry with no location
  and no text is skipped rather than turned into a fake resource,
- **never** queries AWS and does not run in the build pipeline; it reads a
  finished SDR file and writes a derived view.

The SDR remains the source of truth; the OSCAL file is a derived view of it and
is regenerated from the SDR, never edited by hand.
