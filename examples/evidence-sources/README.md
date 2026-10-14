# Optional third-party evidence sources

Some customers run CrowdStrike Falcon, some run Wiz, some run neither. These
adapters let a customer feed that security tool's telemetry into the SDR as
evidence, opt-in, without changing anything for a customer who does not use the
tool.

## How it works

Each adapter reads an EXPORT the customer produces from their own tenant and
maps it to SDR `ksiEvidence` entries via the shared evidence-adapter interface.
Every entry is hashed (`xEvidenceContentHash`) and schema-valid, under the same
trust boundary as the AWS collectors: telemetry only, never a status
determination. A human still decides the implementation status.

This repository holds no Falcon or Wiz API client and no API credentials.
Fetching from the live API needs a token and is the customer's own step in
their own environment. Keeping it out of this public template is deliberate, so
the secret-scanners stay clean.

## Enabling a source (per customer)

In `profiles/common/offering-profile.json`, under `evidence_sources`, set
`enabled: true` and point `export_path` at the customer-produced export:

```json
"evidence_sources": {
  "crowdstrike-falcon": {"enabled": true, "export_path": "automation/facts/falcon-export.json"},
  "wiz": {"enabled": false, "export_path": "automation/facts/wiz-export.json"}
}
```

Both are `false` by default. A customer who does not use the tool leaves it off
and nothing tool-related appears anywhere.

Then run, before `python sdr.py build`:

```bash
python automation/collectors/apply_third_party_evidence.py
```

It attaches evidence to the mapped KSIs and updates the record store. If a
source is enabled but its export file is absent, it is skipped with a message,
not an error. If an adapter yields a fact that does not meet the fact contract
(below), the run stops with the offending field named and the record store is
left untouched.

## The fact contract (every adapter, any platform)

An adapter yields facts, never evidence. The one shape a fact must have is
published as JSON Schema in `automation/collectors/fact-contract.schema.json`
and enforced before any fact is converted:

| Field | Required | Meaning |
|---|---|---|
| `service` | yes | source slug the check belongs to (slug-safe, becomes part of the evidence object key) |
| `check` | yes | the individual check or rule id within the source (slug-safe) |
| `status` | yes | the source's own observation string (a count, a percentage, COMPLIANT). Not a verdict |
| `detail` | yes (may be empty) | short human summary; scrubbed and bounded before it enters the package |
| `region` | yes | where it was observed, or `global` (slug-safe) |
| `observed_at` | yes | the source's real timestamp, ISO 8601 with a calendar-date prefix. Never invented |
| `scope` | no | an opaque scope id (`scope-...` or a slug alias), never a raw identifier |
| `run_id` | no | slug-safe collection-run id |

A fact may carry the raw identifier of the scope it came from (`account`,
`tenant`, `subscription`, `compartment`, `project`, `organization`) on input.
It is exported only when a deployment-private scope key is supplied (an opaque
scope id is derived from it) or an opaque `scope` alias is set; otherwise the
fact is refused with the field named. The raw value never enters an evidence
object, a pointer or a hash. The package layer learns nothing about the
platform from the fact shape; that is what lets one SDR pipeline accept
evidence from any source.

## What each maps to (real CR26 KSI ids, verified against the dataset)

| Source | Signal | KSIs it supports |
|---|---|---|
| CrowdStrike Falcon | sensor coverage, open detections, prevention policy | `KSI-MLA-OSM`, `KSI-MLA-RVL`, `KSI-MLA-LET`, `KSI-INR-RIR` |
| Wiz | issues by severity, config findings, open vulnerabilities | `KSI-MLA-EVC`, `KSI-MLA-OSM`, `KSI-SCR-MON` |

The mapping says the tool's telemetry is evidence toward those indicators. It
does not assert the indicator passes; that is the human assessor's call.

## Export shapes

See `falcon-export.example.json` and `wiz-export.example.json` in this folder
for the expected fields. All fields are optional; a missing field is skipped.
