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
| `record_id` | no | the source's own identity for one record of a check (a finding id), for sources that report one record per resource; converted to an opaque `record` before export, never exported raw |
| `record` | no | an opaque per-record id (`rec-...`), derived from `record_id` under the scope key |
| `run_id` | no | slug-safe collection-run id |

A fact may carry the raw identifier of the scope it came from (`account`,
`tenant`, `subscription`, `compartment`, `project`, `organization`, or `host`
for an on-premises scan target) on input.
It is exported only when a deployment-private scope key is supplied (an opaque
scope id is derived from it) or an opaque `scope` alias is set; otherwise the
fact is refused with the field named. The raw value never enters an evidence
object, a pointer or a hash. The package layer learns nothing about the
platform from the fact shape; that is what lets one SDR pipeline accept
evidence from any source.

## Adding a source with a mapping file, not Python

A provider on any platform adds an evidence source by writing one JSON file
against `automation/collectors/adapter-mapping.schema.json`. It names where in
the customer-produced export the check id, the source's status, the
observation time and the location live, how the source's status words
normalize to `PASS`, `FAIL` or `UNKNOWN`, and which KSIs the facts support:

```json
{
  "schema": "fedramp-adapter-mapping/v1",
  "name": "example-posture-scanner",
  "service": "example-posture",
  "source_type": "posture-findings",
  "evidence_type": "Report",
  "export_format": "jsonl",
  "fields": {
    "check": "finding.type",
    "status": "finding.state",
    "observed_at": "finding.event_time",
    "location": "resource.location",
    "detail": "finding.title",
    "scope": {"path": "resource.project", "kind": "project"}
  },
  "status_normalization": {"ACTIVE": "FAIL", "INACTIVE": "PASS", "MUTED": "UNKNOWN"},
  "ksi_targets": ["KSI-MLA-EVC", "KSI-MLA-OSM"],
  "checks": ["PUBLIC_BUCKET_ACL", "OPEN_FIREWALL", "MFA_NOT_ENFORCED"],
  "check_bindings": {"MFA_NOT_ENFORCED": ["KSI-MLA-OSM"]}
}
```

`checks` lists every check value the export can carry, as it appears in the
export; each one is bound to the `ksi_targets` (or to its own `check_bindings`
list) in the source registry the provenance gate reads. Every binding is
declared; nothing is inferred from a name.

Exports may be JSON lines, CSV (header row; paths are column names), a JSON
document (an array, or an object with `records_path`), or an XCCDF results
document (`"export_format": "xccdf"`, described below). Then, in the offering
profile, declare the source with both paths; the key must equal the mapping's
`name`:

```json
"evidence_sources": {
  "example-posture-scanner": {
    "enabled": true,
    "mapping_path": "automation/collectors/fixtures/mapping/example-posture-scanner.mapping.json",
    "export_path": "automation/facts/posture-export.jsonl"
  }
}
```

and run the same driver. What the adapter guarantees, each with a regression
test and a killed mutation:

- Offline by construction. It reads the export file; there is no client and no
  credential. A test fails if a socket is opened.
- Every fact meets the fact contract above, or the batch is refused naming the
  field. A record with no observation time is refused, never given a
  timestamp.
- A source status with no entry in the normalization table becomes `UNKNOWN`,
  never `PASS`, and the source's own state is kept in `detail`.
- An export with no records yields nothing and reports a collection outcome
  of `not-run`; nothing is attached, because an empty export is not a clean
  posture.
- A mapping naming a KSI id that is not in the pinned KSI profile refuses to
  register, naming the id.
- Each evidence entry is attached only to the KSIs its `(service, check)` pair
  is declared for, and the provenance gate accepts it only there: an export
  record whose check is not in `checks` is refused naming it (or, when the
  mapping sets `"undeclared_checks": "skip"` for an export whose record set
  the provider does not control, yields no fact and is counted and named in
  the adapter's health record), and a signed
  entry claiming an undeclared check, or a declared check under a KSI it is
  not bound to, blocks under production-assurance and is a readiness finding
  under the development profile.
- A record's raw scope identifier (`account`, `tenant`, `subscription`,
  `compartment`, `project`, `organization`, `host`) rides on the fact under the
  kind the mapping declares, so it is refused without `SDR_EVIDENCE_SCOPE_KEY`
  and replaced by an opaque scope with it. It never enters the package.

Dry run without touching the record store:

```bash
python automation/collectors/mapping_adapter.py MAPPING.json EXPORT
```

The example mapping and its two exports (JSON lines and CSV, same records)
live in `automation/collectors/fixtures/mapping/`; every value is fictional.
A source owned by another organization also records `documentation` (the
owner's public page for the export format and the date it was read) in the
mapping, per `THIRD_PARTY_NOTICE.md`.

## On-premises scan results (XCCDF or ARF)

A provider with no cloud at all turns a benchmark scan into KSI-bound facts the
same way: a mapping with `"export_format": "xccdf"`. The reader
(`automation/collectors/xccdf_reader.py`) accepts an XCCDF 1.1 or 1.2 results
document or an ARF result data stream, which is what an OpenSCAP scan writes,
and yields one record per `rule-result` with the fields `rule_id`, `result`,
`time`, `target`, `benchmark`, `profile`, `severity`, `weight`, `test_result`
and `summary`. The mapping names them:

```json
{
  "schema": "fedramp-adapter-mapping/v1",
  "name": "example-openscap-xccdf",
  "service": "openscap",
  "export_format": "xccdf",
  "undeclared_checks": "skip",
  "fields": {
    "check": "rule_id",
    "status": "result",
    "observed_at": "time",
    "detail": "summary",
    "scope": {"path": "target", "kind": "host"}
  },
  "status_normalization": {"pass": "PASS", "fail": "FAIL", "notchecked": "UNKNOWN", "fixed": "UNKNOWN"},
  "ksi_targets": ["KSI-MLA-EVC"],
  "checks": ["xccdf_com.example_rule_audit_logging_enabled"],
  "check_bindings": {"xccdf_com.example_rule_audit_logging_enabled": ["KSI-MLA-LET", "KSI-MLA-EVC"]},
  "documentation": {"url": "https://csrc.nist.gov/schema/xccdf/1.2/xccdf_1.2.xsd", "captured": "2026-10-15"}
}
```

Three things differ from a vendor export, each with a regression test and a
killed mutation:

- The result vocabulary is the XCCDF standard's, not the provider's. Only
  `pass` is `PASS` and only `fail` is `FAIL`; `error`, `unknown`,
  `notapplicable`, `notchecked`, `notselected`, `informational` and `fixed`
  (which the standard defines as "had failed, but was then fixed", with no
  re-check implied) are `UNKNOWN`. A `status_normalization` table that relabels
  any of these is refused naming the key, and the standard's full table applies
  even when the mapping lists only some values, so an omitted `fail` is still
  `FAIL`. The scanner's own result word is kept in `detail`.
- A benchmark scan reports every rule in the benchmark, so the mapping sets
  `"undeclared_checks": "skip"`: a rule the provider has not bound to a KSI
  yields no fact, is counted and named in the adapter's health record, and is
  printed by the apply driver. Nothing unbound is exported and nothing is
  silent. Which rules are evidence toward which KSIs is the provider's
  declaration in `checks` and `check_bindings`.
- The scan target (the host name the `TestResult` records) rides on the fact
  only as a raw `host` scope. It never appears in `detail`, conversion without
  `SDR_EVIDENCE_SCOPE_KEY` is refused naming it, and with the key it becomes an
  opaque scope in the pointer, so two hosts never share an evidence location
  and no host name or address enters the package.

A rule-result without its own `time` inherits the `TestResult` end time; a
document with neither is refused by the fact contract rather than dated by the
adapter. A document carrying a DOCTYPE is refused (scanner output never has
one). The fixture `example-openscap-xccdf.results.xml` is fictional end to end
(the `com.example` namespace, a host under the reserved `.example` domain, a
documentation-range address) and is shaped from the NIST schema and the
OpenSCAP user manual cited in its header. Running scans is out of scope: the
adapter reads the file a scan already wrote.

## Cloud findings exports (one record per resource)

A findings export reports one record per resource: one finding per bucket, per
firewall rule, per key. The pointer identity above (service, check, opaque
scope, region) would put every finding of one category in one project and
region at one evidence location, and the record store keeps one entry per
location, so a resolved finding would replace a still-active one (AUD-F77).
A mapping for such a source therefore names the record's own identity:

```json
{
  "schema": "fedramp-adapter-mapping/v1",
  "name": "example-google-cloud-scc",
  "service": "google-cloud-scc",
  "export_format": "json",
  "records_path": "findings",
  "undeclared_checks": "skip",
  "fields": {
    "check": "finding.category",
    "status": "finding.state",
    "observed_at": "finding.eventTime",
    "location": "resource.location",
    "detail": "finding.description",
    "scope": {"path": "resource.projectDisplayName", "kind": "project"},
    "record_id": "finding.name"
  },
  "status_normalization": {"ACTIVE": "FAIL", "INACTIVE": "UNKNOWN", "STATE_UNSPECIFIED": "UNKNOWN"},
  "ksi_targets": ["KSI-MLA-EVC"],
  "checks": ["PUBLIC_BUCKET_ACL", "OPEN_FIREWALL", "MFA_NOT_ENFORCED"],
  "check_bindings": {"PUBLIC_BUCKET_ACL": ["KSI-CNA-MAT", "KSI-MLA-EVC"], "OPEN_FIREWALL": ["KSI-CNA-RNT"], "MFA_NOT_ENFORCED": ["KSI-IAM-APM"]},
  "documentation": {"url": "https://cloud.google.com/security-command-center/docs/reference/rest/v1/organizations.sources.findings", "captured": "2026-10-15"}
}
```

What `record_id` adds, each with a regression test and a killed mutation:

- The raw record identity (here `finding.name`, which carries the organization
  id) never enters the package. With `SDR_EVIDENCE_SCOPE_KEY` it becomes an
  opaque `rec-...` id, keyed like the scope id so it cannot be brute-forced
  from a low-entropy name, stamped on the sanitized source fact and appended
  to the pointer after the region. Without the key the fact is refused naming
  the field: dropping the id would collide pointers, exporting it would leak
  it.
- The same finding keeps the same pointer across exports, so a later
  observation of it replaces the earlier one, while two findings of one
  category never share a pointer. After two exports in which one finding went
  `INACTIVE`, the store holds both records and the still-active one still
  reads `FAIL`.
- A batch in which two facts resolve to one pointer is refused naming the
  pointer and the `record_id` remedy. Nothing of that batch is attached.
- Sources that report one value per check and scope (the AWS Config path)
  carry no `record_id`, and their pointer form is unchanged.

The state words are the source's published enum, and a findings export states
no pass: `ACTIVE` is a problem the source still reports (`FAIL`); `INACTIVE`
covers a fixed finding and one a person closed as not an issue, which the
export cannot tell apart, so it is `UNKNOWN` with the state kept in `detail`.
A muted `ACTIVE` finding stays `FAIL`; a state outside the enum is `UNKNOWN`.
The fixture `example-google-cloud-scc.export.json` is fictional end to end
(all-zero organization and source numbers, `fictional-` project names) and is
shaped from the owner's public API reference cited in its header and in the
mapping, per `THIRD_PARTY_NOTICE.md`. Category-to-KSI bindings in the example
are the provider's declaration, for illustration only.

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
