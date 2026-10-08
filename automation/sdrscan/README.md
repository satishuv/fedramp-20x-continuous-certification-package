# sdrscan

An assessment-readiness scanner for FedRAMP 20x Security Decision Records, built the way [Prowler](https://github.com/prowler-cloud/prowler) is built.

Prowler scans a cloud account and reports one finding per resource per check, each carrying a severity, a remediation, and a mapping to the compliance framework that makes it a requirement. `sdrscan` does the same thing for the documentation FedRAMP actually asks providers to produce.

| | Prowler | sdrscan |
|---|---|---|
| Target | A cloud account | A Security Decision Record |
| Resources | EC2 instances, buckets, roles | The record itself, each FedRAMP Rule (FRR), each Key Security Indicator (KSI) |
| Checks | Hundreds of provider checks | 38 checks over three resource types |
| Framework mapping | `--compliance cis_2.0_aws` and friends | The FedRAMP Consolidated Rules for 2026 (CR26) dataset, pinned in `references/` |
| Statuses | PASS, FAIL, MANUAL, MUTED | The same four |
| Outputs | OCSF JSON, CSV, HTML | FedRAMP-vocabulary JSON, CSV, HTML, plain text, rule-coverage CSV |
| Muting | Mutelist with justification | The same, plus a mandatory expiry date |
| Exit code | 3 when findings fail | The same, with `--ignore-exit-code-3` |

## Why this exists

Two CR26 rules ask for precisely this tool, and neither can be satisfied by hand.

**CDS-CSO-CBF** (MUST, all classes): *"Providers MUST use automation to ensure information remains consistent between human-readable and machine-readable formats when FedRAMP Certification Data is provided in both formats."*

**FRC-CSX-VVR** (SHOULD at Classes B, C and D; MAY at Class A): *"Providers seeking 20x Class B Certification SHOULD implement automated methods to persistently verify and validate the accuracy and completeness of the Security Decision Record for FedRAMP rules when applicable."*

A scanner emitting per-resource findings is how you answer those two with evidence rather than an assertion. The `sdr_format_consistency` check is the direct implementation of CDS-CSO-CBF: it compares every identifier and every implementation status across the two renderings and fails on a single-word divergence.

## Does FedRAMP really ask for both formats?

Yes, in ten separate rules. Every row below is verified against the pinned CR26 dataset, version 2026.10.05.01, not recalled:

| Rule | Force | What it requires |
|---|---|---|
| SDR-CSO-FRR | MUST | Supply the Security Decision Record "in both human-readable and JSON formats", covering seven listed items for each applicable rule |
| FRC-CSO-JSN | MUST | Machine-readable information must be valid against the corresponding FedRAMP JSON schema |
| CDS-CSO-CBF | MUST | Use automation to keep the two formats consistent |
| CDS-CSO-PUB | MUST | Publicly share up-to-date offering information in both human-readable and JSON formats |
| CDS-CSO-IRP | MUST | Supply a human-readable and machine-readable reference for every included policy and procedure |
| CPO-CSO-OVR | MUST | Certification Package Overview in both human-readable and JSON formats |
| SCN-CSO-HRM | MUST | All Significant Change Notifications and related audit records in human-readable and JSON formats |
| CDS-TRC-PAC | MUST | Trust centres must provide documented programmatic access to all Certification Data, including to human-readable materials |
| CDS-TRC-HMR | SHOULD | Trust centres should offer both formats to view and download |
| CCM-OCR-AVL | MUST | An Ongoing Certification Report every 3 months in a consistent human-readable format |

Three more rules require a human-readable form for adjacent artifacts: MKT-IAS-WEB and MKT-CAS-WEB for assessor and advisor web sites, and VER-TFR-MHR for monthly vulnerability reporting.

One limitation is worth stating plainly rather than glossing over, because it shapes what "FedRAMP shaped" can honestly mean here. **FedRAMP publishes no schema for scan or findings output.** CR26 references exactly ten official JSON schemas:

Security Decision Record, Certification Package Overview, Ongoing Certification Report, Incident Report, Significant Change Notifications, Assessor Information, Advisor Information, Vulnerability Detail Report, Accepted Vulnerability Info, and Historical Verification Activity.

None of them describes a scanner's results. There is no FedRAMP equivalent of OCSF.

So `sdrscan`'s report format is its own. What makes it FedRAMP shaped is that it speaks FedRAMP's vocabulary throughout: findings key on real rule and indicator identifiers, every check cites the rules that make it a requirement, every finding quotes the verbatim FedRAMP requirement text it tests, and statuses use the official `Implemented` / `Not Implemented` / `Partially Implemented` enum. Every report carries a `reportNote` saying exactly this, so nothing downstream mistakes a scan report for a FedRAMP submission.

## Quickstart

```bash
# Generate the record first. sdrscan reads it; it does not build it.
python validation/scripts/build_sdr.py

# Scan. Class comes from profiles/common/offering-profile.json.
python automation/sdrscan/sdrscan.py

# Just the problems, without the passing noise.
python automation/sdrscan/sdrscan.py --only-fails

# What would block a Class C submission specifically?
python automation/sdrscan/sdrscan.py --class c --severity critical,high --only-fails

# What does the tool check, and on whose authority?
python automation/sdrscan/sdrscan.py --list-checks
```

## What the output looks like

Terminal, verbatim:

```
sdrscan 1.0.0  class B  dataset 2026.10.05.01
Example PaaS Foundation

FAIL   high          KSI-CED-RAT    ksi_automation_verified
       automation_verification: field still holds a placeholder marker
       basis: SDR-CSX-KSI, FRC-CSX-VVK
       fix:   Record how the automation was verified, or state why automation is unnecessary for this measure.
       at:    sdr/records/records-store.json -> ksi.KSI-CED-RAT.extension.automation_verification

Summary
  FAIL   1657
  PASS   531
  MANUAL 407
  MUTED  0
  readiness 24.3 percent of decidable findings
  failing severities: high 1459, medium 198
```

Every failing finding names the rule behind it, the risk of leaving it, and the exact path to edit. Placeholders in the path are resolved to the real identifier, so it is copy-pasteable.

One finding in JSON, verbatim:

```json
{
  "findingId": "frr_implementation_explained/AFC-CSO-ACK",
  "checkId": "frr_implementation_explained",
  "checkTitle": "Rule implementation is explained",
  "status": "FAIL",
  "statusDetail": "frrImplementation: field still holds a placeholder marker",
  "severity": "high",
  "resourceType": "FedRAMP Rule",
  "resourceId": "AFC-CSO-ACK",
  "resourceName": "Acknowledge Receipt",
  "certificationClass": "B",
  "fedRampBasis": ["SDR-CSO-FRR"],
  "fedRampRequirement": "Explanation of how the rule is followed, or an explanation of the reason and resulting risk to customers for not following the rule.",
  "risk": "This is the first of the seven items SDR-CSO-FRR requires for every rule; a placeholder here means the rule is undocumented.",
  "remediation": {
    "description": "Replace the placeholder with the provider's real implementation.",
    "location": "sdr/records/records-store.json -> frr.AFC-CSO-ACK.implementation"
  },
  "muted": false
}
```

`fedRampRequirement` holds the FedRAMP item text verbatim from the dataset. That is the difference between a checklist and a traceable verification artifact: an assessor can read the finding and the requirement without leaving the file.

## Output files

Reports land in `validation/reports/sdrscan/`:

| File | Purpose |
|---|---|
| `sdrscan-class-<x>.json` | Full machine-readable findings, with `reportNote`, `scan`, `summary`, `fedRampRuleRollup` and `findings`. Feed this to a dashboard or ticket system. |
| `sdrscan-class-<x>.csv` | One row per finding, for a spreadsheet or pivot table. |
| `sdrscan-class-<x>.html` | Self-contained report, no external assets and no network calls, so it opens on a locked-down workstation. |
| `sdrscan-class-<x>.txt` | Plain text, no markup, for pasting into a ticket or printing. |
| `sdrscan-class-<x>-fedramp-rule-coverage.csv` | The compliance-framework view: MET / NOT MET / NEEDS REVIEW per FedRAMP rule. |

A full Class B scan writes about 6 MB across those five files, so they are gitignored rather than committed. The scan is deterministic, so anyone can reproduce a report exactly from a given commit, and continuous integration uploads them as build artifacts.

## What it checks

38 checks over three resource types. Every check names the CR26 rules that make it a requirement; a check with no basis does not belong in the registry. The full registry with severities, risks and remediations is in [check-catalog.json](check-catalog.json), regenerated with `--write-catalog` and gated in continuous integration so it cannot drift from the code.

The record as a whole, 9 checks: schema validity against the official FedRAMP SDR schema, the three metadata items SDR-CSO-MTD requires (version, date and time of last update, source of update), the Certification Package Overview link, both formats present, consistency between the two formats, the dataset version being the pinned one, no markup in the human-readable rendering, no account identifiers or key material anywhere, and record freshness.

Each applicable FedRAMP rule, 12 checks: all seven items SDR-CSO-FRR enumerates (implementation explained, verification, validation, independent verification, independent validation, responses to assessor comments, rule-specific artifacts), plus status validity, a named owner, statement fidelity against the dataset, the customer-risk statement that non-conformance requires, and senior official acceptance where a rule is not implemented.

> A gap worth knowing about. SDR-CSO-FRR requires seven items per rule, but the official SDR schema carries only three statement fields (`frrImplementation`, `frrValidation`, `frrAssessment`). Items 4 through 7 have no official field to live in. This framework puts them in the extensions companion (`sdr/json/sdr-class-<x>-extensions.json`) and scans them there, so a record can satisfy the rule rather than only the schema.

Each applicable Key Security Indicator, 16 checks at Class C: all five items SDR-CSX-KSI enumerates, the automated-method minimum from FRC-CSX-VVK, evidence presence and evidence typing, the three historical metrics from SDR-CSX-KMT, a named owner, statement fidelity, status validity, annual independent assessment, and an honesty check that an indicator with no published statement anywhere in CR26 (no top-level statement and no per-class statement under varies_by_class, derived from the dataset rather than a hardcoded list) is carried as FedRAMP pending rather than quietly marked done.

Class applicability is enforced per check rather than bolted on afterwards, so the totals differ by class: 34 checks at Class A, 36 at Class B, 37 at Class C.

| Requirement | Class A | Class B | Class C |
|---|---|---|---|
| Automated methods per indicator (FRC-CSX-VVK) | MAY, minimum 0 | SHOULD, minimum 1 | MUST, minimum 2 |
| Summary of each metric over the past 30 days (SDR-CSX-KMT) | MAY, not checked | MUST | MUST |
| Summary of metric up to the past year (SDR-CSX-KMT) | MAY, not checked | MUST | MUST |
| All daily metric data up to the past year (SDR-CSX-KMT) | not required | not required | MUST |
| Historical metrics from persistent validation (FRC-CSX-MOT) | MAY | SHOULD | MUST, at least 6 months |

## The four statuses

They mean different things and are not interchangeable.

- PASS: the record demonstrably satisfies the requirement.
- FAIL: it does not.
- MANUAL: a person has to decide, and the record cannot prove it either way. "No rule-specific artifacts are recorded, confirm none apply" is a real question, not a defect.
- MUTED: failing, but suppressed by a mutelist entry carrying a justification and an expiry.

`readiness_percent` counts only PASS and FAIL, deliberately. If MANUAL findings counted, a record could improve its score by having more undecidable checks, which is backwards. Muted findings are excluded too, so muting never inflates the number.

## Muting

Copy [mutelist.example.json](mutelist.example.json) to `mutelist.json`, which is gitignored because a mutelist belongs to a deployment rather than to the template.

Every entry needs a `justification` and an `expires` date. Entries missing either are ignored outright, which is deliberate: an undated, unexplained mute is how a gap goes missing. Muted findings stay visible in every output with their justification attached.

Never mute a critical finding to turn a pipeline green. Fix it, or seek the certification class whose requirements you actually meet.

## How this fits the rest of the framework

The repository has two verification tools answering different questions. They are not redundant.

```
build_*.py  ---->  validate_sdr.py  ---->  sdrscan.py
 generate           is the build            is the content ready
                    sound?                  for an assessor?
```

[validate_sdr.py](../../validation/scripts/validate_sdr.py) is the build gate. Fourteen aggregate checks, one exit code, runs on every commit. It answers "is the generated package structurally sound and faithful to the dataset". It protects the build and must stay green.

`sdrscan.py` is the readiness scanner. Thousands of per-resource findings, severity-ranked, each with a remediation. It answers "what is still missing before an assessor signs this". It is expected to report failures against a template, because a template genuinely has open gaps. It drives the work rather than gating it.

Both run in continuous integration: the gate blocks the pipeline, the scan attaches its reports for the human approver to read before publication.

## Deterministic by default

Two scans of unchanged inputs produce byte-identical reports. Reports are stamped with the pinned dataset version rather than the run time (`"generated": "deterministic scan against dataset 2026.10.05.01"`), and record freshness is measured against the dataset date rather than today. This is verified by scanning twice and hash-comparing all five outputs.

Pass `--timestamp` for an operational run where you want the real UTC time recorded. It is off by default so determinism is what you get without having to think about it.

## Options

| Flag | Effect |
|---|---|
| `--class {a,b,c}` | Override the class from the offering profile. Class D specifics are FedRAMP pending. |
| `--check ID` | Run only this check. Repeatable. |
| `--exclude-check ID` | Skip this check. Repeatable. |
| `--severity critical,high` | Report only these severities. |
| `--resource-type ...` | Report only one resource type. |
| `--only-fails` | Print failing findings and those needing a human; skip the passes. |
| `--output-formats json,csv,html,txt` | Which files to write. `none` writes nothing. |
| `--output-dir PATH` | Where to write them. |
| `--list-checks` | Print the registry with severities and rule bases, then exit. |
| `--write-catalog` | Regenerate `check-catalog.json`, then exit. |
| `--timestamp` | Stamp with the real run time instead of the dataset version. |
| `--no-colour` | Disable ANSI colour. |
| `--ignore-exit-code-3` | Exit 0 even when findings fail, for reporting rather than gating. |

Exit codes: `0` clean, `3` findings failed, `1` the scan could not run.

## What it does not do

Being explicit about this matters more than the feature list.

- It never changes a status. No check writes to the record store. Moving something to Implemented requires real evidence plus a human, and no scanner supplies either.
- It does not read your cloud account. That is [automation/collectors/](../collectors/), which is read-only by construction. `sdrscan` reads documentation only.
- It does not judge whether an implementation is any good. It reports whether the record says what FedRAMP requires it to say, in a form an assessor can use. A well-documented bad control still passes `frr_implementation_explained`, and it should; judging the control is the assessor's job.
- It is not a FedRAMP submission. FedRAMP publishes no scan-output schema, and every report says so.

## Sources

Every requirement quoted here was checked against the pinned dataset while writing this file, not recalled:

- [references/fedramp-consolidated-rules.json](../../references/fedramp-consolidated-rules.json), CR26 version 2026.10.05.01, from [github.com/FedRAMP/rules](https://github.com/FedRAMP/rules)
- [artifacts/schemas/official/](../../artifacts/schemas/official/), the FedRAMP Security Decision Record and common definitions schemas dated 2026-06-24
- [fedramp.gov/2026/rules](https://www.fedramp.gov/2026/rules/), the published rules

The pinned copies are hash-compared against upstream every day by the [drift-check workflow](../../.github/workflows/drift-check.yml), because FedRAMP updates schema files in place without renaming them.
