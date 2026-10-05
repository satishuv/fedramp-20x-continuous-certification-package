# Getting started

Goal: a validated Security Decision Record on your machine, and a clear picture of what to fill in next. Budget five minutes.

## Prerequisites

Python 3.10 or later, and three packages.

```bash
pip install -r requirements.txt
```

No AWS account is needed. Nothing in the build path makes a network call: the FedRAMP dataset and both official schemas are pinned in the repository.

## One command

```bash
git clone https://github.com/satishuv/fedramp-20x-continuous-certification-package.git
cd fedramp-20x-continuous-certification-package
python sdr.py all
```

`sdr.py` is a thin orchestrator. It runs the build steps in dependency order, then the validator, then the readiness scanner, then prints a summary. Available subcommands:

| Command | What it does |
|---|---|
| `python sdr.py build` | Regenerates every deliverable |
| `python sdr.py validate` | Runs the full validation gate and offline test suite. Exit code is non-zero on a hard failure |
| `python sdr.py scan` | Runs the readiness scanner and writes findings |
| `python sdr.py all` | Build, then validate, then scan, then summarize |
| `python sdr.py explain <rule/KSI>` | Explains one rule or indicator: requirement text, force, applicability, your record's status, and evidence |
| `python sdr.py diff [old] [new]` | Shows what a dataset change would affect (read-only change impact) |
| `python sdr.py review` | Reports the human review register (read-only) |
| `python sdr.py release` | Build, full gate, and the reproducibility double-build, then prints the release tag |
| `python sdr.py package-preflight` | Checks the generated package for submission blockers (read-only) |
| `python sdr.py application-preflight` | Package checks plus FedRAMP application prerequisites (read-only). `preflight` is an alias |
| `python sdr.py clean` | Removes Python caches and scanner reports. Leaves generated deliverables alone, because they are committed on purpose |

If you have GNU make, `make build`, `make validate`, `make scan`, and `make all` wrap the same commands. `make reproducible` runs the build and then the same git diff the continuous integration gate runs.

## What you should see

The validator prints fourteen checks and one gating line:

```text
PASS: official_schema_validation | 0 schema errors
PASS: dataset_version_agreement | pinned dataset info.version 2026.09.13.02 vs profile 2026.09.13.02
PASS: pinned_schema_version_guard | all 9 pinned schemas match expected $id and version
PASS: rule_coverage | missing: [] extra: [] (158/158 rules)
PASS: ksi_coverage | 46/46 KSIs present
PASS: ksi_required_fields | all KSIs carry the six schema-required fields
FAIL: ksi_test_minimums | 43 KSIs below the FRC-CSX-VVK minimum for class B (SHOULD at Class B; advisory)
PASS: no_markdown_in_human_readable | hits: []
PASS: no_sensitive_patterns | hits: []
PASS: content_fidelity_against_dataset | 0 mismatches
PASS: semantic_completeness_cr26 | 0 required semantic elements absent
PASS: no_stale_nist_800_63_3 | no superseded SP 800-63 edition referenced
FAIL: evidence_linkage_for_populated_musts | populated KSIs with no evidence (SHOULD at Class B; advisory)
PASS: sources_lock_consistency | every pinned source matches its recorded sha256
hard failures: 0
```

Then `sdr.py all` closes with a summary:

```text
Readiness summary
Certification class          Class B
Build gate                   BUILD PASS - structurally valid, hard failures: 0
Checks                       12 of 14 passing
Advisory failures            ksi_test_minimums, evidence_linkage_for_populated_musts
Dataset                      deterministic check against dataset 2026.09.13.02
Assessment readiness         24.3% (531 pass, 1657 fail, 407 manual of 2595 findings)
```

The two `FAIL` lines are expected and correct on a fresh clone. Both are `SHOULD`-force at Class B, so they are advisory during authoring: `ksi_test_minimums` reflects `FRC-CSX-VVK` (a per-indicator automated-method target that rises by class - `SHOULD` at B with at least one method, `MUST` at C with at least two), and `evidence_linkage_for_populated_musts` reflects that a populated KSI should carry evidence (`MUST`, and hard, only at Class C/D). A template has neither yet. `hard failures: 0` is the line that gates the build; at Class C/D these advisories become hard.

24.3 percent readiness is also the correct starting number. It measures how much of your record is filled in with facts, not how secure your system is.

## Running the steps by hand

`sdr.py build` runs the full pipeline (20 steps) so you do not have to, but the order matters if you run them individually, because each step consumes the previous step's output. The steps, in order, are:

1. `validate_upstream.py` - validate the pinned dataset against the official rules schema and the lock hashes
2. `build_catalogs.py` - rule and indicator catalogs from the pinned dataset
3. `build_notes.py` - per-rule notes and family name expansions
4. `build_profiles.py` - per-class profiles, the Class C overlay, the Class D register
5. `build_collector_registry.py` - indicator to read-only AWS check map
6. `build_sdr.py` - the official JSON, the extensions companion, and the plain-text record
7. `build_cpo.py` - the Certification Package Overview (`CPO-CSO-OVR`)
8. `build_ocr.py` - an example Ongoing Certification Report (`CCM-OCR-AVL`)
9. `build_scg.py` - the Secure Configuration Guide scaffold (`SCG-CSO-RSC/AUP`)
10. `build_events.py` - example incident, significant-change, and vulnerability artifacts
11. `automation/exporters/oscal_export.py` - the OSCAL export of the SDR
12. `build_docx.py` - the authoring Word document
13. `build_crosswalk.py` - the NIST SP 800-53 Revision 5 to 20x crosswalk
14. `build_applicability_decisions.py` - the applicability decision ledger (included and excluded, with reasons)
15. `build_assurance_graph.py` - the unified assurance graph joining every artifact
16. `build_sbom.py` - the CycloneDX software bill of materials of the framework's own pinned dependencies
17. `build_release_manifest.py` - the cryptographic release manifest of the package (fingerprints the SBOM)
18. `validate_package_consistency.py` - the cross-artifact consistency check
19. `build_reports.py` - the evidence-coverage and reviewer reports
20. `build_visualization.py` - a self-contained HTML assurance-graph view

Build scripts live in `validation/scripts/` except where a path is shown. If a step fails, the build stops, because later steps read what it writes.

## Choosing your class

The repository ships set to Class B. Change one field in `profiles/common/offering-profile.json`:

```json
{
  "certification_class": "C"
}
```

Then rebuild with `python sdr.py all` (or `python sdr.py build`). See [certification classes](certification-classes.md) for what changes between them.

## Adoption models: greenfield and brownfield

The framework never assumes how or when your offering was built. It reads whatever posture exists in the account when it runs, so it fits both a new offering and an existing one. FedRAMP's own rules do not distinguish new from existing systems; obligations are set by certification class (A to D), not by system age. Greenfield and brownfield are a practical lens, not a FedRAMP distinction.

**Greenfield** (a new offering built for 20x): add the framework at the start, so the record grows with the system and each indicator narrative is written as the capability is built. The living-SDR loop banks the up-to-one-year metric history from day one, which matters because that history cannot be backfilled. The only caveat is that a brand-new system has little posture to collect until it is actually running, so early runs correctly report many not-enabled results.

**Brownfield** (an existing offering adopting 20x, often the more common case): point the read-only collectors at your existing account and let the pre-fill map the collected facts into a populated starting draft rather than a blank template. Three honest frictions apply: the metric history still starts accumulating only at adoption; an established account usually needs a remediation pass, because the collectors surface real drift honestly; and the governance-evidence indicators still require you to wire up the evidence location the Config custom rules check.

Either way the pipeline, the build gate, the drift check, and the trust boundary are identical — neither path shortcuts human verification or independent assessment.

## Describing your offering

Still in `profiles/common/offering-profile.json`, replace the placeholder identity fields: `organization_name`, `offering_name`, `offering_abbreviation`, `business_purpose`, `service_model`, `deployment_model`, `aws_partition`, `primary_region`, `dr_region`, `iac_technology`. These feed the metadata block that `SDR-CSO-MTD` requires.

Set `sdr_last_updated` when your content genuinely changes. It is manual on purpose: generated files carry no automatic timestamps, so that two builds of unchanged inputs stay byte-identical.

## Then what

Open `sdr/records/records-store.json`. It has 168 rule entries and 46 indicator entries, each pre-populated with `TBD` markers and inline guidance describing what the requirement is looking for.

Do not start at the top. Run the readiness scanner and let it order the work for you:

```bash
python automation/sdrscan/sdrscan.py --only-fails --severity critical,high
```

Every finding names the rule that makes it a requirement and the exact JSON path to fix. Work the critical findings first. The [implementation guide](implementation-guide.md) walks through a single entry end to end.

## Understanding one requirement

To see what a single rule or indicator asks for and how your record currently addresses it, in plain language:

```bash
python sdr.py explain FRC-CSO-PKG
python sdr.py explain KSI-CNA-RNT
```

The output is grounded: the requirement text, force (MUST/SHOULD/MAY), and class applicability come verbatim from the pinned dataset, and the status, implementation, and evidence come from your record store. It states what is not yet filled rather than inventing text, and it never makes a compliance determination.

## Checking submission readiness

The build gate answers "is this package well-formed?" A separate, stricter check answers "is this package ready to submit?" - a field-level readiness gate that reports exactly what still blocks submission:

```bash
python sdr.py package-preflight
python sdr.py application-preflight
```

`package-preflight` checks the generated package (every required SDR field answered, CPO required-information structurally complete, evidence resolvable, the class-correct assessment and availability rules satisfied, and a human signoff bound to the current release manifest). `application-preflight` adds the FedRAMP application prerequisites (marketplace listing, application form). Both are read-only, exit non-zero while anything blocks, and never author an approval. A bare `TBD`, an unjustified `N/A`, a missing Recognized-assessor id, or an input changed after signoff all keep it blocked. See [validation and readiness](validation.md#submission-readiness-preflight) for the full model.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `ModuleNotFoundError: No module named 'jsonschema'` | Install the three prerequisites above. Note that `python-docx` imports as `docx`, which trips people up |
| The validator reports content fidelity mismatches | You hand-edited a generated file. Regenerate with `python sdr.py build`. The files you edit are the record store and the offering profile, never a generated deliverable |
| Word files differ between builds | Not expected since 1.5.0. The `.docx` is byte-reproducible (fixed zip entry timestamps, dataset-derived core properties) and the gate diffs and fingerprints it like every other output. A differing `.docx` means a changed input, a hand edit, or sample residue |
| Continuous integration fails on a stale check catalog | You changed `automation/sdrscan/checks.py` without regenerating the catalog. Run `python automation/sdrscan/sdrscan.py --write-catalog` |
| The drift check opened an issue | FedRAMP changed a pinned source. That is the system working. See [validation](validation.md#upstream-drift) |
| `Class D SDR generation is not supported` | Correct behavior. Class D is FedRAMP pending, so there is nothing to generate. Read `profiles/class-d-future/readiness-register.json` instead |
