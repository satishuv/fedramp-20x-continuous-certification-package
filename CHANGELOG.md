# Changelog

Notable changes to this project. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

One project-specific convention: the pinned FedRAMP dataset version is recorded alongside every release, because the same code against a different dataset produces a different record.

## Unreleased

Pinned dataset: `2026.09.13.02` (unchanged)

Evidence-path hardening (external end-to-end audit of `2f72a15`, 2026-09-26;
three findings, all reproduced with the public helpers before fixing;
`AUD-F26`..`AUD-F28` in the defect ledger, each with a killed mutation):

- **The evidence digest now binds the whole displayed assertion (AUD-F26,
  High).** `xEvidenceContentHash` (and therefore the KMS signature over it) is
  computed over `evidence_wiring.canonical_payload(entry)` - evidenceType,
  evidenceDescription, evidenceLocation, evidenceText, lastUpdated and the
  sanitized xSourceFact - instead of the sanitized fact alone. Rewriting
  `evidenceDescription` beside a "verified" digest previously stayed
  `verified`; it is now a HARD `INTEGRITY FAILED`. The legacy inline
  `source_fact` shape (digest over the raw fact only) can only reach a
  readiness finding, never `verified`, and is HARD under a signing-required
  signer. The fail-closed "hash implementation missing" check runs before
  source resolution. BREAKING for hand-built evidence entries: produce them
  with `fact_to_evidence` (the readiness sample and attack tests now do).
- **Account scopes never collide and the account never leaks (AUD-F27,
  High).** An account-tagged fact carries an opaque `scope` (HMAC-SHA256 under
  the deployment-private `SDR_EVIDENCE_SCOPE_KEY`, or a caller-supplied
  slug-safe alias that may not be the account itself) in the signed payload and
  the evidence object key, plus the collector `run_id`. Two accounts' opposite
  findings for the same service/check/region were previously collapsed onto
  one pointer and the second (a FAIL) silently dropped by `attach_evidence`;
  both now survive with distinct pointers and digests, de-duplicated on
  (location, scope, observation). A fact tagged with an account but no way to
  derive a scope is REFUSED (`EvidenceExportError`), never dropped or exported.
  `collect_multi_account.py` stamps `run_id`/`scope` on every fact, exposes
  `scope_map()`, and `--out` writes facts plus the PRIVATE scope -> account map
  to the git-excluded facts store (an assessor's key to account-level coverage).
- **Free-form detail cannot carry identifiers into the package (AUD-F28,
  Medium).** `detail` and `status` are scrubbed (ARN, access key, key
  material, email, URL, IPv6, IPv4, account id, hostname, long opaque token)
  and length-bounded before entering an entry; object-key segments (service,
  check, region, scope, run_id) must be slug-safe. First-party collector detail
  strings are unchanged by the scrub (a regression proves it). The
  generated-bundle sensitive gate additionally flags IPv4/IPv6 addresses, ARNs
  and internal hostnames as an independent backstop.

Upstream schema adoption (no dataset change; no rule statement, force,
timeframe or KSI applicability changed):

- Adopted the September 2026 in-place updates to five official FedRAMP JSON
  schemas, verified byte-for-byte against fedramp.gov on 2026-09-26:
  common-definitions `0.3.0 -> 0.4.0` (adds a reusable
  `$defs/contactInformation` object), Certification Package Overview
  `0.1.4 -> 0.1.6` (adds an OPTIONAL top-level `advisors` array), and
  version-string-only bumps to Ongoing Certification Report `0.2.0 -> 0.2.1`,
  Incident Report `0.2.0 -> 0.2.1` and Significant Change Notification
  `0.1.2 -> 0.1.3`. Nothing required was added, so every previously valid
  document stays valid; the generated CPO and OCR re-validate against the new
  schemas. `pinned_schema_version_guard`, `references/sources.lock.json` and the
  release manifest now carry the new versions and hashes. The SDR schema
  (`1.1.1`), the CR26 dataset and rules schema, and the VER-family schemas are
  unchanged upstream.
- `update_sources_lock.py` now refreshes EVERY pinned entry from the file on
  disk (sha256, and `$schemaVersion` for JSON schemas), fails closed on a
  missing pinned file, and stamps `verified_current_on` only when the caller
  asserts `--verified-on`. A schema adoption is therefore a copy plus one
  command, never a hand-edited hash. Tests in
  `validation/scripts/test_update_sources_lock.py`.

Fixed:

- Daily drift check aborted on the first non-dataset drift. In `check()`, the
  line `[ "$NAME" = "CR26-dataset" ] && DATASET_CHANGED=1` was the function's
  last command, so under `set -e` any drifted source other than the dataset made
  `check()` return 1 and killed the step. The 2026-09-26 run reported only the
  common-definitions drift, never reached the remaining seven sources or the
  changelog check, and filed issue #188 with an empty title because the `drift`
  output was never written. Replaced with a plain `if`; the issue step now runs
  only when the check step actually recorded drift, so a download failure fails
  the run without filing a false "sources changed" issue.

## 1.5.0, 2026-09-25

Pinned dataset: `2026.09.13.02` (unchanged)

Release governance and telemetry truth. A twenty-finding review of the
`1.4.0` release concluded that the FedRAMP interpretation (the A/B/C rule
profiles reconcile exactly against the raw CR26 dataset; the 46-KSI catalog and
the five optional-at-B indicators are right) was no longer the weak point, and
that the evidence truth model and release governance were. This release fixes
the governance and telemetry findings (review items 1 through 10, 13 and 14) and
supersedes `1.4.0`. No dataset change; no change to any rule statement, force,
timeframe or KSI applicability.

Release governance:

- One release gate. `audit/release_gate.py` is the single definition of the
  audit and security sections; the CI `audit-gate` and `security-scan` jobs, the
  AWS `RELEASE_MODE` build and `python sdr.py release` all execute it. A new
  `release-gate` aggregate job depends on `validate`, `audit-gate` and
  `security-scan`, runs even when one failed, and is the single required status
  check on `main`. Before this, only `validate` was required, so a red
  audit-gate did not block a merge, and `sdr.py release` ran neither the audit
  gate nor Bandit (AUD-F12).
- Tag-driven publication. `.github/workflows/release.yml` refuses a lightweight
  or unsigned tag and a tag that does not equal the committed manifest's
  `release_tag`, re-runs the whole validate workflow on the tagged commit, and
  attaches the release manifest, the release attestation, the SBOM and the
  active-class bundle as release assets. `sdr.py release` now instructs
  `git tag -s`, matching `docs/versioning.md`.
- Mutation gate integrity. A skipped mutation (target text absent) now fails
  the gate instead of passing it, so a refactor cannot silently disarm a closed
  defect's protection (AUD-F13). The runner reconciles the defect ledger: every
  CLOSED, mutation-verified defect must map to exactly one executed, killed
  mutation and every mutation to such a defect (AUD-F14). The verdict is a pure
  function so each rule is tested in isolation, and restore writes the saved
  original bytes back rather than `git checkout`-ing over a dirty local tree.

Telemetry truth model (Class C metrics):

- Pagination. Every AWS list/describe call walks every page (botocore paginator
  when one exists, continuation token by name otherwise); a page-cap hit yields
  `OBSERVED_PARTIAL` with no ratio and is never scored (AUD-F15). Previously KMS,
  CloudFormation, Config, WAF, EC2, ECR, IAM, CodePipeline, DynamoDB, Backup and
  Access Analyzer read one page, several of them into a measured/total ratio.
- Coverage. Ratio facts carry `scope_total`, `evaluated_total` and
  `unknown_total`; unreadable resources stay in scope as unknown instead of
  vanishing from the denominator. A fact whose evaluated coverage is below the
  project floor (`MIN_EVALUATED_COVERAGE` = 0.95; an offering may tighten it via
  `telemetry_min_coverage`) is withheld from scoring, never scored as a
  failure, and named in the datapoint's `coverage_gaps`; the datapoint carries
  aggregate coverage. Only a response that establishes absence
  (`NoSuchPublicAccessBlockConfiguration`, `NoSuchLifecycleConfiguration`) is
  evaluated (AUD-F17).
- Routing by check. Every `METRIC_SOURCE_MAP` route is `service:check`; a bare
  service key is refused by the metric engine, prefill and `append_metrics`.
  Least privilege is measured by `accessanalyzer:active_findings` (a scored
  binary: zero active findings), never by analyzer presence; recovery testing
  routes `backup:restore_testing` only; data removal routes `s3:lifecycle` and
  `dynamodb:ttl`; resource integrity routes `cloudtrail:log_validation` and
  `ecr:image_immutability` (AUD-F16). The collector registry is regenerated.
- Non-destructive history. A second run on the same day no longer replaces the
  first. Every run is appended as an immutable timestamped observation under
  the KSI (retention-pruned) and the day's series point is the conservative
  rollup of that day's runs (worst passing fraction) with `runs`,
  `min_fraction` and `max_fraction`; per-metric series roll up the same way
  (AUD-F19).
- Compare-and-swap publish. `automation/metrics/publish_history.py` replaces
  the blind `aws s3 cp` down/up of `metric-history.json`: restore remembers the
  ETag, publish uses `If-Match` (`If-None-Match: *` on first run), a 412 exits 3
  and the collect buildspec retries restore, append, publish a bounded number
  of times. Every run's observations are archived append-only under
  `metrics/observations/<date>/<run>.json` (AUD-F20).
- Real method binding. `automation/metrics/method_ids.py` is the one identity
  for a verification method (registry `check_id` for a Config rule,
  `posture:<service>:<check>` for a collector check). The metric engine keys
  per-method series by it and `prefill_from_facts.py` now emits structured
  `{method_id, method, automated: true, cadence, ...}` records with it, so the
  real collector -> history -> prefill -> preflight path binds; plain-string
  tests counted as zero automated methods. A new end-to-end test drives the
  production code through fake AWS clients and asserts every prefilled method
  binds; it caught `cloudtrail:siem_capture` declaring a method that could
  never bind, which is now a scorable binary (AUD-F18).
- The FRC-CSX-MOT continuity tolerance is explicit project policy.
  `mot_max_gap_days` (default 45 days, ceiling 90) is documented as a repository
  bound, not a FedRAMP figure, is declarable in the offering profile for
  assessor review (an invalid value blocks rather than silently defaulting), and
  every preflight message names it as such. The comment that claimed a
  4x-median adaptive tolerance the code never applied is gone (AUD-F21).
- Supply chain: `requirements.lock` is a resolver-generated (uv, linux/py3.12),
  fully hashed 27-package closure of `requirements.txt` + `requirements-ci.txt`;
  every workflow and buildspec installs with `pip install --require-hashes -r
  requirements.lock`, and the SBOM is now that resolved closure with per-package
  hashes (AUD-F25). The requirements oracle independently re-derives the per-class
  FRR set, force, statement and timeframes and the enumerated Class A set from the
  raw dataset (41 / 158 / 158, reconciled clean; AUD-F22); `sdr.py validate` runs
  the authoritative validator for every supported class, which surfaced and
  fixed three example KSIs that were invalid at Class C (AUD-F23); a parity test
  that compared 0 against 0 now reads the real report key (AUD-F24).
- The implementation guide's worked Class C example now uses the structured
  automated-method shape the validator counts and explains `method_id`
  binding; the two plain strings it showed counted as zero methods.

Correction to the `1.4.0` record: the `1.4.0` release notes state a mutation
suite result of 10 killed / 0 survived. The CI run on the release commit
(`c7d43bd`) reported 9 killed / 1 survived (MUT-F10, the stale-bytecode false
survivor fixed in the entry below) and its audit-gate was red when the release
was published; the tag was unsigned and no assets were attached. The 10/0
figure came from local clean-room runs, not from the release commit's CI. The
release is left in place and superseded; its GitHub release notes carry the same
correction.

Post-`1.4.0` fixes folded into this release:

- The mutation runner (`audit/mutation_tests.py`) now purges every
  `__pycache__` before each mutated test run and forbids bytecode writes during
  it, and restores each mutated file byte-exactly with verification. Python
  trusts a cached `.pyc` when the source's size and mtime-in-seconds match; a
  length-preserving mutation (MUT-F10, 50 to 50 characters) that landed in the
  same second as a cache compiled from the original was therefore run as the
  ORIGINAL bytecode, and the audit gate reported a false SURVIVED on `main`
  (validate-sdr run 35993242564, twice). New `audit/test_mutation_runner.py`
  arms that exact trap, proves a bare run is fooled by it, and asserts the
  runner still kills the mutation; it is wired into the audit-gate job as a
  hard gate. No framework behavior, rule, or dataset change.
- The submitted SDR's daily-data window ceilings use the UTC calendar day, the
  same clock the collectors stamp datapoints with (F11, PR #178).

## 1.4.0, 2026-09-24

Pinned dataset: `2026.09.13.02`

Hard-mode audit remediation and an anti-circular-verification gate. Closes a
ten-finding builder/adversarial audit (six High, four Medium) against the CR26
`2026.09.13.02` dataset, adds two provider-integration features, and makes the
audit itself machine-enforced so a regression cannot silently return. No dataset
change and no architecture change; every fix tightens an existing gate or
corrects a reviewer-facing report, shipped CI-green with a regression that fails
on the old code and a mutation that proves the regression can detect the defect.

Metric-engine and evidence-outcome integrity:

- History is keyed by `(rule, region, account)`, so a later region can no longer
  overwrite an earlier region's result and hide a `NON_COMPLIANT` behind a
  `COMPLIANT` (F04).
- A stale fact replayed on a later run is no longer stamped as fresh; ingestion
  time and observation time are kept distinct (F05).
- Corrupt existing metric history is rejected rather than silently treated as a
  first run and overwritten (F07).
- Posture facts route by `(service, check)`, not service alone, so an unrelated
  same-service check can no longer score an unrelated KSI, and each check keeps
  its own metric identity (F03).
- A collector permission error (AccessDenied, throttling) is recorded as
  unmeasured, not as a negative outcome; only a genuine "no encryption
  configured" API response counts as a real negative (F08).
- A bounded Inspector sample with more pages available is reported as partial and
  scores nothing, instead of claiming full coverage from the first 100 records
  (F09).

Signing, verification-method binding, and clock consistency:

- Under a required signer, an unresolvable evidence source is a hard finding; the
  soft-finding early return no longer precedes the signing check (F01).
- Id-less automated verification methods are uncountable and unbindable rather
  than counted by text; the count and binding gates share one identity (F02).
- The metric-over-time continuity check measures the leading gap from the window
  start, so a series clustered near today can no longer pass a long window (F06).
- All preflight date windows read one UTC clock (`_utc_today()`) instead of the
  host's local date, so the same code and fixture cannot pass in CI (UTC) and
  fail on a machine west of UTC (F10).

Provider-integration features:

- `sdr.py init` is a plain-English offering-profile wizard (company, offering,
  class, regions, contacts, URLs), scriptable with `--set` and validated, that
  never mutates a tracked file.
- A custom AWS Config-rule importer maps a provider's own rules to KSIs through a
  gitignored `customer-config-rules.json` overlay with no code edit; the template
  stays secret-free and the registry restores byte-for-byte when the overlay is
  removed.

Anti-circular-verification gate:

- A mutation runner (`audit/mutation_tests.py`) re-introduces each of the ten
  closed defects into production code and asserts its named regression test goes
  red; a surviving mutation fails the build. It caught a real blind spot during
  the audit: the first F10 regression never exercised the UTC clock, so a
  dedicated behavioral test was added and verified to detect the mutation.
- A requirements-differential oracle (`audit/requirements_oracle.py`) reconciles
  an independent dataset traversal against the production applicability engine.
- Both run as hard gates in GitHub Actions (`audit-gate`) and on the AWS
  CodeBuild release path, and a permanent `audit/defect-ledger.json` records every
  finding with its fix, regression test, and mutation.

## 1.3.1, 2026-09-23

Pinned dataset: `2026.09.13.02`

Audit-remediation patch release. Closes the KMT-layer audit and the detailed
repo audit (F-01 through F-09) against the CR26 `2026.09.13.02` dataset. No
dataset change and no architecture change; every fix tightens an existing gate
or corrects a reviewer-facing report, verified against the pinned dataset and
shipped CI-green with an adversarial or negative test that fails on the old code.

Metric-engine truth and routing:

- `OBSERVED` posture no longer counts as passing; a measured `0 / N` contributes
  as a real negative observation rather than inflating a metric.
- Explicit negative posture (`NONE` / `NOT_ENABLED`) is scored `(0, 1)` instead of
  being dropped, so a disabled control cannot silently vanish from the denominator.
- Metric routing is bound to an explicit per-KSI `metric_service_keys` allowlist
  rather than substring-matching AWS service names in narrative prose, closing the
  fan-out where an unrelated posture could accumulate history against a KSI.
- Config-rule vocabulary is allowlist-checked and a bogus Aurora rule was removed.

Verification-method binding (FRC-CSX-VVK):

- Automated-method counting is set-based against the class minimum and counts only
  distinct structured methods, not raw test strings.
- Class C requires each declared automated method to be bound to observed per-method
  telemetry; two declared but one bound blocks, rather than clearing existentially.
  The binding stays active under the initial-certification MOT exception.
- The reviewer-facing assurance graph now uses the exact same automated-method
  counter as the authoritative validator (shared `verification_methods` module), so
  `evidence-coverage.json` can no longer report the VVK minimum as met when the
  validator says it is not.

Class B scope and process/document KSIs:

- The Class B optional-KSI scope (41 baseline, 5 optional excluded unless selected)
  is unified across the builder, validator, scanner, assurance graph, and preflight
  via a single `submitted_ksi_ids` resolver; an unknown optional selection now blocks.
- The 11 document/process KSIs carry provider-deployed outcome-metric contracts rather
  than pretending an AWS API can assess organizational-process effectiveness.

Harness, supply chain, and reproducibility:

- The readiness fixture suite generates into a temporary directory so a validate run
  leaves the worktree clean.
- The scanner treats legitimate JSON metadata citations as present, not drift.
- `make install` and `setup.py` install from `requirements.txt` (including
  `cryptography`), with a drift-guard test so the install list cannot silently omit a
  pinned dependency.

## 1.3.0, 2026-09-20

Pinned dataset: `2026.09.13.02`

Assurance-hardening release. Closes an external re-audit and a fresh acceptance
audit against the CR26 `2026.09.13.02` dataset, tightening the submission-readiness
gates so a structurally complete but content-free or wrong-scope package can no
longer reach ready. No dataset change; the v1 architecture remains frozen. Every
change was verified against the pinned dataset and shipped CI-green.

Readiness and semantic correctness:

- Normalized the `package-preflight` status path so an authoring status of
  `Planned`, `Gap`, `Exception`, or `Needs validation` is evaluated as the official
  `Not Implemented` it maps to, closing a false-ready path where a raw authoring
  status read as answered. Pinned the human-readable and JSON status normalizers
  with a parity test.
- Required the per-metric "summary of each metric" breakdown for multi-metric KSIs
  at Class B, C, and D (`SDR-CSX-KMT`), so a genuinely multi-metric indicator can no
  longer collapse into a single aggregate. Unified the KMT summaries to a single
  source derived from the durable metric history rather than hand-authored duplicates.
- Made `SDR-CSX-KMT` historical-metric summaries a `package-preflight` blocker at the
  classes where they are a MUST (Class B: 30-day and up-to-one-year; Class C and D:
  those plus the actual daily metric data derived from history; the external
  `dailyDataReference` URL is optional). Bounded all metric series against future-dated
  observations.
- Modeled non-implementation as reason AND resulting customer risk for a not-followed
  `SDR-CSO-FRR` rule and a no-measures `SDR-CSX-KSI`, carried end to end through the
  record store, preflight, JSON SDR, and human-readable SDR.
- Hardened `package-preflight` against content-free submissions: an `_is_hollow`
  predicate rejects bare non-answer tokens (`N/A`, `none`, `.`, `unknown`, and the
  like) in addition to `TBD`/empty/placeholder, while a justified `N/A: <reason>`
  still passes. Applied to the CPO structured required-information members,
  `CPO-CSO-OSA` summary, required offering-profile fields, `FRC-APP-FIA` assessor name
  and Recognition id, Sales/Security contact names, `CPO-CSO-MTD` metadata, and the two
  gate-unblocking conditions (`FRC-CSX-MOT` initial-certification exception narratives
  and the `FRC-APP-USA` freshening reviewer/id/reference). Date, URI, and hash fields
  keep the narrower placeholder test.

Artifacts and optional-rule scope:

- Replaced the substring artifact heuristic with a REQUIRED / REQUIRED_ONE_OF /
  CONDITIONAL classifier, so a mandatory one-of artifact (`report OR sample report`)
  is gated rather than demoted to advisory. This newly gates the mandatory one-of
  artifact rules per class that were previously treated as optional.
- Generalized optional Class A review so any selected MAY rule inherits its
  rule-specific artifact obligation, and required a selected Class A `SDR-CSX-KMT` to
  carry actual in-window historical metrics rather than an empty placeholder.
- Enforced the selected Class A `IVV-CSO-FIA` annual FedRAMP Recognized independent
  assessment (identity plus date within the past year) and emitted an
  `xIndependentAssessmentSummary` IV&V block into the B/C SDR metadata, threading the
  active build class so the block is not wrongly emitted for Class A.
- Rendered the Independent Assessment Summary in the human-readable SDR to mirror the
  JSON metadata, with a parity test pinning both renderers.

Evidence, isolation, and security:

- Cryptographically verify evidence signatures offline (ECDSA) against an
  independently-pinned trusted signer instead of trusting the key id carried in the
  evidence object; a signing-required mode blocks a silent downgrade to hash-only.
- Content-addressed evidence ingestion with S3 VersionId provenance and verify-by-exact-
  VersionId.
- Made the evidence-store isolation reference stack access logging real and its keys
  content-addressed and append-only; enforced TLS-only bucket access; split the
  Object Lock deny statement so object-level actions target the object ARN and the
  bucket-level action targets the bucket ARN.
- Hard-gated Bandit in CI at medium severity / medium confidence (no `|| true`).
- Added a standing assessor self-attack harness that probes the three assessor
  archetypes (gate != deliverable, narration != enforcement, optional != absent) on
  every build.
- Derived the scanner's `FedRAMP pending` KSI status from the dataset (honoring
  `varies_by_class`) instead of a hardcoded list.

Samples, docs, and robustness:

- Added a fully-worked fictional Class C sample and an assessor-attack harness under
  `examples/sample-offering-class-c/`. The sample fills a complete Class C package and
  drives it to `package-preflight`; `--attack` tampers the ready package one hollowing
  edit at a time and asserts each is blocked while a justified `N/A: <reason>` stays
  ready.
- Fixed a human-readable render crash on structured `tests` entries: `build_sdr.py`,
  `build_docx.py`, and `explain.py` coerce a structured test entry to readable text,
  so a malformed test surfaces as a clear schema message rather than a `TypeError`.
- Corrected the README CI wording (Bandit is a hard CI gate; ASH and Fortify remain a
  local pre-commit gate), documented that Class A historical KSI metrics are suppressed
  unless `SDR-CSX-KMT` is selected, and corrected stale Class C daily-data and
  `CPO-CSO-OSA` scope wording.

## 1.2.0, 2026-09-14

Pinned dataset: `2026.09.13.02`

Maintenance release adopting the FedRAMP CR26 upstream update published 2026-09-13.
Triggered by an authoritative source change, not by feature work; the v1 architecture
remains frozen.

- Refreshed the pinned CR26 dataset and its structure schema from `2026.07.14.01` to
  `2026.09.13.02` (upstream commit `58487bda`), re-locked in `sources.lock.json`. The
  update added timeframe range fields (`timeframe_num_min`/`timeframe_num_max`, e.g. on
  `CCM-QTR-SAR`), top-level timing on six rules, and the force-of-rule definitions
  `FRD-MAY`/`FRD-MST`/`FRD-MNT`/`FRD-SHD`/`FRD-SNT`. No rules were added or removed.
- Made the rule catalog a lossless projection of top-level timing, including the new
  min/max range pair, so richer official timing semantics are preserved through
  catalog and class profiles rather than silently dropped.
- Expanded `dataset_diff.py` to report timeframe, artifacts, following-information,
  `varies_by_class`, and FRD definition add/remove/change deltas, with adversarial
  tests for the range and definition cases.
- Fixed a collector/evidence timestamp mismatch: the live collector emits
  `collected_at`, which the evidence sanitizer allowlist and timestamp resolution now
  preserve, so `lastUpdated` is populated and the digest covers the timestamp.
- Made the evidence-integrity validator fail closed: if the canonical hash
  implementation cannot be imported, a resolvable evidence entry is a hard failure, not
  a soft finding.
- Storage: a dry-run against a nonexistent bucket with explicit `--retention-days` now
  reports a plan without querying lifecycle on the never-created bucket.
- Documentation sync: corrected stale "two read-only AWS calls" / "one editable
  surface" descriptions, the pinned dataset version references, the build-gate verdict
  wording, and unpinned install samples.

## 1.1.0, 2026-09-13

Pinned dataset: `2026.07.14.01`

This release freezes the v1 architecture. The
theme is a strict, class-correct submission-readiness engine and an explicit trust
boundary from authoritative FedRAMP sources through to human signoff and preflight.
No new subsystem, agent, evidence model, or package format was introduced; these are
correctness and hardening changes grounded verbatim in the pinned CR26 dataset.

### Added

- `validate_upstream.py`: validates the pinned dataset against the official rules schema and verifies both the dataset and rules-schema lock hashes; wired as build step 1 and into the daily drift check. `update_sources_lock.py` refreshes both lock entries atomically.
- Field-level submission readiness: `SDR-CSO-FRR` (7 required items) and `SDR-CSX-KSI` (5 required items) are each gated individually; a justified `N/A` counts, a bare `N/A` or a `TBD`/placeholder does not.
- Class A applicability throughout: preflight, the assurance-graph builder, and its validator all resolve Class A to its 7 CLA-enumerated KSIs; the CPO required-information set intersects `CPO-CSO-OVR` with the resolved class rule set (Class A carries only `CDS-CSO-PUB` + `MAS-CSO-IIR`); the `CPO-CSO-MTD` metadata gate is class-aware.
- Structured CPO semantic completeness: `CDS-CSO-PUB`, `CDS-CSO-IRP`, and `MAS-CSO-TPR` are validated against the CR26-enumerated members, so a bare sentence no longer satisfies a rule that enumerates concrete items. `validate_cpo_semantics.py` independently derives the expected `CPO-CSO-OVR` rule set from CR26 and hard-fails on a missing or extra entry.
- Class A external assessment (`FRC-CLA-ASF`/`FRC-CLA-EAM`): the framework is checked against the approved allowlist (FedRAMP Rev5/Ready, SOC 2 Type II, GovRAMP) and the framework-specific material checklist is enforced.
- Recognized-assessor identity: `FRC-APP-FIA` requires the assessor's FedRAMP Recognition id; `FRC-APP-USA` freshening requires a Recognized reviewer id and a valid `reviewed_at` date on or after the original assessment.
- `FRC-CSX-MOT`: availability survivability (`CDS-CSO-AVR`) is a B/C blocker; entirely-missing KSIs are detected; the initial-certification exception is modeled with an explicit boolean+description contract in the profile and enforced in preflight.
- Signoff input binding: the release manifest hashes the authoritative provider inputs (offering profile, records store) alongside generated artifacts, so a post-signoff input change invalidates the manifest-bound signoff.
- Evidence sanitization: `xSourceFact` is an allowlisted projection and the integrity digest is computed over that same projection, so recompute stays verifiable without over-exposing environment detail.
- The CodeBuild pipeline exports the complete Certification Package (`package/**` plus the release manifest), not an SDR-only subset.
- `automation/exporters/oscal_export.py`: an OSCAL export of the Security Decision Record. It reads a generated SDR JSON and emits an OSCAL Assessment Results document alongside it (`sdr/json/sdr-class-<x>.oscal.json`), so the same verified facts are available in the machine-readable interchange format that agency governance, risk, and compliance tools ingest. It is a pure read-transform-write adapter: it never queries AWS, never runs a determination, passes every status through verbatim (`Not Implemented` stays `not-satisfied`), never invents satisfaction, and skips `TBD` evidence rather than emitting a fake resource. Wired into the build pipeline and `sdr.py`; 7 offline tests. See `docs/oscal-export.md`. The export makes no claim about whether any FedRAMP process requires OSCAL; it simply provides the option.
- `automation/collectors/evidence_wiring.py`: turns read-only collector facts into schema-valid `ksiEvidence[]` entries (populating the official schema's existing `evidenceType`/`evidenceDescription`/`evidenceLocation`/`evidenceText` fields) so the SDR's evidence array is fed from telemetry instead of left empty. It never changes a status, and when it cannot know the durable artifact URI it emits an obvious `sdr://` placeholder for a human to replace rather than fabricating an https link. 9 offline tests.
- `examples/shift-left/`: a policy-as-code pre-deploy gate sibling to the SDR framework, matching the AWS Security Assurance Services compliance-engineering demo. An OPA/Rego rule and an equivalent CFN Guard rule enforce S3 TLS-in-transit against terraform-plan JSON; a local runner uses `opa` if present and otherwise a pure-Python evaluator of the same rule, with pass-is-silent / fail-blocks semantics, an `--alert` dev mode, and optional JSON evidence output. It never writes to the record store or sets an SDR status. 8 offline tests.
- `docs/references/oscal-and-machine-readable-packages.md`: a distilled, sourced reference note recording OSCAL context (the 2022 AWS OSCAL SSP milestone and RFC-0024) with primary-source links. (A companion compliance-engineering control-model reference was later internalized and removed from the public repository; see 1.2.0.)

### Changed

- `submission ready` is now strict and field-level rather than satisfied by a populated implementation field, and its definition is enforced by an end-to-end readiness test suite (20 assertions) with adversarial coverage for each hardened rule.

## 1.0.0, 2026-09-08

Pinned dataset: `2026.07.14.01`

### Added

- Documentation restructured into `docs/`: getting started, implementation guide, architecture, certification classes, validation and readiness, continuous integration, automation layers, glossary, frequently asked questions, vision and mission.
- `sdr.py` orchestrator with `build`, `validate`, `scan`, `all`, and `clean` subcommands, so a first run is one command instead of seven.
- `Makefile` with equivalent targets.
- Community health files: contributing guide, security policy, code of conduct, this changelog, issue templates, pull request template.
- Nineteen additional read-only collectors in `automation/collectors/collectors.py` covering the previously described-only indicators (CloudFormation drift, Config conformance packs, WAF, security-group and network-ACL segmentation, CloudTrail and ECR integrity, S3 data protection and retention, SIEM posture, IAM just-in-time and suspicious-activity response wiring, CodePipeline gates, Inspector supply-chain scanning, and Backup restore-testing). Each is read-only (every action enumerated in the `READ_ONLY_ACTIONS` allowlist), emits posture facts rather than statuses, and is offline-testable; the collector test suite grew to 32 tests.
- `automation/config-rules/`: a provider-deployed AWS Config custom-rule scaffold (a shared, parameterized Lambda evidence-existence evaluator, a manifest of eleven rules, a deploy guide, and 6 offline handler tests) for the eleven indicators whose evidence is a document or a reviewed process rather than a live API field. These are provider infrastructure, not repository collectors; a passing result is telemetry, never a status or assessment.
- `automation/collectors/pending-ksi-classification.json`: the machine-readable triage recording which pending indicators became direct read-only collectors versus provider-deployed rules. `build_collector_registry.py` reads it so the collectable-now count regenerates deterministically.
- Five opt-in AI-assist modules in `automation/ai/` (narrative drafter, finding explainer, evidence rollup, over-claim guard, architecture-to-indicator suggester), each with an offline deterministic default backend and an opt-in Amazon Bedrock backend, a forbidden-field boundary guard, and 27 offline boundary tests wired into continuous integration.
- Compliance CAUTION banner at the top of the README: the framework is not a compliance audit bot, no generated output is compliant or guarantees FedRAMP 20x compliance, every generated statement must be independently verified by a qualified human, and AI output is advisory only.
- Continuous-integration wiring for the AI-module boundary suites and the Config custom-rule handler tests.
- Caching of the AWS Automated Security Helper install in the security-scan job, keyed to the pinned version.
- `automation/storage/provision_store.py`: a deploy-time provisioner for the durable metric-history/facts store. It creates an in-boundary S3 bucket in the provider's own account and enables bucket versioning (optionally Object Lock/WORM and a lifecycle retention). Safety-additive and idempotent â€” it never suspends versioning, deletes anything, or moves a status â€” with a DEPLOY guide and 12 offline tests wired into continuous integration.
- `docs/getting-started.md` and `docs/automation.md`: an "Adoption models" note (greenfield vs brownfield, adoption-model-agnostic) and a "Persistence and retention" note recording the 20x retention windows (KSI metric history up to one year per `SDR-CSX-KMT`; 12 months for `SCN-CSO-HIS`; 6 months for `CDS-TRC-ACL`) and clarifying that a seven-year immutable bucket is a provider policy choice, not a 20x requirement.
- Read-only `collect_bucket_versioning` collector (the read-side complement to the store provisioner): reports whether the durable store bucket has versioning enabled, as tamper-resistance/recovery telemetry. `s3:GetBucketVersioning` added to the read-only allowlist; 5 offline tests (collector suite now 37).
- `automation/config-rules/deploy/`: a deterministic generator (`generate_templates.py`) that emits both a CloudFormation template and a CDK-in-Python app for the 11 provider-deployed Config custom rules from the manifest, so the deploy artifacts never drift from it; 7 offline tests. The generated role is read-only on the evidence bucket; a COMPLIANT result stays telemetry, not a determination.
- `automation/metrics/test_metric_history_longitudinal.py`: a 420-day longitudinal test proving the SDR-CSX-KMT rollups (retention cap, up-to-one-year and last-30-day summaries, average passing fraction, same-day idempotency). It documents that the appender retains RETAIN_DAYS+1 points due to the inclusive cutoff (conservative, not data loss).
- `validation/scripts/dataset_diff.py`: an offline tool reporting which rules changed force, applicability, or statement text (plus KSI count/family changes) between two CR26 datasets; wired into the drift-check workflow so a dataset-drift review PR carries a material-changes summary. 7 offline tests.
- `automation/ai/test_bedrock_boundary.py`: boundary tests proving the drafter's forbidden-field guard still holds when a hostile or garbage non-offline (Bedrock-like) backend is behind it, injected through the existing drafter seam without changing production code.
- `examples/sample-offering/`: a fully-worked, fictional sample offering ("Acme Cloud Widgets", Class B) with a builder that swaps the sample inputs in, runs the gate to a green result (0 hard failures), and restores the real inputs. It fills narrative prose only and deliberately does not fabricate statuses, assessments, tests, or evidence, so the readiness scanner honestly reports remaining work.

### Changed

- README rewritten as an entry point rather than a reference manual. Architecture diagrams, the directory map, the validation detail, and the pipeline reference moved into `docs/`.
- Removed an unsupported claim that mapped certification classes A, B, C, and D to the Low, Moderate, and High impact levels. `FRD-CCL` describes them as assurance categories and the dataset does not state that mapping.
- Corrected three indicator names that were paraphrased rather than quoted: `KSI-CMT-LMC` is "Logging Changes", `KSI-IAM-AAM` is "Automating Account Management", and `KSI-IAM-APM` is "Adopting Passwordless Methods". The `INR` family is Incident Response, not Incident Reporting.
- License changed from MIT to all-rights-reserved, associated with Amazon Web Services (AWS) Security Assurance Services (SAS); README badge, README license section, and `CONTRIBUTING.md` updated to match. Ownership and licensing wording is pending confirmation by AWS legal.
- `docs/automation.md`, `docs/vision.md`, `docs/architecture.md`, `docs/faq.md`, `docs/README.md`, `CONTRIBUTING.md`, and `SECURITY.md` updated to reflect the built state: Layer 1 collectors call many read-only actions (not two), and Layer 2 is five built opt-in AI modules (not a single planned drafter).
- Collector coverage: thirty-five of forty-six indicators are now directly collectable read-only (up from sixteen), with the remaining eleven covered by provider-deployed Config custom rules.

### Fixed

- Corrected the described force of `FRC-CSX-VVK` across the README and `docs/getting-started.md`: automated verification of Key Security Indicators is `MAY` at Class A, `SHOULD` (at least one method per indicator) at Class B, and `MUST` at Class C (two) and Class D (four). Earlier wording implied automation was required at Class B. Verified verbatim against the FedRAMP Consolidated Rules for 2026 dataset (`2026.07.14.01`), confirmed current against the upstream `github.com/FedRAMP/rules` repository.

## 0.1.0, 2026-09-05

First working version. Pinned dataset: `2026.07.14.01`.

### Added

- Pinned canonical sources: the CR26 dataset and both official FedRAMP schemas, hash-verified against upstream.
- Seven-step deterministic pipeline: catalogs, notes, profiles, record, Word output, crosswalk, validation.
- Traceability layer: derived rule and indicator catalogs, per-rule notes, family name expansions, and the NIST SP 800-53 Revision 5 to 20x crosswalk.
- Per-class profiles for Classes A, B, and C, the Class C overlay, and the Class D readiness register at 157 rules with a delta against Class C.
- Deliverables for each class: official schema JSON, an isolated provider extensions companion, plain text, and an authoring Word file.
- `validate_sdr.py`, the build gate: eight checks including schema validation, bidirectional coverage, per-class automated-method minimums, secret scanning, and content fidelity re-derived from the dataset through an independent code path.
- `sdrscan.py`, the readiness scanner: 37 checks emitting one finding per rule and per indicator, each citing the governing rule, in five output formats.
- AWS service to indicator map with one verify and one validate method per indicator, matching the `FRC-CSX-VVK` two-method shape.
- Layer 1 facts collector, read-only by construction: two API calls, refuses administrative-looking credentials, writes a git-excluded timestamped facts store.
- GitHub Actions workflows for the validation gate and a daily upstream drift check, with actions pinned to full commit SHAs.
- Deployable AWS CodePipeline reference with the same gates, human approval before publication, and scheduled drift and collection stages.
- Agent guardrails in `.claude/` for automated sessions.

### Fixed

- Every text writer and git blob pinned to LF line endings, so regeneration in continuous integration is byte-stable across platforms.

## Notes on versioning

A change to the pinned dataset is at least a minor version, because generated deliverables change even when no code does. A change that alters what the validator accepts or rejects is a major version, because it can invalidate a record a provider has already built and shipped.
