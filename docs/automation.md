# Automation layers

The framework separates automation into layers by what each is allowed to decide. This is the boundary that keeps generated content out of the evidence chain.

| Layer | What it does | May it move a status? |
|---|---|---|
| Layer 0: the pipeline | Resolves requirement text, generates deliverables, validates | No. It records what you wrote |
| Layer 1: collectors | Read-only queries against a live account, producing timestamped facts | No. Facts are telemetry |
| Layer 2: AI assist (opt-in) | Drafts narrative prose, explains findings, summarizes, flags over-claims, suggests mappings | No. It proposes; a human approves |

The rule underneath all three: a status moves to `Implemented` when a deterministic check passes and a named human signs off. Nothing else qualifies. Generative output is never deterministic telemetry, which follows from FedRAMP's own definitions of verification and validation, so a drafted sentence can never be the evidence for the claim it makes.

## Layer 1: the facts collector

`traceability/aws-service-ksi-map.json` links every indicator to example Amazon Web Services implementation guidance, with one verify method and one validate method each, matching the two-method shape `FRC-CSX-VVK` asks for.

From that map, `build_collector_registry.py` derives `automation/collectors/registry.json`: all 46 indicators, with any AWS Config managed rule named in the guidance extracted as an immediately collectable check, and each described method wired to a read-only collector where a live API exposes the state. Today 35 of the 46 indicators have at least one directly collectable read-only check; the remaining 11, whose evidence is a document or a reviewed process, are covered by provider-deployed AWS Config custom rules (see `automation/config-rules/`). The registry regenerates this classification deterministically from `automation/collectors/pending-ksi-classification.json`.

`automation/collectors/collect_facts.py` runs the collectable checks against an account and writes a timestamped facts store to `automation/facts/`. A registry Config check is named by the AWS managed rule's catalog name, but an account rarely deploys it under that name: Security Hub deploys `securityhub-<rule>-<hash>`, a conformance pack `<rule>-conformance-pack-<id>`, a provider template whatever it likes. The collector therefore lists the account's rules once (`config:DescribeConfigRules`) and resolves each registry rule to its deployed instances three ways, shared with the offline importer through `automation/collectors/config_rule_resolution.py`: the exact id, the Security Hub linked shape, and the rule's `Source.SourceIdentifier` through the pinned vocabulary in `automation/config-rules/known-config-managed-rules.json` (data read from the AWS Config Developer Guide, never a transform; `restricted-ssh` is `INCOMING_SSH_DISABLED`). Several instances aggregate worst-wins, and the fact records `instances`, `deployed_names` and its `resolution` mode; a role without the listing grant falls back to the exact name and labels every fact `exact-name-only` (AUD-F84). `collect_multi_account.py` fans the same read-only collection across accounts: per account and region it runs the registry Config rule checks through the same per-scope unit as the single-account driver (`collect_config_rule_facts`; a denied listing degrades to `exact-name-only` for that scope only) and then every posture collector, and writes `automation/facts/facts-multi-account.json` in the same `{meta, facts, posture_facts}` shape `collect_facts.py` writes, which is the shape and `facts-*.json` name every downstream reader opens (it refuses an `--out` name outside that glob, AUD-F85). Set the deployment-private `SDR_EVIDENCE_SCOPE_KEY` so every fact carries an **opaque scope id** in place of its account (the raw account must never enter the package, and dropping it would collapse two accounts' observations onto one evidence pointer); the private scope -> account map is written beside the facts in that git-excluded store. The export boundary (`evidence_wiring.fact_to_evidence`) refuses an account-tagged fact that has no scope. When a single-account store and the fan-out store observe the same account, the appender reads the single-account store's identity from its `meta.identity_arn` and counts that scope once.

### Read-only by construction

The collector is constrained by design rather than by policy documentation:

- Every AWS action it may call is enumerated in a read-only allowlist (`READ_ONLY_ACTIONS` in `collectors.py`); the driver refuses any call not in that set, and a test asserts every entry is a read verb (Get, List, Describe, BatchGet). Adding a service means adding its read-only actions to that set on purpose, a reviewable change rather than a silent permission widening.
- It refuses to run under credentials that look administrative.
- `automation/facts/` is git-excluded, because a facts store identifies a real account.

Grant it a role scoped to exactly the read-only actions in the allowlist and nothing more. If a new collector needs an action later, that is a change worth reviewing rather than a permission worth widening pre-emptively.

```bash
python automation/collectors/collect_facts.py
```

### What to do with the output

Facts feed three things: the automated methods you cite in an indicator's `tests`, the evidence pointers in `evidence`, and the metric history that `SDR-CSX-KMT` requires at Class C, where all daily metric data must be retained up to a year.

Facts do not write into the record store. You read them, decide what they demonstrate, and write that. The gap between "the collector saw a passing Config rule" and "this indicator is implemented" is a judgment, and the framework insists a person makes it.

### Persistence and retention

The collected facts and the metric history are the only data the framework produces from a real account, so where they live and how long they are kept follows what FedRAMP 20x specifies, not a fixed house rule.

Today the collectors write dated facts to `automation/facts/` and the appender writes one datapoint per indicator to `automation/metrics/metric-history.json`. Both are git-excluded because they derive from a real account, and the appender retains a little over one year (`RETAIN_DAYS = 400`). That is the template default; a real deployment persists these in the provider's own account or a private store, which the living-SDR workflow assumes and never commits.

Both scheduled loops persist the history and fail closed (AUD-F29 to AUD-F32). The AWS CodeBuild collector and the GitHub Actions `living-sdr-loop.yml` restore the durable `metric-history.json` from the evidence bucket before appending and publish it back with compare-and-swap afterwards; the Actions loop refuses to run until the `SDR_METRIC_HISTORY_BUCKET` repository variable names that bucket, because on an ephemeral runner a history with nowhere to go is discarded every night. A collection that observes nothing (`collect_facts.py` exit 4) or an append that adds no datapoint (`append_metrics.py` exit 4) fails the run instead of recording an empty day; `meta.last_run` advances only on a run that appended, and `meta.last_attempt` records every run. Failures alarm: the AWS template notifies the SNS topic on a failed, faulted, timed-out or stopped collector or drift-check build, and the Actions loop files a GitHub issue. `package-preflight` additionally reports, as an advisory, every KSI whose newest datapoint is older than 7 days (`MOT_STALE_ADVISORY_DAYS`, project policy), well inside the 45-day continuity bound.

### The history is the collector's record (AUD-F37)

Every observation the appender writes is hash-chained to its predecessor (or to the KSI's pruning anchor once old observations age out) and carries the collector's `run_id` plus the SHA-256 of the facts store it was derived from. `history_integrity.verify_history()` recomputes every hash and link; `history_integrity.history_digest()` folds every chain head into one value. Editing, inserting or deleting a past observation breaks the chain; rechaining it is trivial, which is why the digest is meant to be signed by the separate signer principal: `publish_history.py publish --sign-key-arn <kms-key>` writes `meta.history_signature`, and `package-preflight` verifies it offline against the independently pinned `expected_evidence_signer`.

Two evidence-store profiles, declared in the offering profile as `evidence_store_profile`:

| | `development` (template default) | `production-assurance` |
|---|---|---|
| Tampered chain (edited, inserted, deleted observation; bad anchor; series point with no observation) | Blocker at Class C/D | Blocker at Class C/D |
| Observations without chain fields or run provenance | Advisory | Blocker |
| History digest unsigned | Advisory | Blocker |
| Signature present but not verifying under the pinned signer | Blocker | Blocker |
| Evidence behind a populated applicable record not `verified` by the integrity gate (hashless, unresolvable, unsigned under a required signer) | Finding | Blocker |
| Evidence whose source fact names a `service:check` this offering does not operate for its KSI (AUD-F62, AUD-F79) | Finding | Blocker |
| Evidence whose pointer describes a different observation than its own source fact (AUD-F63) | Finding | Blocker |
| Unknown profile value | Blocker | Blocker |

The FRC-CSX-VVK binding gate counts a declared automated method as working only when its per-method series carries a datapoint inside the method's cadence window (daily 7 days, weekly 14, monthly 45, quarterly 90; project policy, FedRAMP names no cadence). A series that exists but stopped, or was written with old dates, is not a working method. A real Class C offering should declare `production-assurance` before submission; the fictional Class C sample stays on `development` because it cannot hold a signer's key, and its attack mode shows that the same package under `production-assurance` is blocked until the digest is signed.

What 20x specifies (verified against the pinned CR26 dataset `2026.09.13.02`):

- KSI metric history (`SDR-CSX-KMT`): Class B (SHOULD) keeps a 30-day summary and an up-to-one-year summary per indicator; Class C (MUST) keeps those plus all daily metric data, including the status of persistent validation, up to the past year; Class D must significantly supersede the lower classes, with specifics set during the 20x Phase 4 Pilot. The governing window is **up to one year**, which is why the appender retains about a year.
- Significant Change Notifications (`SCN-CSO-HIS`): 12 months of history.
- Trust-center access-log summaries (`CDS-TRC-ACL`): at least 6 months.
- Historical Certification Data snapshots (`CDS-CSO-HAD`): kept for the duration of the certification, aligned to the Ongoing Certification Reports.
- Centralized logging (`KSI-MLA-OSM`): must be tamper-resistant. FedRAMP states the property, not the storage product.

On a seven-year immutable bucket: 20x does **not** require seven-year retention for the metric history or facts store; the governing figure for that data is one year. A seven-year window is a general federal records-retention or audit-archive practice, not a 20x rule for this data, so treat it as a provider or agency policy choice rather than a 20x requirement.

### The evidence store: properties the package expects

The rules name properties, not products. A provider on any platform records what its store does in the offering profile's `evidence_store` block, one attestation per property, and never has to name a vendor (`implementation` is optional free text). The five properties, with the identifier that motivates each:

| Property | Attestation field | What the package expects | Motivated by |
|---|---|---|---|
| Versioned | `versioned` (true or false) | Every object version is retained, so an overwrite leaves the prior version readable | AU-09 stored-integrity enhancements; tamper-evidence for `SDR-CSX-KMT` history |
| Write-once | `write_once` (true or false) | An object, once written, cannot be altered or deleted for the retention period | AU-09; `KSI-MLA-OSM` tamper-resistant logging |
| Separately administered | `separately_administered` (true or false) | The store is administered by a principal the collectors and the assessed environment cannot act as | AU-10 at the class where the profile requires it; the non-repudiation boundary below |
| Retention period | `retention_days` (whole days) | Objects are retained at least as long as the applicable rule's window, about a year for the KSI metric history | `SDR-CSX-KMT`, `SCN-CSO-HIS`, `CDS-TRC-ACL`, AU-11 |
| Access logging | `access_logging` (true or false) | Access to the store is logged to a destination the store's own writers cannot alter | AU-09 (03) and `KSI-MLA-ALA` |

`package-preflight` reads the block (MCE-09, AUD-F73). An absent attestation, or one recorded as `false`, is a readiness finding worded as what the package expects; it is never a determination about the provider's compliance, because the attestation is the provider's statement and the assessor assesses it. One case blocks: under `evidence_store_profile` production-assurance, a store attested as neither versioned nor write-once contradicts the profile's own declaration of a tamper-evident store, so the declaration has nothing behind it. Preflight does not verify the store against a live system; that is the assessor's and the provider's work.

### AWS implementation of the store

A sound way to meet those properties on AWS is an Amazon S3 bucket in the provider's own account with versioning enabled and, where write-once tamper-evidence is wanted, Object Lock (WORM), plus a lifecycle policy set to the retention the applicable rule requires (about a year for the metric history, longer only if a separate records-retention policy applies). This is one implementation of what the rules ask for; the rules name the property, and the provider chooses the mechanism.

`automation/storage/provision_store.py` provisions exactly that store at deploy time: it creates the bucket if absent and **enables bucket versioning** (optionally Object Lock and a lifecycle retention). It is the one deploy-time write step, opt-in, idempotent, and safety-additive: it never suspends versioning, deletes anything, or moves a status. See `automation/storage/DEPLOY.md`. The reference stack under `automation/evidence-store-isolation/` (below) is the AWS form of the separately-administered and access-logged properties.

### Tamper-evidence vs non-repudiation

Versioning and the evidence content hash give tamper-**evidence**: a reviewer or CI recomputes the digest and detects a silently edited evidence object. The digest is over the **bound canonical payload** of the entry (`evidence_wiring.canonical_payload`: evidenceType, evidenceDescription, evidenceLocation, evidenceText, lastUpdated and the sanitized xSourceFact), so it attests the assertion a reader actually sees, not just the raw fact behind it; editing the description beside a verified digest is a hard integrity failure. Free text entering an entry is scrubbed of hostnames, IPs, ARNs, account ids, keys and URLs and length-bounded first. Hash and versioning do not by themselves stop a privileged actor who can rewrite the record store **and** recompute the hash, because the same pipeline holds both. Two additions close that gap for providers who want the highest standard:

- **Non-repudiation signing** (`automation/collectors/sign_evidence.py`, contract in `automation/collectors/signers.py`): a **separate** signer principal signs the evidence content hash with a key the read-only collector cannot reach. The signer is pluggable (MCE-08, AUD-F74): `KmsSigner` is the AWS path (KMS asymmetric key, `kms:Sign` denied to the collector role, unchanged output), `ExternalCommandSigner` reaches any separately administered signing service through an operator-supplied command that receives only the canonical hash on stdin and returns the ECDSA P-256 signature, and `SoftwareKeySigner` signs with a PEM key for development and fixtures. Every signer yields the same five-field block, and the key reference of a non-KMS signer is an operator-chosen label that may not be an ARN, a URL, an account id or a GUID (a tenant, subscription, compartment or project identifier would otherwise be published in every signed entry). The profile declares the signer's administration boundary as `expected_evidence_signer.signer_kind` (`managed-key-service`, `external-command` or `software-key`); `package-preflight` warns when it is undeclared, blocks an unknown value, and blocks `software-key` under production-assurance because a key held by the pipeline that runs it is not separately administered from the collectors. The build gate (`validate_evidence.py`) does **real cryptographic verification** through one path for every signer kind, not a mere binding check: when an evidence entry carries a signature, the gate (1) recomputes the hash over the entry's bound canonical payload and requires the signed hash to match, (2) requires the evidence `keyId` to match the **independently pinned** trusted signer (`offering-profile.expected_evidence_signer.key_arn`, compared in key-reference form: the block records the KMS key id, never the ARN, so the signer's account id is not published in the package); it never trusts the `keyId` carried in the evidence, which would be circular; and (3) verifies the ECDSA signature **offline** against the pinned public key (`public_key_pem`, obtained once from the signer, via `kms:GetPublicKey` on AWS), optionally re-pinned by SHA-256 fingerprint. It **fails closed**: a present-but-unpinned, unverifiable, or non-matching signature is a hard failure, and an unsigned entry stays verified-by-hash (signing is opt-in per deployment). The live signing step is desk-gated to a real audit-account key; the verification the gate enforces runs offline in CI via the `cryptography` library.
- **Control-plane isolation** (`automation/evidence-store-isolation/`): a reference CloudFormation stack that puts the evidence bucket and the signing key in a dedicated audit account, denies the assessed accounts' collector roles any mutation of the store or `kms:Sign`, allows only a narrow append-only writer, and logs access separately. It is a reference — the account topology is a provider decision — and the non-repudiation property holds only when the audit account is administered separately from the assessed accounts.

`traceability/evidence-store-controls.json` maps each of these mechanisms to the CR26 / NIST Rev5 control identifiers it supports (AU-09 and its enhancements, AU-10 at the class where the profile requires it, AU-11, KSI-MLA-ALA), and `validate_evidence_store_controls.py` gates that every cited identifier appears verbatim in the pinned dataset so the mapping can never drift into an invented control.

### Semantic provenance: an entry must also belong where it sits

The digest and the signature prove an entry was not edited after it was recorded. They prove nothing about whether the entry belongs to the indicator it sits under: an actor who can write the record store can derive a perfectly valid entry (recomputed digest, real signature from the pinned key) from a different observation and attach it to a KSI it does not measure, or re-target an entry's pointer at another observation. Two semantic checks in `validate_evidence.py` close that (AUD-F62, AUD-F63), reported as readiness findings and enforced as blockers at `package-preflight` under `production-assurance`:

- **Source binding.** An entry that carries a collector source fact must name a `service:check` that is a source for that KSI among the sources THIS offering declares it operates (AUD-F79). The sources are the ones already declared, nothing is inferred from prose, and the offering profile decides which apply: for an offering that declares an AWS platform (`aws_partition` present), the collector registry's per-KSI `metric_service_keys` allowlist and its Config managed-rule and customer custom-rule checks (as service `config`), and the provider-deployed artifact-existence rules in `automation/config-rules/rules-manifest.json` for the 11 KSIs that have no posture source; for any offering, the declared `(service, check)` pairs of each evidence adapter the profile ENABLES under `evidence_sources`, against that adapter's KSI targets (`source_bindings()`; a mapping-driven adapter declares them in its mapping file; nothing is bound service-wide, so an undeclared check under a registered service is unbound, and a registered adapter the profile leaves disabled binds nothing). An offering with no AWS platform therefore binds only its enabled adapters, and an entry claiming an AWS Config rule under it is unbound. Under the AWS template every one of the 46 KSIs has at least one registered source (a test asserts it), so the gate is satisfiable. An entry with no source fact (human-authored or file-backed evidence) makes no claim here; its review stays a human's.
- **Pointer binding.** The factory builds `evidenceLocation` from the same fields it stamps into the source fact (`<base>/<service>/<check>[/<scope>]/<region>[/<run_id>].json`), so a pointer that does not end in that slug describes a different observation than the entry's own source fact. Checked for KSI evidence and FRR rule artifacts alike.

The regression family (`validation/scripts/test_provenance_mutations.py`) tampers one dimension at a time, recomputes the digest and re-signs it, and asserts the cryptographic gate stays silent while the one semantic gate catches it: wrong KSI (source binding), re-targeted pointer (pointer binding), stale observation with a valid signature (the freshness policy, AUD-F64). Each has a killed mutation (`MUT-F62` to `MUT-F64`), and the Class C attack harness drives all three through `package-preflight`.

## Layer 2: AI assist (opt-in, built)

Five optional AI-assist modules live in `automation/ai/`, each a separate pluggable component with hard constraints fixed in code:

- `draft_narratives.py` drafts implementation and validation prose into unanswered fields only (TBD, or a labelled proposal); a per-record guard blocks any change to a forbidden field (status, assessment, tests, evidence) and writes only to a git-ignored draft sidecar. `--scope ksi` drafts the 46 indicators from collected facts; `--scope rules` drafts the 168 FRR process rules with no facts needed, from the CR26-derived `fill_guidance` (`what_it_looks_for`, `how_to_comply`, `evidence_required`) plus the offering profile's real values (organization, offering, security and incident contacts, trust center); a fork that still carries a labelled `Example (` value in a field is re-labelled as a draft rather than overwritten; the default drafts both.
- `explain_findings.py` explains findings in plain English. Advisory, no write path.
- `rollup_evidence.py` summarizes dated facts into a paragraph. Summarizes only, never claims.
- `review_overclaim.py` flags draft prose that claims more than the facts support. Flags only, never edits.
- `suggest_ksi_mapping.py` suggests which indicators a provider's services support. Suggestions only, confirmed by a human against the dataset.

Shared constraints, proven by offline boundary tests wired into CI:

- Drafts, explains, summarizes, flags, or suggests only from facts already collected or from the official rule text. No invented specifics.
- Produces a labelled proposal for human review. It never writes the record store.
- Cannot set a status. Ever. Cannot produce evidence.
- Default backend is offline and deterministic (no model, no network); an Amazon Bedrock backend is opt-in per module and imports its client only when explicitly chosen. The provider decides the backend and whether any data leaves their boundary.

Why bother at all: the bottleneck in a real record is not knowing what the controls are, it is writing the narrative entries of clear prose describing them. A drafter that turns collected facts and the official rule text into a first draft, which a person then confirms or corrects, addresses the actual cost without touching the trust boundary.

## Layer 3: the review step (from typing to deciding)

A proposal is not an answer. Every readiness predicate (`sdr.py` preflight, `validate_sdr.py`, the scanner) treats text that starts with `DRAFT (`, `Example (` or `Example:` as unanswered, through one shared definition in `validation/scripts/unreviewed_text.py` (AUD-F38). A package whose narratives are all machine drafts therefore reads as exactly as unfilled as a template full of TBDs. The only way a proposal becomes the provider's record is a named human's decision:

```
python automation/collectors/collect_facts.py --profile <ReadOnly>   # facts (read-only)
python automation/prefill/prefill_from_facts.py --write              # KSI tests/evidence proposals
python automation/ai/draft_narratives.py --write                     # KSI + rule narrative proposals
python sdr.py review --list                                          # what is pending, by source
python sdr.py review --walk --reviewer "Jane Doe" --role "Compliance lead"
```

`review --walk` shows each pending field (the prefill sidecar, the AI-draft sidecar, and any labelled `Example` text a fork may still carry; the shipped template carries none) with its current value, the proposal, its provenance, and exactly what would be written, then takes one key: accept (the proposal is written with its label stripped), edit (the reviewer's text is written), reject (nothing changes) or skip. A structured item (the prefill's tests or evidence, which are schema objects) offers accept, reject or skip only: collected facts are taken or left as collected, never rewritten as a sentence (AUD-F47). `--accept-all prefill` bulk-accepts the deterministic collector facts (structured tests and evidence, not prose); prose is decided one field at a time. `--decisions FILE` applies a prepared JSON of decisions.

A decision stands. Each sidecar is a snapshot of the whole record store taken when its producer ran, so the review step treats as a proposal only what that producer authors (prefill: tests and evidence; the drafter: `DRAFT`-labelled narrative prose), never the snapshot around it, and a proposal the log already records a decision on (same proposal hash) is not asked again, whatever the decision was. `review --list` prints how many were decided earlier; `review --all` includes them; a changed proposal (a new drafter run on new facts) is pending again (AUD-F46).

Each decision is appended to `sdr/reviews/field-review-log.json` with the reviewer, role, timestamp, source, provenance (collector run id, facts digest, drafter), the hash of the proposal and the hash of what was written. `validate_reviews.py` checks the log in the gate: a human reviewer, an allowed decision, never `implementation_status` or `assessment`, and for the latest accepted or edited decision on a field, the field's CURRENT value must still hash to what was written. Change a reviewed field by hand afterwards and the gate fails until it is decided again.

What typing remains: facts that exist nowhere in writing yet (a new offering with no landing zone, no policies, no prior package). Those are said once in the scoping call and typed once. Everything that exists somewhere (the account's posture, the official rule text with its how-to-comply guidance, the offering profile the wizard collected) arrives as a proposal to decide, not a sentence to compose. The template itself ships no example prose: every narrative field is a `TBD` marker plus the official guidance, so nothing the framework authored can be mistaken for a provider's fact.

### Without account credentials: import the customer's exports

On many engagements the consultant never holds read-only credentials into the customer's account. The customer runs four read-only AWS CLI commands in their own environment and hands over the JSON; `automation/importers/import_findings.py` turns those exports into the same facts store the live collector writes, so prefill, the metric appender, the drafter and the review step consume them through their existing paths with no new routing:

```
aws configservice describe-compliance-by-config-rule        > config-compliance.json
aws configservice describe-config-rules                     > config-rules.json
aws configservice describe-config-rule-evaluation-status    > config-rule-evaluation-status.json
aws securityhub get-findings --filters '{"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' > securityhub-findings.json
python automation/importers/import_findings.py --region us-east-1 exports/*.json --write
```

Each export is detected by its top-level key; any subset works. A deployed Config rule name becomes one of the framework's 34 recognised managed rules through data only, in order: the exact catalog id; Security Hub's service-linked convention (`securityhub-<id>-<suffix>`); the rule's `Source.SourceIdentifier` resolved through the catalog identifiers pinned in `automation/config-rules/known-config-managed-rules.json` (read from the AWS Config Developer Guide, since four identifiers are not a transform of the name: `restricted-ssh` is `INCOMING_SSH_DISABLED`); then the provider's own `automation/importers/config-rule-name-map.json`. A name that matches none is never guessed: it is printed as a review queue and stored under the facts file's `meta.unmapped_config_rules` for the provider to map and re-import. Several instances of one rule aggregate worst-wins.

The import also derives dated, count-only observations for the vulnerability-detection rules the dataset names (`VDR-CSO-DET`, `VDR-CSO-RES`, `VDR-CSO-ADT`, `VDR-TFR-MVX`; each id is checked against the pinned dataset across every applicability branch): how many rules evaluate and how many report `NON_COMPLIANT`, active failed findings by severity and distinct control, workflow states, and how many rules last evaluated within 7 and 3 days of the export. The drafter quotes those into its labelled proposal for each rule, so the proposal names the provider's own findings rather than only the official how-to text. Nothing identifying is kept: no finding titles or ids, no resource ids, no ARNs, no account ids.

Three refusals keep the import honest. The observation time comes from the export itself (latest finding `UpdatedAt` or rule `LastSuccessfulEvaluationTime`); an export with no timestamp needs `--observed-at`, because the importer will not stamp data of unknown age as fresh. An export cut short (a `NextToken` left in the file) yields an `OBSERVED_PARTIAL` fact the metric engine never scores. And one source per region: the import is refused while a live collection for that region exists, and the live collector warns when an import does, because the appender sums posture facts per route across files and two sources for one scope would count it twice. Exit codes match the collector's: 4 when the exports carry no evaluated outcome.

### An existing Rev5 SSP: the provider's own narrative, control by control

A provider moving from Rev5 already holds assessed narrative for every NIST SP 800-53 control, in its OSCAL System Security Plan. The dataset lists, for each indicator, the controls it draws on (`KSI.<family>.indicators.<id>.controls`, in OSCAL ids such as `ac-2.2`). `automation/importers/import_oscal_ssp.py` joins the two:

```
python automation/importers/import_oscal_ssp.py path/to/ssp.json --write
python automation/ai/draft_narratives.py --write --scope ksi
python sdr.py review --walk --reviewer "Jane Doe" --role "Compliance lead"
```

For each KSI, the proposal quotes the SSP's `by-component` implementation descriptions for exactly the controls FedRAMP ties to that indicator, each tagged with the control id, the statement, the component title and what the Rev5 SSP declared (`implemented`, `partial`). Pressing accept makes the provider's own Rev5 words the 20x record; pressing edit trims them. The join key is the dataset's control list and nothing else: an SSP control that no KSI references (`pe-3`, for example) is reported and left alone, and the import prints, per KSI, how many of its dataset controls the SSP implements and which are missing. What never crosses: the SSP's implementation status (quoted as text, never written as `implementation_status`), party names, system ids, inventory. The observation time is the SSP's `metadata.last-modified`.

### The landing-zone configuration: declared, and labelled as such

A Landing Zone Accelerator deployment is described by YAML (`global-config.yaml`, `security-config.yaml`). `automation/importers/import_landing_zone.py` reads those two files (field names verified against the LZA Universal Configuration) and turns what they declare into observations: GuardDuty with its protections and export, Security Hub with its enabled standards, Access Analyzer, the IAM password policy values, S3 Block Public Access, the Config recorder, the organization trail (Control Tower's or the accelerator's), centralized logging and retention, Session Manager logging, Backup vaults, and the declared Config rules. A rule's catalog `identifier` resolves through the same pinned identifiers as the export importer; a declared service reaches exactly the KSIs whose registry `metric_service_keys` route that service, and a declared rule reaches the KSIs that carry it as a check. Two dataset rules receive declared-architecture observations: `VDR-CSO-ADT` (automated detection services) and `VDR-CSO-DFR` (by-default mitigations: default EBS encryption, Block Public Access, SCP change revert, Macie).

```
python automation/importers/import_landing_zone.py path/to/lza-config/ --observed-at 2026-10-01 --write
```

Every sentence it emits begins "Landing zone configuration declares", and the facts file carries `collection_outcome.status: DECLARED_ONLY` with empty `facts` and `posture_facts`. A YAML file states intent; it does not observe the account. So the import contributes nothing to any metric or evidence entry, only material for the narrative, and the live collector or an export import is what observes the account afterwards. The files carry no timestamp, so `--observed-at` (the date they were taken from the repository) is required.

Also planned: annotating infrastructure-as-code modules with the indicators they satisfy.

## What deliberately is not automated

**Status transitions.** The whole point.

**Assessment conclusions.** The `assessment` field stays `TBD` until an accredited independent assessor has actually assessed. No tool in this repository writes it.

**Deviation justifications.** If you take an exception, a person writes why and a named senior official accepts the residual risk. A generated justification is worthless in the meeting where it matters.

**Anything requiring write access to your account.** The collector is read-only and stays that way.

See [validation](validation.md) for how collected facts flow into the checks, and the [implementation guide](implementation-guide.md) for how to turn a fact into a defensible entry.
