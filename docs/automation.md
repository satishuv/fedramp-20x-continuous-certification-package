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

`automation/collectors/collect_facts.py` runs the collectable checks against an account and writes a timestamped facts store to `automation/facts/`. `collect_multi_account.py` fans the same read-only collection across accounts; set the deployment-private `SDR_EVIDENCE_SCOPE_KEY` so every fact carries an **opaque scope id** in place of its account (the raw account must never enter the package, and dropping it would collapse two accounts' observations onto one evidence pointer), and use `--out` to write the facts plus the private scope -> account map to the git-excluded store. The export boundary (`evidence_wiring.fact_to_evidence`) refuses an account-tagged fact that has no scope.

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
| Unknown profile value | Blocker | Blocker |

The FRC-CSX-VVK binding gate counts a declared automated method as working only when its per-method series carries a datapoint inside the method's cadence window (daily 7 days, weekly 14, monthly 45, quarterly 90; project policy, FedRAMP names no cadence). A series that exists but stopped, or was written with old dates, is not a working method. A real Class C offering should declare `production-assurance` before submission; the fictional Class C sample stays on `development` because it cannot hold a signer's key, and its attack mode shows that the same package under `production-assurance` is blocked until the digest is signed.

What 20x specifies (verified against the pinned CR26 dataset `2026.09.13.02`):

- KSI metric history (`SDR-CSX-KMT`): Class B (SHOULD) keeps a 30-day summary and an up-to-one-year summary per indicator; Class C (MUST) keeps those plus all daily metric data, including the status of persistent validation, up to the past year; Class D must significantly supersede the lower classes, with specifics set during the 20x Phase 4 Pilot. The governing window is **up to one year**, which is why the appender retains about a year.
- Significant Change Notifications (`SCN-CSO-HIS`): 12 months of history.
- Trust-center access-log summaries (`CDS-TRC-ACL`): at least 6 months.
- Historical Certification Data snapshots (`CDS-CSO-HAD`): kept for the duration of the certification, aligned to the Ongoing Certification Reports.
- Centralized logging (`KSI-MLA-OSM`): must be tamper-resistant. FedRAMP states the property, not the storage product.

On a seven-year immutable bucket: 20x does **not** require seven-year retention for the metric history or facts store; the governing figure for that data is one year. A seven-year window is a general federal records-retention or audit-archive practice, not a 20x rule for this data, so treat it as a provider or agency policy choice rather than a 20x requirement.

A sound way to meet the tamper-resistant and in-boundary requirements is an Amazon S3 bucket in the provider's own account with versioning enabled and, where write-once tamper-evidence is wanted, Object Lock (WORM), plus a lifecycle policy set to the retention the applicable rule requires (about a year for the metric history, longer only if a separate records-retention policy applies). This is one implementation of what the rules ask for; the rules name the property, and the provider chooses the mechanism.

`automation/storage/provision_store.py` provisions exactly that store at deploy time: it creates the bucket if absent and **enables bucket versioning** (optionally Object Lock and a lifecycle retention). It is the one deploy-time write step, opt-in, idempotent, and safety-additive — it never suspends versioning, deletes anything, or moves a status. See `automation/storage/DEPLOY.md`.

### Tamper-evidence vs non-repudiation

Versioning and the evidence content hash give tamper-**evidence**: a reviewer or CI recomputes the digest and detects a silently edited evidence object. The digest is over the **bound canonical payload** of the entry (`evidence_wiring.canonical_payload`: evidenceType, evidenceDescription, evidenceLocation, evidenceText, lastUpdated and the sanitized xSourceFact), so it attests the assertion a reader actually sees, not just the raw fact behind it; editing the description beside a verified digest is a hard integrity failure. Free text entering an entry is scrubbed of hostnames, IPs, ARNs, account ids, keys and URLs and length-bounded first. Hash and versioning do not by themselves stop a privileged actor who can rewrite the record store **and** recompute the hash, because the same pipeline holds both. Two additions close that gap for providers who want the highest standard:

- **Non-repudiation signing** (`automation/collectors/sign_evidence.py`): a **separate** signer principal signs the evidence content hash with a KMS asymmetric key the read-only collector cannot reach (`kms:Sign` denied to the collector role). The build gate (`validate_evidence.py`) does **real cryptographic verification**, not a mere binding check: when an evidence entry carries a signature, the gate (1) recomputes the hash over the entry's bound canonical payload and requires the signed hash to match, (2) requires the evidence `keyId` to equal the **independently pinned** trusted signer (`offering-profile.expected_evidence_signer.key_arn`) — it never trusts the `keyId` carried in the evidence, which would be circular — and (3) verifies the ECDSA signature **offline** against the pinned public key (`public_key_pem`, obtained once via `kms:GetPublicKey`), optionally re-pinned by SHA-256 fingerprint. It **fails closed**: a present-but-unpinned, unverifiable, or non-matching signature is a hard failure, and an unsigned entry stays verified-by-hash (signing is opt-in per deployment). The live `kms:Sign` step that produces signatures is desk-gated to a real audit-account key; the verification the gate enforces runs offline in CI via the `cryptography` library.
- **Control-plane isolation** (`automation/evidence-store-isolation/`): a reference CloudFormation stack that puts the evidence bucket and the signing key in a dedicated audit account, denies the assessed accounts' collector roles any mutation of the store or `kms:Sign`, allows only a narrow append-only writer, and logs access separately. It is a reference — the account topology is a provider decision — and the non-repudiation property holds only when the audit account is administered separately from the assessed accounts.

`traceability/evidence-store-controls.json` maps each of these mechanisms to the CR26 / NIST Rev5 control identifiers it supports (AU-09 and its enhancements, AU-10 at the class where the profile requires it, AU-11, KSI-MLA-ALA), and `validate_evidence_store_controls.py` gates that every cited identifier appears verbatim in the pinned dataset so the mapping can never drift into an invented control.

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

`review --walk` shows each pending field (the prefill sidecar, the AI-draft sidecar, and any labelled `Example` text a fork may still carry; the shipped template carries none) with its current value, the proposal, its provenance, and exactly what would be written, then takes one key: accept (the proposal is written with its label stripped), edit (the reviewer's text is written), reject (nothing changes) or skip. `--accept-all prefill` bulk-accepts the deterministic collector facts (structured tests and evidence, not prose); prose is decided one field at a time. `--decisions FILE` applies a prepared JSON of decisions.

Each decision is appended to `sdr/reviews/field-review-log.json` with the reviewer, role, timestamp, source, provenance (collector run id, facts digest, drafter), the hash of the proposal and the hash of what was written. `validate_reviews.py` checks the log in the gate: a human reviewer, an allowed decision, never `implementation_status` or `assessment`, and for the latest accepted or edited decision on a field, the field's CURRENT value must still hash to what was written. Change a reviewed field by hand afterwards and the gate fails until it is decided again.

What typing remains: facts that exist nowhere in writing yet (a new offering with no landing zone, no policies, no prior package). Those are said once in the scoping call and typed once. Everything that exists somewhere (the account's posture, the official rule text with its how-to-comply guidance, the offering profile the wizard collected) arrives as a proposal to decide, not a sentence to compose. The template itself ships no example prose: every narrative field is a `TBD` marker plus the official guidance, so nothing the framework authored can be mistaken for a provider's fact.

Also planned: importers for Config rules and Security Hub findings (mapping as data, with a review queue for unmapped rules), the landing-zone configuration, and an OSCAL Rev5 SSP, each producing proposals into the same review step; and annotating infrastructure-as-code modules with the indicators they satisfy.

## What deliberately is not automated

**Status transitions.** The whole point.

**Assessment conclusions.** The `assessment` field stays `TBD` until an accredited independent assessor has actually assessed. No tool in this repository writes it.

**Deviation justifications.** If you take an exception, a person writes why and a named senior official accepts the residual risk. A generated justification is worthless in the meeting where it matters.

**Anything requiring write access to your account.** The collector is read-only and stays that way.

See [validation](validation.md) for how collected facts flow into the checks, and the [implementation guide](implementation-guide.md) for how to turn a fact into a defensible entry.
