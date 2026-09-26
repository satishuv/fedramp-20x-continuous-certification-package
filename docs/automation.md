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

What 20x specifies (verified against the pinned CR26 dataset `2026.09.13.02`):

- KSI metric history (`SDR-CSX-KMT` with `FRC-CSX-MOT`): Class B keeps a 30-day summary and an up-to-one-year summary per indicator; Class C keeps those plus all daily metric data up to the past year; Class D must significantly supersede the lower classes, with specifics set during the 20x Phase 4 Pilot. The governing window is **up to one year**, which is why the appender retains about a year.
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

- `draft_narratives.py` drafts implementation and validation prose into to-be-determined fields only; a per-indicator guard blocks any change to a forbidden field (status, assessment, tests, evidence) and writes only to a git-ignored draft sidecar.
- `explain_findings.py` explains findings in plain English. Advisory, no write path.
- `rollup_evidence.py` summarizes dated facts into a paragraph. Summarizes only, never claims.
- `review_overclaim.py` flags draft prose that claims more than the facts support. Flags only, never edits.
- `suggest_ksi_mapping.py` suggests which indicators a provider's services support. Suggestions only, confirmed by a human against the dataset.

Shared constraints, proven by 27 offline boundary tests wired into CI:

- Drafts, explains, summarizes, flags, or suggests only from facts already collected. No invented specifics.
- Produces a diff or advisory output for human review. It never writes the record store.
- Cannot set a status. Ever. Cannot produce evidence.
- Default backend is offline and deterministic (no model, no network); an Amazon Bedrock backend is opt-in per module and imports its client only when explicitly chosen. The provider decides the backend and whether any data leaves their boundary.

Why bother at all: the bottleneck in a real record is not knowing what the controls are, it is writing the narrative entries of clear prose describing them. A drafter that turns collected facts into a first draft, which a person then corrects, addresses the actual cost without touching the trust boundary.

Also planned: annotating infrastructure-as-code modules with the indicators they satisfy, so the link between a resource and a requirement lives next to the resource.

## What deliberately is not automated

**Status transitions.** The whole point.

**Assessment conclusions.** The `assessment` field stays `TBD` until an accredited independent assessor has actually assessed. No tool in this repository writes it.

**Deviation justifications.** If you take an exception, a person writes why and a named senior official accepts the residual risk. A generated justification is worthless in the meeting where it matters.

**Anything requiring write access to your account.** The collector is read-only and stays that way.

See [validation](validation.md) for how collected facts flow into the checks, and the [implementation guide](implementation-guide.md) for how to turn a fact into a defensible entry.
