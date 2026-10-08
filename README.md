<h1 align="center">FedRAMP 20x Continuous Certification Package Framework</h1>

<p align="center">
  <strong>Build and maintain your FedRAMP 20x Certification Package from traceable, machine-readable facts, not hand-maintained documents.</strong><br>
  Two provider-owned inputs (offering metadata and security-decision facts) become a Security Decision Record, Certification Package Overview, Ongoing Certification Report, Secure Configuration Guide, and the event-driven artifacts. Every FedRAMP-defined JSON package artifact is validated against its corresponding official FedRAMP schema.
</p>

<p align="center">
  <a href="https://github.com/satishuv/fedramp-20x-continuous-certification-package/actions/workflows/validate.yml"><img alt="Validate" src="https://github.com/satishuv/fedramp-20x-continuous-certification-package/actions/workflows/validate.yml/badge.svg"></a>
  <a href="https://github.com/satishuv/fedramp-20x-continuous-certification-package/actions/workflows/drift-check.yml"><img alt="Upstream drift" src="https://github.com/satishuv/fedramp-20x-continuous-certification-package/actions/workflows/drift-check.yml/badge.svg"></a>
  <img alt="CR26 dataset" src="https://img.shields.io/badge/CR26%20dataset-2026.09.13.02-0b7285">
  <img alt="Classes" src="https://img.shields.io/badge/classes-A%20%7C%20B%20%7C%20C-1864ab">
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-3776ab">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-Permissive%20(AWS%20SAS)-2f9e44"></a>
</p>

<p align="center">
  <a href="docs/getting-started.md">Get started</a> &middot;
  <a href="docs/implementation-guide.md">Fill in your facts</a> &middot;
  <a href="docs/architecture.md">Architecture</a> &middot;
  <a href="docs/vision.md">Vision</a> &middot;
  <a href="docs/glossary.md">Glossary</a>
</p>

<p align="center">
  <sub>Pinned to CR26 dataset <code>2026.09.13.02</code>. A scheduled <a href="https://github.com/satishuv/fedramp-20x-continuous-certification-package/actions/workflows/drift-check.yml">drift check</a> hash-compares the pinned dataset and schemas against <a href="https://github.com/FedRAMP/rules">github.com/FedRAMP/rules</a> daily and opens an issue on any change. Green drift badge above means the pin still matches upstream.</sub>
</p>

---

> [!CAUTION]
> ## Read this before you use anything this repository produces
>
> **This is not a compliance audit bot. It does not generate compliance.**
>
> This framework is an authoring and formatting aid. It assembles a schema-valid document and scaffolds draft text. It does **not** assess, certify, or attest anything, and it **cannot** make you FedRAMP 20x compliant.
>
> - **Nothing generated here is compliant, verified, or authoritative.** Any Security Decision Record (SDR), Key Security Indicator (KSI) narrative, implementation text, validation text, evidence summary, finding explanation, or any other output — whether produced by the deterministic pipeline or by an optional AI-assist module — is an **unverified draft only**. It carries no assurance of accuracy, completeness, or correctness.
>
> - **Producing a document with this repository does not guarantee, imply, or contribute to FedRAMP 20x compliance.** Passing the build gate means the file is *well-formed*, not that the *claims in it are true*. A green build is a formatting check, never a compliance determination.
>
> - **Every single letter must be independently re-checked and verified by a qualified human before any use.** Do not submit, rely on, or represent any output of this repository as fact, as evidence, or as a compliance position until a knowledgeable person has read it end to end, confirmed every statement against the actual system and the authoritative FedRAMP sources, and taken ownership of it. Treat all generated text as a starting draft to be rewritten, not as an answer.
>
> - **AI-assisted output is especially not to be trusted as-is.** The optional AI modules draft, explain, summarize, flag, and suggest. They can be wrong, incomplete, or misleading, and they may state things the underlying facts do not support. They never gather evidence, never set an implementation status, and never write an assessment — those remain human decisions with human sign-off. AI output is a suggestion for a human to verify, nothing more.
>
> - **Compliance is determined only by an accredited independent assessor and the authorizing body — never by this tool.** No software, and nothing in this repository, can grant, promise, or substitute for a real FedRAMP 20x authorization.
>
> - **No warranty. Use entirely at your own risk.** This software is provided "as is," without warranty of any kind. The authors and rights holders accept no liability for any use, misuse, or reliance on it or on anything it produces.
>
> **Ownership and rights.** This work is associated with and developed in the context of **Amazon Web Services (AWS) Security Assurance Services (SAS)**, which owns its licensing. It is provided under a permissive license (see [License and rights](#license-and-rights)) that permits use, copy, modification, and distribution with attribution. All AWS-related names, marks, and materials remain the property of Amazon Web Services, Inc. and its affiliates and are not licensed for use except as customary attribution; nothing here should be read as an official AWS position, product, or service. FedRAMP requirement text and schemas remain the property of their respective owners.

---

## The problem

FedRAMP 20x asks providers for a machine-readable, schema-valid Certification Package, not a stack of Word documents. The deliverable is the whole package (`FRC-CSO-PKG`): a Security Decision Record (SDR), a Certification Package Overview, a real or example Ongoing Certification Report, and, for Class B/C, a Secure Configuration Guide, plus the event-driven incident, change, and vulnerability artifacts. The SDR is the anchor record inside that package, not the only deliverable. The whole package is backed by automated verification: `FRC-CSX-VVK` calls for automated methods to persistently verify and validate each Key Security Indicator, with the obligation rising by class (`MAY` at A, `SHOULD` at B, `MUST` at C and D), and `FRC-CSX-VVR` asks for the same across the SDR itself.

A purely hand-maintained document set makes it difficult to sustain the traceability, freshness, metric history, and automated-verification expectations of FedRAMP 20x, and creates substantial drift risk. It drifts from the requirement text the moment FedRAMP updates the dataset, it cannot be diffed, and it gives an assessor no way to trace a sentence back to the rule that demanded it.

## The approach

In plain terms: you write facts about your system, and the framework turns them into a self-checking Certification Package authoring and validation workflow. You edit two provider-owned inputs (`profiles/common/offering-profile.json` for offering metadata and `sdr/records/records-store.json` for the security-decision facts); everything else is generated and validated for you. Some package components remain provider-supplied (the trust center and availability service, the fresh FedRAMP independent assessment and its overall summary, and the Secure Configuration Guide content); the framework models and preflight-gates them but does not host or produce them. A green build proves the package is well-formed and internally consistent, not that it is compliant or certified.

<p align="center">
  <img src="docs/assets/architecture.svg" alt="How it works: your system's facts (records-store.json and offering-profile.json, the two provider-owned inputs you edit) and the official rulebook (the pinned FedRAMP CR26 dataset and JSON schemas) feed the builder (python sdr.py all), which produces the full Certification Package (Security Decision Record, Certification Package Overview, Ongoing Certification Report, Secure Configuration Guide, and the event-driven incident, change, and vulnerability artifacts), every JSON validated against its official FedRAMP schema. Optional evidence sources (AWS collectors, and opt-in CrowdStrike Falcon and Wiz) attach hashed evidence. Two automatic checkers inspect the output: the fact-checker (validate_sdr.py plus validate_package.py) fails the build if a claim does not match the rulebook or a document does not match its schema, and the readiness scanner (sdrscan.py) scores how ready you are. Together they form a loop that points you back to what to fix next in your facts file. A daily drift check compares the pinned sources against upstream FedRAMP." width="820">
</p>

Two inputs, one pipeline, several official-schema artifacts, two checkers with different jobs, and a loop that tells you what to write next.

Requirement text is never typed by hand. It is resolved from the canonical FedRAMP Consolidated Rules for 2026 (CR26) dataset, and an independent validator re-derives every statement from that dataset and fails the build on any mismatch. Every generated JSON artifact is validated against its official FedRAMP schema. You write facts about your system. The framework writes everything else.

## What 20x requires, and what this framework does

Every requirement below is drawn from the pinned CR26 dataset. For each one, this table states the FedRAMP obligation, what the framework does about it, and whether that is fully built, a scaffold you complete, or provider-supplied. A green build proves the package is well-formed against these requirements; it never proves the claims in it are true. Compliance is determined by an accredited independent assessor, never by this tool.

| FedRAMP 20x requires | What this framework does | State |
|---|---|---|
| A complete Certification Package, not a document stack (`FRC-CSO-PKG`), with applicable machine-readable JSON validated against FedRAMP schemas (`FRC-CSO-JSN`) | Generates the whole package (SDR, CPO, OCR, SCG, event artifacts) from two provider-owned fact files; every JSON artifact is validated against its official FedRAMP schema on each build | Built |
| A Security Decision Record that replaces the SSP and is persistently maintained, verified, and validated (`FRD-SDR`) | Derives the SDR in JSON, plain text, and Word from the record store; an independent validator re-derives every statement from the CR26 dataset and fails the build on any mismatch | Built |
| Automated methods to persistently verify and validate each KSI, rising by class: MAY at A, SHOULD at B, MUST at C/D (`FRC-CSX-VVK`) | Maps each KSI to automated methods and preflight-gates the per-class minimum (0 at A, 1 at B, 2 at C, 4 at D); read-only collectors attach hashed posture evidence | Built (methods gated); provider deploys the account-side checks |
| Persistent KSI metric history: a 30-day and a one-year summary at B, plus daily data over at least the past 6 months at C (`SDR-CSX-KMT`, `FRC-CSX-MOT`) | Appends one dated datapoint per KSI per run to a retained history store and derives the exact-window summaries from it, not from hand-authored fields; the 6-month (C) and 18-month (D) windows are measured in calendar months and gated | Built (accumulates once deployed on a schedule) |
| A Certification Package Overview, the concise offering overview replacing the base SSP (`CPO-CSO-OVR`) | Generates the CPO in JSON and Markdown, validated against the official CPO schema, with honest TBD placeholders until you fill values | Built |
| An Ongoing Certification Report on a recurring cadence (`CCM-OCR-AVL`) | Generates a schema-valid OCR example; you swap in real summaries on the required 3-month cadence | Example built; you supply real content |
| A Secure Configuration Guide telling customers how to configure the service securely (`SCG-CSO-RSC`, `SCG-CSO-AUP`) | Generates the SCG Markdown with all required sections as a scaffold (FedRAMP publishes no JSON schema for the SCG) | Scaffold; you write the guidance |
| Event-driven reporting: incidents, significant-change notifications, vulnerability reports (`FedRAMP Incident Evaluation and Communication`, `SCN`, `VDR`) | Generates schema-valid example artifacts for each event type, each validated against its official schema | Examples built; you supply real events |
| FedRAMP Certification Data made available through a FedRAMP-compatible trust center, plus a fresh independent assessment for B/C at least annually | Models and preflight-gates the trust center reference, the availability service, and the independent-assessment summary | Provider-supplied; framework gates their presence |
| The package stays pinned to the current FedRAMP rules | A daily drift check hash-compares the pinned CR26 dataset and schemas against upstream and opens an issue on any change | Built |

The consistent boundary across every row: the framework collects evidence and authors the package, but it never sets an implementation status and never writes the assessment field. Those are human decisions with human sign-off, and an independent assessor still does the assessing.

## Feature highlights

- One command builds everything. `python sdr.py all` regenerates the full package for the active class, runs the validation gate, and prints a readiness summary, offline, with no cloud account.
- Single source of truth. You edit two files (`offering-profile.json`, `records-store.json`); 158 rule statements and 46 KSI entries re-derive from the pinned dataset, so a fact is never hand-copied across JSON, text, docx, CPO, and crosswalk.
- Deterministic and reproducible. CI regenerates every deliverable and fails if a committed file differs, plus a double-build byte-identical check, so the machine-readable and human-readable outputs, the Word document included, cannot silently drift.
- Full-chain traceability. A 204-node assurance graph joins every rule and KSI to its evidence, so "which evidence backs this KSI" is a lookup, not a reconstruction; a Rev5-to-20x crosswalk relates each indicator to NIST SP 800-53 Rev. 5 controls.
- Fail-closed validation. A 14-check validator gates the build on one exit code; a readiness scanner (`sdrscan`) emits one severity-ranked finding per rule and per indicator to tell you what to fix next.
- Class-aware. Classes A, B, and C are supported end to end; Class D ships as a readiness register pending its FedRAMP pilot.
- Cryptographic evidence integrity. Content-addressed evidence keys, versioned append-only storage, offline signature verification against an independently pinned signer, TLS-only isolation buckets.
- Living loop, provider-deployable. A scheduled read-only collect-append-regenerate workflow keeps the package and its metric history current and opens a PR only when a committed deliverable changes; disabled by default until you wire a read-only role.
- Opt-in evidence and AI. Read-only AWS collectors and file-based CrowdStrike Falcon / Wiz evidence attach where relevant; opt-in AI modules draft and explain text for a human to verify. All off by default; the pipeline runs fully with zero AI.


## Quickstart

```bash
git clone https://github.com/satishuv/fedramp-20x-continuous-certification-package.git
cd fedramp-20x-continuous-certification-package
pip install -r requirements.txt

python sdr.py all
```

That builds every deliverable, runs the validator, and prints a readiness summary. Expect `hard failures: 0` and a long list of open items: the repository ships as a template with honest placeholders, so open items are the correct result on a fresh clone.

Then run `python sdr.py init`: it asks every offering-profile question FedRAMP requires (each traced to a Certification Package Overview schema property or a CR26 rule) and writes `profiles/common/offering-profile.json` for you. For the record itself, `sdr/records/records-store.json`, the collectors, the pre-fill and the drafter propose content and `python sdr.py review --walk` takes one keystroke per field from a named human; nothing enters the record without that decision. See the [implementation guide](docs/implementation-guide.md).

If you have GNU make, `make all` wraps the same command. To run the build steps individually, see [getting started](docs/getting-started.md).

## What you get

Every JSON artifact below is validated against its official FedRAMP schema; the whole set is regenerated by one command.

| Deliverable | Path | Purpose |
|---|---|---|
| Security Decision Record (JSON) | `sdr/json/sdr-class-*.json` | The core record. Validates against the official SDR schema; required semantic items carried in `providerExtensions.xFedRampSemantic` |
| SDR plain text and Word | `sdr/human-readable/sdr-class-*.txt` / `*-authoring.docx` | Human-readable halves; `.txt` keeps parity with the JSON per `CDS-CSO-CBF` |
| Certification Package Overview | `package/cpo/cpo.json` / `.md` | `CPO-CSO-OVR`. Validates against the official CPO schema |
| Ongoing Certification Report (example) | `package/ocr/ocr-example.json` / `.md` | `CCM-OCR-AVL`. Validates against the official OCR schema |
| Secure Configuration Guide | `package/scg/secure-configuration-guide.md` | `SCG-CSO-RSC` / `SCG-CSO-AUP` scaffold (no JSON schema exists for the SCG) |
| Event artifacts (examples) | `package/events/*.json` | Incident Report, Significant Change Notification, and the vulnerability set (VDR/VER), each schema-validated |
| Rev5 related-control index | `traceability/rev5-to-20x-crosswalk.csv` | NIST SP 800-53 Rev. 5 (Release 5.2.0) controls related to each 20x indicator |
| OSCAL export | `sdr/json/sdr-class-*.oscal.json` | Interoperability only; not a native 20x submission format |
| Validation report | `validation/reports/validation-report.json` | 14 checks, one exit code, gates the build |
| Readiness findings | `validation/reports/sdrscan/` | One finding per rule and per indicator, severity-ranked |

## Deploy it

You do not deploy this framework to run it: it is a local, offline generator. `python sdr.py all` produces every artifact on your machine with no cloud account and no network. Where "deployment" matters is publishing the finished package and wiring continuous verification. Three paths, smallest first:

1. Local only. Clone, `pip install -r requirements.txt`, run `python sdr.py all`. This is the whole tool. Everything else is optional.
2. Continuous integration. The included GitHub Actions `validate.yml` runs the build gate on every push and pull request, and runs two hard security gates: Bandit (fails the build on any medium-or-higher severity finding at medium-or-higher confidence) and pip-audit (fails the build on any published vulnerability in the hash-locked dependency closure); `drift-check.yml` hash-compares the pinned FedRAMP sources against upstream daily and opens an issue on any change. Fork, and all run for free with no secrets. The deeper SAST scanners (ASH and Fortify) run as a local pre-commit gate rather than in CI: install them once per clone with `scripts/install-fortify-hook.ps1`.
3. Provider pipeline in your own AWS account. `automation/pipeline/` holds a deployable AWS CodePipeline reference (regenerate, validate, human-approval gate, publish to a versioned encrypted S3 bucket that can back a trust center). See [continuous integration](docs/ci-cd.md) and [the deployment guide](docs/deployment.md).

Per-customer work belongs in a private fork: copy this repository, edit only `profiles/common/offering-profile.json` and `sdr/records/records-store.json`, and never commit customer values to the public template.

## Opt in to optional features

The core is deterministic and offline. Everything below is off by default and enabled deliberately.

| Feature | How to turn it on | What it adds |
|---|---|---|
| AWS evidence collectors | Run `automation/collectors/collect_facts.py` with read-only AWS credentials | Collects posture telemetry into evidence, no status set |
| CrowdStrike Falcon evidence | Set `evidence_sources.crowdstrike-falcon.enabled: true` in the offering profile, point `export_path` at a Falcon export, run `automation/collectors/apply_third_party_evidence.py` | Attaches endpoint-detection evidence to `KSI-MLA-OSM/RVL/LET`, `KSI-INR-RIR` |
| Wiz evidence | Set `evidence_sources.wiz.enabled: true`, point `export_path` at a Wiz export, run the same driver | Attaches posture and vulnerability evidence to `KSI-MLA-EVC/OSM`, `KSI-SCR-MON` |
| AI-assist drafting | Opt-in modules under `automation/ai/` | Drafts and explains text for a human to verify; never sets a status |
| Explain a requirement | `python sdr.py explain FRC-CSO-PKG` or `KSI-CNA-RNT` | Plain-language, dataset-grounded summary of one rule or KSI |

Both third-party evidence sources read a file the customer exports in their own environment. This repository holds no Falcon or Wiz API client and no credentials, so a customer who uses neither tool sees nothing change. See [optional evidence sources](examples/evidence-sources/README.md).

## Scope today

| Class | Rules resolved | Indicators | Automated methods per indicator | State |
|---|---|---|---|---|
| A | 41 | 7 mandatory | 0 required | Supported |
| B | 158 | 46 | 1 expected (SHOULD) | Supported |
| C | 158 plus overlay | 46 | 2 required (MUST) | Supported |
| D | 157 | 46 | 4 required (MUST) | Readiness register only. FedRAMP 20x Class D (High) is in Phase 4 development ([RFC-0033](https://www.fedramp.gov/rfcs/0033/)), pilot estimated FY27 Q1-Q2 |

`FRD-CCL` describes the classes as assurance categories "increasing from minimal assurance at Class A to significant assurance at Class D." FedRAMP's current 20x guidance maps them to impact levels: Class A (Pilot), Class B (Low), Class C (Moderate), and the planned Class D (High), per the [FedRAMP 20x page](https://www.fedramp.gov/20x/). Those labels do not make the 20x indicator profile a renamed NIST SP 800-53B baseline, so this framework tracks the class but does not infer baseline equivalence.

Derived from the CR26 dataset at version `2026.09.13.02`: 234 rules in 20x scope out of 246 total entries, the remaining 12 being rev5-only, plus 46 Key Security Indicators across 10 families.

## What this is not

Being direct about this matters more than adoption numbers. See the [caution banner](#read-this-before-you-use-anything-this-repository-produces) at the top for the full statement; in short:

- Not a compliance claim, and not a compliance generator. Every status ships as `Not Implemented` or `TBD`. Nothing here asserts that anyone meets a requirement, and no output of the pipeline or the AI modules is compliant or verified.
- Not a shortcut past assessment. It produces a defensible draft record; an accredited independent assessor still does the assessing. A green build is a formatting check, not a compliance determination.
- Not trustworthy without human verification. Every generated statement — deterministic or AI-assisted — is an unverified draft. Every letter must be re-checked and confirmed by a qualified human before any use.
- Not a place for customer data. No account identifiers, credentials, endpoints, or restricted report content, ever. Per-customer work belongs in a separate private repository. The validator actively scans for leaked secrets and fails on a hit.
- Not affiliated with or endorsed by FedRAMP. FedRAMP publishes the rules; this repository consumes them. Nothing here is an official AWS position, product, or service.

## Documentation

| Guide | Read it when |
|---|---|
| [Getting started](docs/getting-started.md) | You want a validated SDR on your machine in five minutes |
| [Implementation guide](docs/implementation-guide.md) | You are filling in your own facts and need to know what each field wants |
| [Architecture](docs/architecture.md) | You want to know why the pipeline is shaped this way |
| [Certification classes](docs/certification-classes.md) | You are deciding between Class A, B, C, or planning for D |
| [Validation and readiness](docs/validation.md) | You want to understand the build gate and the readiness scanner |
| [Continuous integration](docs/ci-cd.md) | You are wiring this into GitHub Actions or AWS CodePipeline |
| [Deployment](docs/deployment.md) | You want to publish the package and stand up continuous verification |
| [Optional evidence sources](examples/evidence-sources/README.md) | You run CrowdStrike Falcon or Wiz and want that telemetry as evidence |
| [How this relates to official FedRAMP repos](docs/comparison.md) | You want the capability comparison against FedRAMP/rules, /2026, and /2026-markdown |
| [Versioning and releases](docs/versioning.md) | You want the release-tag convention and what a release does and does not mean |
| [Automation layers](docs/automation.md) | You want evidence collected from a live account rather than typed |
| [Glossary](docs/glossary.md) | An acronym is in your way |
| [Frequently asked questions](docs/faq.md) | Something surprised you |
| [Vision and mission](docs/vision.md) | You want to know where this is going and what it refuses to do |

## Contributing

Corrections to requirement interpretation are the most valuable contributions, and they are held to a hard standard: cite the rule identifier and quote its statement from the dataset. See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports go through [SECURITY.md](SECURITY.md), not public issues.

## License and rights

Licensed under a permissive grant owned by AWS Security Assurance Services (SAS): you may use, copy, modify, and distribute the Work with attribution and the disclaimer, subject to the trademark and no-compliance-determination conditions. See [LICENSE](LICENSE). Final terms are subject to confirmation by AWS legal.

This work is associated with **Amazon Web Services (AWS) Security Assurance Services (SAS)**. AWS Security Assurance Services and its affiliates reserve all rights in and to this work to the fullest extent applicable, and all AWS names, marks, and materials remain the property of Amazon Web Services, Inc. and its affiliates. Nothing here is an official AWS position, product, service, or endorsement.

FedRAMP requirement text and schemas are published by the United States General Services Administration at [github.com/FedRAMP/rules](https://github.com/FedRAMP/rules) and are reproduced here under their terms as government works.

