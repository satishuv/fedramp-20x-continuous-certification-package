# AGENTS.md

Guidance for any AI or code agent working in this repository. It is
provider-neutral and applies regardless of which assistant is used.

## What this repository is

A provider-side FedRAMP 20x Continuous Certification Package framework. It deterministically
derives certification-package artifacts (SDR, CPO, OCR, SCG, event artifacts)
from official FedRAMP sources and provider-authored facts, with class-aware
applicability, hashed evidence, continuous validation, human review, and
upstream change-impact analysis. It is an authoring and formatting aid. It does
not assess, certify, or attest anything.

## Authoritative source precedence

When any FedRAMP fact is in question, consult sources in this order and never
assert from memory:

1. The pinned official FedRAMP structured dataset: `references/fedramp-consolidated-rules.json` (CR26), hash-locked in `references/sources.lock.json`.
2. The official FedRAMP JSON schemas under `artifacts/schemas/official/`.
3. The official FedRAMP 2026 narrative and changelog (`github.com/FedRAMP/2026-markdown`).
4. Official government references (NIST publications, etc.).
5. Repository implementation guidance (`docs/`).

The upstream source of truth is `github.com/FedRAMP/rules`. The daily
drift-check workflow verifies the pinned copies against it.

## Hard rules for any agent

Never:
- invent requirement text, rule identifiers, KSI identifiers, or schema fields;
- promote a SHOULD to a MUST, or downgrade a MUST;
- infer, claim, or imply compliance, certification, authorization, or assessment;
- set or change an implementation status, or write an assessment;
- treat generated or AI-authored content as evidence;
- edit the pinned official sources (`references/`, `artifacts/schemas/official/`) by hand;
- edit generated files by hand (edit `sdr/records/records-store.json` and regenerate; `content_fidelity_against_dataset` will catch hand edits);
- record an approval anywhere except `sdr/reviews/review-register.json`, and only as a human act.

Always:
- resolve requirement text from the pinned dataset, never transcribe it;
- keep the trust boundary: collection failure is not control failure, stale evidence is not noncompliance, missing evidence never auto-changes a status;
- run `python sdr.py all` and confirm `hard failures: 0` before proposing a change;
- keep outputs deterministic (no run timestamps in generated files).

## Terminology

Use current FedRAMP 20x terms: Certification, Certification Package, FedRAMP
Recognized independent assessment service, certification classes A/B/C/D.
Class labels map to impact levels (A Pilot, B Low, C Moderate, D High) but the
20x KSI profile is not a renamed NIST SP 800-53B baseline. Class D is in Phase 4
development and is readiness-only here.

## Where things live

- Requirements engine and validators: `validation/scripts/`
- Release gate, mutation runner and defect ledger: `audit/` (`python audit/release_gate.py audit` runs the audit section locally; a fixed defect needs a mutation and a ledger record)
- Provider facts you edit: `sdr/records/records-store.json` and `profiles/common/offering-profile.json`
- Evidence adapters (opt-in): `automation/collectors/`
- Generated package: `sdr/`, `package/`, `traceability/`, `artifacts/release-manifest.json`
- Workflows: `.github/workflows/` (`validate.yml` on every push and PR with `release-gate` as the one required check; `drift-check.yml` daily; `release.yml` on a signed `v*` tag; `living-sdr-loop.yml` the opt-in scheduled collector)
- One-command entry point: `python sdr.py all`
