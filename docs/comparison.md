# How this framework relates to the official FedRAMP repositories

FedRAMP's official projects publish requirements and guidance. They stop at the
requirement boundary and do not generate a provider's package. This repository
is the provider-side implementation layer: it consumes the official
machine-readable rules and schemas and produces, validates, and continuously
checks a Certification Package.

This table reflects the framework's actual state (verified against the code),
not an aspiration. Legend: implemented, partial, not applicable.

| Capability | FedRAMP/rules | FedRAMP/2026 | FedRAMP/2026-markdown | This framework | Notes |
|---|---|---|---|---|---|
| Authoritative rules source | source of truth (JSON) | renders rules | renders rules (Markdown) | consumes pinned JSON | Pinned to `2026.09.13.02`, hash-locked in `sources.lock.json`, drift-checked daily |
| Machine-readable input | JSON, schema-validated | HTML | Markdown | consumes JSON, never HTML | Aligns with FedRAMP guidance to use the machine-readable source |
| Class A/B/C applicability | encoded (`varies_by_class`) | narrative | Markdown | implemented | `build_profiles.py` resolves per-class; the validator independently re-derives every statement from the dataset (`content_fidelity_against_dataset`) |
| Per-class force and dates | in JSON | timelines | changelog | implemented | Per-class force resolved from the dataset; SDR-CSX-KMT reference-period coverage (up to the past year) measured per KSI |
| MUST / SHOULD / MAY semantics | keywords in rules | not semantic | in text | implemented, force-aware | Class B SHOULD is advisory; Class C/D MUST shortfalls are hard build failures (`ksi_test_minimums`, `evidence_linkage_for_populated_musts`) |
| Official JSON schemas | provided | n/a | n/a | 9 pinned, version-guarded | SDR, common, CPO, OCR, incident, SCN, accepted-vuln, VDR, historical-VER; guarded by `pinned_schema_version_guard` |
| Generate a CSP SDR | no | no | no | implemented | The core differentiator |
| Full Certification Package | no | no | no | partial | SDR + CPO + OCR + event artifacts are schema-validated (`validate_package.py`); the SCG is a Markdown scaffold (FedRAMP publishes no JSON schema for it, so it is not schema-validated); certification data sharing is partial (no hosted trust center, the Class B/C availability reporting service is a provider dependency the framework gates); Class A External Assessment Materials are modeled as references, not stored |
| Provider facts / evidence store | no | no | no | implemented | Editable `records-store.json`; facts, not status, are automated |
| Evidence adapter interface | no | no | no | implemented | `EvidenceAdapter` v2 (collect/describe/health) + registry; adapters gather facts only. Hashing happens downstream, validators evaluate, humans assess. AWS collectors plus opt-in CrowdStrike Falcon and Wiz adapters |
| Evidence hashing | no | no | no | implemented | Every evidence entry carries a SHA-256 `xEvidenceContentHash` |
| Requirements-to-evidence traceability | partial (rule to KSI) | no | no | implemented | Every SDR assertion is a structured object (`xFedRampSemantic`), presence-gated by `semantic_completeness_cr26` |
| KSI implementation workflow | no | guidance | guidance | implemented | All 46 KSIs carry implementation/validation/tests/evidence, metrics, and the MOT window |
| Human-readable SDR | no | no | no | implemented | Plain text and Word alongside the JSON; kept in sync per `CDS-CSO-CBF` |
| Automated CI validation | rules self-check | site build | n/a | implemented | Build gate, 14 checks, plus package-schema validation and offline test suites |
| Upstream drift detection | n/a | n/a | n/a | implemented | Daily hash-compare against `FedRAMP/rules`, opens an issue on change |
| Rev5 related-control index | rule to KSI in JSON | no | no | implemented | Reverse index to NIST SP 800-53 Rev. 5 Release 5.2.0; labelled relatedness, not equivalence |
| Explainability | no | no | no | implemented | `python sdr.py explain <RULE\|KSI>`, grounded in the dataset and the record |
| Readiness scanning | no | no | no | implemented | `sdrscan.py` scores per-rule and per-indicator readiness |
| Continuous / living package | no | no | no | implemented | Git workflows, deterministic byte-stable outputs |
| Worked provider example | no | no | no | implemented | `examples/sample-offering/` builds a fictional filled example; `generated/` holds the rendered output |

## What the framework deliberately does NOT do

The trust boundary is a feature, not a gap. The framework automates fact
collection and document assembly; it never sets an implementation status,
writes an assessment, or asserts compliance. A schema-valid, gate-passing
package proves the documents are well-formed, never that the claims are true.
An accredited independent assessor and the authorizing body determine
compliance. Every generated letter is an unverified draft until a qualified
human confirms it.

## Positioning

This framework will never replace `FedRAMP/rules`, which remains the
authoritative source. Its value is being the implementation layer immediately
beneath it: consuming the official data to produce and maintain a Certification
Package, with traceability, hashed evidence, and continuous validation.
