# Security policy

## Reporting a vulnerability

Do not open a public issue.

Use GitHub's private vulnerability reporting on this repository: go to the Security tab, then "Report a vulnerability." That channel is private to the maintainers and is the preferred route.

If private reporting is unavailable, contact the maintainer through their GitHub profile and ask for a private channel before sending details.

Expect an acknowledgement within a few working days. This is a small project, so please be patient rather than escalating publicly.

## What counts as a security issue here

This repository generates authorization artifacts. It does not run a service, so the interesting risks are about data exposure and about the integrity of the evidence chain.

Please report:

- **Data exposure.** Any path by which customer data, account identifiers, credentials, endpoints, or restricted report content could end up in a committed artifact. Including a case the `no_sensitive_patterns` check fails to catch.
- **Evidence integrity.** Any way to make the validator pass on a record that misrepresents reality. A bypass of `content_fidelity_against_dataset` is the highest severity issue in the project, because that check is what makes the traceability claim real.
- **Status integrity.** Any path by which a status reaches `Implemented` without a deterministic check plus human sign-off. Automated collection alone must never be sufficient.
- **Collector scope.** Any way the facts collector performs an action beyond its enumerated read-only API allowlist (READ_ONLY_ACTIONS; the deployed CollectorRole is the enforcement boundary), or accepts credentials it should refuse.
- **Supply chain.** An unpinned action, a dependency confusion path, or anything that lets code you did not review run in the pipeline. Every CI install is hash-locked (`requirements.lock`, `requirements-security.lock`), and Actions are pinned to commit SHAs.
- **Release trust.** Any way a tag that is unsigned, signed by an unlisted key, or pointing at a commit not on protected `main` could reach the publish step of `release.yml`.
- **Living-loop boundary.** Any way the `propose` job of `living-sdr-loop.yml` could apply a change outside the committed deliverable allowlist, or any way the `collect` job could write to the repository.

Also worth reporting even though it is not strictly a vulnerability: a case where a generated deliverable misstates a FedRAMP requirement. A provider could act on that, and the consequence is comparable.

## Handling secrets in this repository

Rules, not suggestions.

- No customer data, ever. Per-customer work belongs in a separate private repository, not a fork of this one.
- No account identifiers, access keys, private keys, internal endpoints, or restricted report content, in any file, including tests and fixtures.
- `automation/facts/` is git-excluded because a facts store identifies a real account. Keep it that way.
- `steering/` and `quality/` are git-excluded because they carry engagement context.
- Examples are synthetic and labeled as examples.

The validator's `no_sensitive_patterns` check scans every deliverable and fails the build on a hit. Treat it as a backstop, not as your control. If you commit a secret, rotate it first and then clean history; the rotation matters more than the cleanup.

## Threat model, briefly

The framework assumes the person running it is authorized to see the data they enter. It does not attempt to protect a record from its own author.

What it does defend:

- **Against drift.** Pinned sources plus a daily hash comparison against upstream, so a silently updated FedRAMP schema cannot change your build without you knowing. FedRAMP updates schema files in place without renaming them, which is exactly why the check exists.
- **Against undetected tampering.** Deterministic builds mean a reviewer can regenerate your package and compare bytes. A modified deliverable that does not match its inputs fails the regenerate-then-diff gate.
- **Against builder bugs.** Critical factual content (statements, names, forces, applicability) is independently checked against the pinned authoritative dataset (`content_fidelity_against_dataset`), so a wrong builder cannot pass by inventing content. Selected canonical normalization and scoping primitives (for example `submitted_ksi_ids`, which resolves per-class KSI applicability, and the automated-method counter) are DELIBERATELY shared between builder and validator so the two cannot disagree on interpretation - a class of cross-component semantic drift that shared canonical functions prevent. The adversarial and semantic round-trip test suites provide an additional, independent failure-detection layer on top of the validator.
- **Against accidental privilege.** The collectors call only read-only actions enumerated in an allowlist and refuse administrative-looking credentials. In the scheduled living loop the job holding the cloud credential has `contents: read` only, and the job that writes to the repository holds no cloud credential and authorizes the patch it applies against a positive allowlist, derived from the patch itself and re-checked after staging (AUD-F89, F93, F95).
- **Against a forged release.** A release tag must be SSH-signed by a key in `.github/release-allowed-signers`, and the tagged commit must already be on protected `main` before that file is consulted, so a side branch cannot carry its own signer list (AUD-F91).
- **Against an untested fix.** A mutation runner re-introduces every closed defect in `audit/defect-ledger.json` and fails the build if its regression test does not go red. This measures the modeled defects, not the absence of unmodeled ones: two High findings in 2026-10 (F91, F95) were threat models no mutation represented until they were written down.
- **Against a vulnerable dependency.** Bandit and pip-audit run as a hard CI gate, installed hash-locked; Dependabot proposes weekly version updates. Dependabot security updates are a repository setting the owner has not enabled, so a GitHub advisory surfaces here through pip-audit failing the gate rather than through an automatic pull request.

What it does not defend against: a maintainer with commit access acting in bad faith, a compromised developer machine, or false facts entered deliberately. Those need controls outside this repository. Two of those controls are GitHub settings the owner has consciously left off for a single-maintainer repository and should revisit before relying on the release trust chain externally: `main` requires no approving review, and administrators can bypass its branch protection.

## Supported versions

The `main` branch is the supported version. Fixes go to `main`; there are no maintained release branches.

The pinned dataset version is recorded in `references/sources.lock.json` (with the SHA-256 of `references/fedramp-consolidated-rules.json` and every pinned schema) and reported in the metadata of every generated deliverable. If you are running against an older pinned dataset, you are running an unsupported configuration for FedRAMP purposes even if the code is current.
