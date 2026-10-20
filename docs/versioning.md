# Versioning and releases

This framework has its own version, independent of the FedRAMP dataset version.
Never call the framework version a "FedRAMP version."

## Two versions, always both

- Framework version: semantic version of this repository's code and generators (e.g. `1.0.0`).
- CR26 dataset version: the pinned FedRAMP Consolidated Rules for 2026 release the package was built against (e.g. `2026.10.13.01`).

The release manifest (`artifacts/release-manifest.json`) records both, plus the
pinned schema versions and a SHA-256 of every generated artifact, so any release
can be reconstructed and verified. Its `source_provenance` block records
`requirements_sha256` and `requirements_ci_sha256` on every build; `source_commit`
and `source_tree` stay null here on purpose.

Exact git source provenance lives in a SEPARATE `artifacts/release-attestation.json`,
not in the manifest. The reason is the signoff binding: the human package signoff
(checked by `package-preflight`) is bound to the SHA-256 of the manifest's bytes,
so if a release step wrote the git commit INTO the manifest, its hash would change
and a prior signoff would silently go stale. The attestation instead binds the
manifest's hash to the git commit/tree WITHOUT changing the manifest. The ordering
is: build, validate, reproducibility, human signoff (binds the deterministic
manifest), `package-preflight` (verifies that binding), then the attestation
(binds that same manifest hash to the git source), then tag. `python sdr.py release`
runs the gate and reproducibility and writes the attestation automatically; the
deployed CodePipeline does the same under `RELEASE_MODE=true`. The attestation is
release-only and git-excluded (a committed one would name its own pre-commit hash
and trip the regenerate-and-diff gate); it is uploaded as a build artifact and
published in the bundle. Because two commits can share a framework version and
dataset version, the attestation's `source_commit` is what binds a release to an
exact source tree.

## Release tag format

```
v<framework-version>-cr26-<dataset-version>
```

Example: `v1.0.0-cr26-2026.10.13.01`

The manifest emits this as `release_tag`. Tagging a release with this string
means: this framework version, built against this CR26 dataset, produced the
artifacts whose hashes are in the manifest.

## Signing a release

Sign the release tag so consumers can verify it came from a trusted maintainer,
not just that a tag with the right name exists:

```
git tag -s v<framework>-cr26-<dataset> -m "FedRAMP 20x SDR framework <tag>"
git push origin v<framework>-cr26-<dataset>
```

`-s` signs the tag with the key your git is configured for; this project's
release tags are SSH-signed (`gpg.format=ssh`, an ed25519 key). The release
workflow first requires the tagged commit to be on protected `main` (it fetches
`main` by its own ref, never from the tag, and runs `git merge-base
--is-ancestor`), and only then verifies the signature cryptographically with
`git verify-tag` against `.github/release-allowed-signers`, which lists the
PUBLIC keys trusted to sign a release, one per line in ssh-keygen
`allowed_signers` form. The order matters (AUD-F91): the signers file is read
from the tagged commit's own tree, so without the ancestry step a tag on a side
branch could carry its own signer list and authorise itself. Requiring the
commit to have reached `main` means the signers file in force is one that passed
`main`'s required `release-gate` status check in a pull request; the
branch protection on `main` (required status check, strict up-to-date, no force
push, no deletion) is therefore part of the release trust chain and is recorded
in the workflow header. Two limits of that chain are repository settings, not
code, and the owner decides them: `main` does not currently require an approving
review, so "passed the gate" means the automated gate and not a second human;
and administrators are not subject to the branch protection
(`enforce_admins` is off). A `v*` tag ruleset restricting tag creation, update
and deletion is the recommended defense in depth beside the ancestry check; none
is configured today. A tag signed by a key not on that list fails the
workflow with "No principal matched", however valid the signature is; so does an
unsigned tag, a tag on a commit that is not on `main`, a tag that does not point
at the commit being built, or a tag whose name differs from the manifest's
`release_tag`. Private keys are the maintainer's own and are never held in this
repository. Consumers verify the same way:

```
git config gpg.format ssh
git config gpg.ssh.allowedSignersFile .github/release-allowed-signers
git verify-tag <tag>
```

Rotating a key: add the new public key to `.github/release-allowed-signers` in
a pull request that passes `release-gate` and merge it BEFORE tagging with the new key; remove a
retired key only once every release it signed is superseded, since verifying
those tags needs it. A GitHub Release created from a signed tag also carries the
signature badge.

## The release gate is one gate

Release-ready has exactly one definition, `audit/release_gate.py`, and every
path that can produce a release executes it:

- GitHub Actions runs its sections as the `audit-gate`, `attack-gate`,
  `attack-gate-non-aws` and `security-scan` jobs beside `validate`, and a
  `release-gate` job that depends on all five (and runs even when one failed)
  is the single required status check on `main`.
- The AWS CodeBuild `RELEASE_MODE=true` build runs `python audit/release_gate.py
  audit attack attack-non-aws security` after the full validate and
  reproducibility gates.
- `python sdr.py release` runs the same sections between validation and the
  reproducibility check, so a local release cannot pass while CI would be red.

The audit section is the requirements-differential oracle, the mutation-runner
self-test, the mutation runner (a surviving OR skipped mutation fails, and the
defect ledger must reconcile with the runner), and a tree-clean check. The
attack section (AUD-F61) is the Class C assessor-attack harness
(`examples/sample-offering-class-c/build_class_c_sample.py --attack`: a fully
populated fictional package driven to Submission ready, then tampered one
hollowing edit at a time, each of which must be blocked while the justified
baseline stays ready) followed by a tree-clean check, because the harness
restores every file it overwrites. The attack-non-aws section (MCE-12) is the
same probe list against the fictional Class C sample on a platform other than
AWS, whose evidence comes through the adapter path, followed by its own
tree-clean check. The security section is Bandit at
medium-or-higher severity and confidence, and pip-audit over the hash-locked
closure, with both scanners themselves installed from the hash-locked
`requirements-security.lock` (AUD-F92).

## Publishing a release

Push the signed tag. `.github/workflows/release.yml` then:

1. refuses a lightweight or unsigned tag, a tag on a commit that is not on
   protected `main`, a tag whose signature does not verify against a key in
   `.github/release-allowed-signers`, a tag that does not point at the commit
   being built, and a tag whose name is not the committed manifest's
   `release_tag` (bump `FRAMEWORK_VERSION` in
   `validation/scripts/build_release_manifest.py`, rebuild and commit first);
2. re-runs the whole validate workflow on the tagged commit;
3. writes the release attestation and assembles the active-class bundle from
   exactly the fingerprinted set, and attaches the manifest, the attestation,
   the SBOM and the bundle to the GitHub Release (creating it if needed).

A release without those assets, or from a tag that skipped the gate, is not a
release of this framework. `v1.4.0-cr26-2026.09.13.02` predates this workflow:
it was published by hand while its audit-gate was red, from an unsigned tag,
with no assets, and its notes overstated the mutation result. It is superseded
by the next version and deliberately left in place (never moved or force-pushed);
its release notes carry a correction.

## Software bill of materials (SBOM)

Every build emits a deterministic CycloneDX SBOM at `artifacts/sbom.cdx.json`,
fingerprinted in the release manifest. A tool that asks providers to evidence
their supply chain models its own. The SBOM is the fully resolved closure: every
package in the committed `requirements.lock`, top-level and transitive, each
with the hash the lock pins it to. Its metadata records the scope
(`sbom:scope = resolved-closure-with-hashes`, `sbom:transitive-included = true`).
`make lock` regenerates the lock and the SBOM together, so the two cannot
disagree; the regenerate-and-diff gate fails a commit where they do.

## What a release means, and does not mean

A release passing the framework's gates means the framework release gate passed:
the package is well-formed, schema-valid, internally consistent, traceable, and
reproducible. It does NOT mean FedRAMP compliant, approved, certified, or
authorized. Those are determinations of an accredited independent assessor and
the authorizing body, never of this tool.

## Reproducibility

Generated JSON, text, CSV and Word output carry no run timestamps and are
byte-identical across builds of unchanged inputs. CI enforces this with a
double-build reproducibility gate that hashes the `.docx` too (byte-reproducible
since AUD-F35: fixed zip entry timestamps, dataset-derived core properties).

## Dependencies

Runtime dependencies are pinned in `requirements.txt`; local test dependencies
in `requirements-dev.txt`; CI-only tools in `requirements-ci.txt`. Those are the
INPUTS to `make lock`, which resolves the full closure with hashes into
`requirements.lock`. Every CI path (GitHub Actions and both CodeBuild buildspecs)
installs `requirements.lock` with `--require-hashes`, so a CI environment holds
exactly the resolved closure and nothing else. The security scanners have the
same shape: `requirements-security.txt` is the input and `make lock-security`
resolves `requirements-security.lock`, constrained against `requirements.lock`
so a shared transitive package resolves to one version. GitHub Actions are
pinned to full commit SHAs. Dependabot proposes weekly version bumps to the
input files; a bump lands only after the maintainer regenerates the affected
lock and the SBOM on the branch. This keeps the build inputs traceable.
