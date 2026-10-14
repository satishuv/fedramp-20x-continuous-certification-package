# Versioning and releases

This framework has its own version, independent of the FedRAMP dataset version.
Never call the framework version a "FedRAMP version."

## Two versions, always both

- Framework version: semantic version of this repository's code and generators (e.g. `1.0.0`).
- CR26 dataset version: the pinned FedRAMP Consolidated Rules for 2026 release the package was built against (e.g. `2026.09.13.02`).

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

Example: `v1.0.0-cr26-2026.09.13.02`

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

`-s` creates a GPG-signed tag (or configure `gpg.format=ssh` / sigstore for
keyless signing per your organization's policy). Verify with
`git tag -v <tag>`. Signing keys are the maintainer's own and are never held in
this repository. A GitHub Release created from a signed tag carries the
signature badge.

## The release gate is one gate

Release-ready has exactly one definition, `audit/release_gate.py`, and every
path that can produce a release executes it:

- GitHub Actions runs its sections as the `audit-gate`, `attack-gate` and
  `security-scan` jobs beside `validate`, and a `release-gate` job that depends
  on all four (and runs even when one failed) is the single required status
  check on `main`.
- The AWS CodeBuild `RELEASE_MODE=true` build runs `python audit/release_gate.py
  audit attack security` after the full validate and reproducibility gates.
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
restores every file it overwrites. The security section is Bandit at
medium-or-higher severity and confidence, and pip-audit over the hash-locked
closure.

## Publishing a release

Push the signed tag. `.github/workflows/release.yml` then:

1. refuses a lightweight or unsigned tag, and a tag whose name is not the
   committed manifest's `release_tag` (bump `FRAMEWORK_VERSION` in
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
their supply chain models its own. The SBOM covers the framework's own
DIRECTLY-PINNED top-level dependencies (the `name==version` entries in the
requirements files) and lets a consumer verify them against the manifest hash.

Scope, stated honestly: the SBOM lists the top-level packages the framework pins
directly. Their transitive dependencies are pinned indirectly (they resolve to
whatever the top-level pins allow) and are not enumerated, and the SBOM's own
metadata records this (`sbom:scope = direct-top-level-pins`,
`sbom:transitive-included = false`). A fully-resolved closure with per-package
hashes would require a committed lock file produced by a resolver (pip-compile or
uv); that is a separate supply-chain-tooling change tracked as follow-up. Until
then, do not read this SBOM as the complete resolved dependency set.

## What a release means, and does not mean

A release passing the framework's gates means the framework release gate passed:
the package is well-formed, schema-valid, internally consistent, traceable, and
reproducible. It does NOT mean FedRAMP compliant, approved, certified, or
authorized. Those are determinations of an accredited independent assessor and
the authorizing body, never of this tool.

## Reproducibility

Generated JSON, text, and CSV carry no run timestamps and are byte-identical
across builds of unchanged inputs. CI enforces this with a double-build
reproducibility gate. Word files are the documented exception (their zip
container embeds timestamps).

## Dependencies

Runtime dependencies are pinned in `requirements.txt`; local test dependencies
in `requirements-dev.txt`; CI installs the pinned set from `requirements-ci.txt`
(GitHub Actions and CodeBuild both install `requirements-ci.txt`, so the CI
environment is reproducible). GitHub Actions are pinned to full commit SHAs.
This keeps the build inputs traceable.
