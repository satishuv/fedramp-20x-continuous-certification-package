# Deployment

This framework is a local, offline generator. Running it needs no cloud account and no network: `python sdr.py all` produces every Certification Package artifact on your machine. "Deployment" here means three separable things, and you adopt only the ones you need.

## 1. Local (the whole tool)

```bash
git clone https://github.com/satishuv/fedramp-20x-continuous-certification-package.git
cd fedramp-20x-continuous-certification-package
pip install -r requirements.txt
python sdr.py all
```

`python sdr.py all` builds every deliverable, runs the 14-check SDR validator and the package-schema validator, runs the readiness scanner, and prints a summary. On a fresh clone expect `hard failures: 0` and many open items: the repo ships as a template with honest `TBD` placeholders.

For a real engagement, copy the repository into a private fork and edit only two files:

- `profiles/common/offering-profile.json`: your offering identity and the certification class.
- `sdr/records/records-store.json`: your implementation, validation, and evidence facts.

Never edit generated files by hand; the `content_fidelity_against_dataset` gate exists to catch exactly that. Never commit customer values to the public template.

## 2. Continuous verification (GitHub Actions)

Four workflows ship with the repo and run on a fork with no secrets:

- `.github/workflows/validate.yml` regenerates every artifact on each push and pull request, refuses hand-edited generated files, runs the build gate plus the package-schema validator, and then the release gate's sections as parallel jobs: the audit gate (mutation runner, requirements oracle), two assessor-attack gates, and a hard security gate (Bandit and pip-audit, installed hash-locked). A `release-gate` job aggregates them into the single status check `main` requires.
- `.github/workflows/drift-check.yml` runs daily. It hash-compares the pinned CR26 dataset and all pinned official schemas against upstream `github.com/FedRAMP/rules` and opens a deduplicated issue on any change, so a silent FedRAMP update cannot drift your package without you knowing.
- `.github/workflows/release.yml` runs on a `v*` tag. It publishes a GitHub Release only from a signed tag whose commit is already on protected `main`; see [versioning](versioning.md).
- `.github/workflows/living-sdr-loop.yml` is the scheduled living loop (below). On a fresh fork its collection job is skipped until you set the `AWS_OIDC_ROLE_ARN` repository variable.

The deeper SAST scanners, ASH and Fortify, run as a local pre-push gate so scanning happens before code leaves your machine. Install the hook once per clone:

```powershell
.\scripts\install-fortify-hook.ps1
```

It runs ASH then Fortify on a push to `main`. See [scripts/README-fortify.md](../scripts/README-fortify.md).

### The living loop (opt-in)

`living-sdr-loop.yml` is the provider-deployable continuous loop: a `collect` job assumes a read-only AWS role through OpenID Connect (OIDC), collects facts, appends one dated metric datapoint per indicator, regenerates the package and hands the result across an artifact boundary as a patch; a `propose` job, which never holds a cloud credential, derives the changed-file set from that patch, authorizes it against a positive allowlist of deliverables, applies it and opens a pull request only when a committed deliverable changed; an `alarm` job files an issue on failure. To turn it on, set three repository variables: `AWS_OIDC_ROLE_ARN` (a role trusting GitHub's OIDC provider for this repository, granted only the collector's read-only actions), `AWS_REGION`, and `SDR_METRIC_HISTORY_BUCKET` (a versioned bucket in your account where the metric history persists between runs). Until all three are set the loop records nothing: the public template is not an operating continuous-certification system until a provider wires it to an account and several scheduled runs have succeeded. See [automation](automation.md#persistence-and-retention) for what the loop persists and how it fails closed.

## 3. Provider pipeline (your own AWS account)

When a provider wants approval, publication, evidence storage, and scheduled collection inside their own AWS environment, `automation/pipeline/` holds a deployable AWS CodePipeline reference:

| Stage | What happens |
|---|---|
| Source | A push to the private SDR repository triggers the pipeline |
| Validate and package | CodeBuild regenerates every artifact, refuses hand-edited files, runs the validator requiring zero hard failures |
| Readiness scan | The scanner writes per-rule and per-indicator findings into the build artifact (reports, does not gate) |
| Human approval | Amazon SNS emails an approver, who reads the readiness report before signing. Nothing publishes without sign-off |
| Publish | Deliverables land in a versioned, encrypted Amazon S3 bucket that can back a trust center |
| Daily drift check | Hash-compares pinned sources against upstream and alerts on change |
| Daily collector (opt-in) | Runs the read-only facts collector into an evidence bucket |

See [continuous integration](ci-cd.md) for the deploy command and parameters. This is a reference a provider adapts and hardens for their own account, not infrastructure this repository deploys for you.

## Opt-in features

Everything below is off by default.

### Optional evidence sources

Feed live posture and detection telemetry into the SDR as hashed, schema-valid evidence. A human still decides every status.

- AWS collectors: `python automation/collectors/collect_facts.py` with read-only AWS credentials.
- CrowdStrike Falcon and Wiz: enable per customer in `profiles/common/offering-profile.json` under `evidence_sources`, point `export_path` at a customer-produced export, and run `python automation/collectors/apply_third_party_evidence.py`. This repository holds no Falcon or Wiz API client and no credentials; the export is produced in the customer's own environment. See [optional evidence sources](../examples/evidence-sources/README.md).

### AI-assist

Opt-in modules under `automation/ai/` draft and explain text for a human to verify. They never gather evidence, set a status, or write an assessment.

### Explain a requirement

```bash
python sdr.py explain FRC-CSO-PKG
python sdr.py explain KSI-CNA-RNT
```

Prints a plain-language summary grounded in the dataset and your record store. Not a compliance determination.

## What deployment never does

No path here makes anything compliant. Publishing a schema-valid package proves it is well-formed, not that its claims are true. An accredited independent assessor and the authorizing body determine compliance. Every generated letter is an unverified draft until a qualified human confirms it.
