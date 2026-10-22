# Documentation

## Start here

| Guide | Read it when |
|---|---|
| [Getting started](getting-started.md) | You want a validated Security Decision Record on your machine in five minutes |
| [Quickstart for a platform other than AWS](quickstart-non-aws.md) | Your offering runs elsewhere and you want evidence from your own exports behind the right indicators, through to Submission ready, with no credential in the repository |
| [Implementation guide](implementation-guide.md) | You are filling in your own facts and need to know what each field wants |
| [Certification classes](certification-classes.md) | You are choosing between Class A, B, and C, or planning for D |

## Understanding it

| Guide | Covers |
|---|---|
| [Architecture](architecture.md) | The build flow, the operational pipeline, why the design is shaped this way, and the dataset traversal problem |
| [Validation and readiness](validation.md) | The SDR build-gate checks, the full validation gate, submission-readiness preflight, the readiness scanner, determinism, upstream drift |
| [Automation layers](automation.md) | What each layer may and may not decide, the read-only collectors, and the five opt-in AI-assist modules |
| [KSI gap assessment](gap-assessment.md) | One page scoring an existing environment's collected facts against the 46 Class C KSIs: passing, partial, failing, not observed, weakest family, highest risk, and the FRC-CSX-VVK method minimum |
| [OSCAL export](oscal-export.md) | Emitting the SDR as OSCAL for downstream governance, risk, and compliance tools |
| [Continuous integration](ci-cd.md) | The four gates, the GitHub Actions workflows and what each gate job proves, the AWS CodePipeline reference |
| [Deployment](deployment.md) | Local use, the GitHub Actions workflows on a fork, the opt-in living loop and the variables that turn it on, the provider pipeline |
| [Versioning and releases](versioning.md) | The two versions, the release tag, the one release gate, signed tags and the release trust chain, the SBOM and the hash-locked dependencies |
| [How this relates to official FedRAMP repos](comparison.md) | Capability comparison against FedRAMP/rules, /2026 and /2026-markdown |

## Reference

| Page | Covers |
|---|---|
| [Glossary](glossary.md) | Every abbreviation, all 17 rule families, all 10 indicator families, how to read a rule identifier |
| [Frequently asked questions](faq.md) | The questions that come up most, including the ones with uncomfortable answers |
| [Vision and mission](vision.md) | Where this is going, the principles behind it, and what it refuses to do |
| [Scanner reference](../automation/sdrscan/README.md) | Every readiness check, output formats, mutelist |
| [Shift-left policy-as-code](../examples/shift-left/README.md) | The pre-deploy OPA / CFN Guard gate sibling to the SDR |
| [Reference: OSCAL and machine-readable packages](references/oscal-and-machine-readable-packages.md) | OSCAL context and primary sources |

## Reading order for a first authorization

1. [Vision](vision.md) to decide whether this approach suits you at all.
2. [Certification classes](certification-classes.md) to choose a class, because two Class C requirements have calendar dependencies you cannot compress later.
3. [Getting started](getting-started.md) to get a build running.
4. [Implementation guide](implementation-guide.md) as your working reference from then on.
5. [Continuous integration](ci-cd.md) once your record is real enough to protect with a gate.

## Authoritative source

[github.com/FedRAMP/rules](https://github.com/FedRAMP/rules) is the controlling upstream for every requirement. Where this documentation and the dataset disagree, the dataset wins and the documentation is a bug worth reporting.
