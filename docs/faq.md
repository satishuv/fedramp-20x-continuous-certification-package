# Frequently asked questions

## Does using this make me FedRAMP certified?

No. It produces a defensible, traceable record of what you actually do. An accredited independent assessor still assesses, and FedRAMP still decides. Any tool claiming otherwise is selling something.

## Is this an official FedRAMP tool?

No. FedRAMP publishes the rules as a versioned dataset at [github.com/FedRAMP/rules](https://github.com/FedRAMP/rules); this repository consumes them. Not affiliated with or endorsed by FedRAMP or the General Services Administration.

## Is it AWS-specific?

The core is not. The pipeline, the record store, the validator, and the scanner care about FedRAMP rules, not about which cloud you run on.

Two parts are AWS-flavoured: `traceability/aws-service-ksi-map.json` gives AWS examples for each indicator, and the Layer 1 collector queries AWS Config. Both are optional. Replace the map with your own provider's equivalents and the rest works unchanged. The GitHub Actions path needs no cloud account at all.

## Why is the readiness scanner reporting thousands of failures?

Because the shipped template has thousands of open items, and saying so is the correct behaviour. The scanner reports; the validator gates. As you fill in the record store the count falls. A tool that reported green on an empty record would be actively harmful.

## Why does the validator show a FAIL but say "hard failures: 0"?

That is `ksi_test_minimums`, and it is expected on a fresh clone. `FRC-CSX-VVK` sets a per-indicator automated-method target that rises by class, and a template has none yet. At Class B the force is `SHOULD`, so it is an advisory (soft) failure, not a hard one; it becomes a hard failure at Class C and D where the force is `MUST`. `python sdr.py release` does not turn the Class B `SHOULD` into a FedRAMP `MUST`. On a fresh Class B clone you will also see `evidence_linkage_for_populated_musts` as a second advisory. Detail in [validation](validation.md#the-one-expected-failure).

## Can I edit the generated JSON directly?

You can, and the next build will overwrite it and the validator will fail first. `content_fidelity_against_dataset` catches hand-edited outputs, and continuous integration fails on them. Edit `sdr/records/records-store.json` and regenerate.

## Why one enormous record store instead of a file per family?

Because there is exactly one place a fact can enter, so there is exactly one place to review. The cost is real: a 214-entry JSON file is awkward to edit and merges badly when two people work at once. If concurrent authoring becomes normal this is the first design decision to revisit. It is listed among the [open questions in the architecture](architecture.md#design-decisions-worth-questioning).

## Can I put my real provider data in a fork?

Use a separate private repository instead. Nothing customer-identifying belongs in this repository or a public fork of it: no account identifiers, credentials, endpoints, or restricted report content. The validator scans for leaked secrets, but do not rely on a scanner as your only control. See [SECURITY.md](../SECURITY.md).

## What happens when FedRAMP changes a rule?

The daily drift check hash-compares the pinned dataset and both schemas against upstream and opens an issue on any change. You re-pin, rebuild, and read the diff. Because requirement text is resolved rather than transcribed, the wording updates itself; what needs human attention is whether the new wording changes what your record has to say. That is a review, not a mechanical bump.

## Why pin the dataset at all, rather than fetching it live?

Three reasons. Builds stay reproducible, so a reviewer can regenerate your package and get identical bytes. The build path makes no network calls, which matters in restricted environments. And you find out about an upstream change through a drift alert you can review, rather than through a silently different build. FedRAMP also updates schema files in place without renaming them, so fetching live would give you no way to know something moved.

## Class D?

Readiness register only, at `profiles/class-d-future/readiness-register.json`: 157 rules resolved against the class D variants already in the dataset, plus a delta against Class C. FedRAMP lists the 20x Program path for Class D as coming in 2027 with specifics set during the Phase 4 Pilot. The register is a planning aid and claims nothing.

## Is Class D the same as FedRAMP High?

People say so, and it may end up that way, but no rule in CR26 states it. `FRD-CCL` only describes assurance "increasing from minimal assurance at Class A to significant assurance at Class D." This framework does not encode the mapping and you should not put it in your record.

## Which class should I pick?

Whatever your federal customers require. Two practical points: a class change is itself a significant change under `FRD-CCC`, so moving later triggers notification obligations, and Class C carries two calendar dependencies you cannot compress at the end, namely the daily metric data, including the status of persistent validation, that `SDR-CSX-KMT` asks for up to the past year (where available; a shorter history needs the recorded initial-certification commitment in the rule's note). See [certification classes](certification-classes.md).

## Will an AI write my record for me?

Partly, and deliberately not the part that matters. The opt-in Layer 2 AI-assist modules turn collected facts into draft prose and propose a diff for you to correct, explain findings, summarize evidence, flag over-claims, and suggest mappings. None can set a status, produce evidence, or invent a specific that no telemetry supports. The bottleneck in a real record is writing the narrative entries of clear prose, not deciding what is true, and only the first of those is safe to automate. See [automation](automation.md).

## Why Python with three dependencies?

So a provider's security team can read the entire pipeline in an afternoon and satisfy themselves it does what it claims. Boring is a feature in code that produces authorization artifacts.

## Word files differ between builds. Bug?

Yes, since 1.5.0 that is a defect: the `.docx` is byte-reproducible (the build rewrites its zip container with fixed entry timestamps and stamps the core properties with the pinned dataset's date, never the wall clock), so it is diffed, double-build hashed and fingerprinted in the release manifest like every JSON, text and CSV output. A `.docx` that differs from its committed copy after `python sdr.py build` means a changed input, a hand edit, or sample residue; the CI regenerate-and-diff gate fails on it.

## Why is there a `.claude/` directory?

Guardrails for automated agent sessions working in this repository: do not fabricate, do not commit without instruction, resolve every rule against the pinned dataset before writing an identifier, never hand-edit generated outputs. If you use an AI assistant here, it reads those first.

## How do I contribute a correction to a requirement interpretation?

Those are the most valuable contributions and they carry a hard requirement: cite the rule identifier and quote its statement from the dataset. An interpretation argued from memory will be asked for a citation. See [CONTRIBUTING.md](../CONTRIBUTING.md).

## Something is wrong and it is not covered here

Open an issue. If it concerns a security or data-exposure problem, use the [security policy](../SECURITY.md) instead of a public issue.
