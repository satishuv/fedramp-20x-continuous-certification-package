# Implementation guide

This is the page you work from. It covers what each field in the record store means, how to fill one entry end to end, and how to decide when a status may move off `Not Implemented`.

You edit two provider-owned files: `sdr/records/records-store.json` (the security-decision facts, holding 168 rule entries under `frr` and 46 indicator entries under `ksi`) and `profiles/common/offering-profile.json` (your offering identity, certification class, and the assessment, availability, and CPO inputs). This page focuses on the record store, where most of the work is; see [getting started](getting-started.md#describing-your-offering) for the offering profile. Nothing else in the repository is hand-edited, and the validator will catch you if you try.

## Let the scanner set your order

168 entries is not a to-do list you read top to bottom. Ask the scanner what matters first.

```bash
python automation/sdrscan/sdrscan.py --only-fails --severity critical,high
```

Each finding names the rule that makes it a requirement, the resource it applies to, and the JSON path to fix. Narrow further while you work:

```bash
# One family at a time
python automation/sdrscan/sdrscan.py --only-fails --resource-type KSI

# One check at a time, once you know which one you are clearing
python automation/sdrscan/sdrscan.py --check ksi_test_minimum_met --only-fails
```

Work in passes rather than perfecting one entry: get every entry to a truthful `implementation` first, then do a validation pass, then an evidence pass. A record that is uniformly honest and half-complete is far more useful to an assessor than one where twenty entries are polished and the rest still say `TBD`.

## The fields on a rule entry

Every entry under `frr` carries the same shape. The `fill_guidance` field is generated for you and describes what that specific rule is looking for. Read it before writing anything.

| Field | What it wants | Common mistake |
|---|---|---|
| `implementation_status` | One of the allowed statuses. See the status table below | Setting `Implemented` because the work is planned |
| `implementation` | What you actually do, in plain sentences. A reader who does not know your system should understand the control from this alone | Restating the requirement back at itself |
| `validation` | How you know it is still true, and how often you check. Name the mechanism and the cadence | Writing "reviewed periodically" with no cadence |
| `assessment` | What an independent assessor concluded. Stays `TBD` until one actually has | Filling this in with your own conclusion |
| `extension.owner` | The role accountable for this, not a person's name | Naming an individual, which goes stale |
| `extension.verification` | The check that proves the control exists | Confusing this with validation. Verification asks "is it there", validation asks "is it working" |
| `extension.validation_frequency` | How often validation runs, as a real interval | "Continuous" when it is actually daily |
| `extension.failure_condition` | What counts as this control failing, stated so a machine could evaluate it | Vague language that no alarm could implement |
| `extension.failure_response` | What happens when it fails, including who is paged | Describing an intention rather than a procedure |
| `extension.evidence_freshness` | How old evidence may be before it stops counting | Leaving it open-ended |
| `extension.responsibility` | Yours, the customer's, or shared, and where the line sits | Claiming full responsibility for something the customer configures |
| `extension.independent_verification` | How a third party could confirm this without your help | Pointing at an internal-only system |
| `extension.independent_validation` | How a third party could confirm it keeps working | Same |
| `extension.customer_risk` | What the customer carries if this fails | Leaving blank because it feels like admitting weakness |
| `extension.rule_artifacts` | The artifact this rule requires, and where it lives. Often a URL on your trust center. Preflight reads the dataset's artifact list per item: a rule is blocked without one as soon as any listed artifact is mandatory or a mandatory one-of (for example CDS-CSO-SVC's human-readable URL beside its "if applicable" machine-readable one); only a rule whose every artifact is conditional stays advisory | Naming a document with no location |
| `extension.exception_reference` | The deviation record, if you are not meeting this | Silently marking `Not Applicable` with no justification |
| `extension.senior_official_acceptance` | Who accepted the residual risk, by role | Leaving it blank on a rule where you have taken an exception |
| `extension.assessor_responses` | Answers to questions an assessor raised | Using it as a scratchpad |

## The extra fields on an indicator entry

Indicator entries under `ksi` add the machinery that `FRC-CSX-VVK` and `SDR-CSX-KMT` require.

| Field | What it wants |
|---|---|
| `tests` | The automated methods that validate this indicator. Class B needs at least one, Class C at least two, Class D at least four. Each should name what it queries and how often it runs |
| `evidence` | Where the output of those tests lands, so it can be produced on request |
| `extension.measures` | The metric this indicator is measured by |
| `extension.metric_source` | The system the metric comes from |
| `extension.operating_cycle` | How often the control itself operates, as distinct from how often you test it |
| `extension.pass_condition` | The threshold that counts as passing, as a number or a boolean a machine can evaluate |
| `extension.failure_condition` | The threshold that counts as failing |
| `extension.automation_verification` | How the automation itself is verified, because an unverified test is not evidence |
| `extension.aws_responsibility` | What the cloud provider handles under shared responsibility |
| `extension.provider_responsibility` | What you handle |
| `extension.customer_responsibility` | What your customer must configure |
| `extension.known_limitation` | Where this control does not reach. Writing this down is a strength, not an admission |
| `historical_metrics` | Retained metric history. Class C requires daily metric data kept up to a year under `SDR-CSX-KMT`, which is a storage sizing decision, not a documentation one |

## Statuses, and when you may move one

The status vocabulary is deliberately narrow. Anything you cannot honestly claim gets a label that says so.

| Status | Use it when |
|---|---|
| `Not Implemented` | The control does not exist yet. The honest default |
| `Planned` | Committed, scheduled, not built |
| `Implemented` | It exists, it operates, and evidence exists that a third party could inspect |
| `Not Applicable` | The requirement genuinely does not apply, with a written justification. Never a way to avoid work |
| `Exception` | You are not meeting it, a deviation is recorded, and a named senior official accepted the residual risk |
| `Gap` | You know it is missing and it is not yet planned |
| `Needs validation` | Implemented but you cannot yet demonstrate it keeps working |
| `FedRAMP pending` | FedRAMP has not published enough to act on. Five indicators ship with empty statements in the dataset and legitimately sit here |
| `TBD` | Nobody has looked yet |

The rule for moving to `Implemented`: a deterministic check passes, and a named human signs off. Automated collection alone is not enough, and neither is a person's opinion alone. This is not bureaucratic caution. A status you cannot defend under questioning is a finding waiting to happen, and it costs more to walk back than it ever saved.

These are AUTHORING statuses. The official FedRAMP SDR schema allows only three values in the `frrImplementationStatus` / `ksiImplementationStatus` field: `Implemented`, `Not Implemented`, and `Partially Implemented`. The builder maps your authoring status onto that field (only `Implemented` and `Partially Implemented` pass through as-is; everything else - `Planned`, `Gap`, `Not Applicable`, `Exception`, `Needs validation`, `FedRAMP pending`, `TBD` - becomes `Not Implemented` in the official field) and preserves your exact authoring status in the record's extension (`providerExtensions.xAuthoringStatus`). So you can use the rich vocabulary above without producing a schema-invalid record, and the nuance (an `Exception` with senior-official acceptance, say) still travels with the SDR.

## A worked example

Take `KSI-IAM-ELP`, least privilege enforcement. Here is the template state, with the `extension` block abbreviated: it actually ships with every field present and set to a `TBD` placeholder, plus a generated `fill_guidance` string describing what this indicator wants.

```json
"KSI-IAM-ELP": {
  "implementation_status": "Not Implemented",
  "implementation": ["TBD: Information has not been provided."],
  "validation": ["TBD: Information has not been provided."],
  "assessment": ["TBD: Independent assessment has not been performed."],
  "tests": [],
  "evidence": [],
  "historical_metrics": [],
  "extension": {
    "owner": "TBD: Information has not been provided.",
    "measures": "TBD: Information has not been provided.",
    "pass_condition": "TBD: Information has not been provided."
  },
  "fill_guidance": "..."
}
```

Filled in, at Class C, for a hypothetical offering. This is a synthetic example, not anyone's real configuration:

```json
"KSI-IAM-ELP": {
  "implementation_status": "Implemented",
  "implementation": [
    "Human access to production runs through short-lived role assumption from a central identity provider. No long-lived user credentials exist in production accounts.",
    "Every role is scoped to a single service boundary. Permission boundaries prevent privilege escalation via policy attachment.",
    "Standing administrative access is zero. Elevation requires an approved change record and expires automatically after four hours."
  ],
  "validation": [
    "A daily job enumerates production roles and fails on any policy granting a wildcard action on a wildcard resource.",
    "A weekly job compares granted permissions against permissions actually used in the last 90 days and opens a ticket for each unused grant."
  ],
  "assessment": ["TBD: Independent assessment has not been performed."],
  "tests": [
    {
      "method_id": "KSI-IAM-ELP:verify:config:iam-policy-no-statements-with-admin-access",
      "method": "Daily wildcard-policy scan across all in-scope production accounts (AWS Config managed rule). Pass requires zero findings. Runs daily at 0600 UTC.",
      "automated": true,
      "cadence": "daily"
    },
    {
      "method_id": "posture:accessanalyzer:active_findings",
      "method": "Weekly unused-permission comparison via IAM Access Analyzer. Pass requires no active unused-access finding older than 90 days without an open remediation ticket.",
      "automated": true,
      "cadence": "weekly"
    }
  ],
  "evidence": [
    {
      "evidenceType": "Report",
      "evidenceDescription": "Daily least-privilege scan output, one object per account per day.",
      "evidenceLocation": "s3://your-evidence-bucket/ksi-iam-elp/daily-scan/",
      "evidenceText": "Daily scan output retained 400 days in the evidence bucket."
    },
    {
      "evidenceType": "Report",
      "evidenceDescription": "Weekly comparison reports and the resulting ticket identifiers.",
      "evidenceLocation": "s3://your-evidence-bucket/ksi-iam-elp/weekly-comparison/",
      "evidenceText": "Weekly comparison reports with ticket identifiers."
    }
  ],
  "extension": {
    "owner": "Cloud Security Engineering Manager",
    "measures": "Percentage of production roles free of wildcard action or resource grants.",
    "metric_source": "Daily scan output in the evidence bucket.",
    "operating_cycle": "Continuous. Enforcement is a permission boundary, evaluated on every authorization decision.",
    "pass_condition": "100 percent of in-scope roles free of wildcard grants, and zero unused grants older than 90 days without an open ticket.",
    "failure_condition": "Any wildcard grant in a production account, or any unused grant older than 90 days with no ticket.",
    "failure_response": "The scan failure pages the on-call security engineer. Remediation target is 24 hours for a wildcard grant. A grant that cannot be removed within 24 hours requires a recorded exception.",
    "automation_verification": "The scan is tested monthly against a deliberately over-permissive role in a non-production account; a run that does not flag it is treated as a scan outage.",
    "known_limitation": "Break-glass roles are excluded from the wildcard scan by design. They are individually reviewed monthly and every use is alarmed.",
    "aws_responsibility": "Correct evaluation of identity policies and permission boundaries.",
    "provider_responsibility": "Role design, boundary configuration, scan operation, and remediation.",
    "customer_responsibility": "Access management inside the customer's own tenancy.",
    "exception_reference": "None recorded"
  }
}
```

Note what makes this defensible. The pass condition is a number a machine can evaluate. The failure response names who is paged and how fast. The known limitation admits an exclusion and says how it is compensated. The two tests are structured records, not sentences: FRC-CSX-VVK at Class C requires at least two AUTOMATED verification methods, and the validator counts only entries with `"automated": true` and a distinct `method_id`. Two plain strings count as zero. The `method_id` is not decorative either: package-preflight binds each declared method to the per-method metric series in `metric-history.json` that carries the same id, so use the id the collectors produce (a registry `check_id` for an AWS Config rule, `posture:<service>:<check>` for a collector posture check, exactly as `prefill_from_facts.py` writes them). A method with an id nothing measures is declared but unbound and does not satisfy the gate. And `assessment` is still `TBD`, because no assessor has looked, and claiming otherwise would be the one unrecoverable mistake in the whole file.

## After each pass

```bash
python sdr.py all
```

Three things to confirm. The validator reports `hard failures: 0`. Content fidelity passes, which means you did not accidentally edit a generated file. And your scanner finding count went down.

If you added an indicator test, check that `ksi_test_minimums` moved. That check is the difference between a record that satisfies `FRC-CSX-VVK` and one that only looks like it does.

## Before you ship

- Every entry has a status you would defend in a meeting.
- Nothing says `Implemented` without evidence a third party could inspect.
- Every `Not Applicable` has a written justification, and every `Exception` names the official who accepted the risk.
- `python sdr.py validate` reports zero hard failures, and `ksi_test_minimums` now passes for your class rather than being tolerated.
- The secret scan is clean. It runs automatically, but look at the deliverables yourself once.
- Nothing customer-identifying entered the repository. If this is real provider work, it belongs in your own private repository, not a fork of this one.

Next: [validation and readiness](validation.md) for what the two tools check, or [automation](automation.md) to collect evidence from a live account instead of typing it.
