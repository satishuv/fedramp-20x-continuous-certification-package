# KSI gap assessment

Score an existing AWS environment against the 46 Key Security Indicators (KSIs) of
the pinned FedRAMP Consolidated Rules dataset, for one certification class, and get
one page that answers: how many KSIs have every automated check passing, how many
are partly passing, how many are failing, how many the collectors could not observe,
which family is weakest, and where the largest failing footprint is.

```
python automation/collectors/collect_facts.py --profile READONLY --region us-east-1
python automation/assessment/gap_assessment.py --class c
# or: make gap-assessment CLASS=b
```

Output lands in `automation/assessment/report/` (git-excluded, because it derives
from a real account): `gap-assessment-class-<x>.html` and `.json`.

To see the page without an AWS account:

```
make gap-assessment-demo
```

The demo uses a deterministic synthetic facts store and carries a DEMO banner on
the page and in the JSON `meta.source`.

## What the page shows

The headline sentence, for example: "Of the 46 KSIs that apply at Class C, all
automated checks pass on 10, 18 are partly passing, 5 are failing, 2 were not
observed by the collectors, and 11 need provider-produced evidence that no
read-only check can gather."

Then:

- Weakest and strongest family by fraction of observed checks passing.
- Highest risk: the failing or partly failing KSIs ranked by failing-check count,
  then by the number of NIST SP 800-53 controls the KSI maps to in the dataset.
  The ranking rule is printed on the page so a reader can dispute it.
- FRC-CSX-VVK automated-method minimum: for each observed KSI, how many distinct
  automated method ids produced an outcome against the class minimum (A 0, B 1,
  C 2), and which KSIs fall short.
- A per-family table and an expandable entry for every applicable KSI with its
  class statement, observed methods, failing checks and coverage gaps.

## Which KSIs apply

Derived from `profiles/common/ksi-profile.json`, which is built from the dataset.
Class A: the 7 KSIs whose class-A obligation is mandatory. Class B: 41, which is
all 46 minus the five whose class-B statement is marked Optional (KSI-CNA-EIS,
KSI-MLA-ALA, KSI-SVC-PRR, KSI-SVC-RUD, KSI-SVC-VCM). Class C: all 46. The tests
pin these counts.

## Status vocabulary

| Status | Meaning |
|---|---|
| passing | every automated check the collectors observed for the KSI passed |
| partial | some observed checks passed, some failed |
| failing | every observed check failed |
| not_observed | the registry has read-only checks for the KSI, but none produced an evaluated outcome in this facts store (wrong region, denied API, rule not deployed) |
| provider_evidence | a document or process KSI with no read-only collector; evidence comes from the provider's own artifacts and a deployed Config custom rule |

Scoring reuses `automation/metrics/append_metrics.datapoint_for_ksi`, the same
function that builds the SDR-CSX-KMT metric history, so this page and the history
cannot disagree about a KSI. A NON_COMPLIANT in any region counts; coverage below
the 95 percent evaluated-coverage policy is withheld from scoring and listed as a
gap rather than counted as a pass.

## Boundary

Passing is telemetry about an environment. It is not an implementation status and
not a compliance determination. The record store's statuses change only through
human sign-off, and FedRAMP Certification decisions belong to the assessor and the
authorizing agency. The page carries that statement and the AWS Security Assurance
Services advisory-only disclaimer.
