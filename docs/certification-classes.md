# Certification classes

FedRAMP 20x defines four certification classes. `FRD-CCL` describes them as categories of assurance a cloud service offering supplies to federal customers, "increasing from minimal assurance at Class A to significant assurance at Class D."

A note on impact levels. FedRAMP's current public 20x guidance maps the classes to impact levels: Class A (Pilot), Class B (Low), Class C (Moderate), and the planned Class D (High). The [FedRAMP 20x page](https://www.fedramp.gov/20x/) states this directly ("Class A (Pilot), Class B (Low), and Class C (Moderate)" available now, with a "20x Class D (High) Pilot" in Phase 4). These labels describe the certification classes. They do not mean the 20x Key Security Indicator profile is a renamed NIST SP 800-53B Low, Moderate, or High baseline, and this framework does not infer one-to-one baseline equivalence. The `FRD-CCL` definition in the dataset describes the classes as assurance categories "increasing from minimal assurance at Class A to significant assurance at Class D"; the Low/Moderate/High labels come from FedRAMP's program guidance rather than from a mapping field inside the dataset.

## What differs between classes

| | Class A | Class B | Class C | Class D |
|---|---|---|---|---|
| Provider rules resolved | 41 | 157 | 157 plus overlay | 156 in readiness register |
| Indicators in scope | 7 mandatory | all 46 | all 46 | all 46 |
| Automated methods per indicator (`FRC-CSX-VVK`) | none required | at least 1 | at least 2 | at least 4 |
| Metrics in the record (`SDR-CSX-KMT`) | `MAY` include | `MUST`: 30-day summary, plus a summary up to the past year where available | the same, plus all daily metric data up to the past year | `MUST` significantly supersede lower classes, specifics set in the Phase 4 Pilot |
| Historical KSI metrics including persistent-validation status (`SDR-CSX-KMT`) | `MAY` include | `SHOULD` include 30-day and one-year summaries | `MUST`: summaries plus all daily data up to the past year, where available | `MUST` significantly supersede lower classes (specifics pending) |
| Support in this repository | full | full | full | register only |

Read the last two rows before you pick a class. They are the only requirements in the framework that you cannot satisfy by working harder later.

The daily metric history at Class C is a calendar dependency: `SDR-CSX-KMT` asks for all daily data, including the status of persistent validation, up to the past year, and if you start collecting the week before assessment you cannot compress it. The dataset mandates no minimum duration since `2026.10.08.01` (the removed `FRC-CSX-MOT` carried six months); the data is supplied "where available", and for a first certification the rule's note has providers "have mechanisms in place and agree to meet this requirement" when metrics have not been available for the period. That is an agreement to start the clock, not a waiver.

All daily metric data up to the past year at Class C is a storage sizing decision, and it belongs in your pipeline design from the start rather than in a migration later.

### Class A historical KSI metrics are opt-in, and opting in is a commitment

At Class A, `SDR-CSX-KMT` is `MAY` include, so historical KSI metrics are suppressed from the submitted SDR by default: leave `selected_optional_rules` without `SDR-CSX-KMT` and no metric summaries are emitted or gated. Include them only by explicitly selecting `SDR-CSX-KMT`. Once selected, FedRAMP treats included optional Class A material as part of the fully reviewed surface, so the framework then requires the applicable Class A indicators to carry actual in-window historical metric content rather than an empty placeholder. In short: do not select `SDR-CSX-KMT` at Class A unless you have real metric history to stand behind, because selecting it turns the metrics from optional into a readiness obligation.

## Class A is enumerated, not scaled down

Class A is the one that behaves unlike the others. It is not "Class B with fewer rules by severity." Applicability is enumerated explicitly by `FRC-CLA-MFR`, so the 41 rules are the ones FedRAMP named, not the ones a filter selected. Same for the indicators: 7 are mandatory at Class A and the other 39 carry `not required for Class A` in the profile.

The seven mandatory indicators at Class A:

Names below are the dataset's own, not paraphrases.

| Indicator | Family | Name |
|---|---|---|
| `KSI-CED-RAT` | Cybersecurity Education | Reviewing All Training |
| `KSI-CMT-LMC` | Change Management | Logging Changes |
| `KSI-CNA-RNT` | Cloud Native Architecture | Restricting Network Traffic |
| `KSI-IAM-AAM` | Identity and Access Management | Automating Account Management |
| `KSI-IAM-APM` | Identity and Access Management | Adopting Passwordless Methods |
| `KSI-INR-RIR` | Incident Response | Reviewing Incident Response Procedures |
| `KSI-SVC-SIN` | Service Configuration | Securing Information |

If you are treating Class A as a starting point on the way to Class B, know that the jump is large: 41 rules to 157, and 7 indicators to 46. Plan it as a separate project rather than an increment.

## Choosing

Pick based on what your federal customers need, not on what is easiest to document. Two practical considerations.

A class change is itself a significant change. `FRD-CCC` defines a Certification Class Change as a type of significant change likely to change the class for the entire offering, which means moving from B to C later triggers the notification machinery in the `SCN` family. Getting the class right the first time is cheaper than being right eventually.

Class C carries the calendar dependencies above. If you know you need Class C, start the validation history and metric retention clocks now, even while the rest of the record is still `TBD`. Those are the only two requirements in the framework where waiting costs you time you cannot buy back.

## Switching class in this repository

One field in `profiles/common/offering-profile.json`:

```json
{
  "certification_class": "C"
}
```

Then rebuild:

```bash
python sdr.py all
```

The profiles are already generated for all three supported classes, so switching is instant. What changes is which profile `build_sdr.py` reads, which rules appear in the deliverables, and which minimum the validator enforces for `ksi_test_minimums`.

Your record store is shared across classes. Entries for rules outside your class stay in the file and are ignored, so switching does not lose work. Going from C to B does not delete your second automated method per indicator; it just stops requiring it.

## Class D

`profiles/class-d-future/readiness-register.json` holds 157 rules resolved against the class D variants already present in the dataset, plus a `delta_from_class_c` block so a Class C provider can see exactly what tightens.

It is a planning aid, nothing more. Its metadata carries `status: FedRAMP pending`. On September 9, 2026 FedRAMP opened [RFC-0033](https://www.fedramp.gov/rfcs/0033/), "20x Phase 4 Development Tracks for 20x Class D," which states that detailed proposed Class D requirements will be released during the pilot and previews the direction: Class D will require holding a Class C certification without corrective action for 6 months to become eligible, deployment on a Class D certified IaaS/PaaS, and new Key Security Indicators including a theme for Foreign Ownership, Control, or Influence (FOCI). RFC-0033 anticipates a full-requirements RFC on October 14, 2026, final pilot requirements around November 18, 2026, and the pilot during FY27 Q1 to Q2. The register will change as those land. Nothing in it constitutes a claim of Class D readiness, and the framework will not generate a Class D deliverable.

See the [implementation guide](implementation-guide.md) for filling in a class once you have chosen, or [validation](validation.md) for how the per-class minimums are enforced.
