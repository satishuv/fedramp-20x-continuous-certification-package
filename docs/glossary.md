# Glossary

Every abbreviation this repository uses, expanded. Family names are the dataset's own, taken from `traceability/family-names.json`, which is generated from the pinned dataset rather than typed.

## Reading a rule identifier

Rule identifiers have three segments: `FAMILY-SUBSET-RULE`.

```text
        SDR - CSX - KMT
         |     |     |
family --+     |     +-- rule: "Key Security Indicator Metrics"
               |
      subset --+   who or what it applies to; CSX marks a 20x-only rule
```

So `SDR-CSX-KMT` reads as: the Security Decision Record family, the 20x-only subset, the rule named "Key Security Indicator Metrics." Indicator identifiers work the same way with a fixed first segment: `KSI-IAM-ELP` is the Identity and Access Management family, indicator "Ensuring Least Privilege."

The subsets, with how many rules each holds and which applicability layers they appear under:

| Subset | Rules | Applicability | Meaning |
|---|---|---|---|
| `CSO` | 76 | `all` | Applies to a cloud service offering. The bulk of the catalog |
| `IAS` | 23 | `all` | Independent assessment services |
| `FRP` | 16 | `all` | FedRAMP itself, not the provider |
| `TFR` | 15 | `all`, `20x`, `rev5` | Timeframes, in the vulnerability families |
| `CSF` | 11 | `rev5` only | Rev5-carryover rules |
| `USE` | 10 | `all` | Agency use of a certified service |
| `QTR` | 10 | `all` | Quarterly continuous monitoring reviews |
| `AGC` | 9 | `all` | Agency obligations |
| `CSX` | 8 | `20x` only | The 20x-only rules |
| `OCR` | 7 | `all` | Ongoing Certification Reports |
| `TRC` | 6 | `all` | Trust centers |
| `CLA` | 6 | `all` | Certification class scoping |
| `RPT` | 6 | `all` | Vulnerability reporting |

Sixteen more subsets hold five rules or fewer each.

The `CSX` subset matters more than its size suggests. Every 20x-only rule lives there and nowhere else, so an index built only from the `all` applicability layer misses all eight and will report real identifiers as fabricated. See the [traversal problem](architecture.md#the-traversal-problem-and-why-it-is-called-out-everywhere).

## Rule families

| Code | Name |
|---|---|
| `AFC` | Addressing FedRAMP Communication |
| `AGU` | Agency Use of FedRAMP Certified Cloud Services |
| `CCM` | Collaborative Continuous Monitoring |
| `CDS` | Certification Data Sharing |
| `CMU` | Cryptographic Module Use |
| `CPO` | Certification Package Overview |
| `FRC` | FedRAMP Certification |
| `IEC` | Incident Evaluation and Communication |
| `IVV` | Independent Verification and Validation |
| `MAS` | Minimum Assessment Scope |
| `MKT` | Marketplace Listing |
| `REC` | FedRAMP Recognition of Independent Assessment Services |
| `SCG` | Secure Configuration Guide |
| `SCN` | Significant Change Notification |
| `SDR` | Security Decision Record |
| `VDR` | Vulnerability Detection and Response |
| `VER` | Vulnerability Evaluation and Reporting |

## Indicator families

Ten families, 46 indicators.

| Code | Name | Indicators |
|---|---|---|
| `CED` | Cybersecurity Education | 1 |
| `CMT` | Change Management | 4 |
| `CNA` | Cloud Native Architecture | 8 |
| `IAM` | Identity and Access Management | 6 |
| `INR` | Incident Response | 3 |
| `MLA` | Monitoring, Logging, and Auditing | 5 |
| `PIY` | Policy and Inventory | 5 |
| `RPL` | Recovery Planning | 4 |
| `SCR` | Supply Chain Risk | 2 |
| `SVC` | Service Configuration | 8 |

There is no `TPR` indicator family, and `VDR` and `VER` are rule families rather than indicator families. This trips people up often enough to be worth stating.

## Dataset sections

The CR26 dataset has five top-level keys.

| Key | Contents | Count |
|---|---|---|
| `FRR` | FedRAMP Requirements, the rules | 245 entries; 233 in 20x scope |
| `KSI` | Key Security Indicators | 46 |
| `FRD` | FedRAMP Definitions | 80 |
| `CTL` | Control guidance, organized by NIST SP 800-53 control identifier | 79 in 14 control families |
| `info` | Dataset metadata, including the version | |

## Terms

Certification Class (`FRD-CCL`). The category of assurance an offering supplies, "increasing from minimal assurance at Class A to significant assurance at Class D." Not mapped to Low, Moderate, or High anywhere in the dataset.

Certification Data (`FRD-CRD`). "The collective information required by FedRAMP for initial and ongoing FedRAMP Certification of a cloud service offering, including the FedRAMP Certification Package."

Trust Center (`FRD-TRC`). "A secure repository or service used by cloud service providers to store and share FedRAMP Certification Data. Trust centers are the complete and definitive source for FedRAMP Certification Data and must follow the FedRAMP Certification Data Sharing rules to be FedRAMP-compatible." The definitive-source wording is load-bearing: it pulls far more onto a trust center than the `CDS` family alone.

All Necessary Parties (`FRD-ANP`). "All entities whose interests are affected directly by activity related to a specific cloud service offering in the context of FedRAMP Certifications." That "always includes FedRAMP and any agency customer who is using the cloud service offering, but may include additional parties depending on agreements made by the cloud service provider (such as consultants or independent assessors)." Worth reading in full before designing an access model around agency customers alone.

Force. The obligation level on a rule: `MUST`, `SHOULD`, `MAY`, `MUST NOT`, `SHOULD NOT`. A rule carries either a single force, or a `varies_by_class` object with a different force per class.

Verification versus validation. Verification asks whether a control exists. Validation asks whether it keeps working. The record store has separate fields for each because FedRAMP treats them as distinct, and conflating them is the most common authoring error.

Significant Change Notification. The notification obligation when something material changes. Notifications are certification data, so they live on the trust center with the history the `SCN` rules require.

Ongoing Certification Report. The periodic report at the center of continuous monitoring, governed by the `CCM` family, with a feedback mechanism and an anonymized feedback summary.

## Abbreviations

| Short | Full |
|---|---|
| AAL | Authenticator Assurance Level |
| API | Application Programming Interface |
| AWS | Amazon Web Services |
| CI | Continuous Integration |
| CMVP | Cryptographic Module Validation Program |
| CR26 | Consolidated Rules for 2026, the FedRAMP rules dataset |
| CSO | Cloud Service Offering |
| CSP | Cloud Service Provider |
| FAL | Federation Assurance Level |
| FedRAMP | Federal Risk and Authorization Management Program |
| FIPS | Federal Information Processing Standards |
| FRD | FedRAMP Definitions, a dataset section |
| FRR | FedRAMP Requirements, a dataset section |
| GSA | United States General Services Administration |
| IAL | Identity Assurance Level |
| IaC | Infrastructure as Code |
| JSON | JavaScript Object Notation |
| JWE | JSON Web Encryption |
| KSI | Key Security Indicator |
| MAS | Minimum Assessment Scope |
| NIST | National Institute of Standards and Technology |
| OCR | Ongoing Certification Report |
| PII | Personally Identifiable Information |
| SAML | Security Assertion Markup Language |
| SCN | Significant Change Notification |
| SDR | Security Decision Record |
| SNS | Amazon Simple Notification Service |
| SP | Special Publication, as in NIST SP 800-53 |
| UEI | Unique Entity Identifier |
| URL | Uniform Resource Locator |
| YAML | YAML Ain't Markup Language |

## Authoritative source

Everything above derives from [github.com/FedRAMP/rules](https://github.com/FedRAMP/rules), which is the controlling upstream. When this glossary and the dataset disagree, the dataset wins and this page is a bug.

Do not cite archived pilot material as current: RFC-0006 era indicator counts, RFC-0024, or pre-CR26 workbooks using numeric identifiers such as `KSI-IAM-01`. The identifiers changed shape, and quoting the old form in a record signals the whole thing was written from memory.
