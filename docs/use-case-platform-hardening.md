# Use case: platform hardening evidence with native AWS tooling

A team that owns image builds, certificates, secrets, network controls and logging rarely needs the whole 46-indicator picture at once. This use case narrows the gap assessment and the evidence collection to the 16 Key Security Indicators (KSIs) those five domains satisfy, using only native AWS services and read-only API calls. It is the pattern to follow when the ask is "give me the FedRAMP 20x evidence for our hardening controls", and it is written so the output can be published as a reusable pattern.

Everything below is read from the pinned CR26 dataset (release recorded in `references/sources.lock.json`). No KSI statement is typed by hand; the profile only selects which indicators are reported.

## What the use case does and does not claim

- It reports whether the automated checks the collectors observed for these 16 indicators passed. That is telemetry about an environment.
- It is not an implementation status and not a compliance determination. A status in the record store changes only through human sign-off. FedRAMP Certification decisions belong to the assessor and the authorizing agency.
- Narrowing the report does not narrow the certification. All 46 indicators still apply at Class C; a use-case report is one workstream's slice of the full package.

## The five domains and their indicators

| Domain | Indicators | Native AWS controls the collectors read |
|---|---|---|
| Image hardening (AMI and container) | KSI-CNA-IBP, KSI-CMT-RMV, KSI-SVC-VRI, KSI-SCR-MON | EC2 Image Builder pipelines with a test component, ECR scan-on-push, ECR immutable tags, Amazon Inspector coverage, CloudFormation drift |
| Certificate management | KSI-SVC-ASM | ACM managed-renewal eligibility, certificates expiring within 30 days, Config rule `acm-certificate-expiration-check`, TLS-only listeners |
| Secrets and configuration (Secrets Manager, Parameter Store, third-party) | KSI-SVC-ASM, KSI-SVC-ACM, KSI-SVC-SIN | Secrets Manager rotation Config rules, Parameter Store SecureString share and customer managed KMS key use, KMS key rotation, Config conformance, CloudFormation drift |
| Networking | KSI-CNA-RNT, KSI-CNA-ULN, KSI-CNA-MAT, KSI-CNA-DFP | Security group posture, AWS WAF web ACLs, Config rules for default security group, authorized ports, common ports, SSH, HTTP to HTTPS redirection, VPC Flow Logs |
| Observability and logging | KSI-MLA-LET, KSI-MLA-OSM, KSI-MLA-RVL, KSI-MLA-EVC, KSI-CMT-LMC | CloudTrail multi-region trail and log file validation, Security Hub aggregation, KMS-encrypted log groups, VPC Flow Logs |

The indicator statements, the force words and the Class C minimum of two automated validation methods per indicator (rule FRC-CSX-VVK) come from the dataset. Run `python sdr.py explain KSI-SVC-ASM` to read any statement in plain language.

## Run it

From the repository root, with read-only credentials to the account under review:

```
python automation/collectors/collect_facts.py --profile READONLY --region us-east-1
python automation/assessment/gap_assessment.py --use-case profiles/use-cases/platform-hardening.json
```

Without an account, `--demo` produces a labelled synthetic store so the report shape can be reviewed:

```
python automation/assessment/gap_assessment.py --demo --use-case profiles/use-cases/platform-hardening.json
```

Output is `automation/assessment/report/gap-assessment.html` and `.json`, titled with the use case and the "16 of 46 indicators" count. The HTML carries the boundary statement above on every page.

## The three collectors added for this use case

All three are read-only, paginate to the end, and report `ERROR:<code>` on access denial rather than a zero (collection failure is never a control failure).

| Collector | Checks it emits | IAM actions it needs |
|---|---|---|
| `image_hardening` | `ecr:scan_on_push` (repositories scanning every pushed image), `imagebuilder:pipelines` (pipelines whose recipe carries a test component) | `ecr:DescribeRepositories`, `imagebuilder:ListImagePipelines`, `imagebuilder:GetImageRecipe`, `imagebuilder:GetContainerRecipe` |
| `certificate_management` | `acm:renewal_eligible`, `acm:expiring_soon` (counted as certificates NOT expiring within 30 days, so higher is better) | `acm:ListCertificates`, `acm:DescribeCertificate` |
| `parameter_store` | `ssm:secure_string` (parameters stored encrypted), `ssm:customer_key` (SecureStrings on a customer managed key) | `ssm:DescribeParameters` |

The deployed collector role in `automation/pipeline/sdr-pipeline.yaml` grants exactly these actions; `automation/collectors/test_collector_iam_matches.py` fails if the allowlist and the role drift apart.

## Parameter Store with compensating controls, for a limited time

The question comes up on most engagements: can secrets live in Parameter Store rather than Secrets Manager for a while, with extra controls? The dataset answers the outcome, not the service. KSI-SVC-ASM asks that management, protection and regular rotation of secrets is automated and persistently reviewed. Parameter Store SecureString with a customer managed key covers protection. It does not rotate, so rotation has to come from somewhere else, or the gap is recorded.

How to record it honestly in this framework:

1. On the KSI-SVC-ASM record in `sdr/records/records-store.json`, fill the `exception` block: the parameter path pattern (never a value), the compensating controls, the owner, the review date and the end date.
2. Point the compensating controls at facts the collectors can see: `ssm:secure_string` at 100 percent, `ssm:customer_key` at 100 percent with `kms:key_rotation` enabled, and a scheduled rotation job whose last successful run is attached as evidence.
3. Keep the provider evidence the collectors cannot see: the IAM policy restricting the parameter path, and a sample of CloudTrail data events for reads.
4. Close the exception when the secret moves to Secrets Manager with rotation enabled, or when the rotation job is accepted as the permanent mechanism and that decision is written into the record.

The exception is re-reviewed on the record's validation frequency. The validator treats an exception past its end date as a readiness finding.

## Publishing the output as a pattern

The JSON report, the use-case profile and this page are the three files a pattern needs. Strip account-specific detail from the report before publishing: regions and counts are fine, resource names are not. The facts store itself (`automation/facts/`) is git-excluded and should stay out of any published artifact.

## Adding another use case

Copy `profiles/use-cases/platform-hardening.json`, change `use_case_id`, the domains and `ksis_in_scope`. The loader refuses a profile whose domain lists and `ksis_in_scope` disagree, and the assessment refuses an indicator id the dataset does not carry, so a typo fails loudly instead of silently dropping an indicator from the report.
