# Shift-left policy-as-code (pre-deploy gate)

A companion to the SDR framework that checks infrastructure-as-code **before it
deploys**, in the same spirit as the AWS Security Assurance Services
compliance-engineering demo: an OPA or CFN Guard stage in a CI/CD pipeline that
matches planned resources against policy and blocks non-compliant ones.

Where the SDR framework verifies a **finished record** against the CR26 ruleset,
this checks **planned infrastructure**. They are different control points that
share intent. This example does **not** set or change any SDR status; it is a
pre-deploy gate that produces its own pass/fail and can emit its own evidence.

## What the example enforces

Every `aws_s3_bucket` (or `AWS::S3::Bucket`) must have a bucket policy that
denies non-TLS access (`aws:SecureTransport = false`): the encryption-in-transit
outcome the SDR tracks under the KSI-CNA / SC-8 family.

## Files

- `policy/s3_tls.rego`: the OPA/Rego rule.
- `policy/s3_tls.guard`: the equivalent CFN Guard rule (same intent).
- `fixtures/plan-compliant.json`: a bucket with a TLS-enforcing policy (passes).
- `fixtures/plan-noncompliant.json`: a bare bucket (blocked).
- `run_policy.py`: a local runner that uses the `opa` binary if present, and
  otherwise a pure-Python evaluator of the same rule (so it runs in CI with no
  extra tooling).

## Run it

```bash
# passes, silent, exit 0
python examples/shift-left/run_policy.py examples/shift-left/fixtures/plan-compliant.json

# blocked, prints the violation, exit 1
python examples/shift-left/run_policy.py examples/shift-left/fixtures/plan-noncompliant.json

# dev/alert mode: report but do not block (exit 0)
python examples/shift-left/run_policy.py examples/shift-left/fixtures/plan-noncompliant.json --alert

# emit a JSON evidence record of the run
python examples/shift-left/run_policy.py examples/shift-left/fixtures/plan-compliant.json --evidence run-evidence.json
```

With the real engines:

```bash
opa eval -d examples/shift-left/policy/s3_tls.rego -i plan.json "data.shiftleft.s3.deny"
cfn-guard validate --rules examples/shift-left/policy/s3_tls.guard --data template.yaml
```

## Pipeline semantics

- **Pass** is silent (exit 0), like a clean pipeline stage.
- **Fail** prints each violation and exits 1, blocking the deploy. Use `--alert`
  in development to report without blocking.
- `--evidence PATH` writes a small JSON record of the run for feeding a
  monitoring dashboard or trust center.

## Boundary

This gate is intentionally separate from the SDR generator. It never writes to
the record store and never sets an implementation, validation, or assessment
status. Its output is its own pass/fail plus optional evidence.
