# Durable store provisioning (deploy-time)

The collectors and the metric appender write locally by default. When you wire
the living-SDR loop into your own AWS account, the facts and the per-KSI metric
history should persist in an in-boundary, tamper-resistant store. This is the
one deploy-time **write** step in the repository, kept separate from the
read-only collectors and run explicitly.

## What it does

`provision_store.py` provisions an S3 bucket in **your own account** with:

- **Bucket versioning enabled**: the core feature. Every write keeps prior
  versions, so history is recoverable and tamper-evident.
- Optional **Object Lock (WORM)** (`--object-lock`) for write-once
  tamper-evidence, with a real default retention rule (`--object-lock-mode`
  GOVERNANCE|COMPLIANCE and `--object-lock-days`). Applied at bucket creation for
  a new bucket, or via PutObjectLockConfiguration on an existing versioned
  bucket. Object Lock retention is distinct from `--retention-days` lifecycle
  expiry, which merges with (never replaces) any existing lifecycle rules.
- Optional **lifecycle retention** (`--retention-days N`), a provider policy
  choice, not a default.

## Safety

This step is **safety-additive and idempotent**:

- Creates the bucket only if it does not exist; never recreates an existing one.
- Turns versioning **on**; never suspends it.
- Never deletes a bucket or object, never disables Object Lock.
- Refuses to proceed if the named bucket exists but is owned by another account.
- `--dry-run` reports intended changes without calling AWS.

It provisions storage only. It never writes the record store, never sets an
implementation status, and never writes an assessment.

## Retention and FedRAMP 20x

FedRAMP 20x's governing window for the KSI metric history (`SDR-CSX-KMT`) is
**up to one year**. This tool does not impose a 7-year immutable policy; a
seven-year window is a general records-retention practice, not a 20x rule for
this data. Set `--retention-days` to whatever your applicable policy requires
(about 365 for the metric history), or omit it and manage retention separately.

## Usage

```bash
# Preview
python automation/storage/provision_store.py --bucket my-sdr-store --region us-east-1 --dry-run

# Provision with versioning (least-privilege profile that can write this bucket)
python automation/storage/provision_store.py --bucket my-sdr-store --region us-east-1 --profile deploy

# Versioning + Object Lock (WORM) + 1-year lifecycle
python automation/storage/provision_store.py --bucket my-sdr-store --region us-east-1 \
    --object-lock --retention-days 365 --profile deploy
```

Grant the deploy identity a least-privilege policy scoped to
`s3:CreateBucket`, `s3:PutBucketVersioning`, `s3:GetBucketVersioning`,
`s3:PutLifecycleConfiguration`, and (for `--object-lock`) the Object Lock
permissions, on the target bucket only.
