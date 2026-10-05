#!/usr/bin/env python3
"""Publish the durable metric history with a compare-and-swap, never a blind
overwrite (AUD-F20), and archive every run's observations append-only.

The scheduled collect build used to `aws s3 cp` the history DOWN, append, and
`aws s3 cp` it back UP. Two overlapping runs (a retry beside a scheduled run,
two regions' collectors, a manual trigger) could both read version N, each
append its own datapoint, and the later upload silently discard the earlier
run's observations. S3 versioning kept the lost bytes recoverable but nothing
noticed the loss, and "persistent validation" history is exactly the record
that must not lose runs.

    python automation/metrics/publish_history.py restore   # download + remember ETag
    python automation/metrics/publish_history.py publish   # conditional upload

restore   GETs s3://$EVIDENCE_BUCKET/metrics/metric-history.json to the local
          history path and records its ETag in a sidecar. A confirmed-missing
          object (first run) is allowed; any other error exits non-zero so the
          run never appends onto absent history (fail closed, as before).
publish   1. PUTs this run's observations to
             metrics/observations/<UTC date>/<run id>.json with If-None-Match:*
             (create-only; an existing key is never overwritten), so the
             run-level record survives regardless of what happens to the rollup.
          2. PUTs the updated history with If-Match: <ETag from restore> (or
             If-None-Match:* when restore found no object). A 412
             PreconditionFailed means another writer landed first: exit 3 and
             the build re-runs restore -> append -> publish (bounded retries in
             the buildspec) instead of overwriting the other run's datapoints.

Both conditional-write forms are native S3 request headers (If-Match /
If-None-Match on PutObject); no lock table is needed. The client is injectable
so the offline test drives the whole protocol with a fake.
"""
import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HISTORY = os.path.join(BASE, "automation", "metrics", "metric-history.json")

# AUD-F37: the digest the signer attests, and the KMS signing primitive the
# evidence path already uses.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))
import history_integrity as hi  # noqa: E402
import sign_evidence as se  # noqa: E402
ETAG_SIDECAR = HISTORY + ".etag"
HISTORY_KEY = "metrics/metric-history.json"
OBSERVATIONS_PREFIX = "metrics/observations"

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFLICT = 3  # another writer won; caller must restore+append+publish again


def _error_code(exc):
    try:
        return exc.response.get("Error", {}).get("Code", "")
    except AttributeError:
        return ""


def _http_status(exc):
    try:
        return int(exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", 0))
    except (AttributeError, TypeError, ValueError):
        return 0


def _is_missing(exc):
    return _error_code(exc) in ("NoSuchKey", "404", "NotFound") or _http_status(exc) == 404


def _is_precondition_failed(exc):
    return (_error_code(exc) in ("PreconditionFailed", "412")
            or _http_status(exc) == 412)


def restore(s3, bucket, history_path=HISTORY, etag_path=ETAG_SIDECAR, log=print):
    """Download the durable history and remember its ETag. Returns an exit code."""
    try:
        resp = s3.get_object(Bucket=bucket, Key=HISTORY_KEY)
    except Exception as exc:  # noqa: BLE001 - classify, do not guess
        if _is_missing(exc):
            log("No prior metric-history.json (confirmed missing); first run.")
            if os.path.exists(history_path):
                os.remove(history_path)
            with open(etag_path, "w", encoding="utf-8") as f:
                f.write("")  # empty sidecar = create-only publish
            return EXIT_OK
        log(f"FAIL. Could not restore metric history and the object is not confirmed "
            f"missing ({_error_code(exc) or type(exc).__name__}). Aborting so a transient "
            "error does not lead to appending onto absent history.")
        return EXIT_ERROR
    body = resp["Body"].read()
    os.makedirs(os.path.dirname(history_path), exist_ok=True)
    with open(history_path, "wb") as f:
        f.write(body)
    etag = (resp.get("ETag") or "").strip()
    with open(etag_path, "w", encoding="utf-8") as f:
        f.write(etag)
    log(f"Restored prior metric history (ETag {etag or 'unknown'}).")
    return EXIT_OK


def _run_observations(history, run_id, observed_at):
    """This run's observations only (those stamped with observed_at), as one
    immutable object. Empty when the appender recorded nothing this run."""
    out = {}
    for kid, entry in (history.get("ksis") or {}).items():
        mine = [o for o in (entry.get("observations") or [])
                if o.get("observed_at") == observed_at]
        if mine:
            out[kid] = mine
    return {"run_id": run_id, "observed_at": observed_at,
            "dataset_version": (history.get("meta") or {}).get("dataset_version"),
            "ksis": out}


def publish(s3, bucket, history_path=HISTORY, etag_path=ETAG_SIDECAR, run_id=None,
            log=print, kms=None, sign_key_arn=None):
    """Conditionally upload the history and archive this run's observations.

    AUD-F37: when sign_key_arn (and a KMS client) is given, the history digest
    (history_integrity.history_digest over every KSI's chain head) is signed
    with that key and stored under meta.history_signature BEFORE upload, so the
    durable object carries the separate signer's attestation of the chain head.
    A signing failure is a publish failure: the caller asked for an attested
    history and must not get an unattested one."""
    if not os.path.exists(history_path):
        log("FAIL. No local metric history to publish (append step did not run?).")
        return EXIT_ERROR
    with open(history_path, "rb") as f:
        body = f.read()
    try:
        history = json.loads(body.decode("utf-8"))
    except ValueError as exc:
        log(f"FAIL. Local metric history is not valid JSON: {exc}")
        return EXIT_ERROR
    if sign_key_arn:
        if kms is None:
            log("FAIL. --sign-key-arn given but no KMS client; refusing to publish an "
                "unsigned history when signing was requested.")
            return EXIT_ERROR
        try:
            digest = hi.record_heads(history)
            history.setdefault("meta", {})["history_signature"] = se.sign_hash(kms, sign_key_arn, digest)
        except Exception as exc:  # noqa: BLE001 - fail closed
            log(f"FAIL. Could not sign the metric history digest: {type(exc).__name__}: {exc}")
            return EXIT_ERROR
        body = json.dumps(history, indent=1).encode("utf-8")
        with open(history_path, "wb") as f:
            f.write(body)
        log(f"Signed metric history digest {digest[:23]}... with {sign_key_arn}.")
    etag = ""
    if os.path.exists(etag_path):
        with open(etag_path, encoding="utf-8") as f:
            etag = f.read().strip()
    observed_at = (history.get("meta") or {}).get("last_observed_at") or \
        datetime.now(timezone.utc).isoformat(timespec="seconds")
    run_id = run_id or uuid.uuid4().hex[:12]

    # 1. Append-only run record. If-None-Match:* makes the PUT create-only.
    obs = _run_observations(history, run_id, observed_at)
    obs_key = f"{OBSERVATIONS_PREFIX}/{observed_at[:10]}/{run_id}.json"
    try:
        s3.put_object(Bucket=bucket, Key=obs_key, IfNoneMatch="*",
                      Body=json.dumps(obs, indent=1).encode("utf-8"),
                      ContentType="application/json")
        log(f"Archived this run's observations: {obs_key} ({len(obs['ksis'])} KSI(s)).")
    except Exception as exc:  # noqa: BLE001
        if _is_precondition_failed(exc):
            # Same run id, already archived (a previous attempt of THIS run
            # archived it before its history CAS lost the race). Keep the first
            # record: append-only means never overwrite, and a retry must not
            # fail on its own earlier success.
            log(f"Run observations already archived at {obs_key}; keeping the "
                "existing immutable record.")
        else:
            log(f"FAIL. Could not archive run observations: "
                f"{_error_code(exc) or type(exc).__name__}")
            return EXIT_ERROR

    # 2. Compare-and-swap the rollup history.
    params = {"Bucket": bucket, "Key": HISTORY_KEY, "Body": body,
              "ContentType": "application/json"}
    if etag:
        params["IfMatch"] = etag
    else:
        params["IfNoneMatch"] = "*"
    try:
        resp = s3.put_object(**params)
    except Exception as exc:  # noqa: BLE001
        if _is_precondition_failed(exc):
            log("CONFLICT. The durable metric history changed since it was restored "
                "(another run published first). Not overwriting it; re-run "
                "restore -> append -> publish.")
            return EXIT_CONFLICT
        log(f"FAIL. Could not publish metric history: "
            f"{_error_code(exc) or type(exc).__name__}")
        return EXIT_ERROR
    new_etag = (resp.get("ETag") or "").strip()
    with open(etag_path, "w", encoding="utf-8") as f:
        f.write(new_etag)
    log(f"Published metric history (ETag {new_etag or 'unknown'}).")
    return EXIT_OK


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    ap.add_argument("action", choices=["restore", "publish"])
    ap.add_argument("--bucket", default=os.environ.get("EVIDENCE_BUCKET"))
    ap.add_argument("--run-id", default=os.environ.get("CODEBUILD_BUILD_ID"))
    ap.add_argument("--sign-key-arn", default=os.environ.get("SDR_HISTORY_SIGN_KEY_ARN"),
                    help="AUD-F37: KMS asymmetric key (held by the SEPARATE signer "
                         "principal) that signs the history digest before publish; "
                         "required for evidence_store_profile production-assurance")
    args = ap.parse_args(argv)
    if not args.bucket:
        print("FAIL. --bucket or EVIDENCE_BUCKET is required.")
        return EXIT_ERROR
    import boto3  # imported here so the offline test never needs it
    s3 = boto3.client("s3")
    if args.action == "restore":
        return restore(s3, args.bucket)
    run_id = (args.run_id or "").replace(":", "-").replace("/", "-") or None
    kms = boto3.client("kms") if args.sign_key_arn else None
    return publish(s3, args.bucket, run_id=run_id, kms=kms, sign_key_arn=args.sign_key_arn)


if __name__ == "__main__":
    sys.exit(main())
