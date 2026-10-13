#!/usr/bin/env python3
"""Offline tests for the evidence-signing layer (automation/collectors).

No network, no boto3: a FakeKMS records sign/verify calls and simulates a real
asymmetric key over a stable in-memory keypair-substitute (it maps a message to
a deterministic "signature" and verifies by re-deriving it). This lets us assert
the SEMANTICS the module promises:
  - a content hash is signed and the block is well-formed
  - a valid signature verifies
  - a fact changed after signing fails verification BEFORE calling KMS
  - a tampered signature fails verification (KMS says invalid)
  - a non-canonical hash is refused (not silently signed)
  - a refused KMS sign is a SigningError, never a silent success
  - an entry with no content hash cannot be signed

Run: python automation/collectors/test_sign_evidence.py
"""

import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sign_evidence as se
from evidence_wiring import evidence_hash

PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS {name}")
    else:
        FAIL += 1; print(f"  FAIL {name}")


class FakeKMSInvalidSignature(Exception):
    def __init__(self):
        super().__init__("invalid")
        self.response = {"Error": {"Code": "KMSInvalidSignatureException"}}


class FakeKMS:
    """Deterministic stand-in for a KMS asymmetric key. The 'signature' is a
    hash of (key_id || message); verify recomputes it. Not cryptography - it
    exercises the module's control flow and the sign/verify contract offline."""

    def __init__(self, key_id="fake-signer-key-for-tests-not-an-arn",
                 fail_sign=False, empty_sig=False):
        self.key_id = key_id
        self.fail_sign = fail_sign
        self.empty_sig = empty_sig
        self.sign_calls = []
        self.verify_calls = []

    def _mac(self, message):
        return hashlib.sha256(self.key_id.encode() + b"|" + message).digest()

    def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
        self.sign_calls.append((KeyId, Message, MessageType, SigningAlgorithm))
        if self.fail_sign:
            raise RuntimeError("kms unavailable")
        if self.empty_sig:
            return {"Signature": b""}
        return {"Signature": self._mac(Message)}

    def verify(self, KeyId, Message, MessageType, Signature, SigningAlgorithm):
        self.verify_calls.append((KeyId, Message, MessageType, SigningAlgorithm))
        if Signature != self._mac(Message):
            raise FakeKMSInvalidSignature()
        return {"SignatureValid": True}


def test_sign_and_verify_roundtrip():
    kms = FakeKMS()
    fact = {"service": "iam", "check": "mfa", "status": "pass"}
    h = evidence_hash(fact)
    block = se.sign_hash(kms, kms.key_id, h, when="2026-09-18")
    check("signed block carries the exact signed hash", block["signedHash"] == h)
    check("signed block records the key id", block["keyId"] == kms.key_id)
    check("signed block algorithm is ECDSA_SHA_256",
          block["algorithm"] == "ECDSA_SHA_256")
    check("valid signature verifies",
          se.verify_signature(kms, block, recomputed_hash=h) is True)


def test_changed_fact_fails_before_kms():
    kms = FakeKMS()
    fact = {"service": "iam", "check": "mfa", "status": "pass"}
    block = se.sign_hash(kms, kms.key_id, evidence_hash(fact))
    # Attacker edits the fact (pass -> the same shape but different content).
    tampered = {"service": "iam", "check": "mfa", "status": "FAIL-hidden"}
    before = len(kms.verify_calls)
    result = se.verify_signature(kms, block, recomputed_hash=evidence_hash(tampered))
    check("changed fact fails verification", result is False)
    check("changed-fact failure does not even call KMS",
          len(kms.verify_calls) == before)


def test_tampered_signature_fails():
    kms = FakeKMS()
    h = evidence_hash({"service": "s3", "check": "encryption", "status": "pass"})
    block = se.sign_hash(kms, kms.key_id, h)
    block["signature"] = se.base64.b64encode(b"not-the-real-signature").decode()
    check("tampered signature fails verification",
          se.verify_signature(kms, block, recomputed_hash=h) is False)


def test_non_canonical_hash_refused():
    kms = FakeKMS()
    try:
        se.sign_hash(kms, kms.key_id, "deadbeef")  # not sha256:<hex>
        check("non-canonical hash is refused", False)
    except se.SigningError:
        check("non-canonical hash is refused", True)


def test_refused_kms_sign_is_error():
    kms = FakeKMS(fail_sign=True)
    h = evidence_hash({"service": "kms", "check": "rotation", "status": "pass"})
    try:
        se.sign_hash(kms, kms.key_id, h)
        check("refused KMS sign raises SigningError", False)
    except se.SigningError:
        check("refused KMS sign raises SigningError", True)


def test_empty_signature_is_error():
    kms = FakeKMS(empty_sig=True)
    h = evidence_hash({"service": "kms", "check": "rotation", "status": "pass"})
    try:
        se.sign_hash(kms, kms.key_id, h)
        check("empty KMS signature raises SigningError", False)
    except se.SigningError:
        check("empty KMS signature raises SigningError", True)


def test_attach_signature_needs_hash():
    kms = FakeKMS()
    try:
        se.attach_signature({"evidenceType": "Report"}, kms, kms.key_id)
        check("entry with no content hash cannot be signed", False)
    except se.SigningError:
        check("entry with no content hash cannot be signed", True)


def test_attach_signature_in_place():
    kms = FakeKMS()
    entry = {"evidenceType": "Policy",
             "xEvidenceContentHash": evidence_hash({"service": "iam", "s": 1})}
    block = se.attach_signature(entry, kms, kms.key_id)
    check("attach stores the block on the entry",
          entry.get("xEvidenceSignature") == block)


def test_f60_signature_block_never_carries_the_key_arn_or_account():
    # AUD-F60: the block is rendered into the SDR and the record store, which
    # the package gate scans for account ids and ARNs. Signing with the key ARN
    # (the documented pin form) must record only the key id.
    import json
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "validation", "scripts"))
    import validate_sdr  # noqa: E402
    arn = "arn:aws:kms:us-east-1:123456789012:key/1a2b3c4d-0000-4000-8000-00000000abcd"
    kms = FakeKMS(key_id=arn)
    h = evidence_hash({"service": "iam", "check": "mfa", "status": "pass"})
    block = se.sign_hash(kms, arn, h, when="2026-10-13")
    check("KMS is still called with the full key id", kms.sign_calls[0][0] == arn)
    check("block keyId is the key id, not the ARN",
          block["keyId"] == "1a2b3c4d-0000-4000-8000-00000000abcd")
    hits = [label for pat, label in validate_sdr.SENSITIVE_PATTERNS if pat.search(json.dumps(block))]
    check("block trips none of the package gate's sensitive patterns", hits == [])
    check("alias ARN reduces to alias/<name>",
          se.key_reference("arn:aws-us-gov:kms:us-gov-west-1:123456789012:alias/sdr-signer") == "alias/sdr-signer")
    check("a bare key id / label is unchanged",
          se.key_reference("fake-signer-key-for-tests-not-an-arn") == "fake-signer-key-for-tests-not-an-arn")
    check("pinned ARN and block key id compare equal in reference form",
          se.key_reference(arn) == block["keyId"])
    check("a different key is still a different reference",
          se.key_reference(arn.replace("abcd", "ffff")) != block["keyId"])


def main():
    for t in (test_sign_and_verify_roundtrip, test_changed_fact_fails_before_kms,
              test_tampered_signature_fails, test_non_canonical_hash_refused,
              test_refused_kms_sign_is_error, test_empty_signature_is_error,
              test_attach_signature_needs_hash, test_attach_signature_in_place,
              test_f60_signature_block_never_carries_the_key_arn_or_account):
        print(t.__name__); t()
    print(f"\n{PASS}/{PASS + FAIL} passed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
