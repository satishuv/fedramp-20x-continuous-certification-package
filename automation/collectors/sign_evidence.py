#!/usr/bin/env python3
"""Non-repudiation signing for evidence digests (AU-09(02/03/04), AU-10).

The collector produces a sanitized source fact and a SHA-256 content hash
(`evidence_wiring.evidence_hash`). That hash is tamper-EVIDENCE: a reviewer or
CI can recompute it to catch a silently-edited evidence object. It is NOT
tamper-PROOF against a privileged actor who can rewrite the record store AND
recompute the hash, because the same pipeline holds both.

This module closes that gap. It signs the canonical evidence hash with a KMS
ASYMMETRIC key held by a SEPARATE signer principal (the collector IAM role is
denied `kms:Sign` on this key by policy). The signature is stored alongside the
evidence. To forge a record now, an attacker needs `kms:Sign` on the signing
key, which the collector - and, when the key lives in a separate audit account,
the assessed account's admins - do not have. Verification is `kms:Verify` (or an
offline public-key verify), so an assessor can independently confirm the
evidence digest was signed by the audit-account key and has not changed.

TRUST BOUNDARY (unchanged): signing binds a digest to a key; it never sets a
status, never makes a determination, and never decides PASS/FAIL. A signature
attests "this evidence content was recorded and has not changed since," nothing
more. Signing is a SEPARATE step from collection, run by a separate principal,
exactly so the collector's blast radius cannot reach the signing key.

What the signature covers: the canonical `sha256:<hex>` string produced by
`evidence_wiring.evidence_hash` over the BOUND CANONICAL PAYLOAD of the entry
(evidence_wiring.canonical_payload: evidenceType, evidenceDescription,
evidenceLocation, evidenceText, lastUpdated and the sanitized xSourceFact), so
the signature attests every field a reader uses to interpret the observation,
not just the raw fact (AUD-F26). The message the KMS key signs is the ASCII
bytes of that hash string with MessageType='RAW', signing algorithm
ECDSA_SHA_256 (asymmetric ECC_NIST_P256 key). Storing the signature over the
hash (not the payload) keeps the signed message small and lets verification
recompute the hash from the entry first, then verify the signature over it - so
a change to ANY bound field OR to the signature fails.

Offline by construction: pass any object exposing `.sign(...)` / `.verify(...)`
(a boto3 KMS client or a fake). No network in tests.

Storage shape added to an evidence entry (extension namespace, schema-clean):
    xEvidenceSignature: {
        "algorithm": "ECDSA_SHA_256",
        "keyId": "<kms key arn or id used>",
        "signedHash": "sha256:<hex>",   # the exact message that was signed
        "signature": "<base64 DER signature>",
        "signedAt": "<ISO8601 date>",
    }
"""

import base64
import datetime


SIGNING_ALGORITHM = "ECDSA_SHA_256"


class SigningError(RuntimeError):
    """Raised when a requested signing/verification operation cannot be
    completed. A refused signature must never be a silent success."""


def _today_iso():
    return datetime.date.today().isoformat()


def sign_hash(kms_client, key_id, content_hash, *, when=None):
    """Sign a canonical evidence hash string with a KMS asymmetric key.

    kms_client   : object exposing sign(KeyId, Message, MessageType,
                   SigningAlgorithm) -> {"Signature": bytes, ...}
    key_id       : the signing key ARN/id (held by the SEPARATE signer principal)
    content_hash : the 'sha256:<64 hex>' string from evidence_wiring.evidence_hash

    Returns the xEvidenceSignature dict. Raises SigningError on any failure -
    a refused signature is never reported as success.
    """
    if not isinstance(content_hash, str) or not content_hash.startswith("sha256:"):
        raise SigningError(
            f"refusing to sign a non-canonical hash {content_hash!r}; expected "
            "'sha256:<64 hex>' from evidence_wiring.evidence_hash")
    try:
        resp = kms_client.sign(
            KeyId=key_id,
            Message=content_hash.encode("ascii"),
            MessageType="RAW",
            SigningAlgorithm=SIGNING_ALGORITHM,
        )
    except Exception as e:  # noqa: BLE001 - normalize any KMS/client failure
        raise SigningError(
            f"KMS sign failed for key {key_id!r} ({type(e).__name__}); refusing "
            "to report a signed evidence entry without a real signature") from e
    sig = resp.get("Signature")
    if not sig:
        raise SigningError(
            f"KMS sign returned no Signature for key {key_id!r}; refusing to "
            "record an empty signature")
    return {
        "algorithm": SIGNING_ALGORITHM,
        "keyId": key_id,
        "signedHash": content_hash,
        "signature": base64.b64encode(sig).decode("ascii"),
        "signedAt": when or _today_iso(),
    }


def verify_signature(kms_client, signature_block, *, recomputed_hash=None):
    """Verify an xEvidenceSignature block with KMS.

    kms_client      : object exposing verify(KeyId, Message, MessageType,
                      Signature, SigningAlgorithm) -> {"SignatureValid": bool}
    signature_block : the xEvidenceSignature dict produced by sign_hash
    recomputed_hash : if provided, the hash freshly recomputed from xSourceFact.
                      It MUST equal the block's signedHash, otherwise the fact
                      changed after signing and verification fails BEFORE the
                      KMS call (a changed fact is a failure even if the old
                      signature over the old hash would still verify).

    Returns True only when the signed hash still matches the fact AND KMS
    confirms the signature. Raises SigningError if the block is malformed or the
    KMS verify call itself errors (cannot-verify is not verified).
    """
    if not isinstance(signature_block, dict):
        raise SigningError("signature block is not a dict")
    signed_hash = signature_block.get("signedHash")
    key_id = signature_block.get("keyId")
    sig_b64 = signature_block.get("signature")
    algo = signature_block.get("algorithm", SIGNING_ALGORITHM)
    if not (signed_hash and key_id and sig_b64):
        raise SigningError(
            "signature block missing signedHash/keyId/signature")
    if recomputed_hash is not None and recomputed_hash != signed_hash:
        # The evidence fact changed after it was signed. Fail without even
        # calling KMS - the signature is over stale content.
        return False
    try:
        signature = base64.b64decode(sig_b64)
    except Exception as e:  # noqa: BLE001
        raise SigningError(f"signature is not valid base64: {e}") from e
    try:
        resp = kms_client.verify(
            KeyId=key_id,
            Message=signed_hash.encode("ascii"),
            MessageType="RAW",
            Signature=signature,
            SigningAlgorithm=algo,
        )
    except Exception as e:  # noqa: BLE001
        # KMS raises on an invalid signature (KMSInvalidSignatureException) AND
        # on operational errors. Either way we cannot assert a valid signature,
        # so this is NOT verified. Distinguish a clean "invalid" from an error
        # only in the message; both return unverified.
        code = getattr(e, "response", {}).get("Error", {}).get("Code",
                                                               type(e).__name__)
        if "InvalidSignature" in str(code):
            return False
        raise SigningError(
            f"KMS verify errored for key {key_id!r} ({code}); cannot assert a "
            "valid signature") from e
    return bool(resp.get("SignatureValid", False))


def attach_signature(evidence_entry, kms_client, key_id, *, when=None):
    """Sign an evidence entry's content hash in place and attach the block.

    Reads xEvidenceContentHash (set by evidence_wiring.fact_to_evidence),
    signs it, and stores the result under xEvidenceSignature. Returns the
    signature block. Raises SigningError if the entry has no content hash to
    sign (you cannot sign what was never hashed)."""
    if not isinstance(evidence_entry, dict):
        raise SigningError("evidence_entry must be a dict")
    content_hash = evidence_entry.get("xEvidenceContentHash")
    if not content_hash:
        raise SigningError(
            "evidence entry has no xEvidenceContentHash to sign; run it through "
            "evidence_wiring.fact_to_evidence first")
    block = sign_hash(kms_client, key_id, content_hash, when=when)
    evidence_entry["xEvidenceSignature"] = block
    return block


# ---------------------------------------------------------------------------
# Offline, CI-runnable cryptographic verification against a PINNED trusted
# signer (findings 7 and 8). The gate must NOT trust the keyId carried inside
# the evidence object (circular), and must NOT merely check that a signature
# blob exists. It must cryptographically verify the signature over the signed
# hash using a public key the VERIFIER pins independently - obtained once via
# kms:GetPublicKey and stored in the release trust config - so that forging a
# record requires the audit-account signing key, which the collector and the
# assessed accounts do not hold.
# ---------------------------------------------------------------------------

import hashlib


def public_key_fingerprint(pubkey_der_or_pem):
    """SHA-256 fingerprint of a signer public key, for pinning by digest.

    Accepts DER bytes or a PEM string. Returns 'sha256:<hex>' over the DER
    SubjectPublicKeyInfo bytes (the stable, encoding-independent identity of
    the key), so a profile can pin a short fingerprint instead of the whole key.
    """
    from cryptography.hazmat.primitives import serialization
    if isinstance(pubkey_der_or_pem, str):
        pub = serialization.load_pem_public_key(pubkey_der_or_pem.encode("ascii"))
    elif isinstance(pubkey_der_or_pem, (bytes, bytearray)):
        data = bytes(pubkey_der_or_pem)
        try:
            pub = serialization.load_der_public_key(data)
        except Exception:  # noqa: BLE001
            pub = serialization.load_pem_public_key(data)
    else:
        raise SigningError("public key must be PEM str or DER bytes")
    der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    return "sha256:" + hashlib.sha256(der).hexdigest()


def verify_signature_offline(signature_block, trusted_public_key, *,
                             recomputed_hash=None, expected_fingerprint=None):
    """Cryptographically verify an xEvidenceSignature block OFFLINE against a
    PINNED trusted public key - no KMS call, no network, CI-runnable.

    signature_block     : the xEvidenceSignature dict produced by sign_hash.
    trusted_public_key  : the signer's public key the VERIFIER pins (PEM str or
                          DER bytes), obtained once via kms:GetPublicKey and
                          stored in the release trust config. NOT taken from the
                          evidence.
    recomputed_hash     : if provided, the hash freshly recomputed from the
                          source fact; MUST equal the block's signedHash or the
                          fact changed after signing (fail BEFORE the crypto).
    expected_fingerprint: if provided ('sha256:<hex>'), the pinned key's own
                          fingerprint MUST match it - a second, independent
                          pinning check so a swapped trusted_public_key is caught.

    Returns True ONLY when the signed hash still matches the fact AND the
    signature verifies under the pinned key. Fail-closed: any malformed input,
    missing library, or verification failure returns False (or raises
    SigningError for a structural problem), never a silent pass.
    """
    if not isinstance(signature_block, dict):
        raise SigningError("signature block is not a dict")
    signed_hash = signature_block.get("signedHash")
    sig_b64 = signature_block.get("signature")
    if not (signed_hash and sig_b64):
        raise SigningError("signature block missing signedHash/signature")
    if recomputed_hash is not None and recomputed_hash != signed_hash:
        return False  # fact changed after signing; signature is over old content
    if not trusted_public_key:
        # No pinned trusted signer configured: we CANNOT assert a verified
        # signature. Fail closed - never treat "cannot verify" as verified.
        raise SigningError(
            "no trusted signer public key pinned; refusing to assert a verified "
            "signature (findings 7/8: verification must use an independently "
            "pinned key, not the keyId carried in the evidence)")
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, utils as _ecutils
    except Exception as e:  # noqa: BLE001
        raise SigningError(
            "the cryptography library is required for offline signature "
            "verification but could not be imported; refusing to pass evidence "
            f"signing without it: {e}") from e
    # Load the pinned public key.
    try:
        if isinstance(trusted_public_key, str):
            pub = serialization.load_pem_public_key(trusted_public_key.encode("ascii"))
        else:
            data = bytes(trusted_public_key)
            try:
                pub = serialization.load_der_public_key(data)
            except Exception:  # noqa: BLE001
                pub = serialization.load_pem_public_key(data)
    except Exception as e:  # noqa: BLE001
        raise SigningError(f"pinned trusted public key is unreadable: {e}") from e
    # Optional second pin: the key's own fingerprint must match.
    if expected_fingerprint:
        der = pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        actual = "sha256:" + hashlib.sha256(der).hexdigest()
        if actual != expected_fingerprint:
            raise SigningError(
                f"pinned key fingerprint {actual} does not match the expected "
                f"{expected_fingerprint}; refusing to verify against an "
                "unexpected key")
    try:
        signature = base64.b64decode(sig_b64)
    except Exception as e:  # noqa: BLE001
        raise SigningError(f"signature is not valid base64: {e}") from e
    # KMS ECDSA_SHA_256 signs the message with MessageType RAW: KMS hashes the
    # message with SHA-256 itself and returns a DER-encoded ECDSA signature. We
    # verify the DER signature over the same message bytes (the signed_hash
    # ASCII string) with SHA-256.
    try:
        pub.verify(signature, signed_hash.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except Exception:  # noqa: BLE001 - InvalidSignature or any verify failure
        return False
    return True
