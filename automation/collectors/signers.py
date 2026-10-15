"""Pluggable evidence signer contract (MCE-08; AUD-F74).

One contract, several signers, one unchanged verifier. Every signer turns a
canonical evidence hash ('sha256:<64 hex>') into the existing xEvidenceSignature
block shape that `sign_evidence.sign_hash` has always produced:

    {"algorithm": "ECDSA_SHA_256", "keyId": <key reference>,
     "signedHash": <the hash>, "signature": <base64 DER>, "signedAt": <date>}

so `validate_evidence.py` verifies every block through the one offline path
(`sign_evidence.verify_signature_offline` under the pinned public key, keyId
compared in reference form) with no signer-specific branch. Nothing here sets a
status or makes a determination: a signature attests that this digest was
recorded by the holder of this key and has not changed since.

Signers:

  KmsSigner             the existing AWS KMS path. `sign` returns exactly what
                        `sign_evidence.sign_hash` returns, byte for byte; the
                        AUD-F60 key-reference contract (key id, never the ARN)
                        is unchanged.
  ExternalCommandSigner a separately administered signing service reached
                        through a command the operator supplies. ONLY the hash
                        string crosses the process boundary (stdin); the
                        command returns the base64 DER ECDSA P-256 signature on
                        stdout. Evidence text and source facts never leave this
                        process (MCE-08 AC5).
  SoftwareKeySigner     an ECDSA P-256 private key in PEM, for development and
                        fixtures. A software key is held by whoever holds the
                        file, so it is NOT separately administered from the
                        pipeline that runs it: package-preflight blocks it under
                        evidence_store_profile production-assurance (AC4).

Key references for the non-KMS signers are operator-chosen LABELS checked by
shape (`check_key_reference`): a block is rendered into the package the
no_sensitive_patterns gate scans, so a reference that is an ARN, a URL, a
12-digit account id, or a GUID-shaped tenant / subscription / compartment /
project identifier is refused here, before any block exists (AC3). The
downstream gate still catches account ids and ARNs (AUD-F60); it cannot tell a
tenant GUID from the KMS key-id GUID the AWS path legitimately records, which
is why this contract refuses GUID shapes for the non-KMS signers.

The profile declares which kind of signer is in use
(`expected_evidence_signer.signer_kind`, one of SIGNER_KINDS) so preflight can
reason about the administration boundary without any vendor name.
"""

import base64
import re
import subprocess

from sign_evidence import SIGNING_ALGORITHM, SigningError, _today_iso, sign_hash

# The administration boundary a provider declares for its signer. Neutral
# names: a managed key service is any cloud provider's key-management or HSM
# service; an external command is any separately administered signing service.
SIGNER_KINDS = ("managed-key-service", "external-command", "software-key")
NOT_SEPARATELY_ADMINISTERED = ("software-key",)

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# A key reference LABEL: lower-case slug, 3 to 64 characters, no path or URL.
_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
_GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
# Stricter than the downstream gate on purpose: any run of 12 or more digits,
# whatever its neighbours, is refused in a label.
_ACCOUNT_RE = re.compile(r"\d{12,}")


def check_key_reference(ref):
    """Refuse a key reference that would publish an identifier (AC3). Returns
    the reference unchanged when it is an acceptable label."""
    s = str(ref or "").strip()
    if not s:
        raise SigningError("key reference is empty; choose a label such as 'audit-signer-2026'")
    low = s.lower()
    if low.startswith("arn:"):
        raise SigningError("key reference must not be an ARN (it carries the signer's account id); "
                           "use a label")
    if "://" in s or "/" in s or "\\" in s:
        raise SigningError("key reference must not be a URL or path (it names the signer's "
                           "vault or project); use a label")
    if _ACCOUNT_RE.search(s):
        raise SigningError("key reference must not contain a 12-digit account identifier")
    if _GUID_RE.search(s):
        raise SigningError("key reference must not contain a GUID (a tenant, subscription, "
                           "compartment or project identifier would be published); use a label")
    if not _LABEL_RE.match(s):
        raise SigningError(f"key reference {s!r} is not a label (lower-case letters, digits, "
                           "'.', '_' or '-', 3 to 64 characters)")
    return s


def _check_hash(content_hash):
    if not isinstance(content_hash, str) or not _HASH_RE.match(content_hash):
        raise SigningError(
            f"refusing to sign a non-canonical hash {content_hash!r}; expected "
            "'sha256:<64 hex>' from evidence_wiring.evidence_hash")
    return content_hash


def _block(key_reference, content_hash, signature_der, when=None):
    """The one block shape every signer returns (identical to sign_hash's)."""
    if not signature_der:
        raise SigningError("signer returned an empty signature; refusing to record it")
    return {
        "algorithm": SIGNING_ALGORITHM,
        "keyId": key_reference,
        "signedHash": content_hash,
        "signature": base64.b64encode(bytes(signature_der)).decode("ascii"),
        "signedAt": when or _today_iso(),
    }


class Signer:
    """Contract: sign(content_hash, when=None) -> xEvidenceSignature block."""
    kind = None            # one of SIGNER_KINDS
    key_reference = None   # what the block records as keyId

    def sign(self, content_hash, *, when=None):
        raise NotImplementedError


class KmsSigner(Signer):
    """The existing AWS KMS path, unchanged: delegates to sign_evidence.sign_hash,
    so the block is byte-identical to what callers have always received."""
    kind = "managed-key-service"

    def __init__(self, kms_client, key_id):
        from sign_evidence import key_reference as _kr
        self._kms = kms_client
        self._key_id = key_id
        self.key_reference = _kr(key_id)

    def sign(self, content_hash, *, when=None):
        return sign_hash(self._kms, self._key_id, content_hash, when=when)


class ExternalCommandSigner(Signer):
    """A separately administered signing service behind an operator-supplied
    command. The command receives ONLY the canonical hash string on stdin and
    must print the base64 DER ECDSA P-256 signature over the ASCII bytes of
    that string on stdout. Nothing else is passed: no evidence text, no source
    facts, no file paths (AC5)."""
    kind = "external-command"

    def __init__(self, argv, key_reference, *, timeout=60):
        if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(a, str) for a in argv):
            raise SigningError("external signer command must be a non-empty list of strings")
        self._argv = list(argv)
        self._timeout = timeout
        self.key_reference = check_key_reference(key_reference)

    def sign(self, content_hash, *, when=None):
        _check_hash(content_hash)
        try:
            r = subprocess.run(self._argv, input=content_hash.encode("ascii"),
                               capture_output=True, timeout=self._timeout, check=False)
        except Exception as e:  # noqa: BLE001 - any launch failure is a signing failure
            raise SigningError(f"external signer could not run ({type(e).__name__}); refusing to "
                               "report a signed entry without a real signature") from e
        if r.returncode != 0:
            raise SigningError(f"external signer exited {r.returncode}; refusing to record a signature")
        try:
            der = base64.b64decode(r.stdout.strip(), validate=True)
        except Exception as e:  # noqa: BLE001
            raise SigningError("external signer output is not base64; refusing to record it") from e
        return _block(self.key_reference, content_hash, der, when)


class SoftwareKeySigner(Signer):
    """An ECDSA P-256 private key in PEM. Development and fixtures only: a
    software key is administered by whoever holds the file, so under
    production-assurance preflight blocks this kind (AC4)."""
    kind = "software-key"

    def __init__(self, private_key_pem, key_reference, *, password=None):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        pem = private_key_pem.encode("ascii") if isinstance(private_key_pem, str) else bytes(private_key_pem)
        try:
            key = serialization.load_pem_private_key(pem, password=password)
        except Exception as e:  # noqa: BLE001
            raise SigningError(f"software signing key could not be loaded ({type(e).__name__})") from e
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
            raise SigningError("software signing key must be ECDSA P-256 (secp256r1) to match "
                               f"{SIGNING_ALGORITHM} and the offline verifier")
        self._key = key
        self.key_reference = check_key_reference(key_reference)

    def public_key_pem(self):
        from cryptography.hazmat.primitives import serialization
        return self._key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")

    def sign(self, content_hash, *, when=None):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        _check_hash(content_hash)
        der = self._key.sign(content_hash.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        return _block(self.key_reference, content_hash, der, when)


def sign_entry(evidence_entry, signer, *, when=None):
    """Sign an evidence entry's content hash in place through any Signer and
    attach the block (the contract form of sign_evidence.attach_signature)."""
    if not isinstance(evidence_entry, dict):
        raise SigningError("evidence_entry must be a dict")
    if not isinstance(signer, Signer):
        raise SigningError("signer must implement the Signer contract")
    content_hash = evidence_entry.get("xEvidenceContentHash")
    if not content_hash:
        raise SigningError(
            "evidence entry has no xEvidenceContentHash to sign; run it through "
            "evidence_wiring.fact_to_evidence first")
    block = signer.sign(content_hash, when=when)
    evidence_entry["xEvidenceSignature"] = block
    return block


def signer_administration_findings(signer_decl, production=False):
    """AUD-F74 / MCE-08 AC4. Read the offering profile's expected_evidence_signer
    declaration and return (level, message) tuples, level 'hard' or 'warning'.

    Signing not in use (nothing pinned): no finding. A pinned signer with no
    `signer_kind`: a warning asking for the declaration. An unknown kind: hard
    under every profile (no silent default, as AUD-F37 does for the store
    profile). A software key under production-assurance: hard, because the key
    is held by the pipeline that runs it and is therefore not separately
    administered from the collectors; under development, a warning. Every
    message states what the package expects, not a compliance verdict. Pure."""
    out = []
    if not isinstance(signer_decl, dict):
        return out

    def _set(v):
        return v is not None and str(v).strip() != "" and not str(v).strip().startswith("TBD")

    pinned = _set(signer_decl.get("public_key_pem")) or _set(signer_decl.get("public_key_pem_path"))
    if not pinned:
        return out
    kind = signer_decl.get("signer_kind")
    if not _set(kind):
        out.append(("warning", "a trusted evidence signer is pinned but expected_evidence_signer."
                               "signer_kind is not declared; the package expects one of "
                               + ", ".join(SIGNER_KINDS) + " so the signer's administration "
                               "boundary is stated"))
        return out
    kind = str(kind).strip().lower()
    if kind not in SIGNER_KINDS:
        out.append(("hard", f"expected_evidence_signer.signer_kind {kind!r} is not one of "
                            + ", ".join(SIGNER_KINDS)))
        return out
    if kind in NOT_SEPARATELY_ADMINISTERED:
        msg = ("the configured evidence signer is a software key (expected_evidence_signer."
               "signer_kind software-key): the key is held by the pipeline that runs it, so the "
               "signer is not separately administered from the collectors and the signature "
               "moves the trust rather than removing it")
        if production:
            out.append(("hard", msg + "; evidence_store_profile production-assurance declares a "
                        "separately administered signer, so this contradicts the declaration"))
        else:
            out.append(("warning", msg + "; acceptable under the development profile, a blocker "
                        "under production-assurance"))
    return out
