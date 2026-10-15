#!/usr/bin/env python3
# Regression test for MCE-08 / AUD-F74: the pluggable evidence signer contract
# (automation/collectors/signers.py) with KMS as one implementation.
#
# Finding closed here: the only way to sign evidence was sign_evidence.sign_hash
# bound to a KMS client, and the profile pinned a verifier key but said nothing
# about WHO administers the signing key. A provider on another platform had no
# contract to implement, and a provider on any platform could sign with a PEM
# file held by the same pipeline that collects, under a production-assurance
# declaration of a separately administered signer, and preflight could not
# tell. The verifier is unchanged: every signer yields the one block shape and
# validate_evidence.classify_entry verifies it through the one offline path.
#
# Acceptance criteria exercised:
#   AC1  Signer.sign(content_hash) returns the existing block shape; KmsSigner
#        returns byte for byte what sign_hash returns
#   AC2  a non-KMS signer's block classifies `verified` through the real gate
#        with the pinned public key, and the gate source has no signer branch
#   AC3  a key reference carrying an account, tenant, subscription or
#        compartment identifier is refused by the contract; the downstream
#        no_sensitive_patterns gate still catches account ids and ARNs (AUD-F60)
#   AC4  production-assurance plus a software-key signer is a preflight blocker
#        naming the signer as not separately administered
#   AC5  the external-command signer passes ONLY the content hash to the
#        process; evidence text and source facts never cross the boundary
#
# Run: python automation/collectors/test_signers.py

import base64
import json
import os
import sys
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
import signers  # noqa: E402
import sign_evidence as se  # noqa: E402
import evidence_wiring as ew  # noqa: E402
import validate_evidence as ve  # noqa: E402
import validate_sdr as vs  # noqa: E402

_fail = 0
_BASE_URI = "https://evidence.example.gov/store"
_WHEN = "2026-10-14"


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def _raises(fn, *a, **k):
    try:
        fn(*a, **k)
    except se.SigningError as e:
        return str(e)
    return None


def _keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = ec.generate_private_key(ec.SECP256R1())
    priv_pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()).decode("ascii")
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    return priv, priv_pem, pub_pem


class _FakeKms:
    """Deterministic stand-in for a KMS client: signs with a local P-256 key and
    records every call, so the KMS path can be compared byte for byte."""

    def __init__(self, priv):
        self._priv = priv
        self.calls = []

    def sign(self, **kw):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        self.calls.append(kw)
        return {"Signature": self._priv.sign(kw["Message"], ec.ECDSA(hashes.SHA256()))}


def _entry():
    return ew.fact_to_evidence(
        {"service": "config", "check": "recorder", "status": "COMPLIANT", "region": "us-east-1",
         "detail": "unit fixture", "collected_at": "2026-10-13T00:00:00+00:00"},
        location_base=_BASE_URI)


def _signer_pin(pub_pem, key_ref):
    return {"public_key": pub_pem, "key_arn": key_ref, "public_key_fingerprint": None, "required": True}


print("MCE-08 / AUD-F74: pluggable signer contract, KMS as one implementation")
priv, priv_pem, pub_pem = _keypair()

# ---- AC1: the KMS path is byte-identical through the contract ---------------
ARN = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
h = _entry()["xEvidenceContentHash"]
kms_a, kms_b = _FakeKms(priv), _FakeKms(priv)
direct = se.sign_hash(kms_a, ARN, h, when=_WHEN)
via = signers.KmsSigner(kms_b, ARN).sign(h, when=_WHEN)
# ECDSA signatures are randomized, so compare everything except the signature
# bytes, and prove both signatures verify over the same message.
check("KmsSigner block equals sign_hash's block in every field but the randomized signature",
      {k: v for k, v in direct.items() if k != "signature"}
      == {k: v for k, v in via.items() if k != "signature"})
check("KmsSigner issued the same KMS call sign_hash issues (KeyId, Message, MessageType, algorithm)",
      kms_a.calls == kms_b.calls and kms_b.calls[0]["KeyId"] == ARN
      and kms_b.calls[0]["Message"] == h.encode("ascii") and kms_b.calls[0]["MessageType"] == "RAW")
check("KmsSigner records the key id, never the ARN (AUD-F60 unchanged)",
      via["keyId"] == "1234abcd-12ab-34cd-56ef-1234567890ab" and "arn:" not in json.dumps(via))
check("KmsSigner.kind is managed-key-service", signers.KmsSigner(kms_b, ARN).kind == "managed-key-service")
check("every signer kind the profile may declare is one the contract names",
      set(signers.SIGNER_KINDS) == {"managed-key-service", "external-command", "software-key"}
      and set(signers.NOT_SEPARATELY_ADMINISTERED) == {"software-key"})
for s in (direct, via):
    check("block shape is the documented five-field shape",
          set(s) == {"algorithm", "keyId", "signedHash", "signature", "signedAt"}
          and s["algorithm"] == "ECDSA_SHA_256" and s["signedHash"] == h and s["signedAt"] == _WHEN)

# ---- AC2: a non-KMS signer verifies through the unchanged gate ---------------
soft = signers.SoftwareKeySigner(priv_pem, "harbor-audit-signer-2026")
check("SoftwareKeySigner exposes its public key for pinning", soft.public_key_pem() == pub_pem)
e = _entry()
blk = signers.sign_entry(e, soft, when=_WHEN)
check("sign_entry attaches the block under xEvidenceSignature", e.get("xEvidenceSignature") is blk)
check("the software signer's block has the same shape as the KMS block", set(blk) == set(via))
outcome, msg = ve.classify_entry(e, ew.evidence_hash, _signer_pin(pub_pem, "harbor-audit-signer-2026"))
check(f"a software-signed entry classifies `verified` under the pinned key ({outcome}: {msg[:60]})",
      outcome == "verified")
outcome, msg = ve.classify_entry(e, ew.evidence_hash, _signer_pin(pub_pem, "some-other-signer"))
check("the same entry under a different pinned key reference is HARD (signer not trusted)",
      outcome == "hard" and "SIGNER NOT TRUSTED" in msg)
_, _, other_pub = _keypair()
outcome, msg = ve.classify_entry(e, ew.evidence_hash, _signer_pin(other_pub, "harbor-audit-signer-2026"))
check("the same entry under a different pinned public key is HARD (signature does not verify)",
      outcome == "hard")
tampered = dict(e)
tampered["evidenceDescription"] = (e.get("evidenceDescription") or "") + " edited"
outcome, _ = ve.classify_entry(tampered, ew.evidence_hash, _signer_pin(pub_pem, "harbor-audit-signer-2026"))
check("editing a bound field after software signing is HARD, exactly as for KMS", outcome == "hard")
with open(ve.__file__, encoding="utf-8") as fh:
    gate_src = fh.read()
check("validate_evidence.py has no signer-specific branch (no reference to the signers module or its kinds)",
      "signers" not in gate_src and "software-key" not in gate_src and "external-command" not in gate_src)

# ---- AC5: the external command receives only the hash -----------------------
with tempfile.TemporaryDirectory() as td:
    key_path = os.path.join(td, "k.pem")
    log_path = os.path.join(td, "received.txt")
    with open(key_path, "w", encoding="ascii") as fh:
        fh.write(priv_pem)
    helper = os.path.join(td, "fake_signing_service.py")
    with open(helper, "w", encoding="utf-8") as fh:
        fh.write(
            "import sys, base64\n"
            "from cryptography.hazmat.primitives import hashes, serialization\n"
            "from cryptography.hazmat.primitives.asymmetric import ec\n"
            "data = sys.stdin.buffer.read()\n"
            "open(sys.argv[2], 'wb').write(data + b'|' + repr(sys.argv[3:]).encode())\n"
            "key = serialization.load_pem_private_key(open(sys.argv[1], 'rb').read(), password=None)\n"
            "sys.stdout.write(base64.b64encode(key.sign(data, ec.ECDSA(hashes.SHA256()))).decode())\n")
    ext = signers.ExternalCommandSigner([sys.executable, helper, key_path, log_path], "harbor-ext-signer")
    e2 = _entry()
    e2["evidenceText"] = "SECRET-LOOKING TEXT that must never reach the signer"
    e2 = ew.fact_to_evidence(
        {"service": "config", "check": "recorder", "status": "COMPLIANT", "region": "us-east-1",
         "detail": "the detail text must stay inside this process", "collected_at": "2026-10-13T00:00:00+00:00"},
        location_base=_BASE_URI)
    blk2 = signers.sign_entry(e2, ext, when=_WHEN)
    with open(log_path, "rb") as fh:
        received = fh.read()
    stdin_part, argv_part = received.split(b"|", 1)
    check("the external signer received exactly the content hash on stdin",
          stdin_part == e2["xEvidenceContentHash"].encode("ascii"))
    check("the external signer received no extra arguments beyond the operator's command",
          argv_part == b"[]")
    check("no evidence text, detail or source fact crossed the process boundary",
          b"detail text" not in received and b"recorder" not in received
          and b"xSourceFact" not in received and b"COMPLIANT" not in received)
    outcome, msg = ve.classify_entry(e2, ew.evidence_hash, _signer_pin(pub_pem, "harbor-ext-signer"))
    check(f"the externally signed entry classifies `verified` through the unchanged gate ({outcome})",
          outcome == "verified")
    # Failure modes fail closed.
    bad = signers.ExternalCommandSigner([sys.executable, "-c", "import sys; sys.exit(3)"], "harbor-ext-signer")
    check("a non-zero exit from the signing command is a SigningError",
          "exited 3" in (_raises(bad.sign, h) or ""))
    junk = signers.ExternalCommandSigner([sys.executable, "-c", "print('not base64!!')"], "harbor-ext-signer")
    check("non-base64 output from the signing command is a SigningError",
          "not base64" in (_raises(junk.sign, h) or ""))
    empty = signers.ExternalCommandSigner([sys.executable, "-c", "pass"], "harbor-ext-signer")
    check("empty output from the signing command is a SigningError",
          (_raises(empty.sign, h) or "") != "")
    check("a non-canonical hash is refused before any process is launched",
          "non-canonical" in (_raises(ext.sign, "sha1:abc") or ""))

# ---- AC3: identifiers are refused in a key reference; the gate backstops ------
for label, ref in (("ARN", ARN),
                   ("12-digit account id", "signer-111122223333"),
                   ("GUID (tenant / subscription / compartment / project shape)",
                    "tenant-72f988bf-86f1-41af-91ab-2d7cd011db47"),
                   ("URL (vault / project address)", "https://vault.example.net/keys/signer"),
                   ("path", "keys/signer/1"),
                   ("upper case or spaces", "Audit Signer"),
                   ("empty", "")):
    why = _raises(signers.check_key_reference, ref)
    check(f"key reference carrying a {label} is refused by the contract ({(why or '')[:50]})", why is not None)
for ok in ("audit-signer-2026", "harbor.prod.signer", "k_1"):
    check(f"label {ok!r} is accepted", signers.check_key_reference(ok) == ok)
check("SoftwareKeySigner refuses a GUID-shaped key reference at construction",
      _raises(signers.SoftwareKeySigner, priv_pem, "72f988bf-86f1-41af-91ab-2d7cd011db47") is not None)
check("ExternalCommandSigner refuses an ARN key reference at construction",
      _raises(signers.ExternalCommandSigner, [sys.executable], ARN) is not None)
# The downstream gate (AUD-F60) still catches what it always caught. Its account
# regex deliberately skips a 12-digit run whose neighbour is a hyphen or hex
# digit (so GUIDs do not false-trip), which is why the contract above refuses
# any 12-digit run regardless of neighbours.
hand_built = {"algorithm": "ECDSA_SHA_256", "keyId": "signer 111122223333", "signedHash": h,
              "signature": base64.b64encode(b"x").decode("ascii"), "signedAt": _WHEN}
blob = json.dumps(hand_built)
check("a hand-built block with a 12-digit account id trips no_sensitive_patterns (AUD-F60 backstop)",
      any(pat.search(blob) for pat, _ in vs.SENSITIVE_PATTERNS))
check("the gate skips a hyphen-adjacent 12-digit run (GUID safety), so the contract refusal is needed",
      not any(pat.search(json.dumps({"keyId": "signer-111122223333"})) for pat, _ in vs.SENSITIVE_PATTERNS)
      and _raises(signers.check_key_reference, "signer-111122223333") is not None)
hand_built["keyId"] = ARN
check("a hand-built block with an ARN trips no_sensitive_patterns (AUD-F60 backstop)",
      any(pat.search(json.dumps(hand_built)) for pat, _ in vs.SENSITIVE_PATTERNS))
hand_built["keyId"] = "tenant-72f988bf-86f1-41af-91ab-2d7cd011db47"
check("a GUID-shaped tenant id is NOT caught downstream (the KMS key id is a GUID), so the contract "
      "refusal above is the load-bearing control",
      not any(pat.search(json.dumps(hand_built)) for pat, _ in vs.SENSITIVE_PATTERNS))

# ---- Software key constraints -----------------------------------------------
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
p384 = ec.generate_private_key(ec.SECP384R1()).private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode("ascii")
check("a non-P-256 software key is refused (the verifier is ECDSA_SHA_256 over P-256)",
      "P-256" in (_raises(signers.SoftwareKeySigner, p384, "audit-signer") or ""))
check("garbage PEM is refused", _raises(signers.SoftwareKeySigner, "not a key", "audit-signer") is not None)
check("sign_entry refuses an entry with no content hash",
      "no xEvidenceContentHash" in (_raises(signers.sign_entry, {"evidenceType": "x"}, soft) or ""))
check("sign_entry refuses an object that is not a Signer",
      _raises(signers.sign_entry, _entry(), object()) is not None)

# ---- AC4: preflight findings on the declared administration boundary --------
F = signers.signer_administration_findings


def _decl(**over):
    d = {"key_arn": "harbor-audit-signer-2026", "public_key_pem": pub_pem}
    d.update(over)
    return d


check("no signer pinned (template TBDs): no finding under either profile",
      F({"public_key_pem": "TBD: fill", "key_arn": "TBD"}) == []
      and F({"public_key_pem": "TBD: fill"}, production=True) == [])
check("a non-dict declaration yields no finding", F(None) == [] and F("x") == [])
w = F(_decl())
check("pinned signer with no signer_kind: one warning asking for the declaration",
      len(w) == 1 and w[0][0] == "warning" and "signer_kind is not declared" in w[0][1])
check("pinned signer with no signer_kind is still only a warning under production-assurance",
      [lvl for lvl, _ in F(_decl(), production=True)] == ["warning"])
bad_kind = F(_decl(signer_kind="hsm"))
check("an unknown signer_kind is hard under development (no silent default)",
      len(bad_kind) == 1 and bad_kind[0][0] == "hard" and "'hsm'" in bad_kind[0][1])
check("an unknown signer_kind is hard under production-assurance",
      [lvl for lvl, _ in F(_decl(signer_kind="hsm"), production=True)] == ["hard"])
for kind in ("managed-key-service", "external-command"):
    check(f"{kind} yields no finding under either profile",
          F(_decl(signer_kind=kind)) == [] and F(_decl(signer_kind=kind), production=True) == [])
check("signer_kind is case- and space-insensitive", F(_decl(signer_kind=" Managed-Key-Service ")) == [])
sk_dev = F(_decl(signer_kind="software-key"))
check("software-key under development: a warning naming it not separately administered",
      len(sk_dev) == 1 and sk_dev[0][0] == "warning" and "not separately administered" in sk_dev[0][1])
sk_prod = F(_decl(signer_kind="software-key"), production=True)
check("software-key under production-assurance: HARD, naming the signer as not separately administered",
      len(sk_prod) == 1 and sk_prod[0][0] == "hard" and "not separately administered" in sk_prod[0][1]
      and "production-assurance" in sk_prod[0][1])
import re  # noqa: E402
_DETERMINATION = re.compile(r"\b(compliant|non-?compliant|satisfies|meets|violat\w*)\b", re.I)
check("no finding is worded as a compliance determination",
      all(not _DETERMINATION.search(m) for lst in (w, bad_kind, sk_dev, sk_prod) for _, m in lst))

# Preflight wiring reads the live flag and routes hard to blockers.
with open(os.path.join(BASE, "sdr.py"), encoding="utf-8") as fh:
    sdr_src = fh.read()
_i = sdr_src.find("_signers.signer_administration_findings(")
check("preflight calls signer_administration_findings with the live production flag",
      _i > 0 and "production=_production" in sdr_src[_i:_i + 200])
check("preflight routes 'hard' to blockers and the rest to warnings, tagged AUD-F74",
      'blockers if _level == "hard" else warnings' in sdr_src[_i:_i + 400] and "AUD-F74" in sdr_src[_i:_i + 400])

# Template and sample.
with open(os.path.join(BASE, "profiles", "common", "offering-profile.json"), encoding="utf-8") as fh:
    tmpl = json.load(fh)
check("the template profile declares signer_kind (TBD) beside the pinned verifier key",
      str(tmpl["expected_evidence_signer"].get("signer_kind", "")).startswith("TBD")
      and all(k in tmpl["expected_evidence_signer"]["signer_kind"] for k in signers.SIGNER_KINDS))
with open(os.path.join(BASE, "examples", "sample-offering-class-c", "build_class_c_sample.py"),
          encoding="utf-8") as fh:
    sample_src = fh.read()
check("the Class C sample declares its fictional signer kind and carries the software-key probe",
      '"signer_kind": "managed-key-service"' in sample_src and "_production_software_key_signer" in sample_src)

print(f"\n{'FAIL' if _fail else 'PASS'}: {_fail} failing check(s)")
sys.exit(1 if _fail else 0)
