# Adversarial tests for the production-assurance evidence linkage gate
# (sdr.unverified_evidence_under_production, AUD-F59).
#
# Finding closed here: the SDR linkage gate (validate_sdr check 9) asked only
# whether a populated KSI had a NON-EMPTY evidence array, and the evidence
# integrity gate exits 0 on findings, so a hashless or unresolvable entry
# satisfied linkage while the gate could verify nothing about it. Under
# evidence_store_profile production-assurance (the provider's declaration that
# the evidence store is tamper-evident) preflight now blocks on any evidence
# entry behind a populated applicable record whose integrity outcome is not
# `verified`. The development profile is untouched.
#
# Every case runs the REAL classifier (validate_evidence.classify_entry with
# the real canonical hash), never a stub, so the gate and this test cannot
# agree by construction.
#
# Run: python validation/scripts/test_production_evidence_linkage.py

import base64
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))
import sdr  # noqa: E402
import validate_evidence as ve  # noqa: E402
import evidence_wiring as ew  # noqa: E402

_fail = 0
_TEST_ARN = "TEST-KMS-KEY-f59-signer-not-an-arn"
_BASE_URI = "https://evidence.example.gov/store"


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def _keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = ec.generate_private_key(ec.SECP256R1())
    pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    return priv, pem


def _signer(pem, required=True):
    return {"public_key": pem, "key_arn": _TEST_ARN, "public_key_fingerprint": None,
            "required": required}


def _bound(check_name="recorder", sign_with=None):
    ev = ew.fact_to_evidence(
        {"service": "config", "check": check_name, "status": "COMPLIANT", "region": "us-east-1",
         "detail": "unit fixture", "collected_at": "2026-10-13T00:00:00+00:00"},
        location_base=_BASE_URI)
    if sign_with is not None:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        h = ev["xEvidenceContentHash"]
        sig = sign_with.sign(h.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        ev["xEvidenceSignature"] = {"algorithm": "ECDSA_SHA_256", "keyId": _TEST_ARN,
                                    "signedHash": h, "signature": base64.b64encode(sig).decode("ascii")}
    return ev


def _hashless():
    return {"evidenceType": "Configuration", "evidenceDescription": "hand-written",
            "evidenceText": "assertion", "lastUpdated": "2026-10-13"}


def _populated(evidence=None, rule_artifacts=None):
    rec = {"implementation": ["The provider does X in way Y (populated narrative)."],
           "evidence": list(evidence or []), "extension": {}}
    if rule_artifacts is not None:
        rec["extension"]["rule_artifacts"] = list(rule_artifacts)
    return rec


def _template(evidence=None):
    return {"implementation": ["TBD: Information has not been provided."],
            "evidence": list(evidence or []), "extension": {}}


def _run(records, signer=None):
    return sdr.unverified_evidence_under_production(records, signer, ve.classify_entry,
                                                    ve._evidence_hash)


def test_record_is_populated_predicate():
    check("TBD narrative is not populated", not sdr._record_is_populated(_template()))
    check("empty narrative is not populated", not sdr._record_is_populated({"implementation": []}))
    check("mixed real + TBD line is not populated",
          not sdr._record_is_populated({"implementation": ["real", "TBD: more"]}))
    check("real narrative is populated", sdr._record_is_populated(_populated()))
    check("string narrative is populated", sdr._record_is_populated({"implementation": "real text"}))


def test_bound_verified_evidence_is_not_listed():
    out = _run([("KSI-X", _populated([_bound()]))])
    check("bound+hashed entry with no signer -> verified, not listed", out == [])


def test_hashless_evidence_behind_a_populated_record_is_listed():
    out = _run([("KSI-X", _populated([_hashless()]))])
    check("hashless entry -> listed as a finding", len(out) == 1 and out[0][:3] == ("KSI-X", 0, "finding"))


def test_unresolvable_evidence_is_listed():
    e = {"xEvidenceContentHash": "sha256:" + "a" * 64, "evidenceLocation": "s3://bucket/key",
         "evidenceType": "Configuration", "evidenceDescription": "d", "lastUpdated": "2026-10-13"}
    out = _run([("KSI-X", _populated([e]))])
    check("well-formed hash with no resolvable source -> listed (not verified)",
          len(out) == 1 and out[0][2] == "finding")


def test_template_records_never_count():
    # The shipped all-TBD template must not block a development-to-production
    # switch on records the provider has not authored yet.
    out = _run([("KSI-X", _template([_hashless()])), ("FRR-Y", _template())])
    check("hashless evidence behind a TBD record is not listed", out == [])


def test_frr_rule_artifacts_are_scanned_too():
    out = _run([("FRC-X", _populated(rule_artifacts=[_bound("frr-x"), _hashless()]))])
    check("FRR rule_artifacts scanned; only the hashless one listed",
          [(o[0], o[1], o[2]) for o in out] == [("FRC-X", 1, "finding")])


def test_non_object_entry_is_listed_hard():
    out = _run([("KSI-X", _populated(["a bare string"]))])
    check("non-object evidence entry -> listed hard", len(out) == 1 and out[0][2] == "hard")


def test_required_signer_signed_entry_passes_and_each_downgrade_is_listed_hard():
    priv, pem = _keypair()
    signer = _signer(pem)
    good = _bound(sign_with=priv)
    check("bound+signed entry under required signer -> verified, not listed",
          _run([("KSI-X", _populated([good]))], signer) == [])
    no_sig = dict(good)
    no_sig.pop("xEvidenceSignature")
    out = _run([("KSI-X", _populated([no_sig]))], signer)
    check("signature deleted under required signer -> listed hard",
          len(out) == 1 and out[0][2] == "hard")
    no_hash = dict(good)
    no_hash.pop("xEvidenceSignature")
    no_hash.pop("xEvidenceContentHash")
    out = _run([("KSI-X", _populated([no_hash]))], signer)
    check("digest + signature deleted under required signer -> listed hard (AUD-F57 via F59)",
          len(out) == 1 and out[0][2] == "hard" and "NO CONTENT HASH" in out[0][3])


def test_mixed_record_lists_only_the_unverifiable_entries():
    priv, pem = _keypair()
    out = _run([("KSI-X", _populated([_bound("a", sign_with=priv), _hashless(), _bound("b", sign_with=priv)]))],
               _signer(pem))
    check("one unverifiable entry among verified ones is listed by index",
          [(o[0], o[1]) for o in out] == [("KSI-X", 1)])


def test_optional_signer_does_not_turn_findings_into_hard_but_still_lists_them():
    # signing_required=false: a hashless entry stays a finding, and under
    # production-assurance a finding is still NOT verified, so it is listed.
    _, pem = _keypair()
    out = _run([("KSI-X", _populated([_hashless()]))], _signer(pem, required=False))
    check("optional signer: hashless -> finding, still listed as unverified",
          len(out) == 1 and out[0][2] == "finding")


def main():
    for t in (test_record_is_populated_predicate,
              test_bound_verified_evidence_is_not_listed,
              test_hashless_evidence_behind_a_populated_record_is_listed,
              test_unresolvable_evidence_is_listed,
              test_template_records_never_count,
              test_frr_rule_artifacts_are_scanned_too,
              test_non_object_entry_is_listed_hard,
              test_required_signer_signed_entry_passes_and_each_downgrade_is_listed_hard,
              test_mixed_record_lists_only_the_unverifiable_entries,
              test_optional_signer_does_not_turn_findings_into_hard_but_still_lists_them):
        print(t.__name__)
        t()
    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: production evidence linkage ({_fail} failures)")
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
