"""AUD-F37: the metric history cannot be filled in after the fact unnoticed.

Offline. Builds histories through the real appender (append_run) so the chain
is exactly what production writes, then attacks the JSON the way a tamperer
would and asserts verify_history names the break.

Run: python automation/metrics/test_history_integrity.py
"""
import copy
import os
import sys
from datetime import date, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(HERE)), "automation", "collectors"))

import append_metrics as am  # noqa: E402
import history_integrity as hi  # noqa: E402

PROV = {"run_id": "run-0123456789abcdef", "facts_sha256": "sha256:" + "ab" * 32}


def _reg():
    return {"ksis": {"KSI-X": {"metric_service_keys": ["kms:key_rotation"], "checks": []}},
            "meta": {"dataset_version": "t"}}


def _kms(measured, total, at):
    return {"kms": [{"service": "kms", "check": "key_rotation", "status": "OBSERVED",
                     "measured": measured, "total": total, "collected_at": at}]}


def _grow(days, start=date(2026, 1, 1), prov=PROV, measured=3, total=3):
    """A history grown day by day through the real appender."""
    h = {}
    for i in range(days):
        d = start + timedelta(days=i)
        at = f"{d.isoformat()}T06:00:00+00:00"
        am.append_run(h, _reg(), {}, _kms(measured, total, at), d, observed_at=at, provenance=prov)
    return h


def test_honest_growth_verifies_clean_and_is_attested():
    h = _grow(10)
    assert hi.verify_history(h) == [], hi.verify_history(h)
    obs = h["ksis"]["KSI-X"]["observations"]
    assert len(obs) == 10
    assert obs[0]["prev_hash"] is None
    for a, b in zip(obs, obs[1:]):
        assert b["prev_hash"] == a["hash"]
    assert all(hi.is_attested(o) for o in obs)
    assert h["meta"]["chain_heads"]["KSI-X"] == obs[-1]["hash"]
    assert h["meta"]["history_digest"] == hi.history_digest(h)


def test_editing_a_past_observation_is_detected():
    h = _grow(10)
    h["ksis"]["KSI-X"]["observations"][3]["passing"] = 3  # was honest 3/3 anyway; flip total instead
    h["ksis"]["KSI-X"]["observations"][3]["total"] = 1   # make day 4 look like 3 of 1 -> edited
    codes = [c for c, _k, _d in hi.verify_history(h)]
    assert "bad-hash" in codes, codes


def test_backfilling_an_observation_is_detected():
    """The attack from the review: insert a dated observation for a day that
    was never collected, hashed to look consistent on its own."""
    h = _grow(10)
    obs = h["ksis"]["KSI-X"]["observations"]
    fake = hi.chain_observation({"observed_at": "2025-12-25T06:00:00+00:00", "date": "2025-12-25",
                                 "passing": 3, "total": 3}, None, PROV)
    obs.insert(0, fake)  # backfilled before the real start
    problems = hi.verify_history(h)
    codes = [c for c, _k, _d in problems]
    assert "chain-break" in codes, problems
    # Also try inserting in the middle with a correct-looking prev_hash: the
    # NEXT observation then no longer links.
    h2 = _grow(10)
    obs2 = h2["ksis"]["KSI-X"]["observations"]
    mid = hi.chain_observation({"observed_at": "2026-01-05T12:00:00+00:00", "date": "2026-01-05",
                                "passing": 3, "total": 3}, obs2[4]["hash"], PROV)
    obs2.insert(5, mid)
    assert any(c == "chain-break" for c, _k, _d in hi.verify_history(h2))


def test_deleting_a_bad_day_is_detected():
    h = _grow(10, measured=0, total=3)   # a run of failing days
    del h["ksis"]["KSI-X"]["observations"][6]
    problems = hi.verify_history(h)
    assert any(c == "chain-break" for c, _k, _d in problems), problems
    # The orphaned series point (date with no observation) is also named.
    assert any(c == "unbacked-point" for c, _k, _d in problems), problems


def test_rechaining_hides_the_edit_but_moves_the_digest():
    """Anyone can rechain a tampered log; that is why production assurance
    requires the digest to be SIGNED by the separate signer."""
    h = _grow(10)
    before = hi.history_digest(h)
    h["ksis"]["KSI-X"]["observations"][3]["total"] = 1
    hi.rechain(h, PROV)
    assert hi.verify_history(h) == []          # chain looks intact again
    assert hi.history_digest(h) != before      # but the signed digest no longer matches


def test_unattested_observations_are_reported():
    h = _grow(3, prov=None)
    codes = {c for c, _k, _d in hi.verify_history(h)}
    assert codes == {"unattested"}, codes


def test_pre_f37_history_without_chain_fields_is_reported_not_crashed():
    h = {"ksis": {"KSI-X": {"series": [{"date": "2026-01-01", "passing": 1, "total": 1}],
                            "observations": [{"observed_at": "2026-01-01T06:00:00+00:00",
                                              "date": "2026-01-01", "passing": 1, "total": 1}]}}}
    codes = {c for c, _k, _d in hi.verify_history(h)}
    assert codes == {"missing-chain"}, codes


def test_pruning_keeps_the_chain_verifiable_via_the_anchor():
    start = date(2025, 1, 1)
    h = _grow(5, start=start)
    # Jump far enough ahead that the first five fall out of the 400-day window.
    later = date(2026, 6, 1)
    at = f"{later.isoformat()}T06:00:00+00:00"
    am.append_run(h, _reg(), {}, _kms(3, 3, at), later, observed_at=at, provenance=PROV)
    obs = h["ksis"]["KSI-X"]["observations"]
    assert len(obs) == 1 and obs[0]["date"] == "2026-06-01"
    anchor = h["meta"]["chain_anchor"]["KSI-X"]
    assert anchor and obs[0]["prev_hash"] == anchor
    assert hi.verify_history(h) == [], hi.verify_history(h)
    # Tampering the anchor (to graft a different past) is detected.
    h["meta"]["chain_anchor"]["KSI-X"] = "sha256:" + "00" * 32
    assert any(c == "bad-anchor" for c, _k, _d in hi.verify_history(h))


def test_digest_changes_on_any_observation_and_signature_fails_after_tamper():
    """Offline ECDSA over the history digest, verified against a pinned public
    key (the same primitive validate_evidence uses for evidence signatures)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    import base64
    import sign_evidence as se

    h = _grow(10)
    digest = hi.history_digest(h)
    key = ec.generate_private_key(ec.SECP256R1())
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    sig = key.sign(digest.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    block = {"algorithm": "ECDSA_SHA_256", "keyId": "arn:aws:kms:us-east-1:000000000000:key/test",
             "signedHash": digest, "signature": base64.b64encode(sig).decode("ascii")}
    assert se.verify_signature_offline(block, pub_pem, recomputed_hash=hi.history_digest(h)) is True
    # Tamper + rechain: chain verifies, digest moves, signature no longer covers it.
    h["ksis"]["KSI-X"]["observations"][2]["total"] = 1
    hi.rechain(h, PROV)
    assert se.verify_signature_offline(block, pub_pem, recomputed_hash=hi.history_digest(h)) is False


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
