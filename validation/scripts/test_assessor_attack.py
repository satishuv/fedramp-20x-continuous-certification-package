#!/usr/bin/env python3
"""Assessor self-attack harness.

A 20x assessor does not memorize findings; they carry a few probes and apply
them everywhere. Every false-ready defect this framework has closed reduces to
one of three archetypes. This harness takes a fully-filled, Submission-ready
Class C package and mechanically runs one attack per archetype, asserting each
is caught. It is a STANDING regression gate that thinks like the assessor on
every build, so the whole CLASS of defect stays closed - not just the specific
findings already fixed.

The three archetypes:

  A. GATE != DELIVERABLE. Something the readiness gate relied on does not
     actually appear in the submitted package. Attack: strip a canonical
     required artifact from a rule that passed on its narrative fields, and a
     required reason field, then confirm the package no longer reaches READY.

  B. NARRATION != ENFORCEMENT. A property claimed in docs/comments is not
     enforced in code. Attack: present a signed-evidence deployment and DELETE
     the signature (the downgrade), then confirm signing-required mode blocks
     it rather than falling back to hash-only.

  C. OPTIONAL != ABSENT. A property can be silently downgraded, or a capability
     claimed without owing its proof. Attack: SELECT a Class A optional rule
     for credit while omitting its required artifact / CPO summary, and confirm
     the selected rule is fully reviewed (blocks).

Reuses the readiness harness helpers (temp-copy build + preflight) so it never
touches the real tree and never duplicates the build scaffolding.

    python validation/scripts/test_assessor_attack.py
"""

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))

# The readiness module owns the temp-copy build/preflight helpers and the
# offering-fill logic; import and reuse them rather than re-implement.
import test_submission_readiness as rt  # noqa: E402
import validate_evidence as ve  # noqa: E402
from evidence_wiring import evidence_hash, fact_to_evidence  # noqa: E402

PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}")
    return bool(cond)


# ---------------------------------------------------------------------------
# Archetype B is pure and needs no package build: it is a property of the
# evidence-integrity classifier. Run it directly.
# ---------------------------------------------------------------------------
def attack_b_signature_downgrade():
    """NARRATION != ENFORCEMENT: a signed-evidence deployment must not be
    silently downgradeable to hash-only by deleting the signature."""
    # The PRODUCTION entry shape (AUD-F26: digest over the bound payload). The
    # legacy hand-built `source_fact` shape can no longer reach `verified`.
    fact = {"service": "iam", "check": "mfa", "status": "pass", "region": "us-east-1",
            "detail": "root MFA enabled", "collected_at": "2026-09-26T00:00:00+00:00"}
    entry = fact_to_evidence(fact, "s3://bucket")
    # A deployment that pins a trusted signer in required mode.
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    required_signer = {"public_key": pem, "key_arn": "TEST-ARN",
                       "public_key_fingerprint": None, "required": True}
    # The attack: the signature was removed. Under signing-required, this is a
    # downgrade and must be HARD, not verified-by-hash.
    outcome, _ = ve.classify_entry(entry, hash_fn=evidence_hash,
                                   trusted_signer=required_signer)
    check("Archetype B (narration != enforcement): stripping a signature under "
          "signing-required mode is blocked, not downgraded to hash-only",
          outcome == "hard")
    # Control: with no signer pinned, hash-only is a legitimate posture.
    outcome_ctrl, _ = ve.classify_entry(entry, hash_fn=evidence_hash,
                                        trusted_signer=None)
    check("Archetype B control: hash-only stays verified when no signer is pinned",
          outcome_ctrl == "verified")


# ---------------------------------------------------------------------------
# Archetypes A and C operate on a built package. Build one filled Class C tree
# and one filled Class A tree, then attack each.
# ---------------------------------------------------------------------------
def attack_a_gate_not_deliverable(tmp):
    """GATE != DELIVERABLE: a rule that passed the gate on narrative fields must
    not reach READY if a canonical required artifact is missing from the
    package."""
    import shutil
    root = os.path.join(tmp, "repo-attack-a")
    shutil.copytree(BASE, root, ignore=shutil.ignore_patterns(
        ".git", "__pycache__", "*.log", ".tmp"))
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    profile = os.path.join(root, "profiles", "common", "offering-profile.json")
    rt._fill(profile, now, cls="C")
    rt._fill_records(root)
    rt._build(root)
    # Sign off the built package so it is genuinely READY before the attack.
    manifest = os.path.join(root, "artifacts", "release-manifest.json")
    register = os.path.join(root, "sdr", "reviews", "review-register.json")
    rt._sign_package(root, now) if hasattr(rt, "_sign_package") else _sign(root, manifest, register, now)
    baseline = rt._preflight(root)
    if not check("Archetype A precondition: the filled Class C package is READY",
                 baseline.returncode == 0):
        return
    # Attack: strip the canonical artifact from an unconditional-MUST-artifact
    # rule that otherwise passes on its narrative fields.
    rp = os.path.join(root, "sdr", "records", "records-store.json")
    recs = json.load(open(rp, encoding="utf-8"))
    art_rid = "AFC-CSO-INB"
    if art_rid in recs.get("frr", {}):
        recs["frr"][art_rid].setdefault("extension", {})["rule_artifacts"] = []
        json.dump(recs, open(rp, "w", encoding="utf-8", newline="\n"), indent=1)
        rt._build(root)
        r = rt._preflight(root)
        check("Archetype A (gate != deliverable): a rule missing its canonical "
              "artifact no longer reaches READY",
              r.returncode == 1 and "rule-artifact" in r.stdout)


def attack_c_optional_not_absent(tmp):
    """OPTIONAL != ABSENT: selecting a Class A optional rule for credit while
    omitting its required artifact must block (the selected rule is fully
    reviewed)."""
    import shutil
    root = os.path.join(tmp, "repo-attack-c")
    shutil.copytree(BASE, root, ignore=shutil.ignore_patterns(
        ".git", "__pycache__", "*.log", ".tmp"))
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    profile = os.path.join(root, "profiles", "common", "offering-profile.json")
    rt._fill(profile, now, cls="A")
    rt._fill_records(root)
    # Attack: select the optional cryptographic-module rule for credit, then
    # strip its artifact. A selected MAY rule is fully reviewed, so this blocks.
    rp = os.path.join(root, "sdr", "records", "records-store.json")
    recs = json.load(open(rp, encoding="utf-8"))
    cmu = "CMU-CSO-UVM"
    pa = json.load(open(profile, encoding="utf-8"))
    pa["selected_optional_rules"] = ["CMU-CSO-UVM"]
    json.dump(pa, open(profile, "w", encoding="utf-8", newline="\n"), indent=1)
    if cmu in recs.get("frr", {}):
        recs["frr"][cmu].setdefault("extension", {})["rule_artifacts"] = []
        json.dump(recs, open(rp, "w", encoding="utf-8", newline="\n"), indent=1)
    rt._build(root)
    r = rt._preflight(root)
    check("Archetype C (optional != absent): selecting an optional rule for "
          "credit while omitting its artifact is fully reviewed (blocks)",
          r.returncode == 1 and ("rule-artifact" in r.stdout and cmu in r.stdout))


def _sign(root, manifest, register, now):
    """Minimal package signoff bound to the current manifest hash (mirrors the
    readiness test's inline signoff for trees where rt has no _sign_package)."""
    import hashlib
    mh = "sha256:" + hashlib.sha256(open(manifest, "rb").read()).hexdigest()
    tag = json.load(open(manifest, encoding="utf-8")).get("release_tag")
    reg = json.load(open(register, encoding="utf-8"))
    reg["package_signoff"] = {
        "decision": "approved", "reviewer": "Jane Provider, VP Security",
        "timestamp": now.isoformat(), "release_tag": tag,
        "package_manifest_sha256": mh, "notes": "Reviewed for the attack harness."}
    json.dump(reg, open(register, "w", encoding="utf-8", newline="\n"), indent=1)


def main():
    import tempfile
    attack_b_signature_downgrade()  # no build needed
    with tempfile.TemporaryDirectory() as tmp:
        attack_a_gate_not_deliverable(tmp)
        attack_c_optional_not_absent(tmp)
    print(f"\n{PASS}/{PASS + FAIL} assessor-attack probes passed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
