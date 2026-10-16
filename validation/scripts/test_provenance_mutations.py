# Orthogonal evidence-provenance mutations (AUD-F62, AUD-F63, AUD-F64; the
# HASH family is the existing AUD-F57/F01/finding-8 tripwire).
#
# A weak suite would tamper an entry's check, source or date and leave the
# digest in place: every such tamper dies at the same hash-mismatch line and
# proves only that the digest covers the object. These tests prove something
# stronger. Each SEMANTIC tamper RECOMPUTES the digest over the tampered bound
# payload and RE-SIGNS it with the pinned test key, so the cryptographic gate
# reports `verified` for the tampered entry (asserted explicitly: the tripwire
# is silent), and the one gate that must catch it is the semantic one:
#
#   family      tamper (then recompute + re-sign)        must be killed by
#   HASH        delete / corrupt / stale-bind the digest  integrity + signing
#   QUERY       valid source, WRONG KSI                   source binding (F62)
#   SOURCE      pointer re-targeted to another observation pointer binding (F63)
#   FRESHNESS   stale observation, digest/signature valid freshness policy (F64)
#
# Every case runs the REAL factory (evidence_wiring.fact_to_evidence), the REAL
# classifier (validate_evidence.classify_entry) and the REAL canonical hash;
# nothing is stubbed, so the gate and this test cannot agree by construction.
# The repository bindings are also exercised: all 46 KSIs must have at least one
# registered source (otherwise the production gate would be unsatisfiable).
#
# Run: python validation/scripts/test_provenance_mutations.py

import base64
import copy
import datetime as dt
import json
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
_TEST_ARN = "TEST-KMS-KEY-provenance-signer-not-an-arn"
_BASE_URI = "https://evidence.example.gov/store"
_NOW = dt.datetime(2026, 10, 14, tzinfo=dt.timezone.utc)


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


KEY, PEM = _keypair()
SIGNER = {"public_key": PEM, "key_arn": _TEST_ARN, "public_key_fingerprint": None, "required": True}


def _sign(ev, key=KEY):
    """Sign the entry's CURRENT digest the way sign_evidence.sign_hash records it."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    h = ev["xEvidenceContentHash"]
    sig = key.sign(h.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    ev["xEvidenceSignature"] = {"algorithm": "ECDSA_SHA_256", "keyId": _TEST_ARN,
                                "signedHash": h, "signature": base64.b64encode(sig).decode("ascii")}
    return ev


def _recompute_and_resign(ev, key=KEY):
    """What a capable insider does after a semantic tamper: recompute the digest
    over the tampered bound payload and re-sign it with the legitimate key."""
    ev["xEvidenceContentHash"] = ew.evidence_hash(ew.canonical_payload(ev))
    return _sign(ev, key)


def _entry(service="config", check="rule-a", region="us-east-1", observed="2026-10-10T00:00:00+00:00",
           account=None, scope_key=None, run_id=None, signed=True):
    fact = {"service": service, "check": check, "status": "COMPLIANT", "region": region,
            "detail": "unit fixture", "collected_at": observed}
    if account:
        fact["account"] = account
    if run_id:
        fact["run_id"] = run_id
    ev = ew.fact_to_evidence(fact, location_base=_BASE_URI, scope_key=scope_key)
    return _sign(ev) if signed else ev


def _verified(ev):
    outcome, _msg = ve.classify_entry(ev, ve._evidence_hash, SIGNER)
    return outcome == "verified"


def _outcome(ev):
    return ve.classify_entry(ev, ve._evidence_hash, SIGNER)


def _populated(evidence):
    return {"implementation": ["The provider does X in way Y (populated narrative)."],
            "evidence": list(evidence), "extension": {}}


def _template(evidence):
    return {"implementation": ["TBD: Information has not been provided."],
            "evidence": list(evidence), "extension": {}}


class _FakeAdapter:
    service = "wiz"
    checks = ("vulnerabilities",)

    def ksi_targets(self):
        return ["KSI-A"]

    def source_bindings(self):
        # MCE-03: adapters bind the (service, check) pairs they declare.
        return {f"{self.service}:{c}": set(self.ksi_targets()) for c in self.checks}


SYNTH_REGISTRY = {
    "KSI-A": {"metric_service_keys": ["guardduty:detector"],
              "checks": [{"type": "config_managed_rule", "target": "rule-a"},
                         {"type": "described_method", "target": None}]},
    "KSI-B": {"metric_service_keys": [],
              "checks": [{"type": "config_managed_rule", "target": "rule-b"}]},
    "KSI-C": {"metric_service_keys": [], "checks": [{"type": "described_method"}]},
}
SYNTH_MANIFEST = {"rules": [{"ksi_id": "KSI-C", "rule_name": "sdr-c-artifact-rule"}]}
BINDINGS = ve.load_source_bindings(SYNTH_REGISTRY, SYNTH_MANIFEST, [_FakeAdapter()])


# ---------------------------------------------------------------------------
# HASH family: the cryptographic tripwire, every shape.
def test_hash_family_tripwire():
    base = _entry()
    check("control: untampered signed entry is verified", _verified(base))

    e = copy.deepcopy(base); e.pop("xEvidenceContentHash"); e.pop("xEvidenceSignature")
    o, m = _outcome(e)
    check("HASH: digest + signature deleted under required signer -> hard (AUD-F57)",
          o == "hard" and "NO CONTENT HASH" in m)

    e = copy.deepcopy(base); e["xEvidenceContentHash"] = "sha256:" + "0" * 64
    o, m = _outcome(e)
    check("HASH: corrupted digest -> hard (binding stale or integrity failed)",
          o == "hard" and ("STALE" in m or "INTEGRITY FAILED" in m))

    e = copy.deepcopy(base); e["evidenceText"] = "tampered assertion"
    o, m = _outcome(e)
    check("HASH: bound field edited, digest kept -> hard INTEGRITY FAILED",
          o == "hard" and "INTEGRITY FAILED" in m)

    e = copy.deepcopy(base); e["evidenceText"] = "tampered assertion"
    e["xEvidenceContentHash"] = ew.evidence_hash(ew.canonical_payload(e))  # recomputed, NOT re-signed
    o, m = _outcome(e)
    check("HASH: edited + recomputed digest with the OLD signature -> hard BINDING STALE",
          o == "hard" and "SIGNATURE BINDING STALE" in m)

    other_key, _ = _keypair()
    e = copy.deepcopy(base); e["evidenceText"] = "tampered assertion"
    _recompute_and_resign(e, other_key)
    o, m = _outcome(e)
    check("HASH: edited + recomputed + re-signed by an UNPINNED key -> hard SIGNATURE INVALID",
          o == "hard" and "SIGNATURE INVALID" in m)

    e = copy.deepcopy(base); e["evidenceText"] = "tampered assertion"
    _recompute_and_resign(e)
    check("HASH family boundary: edited + recomputed + re-signed by the PINNED key is "
          "cryptographically VERIFIED (the tripwire cannot see semantics; the families "
          "below must)", _verified(e))


# ---------------------------------------------------------------------------
# QUERY family: a valid source attached to the wrong KSI (AUD-F62).
def test_query_family_bindings_from_the_repository():
    bindings = ve.load_source_bindings()
    reg = json.load(open(ve.REGISTRY, encoding="utf-8"))["ksis"]
    check("repository bindings cover every registry KSI", set(reg) <= set(bindings))
    unsatisfiable = [k for k in sorted(reg) if ve.first_bound_source(k, bindings) is None]
    check(f"every one of the {len(reg)} KSIs has at least one registered source "
          f"(the production gate is satisfiable); none missing: {unsatisfiable}",
          len(reg) == 46 and not unsatisfiable)
    manifest = json.load(open(ve.RULES_MANIFEST, encoding="utf-8"))
    rules = manifest.get("rules") if isinstance(manifest, dict) else manifest
    check("config-rules manifest has the 11 provider-deployed rules",
          isinstance(rules, list) and len(rules) == 11)
    all_bound = all(r["rule_name"] in bindings.get(r["ksi_id"], {}).get("config", set())
                    for r in rules)
    check("each manifest rule is bound to its own KSI as service config", all_bound)
    cross = ve.classify_source_binding(rules[0]["ksi_id"],
                                       _entry("config", rules[1]["rule_name"], signed=False), bindings)
    check("a manifest rule attached to a DIFFERENT manifest KSI is unbound", cross[0] == "unbound")
    # Third-party adapters register exactly their declared (service, check)
    # pairs against their targets (MCE-03); nothing is bound service-wide, and
    # the pairs bind only for an offering that ENABLES the source (AUD-F79).
    import thirdparty_adapters as tpa  # noqa: F401
    bindings = ve.load_source_bindings(
        profile={"aws_partition": "aws", "evidence_sources": {"crowdstrike-falcon": {"enabled": True}}})
    falcon_pairs = {f"crowdstrike:{c}" for c in ("sensor_coverage", "open_detections", "prevention_policy")}
    check("Falcon adapter binds each declared check to each of its KSI targets",
          all(falcon_pairs <= bindings.get(k, {}).get("keys", set())
              for k in ("KSI-MLA-OSM", "KSI-MLA-RVL", "KSI-MLA-LET", "KSI-INR-RIR")))
    check("Falcon's checks are NOT bound to a KSI it does not target",
          not (falcon_pairs & bindings.get("KSI-CNA-NET", {}).get("keys", set())))
    check("an UNDECLARED check under Falcon's service is unbound even on a target KSI",
          ve.classify_source_binding("KSI-MLA-OSM", _entry("crowdstrike", "made_up_check", region="global"),
                                     bindings)[0] == "unbound")


def test_query_family_wrong_ksi_is_unbound_while_cryptographically_verified():
    wrong = _entry("config", "rule-b")          # rule-b is KSI-B's source
    check("QUERY: the entry is cryptographically VERIFIED (tripwire silent)", _verified(wrong))
    o, m = ve.classify_source_binding("KSI-A", wrong, BINDINGS)
    check("QUERY: rule-b attached to KSI-A -> unbound (AUD-F62)", o == "unbound" and "AUD-F62" in m)
    check("QUERY: the same entry on KSI-B -> bound",
          ve.classify_source_binding("KSI-B", wrong, BINDINGS)[0] == "bound")
    posture = _entry("guardduty", "detector")
    check("QUERY: metric allowlist source bound on its KSI",
          ve.classify_source_binding("KSI-A", posture, BINDINGS)[0] == "bound")
    check("QUERY: metric allowlist source unbound on another KSI",
          ve.classify_source_binding("KSI-B", posture, BINDINGS)[0] == "unbound")
    check("QUERY: a described_method check with no target binds nothing (rule-less)",
          ve.classify_source_binding("KSI-C", _entry("config", "rule-a"), BINDINGS)[0] == "unbound")
    check("QUERY: the manifest's deployed rule binds the artifact-rule KSI",
          ve.classify_source_binding("KSI-C", _entry("config", "sdr-c-artifact-rule"), BINDINGS)[0] == "bound")
    adapter_ev = _entry("wiz", "vulnerabilities", region="global")
    check("QUERY: adapter source bound on its target KSI",
          ve.classify_source_binding("KSI-A", adapter_ev, BINDINGS)[0] == "bound")
    check("QUERY: adapter source unbound on a non-target KSI",
          ve.classify_source_binding("KSI-B", adapter_ev, BINDINGS)[0] == "unbound")
    check("QUERY: unknown KSI -> unbound (nothing registers a source for it)",
          ve.classify_source_binding("KSI-ZZZ", posture, BINDINGS)[0] == "unbound")
    human = {"evidenceType": "Document", "evidenceDescription": "policy", "evidenceLocation": "https://x/y.pdf",
             "lastUpdated": "2026-10-10"}
    check("QUERY: an entry without a source fact makes no claim (human review, not this gate)",
          ve.classify_source_binding("KSI-A", human, BINDINGS)[0] == "no-claim")
    # Preflight helper: lists the wrong-KSI entry for a populated record only.
    out = sdr.unbound_evidence_under_production([("KSI-A", _populated([wrong]))], [], BINDINGS,
                                                ve.classify_source_binding, ve.classify_pointer_binding)
    check("QUERY: preflight helper lists (KSI-A, 0, source)",
          [(r, i, k) for r, i, k, _ in out] == [("KSI-A", 0, "source")])
    out = sdr.unbound_evidence_under_production([("KSI-B", _populated([wrong]))], [], BINDINGS,
                                                ve.classify_source_binding, ve.classify_pointer_binding)
    check("QUERY: no over-block, the bound twin lists nothing", out == [])
    out = sdr.unbound_evidence_under_production([("KSI-A", _template([wrong]))], [], BINDINGS,
                                                ve.classify_source_binding, ve.classify_pointer_binding)
    check("QUERY: template (unpopulated) records never count", out == [])


# ---------------------------------------------------------------------------
# SOURCE family: the pointer re-targeted to another observation (AUD-F63).
def test_source_family_pointer_substitution_is_unbound_while_verified():
    base = _entry("config", "rule-a", region="us-east-1")
    check("SOURCE: factory-built pointer is bound", ve.classify_pointer_binding(base)[0] == "bound")
    other = _entry("config", "rule-a", region="eu-west-1")
    swapped = copy.deepcopy(base)
    swapped["evidenceLocation"] = other["evidenceLocation"]  # another observation's pointer
    o, m = _outcome(swapped)
    check("SOURCE: pointer swapped, digest kept -> hard INTEGRITY FAILED (the pointer is bound)",
          o == "hard" and "INTEGRITY FAILED" in m)
    _recompute_and_resign(swapped)
    check("SOURCE: pointer swapped + recomputed + re-signed is cryptographically VERIFIED",
          _verified(swapped))
    o, m = ve.classify_pointer_binding(swapped)
    check("SOURCE: ... and the pointer gate reports unbound (AUD-F63)", o == "unbound" and "AUD-F63" in m)
    # Scope and run id are part of the observation identity (AUD-F27).
    scoped = _entry("config", "rule-a", account="123456789012", scope_key=b"k" * 32, run_id="run-0123abcd")
    check("SOURCE: scoped + run-stamped pointer is bound", ve.classify_pointer_binding(scoped)[0] == "bound")
    check("SOURCE: the scoped pointer carries the opaque scope and the run id",
          scoped["xSourceFact"]["scope"] in scoped["evidenceLocation"]
          and "/run-0123abcd.json" in scoped["evidenceLocation"])
    descoped = copy.deepcopy(scoped)
    descoped["evidenceLocation"] = descoped["evidenceLocation"].replace(
        "/" + scoped["xSourceFact"]["scope"] + "/", "/")
    _recompute_and_resign(descoped)
    check("SOURCE: scope stripped from the pointer (recomputed, re-signed) -> verified but unbound",
          _verified(descoped) and ve.classify_pointer_binding(descoped)[0] == "unbound")
    rerun = copy.deepcopy(scoped)
    rerun["evidenceLocation"] = rerun["evidenceLocation"].replace("/run-0123abcd.json", "/run-ffffffff.json")
    _recompute_and_resign(rerun)
    check("SOURCE: pointer moved to another run (recomputed, re-signed) -> verified but unbound",
          _verified(rerun) and ve.classify_pointer_binding(rerun)[0] == "unbound")
    # AUD-F81 (found by MCE-12): the per-record identity a findings-type source
    # stamps (AUD-F77) is part of the pointer; the check must know the segment,
    # or every such entry is unbound and production-assurance is unsatisfiable
    # for that source.
    per_record = ew.fact_to_evidence(
        {"service": "scanner", "check": "open-port", "status": "FAIL", "region": "global",
         "detail": "unit fixture", "observed_at": "2026-10-10T00:00:00+00:00",
         "project": "fictional-project-0001", "record_id": "findings/0001"},
        location_base=_BASE_URI, scope_key=b"k" * 32)
    _sign(per_record)
    check("SOURCE: a per-record pointer carries scope, region and the opaque record id",
          per_record["xSourceFact"].get("record", "").startswith("rec-")
          and per_record["evidenceLocation"].endswith(
              f"/{per_record['xSourceFact']['scope']}/global/{per_record['xSourceFact']['record']}.json"))
    check("SOURCE: the factory-built per-record pointer is BOUND (AUD-F81)",
          ve.classify_pointer_binding(per_record)[0] == "bound")
    other_record = ew.fact_to_evidence(
        {"service": "scanner", "check": "open-port", "status": "FAIL", "region": "global",
         "detail": "unit fixture", "observed_at": "2026-10-10T00:00:00+00:00",
         "project": "fictional-project-0001", "record_id": "findings/0002"},
        location_base=_BASE_URI, scope_key=b"k" * 32)
    swapped_record = copy.deepcopy(per_record)
    swapped_record["evidenceLocation"] = other_record["evidenceLocation"]  # another resource's pointer
    _recompute_and_resign(swapped_record)
    check("SOURCE: pointer moved to another RECORD of the same check (recomputed, re-signed) -> verified but unbound",
          _verified(swapped_record) and ve.classify_pointer_binding(swapped_record)[0] == "unbound")
    derecorded = copy.deepcopy(per_record)
    derecorded["evidenceLocation"] = derecorded["evidenceLocation"].replace(
        "/" + per_record["xSourceFact"]["record"] + ".json", ".json")
    _recompute_and_resign(derecorded)
    check("SOURCE: record segment stripped from the pointer (recomputed, re-signed) -> verified but unbound",
          _verified(derecorded) and ve.classify_pointer_binding(derecorded)[0] == "unbound")
    placeholder = ew.fact_to_evidence({"service": "config", "check": "rule-a", "status": "COMPLIANT",
                                       "region": "us-east-1", "collected_at": "2026-10-10T00:00:00+00:00"})
    check("SOURCE: a placeholder pointer makes no claim here (already a readiness finding)",
          placeholder["evidenceLocation"].startswith("sdr://placeholder/")
          and ve.classify_pointer_binding(placeholder)[0] == "no-claim")
    human = {"evidenceType": "Document", "evidenceLocation": "https://x/y.pdf", "lastUpdated": "2026-10-10"}
    check("SOURCE: no source fact -> no claim", ve.classify_pointer_binding(human)[0] == "no-claim")
    # Preflight helper: KSI evidence and FRR rule artifacts alike.
    frr = {"implementation": ["Real narrative."], "extension": {"rule_artifacts": [swapped]}}
    out = sdr.unbound_evidence_under_production([("KSI-A", _populated([base]))], [("FRR-X", frr)], BINDINGS,
                                                ve.classify_source_binding, ve.classify_pointer_binding)
    check("SOURCE: preflight helper lists the FRR artifact's pointer and nothing for the bound KSI entry",
          [(r, i, k) for r, i, k, _ in out] == [("FRR-X", 0, "pointer")])


# ---------------------------------------------------------------------------
# FRESHNESS family: a stale observation with a valid digest and signature (AUD-F64).
def test_freshness_family_stale_but_internally_valid_is_expired():
    fresh = _entry(observed="2026-10-10T00:00:00+00:00")
    stale = copy.deepcopy(fresh)
    old = (_NOW - dt.timedelta(days=400)).isoformat()
    stale["lastUpdated"] = old[:10]
    stale["xSourceFact"]["collected_at"] = old
    o, m = _outcome(stale)
    check("FRESHNESS: date edited, digest kept -> hard (lastUpdated is a bound field)",
          o == "hard" and "INTEGRITY FAILED" in m)
    _recompute_and_resign(stale)
    check("FRESHNESS: stale + recomputed + re-signed is cryptographically VERIFIED", _verified(stale))
    check("FRESHNESS: the same observation date the preflight scan reads is the bound lastUpdated",
          sdr._evidence_observed_at(stale) == old[:10])
    check("FRESHNESS: 400-day-old observation -> expired under the default 90-day policy (AUD-F64)",
          sdr.classify_evidence_freshness(sdr._evidence_observed_at(stale), _NOW) == "expired")
    mid = copy.deepcopy(fresh)
    mid["lastUpdated"] = (_NOW - dt.timedelta(days=120)).date().isoformat()
    _recompute_and_resign(mid)
    check("FRESHNESS: 120-day-old -> stale (warning tier), still verified",
          _verified(mid) and sdr.classify_evidence_freshness(sdr._evidence_observed_at(mid), _NOW) == "stale")
    check("FRESHNESS: 4-day-old -> current (no over-block)",
          sdr.classify_evidence_freshness(sdr._evidence_observed_at(fresh), _NOW) == "current")
    check("FRESHNESS: a tightened 30-day policy expires the 120-day entry",
          sdr.classify_evidence_freshness(sdr._evidence_observed_at(mid), _NOW, policy_days=30) == "expired")


def main():
    for t in (test_hash_family_tripwire,
              test_query_family_bindings_from_the_repository,
              test_query_family_wrong_ksi_is_unbound_while_cryptographically_verified,
              test_source_family_pointer_substitution_is_unbound_while_verified,
              test_freshness_family_stale_but_internally_valid_is_expired):
        print(t.__name__)
        t()
    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: provenance mutation families ({_fail} failures)")
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
