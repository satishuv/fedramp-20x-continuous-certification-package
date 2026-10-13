# Offline tests for the deterministic fact-to-field pre-fill. No AWS account
# and no files needed: the prefill_ksi function is exercised directly with
# synthetic registry entries, facts, and records. Run:
#   python automation/prefill/test_prefill.py

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import prefill_from_facts as pf  # noqa: E402


def blank_ksi_record():
    return {
        "implementation_status": "Not Implemented",
        "implementation": ["TBD: Information has not been provided."],
        "validation": ["TBD: Information has not been provided."],
        "assessment": ["TBD: Independent assessment has not been performed."],
        "tests": [],
        "evidence": [],
        "extension": {
            "automation_verification": "TBD: Information has not been provided.",
            "owner": "TBD: Information has not been provided.",
        },
    }


def test_is_tbd():
    assert pf.is_tbd([])
    assert pf.is_tbd(["TBD: Information has not been provided."])
    assert pf.is_tbd("")
    assert not pf.is_tbd(["Real content here."])
    assert not pf.is_tbd("A real sentence.")


def test_config_fact_prefills_tests_and_evidence():
    ksi_entry = {
        "services": ["AWS Config"],
        "checks": [{"type": "config_managed_rule", "target": "cloudtrail-enabled",
                    "source": "verify", "check_id": "KSI-CMT-LMC:verify:config:cloudtrail-enabled"}],
    }
    config_by_rule = {"cloudtrail-enabled": {
        "rule": "cloudtrail-enabled", "compliance_type": "COMPLIANT",
        "collected_at": "2026-09-06T00:00:00+00:00", "region": "us-east-1"}}
    rec = blank_ksi_record()
    changed, notes = pf.prefill_ksi("KSI-CMT-LMC", rec, ksi_entry, config_by_rule, {})
    assert changed
    # AUD-F18: a STRUCTURED automated method whose method_id is EXACTLY the
    # registry check_id the metric engine keys the per-method series by.
    assert len(rec["tests"]) == 1 and isinstance(rec["tests"][0], dict), rec["tests"]
    t = rec["tests"][0]
    assert t["method_id"] == "KSI-CMT-LMC:verify:config:cloudtrail-enabled"
    assert t["automated"] is True and "cloudtrail-enabled" in t["method"]
    assert "COMPLIANT" in t["method"]
    assert len(rec["evidence"]) == 1


def test_posture_fact_prefills():
    # Routing is by the EXPLICIT metric_service_keys allowlist, not prose services.
    ksi_entry = {"services": ["Amazon GuardDuty"], "metric_service_keys": ["guardduty:detector"],
                 "checks": []}
    posture = {"guardduty": [{"service": "guardduty", "check": "detector",
                              "status": "ENABLED", "detail": "Detector status ENABLED",
                              "collected_at": "2026-09-06T00:00:00+00:00",
                              "region": "us-east-1"}]}
    rec = blank_ksi_record()
    changed, _ = pf.prefill_ksi("KSI-INR-XXX", rec, ksi_entry, {}, posture)
    assert changed
    # AUD-F18: method_id is the metric engine's posture key for this check.
    assert [t["method_id"] for t in rec["tests"]] == ["posture:guardduty:detector"]
    assert all(t["automated"] is True for t in rec["tests"])
    assert any("guardduty.detector" in t["method"] and "ENABLED" in t["method"]
               for t in rec["tests"])


def test_securityhub_posture_prefills_with_collector_service_name():
    # The collector emits service="securityhub" (not "security_hub"). This
    # proves the downstream mapping uses the collector's real name, so the
    # telemetry is not silently dropped (regression for the service-name drift).
    ksi_entry = {"services": ["AWS Security Hub"], "metric_service_keys": ["securityhub:enabled"],
                 "checks": []}
    posture = {"securityhub": [{"service": "securityhub", "check": "enabled",
                                "status": "ENABLED", "detail": "Security Hub ENABLED",
                                "collected_at": "2026-09-06T00:00:00+00:00",
                                "region": "us-east-1"}]}
    rec = blank_ksi_record()
    changed, _ = pf.prefill_ksi("KSI-MLA-XXX", rec, ksi_entry, {}, posture)
    assert changed, "a securityhub posture fact must prefill an AWS Security Hub KSI"
    assert [t["method_id"] for t in rec["tests"]] == ["posture:securityhub:enabled"]


def test_prose_services_alone_does_not_route_posture():
    # F-06 regression: a KSI that only NAMES a service in its prose `services`
    # list, with an EMPTY metric_service_keys allowlist, must NOT receive that
    # service's posture. Prefill honors the same explicit allowlist the metric
    # engine uses, so generic posture cannot fan out by service-name mention.
    ksi_entry = {"services": ["Amazon GuardDuty"], "metric_service_keys": [],
                 "checks": []}
    posture = {"guardduty": [{"service": "guardduty", "check": "detector",
                              "status": "ENABLED", "detail": "ENABLED",
                              "collected_at": "2026-09-06T00:00:00+00:00",
                              "region": "us-east-1"}]}
    rec = blank_ksi_record()
    changed, _ = pf.prefill_ksi("KSI-CNA-XXX", rec, ksi_entry, {}, posture)
    assert not changed, "prose services mention must not route posture without the allowlist"
    assert rec["tests"] == []


def test_unknown_metric_service_key_fails_loud():
    # A typo'd allowlist key would silently route nothing; it must raise instead.
    ksi_entry = {"services": [], "metric_service_keys": ["guarddutyy:detector"], "checks": []}
    posture = {"guardduty": [{"service": "guardduty", "check": "detector",
                              "status": "ENABLED", "detail": "ENABLED",
                              "collected_at": "t", "region": "x"}]}
    rec = blank_ksi_record()
    raised = False
    try:
        pf.prefill_ksi("KSI-CNA-YYY", rec, ksi_entry, {}, posture)
    except RuntimeError:
        raised = True
    assert raised, "an unknown metric_service_keys entry must fail loud"


def test_never_touches_status_or_assessment():
    ksi_entry = {
        "services": ["AWS Config"],
        "checks": [{"type": "config_managed_rule", "target": "r",
                    "source": "verify", "check_id": "cid"}],
    }
    config_by_rule = {"r": {"rule": "r", "compliance_type": "COMPLIANT",
                            "collected_at": "2026-09-06T00:00:00+00:00", "region": "x"}}
    rec = blank_ksi_record()
    pf.prefill_ksi("K", rec, ksi_entry, config_by_rule, {})
    assert rec["implementation_status"] == "Not Implemented"
    assert rec["assessment"] == ["TBD: Independent assessment has not been performed."]


def test_does_not_overwrite_populated_fields():
    ksi_entry = {
        "services": ["AWS Config"],
        "checks": [{"type": "config_managed_rule", "target": "r",
                    "source": "verify", "check_id": "cid"}],
    }
    config_by_rule = {"r": {"rule": "r", "compliance_type": "COMPLIANT",
                            "collected_at": "2026-09-06T00:00:00+00:00", "region": "x"}}
    rec = blank_ksi_record()
    rec["tests"] = ["Real author-written test, do not clobber."]
    changed, _ = pf.prefill_ksi("K", rec, ksi_entry, config_by_rule, {})
    # evidence and automation_verification still fill, but tests is preserved.
    assert rec["tests"] == ["Real author-written test, do not clobber."]


def test_error_and_not_deployed_facts_do_not_prefill():
    ksi_entry = {
        "services": ["AWS Config", "Amazon GuardDuty"],
        "checks": [{"type": "config_managed_rule", "target": "r",
                    "source": "verify", "check_id": "cid"}],
    }
    config_by_rule = {"r": {"rule": "r", "compliance_type": "RULE_NOT_DEPLOYED",
                            "collected_at": "t", "region": "x"}}
    posture = {"guardduty": [{"service": "guardduty", "check": "detector",
                              "status": "ERROR:AccessDenied", "detail": "d",
                              "collected_at": "t", "region": "x"}]}
    rec = blank_ksi_record()
    changed, _ = pf.prefill_ksi("K", rec, ksi_entry, config_by_rule, posture)
    assert not changed
    assert rec["tests"] == []


def test_f48_prefilled_text_carries_no_markdown():
    """AUD-F48. The method and evidenceDescription templates wrapped the rule
    name in backticks. Accepting the deterministic facts (the documented
    `review --accept-all prefill`) put them in the human-readable SDR, and the
    gate's no_markdown_in_human_readable check failed on 'backticks' for every
    class. The patterns are the gate's own (validate_sdr.MD_PATTERNS)."""
    import json
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "validation", "scripts"))
    import validate_sdr  # noqa: E402
    ksi_entry = {
        "services": ["AWS Config", "Amazon GuardDuty"],
        "metric_service_keys": ["guardduty:detector"],
        "checks": [{"type": "config_managed_rule", "target": "cloudtrail-enabled",
                    "source": "verify", "check_id": "KSI-CMT-LMC:verify:config:cloudtrail-enabled"}],
    }
    config_by_rule = {"cloudtrail-enabled": {
        "rule": "cloudtrail-enabled", "compliance_type": "COMPLIANT",
        "collected_at": "2026-10-10T06:20:11+00:00", "region": "us-east-1"}}
    posture = {"guardduty": [{"service": "guardduty", "check": "detector", "status": "ENABLED",
                              "detail": "Detector status ENABLED", "region": "us-east-1",
                              "collected_at": "2026-10-10T06:20:11+00:00"}]}
    rec = blank_ksi_record()
    changed, _ = pf.prefill_ksi("KSI-CMT-LMC", rec, ksi_entry, config_by_rule, posture)
    assert changed and len(rec["tests"]) == 2 and len(rec["evidence"]) == 2
    rendered = "\n".join(json.dumps(x) for x in rec["tests"] + rec["evidence"])
    hits = [label for pattern, label in validate_sdr.MD_PATTERNS if pattern.search(rendered)]
    assert not hits, (hits, rendered)
    assert "cloudtrail-enabled" in rec["tests"][0]["method"]  # the rule is still named


def _f58_inputs():
    ksi_entry = {
        "services": ["AWS Config", "Amazon GuardDuty"],
        "metric_service_keys": ["guardduty:detector"],
        "checks": [{"type": "config_managed_rule", "target": "cloudtrail-enabled",
                    "source": "verify", "check_id": "KSI-CMT-LMC:verify:config:cloudtrail-enabled"}],
    }
    config_by_rule = {"cloudtrail-enabled": {
        "rule": "cloudtrail-enabled", "compliance_type": "COMPLIANT",
        "collected_at": "2026-10-10T06:20:11+00:00", "region": "us-east-1"}}
    posture = {"guardduty": [{"service": "guardduty", "check": "detector", "status": "ENABLED",
                              "detail": "Detector status ENABLED", "region": "us-east-1",
                              "collected_at": "2026-10-10T06:20:11+00:00"}]}
    return ksi_entry, config_by_rule, posture


def _integrity_modules():
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.path.insert(0, os.path.join(base, "validation", "scripts"))
    sys.path.insert(0, os.path.join(base, "automation", "collectors"))
    import validate_evidence  # noqa: E402
    import evidence_wiring  # noqa: E402
    return validate_evidence, evidence_wiring


def test_f58_prefilled_evidence_is_bound_hashed_and_verifies_under_the_live_gate():
    """AUD-F58. Prefill hand-assembled evidence objects (type, description, text,
    date) with no evidenceLocation, no xSourceFact and no xEvidenceContentHash,
    while the collector path derived every entry through
    evidence_wiring.fact_to_evidence. Once a human accepted a proposal the record
    carried evidence the live integrity gate could never verify (a permanent
    "no content hash yet" finding, HARD under a required signer after AUD-F57).
    Proposed evidence must now be the canonical bound shape: the gate recomputes
    the digest from the entry's own fields and classifies it verified."""
    ve, ew = _integrity_modules()
    ksi_entry, config_by_rule, posture = _f58_inputs()
    rec = blank_ksi_record()
    changed, _ = pf.prefill_ksi("KSI-CMT-LMC", rec, ksi_entry, config_by_rule, posture,
                                location_base="https://evidence.example.gov/store")
    assert changed and len(rec["evidence"]) == 2, rec["evidence"]
    for e in rec["evidence"]:
        assert e.get("evidenceLocation", "").startswith("https://evidence.example.gov/store/"), e
        assert isinstance(e.get("xSourceFact"), dict) and e["xSourceFact"].get("check"), e
        assert e.get("xEvidenceContentHash") == ew.evidence_hash(ew.canonical_payload(e)), e
        assert e.get("lastUpdated") == "2026-10-10", e
        outcome, msg = ve.classify_entry(e, hash_fn=ew.evidence_hash, trusted_signer=None)
        assert outcome == "verified", (outcome, msg, e)
    # The config fact is rendered as a config-service observation (one factory,
    # one evidenceType mapping) and still names the rule.
    cfg = [e for e in rec["evidence"] if e["xSourceFact"].get("service") == "config"]
    assert len(cfg) == 1 and cfg[0]["xSourceFact"]["check"] == "cloudtrail-enabled", cfg
    assert cfg[0]["evidenceType"] == "Configuration" and "cloudtrail-enabled" in cfg[0]["evidenceText"]


def test_f58_prefilled_evidence_without_location_base_is_an_explicit_placeholder():
    # No base URI: the pointer is the explicit sdr://placeholder/ pseudo-URI the
    # preflight refuses, never a fabricated https link, and it is still hashed
    # so a hand edit of the pointer is detected (the entry must be re-derived).
    ve, ew = _integrity_modules()
    ksi_entry, config_by_rule, posture = _f58_inputs()
    rec = blank_ksi_record()
    pf.prefill_ksi("KSI-CMT-LMC", rec, ksi_entry, config_by_rule, posture)
    for e in rec["evidence"]:
        assert e["evidenceLocation"].startswith("sdr://placeholder/"), e
        assert e.get("xEvidenceContentHash") == ew.evidence_hash(ew.canonical_payload(e))
        outcome, msg = ve.classify_entry(e, hash_fn=ew.evidence_hash, trusted_signer=None)
        assert outcome == "finding" and "placeholder" in msg, (outcome, msg)
        e["evidenceLocation"] = "https://evidence.example.gov/edited-by-hand.json"
        outcome, _ = ve.classify_entry(e, hash_fn=ew.evidence_hash, trusted_signer=None)
        assert outcome == "hard", "a hand-edited bound pointer must fail the digest recompute"


def test_f58_account_tagged_facts_are_scoped_never_leaked_and_refused_without_a_key():
    # AUD-F27 carried through prefill: a multi-account fact carrying a raw
    # account is exported with an opaque scope (given a scope key) and the
    # account id never appears anywhere in the proposed object; without a scope
    # key the factory refuses and prefill does not swallow the refusal.
    import json
    _, ew = _integrity_modules()
    ksi_entry, config_by_rule, posture = _f58_inputs()
    account = "123456789012"
    config_by_rule["cloudtrail-enabled"]["account"] = account
    config_by_rule["cloudtrail-enabled"]["run_id"] = "run-20261010-0620"
    posture["guardduty"][0]["account"] = account
    rec = blank_ksi_record()
    pf.prefill_ksi("KSI-CMT-LMC", rec, ksi_entry, config_by_rule, posture,
                   location_base="https://evidence.example.gov/store", scope_key="unit-test-key")
    assert len(rec["evidence"]) == 2
    for e in rec["evidence"]:
        assert account not in json.dumps(e), e
        assert e["xSourceFact"].get("scope") == ew.scope_id(account, "unit-test-key"), e
        assert e["xSourceFact"]["scope"] in e["evidenceLocation"], e
    rec2 = blank_ksi_record()
    try:
        pf.prefill_ksi("KSI-CMT-LMC", rec2, ksi_entry, config_by_rule, posture,
                       location_base="https://evidence.example.gov/store")
    except ew.EvidenceExportError:
        pass
    else:
        raise AssertionError("an account-tagged fact with no scope key must be refused, not exported")
    assert rec2["evidence"] == [], "a refused fact must not leave a partial proposal"


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
