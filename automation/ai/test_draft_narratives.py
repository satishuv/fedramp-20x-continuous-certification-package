"""Offline tests for the OPT-IN AI narrative drafter. No AWS, no model, no
network: the TemplateDrafter is deterministic. These tests exist to prove the
TRUST BOUNDARY holds in code, the AI module drafts only TBD implementation/
validation prose and never touches status, assessment, tests, or evidence.

Run: python automation/ai/test_draft_narratives.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import draft_narratives as dn  # noqa: E402


def blank_ksi_record():
    return {
        "implementation_status": "Not Implemented",
        "implementation": ["TBD: Information has not been provided."],
        "validation": ["TBD: Information has not been provided."],
        "assessment": ["TBD: Independent assessment has not been performed."],
        "tests": [],
        "evidence": [],
    }


def ksi_entry():
    return {
        "services": ["Amazon GuardDuty"],
        "fill_guidance": {"what_it_looks_for": "Detect suspicious activity."},
    }


def posture():
    return {"guardduty": [{"service": "guardduty", "check": "detector",
                           "status": "ENABLED", "detail": "Detector status ENABLED",
                           "collected_at": "2026-09-07T00:00:00+00:00",
                           "region": "us-east-1"}]}


SERVICE_MAP = {"guardduty": "Amazon GuardDuty"}


def test_drafts_tbd_implementation_and_validation():
    rec = blank_ksi_record()
    changed, notes = dn.draft_ksi("KSI-IAM-SUS", rec, ksi_entry(), posture(),
                                  dn.TemplateDrafter(), SERVICE_MAP)
    assert changed
    assert "DRAFT" in rec["implementation"][0]
    assert "DRAFT" in rec["validation"][0]
    print("PASS: test_drafts_tbd_implementation_and_validation")


def test_never_touches_status_assessment_tests_evidence():
    rec = blank_ksi_record()
    before = {k: rec[k] for k in dn.FORBIDDEN_FIELDS}
    dn.draft_ksi("K", rec, ksi_entry(), posture(), dn.TemplateDrafter(), SERVICE_MAP)
    for field in dn.FORBIDDEN_FIELDS:
        assert rec[field] == before[field], f"AI drafting changed forbidden field {field}"
    print("PASS: test_never_touches_status_assessment_tests_evidence")


def test_boundary_guard_raises_on_violation():
    # A malicious/buggy drafter that tries to flip status must be caught by the
    # per-KSI boundary assertion.
    before = blank_ksi_record()
    after = blank_ksi_record()
    after["implementation_status"] = "Implemented"  # simulated violation
    try:
        dn._assert_boundary(before, after, "K")
        raised = False
    except AssertionError:
        raised = True
    assert raised, "boundary guard failed to catch a status change"
    print("PASS: test_boundary_guard_raises_on_violation")


def test_does_not_overwrite_authored_prose():
    rec = blank_ksi_record()
    rec["implementation"] = ["Real author-written implementation, keep it."]
    dn.draft_ksi("K", rec, ksi_entry(), posture(), dn.TemplateDrafter(), SERVICE_MAP)
    assert rec["implementation"] == ["Real author-written implementation, keep it."]
    print("PASS: test_does_not_overwrite_authored_prose")


def test_draft_never_asserts_compliance():
    # The stub draft must carry the unverified/telemetry caveat, never a claim.
    d = dn.TemplateDrafter()
    text = d.draft("implementation", "KSI-X", {"what_it_looks_for": "x"}, [])
    assert "unverified" in text.lower()
    assert "not a compliance conclusion" in text.lower()
    print("PASS: test_draft_never_asserts_compliance")


def test_offline_stub_needs_no_network_or_model():
    # Constructing and using the default drafter must not import boto3 or reach
    # any network; it is pure string assembly.
    d = dn.get_drafter("template")
    assert d.name == "template"
    text = d.draft("validation", "KSI-Y", {"aws_implementation": "y"}, [])
    assert isinstance(text, str) and text
    print("PASS: test_offline_stub_needs_no_network_or_model")


def test_measure_comes_from_the_record_guidance_when_registry_has_none():
    # The collector registry entry carries no fill_guidance (only services,
    # routes and checks); the record store does. Reading only the registry
    # left "Intended measure:" empty in every KSI proposal.
    rec = blank_ksi_record()
    rec["fill_guidance"] = {"what_it_looks_for": "Accounts are managed using automation."}
    registry_entry = {"services": ["Amazon GuardDuty"], "metric_service_keys": [], "checks": []}
    dn.draft_ksi("KSI-IAM-AAM", rec, registry_entry, posture(), dn.TemplateDrafter(), SERVICE_MAP)
    assert "Intended measure: Accounts are managed using automation." in rec["implementation"][0]
    print("PASS: test_measure_comes_from_the_record_guidance_when_registry_has_none")


def test_imported_observations_are_quoted_and_bounded():
    rec = blank_ksi_record()
    obs = [{"observed_at": "2026-08-15T14:02:00+00:00", "source": "rev5-oscal-ssp",
            "text": "ac-2.2 (Identity Service): temporary accounts expire after 24 hours."}]
    changed, notes = dn.draft_ksi("KSI-IAM-AAM", rec, ksi_entry(), posture(),
                                  dn.TemplateDrafter(), SERVICE_MAP, obs)
    assert changed and notes == [
        "KSI-IAM-AAM: drafted implementation (template + imported observations)",
        "KSI-IAM-AAM: drafted validation (template + imported observations)"]
    text = rec["implementation"][0]
    assert "[rev5-oscal-ssp, 2026-08-15] ac-2.2 (Identity Service)" in text
    assert "not a 20x status" in text
    assert text.endswith("before relying on this text.")
    # Without observations the proposal is unchanged from the plain form.
    plain = blank_ksi_record()
    dn.draft_ksi("KSI-IAM-AAM", plain, ksi_entry(), posture(), dn.TemplateDrafter(), SERVICE_MAP)
    assert "imported sources" not in plain["implementation"][0]
    assert dn._ksi_observations_block([]) == "" and dn._ksi_observations_block(None) == ""

    # A provider's drafter on the older 4-argument interface still gets the
    # quoted imports appended rather than losing them.
    class Legacy:
        name = "legacy"

        def draft(self, kind, ksi_id, guidance, facts):
            return "DRAFT (legacy): body."
    rec2 = blank_ksi_record()
    dn.draft_ksi("KSI-IAM-AAM", rec2, ksi_entry(), posture(), Legacy(), SERVICE_MAP, obs)
    assert rec2["implementation"][0].startswith("DRAFT (legacy): body.")
    assert "[rev5-oscal-ssp, 2026-08-15]" in rec2["implementation"][0]
    print("PASS: test_imported_observations_are_quoted_and_bounded")


def test_f49_ksi_proposal_names_the_indicators_own_config_rule_facts():
    """AUD-F49. The drafter read posture facts only. A KSI whose collected facts
    were Config-rule evaluations (the common case: prefill had just proposed
    them as that KSI's tests) was told 'no automated facts collected for this
    indicator yet' in the very next review item. Config facts are matched the
    way prefill matches them: the registry's config_managed_rule checks."""
    entry = {
        "services": ["AWS IAM"],
        "fill_guidance": {"what_it_looks_for": "Account lifecycle is automated."},
        "checks": [{"type": "config_managed_rule", "target": "access-keys-rotated",
                    "source": "verify", "check_id": "KSI-IAM-AAM:verify:config:access-keys-rotated"},
                   {"type": "config_managed_rule", "target": "iam-user-unused-credentials-check",
                    "source": "verify", "check_id": "KSI-IAM-AAM:verify:config:iam-user-unused-credentials-check"}],
    }
    config_by_rule = {
        "access-keys-rotated": {"rule": "access-keys-rotated", "compliance_type": "NON_COMPLIANT",
                                "collected_at": "2026-10-10T06:20:11+00:00", "region": "us-east-1",
                                "last_evaluated_at": "2026-09-27T05:58:10+00:00"},
        "iam-user-unused-credentials-check": {"rule": "iam-user-unused-credentials-check",
                                              "compliance_type": "RULE_NOT_DEPLOYED",
                                              "collected_at": "2026-10-10T06:20:11+00:00",
                                              "region": "us-east-1"},
    }
    rec = blank_ksi_record()
    changed, _ = dn.draft_ksi("KSI-IAM-AAM", rec, entry, {}, dn.TemplateDrafter(), {},
                              None, config_by_rule)
    assert changed
    text = rec["implementation"][0]
    assert "no automated facts collected" not in text, text
    assert "config.access-keys-rotated=NON_COMPLIANT" in text, text
    assert "last evaluated 2026-09-27" in text, text
    assert "iam-user-unused-credentials-check" not in text  # not deployed: no fact to quote
    # Without config facts the old behaviour is unchanged.
    rec2 = blank_ksi_record()
    dn.draft_ksi("KSI-IAM-AAM", rec2, entry, {}, dn.TemplateDrafter(), {}, None, {})
    assert "no automated facts collected" in rec2["implementation"][0]
    # The matching helper mirrors prefill's: only real evaluated outcomes.
    facts = dn.config_facts_for_ksi(entry, config_by_rule)
    assert [f["check"] for f in facts] == ["access-keys-rotated"]
    assert facts[0]["service"] == "config" and facts[0]["status"] == "NON_COMPLIANT"
    # And the proposal carries no markdown the human-readable gate forbids (AUD-F48).
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "validation", "scripts"))
    import validate_sdr  # noqa: E402
    for field in ("implementation", "validation"):
        hits = [label for pattern, label in validate_sdr.MD_PATTERNS
                if pattern.search(rec[field][0])]
        assert not hits, (field, hits)


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
