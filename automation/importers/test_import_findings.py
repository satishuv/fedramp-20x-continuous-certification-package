#!/usr/bin/env python3
"""Offline tests for the AWS Config / Security Hub export importer.

No network, no AWS, no credentials. Fixtures are small hand-built AWS CLI
response shapes (field names verified against the Config and Security Hub API
references: ComplianceByConfigRules, ConfigRules Source.SourceIdentifier,
ConfigRulesEvaluationStatus LastSuccessfulEvaluationTime, ASFF Compliance /
Workflow / Severity / RecordState). Run:
    python automation/importers/test_import_findings.py
"""
import copy
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(BASE, "automation", "prefill"))
sys.path.insert(0, os.path.join(BASE, "automation", "ai"))
import import_findings as imp  # noqa: E402
import prefill_from_facts as pf  # noqa: E402
import draft_narratives as dn  # noqa: E402

REGISTRY = json.load(open(imp.REGISTRY, encoding="utf-8"))
RULE_CHECKS = imp.registry_rule_checks(REGISTRY)
KNOWN = set(RULE_CHECKS)
RECORD_STORE = json.load(open(os.path.join(BASE, "sdr", "records", "records-store.json"),
                              encoding="utf-8"))

SECRET_TITLE = "S3 bucket acme-prod-customer-data allows public read"
SECRET_RESOURCE = "arn:aws:s3:::acme-prod-customer-data"


def compliance_export(rows, next_token=None):
    doc = {"ComplianceByConfigRules": [
        {"ConfigRuleName": n, "Compliance": {"ComplianceType": ct}} for n, ct in rows]}
    if next_token:
        doc["NextToken"] = next_token
    return doc


def rules_export(rows):
    return {"ConfigRules": [
        {"ConfigRuleName": n, "Source": {"Owner": "AWS", "SourceIdentifier": ident}}
        for n, ident in rows]}


def status_export(rows):
    return {"ConfigRulesEvaluationStatus": [
        {"ConfigRuleName": n, "LastSuccessfulEvaluationTime": ts, **extra}
        for n, ts, extra in rows]}


def finding(status="FAILED", workflow="NEW", severity="HIGH", record="ACTIVE",
            updated="2026-10-09T12:00:00.000Z", control="S3.2",
            standard="standards/aws-foundational-security-best-practices/v/1.0.0",
            product="Security Hub"):
    return {
        "Id": SECRET_RESOURCE + "/finding/0001",
        "Title": SECRET_TITLE,
        "ProductName": product,
        "Region": "us-east-1",
        "RecordState": record,
        "UpdatedAt": updated,
        "Severity": {"Label": severity},
        "Workflow": {"Status": workflow},
        "Compliance": {"Status": status, "SecurityControlId": control,
                       "AssociatedStandards": [{"StandardsId": standard}]},
        "Resources": [{"Type": "AwsS3Bucket", "Id": SECRET_RESOURCE}],
    }


def write_exports(tmp, **docs):
    paths = []
    for name, doc in docs.items():
        p = os.path.join(tmp, name + ".json")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        paths.append(p)
    return paths


# ---- detection ---------------------------------------------------------------

def test_detects_each_kind_by_top_level_key():
    assert imp.detect_kind(compliance_export([])) == "config-compliance"
    assert imp.detect_kind(rules_export([])) == "config-rules"
    assert imp.detect_kind(status_export([])) == "config-evaluation-status"
    assert imp.detect_kind({"Findings": []}) == "securityhub-findings"
    assert imp.detect_kind({"Something": []}) is None
    assert imp.detect_kind({"Findings": [], "ConfigRules": []}) is None  # ambiguous
    assert imp.detect_kind([1, 2]) is None


def test_unrecognised_export_is_refused():
    with tempfile.TemporaryDirectory() as tmp:
        paths = write_exports(tmp, odd={"Buckets": []})
        try:
            imp.read_exports(paths)
            raised = False
        except imp.RefusedInput:
            raised = True
        assert raised


# ---- mapping as data ---------------------------------------------------------

def test_exact_id_maps_to_itself():
    assert imp.map_rule_name("s3-bucket-versioning-enabled", KNOWN, {}, {}) \
        == "s3-bucket-versioning-enabled"


def test_securityhub_service_linked_convention_maps_whole_body():
    assert imp.map_rule_name("securityhub-vpc-flow-logs-enabled-12345", KNOWN, {}, {}) \
        == "vpc-flow-logs-enabled"
    # The body is matched whole: a longer managed rule that CONTAINS a shorter
    # one as a token resolves to the longer one, never to the substring.
    assert imp.map_rule_name("securityhub-multi-region-cloudtrail-enabled-ab12cd34",
                             KNOWN, {}, {}) == "multi-region-cloudtrail-enabled"
    assert "cloudtrail-enabled" in KNOWN  # the trap exists in the vocabulary
    # A securityhub- rule whose body is not a framework id is not guessed.
    assert imp.map_rule_name("securityhub-not-a-framework-rule-1a2b3c", KNOWN, {}, {}) is None


BY_IDENT = imp.catalog_identifiers()


def test_source_identifier_maps_through_pinned_catalog_not_a_transform():
    ids = {"MyOrgEncryptedVolumes": "ENCRYPTED_VOLUMES"}
    assert imp.map_rule_name("MyOrgEncryptedVolumes", KNOWN, ids, {}, BY_IDENT) \
        == "encrypted-volumes"
    # The four identifiers that are not a transform of the rule name, each
    # read from the rule's AWS Config Developer Guide page.
    irregular = {"INCOMING_SSH_DISABLED": "restricted-ssh",
                 "RESTRICTED_INCOMING_TRAFFIC": "restricted-common-ports",
                 "CLOUD_TRAIL_ENABLED": "cloudtrail-enabled",
                 "MULTI_REGION_CLOUD_TRAIL_ENABLED": "multi-region-cloudtrail-enabled"}
    for ident, expect in irregular.items():
        assert imp.map_rule_name("ct-rule", KNOWN, {"ct-rule": ident}, {}, BY_IDENT) == expect
    # A naive lower/underscore transform would have missed all four.
    for ident, expect in irregular.items():
        assert ident.lower().replace("_", "-") != expect
    # Without the pinned map nothing resolves by identifier (no guessing).
    assert imp.map_rule_name("MyOrgEncryptedVolumes", KNOWN, ids, {}, None) is None
    assert imp.map_rule_name("MyOrgEncryptedVolumes", KNOWN, ids, {}, {}) is None
    # A custom Lambda ARN identifier never resolves.
    ids = {"custom": "arn:aws:lambda:us-east-1:111122223333:function:custom_rule"}
    assert imp.map_rule_name("custom", KNOWN, ids, {}, BY_IDENT) is None


def test_pinned_catalog_covers_every_framework_rule_exactly_once():
    assert set(BY_IDENT.values()) == KNOWN
    assert len(BY_IDENT) == len(KNOWN)  # identifiers are unique
    for ident in BY_IDENT:
        assert ident == ident.upper() and " " not in ident, ident


def test_source_identifier_requires_aws_owner():
    doc = rules_export([("a", "ENCRYPTED_VOLUMES")])
    doc["ConfigRules"].append({"ConfigRuleName": "b",
                               "Source": {"Owner": "CUSTOM_LAMBDA",
                                          "SourceIdentifier": "ENCRYPTED_VOLUMES"}})
    assert imp.config_source_identifiers([doc]) == {"a": "ENCRYPTED_VOLUMES"}


def test_provider_map_is_last_resort_and_validated():
    assert imp.map_rule_name("AWSControlTower_AWS-GR_ENCRYPTED_VOLUMES", KNOWN, {},
                             {"AWSControlTower_AWS-GR_ENCRYPTED_VOLUMES": "encrypted-volumes"}) \
        == "encrypted-volumes"
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "map.json")
        json.dump({"names": {"x": "not-a-framework-id"}}, open(p, "w", encoding="utf-8"))
        try:
            imp.load_name_map(p, KNOWN)
            raised = False
        except imp.RefusedInput:
            raised = True
        assert raised, "a map value that cannot route must be refused, not dropped"
        assert imp.load_name_map(os.path.join(tmp, "absent.json"), KNOWN) == {}


def test_shipped_name_map_is_valid_and_empty():
    names = imp.load_name_map(imp.NAME_MAP, KNOWN)
    assert names == {}, "the template ships no provider-specific names"


def test_unmapped_names_go_to_the_review_queue_not_to_facts():
    comp = {"securityhub-s3-bucket-versioning-enabled-1a2b3c": "COMPLIANT",
            "acme-custom-rule": "NON_COMPLIANT"}
    facts, unmapped = imp.build_config_facts(comp, RULE_CHECKS, {}, {}, {},
                                             "us-east-1", "2026-10-09T12:00:00+00:00")
    assert [f["rule"] for f in facts] == ["s3-bucket-versioning-enabled"]
    assert unmapped == ["acme-custom-rule"]


def test_instances_aggregate_worst_wins():
    comp = {"encrypted-volumes": "COMPLIANT",
            "securityhub-encrypted-volumes-9f8e7d": "NON_COMPLIANT"}
    facts, _ = imp.build_config_facts(comp, RULE_CHECKS, {}, {}, {}, "r", "t")
    assert len(facts) == 1 and facts[0]["compliance_type"] == "NON_COMPLIANT"
    assert facts[0]["instances"] == 2
    comp = {"encrypted-volumes": "INSUFFICIENT_DATA",
            "securityhub-encrypted-volumes-9f8e7d": "COMPLIANT"}
    facts, _ = imp.build_config_facts(comp, RULE_CHECKS, {}, {}, {}, "r", "t")
    assert facts[0]["compliance_type"] == "COMPLIANT"
    comp = {"encrypted-volumes": "UNKNOWN"}
    facts, _ = imp.build_config_facts(comp, RULE_CHECKS, {}, {}, {}, "r", "t")
    assert facts[0]["compliance_type"] == "UNKNOWN"


# ---- shape parity with the live collector -----------------------------------

def test_config_fact_shape_matches_collector():
    comp = {"encrypted-volumes": "COMPLIANT"}
    status = {"encrypted-volumes": {"last_success": imp.parse_ts("2026-10-09T01:00:00Z"),
                                    "last_failed": None, "error_code": None}}
    facts, _ = imp.build_config_facts(comp, RULE_CHECKS, {}, {}, status, "us-east-1",
                                      "2026-10-09T12:00:00+00:00")
    f = facts[0]
    # The keys collect_facts.py writes, which prefill and the appender read.
    for k in ("rule", "check_ids", "collected_at", "region", "compliance_type"):
        assert k in f, k
    assert f["check_ids"] == RULE_CHECKS["encrypted-volumes"]
    assert f["last_evaluated_at"] == "2026-10-09T01:00:00+00:00"


def test_posture_fact_shape_matches_collector_fact():
    comp = {"a": "COMPLIANT", "b": "NON_COMPLIANT", "c": "INSUFFICIENT_DATA"}
    sh = imp.securityhub_summary([{"Findings": [finding(), finding(status="PASSED")]}])
    facts = imp.build_posture_facts(comp, False, sh, "us-east-1", "2026-10-09T12:00:00+00:00")
    by = {(x["service"], x["check"]): x for x in facts}
    rc = by[("config", "rule_compliance")]
    assert rc["status"] == "OBSERVED"
    assert (rc["measured"], rc["total"], rc["evaluated_total"]) == (1, 2, 2)
    assert (rc["scope_total"], rc["unknown_total"]) == (3, 1)
    for k in ("service", "check", "status", "detail", "region", "collected_at"):
        assert k in rc
    ff = by[("securityhub", "failed_findings")]
    assert ff["status"] == "OBSERVED" and "1 active failed" in ff["detail"]
    assert "measured" not in ff  # an observation, never a pass
    assert by[("securityhub", "siem_aggregation")]["status"] == "ENABLED"


def test_partial_export_is_not_scorable():
    comp, partial = imp.config_compliance([compliance_export(
        [("a", "COMPLIANT")], next_token="abc")])
    assert partial
    facts = imp.build_posture_facts(comp, partial, None, "r", "t")
    assert facts[0]["status"] == "OBSERVED_PARTIAL" and facts[0]["partial"] is True
    assert "measured" not in facts[0]


def test_no_findings_means_no_securityhub_facts():
    sh = imp.securityhub_summary([{"Findings": []}])
    assert imp.build_posture_facts({}, False, sh, "r", "t") == []


# ---- observation time --------------------------------------------------------

def test_parse_ts_accepts_cli_shapes():
    for s in ("2026-10-09T12:00:00.123000+00:00", "2026-10-09T12:00:00Z",
              "2026-10-09 12:00:00+00:00", 1791979200):
        assert imp.parse_ts(s) is not None, s
    assert imp.parse_ts("yesterday") is None and imp.parse_ts(None) is None


def test_observed_time_is_the_latest_in_the_exports():
    with tempfile.TemporaryDirectory() as tmp:
        paths = write_exports(
            tmp,
            comp=compliance_export([("encrypted-volumes", "COMPLIANT")]),
            status=status_export([("encrypted-volumes", "2026-10-08T00:00:00Z", {})]),
            sh={"Findings": [finding(updated="2026-10-09T15:30:00.000Z")]})
        store, _ = imp.build_store(paths, "us-east-1")
    assert store["meta"]["collected_at"] == "2026-10-09T15:30:00+00:00"
    assert store["meta"]["observed_at_source"] == "export"


def test_export_without_time_needs_observed_at():
    with tempfile.TemporaryDirectory() as tmp:
        paths = write_exports(tmp, comp=compliance_export([("encrypted-volumes", "COMPLIANT")]))
        store, _ = imp.build_store(paths, "us-east-1")
        assert store is None
        store, _ = imp.build_store(paths, "us-east-1", observed_at="2026-10-09T09:00:00Z")
        assert store["meta"]["collected_at"] == "2026-10-09T09:00:00+00:00"
        assert store["meta"]["observed_at_source"] == "explicit"
        try:
            imp.build_store(paths, "us-east-1", observed_at="last tuesday")
            raised = False
        except imp.RefusedInput:
            raised = True
        assert raised


# ---- observations: real ids, no specifics -----------------------------------

def test_observation_rule_ids_exist_in_pinned_dataset_all_branches():
    ids = imp.dataset_rule_ids()
    for rid in imp.OBSERVED_RULES:
        assert rid in ids, rid
    assert "VDR-TFR-MVX" in ids  # lives in the 20x branch, not 'all'


def test_observations_carry_counts_never_specifics():
    with tempfile.TemporaryDirectory() as tmp:
        paths = write_exports(
            tmp,
            comp=compliance_export([("encrypted-volumes", "NON_COMPLIANT"),
                                    ("acme-custom-rule", "COMPLIANT")]),
            status=status_export([
                ("encrypted-volumes", "2026-10-09T01:00:00Z", {}),
                ("acme-custom-rule", "2026-09-01T01:00:00Z",
                 {"LastFailedEvaluationTime": "2026-10-01T00:00:00Z",
                  "LastErrorCode": "InsufficientPermissionsException"})]),
            sh={"Findings": [finding(), finding(severity="CRITICAL", control="S3.8"),
                             finding(status="PASSED", workflow="RESOLVED",
                                     record="ARCHIVED"),
                             finding(workflow="SUPPRESSED", severity="LOW",
                                     product="GuardDuty")]})
        store, _ = imp.build_store(paths, "us-east-1")
    blob = json.dumps(store)
    assert SECRET_TITLE not in blob and SECRET_RESOURCE not in blob
    assert "arn:" not in blob and "111122223333" not in blob
    obs = store["rule_observations"]
    assert set(obs) == set(imp.OBSERVED_RULES)
    det = " ".join(o["text"] for o in obs["VDR-CSO-DET"])
    assert "2 rule(s)" in det and "1 report NON_COMPLIANT" in det
    assert "3 active finding(s)" in det and "1 critical, 1 high, 0 medium, 1 low" in det
    assert "2 distinct control(s)" in det
    res = obs["VDR-CSO-RES"][0]["text"]
    assert "NEW 2" in res and "SUPPRESSED 1" in res and "RESOLVED across all records in the export: 1" in res
    mvx = obs["VDR-TFR-MVX"][0]["text"]
    assert "Of 2 rule(s)" in mvx and "1 evaluated within 7 days and 1 within 3 days" in mvx
    assert "1 rule(s) whose last failed evaluation is more recent" in mvx
    adt = " ".join(o["text"] for o in obs["VDR-CSO-ADT"])
    assert "GuardDuty" in adt and "Security Hub" in adt and "standards enabled" in adt
    for items in obs.values():
        for o in items:
            assert o["observed_at"] == store["meta"]["collected_at"]
            assert o["source"] in ("aws-config-export", "securityhub-export")
    assert store["meta"]["unmapped_config_rules"] == ["acme-custom-rule"]


# ---- downstream: prefill routes the imported facts unchanged ------------------

def test_prefill_consumes_imported_facts_through_its_existing_path():
    comp = {"securityhub-s3-bucket-server-side-encryption-enabled-1a2b3c": "COMPLIANT",
            "x": "NON_COMPLIANT"}
    facts, _ = imp.build_config_facts(comp, RULE_CHECKS, {}, {}, {}, "us-east-1",
                                      "2026-10-09T12:00:00+00:00")
    posture = imp.build_posture_facts(comp, False, None, "us-east-1",
                                      "2026-10-09T12:00:00+00:00")
    config_by_rule = {f["rule"]: f for f in facts}
    posture_by_service = {}
    for p in posture:
        posture_by_service.setdefault(p["service"], []).append(p)
    # KSI-SVC-SIN carries the s3 encryption rule as a config_managed_rule check.
    entry = REGISTRY["ksis"]["KSI-SVC-SIN"]
    rec = copy.deepcopy(RECORD_STORE["ksi"]["KSI-SVC-SIN"])
    changed, notes = pf.prefill_ksi("KSI-SVC-SIN", rec, entry, config_by_rule,
                                    posture_by_service)
    assert changed and any("structured automated method" in n for n in notes)
    methods = [t["method_id"] for t in rec["tests"]]
    assert "KSI-SVC-SIN:verify:config:s3-bucket-server-side-encryption-enabled" in methods
    assert rec["implementation_status"] == RECORD_STORE["ksi"]["KSI-SVC-SIN"]["implementation_status"]
    # KSI-MLA-EVC routes config:rule_compliance by its explicit allowlist.
    entry = REGISTRY["ksis"]["KSI-MLA-EVC"]
    rec = copy.deepcopy(RECORD_STORE["ksi"]["KSI-MLA-EVC"])
    changed, _ = pf.prefill_ksi("KSI-MLA-EVC", rec, entry, {}, posture_by_service)
    assert changed
    assert any(t["method_id"] == "posture:config:rule_compliance" for t in rec["tests"])


# ---- downstream: the drafter quotes observations, labelled, boundary intact --

def _vdr_det_record():
    rec = copy.deepcopy(RECORD_STORE["frr"]["VDR-CSO-DET"])
    rec["implementation"] = ["TBD: Information has not been provided."]
    rec["validation"] = ["TBD: Information has not been provided."]
    return rec


def test_drafter_quotes_observations_when_present_and_is_unchanged_without():
    ctx = {"organization": None, "offering": None}
    plain = _vdr_det_record()
    dn.draft_rule("VDR-CSO-DET", plain, ctx)
    quoted = _vdr_det_record()
    obs = [{"observed_at": "2026-10-09T15:30:00+00:00", "source": "securityhub-export",
            "text": "Security Hub reports 3 active finding(s) with Compliance.Status FAILED."}]
    changed, notes = dn.draft_rule("VDR-CSO-DET", quoted, ctx, obs)
    assert changed and notes == [
        "VDR-CSO-DET: drafted implementation (guidance + imported observations)",
        "VDR-CSO-DET: drafted validation (guidance + imported observations)"]
    for field in ("implementation", "validation"):
        text = quoted[field][0]
        assert text.startswith(dn.DRAFT_LABEL)
        assert "[securityhub-export, 2026-10-09] Security Hub reports 3 active" in text
        assert "telemetry not a verdict" in text
        assert text.endswith("before relying on this text.")
        assert "Observed from the provider's own exports" not in plain[field][0]
    # Identical apart from the observation sentence.
    stripped = quoted["implementation"][0].replace(
        dn._observations_sentence(obs), "")
    assert stripped == plain["implementation"][0]
    for field in dn.FORBIDDEN_FIELDS:
        assert quoted.get(field) == RECORD_STORE["frr"]["VDR-CSO-DET"].get(field)


def test_drafter_caps_quoted_observations_and_skips_malformed():
    obs = [{"text": f"obs {i}", "observed_at": "2026-10-09", "source": "s"} for i in range(6)]
    obs.append({"no_text": True})
    sentence = dn._observations_sentence(obs)
    assert sentence.count("[s, 2026-10-09]") == dn.MAX_OBSERVATIONS
    assert dn._observations_sentence([]) == "" and dn._observations_sentence(None) == ""


def test_load_rule_observations_dedupes_identical_texts(monkeypatched=None):
    with tempfile.TemporaryDirectory() as tmp:
        o = {"observed_at": "2026-10-09T00:00:00+00:00", "source": "s", "text": "same"}
        for fn in ("facts-a-import.json", "facts-b-import.json"):
            json.dump({"rule_observations": {"VDR-CSO-DET": [o]}},
                      open(os.path.join(tmp, fn), "w", encoding="utf-8"))
        json.dump({"posture_facts": []}, open(os.path.join(tmp, "facts-c.json"), "w",
                                              encoding="utf-8"))
        saved = dn.FACTS_DIR
        dn.FACTS_DIR = tmp
        try:
            got = dn.load_rule_observations()
        finally:
            dn.FACTS_DIR = saved
    assert got == {"VDR-CSO-DET": [o]}


# ---- CLI: refusal guards and exit codes ---------------------------------------

def _run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = imp.main(argv)
    return code, buf.getvalue()


def test_cli_dry_run_writes_nothing_and_write_lands_the_store():
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "facts")
        paths = write_exports(tmp, comp=compliance_export([("encrypted-volumes", "COMPLIANT")]),
                              sh={"Findings": [finding()]})
        code, text = _run(paths + ["--region", "us-east-1", "--out-dir", out])
        assert code == 0 and "dry run" in text
        assert not os.path.exists(out)
        code, text = _run(paths + ["--region", "us-east-1", "--out-dir", out, "--write"])
        assert code == 0
        store = json.load(open(imp.out_path(out, "us-east-1"), encoding="utf-8"))
        assert store["meta"]["run_id"].startswith("import-")
        assert store["meta"]["collection_outcome"]["status"] == "OK"
        assert store["meta"]["registry_dataset_version"] == REGISTRY["meta"]["dataset_version"]
        assert [f["kind"] for f in store["meta"]["import_files"]] == [
            "config-compliance", "securityhub-findings"]


def test_cli_refuses_when_live_collection_exists_for_region():
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "facts")
        os.makedirs(out)
        open(imp.live_path(out, "us-east-1"), "w", encoding="utf-8").write("{}")
        paths = write_exports(tmp, sh={"Findings": [finding()]})
        code, text = _run(paths + ["--region", "us-east-1", "--out-dir", out, "--write"])
        assert code == 1 and "double-count" in text
        assert not os.path.exists(imp.out_path(out, "us-east-1"))


def test_cli_exit_codes_for_no_time_and_nothing_evaluated():
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "facts")
        paths = write_exports(tmp, comp=compliance_export([("encrypted-volumes", "COMPLIANT")]))
        code, text = _run(paths + ["--region", "r", "--out-dir", out])
        assert code == 2 and "--observed-at" in text
        paths = write_exports(tmp, comp=compliance_export([("encrypted-volumes", "NOT_APPLICABLE")]))
        code, text = _run(paths + ["--region", "r", "--out-dir", out,
                                   "--observed-at", "2026-10-09T00:00:00Z"])
        assert code == imp.EXIT_NO_EVALUATED and "no evaluated outcome" in text
        paths = write_exports(tmp, odd={"Buckets": []})
        code, text = _run(paths + ["--region", "r", "--out-dir", out])
        assert code == 1 and "Import refused" in text


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
