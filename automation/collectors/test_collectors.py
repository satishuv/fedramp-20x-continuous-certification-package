# Offline tests for the read-only posture collectors. No AWS account, no boto3
# required: a fake session returns canned client objects whose methods return
# canned responses or raise canned client errors. Run: python -m pytest, or
# python automation/collectors/test_collectors.py for a dependency-free run.

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import collectors  # noqa: E402


class FakeClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeClient:
    """Returns canned values per method name, or raises a canned error."""
    def __init__(self, responses=None, errors=None):
        self._responses = responses or {}
        self._errors = errors or {}

    def __getattr__(self, name):
        def method(**_kwargs):
            if name in self._errors:
                raise self._errors[name]
            return self._responses.get(name, {})
        return method


class FakeSession:
    def __init__(self, clients):
        self._clients = clients

    def client(self, name):
        c = self._clients.get(name)
        if c is None:
            raise RuntimeError(f"no fake client for {name}")
        return c


def facts_by_check(facts):
    return {f["check"]: f for f in facts}


def test_security_hub_enabled_with_findings():
    sess = FakeSession({"securityhub": FakeClient(responses={
        "describe_hub": {"HubArn": "arn"},
        "get_findings": {"Findings": [{}, {}, {}], "NextToken": "more"},
    })})
    facts = collectors.collect_security_hub(sess, "us-east-1")
    by = facts_by_check(facts)
    assert by["enabled"]["status"] == "ENABLED"
    assert "3+" in by["failed_findings"]["detail"]


def test_security_hub_not_enabled():
    sess = FakeSession({"securityhub": FakeClient(
        errors={"describe_hub": FakeClientError("InvalidAccessException")})})
    facts = collectors.collect_security_hub(sess, "us-east-1")
    assert facts_by_check(facts)["enabled"]["status"] == "NOT_ENABLED"


def test_access_analyzer_none():
    sess = FakeSession({"accessanalyzer": FakeClient(responses={
        "list_analyzers": {"analyzers": []}})})
    facts = collectors.collect_access_analyzer(sess, "us-east-1")
    assert facts_by_check(facts)["analyzer"]["status"] == "NONE"


def test_access_analyzer_present_with_findings():
    sess = FakeSession({"accessanalyzer": FakeClient(responses={
        "list_analyzers": {"analyzers": [{"arn": "a1"}]},
        "list_findings": {"findings": [{}, {}]},
    })})
    facts = facts_by_check(collectors.collect_access_analyzer(sess, "us-east-1"))
    assert facts["analyzer"]["status"] == "PRESENT"
    assert "2 active" in facts["active_findings"]["detail"]


def test_inspector_active():
    sess = FakeSession({"inspector2": FakeClient(responses={
        "list_coverage": {"coveredResources": [
            {"scanStatus": {"statusCode": "ACTIVE"}},
            {"scanStatus": {"statusCode": "INACTIVE"}},
        ]}})})
    fact = collectors.collect_inspector(sess, "us-east-1")[0]
    # F09: complete page (no nextToken) -> OBSERVED with the real fraction.
    assert fact["status"] == "OBSERVED"
    assert fact.get("measured") == 1 and fact.get("total") == 2, fact


def test_f09_bounded_sample_is_partial_not_full_pass():
    # The audit's case: 1 active of 100, with a nextToken (more unexamined).
    # Must NOT become a 1/1 (100%) passing metric; it is a bounded partial
    # sample that scores nothing.
    resources = [{"scanStatus": {"statusCode": "ACTIVE"}}]
    resources += [{"scanStatus": {"statusCode": "INACTIVE"}} for _ in range(99)]
    sess = FakeSession({"inspector2": FakeClient(responses={
        "list_coverage": {"coveredResources": resources, "nextToken": "more"}})})
    fact = collectors.collect_inspector(sess, "us-east-1")[0]
    assert fact["status"] == "OBSERVED_PARTIAL", fact
    # No measured/total ratio -> the scorer skips it (no false 100%).
    assert "measured" not in fact, fact
    import sys as _s
    _s.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "metrics"))
    import append_metrics as _am
    assert _am._posture_score(fact) is None, "partial sample must not score"


def test_guardduty_enabled():
    sess = FakeSession({"guardduty": FakeClient(responses={
        "list_detectors": {"DetectorIds": ["d1"]},
        "get_detector": {"Status": "ENABLED"},
    })})
    assert collectors.collect_guardduty(sess, "us-east-1")[0]["status"] == "ENABLED"


def test_guardduty_none():
    sess = FakeSession({"guardduty": FakeClient(responses={
        "list_detectors": {"DetectorIds": []}})})
    assert collectors.collect_guardduty(sess, "us-east-1")[0]["status"] == "NONE"


def test_backup_present_and_protected():
    sess = FakeSession({"backup": FakeClient(responses={
        "list_backup_plans": {"BackupPlansList": [{}]},
        "list_protected_resources": {"Results": [{}, {}, {}]},
    })})
    by = facts_by_check(collectors.collect_backup(sess, "us-east-1"))
    assert by["plans"]["status"] == "PRESENT"
    assert "3 protected" in by["protected_resources"]["detail"]


def test_kms_rotation_fraction():
    kms = FakeClient(responses={
        "list_keys": {"Keys": [{"KeyId": "k1"}, {"KeyId": "k2"}]},
        "get_key_rotation_status": {"KeyRotationEnabled": True},
    })
    sess = FakeSession({"kms": kms})
    fact = collectors.collect_kms(sess, "us-east-1")[0]
    assert fact["status"] == "OBSERVED"
    assert "2 of 2" in fact["detail"]


def test_one_service_failure_does_not_raise():
    # A client that raises on every call must yield an ERROR fact, not crash.
    sess = FakeSession({"guardduty": FakeClient(
        errors={"list_detectors": FakeClientError("AccessDenied")})})
    facts = collectors.collect_guardduty(sess, "us-east-1")
    assert facts and facts[0]["status"].startswith("ERROR")


def test_allowlist_is_read_only():
    # Every action in the allowlist must be a read verb; no mutations ever.
    # BatchGet is a read (e.g. inspector2:BatchGetAccountStatus reads status).
    read_prefixes = ("Get", "List", "Describe", "BatchGet")
    for action in collectors.READ_ONLY_ACTIONS:
        verb = action.split(":", 1)[1]
        assert verb.startswith(read_prefixes), f"non-read action in allowlist: {action}"


# --- AUD-F83: allowlist entries must be the names IAM evaluates --------------
# Found by the first live AWS run (2026-10-17) under a role granting exactly
# READ_ONLY_ACTIONS: three collectors were denied. AWS's own denial messages
# named the actions it evaluates: "access-analyzer:ListAnalyzers" (the IAM
# prefix is not the boto3 client name), "s3:GetEncryptionConfiguration" and
# "s3:GetLifecycleConfiguration" (the IAM action is not the API operation name).
# The pipeline CollectorRole copied the same wrong strings, so the iam-matches
# test agreed with itself. An offline oracle exists for the prefix (botocore's
# signing name is the IAM service prefix for every service the collectors use);
# the two S3 names are pinned from the live denials.

# botocore client name -> IAM service prefix (botocore signing name). s3control
# signs as s3, so its one action lives under the s3: prefix in IAM as well.
_IAM_PREFIX_FOR_CLIENT = {"accessanalyzer": "access-analyzer", "s3control": "s3"}
_LIVE_DENIED_FORMS = {
    "accessanalyzer:ListAnalyzers", "accessanalyzer:ListFindings",
    "s3:GetBucketEncryption", "s3:GetBucketLifecycleConfiguration",
}
_LIVE_EVALUATED_FORMS = {
    "access-analyzer:ListAnalyzers", "access-analyzer:ListFindings",
    "s3:GetEncryptionConfiguration", "s3:GetLifecycleConfiguration",
}


def test_f83_allowlist_prefixes_are_iam_signing_names():
    import botocore.session
    sess = botocore.session.get_session()
    prefixes = {a.split(":", 1)[0] for a in collectors.READ_ONLY_ACTIONS}
    # Every prefix must be the signing name of SOME service the SDK knows.
    known = set()
    for client in ("accessanalyzer", "backup", "cloudformation", "cloudtrail",
                   "codepipeline", "config", "dynamodb", "ec2", "ecr", "events",
                   "guardduty", "iam", "inspector2", "kms", "s3", "s3control",
                   "securityhub", "sts", "wafv2"):
        known.add(sess.get_service_model(client).signing_name)
    bad = sorted(p for p in prefixes if p not in known)
    assert not bad, f"allowlist prefixes that IAM does not evaluate: {bad}"
    for client, prefix in _IAM_PREFIX_FOR_CLIENT.items():
        assert sess.get_service_model(client).signing_name == prefix


def test_f83_allowlist_uses_live_evaluated_action_names():
    denied = sorted(_LIVE_DENIED_FORMS & collectors.READ_ONLY_ACTIONS)
    assert not denied, f"allowlist carries names AWS denied live: {denied}"
    missing = sorted(_LIVE_EVALUATED_FORMS - collectors.READ_ONLY_ACTIONS)
    assert not missing, f"allowlist lacks the names AWS evaluates: {missing}"


# --- Stage 2 Bucket A collector tests (CNA, SVC, MLA) ------------------------


def test_cfn_drift_observed():
    sess = FakeSession({"cloudformation": FakeClient(responses={
        "list_stacks": {"StackSummaries": [
            {"StackStatus": "CREATE_COMPLETE", "DriftInformation": {"StackDriftStatus": "DRIFTED"}},
            {"StackStatus": "CREATE_COMPLETE", "DriftInformation": {"StackDriftStatus": "IN_SYNC"}},
            {"StackStatus": "DELETE_COMPLETE"},
        ]}})})
    fact = collectors.collect_cfn_drift(sess, "us-east-1")[0]
    assert fact["status"] == "OBSERVED"
    assert "1 drifted, 1 in sync of 2" in fact["detail"]


def test_cfn_drift_no_stacks():
    sess = FakeSession({"cloudformation": FakeClient(responses={
        "list_stacks": {"StackSummaries": []}})})
    assert collectors.collect_cfn_drift(sess, "us-east-1")[0]["status"] == "NO_STACKS"


def test_config_conformance_present_and_compliant():
    cfg = FakeClient(responses={
        "describe_conformance_packs": {"ConformancePackDetails": [
            {"ConformancePackName": "p1"}]},
        "get_conformance_pack_compliance_summary": {
            "ConformancePackComplianceSummaryList": [
                {"ConformancePackComplianceStatus": "COMPLIANT"}]},
    })
    by = facts_by_check(collectors.collect_config_conformance(
        FakeSession({"config": cfg}), "us-east-1"))
    assert by["conformance_packs"]["status"] == "PRESENT"
    assert "1 of 1" in by["conformance_compliance"]["detail"]


def test_config_conformance_none():
    sess = FakeSession({"config": FakeClient(responses={
        "describe_conformance_packs": {"ConformancePackDetails": []}})})
    assert collectors.collect_config_conformance(
        sess, "us-east-1")[0]["status"] == "NONE"


def test_waf_associated_count():
    waf = FakeClient(responses={
        "list_web_acls": {"WebACLs": [{"ARN": "a1"}, {"ARN": "a2"}]},
        "list_resources_for_web_acl": {"ResourceArns": ["r1"]},
    })
    fact = collectors.collect_waf(FakeSession({"wafv2": waf}), "us-east-1")[0]
    assert fact["status"] == "OBSERVED"
    assert "2 of 2" in fact["detail"]


def test_network_segmentation_open_ingress():
    ec2 = FakeClient(responses={
        "describe_security_groups": {"SecurityGroups": [
            {"IpPermissions": [{"IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]},
            {"IpPermissions": [{"IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]},
        ]},
        "describe_network_acls": {"NetworkAcls": [{}, {}]},
    })
    by = facts_by_check(collectors.collect_network_segmentation(
        FakeSession({"ec2": ec2}), "us-east-1"))
    assert "2 security group(s), 1 with an open" in by["security_groups"]["detail"]
    assert "2 network ACL(s)" in by["network_acls"]["detail"]


def test_cloudtrail_integrity_validation():
    ct = FakeClient(responses={"describe_trails": {"trailList": [
        {"LogFileValidationEnabled": True},
        {"LogFileValidationEnabled": False},
    ]}})
    fact = collectors.collect_cloudtrail_integrity(
        FakeSession({"cloudtrail": ct}), "us-east-1")[0]
    assert "1 of 2" in fact["detail"]


def test_ecr_integrity_immutable():
    ecr = FakeClient(responses={"describe_repositories": {"repositories": [
        {"imageTagMutability": "IMMUTABLE"},
        {"imageTagMutability": "MUTABLE"},
    ]}})
    fact = collectors.collect_ecr_integrity(
        FakeSession({"ecr": ecr}), "us-east-1")[0]
    assert "1 of 2" in fact["detail"]


def test_ecr_integrity_no_repos():
    sess = FakeSession({"ecr": FakeClient(responses={
        "describe_repositories": {"repositories": []}})})
    assert collectors.collect_ecr_integrity(
        sess, "us-east-1")[0]["status"] == "NO_REPOS"


def test_s3_data_protection_encryption():
    s3 = FakeClient(responses={
        "list_buckets": {"Buckets": [{"Name": "b1"}, {"Name": "b2"}]},
        "get_bucket_encryption": {"ServerSideEncryptionConfiguration": {
            "Rules": [{"ApplyServerSideEncryptionByDefault": {}}]}},
    })
    fact = collectors.collect_s3_data_protection(
        FakeSession({"s3": s3}), "us-east-1")[0]
    assert "2 of 2" in fact["detail"]


def test_f08_access_denied_is_unknown_not_negative():
    # F08: get_bucket_encryption denied on every bucket -> UNKNOWN, and NOT a
    # 0/N failing metric (an instrumentation gap must not become adverse
    # control telemetry).
    s3 = FakeClient(
        responses={"list_buckets": {"Buckets": [{"Name": "b1"}, {"Name": "b2"}]}},
        errors={"get_bucket_encryption": FakeClientError("AccessDenied")})
    fact = collectors.collect_s3_data_protection(
        FakeSession({"s3": s3}), "us-east-1")[0]
    assert fact["status"] == "UNKNOWN", fact
    # No measured/total ratio was emitted (would score in the metric tally).
    assert "measured" not in fact or fact.get("total", 0) == 0, fact


def test_f08_genuine_absence_counts_as_evaluated_negative():
    # A real ServerSideEncryptionConfigurationNotFoundError means the bucket has
    # no default encryption -> a legitimate negative (evaluated), so 0 of 1.
    s3 = FakeClient(
        responses={"list_buckets": {"Buckets": [{"Name": "b1"}]}},
        errors={"get_bucket_encryption": FakeClientError(
            "ServerSideEncryptionConfigurationNotFoundError")})
    fact = collectors.collect_s3_data_protection(
        FakeSession({"s3": s3}), "us-east-1")[0]
    assert fact["status"] == "OBSERVED" and fact.get("measured") == 0 \
        and fact.get("total") == 1, fact


def test_data_retention_lifecycle_and_ttl():
    s3 = FakeClient(responses={
        "list_buckets": {"Buckets": [{"Name": "b1"}]},
        "get_bucket_lifecycle_configuration": {"Rules": [{"ID": "expire"}]},
    })
    ddb = FakeClient(responses={
        "list_tables": {"TableNames": ["t1", "t2"]},
        "describe_time_to_live": {"TimeToLiveDescription": {"TimeToLiveStatus": "ENABLED"}},
    })
    by = facts_by_check(collectors.collect_data_retention(
        FakeSession({"s3": s3, "dynamodb": ddb}), "us-east-1"))
    assert "1 of 1" in by["lifecycle"]["detail"]
    assert "2 of 2" in by["ttl"]["detail"]


def test_siem_posture_enabled():
    ct = FakeClient(responses={"describe_trails": {"trailList": [
        {"IsMultiRegionTrail": True}]}})
    sh = FakeClient(responses={"describe_hub": {"HubArn": "arn"}})
    by = facts_by_check(collectors.collect_siem_posture(
        FakeSession({"cloudtrail": ct, "securityhub": sh}), "us-east-1"))
    assert by["siem_aggregation"]["status"] == "ENABLED"
    assert "1 trail(s), 1 multi-region" in by["siem_capture"]["detail"]


def test_siem_posture_securityhub_off():
    ct = FakeClient(responses={"describe_trails": {"trailList": []}})
    sh = FakeClient(errors={"describe_hub": FakeClientError("InvalidAccessException")})
    by = facts_by_check(collectors.collect_siem_posture(
        FakeSession({"cloudtrail": ct, "securityhub": sh}), "us-east-1"))
    assert by["siem_aggregation"]["status"] == "NOT_ENABLED"


# --- Stage 3 Bucket A collector tests (IAM, CMT, PIY, SCR, RPL) --------------


def test_iam_jit_sessions_and_keys():
    iam = FakeClient(responses={
        "list_roles": {"Roles": [
            {"MaxSessionDuration": 7200}, {"MaxSessionDuration": 3600}]},
        "list_users": {"Users": [{"UserName": "u1"}, {"UserName": "u2"}]},
        "list_access_keys": {"AccessKeyMetadata": [{"AccessKeyId": "AKIA"}]},
    })
    by = facts_by_check(collectors.collect_iam_jit(
        FakeSession({"iam": iam}), "us-east-1"))
    assert "1 of 2 role(s) allow a session longer" in by["role_session_duration"]["detail"]
    assert "2 of 2 user(s) have a long-lived" in by["long_lived_keys"]["detail"]


def test_iam_response_wiring():
    gd = FakeClient(responses={"list_detectors": {"DetectorIds": ["d1"]}})
    ev = FakeClient(responses={"list_rules": {"Rules": [
        {"State": "ENABLED"}, {"State": "DISABLED"}]}})
    by = facts_by_check(collectors.collect_iam_response_wiring(
        FakeSession({"guardduty": gd, "events": ev}), "us-east-1"))
    assert by["response_detector"]["status"] == "ENABLED"
    assert "1 of 2 EventBridge rule(s) enabled" in by["response_rules"]["detail"]


def test_pipeline_gates_present():
    cp = FakeClient(responses={
        "list_pipelines": {"pipelines": [{"name": "p1"}, {"name": "p2"}]},
        "get_pipeline": {"pipeline": {"stages": [
            {"name": "Source"}, {"name": "SecurityScan"}]}},
    })
    fact = collectors.collect_pipeline_gates(
        FakeSession({"codepipeline": cp}), "us-east-1")[0]
    assert fact["status"] == "OBSERVED"
    assert "2 of 2 pipeline(s) include" in fact["detail"]


def test_pipeline_gates_none():
    sess = FakeSession({"codepipeline": FakeClient(responses={
        "list_pipelines": {"pipelines": []}})})
    assert collectors.collect_pipeline_gates(
        sess, "us-east-1")[0]["status"] == "NONE"


def test_supply_chain_scanning_enabled():
    insp = FakeClient(responses={"batch_get_account_status": {"accounts": [
        {"resourceState": {"ecr": {"status": "ENABLED"},
                           "lambda": {"status": "DISABLED"}}}]}})
    fact = collectors.collect_supply_chain_scanning(
        FakeSession({"inspector2": insp}), "us-east-1")[0]
    assert fact["status"] == "ENABLED"
    assert "ECR" in fact["detail"] and "Lambda" not in fact["detail"]


def test_supply_chain_scanning_off():
    insp = FakeClient(responses={"batch_get_account_status": {"accounts": [
        {"resourceState": {"ecr": {"status": "DISABLED"},
                           "lambda": {"status": "DISABLED"}}}]}})
    assert collectors.collect_supply_chain_scanning(
        FakeSession({"inspector2": insp}), "us-east-1")[0]["status"] == "NOT_ENABLED"


def test_restore_testing_present():
    bk = FakeClient(responses={"list_restore_testing_plans": {
        "RestoreTestingPlans": [{"RestoreTestingPlanName": "rt1"}]}})
    fact = collectors.collect_restore_testing(
        FakeSession({"backup": bk}), "us-east-1")[0]
    assert fact["status"] == "PRESENT"


def test_restore_testing_none():
    bk = FakeClient(responses={"list_restore_testing_plans": {
        "RestoreTestingPlans": []}})
    assert collectors.collect_restore_testing(
        FakeSession({"backup": bk}), "us-east-1")[0]["status"] == "NONE"


def test_bucket_versioning_enabled():
    os.environ["SDR_STORE_BUCKET"] = "my-store"
    try:
        sess = FakeSession({"s3": FakeClient(responses={
            "get_bucket_versioning": {"Status": "Enabled"}})})
        fact = collectors.collect_bucket_versioning(sess, "us-east-1")[0]
        assert fact["status"] == "ENABLED"
        assert fact["check"] == "versioning"
    finally:
        del os.environ["SDR_STORE_BUCKET"]


def test_bucket_versioning_suspended():
    sess = FakeSession({"s3": FakeClient(responses={
        "get_bucket_versioning": {"Status": "Suspended"}})})
    fact = collectors.collect_bucket_versioning(sess, "us-east-1", bucket="b")[0]
    assert fact["status"] == "NOT_ENABLED"
    assert "Suspended" in fact["detail"]


def test_bucket_versioning_never_set():
    sess = FakeSession({"s3": FakeClient(responses={"get_bucket_versioning": {}})})
    fact = collectors.collect_bucket_versioning(sess, "us-east-1", bucket="b")[0]
    assert fact["status"] == "NOT_ENABLED"


def test_bucket_versioning_not_configured():
    os.environ.pop("SDR_STORE_BUCKET", None)
    sess = FakeSession({"s3": FakeClient()})
    fact = collectors.collect_bucket_versioning(sess, "us-east-1")[0]
    assert fact["status"] == "NOT_CONFIGURED"


def test_bucket_versioning_client_error():
    sess = FakeSession({"s3": FakeClient(
        errors={"get_bucket_versioning": FakeClientError("AccessDenied")})})
    fact = collectors.collect_bucket_versioning(sess, "us-east-1", bucket="b")[0]
    assert fact["status"].startswith("ERROR:")


# --- AUD-F15: every page is read; a truncated enumeration is never scored ----

class PagedFakeClient(FakeClient):
    """Like FakeClient, but a method named in `pages` returns successive
    responses on successive calls (the last page repeats), and a per-call
    error map may raise for a specific argument value (per-resource denial)."""
    def __init__(self, responses=None, errors=None, pages=None, arg_errors=None):
        super().__init__(responses, errors)
        self._pages = {k: list(v) for k, v in (pages or {}).items()}
        self._arg_errors = arg_errors or {}
        self.calls = []

    def __getattr__(self, name):
        def method(**kwargs):
            self.calls.append((name, dict(kwargs)))
            if name in self._errors:
                raise self._errors[name]
            for k, v in kwargs.items():
                if (name, k, v) in self._arg_errors:
                    raise self._arg_errors[(name, k, v)]
            if name in self._pages:
                pages = self._pages[name]
                return pages.pop(0) if len(pages) > 1 else pages[0]
            return self._responses.get(name, {})
        return method


def test_f15_kms_walks_every_page_of_keys():
    # Three keys across two pages (KMS pages with NextMarker/Truncated and takes
    # Marker). A first-page-only read would report 2 of 2; the truth is 3 of 3.
    kms = PagedFakeClient(
        pages={"list_keys": [
            {"Keys": [{"KeyId": "k1"}, {"KeyId": "k2"}], "NextMarker": "m1", "Truncated": True},
            {"Keys": [{"KeyId": "k3"}], "Truncated": False}]},
        responses={"get_key_rotation_status": {"KeyRotationEnabled": True}})
    fact = collectors.collect_kms(FakeSession({"kms": kms}), "us-east-1")[0]
    assert fact["status"] == "OBSERVED", fact
    assert fact["measured"] == 3 and fact["total"] == 3, fact
    assert fact["scope_total"] == 3 and fact["unknown_total"] == 0, fact
    # The second call carried the marker back as the request parameter KMS wants.
    assert any(c[0] == "list_keys" and c[1].get("Marker") == "m1" for c in kms.calls), kms.calls
    assert "partial" not in fact


def test_f15_runaway_pagination_is_partial_not_scored():
    # A client that always hands back a token (never terminates) hits the page
    # cap; the fact is OBSERVED_PARTIAL with no ratio and never scores.
    kms = FakeClient(responses={
        "list_keys": {"Keys": [{"KeyId": "k"}], "NextMarker": "again", "Truncated": True},
        "get_key_rotation_status": {"KeyRotationEnabled": True}})
    fact = collectors.collect_kms(FakeSession({"kms": kms}), "us-east-1")[0]
    assert fact["status"] == "OBSERVED_PARTIAL" and fact.get("partial") is True, fact
    assert "measured" not in fact, fact
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "metrics"))
    import append_metrics as _am
    assert _am._posture_score(fact) is None


def test_f15_ecr_and_cloudformation_read_all_pages():
    ecr = PagedFakeClient(pages={"describe_repositories": [
        {"repositories": [{"imageTagMutability": "IMMUTABLE"}], "nextToken": "n"},
        {"repositories": [{"imageTagMutability": "MUTABLE"}]}]})
    fact = collectors.collect_ecr_integrity(FakeSession({"ecr": ecr}), "us-east-1")[0]
    assert (fact["measured"], fact["total"]) == (1, 2), fact
    cf = PagedFakeClient(pages={"list_stacks": [
        {"StackSummaries": [{"StackStatus": "CREATE_COMPLETE",
                             "DriftInformation": {"StackDriftStatus": "IN_SYNC"}}],
         "NextToken": "n"},
        {"StackSummaries": [{"StackStatus": "CREATE_COMPLETE",
                             "DriftInformation": {"StackDriftStatus": "DRIFTED"}}]}]})
    fact = collectors.collect_cfn_drift(FakeSession({"cloudformation": cf}), "us-east-1")[0]
    assert (fact["measured"], fact["total"]) == (1, 2), fact


# --- AUD-F17: unreadable resources stay in scope as unknown, not vanish -----

def test_f17_kms_unreadable_key_is_unknown_not_dropped_from_scope():
    denied = FakeClientError("AccessDeniedException")
    kms = PagedFakeClient(
        responses={"list_keys": {"Keys": [{"KeyId": "k1"}, {"KeyId": "k2"}, {"KeyId": "k3"}]},
                   "get_key_rotation_status": {"KeyRotationEnabled": True}},
        arg_errors={("get_key_rotation_status", "KeyId", "k3"): denied})
    fact = collectors.collect_kms(FakeSession({"kms": kms}), "us-east-1")[0]
    assert fact["status"] == "OBSERVED"
    assert fact["measured"] == 2 and fact["total"] == 2, fact
    assert fact["scope_total"] == 3 and fact["evaluated_total"] == 2 \
        and fact["unknown_total"] == 1, fact


def test_f17_s3_public_access_denied_is_unknown_not_a_failure():
    # Before: any exception counted the bucket as evaluated-and-not-blocked, so
    # an AccessDenied read became adverse telemetry. Now only a confirmed
    # absent block is evaluated; denial is unknown.
    denied = FakeClientError("AccessDenied")
    absent = FakeClientError("NoSuchPublicAccessBlockConfiguration")
    s3 = PagedFakeClient(
        responses={"list_buckets": {"Buckets": [{"Name": "a"}, {"Name": "b"}, {"Name": "c"}]},
                   "get_public_access_block": {"PublicAccessBlockConfiguration": {
                       "BlockPublicAcls": True, "IgnorePublicAcls": True,
                       "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}},
        arg_errors={("get_public_access_block", "Bucket", "b"): denied,
                    ("get_public_access_block", "Bucket", "c"): absent})
    fact = collectors.collect_s3(FakeSession({"s3": s3}), "us-east-1")[0]
    # a blocked (evaluated), b unknown, c evaluated-not-blocked
    assert fact["measured"] == 1 and fact["total"] == 2, fact
    assert fact["scope_total"] == 3 and fact["unknown_total"] == 1, fact


def test_f17_all_reads_denied_is_unknown_not_a_pass():
    denied = FakeClientError("AccessDeniedException")
    kms = FakeClient(responses={"list_keys": {"Keys": [{"KeyId": "k1"}]}},
                     errors={"get_key_rotation_status": denied})
    fact = collectors.collect_kms(FakeSession({"kms": kms}), "us-east-1")[0]
    assert fact["status"] == "UNKNOWN" and "measured" not in fact, fact


def test_f16_access_analyzer_active_findings_is_the_scored_signal():
    sess = FakeSession({"accessanalyzer": FakeClient(responses={
        "list_analyzers": {"analyzers": [{"arn": "a1"}]},
        "list_findings": {"findings": [{"id": "f1"}]}})})
    by = facts_by_check(collectors.collect_access_analyzer(sess, "us-east-1"))
    assert by["analyzer"]["status"] == "PRESENT" and "measured" not in by["analyzer"]
    assert (by["active_findings"]["measured"], by["active_findings"]["total"]) == (0, 1)
    sess2 = FakeSession({"accessanalyzer": FakeClient(responses={
        "list_analyzers": {"analyzers": [{"arn": "a1"}]},
        "list_findings": {"findings": []}})})
    by2 = facts_by_check(collectors.collect_access_analyzer(sess2, "us-east-1"))
    assert (by2["active_findings"]["measured"], by2["active_findings"]["total"]) == (1, 1)


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = 0
    for t in tests:
        t()
        passed += 1
        print(f"PASS: {t.__name__}")
    print(f"\n{passed}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
