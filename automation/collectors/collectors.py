# Read-only AWS posture collectors (Layer 1, broadened).
#
# Each function queries ONE AWS service with read-only describe/list/get calls
# and returns a list of dated posture facts. Facts are telemetry, never
# statuses: nothing here decides that a control is Implemented. A fact records
# what a read-only API returned at a point in time, for a human (or a gated
# pipeline step) to interpret.
#
# Read-only by construction. The complete set of API actions this module may
# call is enumerated in READ_ONLY_ACTIONS below; the collector driver asserts
# every call it makes is in that set, and refuses admin-looking identities.
# Adding a service means adding its read-only actions to that set on purpose,
# which is a reviewable change rather than a silent permission widening.
#
# Every collector is written to be offline-testable: it takes a boto3-style
# session whose clients can be stubbed, catches client errors, and never
# raises out of a single service failure (one unreachable service must not
# sink a whole collection run).

from datetime import datetime, timezone

# The exhaustive read-only allowlist. If an action is not here, the driver
# refuses to run it. Keep this list in sync with the calls each collector makes.
READ_ONLY_ACTIONS = {
    "sts:GetCallerIdentity",
    "config:DescribeComplianceByConfigRule",
    "securityhub:GetFindings",
    "securityhub:DescribeHub",
    # AUD-F83: IAM evaluates Access Analyzer under the "access-analyzer" prefix
    # (botocore's signing name), not the boto3 client name "accessanalyzer".
    "access-analyzer:ListAnalyzers",
    "access-analyzer:ListFindings",
    "inspector2:ListCoverage",
    "inspector2:ListFindings",
    "guardduty:ListDetectors",
    "guardduty:GetDetector",
    "backup:ListBackupPlans",
    "backup:ListProtectedResources",
    "kms:ListKeys",
    "kms:GetKeyRotationStatus",
    # Config is the aggregator that absorbs breadth: it records the config
    # state of all supported resource types across every service in scope.
    "config:DescribeConfigurationRecorderStatus",
    "config:DescribeConfigurationRecorders",
    # AUD-F84: list the account's deployed rules once so a registry rule running
    # under a Security Hub or conformance-pack name is found, not reported as
    # RULE_NOT_DEPLOYED. Read verb; the first widening since the allowlist began.
    "config:DescribeConfigRules",
    "config:DescribeComplianceByConfigRule",
    "config:GetDiscoveredResourceCounts",
    # CloudTrail: account-wide audit capture across all services.
    "cloudtrail:DescribeTrails",
    "cloudtrail:GetTrailStatus",
    # S3: account-wide data-at-rest and public-access posture.
    "s3:ListAllMyBuckets",
    "s3:GetBucketPublicAccessBlock",
    # (AUD-F83: a former "s3control:GetPublicAccessBlock" entry granted an action
    # no collector calls, under a prefix IAM does not evaluate; removed.)
    # IAM: account-wide identity posture.
    "iam:GetAccountSummary",
    "iam:GetAccountPasswordPolicy",
    "iam:ListUsers",
    # Stage 2 Bucket A additions (CNA, SVC, MLA families): all read-only.
    "cloudformation:ListStacks",
    "cloudformation:DescribeStackResourceDrifts",
    "config:DescribeConformancePacks",
    "config:GetConformancePackComplianceSummary",
    "wafv2:ListWebACLs",
    "wafv2:ListResourcesForWebACL",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeNetworkAcls",
    "ecr:DescribeRepositories",
    # AUD-F83: the IAM action names differ from the API operation names
    # (GetBucketEncryption / GetBucketLifecycleConfiguration); these are the
    # names AWS evaluates, recorded from live AccessDenied messages.
    "s3:GetEncryptionConfiguration",
    "s3:GetLifecycleConfiguration",
    "dynamodb:ListTables",
    "dynamodb:DescribeTimeToLive",
    # Stage 3 Bucket A additions (IAM, CMT, PIY, SCR, RPL families): read-only.
    "iam:ListRoles",
    "iam:ListAccessKeys",
    "events:ListRules",
    "codepipeline:ListPipelines",
    "codepipeline:GetPipeline",
    "inspector2:BatchGetAccountStatus",
    "backup:ListRestoreTestingPlans",
    # Durable-store verification (read-side complement to provision_store.py).
    "s3:GetBucketVersioning",
}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fact(service, check, status, detail, region, measured=None, total=None,
          scope_total=None, unknown_total=None, partial=False):
    """Uniform posture-fact shape. status is a short machine token; detail is
    a human-readable, non-sensitive summary. Never include ARNs of principals,
    account IDs, or finding bodies that could carry sensitive specifics.

    measured/total (optional) carry the STRUCTURED ratio behind an OBSERVED
    fact: `measured` resources met the desirable condition out of `total`
    evaluated. The metric engine uses these to compute a real passing fraction;
    a bare OBSERVED with no measured/total is an observation, NOT a pass (an
    observation that something was measured is not the same as the measured
    thing being in good posture). For a count where MORE is worse (e.g. failed
    findings, drifted stacks), set measured to the GOOD count (total - bad) so
    the fraction still reads as "fraction in good posture".

    Coverage (AUD-F15 / AUD-F17). `total` is what was EVALUATED. It is not the
    same as what is IN SCOPE: a per-resource read can be denied or throttled,
    and a listing can be cut short. So a ratio fact also carries
      scope_total     resources the collector enumerated (the denominator that
                      matters to an assessor),
      evaluated_total the same value as `total`, named for what it is,
      unknown_total   scope_total - evaluated_total: enumerated but NOT
                      evaluated (read failed, so posture unknown), and
      partial         True when the enumeration itself was incomplete (page
                      cap hit), in which case status is OBSERVED_PARTIAL.
    The metric engine refuses to score a partial fact and refuses a fact whose
    evaluated coverage is below policy, so 10 readable of 50 in scope can never
    become a 100 percent pass, and 1 evaluated of 100 cannot either."""
    f = {
        "service": service,
        "check": check,
        "status": status,
        "detail": detail,
        "region": region,
        "collected_at": _now(),
    }
    if measured is not None and total is not None:
        f["measured"] = measured
        f["total"] = total
        f["evaluated_total"] = total
    if scope_total is not None:
        f["scope_total"] = scope_total
        evaluated = total if total is not None else 0
        f["unknown_total"] = (unknown_total if unknown_total is not None
                              else max(scope_total - evaluated, 0))
    if partial:
        f["partial"] = True
    return f


def _ratio_fact(service, check, region, good, evaluated, scope, partial,
                unit, condition):
    """Build the standard ratio fact for `good` of `evaluated` <unit>s that
    <condition>, out of `scope` enumerated, honestly labeled:
      - partial enumeration        -> OBSERVED_PARTIAL, NO ratio (never scored)
      - nothing evaluated          -> UNKNOWN (never scored; not a 0/0 pass)
      - otherwise                  -> OBSERVED with the ratio + coverage."""
    unknown = max(scope - evaluated, 0)
    if partial:
        return _fact(service, check, "OBSERVED_PARTIAL",
                     f"Enumeration incomplete (page cap); {good} of {evaluated} "
                     f"{unit}(s) {condition} among {scope}+ seen, {unknown} "
                     "unreadable. Bounded sample, not scorable.", region,
                     scope_total=scope, unknown_total=unknown, partial=True)
    if evaluated == 0:
        return _fact(service, check, "UNKNOWN",
                     f"Could not evaluate any of {scope} {unit}(s) "
                     f"({unknown} unreadable)", region)
    return _fact(service, check, "OBSERVED",
                 f"{good} of {evaluated} {unit}(s) {condition} "
                 f"({scope} in scope, {unknown} unreadable)", region,
                 measured=good, total=evaluated, scope_total=scope,
                 unknown_total=unknown)


# Pagination (AUD-F15). Every AWS list/describe call that can page is walked to
# the end. A botocore paginator is used when the client has one; otherwise the
# response's continuation token is followed by name. MAX_PAGES bounds a runaway
# (a fake or a service that never stops handing out tokens): hitting it marks
# the result PARTIAL, and a partial enumeration is never scored.
MAX_PAGES = 200

# (response token key, request parameter) pairs, in detection order. Ops whose
# response key does not name the request parameter pass token_in explicitly.
_TOKEN_PAIRS = (
    ("NextToken", "NextToken"),
    ("nextToken", "nextToken"),
    ("NextMarker", "NextMarker"),
    ("LastEvaluatedTableName", "ExclusiveStartTableName"),
    ("NextContinuationToken", "ContinuationToken"),
    ("ContinuationToken", "ContinuationToken"),
    ("Marker", "Marker"),
)


def _paginate(client, op, key, token_in=None, **kwargs):
    """Return (items, partial) for a paged list/describe operation.

    items is the concatenation of response[key] over every page; partial is True
    only when MAX_PAGES was reached with a continuation token still present.
    Raises whatever the client raises on the FIRST page (the caller labels the
    fact ERROR); a failure on a LATER page is reported as partial rather than
    discarding the pages already read, so the caller never scores it."""
    can = getattr(client, "can_paginate", None)
    has_paginator = False
    if callable(can):
        try:
            has_paginator = can(op) is True
        except Exception:  # noqa: BLE001 - a fake/stub client is not botocore
            has_paginator = False
    if has_paginator:
        items = []
        pages = 0
        for page in client.get_paginator(op).paginate(**kwargs):
            items.extend(page.get(key, []) or [])
            pages += 1
            if pages >= MAX_PAGES:
                return items, True
        return items, False
    method = getattr(client, op)
    items = []
    params = dict(kwargs)
    for _page in range(MAX_PAGES):
        resp = method(**params) or {}
        items.extend(resp.get(key, []) or [])
        token = None
        param = None
        if token_in:
            for out_key, _ in _TOKEN_PAIRS:
                if resp.get(out_key):
                    token, param = resp[out_key], token_in
                    break
        else:
            for out_key, in_key in _TOKEN_PAIRS:
                if resp.get(out_key):
                    token, param = resp[out_key], in_key
                    break
        # IAM-style: Marker is only valid while IsTruncated is true.
        if token is not None and param == "Marker" and resp.get("IsTruncated") is False:
            token = None
        if token is None:
            return items, False
        params[param] = token
    return items, True


def _client_error_name(exc):
    try:
        return exc.response.get("Error", {}).get("Code", type(exc).__name__)
    except AttributeError:
        return type(exc).__name__


def collect_security_hub(session, region):
    """Security Hub enablement and a count of active FAILED control findings.
    Records posture, not the findings themselves (those can carry specifics)."""
    facts = []
    try:
        sh = session.client("securityhub")
    except Exception as e:  # noqa: BLE001 - client construction can fail offline
        return [_fact("securityhub", "client", "ERROR", type(e).__name__, region)]
    try:
        sh.describe_hub()
        facts.append(_fact("securityhub", "enabled", "ENABLED",
                           "Security Hub is enabled in this region", region))
    except Exception as e:  # noqa: BLE001
        name = _client_error_name(e)
        if "InvalidAccess" in name or "ResourceNotFound" in name:
            facts.append(_fact("securityhub", "enabled", "NOT_ENABLED",
                               "Security Hub is not enabled in this region", region))
            return facts
        facts.append(_fact("securityhub", "enabled", f"ERROR:{name}",
                           "Could not determine Security Hub status", region))
        return facts
    try:
        resp = sh.get_findings(Filters={
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
        }, MaxResults=100)
        count = len(resp.get("Findings", []))
        more = "+" if resp.get("NextToken") else ""
        facts.append(_fact("securityhub", "failed_findings", "OBSERVED",
                           f"{count}{more} active failed control findings "
                           "(first page)", region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("securityhub", "failed_findings", f"ERROR:{_client_error_name(e)}",
                           "Could not read Security Hub findings", region))
    return facts


def collect_access_analyzer(session, region):
    """IAM Access Analyzer presence and count of active external-access
    findings. Counts only; finding detail can name resources."""
    facts = []
    try:
        aa = session.client("accessanalyzer")
    except Exception as e:  # noqa: BLE001
        return [_fact("accessanalyzer", "client", "ERROR", type(e).__name__, region)]
    try:
        analyzers, _ = _paginate(aa, "list_analyzers", "analyzers", type="ACCOUNT")
    except Exception as e:  # noqa: BLE001
        return [_fact("accessanalyzer", "analyzer", f"ERROR:{_client_error_name(e)}",
                      "Could not list Access Analyzers", region)]
    if not analyzers:
        return [_fact("accessanalyzer", "analyzer", "NONE",
                      "No IAM Access Analyzer configured in this region", region)]
    facts.append(_fact("accessanalyzer", "analyzer", "PRESENT",
                       f"{len(analyzers)} analyzer(s) configured", region))
    arn = analyzers[0].get("arn")
    try:
        findings, more = _paginate(
            aa, "list_findings", "findings",
            analyzerArn=arn, filter={"status": {"eq": ["ACTIVE"]}})
        active = len(findings)
        if more:
            facts.append(_fact("accessanalyzer", "active_findings", "OBSERVED_PARTIAL",
                               f"{active}+ active finding(s) on first analyzer; "
                               "enumeration incomplete, not scorable", region,
                               partial=True))
        else:
            # AUD-F16: the least-privilege signal is the ABSENCE of active
            # findings, scored as a binary (1 of 1 when none remain). Analyzer
            # PRESENCE above is deliberately not a metric; a KSI routes
            # accessanalyzer:active_findings, never the whole service.
            facts.append(_fact("accessanalyzer", "active_findings", "OBSERVED",
                               f"{active} active finding(s) on first analyzer "
                               "(all pages)", region,
                               measured=1 if active == 0 else 0, total=1))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("accessanalyzer", "active_findings",
                           f"ERROR:{_client_error_name(e)}",
                           "Could not list Access Analyzer findings", region))
    return facts


def collect_inspector(session, region):
    """Amazon Inspector coverage: is anything actively scanned."""
    try:
        insp = session.client("inspector2")
    except Exception as e:  # noqa: BLE001
        return [_fact("inspector2", "client", "ERROR", type(e).__name__, region)]
    try:
        cov, more = _paginate(insp, "list_coverage", "coveredResources", maxResults=100)
        active = sum(1 for c in cov if c.get("scanStatus", {}).get("statusCode") == "ACTIVE")
        # F09: preserve the ACTUAL coverage fraction, not a binary ACTIVE that
        # the scorer would turn into 1/1. 1 active of 100 covered must score
        # 1/100, not 100%. AUD-F15: every page is now read; `more` is True
        # only when the page cap was hit with resources still unexamined, and
        # that bounded sample is marked partial so it is NOT indistinguishable
        # from complete boundary coverage.
        if not cov:
            return [_fact("inspector2", "coverage", "NO_COVERAGE",
                          "No covered resources returned", region)]
        if more:
            # Bounded sample: report the enabling signal WITHOUT a full-coverage
            # ratio (partial). It is telemetry that scanning is on for the
            # sampled resources, not a boundary-wide passing measure.
            return [_fact("inspector2", "coverage", "OBSERVED_PARTIAL",
                          f"{active} of {len(cov)} sampled resources actively "
                          "scanned; more resources exist (bounded sample, "
                          "boundary coverage not measured)", region, partial=True)]
        return [_fact("inspector2", "coverage", "OBSERVED",
                      f"{active} of {len(cov)} covered resources actively scanned",
                      region, measured=active, total=len(cov), scope_total=len(cov))]
    except Exception as e:  # noqa: BLE001
        return [_fact("inspector2", "coverage", f"ERROR:{_client_error_name(e)}",
                      "Could not read Inspector coverage", region)]


def collect_guardduty(session, region):
    """GuardDuty: is a detector present and enabled in this region."""
    try:
        gd = session.client("guardduty")
    except Exception as e:  # noqa: BLE001
        return [_fact("guardduty", "client", "ERROR", type(e).__name__, region)]
    try:
        ids, _ = _paginate(gd, "list_detectors", "DetectorIds")
    except Exception as e:  # noqa: BLE001
        return [_fact("guardduty", "detector", f"ERROR:{_client_error_name(e)}",
                      "Could not list GuardDuty detectors", region)]
    if not ids:
        return [_fact("guardduty", "detector", "NONE",
                      "No GuardDuty detector in this region", region)]
    try:
        det = gd.get_detector(DetectorId=ids[0])
        status = det.get("Status", "UNKNOWN")
        return [_fact("guardduty", "detector",
                      "ENABLED" if status == "ENABLED" else status,
                      f"Detector status {status}", region)]
    except Exception as e:  # noqa: BLE001
        return [_fact("guardduty", "detector", f"ERROR:{_client_error_name(e)}",
                      "Could not read GuardDuty detector", region)]


def collect_backup(session, region):
    """AWS Backup: are backup plans defined and protecting resources."""
    try:
        bk = session.client("backup")
    except Exception as e:  # noqa: BLE001
        return [_fact("backup", "client", "ERROR", type(e).__name__, region)]
    facts = []
    try:
        plans, _ = _paginate(bk, "list_backup_plans", "BackupPlansList")
        facts.append(_fact("backup", "plans",
                           "PRESENT" if plans else "NONE",
                           f"{len(plans)} backup plan(s)", region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("backup", "plans", f"ERROR:{_client_error_name(e)}",
                           "Could not list backup plans", region))
    try:
        protected, more = _paginate(bk, "list_protected_resources", "Results")
        facts.append(_fact("backup", "protected_resources",
                           "OBSERVED_PARTIAL" if more else "OBSERVED",
                           f"{len(protected)}{'+' if more else ''} protected "
                           "resource(s)", region, partial=more))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("backup", "protected_resources",
                           f"ERROR:{_client_error_name(e)}",
                           "Could not list protected resources", region))
    return facts


def collect_kms(session, region):
    """KMS: fraction of customer keys with automatic rotation enabled.
    Reports an aggregate, not individual key identifiers. Walks every page of
    keys (AUD-F15) and counts keys whose rotation status could not be read as
    unknown, not as evaluated (AUD-F17)."""
    try:
        kms = session.client("kms")
    except Exception as e:  # noqa: BLE001
        return [_fact("kms", "client", "ERROR", type(e).__name__, region)]
    try:
        # KMS returns NextMarker/Truncated and takes Marker on the request.
        keys, more = _paginate(kms, "list_keys", "Keys", token_in="Marker", Limit=1000)
    except Exception as e:  # noqa: BLE001
        return [_fact("kms", "keys", f"ERROR:{_client_error_name(e)}",
                      "Could not list KMS keys", region)]
    if not keys:
        return [_fact("kms", "key_rotation", "NO_KEYS",
                      "No KMS keys in this region", region)]
    rotating = 0
    checked = 0
    for k in keys:
        try:
            r = kms.get_key_rotation_status(KeyId=k["KeyId"])
            checked += 1
            if r.get("KeyRotationEnabled"):
                rotating += 1
        except Exception:  # noqa: BLE001 - AWS-managed keys reject this call; unknown
            continue
    return [_ratio_fact("kms", "key_rotation", region, rotating, checked, len(keys),
                        more, "customer key", "have automatic rotation enabled")]


def collect_config(session, region):
    """AWS Config: the breadth aggregator. Reports whether the configuration
    recorder is on, how many resources it has discovered (the 400-service
    breadth collapsed into one count), and the compliance tally across rules.
    A count and aggregate posture, never per-resource detail."""
    try:
        cfg = session.client("config")
    except Exception as e:  # noqa: BLE001
        return [_fact("config", "client", "ERROR", type(e).__name__, region)]
    facts = []
    # 1. Is the recorder running? Without it, breadth coverage is zero.
    try:
        statuses = cfg.describe_configuration_recorder_status().get(
            "ConfigurationRecordersStatus", [])
        recording = sum(1 for s in statuses if s.get("recording"))
        if not statuses:
            facts.append(_fact("config", "recorder", "NONE",
                               "No Config recorder in this region", region))
        else:
            facts.append(_fact("config", "recorder",
                               "RECORDING" if recording else "STOPPED",
                               f"{recording} of {len(statuses)} recorder(s) recording",
                               region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("config", "recorder", f"ERROR:{_client_error_name(e)}",
                           "Could not read Config recorder status", region))
    # 2. How many resources has Config discovered? This is the 400-service
    #    breadth expressed as one number: every recorded resource, all services.
    try:
        counts, _ = _paginate(cfg, "get_discovered_resource_counts", "resourceCounts")
        total = sum(c.get("count", 0) for c in counts)
        facts.append(_fact("config", "discovered_resources", "OBSERVED",
                           f"{total} resources across {len(counts)} resource "
                           "type(s) recorded", region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("config", "discovered_resources",
                           f"ERROR:{_client_error_name(e)}",
                           "Could not read discovered resource counts", region))
    # 3. Rule compliance tally (aggregate, not per-rule bodies). Every page
    #    (AUD-F15); evaluated = rules with a definite COMPLIANT/NON_COMPLIANT,
    #    INSUFFICIENT_DATA/NOT_APPLICABLE are in scope but unknown.
    try:
        rules, more = _paginate(cfg, "describe_compliance_by_config_rule",
                                "ComplianceByConfigRules")
        compliant = sum(1 for r in rules
                        if r.get("Compliance", {}).get("ComplianceType") == "COMPLIANT")
        noncompliant = sum(1 for r in rules
                           if r.get("Compliance", {}).get("ComplianceType") == "NON_COMPLIANT")
        if not rules:
            facts.append(_fact("config", "rule_compliance", "NONE",
                               "No Config rules evaluated in this region", region))
        else:
            facts.append(_ratio_fact("config", "rule_compliance", region, compliant,
                                     compliant + noncompliant, len(rules), more,
                                     "rule", "report COMPLIANT"))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("config", "rule_compliance",
                           f"ERROR:{_client_error_name(e)}",
                           "Could not read Config rule compliance", region))
    return facts


def collect_cloudtrail(session, region):
    """AWS CloudTrail: account-wide audit capture. Reports whether a
    multi-region trail exists and is logging. One trail covers all services."""
    try:
        ct = session.client("cloudtrail")
    except Exception as e:  # noqa: BLE001
        return [_fact("cloudtrail", "client", "ERROR", type(e).__name__, region)]
    try:
        trails = ct.describe_trails().get("trailList", [])
    except Exception as e:  # noqa: BLE001
        return [_fact("cloudtrail", "trails", f"ERROR:{_client_error_name(e)}",
                      "Could not describe CloudTrail trails", region)]
    if not trails:
        return [_fact("cloudtrail", "trails", "NONE",
                      "No CloudTrail trails visible in this region", region)]
    multiregion = sum(1 for t in trails if t.get("IsMultiRegionTrail"))
    logging_on = 0
    checked = 0
    for t in trails:
        try:
            st = ct.get_trail_status(Name=t.get("TrailARN") or t.get("Name"))
            checked += 1
            if st.get("IsLogging"):
                logging_on += 1
        except Exception:  # noqa: BLE001 - status of one trail must not sink the rest
            continue
    return [_fact("cloudtrail", "trails", "OBSERVED",
                  f"{len(trails)} trail(s), {multiregion} multi-region, "
                  f"{logging_on} of {checked} readable actively logging "
                  f"({len(trails) - checked} status unreadable)", region,
                  measured=logging_on, total=checked, scope_total=len(trails))
            if checked else
            _fact("cloudtrail", "trails", "UNKNOWN",
                  f"{len(trails)} trail(s); no trail status readable", region)]


def collect_s3(session, region):
    """Amazon S3: account-wide data-at-rest surface. Reports bucket count and
    how many have account-level or bucket-level public access blocked. An
    aggregate posture across all buckets, not per-bucket detail."""
    try:
        s3 = session.client("s3")
    except Exception as e:  # noqa: BLE001
        return [_fact("s3", "client", "ERROR", type(e).__name__, region)]
    try:
        buckets, more = _paginate(s3, "list_buckets", "Buckets")
    except Exception as e:  # noqa: BLE001
        return [_fact("s3", "buckets", f"ERROR:{_client_error_name(e)}",
                      "Could not list S3 buckets", region)]
    if not buckets:
        return [_fact("s3", "buckets", "NONE", "No S3 buckets in this account", region)]
    blocked = 0
    checked = 0
    for b in buckets:
        try:
            pab = s3.get_public_access_block(Bucket=b["Name"]).get(
                "PublicAccessBlockConfiguration", {})
            checked += 1
            if all(pab.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls",
                                        "BlockPublicPolicy", "RestrictPublicBuckets")):
                blocked += 1
        except Exception as e:  # noqa: BLE001 - one bucket's read must not sink the run
            # AUD-F17: only a response that ESTABLISHES absence is evaluated.
            # NoSuchPublicAccessBlockConfiguration means the bucket genuinely has
            # no block (evaluated, not blocked). AccessDenied / throttling means
            # the posture is UNKNOWN, and an unknown must not sit in the
            # denominator as a failure nor vanish from scope.
            if "NoSuchPublicAccessBlockConfiguration" in _client_error_name(e):
                checked += 1
            continue
    return [_ratio_fact("s3", "public_access_block", region, blocked, checked,
                        len(buckets), more, "bucket", "fully block public access")]


def collect_iam(session, region):
    """IAM: account-wide identity posture. Reports MFA/password-policy and the
    account summary tallies. IAM is global; region is recorded for provenance."""
    try:
        iam = session.client("iam")
    except Exception as e:  # noqa: BLE001
        return [_fact("iam", "client", "ERROR", type(e).__name__, region)]
    facts = []
    try:
        summary = iam.get_account_summary().get("SummaryMap", {})
        users = summary.get("Users", 0)
        mfa_devices = summary.get("MFADevices", 0)
        facts.append(_fact("iam", "account_summary", "OBSERVED",
                           f"{users} users, {mfa_devices} MFA device(s), "
                           f"{summary.get('Roles', 0)} roles", region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("iam", "account_summary",
                           f"ERROR:{_client_error_name(e)}",
                           "Could not read IAM account summary", region))
    try:
        iam.get_account_password_policy()
        facts.append(_fact("iam", "password_policy", "PRESENT",
                           "Account password policy is set", region))
    except Exception as e:  # noqa: BLE001
        name = _client_error_name(e)
        if "NoSuchEntity" in name:
            facts.append(_fact("iam", "password_policy", "NONE",
                               "No account password policy set", region))
        else:
            facts.append(_fact("iam", "password_policy", f"ERROR:{name}",
                               "Could not read account password policy", region))
    return facts


# Ordered so a driver can iterate. Each entry: (name, function).
# --- Bucket A collectors (Stage 2: CNA, SVC, MLA families) -------------------
# Each reads genuine AWS state read-only and emits posture facts. They map to
# the pending KSIs classified in pending-ksi-classification.json (bucket_a).


def collect_cfn_drift(session, region):
    """AWS CloudFormation drift posture. Reports how many stacks report drift
    against their template (the 'enforcing intended state' signal). Aggregate
    counts only, never stack contents. Maps: CNA-EIS, SVC-ACM, CMT-RMV."""
    try:
        cf = session.client("cloudformation")
    except Exception as e:  # noqa: BLE001
        return [_fact("cloudformation", "client", "ERROR", type(e).__name__, region)]
    try:
        stacks, more = _paginate(cf, "list_stacks", "StackSummaries")
    except Exception as e:  # noqa: BLE001
        return [_fact("cloudformation", "stacks", f"ERROR:{_client_error_name(e)}",
                      "Could not list CloudFormation stacks", region)]
    active = [s for s in stacks if s.get("StackStatus") != "DELETE_COMPLETE"]
    if not active:
        return [_fact("cloudformation", "drift", "NO_STACKS",
                      "No active CloudFormation stacks in this region", region)]
    drifted = sum(1 for s in active
                  if s.get("DriftInformation", {}).get("StackDriftStatus") == "DRIFTED")
    in_sync = sum(1 for s in active
                  if s.get("DriftInformation", {}).get("StackDriftStatus") == "IN_SYNC")
    # AUD-F17: a stack whose drift status is NOT_CHECKED/UNKNOWN is in scope but
    # not evaluated; it must not count as in sync nor vanish from the scope.
    fact = _ratio_fact("cloudformation", "drift", region, in_sync, drifted + in_sync,
                       len(active), more, "active stack", "in sync (not drifted)")
    if fact["status"] == "OBSERVED":
        fact["detail"] = (f"{drifted} drifted, {in_sync} in sync of {len(active)} "
                          f"active stack(s) ({len(active) - drifted - in_sync} "
                          "drift status not checked)")
    return [fact]


def collect_config_conformance(session, region):
    """AWS Config conformance packs: codified best-practice / baseline rule
    sets and their compliance. Maps: CNA-IBP, MLA-EVC, SVC-EIS."""
    try:
        cfg = session.client("config")
    except Exception as e:  # noqa: BLE001
        return [_fact("config", "conformance_client", "ERROR", type(e).__name__, region)]
    try:
        packs, more = _paginate(cfg, "describe_conformance_packs", "ConformancePackDetails")
    except Exception as e:  # noqa: BLE001
        return [_fact("config", "conformance_packs", f"ERROR:{_client_error_name(e)}",
                      "Could not describe conformance packs", region)]
    if not packs:
        return [_fact("config", "conformance_packs", "NONE",
                      "No Config conformance packs in this region", region)]
    facts = [_fact("config", "conformance_packs", "PRESENT",
                   f"{len(packs)} conformance pack(s)", region)]
    compliant = 0
    checked = 0
    for p in packs:
        try:
            s = cfg.get_conformance_pack_compliance_summary(
                ConformancePackNames=[p["ConformancePackName"]])
            checked += 1
            summaries = s.get("ConformancePackComplianceSummaryList", [])
            if summaries and summaries[0].get("ConformancePackComplianceStatus") == "COMPLIANT":
                compliant += 1
        except Exception:  # noqa: BLE001 - one pack's summary must not sink the run
            continue
    facts.append(_ratio_fact("config", "conformance_compliance", region, compliant,
                             checked, len(packs), more, "pack", "reporting COMPLIANT"))
    return facts


def collect_waf(session, region):
    """AWS WAFv2 web ACLs and how many are associated with a resource
    (ALB / CloudFront). The 'reviewing protections' signal. Maps: CNA-RVP."""
    try:
        waf = session.client("wafv2")
    except Exception as e:  # noqa: BLE001
        return [_fact("wafv2", "client", "ERROR", type(e).__name__, region)]
    try:
        # WAFv2 has no botocore paginator; it pages with NextMarker in and out.
        acls, more = _paginate(waf, "list_web_acls", "WebACLs", token_in="NextMarker",
                               Scope="REGIONAL")
    except Exception as e:  # noqa: BLE001
        return [_fact("wafv2", "web_acls", f"ERROR:{_client_error_name(e)}",
                      "Could not list WAF web ACLs", region)]
    if not acls:
        return [_fact("wafv2", "web_acls", "NONE",
                      "No regional WAF web ACLs in this region", region)]
    associated = 0
    checked = 0
    for a in acls:
        try:
            res = waf.list_resources_for_web_acl(WebACLArn=a["ARN"]).get(
                "ResourceArns", [])
            checked += 1
            if res:
                associated += 1
        except Exception:  # noqa: BLE001
            continue
    return [_ratio_fact("wafv2", "web_acls", region, associated, checked, len(acls),
                        more, "web ACL", "associated with a resource")]


def collect_network_segmentation(session, region):
    """EC2 security groups and network ACLs: the logical-segmentation signal.
    Reports counts and how many SGs allow unrestricted (0.0.0.0/0) inbound.
    Aggregate posture, no rule bodies. Maps: CNA-ULN."""
    try:
        ec2 = session.client("ec2")
    except Exception as e:  # noqa: BLE001
        return [_fact("ec2", "client", "ERROR", type(e).__name__, region)]
    facts = []
    try:
        sgs, more = _paginate(ec2, "describe_security_groups", "SecurityGroups")
        open_ingress = 0
        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                if any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])):
                    open_ingress += 1
                    break
        fact = _ratio_fact("ec2", "security_groups", region, len(sgs) - open_ingress,
                           len(sgs), len(sgs), more, "security group",
                           "without an open (0.0.0.0/0) inbound rule")
        if fact["status"] == "OBSERVED":
            fact["detail"] = (f"{len(sgs)} security group(s), {open_ingress} with "
                              "an open (0.0.0.0/0) inbound rule")
        facts.append(fact)
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("ec2", "security_groups", f"ERROR:{_client_error_name(e)}",
                           "Could not describe security groups", region))
    try:
        acls, _ = _paginate(ec2, "describe_network_acls", "NetworkAcls")
        facts.append(_fact("ec2", "network_acls", "OBSERVED",
                           f"{len(acls)} network ACL(s)", region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("ec2", "network_acls", f"ERROR:{_client_error_name(e)}",
                           "Could not describe network ACLs", region))
    return facts


def collect_cloudtrail_integrity(session, region):
    """CloudTrail log-file validation: the resource-integrity signal. Reports
    how many trails have log-file validation enabled. Maps: SVC-VRI (with
    collect_ecr_integrity)."""
    try:
        ct = session.client("cloudtrail")
    except Exception as e:  # noqa: BLE001
        return [_fact("cloudtrail", "log_validation_client", "ERROR",
                      type(e).__name__, region)]
    try:
        trails = ct.describe_trails().get("trailList", [])
    except Exception as e:  # noqa: BLE001
        return [_fact("cloudtrail", "log_validation", f"ERROR:{_client_error_name(e)}",
                      "Could not describe trails for log validation", region)]
    if not trails:
        return [_fact("cloudtrail", "log_validation", "NONE",
                      "No CloudTrail trails visible in this region", region)]
    validated = sum(1 for t in trails if t.get("LogFileValidationEnabled"))
    return [_fact("cloudtrail", "log_validation", "OBSERVED",
                  f"{validated} of {len(trails)} trail(s) have log-file "
                  "validation enabled", region, measured=validated, total=len(trails),
                  scope_total=len(trails))]


def collect_ecr_integrity(session, region):
    """Amazon ECR image-tag immutability: the resource-integrity signal for
    container images. Reports how many repositories enforce immutable tags.
    Maps: SVC-VRI (with collect_cloudtrail_integrity)."""
    try:
        ecr = session.client("ecr")
    except Exception as e:  # noqa: BLE001
        return [_fact("ecr", "client", "ERROR", type(e).__name__, region)]
    try:
        repos, more = _paginate(ecr, "describe_repositories", "repositories")
    except Exception as e:  # noqa: BLE001
        return [_fact("ecr", "repositories", f"ERROR:{_client_error_name(e)}",
                      "Could not describe ECR repositories", region)]
    if not repos:
        return [_fact("ecr", "image_immutability", "NO_REPOS",
                      "No ECR repositories in this region", region)]
    immutable = sum(1 for r in repos
                    if r.get("imageTagMutability") == "IMMUTABLE")
    fact = _ratio_fact("ecr", "image_immutability", region, immutable, len(repos),
                       len(repos), more, "repository", "enforce immutable image tags")
    if fact["status"] == "OBSERVED":
        fact["detail"] = (f"{immutable} of {len(repos)} repositor(y/ies) enforce "
                          "immutable image tags")
    return [fact]


def collect_s3_data_protection(session, region):
    """Amazon S3 encryption and public-access posture across buckets: the
    residual-risk / prevent-exposure signal. Aggregate counts, no bucket
    identifiers. Maps: SVC-PRR."""
    try:
        s3 = session.client("s3")
    except Exception as e:  # noqa: BLE001
        return [_fact("s3", "data_protection_client", "ERROR", type(e).__name__, region)]
    try:
        buckets, more = _paginate(s3, "list_buckets", "Buckets")
    except Exception as e:  # noqa: BLE001
        return [_fact("s3", "encryption", f"ERROR:{_client_error_name(e)}",
                      "Could not list S3 buckets", region)]
    if not buckets:
        return [_fact("s3", "encryption", "NONE", "No S3 buckets in this account", region)]
    encrypted = 0
    checked = 0
    unmeasured = 0
    for b in buckets:
        try:
            enc = s3.get_bucket_encryption(Bucket=b["Name"])
            checked += 1
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                encrypted += 1
        except Exception as e:  # noqa: BLE001 - one bucket read must not sink the run
            # F08: only a response that ESTABLISHES ABSENCE is a real negative.
            # ServerSideEncryptionConfigurationNotFoundError means the bucket
            # genuinely has no default encryption -> counts as evaluated (not
            # encrypted). AccessDenied / throttling / any other error means we
            # could NOT measure this bucket -> it is unmeasured, and must NOT be
            # scored as a failure (that would turn an instrumentation gap into
            # adverse control telemetry, contradicting the read-only trust
            # boundary).
            name = _client_error_name(e)
            if "ServerSideEncryptionConfigurationNotFound" in name:
                checked += 1  # evaluated: no encryption configured
            else:
                unmeasured += 1
            continue
    if more:
        return [_fact("s3", "encryption", "OBSERVED_PARTIAL",
                      f"Bucket enumeration incomplete; {encrypted} of {checked} "
                      "evaluated bucket(s) encrypted. Not scorable.", region,
                      scope_total=len(buckets), unknown_total=unmeasured, partial=True)]
    if checked == 0:
        # Nothing could be evaluated (e.g. all reads denied): report UNKNOWN, not
        # a 0/0 or a false pass/fail.
        return [_fact("s3", "encryption", "UNKNOWN",
                      f"Could not evaluate encryption on any of {len(buckets)} "
                      f"bucket(s) ({unmeasured} unmeasured)", region)]
    # AUD-F17: scope_total/unknown_total let the metric engine refuse a
    # confident pass built on 1 readable bucket of 100 (coverage policy).
    return [_fact("s3", "encryption", "OBSERVED",
                  f"{encrypted} of {checked} bucket(s) have default encryption "
                  f"configured ({len(buckets)} total, {unmeasured} unmeasured)",
                  region, measured=encrypted, total=checked,
                  scope_total=len(buckets), unknown_total=unmeasured)]


def collect_data_retention(session, region):
    """Data-retention posture: S3 lifecycle rules, DynamoDB TTL, and backup
    plans. The 'removing unwanted data' signal. Maps: SVC-RUD."""
    facts = []
    try:
        s3 = session.client("s3")
        buckets, more = _paginate(s3, "list_buckets", "Buckets")
        with_lifecycle = 0
        checked = 0
        for b in buckets:
            try:
                lc = s3.get_bucket_lifecycle_configuration(Bucket=b["Name"])
                checked += 1
                if lc.get("Rules"):
                    with_lifecycle += 1
            except Exception as e:  # noqa: BLE001 - NoSuchLifecycleConfiguration is normal
                # AUD-F17: NoSuchLifecycleConfiguration ESTABLISHES absence
                # (evaluated, no policy); any other error is unknown posture.
                if "NoSuchLifecycleConfiguration" in _client_error_name(e):
                    checked += 1
                continue
        if buckets:
            facts.append(_ratio_fact("s3", "lifecycle", region, with_lifecycle, checked,
                                     len(buckets), more, "bucket",
                                     "have a lifecycle policy"))
        else:
            facts.append(_fact("s3", "lifecycle", "NONE", "No S3 buckets in this account",
                               region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("s3", "lifecycle", f"ERROR:{_client_error_name(e)}",
                           "Could not read S3 lifecycle posture", region))
    try:
        ddb = session.client("dynamodb")
        tables, more = _paginate(ddb, "list_tables", "TableNames")
        ttl_on = 0
        checked = 0
        for t in tables:
            try:
                d = ddb.describe_time_to_live(TableName=t)
                checked += 1
                if d.get("TimeToLiveDescription", {}).get(
                        "TimeToLiveStatus") == "ENABLED":
                    ttl_on += 1
            except Exception:  # noqa: BLE001
                continue
        if tables:
            facts.append(_ratio_fact("dynamodb", "ttl", region, ttl_on, checked,
                                     len(tables), more, "table", "have TTL enabled"))
        else:
            facts.append(_fact("dynamodb", "ttl", "NONE", "No DynamoDB tables in this region",
                               region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("dynamodb", "ttl", f"ERROR:{_client_error_name(e)}",
                           "Could not read DynamoDB TTL posture", region))
    return facts


def collect_siem_posture(session, region):
    """Centralized-logging / SIEM posture: CloudTrail on, and Security Hub
    enabled (the aggregation point). The 'operating SIEM capability' signal.
    Maps: MLA-OSM."""
    facts = []
    try:
        ct = session.client("cloudtrail")
        trails = ct.describe_trails().get("trailList", [])
        multiregion = [t for t in trails if t.get("IsMultiRegionTrail")]
        # AUD-F18: this route feeds KSI-MLA-OSM, so it must carry a scorable
        # measure or prefill would declare a method that can never bind. The
        # SIEM-capture signal is binary: at least one multi-region trail is
        # actively logging (1 of 1), else 0 of 1. Status reads that fail leave
        # the trail out of the count (unknown), never counted as logging.
        capturing = 0
        for t in multiregion:
            try:
                st = ct.get_trail_status(Name=t.get("TrailARN") or t.get("Name"))
                if st.get("IsLogging"):
                    capturing += 1
            except Exception:  # noqa: BLE001 - unknown status is not "logging"
                continue
        if not trails:
            facts.append(_fact("cloudtrail", "siem_capture", "NONE",
                               "No CloudTrail trails visible in this region", region))
        else:
            facts.append(_fact("cloudtrail", "siem_capture", "OBSERVED",
                               f"{len(trails)} trail(s), {len(multiregion)} multi-region, "
                               f"{capturing} multi-region actively logging", region,
                               measured=1 if capturing else 0, total=1))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("cloudtrail", "siem_capture",
                           f"ERROR:{_client_error_name(e)}",
                           "Could not read CloudTrail for SIEM posture", region))
    try:
        sh = session.client("securityhub")
        sh.describe_hub()
        facts.append(_fact("securityhub", "siem_aggregation", "ENABLED",
                           "Security Hub is enabled as the aggregation point",
                           region))
    except Exception as e:  # noqa: BLE001
        name = _client_error_name(e)
        if "InvalidAccess" in name or "ResourceNotFound" in name:
            facts.append(_fact("securityhub", "siem_aggregation", "NOT_ENABLED",
                               "Security Hub is not enabled in this region", region))
        else:
            facts.append(_fact("securityhub", "siem_aggregation", f"ERROR:{name}",
                               "Could not determine Security Hub status", region))
    return facts


def collect_iam_jit(session, region):
    """Just-in-time access posture: role max-session durations and whether
    long-lived access keys exist. The 'authorizing just-in-time' signal.
    Aggregate counts, no principal ARNs. Maps: IAM-JIT."""
    try:
        iam = session.client("iam")
    except Exception as e:  # noqa: BLE001
        return [_fact("iam", "jit_client", "ERROR", type(e).__name__, region)]
    facts = []
    try:
        roles, more = _paginate(iam, "list_roles", "Roles")
        long_session = sum(1 for r in roles
                           if (r.get("MaxSessionDuration") or 3600) > 3600)
        if roles:
            fact = _ratio_fact("iam", "role_session_duration", region,
                               len(roles) - long_session, len(roles), len(roles), more,
                               "role", "cap sessions at 1 hour")
            if fact["status"] == "OBSERVED":
                fact["detail"] = (f"{long_session} of {len(roles)} role(s) allow a "
                                  "session longer than 1 hour")
            facts.append(fact)
        else:
            facts.append(_fact("iam", "role_session_duration", "NONE",
                               "No IAM roles", region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("iam", "role_session_duration",
                           f"ERROR:{_client_error_name(e)}",
                           "Could not list IAM roles", region))
    try:
        users, more = _paginate(iam, "list_users", "Users")
        with_keys = 0
        checked = 0
        for u in users:
            try:
                keys, _ = _paginate(iam, "list_access_keys", "AccessKeyMetadata",
                                    UserName=u["UserName"])
                checked += 1
                if keys:
                    with_keys += 1
            except Exception:  # noqa: BLE001 - AUD-F17: unreadable user is unknown
                continue
        if users:
            fact = _ratio_fact("iam", "long_lived_keys", region, checked - with_keys,
                               checked, len(users), more, "user",
                               "have no long-lived access key")
            if fact["status"] == "OBSERVED":
                fact["detail"] = (f"{with_keys} of {checked} user(s) have a "
                                  f"long-lived access key ({len(users)} users, "
                                  f"{len(users) - checked} unreadable)")
            facts.append(fact)
        else:
            facts.append(_fact("iam", "long_lived_keys", "NONE", "No IAM users", region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("iam", "long_lived_keys",
                           f"ERROR:{_client_error_name(e)}",
                           "Could not list IAM users", region))
    return facts


def collect_iam_response_wiring(session, region):
    """Suspicious-activity response wiring: GuardDuty enabled and EventBridge
    rules present to route findings to containment. The 'responding to
    suspicious activity' signal. Maps: IAM-SUS."""
    facts = []
    try:
        gd = session.client("guardduty")
        ids, _ = _paginate(gd, "list_detectors", "DetectorIds")
        facts.append(_fact("guardduty", "response_detector",
                           "ENABLED" if ids else "NONE",
                           f"{len(ids)} GuardDuty detector(s) present", region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("guardduty", "response_detector",
                           f"ERROR:{_client_error_name(e)}",
                           "Could not list GuardDuty detectors", region))
    try:
        ev = session.client("events")
        rules, more = _paginate(ev, "list_rules", "Rules")
        enabled = sum(1 for r in rules if r.get("State") == "ENABLED")
        if rules:
            fact = _ratio_fact("events", "response_rules", region, enabled, len(rules),
                               len(rules), more, "EventBridge rule", "enabled")
            if fact["status"] == "OBSERVED":
                fact["detail"] = (f"{enabled} of {len(rules)} EventBridge rule(s) "
                                  "enabled to route events")
            facts.append(fact)
        else:
            facts.append(_fact("events", "response_rules", "NONE",
                               "No EventBridge rules to route events", region))
    except Exception as e:  # noqa: BLE001
        facts.append(_fact("events", "response_rules",
                           f"ERROR:{_client_error_name(e)}",
                           "Could not list EventBridge rules", region))
    return facts


def collect_pipeline_gates(session, region):
    """CodePipeline stage posture: how many pipelines include an approval or a
    test/scan stage. The 'validating throughout deployment' and 'security in
    the SDLC' signal. Maps: CMT-VTD, PIY-RSD."""
    try:
        cp = session.client("codepipeline")
    except Exception as e:  # noqa: BLE001
        return [_fact("codepipeline", "client", "ERROR", type(e).__name__, region)]
    try:
        pipelines, more = _paginate(cp, "list_pipelines", "pipelines")
        names = [p["name"] for p in pipelines]
    except Exception as e:  # noqa: BLE001
        return [_fact("codepipeline", "pipelines", f"ERROR:{_client_error_name(e)}",
                      "Could not list CodePipelines", region)]
    if not names:
        return [_fact("codepipeline", "pipelines", "NONE",
                      "No CodePipelines in this region", region)]
    gate_keywords = ("approval", "test", "scan", "analysis", "security")
    with_gate = 0
    checked = 0
    for n in names:
        try:
            pl = cp.get_pipeline(name=n).get("pipeline", {})
            checked += 1
            stage_text = " ".join(s.get("name", "").lower()
                                  for s in pl.get("stages", []))
            if any(k in stage_text for k in gate_keywords):
                with_gate += 1
        except Exception:  # noqa: BLE001 - AUD-F17: unreadable pipeline is unknown
            continue
    fact = _ratio_fact("codepipeline", "pipeline_gates", region, with_gate, checked,
                       len(names), more, "pipeline", "include an approval or test/scan stage")
    if fact["status"] == "OBSERVED":
        fact["detail"] = (f"{with_gate} of {checked} pipeline(s) include an approval or "
                          f"test/scan stage ({len(names)} pipelines, "
                          f"{len(names) - checked} unreadable)")
    return [fact]


def collect_supply_chain_scanning(session, region):
    """Amazon Inspector account scanning status for ECR and Lambda: the
    supply-chain mitigation/monitoring signal. Maps: SCR-MIT, SCR-MON."""
    try:
        insp = session.client("inspector2")
    except Exception as e:  # noqa: BLE001
        return [_fact("inspector2", "supply_chain_client", "ERROR",
                      type(e).__name__, region)]
    try:
        resp = insp.batch_get_account_status()
        accounts = resp.get("accounts", [])
    except Exception as e:  # noqa: BLE001
        return [_fact("inspector2", "scanning_status",
                      f"ERROR:{_client_error_name(e)}",
                      "Could not read Inspector account status", region)]
    if not accounts:
        return [_fact("inspector2", "scanning_status", "UNKNOWN",
                      "No Inspector account status returned", region)]
    state = accounts[0].get("resourceState", {})
    ecr_on = state.get("ecr", {}).get("status") == "ENABLED"
    lambda_on = state.get("lambda", {}).get("status") == "ENABLED"
    enabled = [n for n, on in (("ECR", ecr_on), ("Lambda", lambda_on)) if on]
    status = "ENABLED" if enabled else "NOT_ENABLED"
    return [_fact("inspector2", "scanning_status", status,
                  f"Inspector scanning enabled for: "
                  f"{', '.join(enabled) if enabled else 'none'}", region)]


def collect_restore_testing(session, region):
    """AWS Backup restore-testing plans: the 'testing recovery capabilities'
    signal. Reports whether a restore-testing plan is configured. Maps:
    RPL-TRC."""
    try:
        bk = session.client("backup")
    except Exception as e:  # noqa: BLE001
        return [_fact("backup", "restore_testing_client", "ERROR",
                      type(e).__name__, region)]
    try:
        plans, _ = _paginate(bk, "list_restore_testing_plans", "RestoreTestingPlans")
    except Exception as e:  # noqa: BLE001
        return [_fact("backup", "restore_testing", f"ERROR:{_client_error_name(e)}",
                      "Could not list restore-testing plans", region)]
    return [_fact("backup", "restore_testing",
                  "PRESENT" if plans else "NONE",
                  f"{len(plans)} restore-testing plan(s) configured", region)]


# Ordered so a driver can iterate. Each entry: (name, function).
def collect_bucket_versioning(session, region, bucket=None):
    """Verify the durable metric-history/facts store bucket has versioning
    enabled. Read-side complement to automation/storage/provision_store.py.

    The bucket name comes from the SDR_STORE_BUCKET environment variable unless
    passed explicitly. If no bucket is configured, this is NOT_CONFIGURED (not
    an error): the living-SDR loop may run before a durable store is wired.
    Telemetry only: a passing result says versioning is on, not that any
    indicator is met.
    """
    import os
    bucket = bucket or os.environ.get("SDR_STORE_BUCKET")
    if not bucket:
        return [_fact("s3_store", "versioning", "NOT_CONFIGURED",
                      "No SDR_STORE_BUCKET set; durable store not wired yet.",
                      region)]
    try:
        s3 = session.client("s3")
        resp = s3.get_bucket_versioning(Bucket=bucket)
        status = resp.get("Status")  # "Enabled" | "Suspended" | None
        if status == "Enabled":
            return [_fact("s3_store", "versioning", "ENABLED",
                          "Store bucket has versioning enabled.", region)]
        detail = ("Store bucket versioning is Suspended." if status == "Suspended"
                  else "Store bucket has never had versioning enabled.")
        return [_fact("s3_store", "versioning", "NOT_ENABLED", detail, region)]
    except Exception as e:  # noqa: BLE001 - one service must not sink the run
        return [_fact("s3_store", "versioning", f"ERROR:{_client_error_name(e)}",
                      "Could not read bucket versioning.", region)]


COLLECTORS = [
    ("security_hub", collect_security_hub),    ("access_analyzer", collect_access_analyzer),
    ("inspector", collect_inspector),
    ("guardduty", collect_guardduty),
    ("backup", collect_backup),
    ("kms", collect_kms),
    ("config", collect_config),
    ("cloudtrail", collect_cloudtrail),
    ("s3", collect_s3),
    ("iam", collect_iam),
    # Stage 2 Bucket A additions (CNA, SVC, MLA):
    ("cfn_drift", collect_cfn_drift),
    ("config_conformance", collect_config_conformance),
    ("waf", collect_waf),
    ("network_segmentation", collect_network_segmentation),
    ("cloudtrail_integrity", collect_cloudtrail_integrity),
    ("ecr_integrity", collect_ecr_integrity),
    ("s3_data_protection", collect_s3_data_protection),
    ("data_retention", collect_data_retention),
    ("siem_posture", collect_siem_posture),
    # Stage 3 Bucket A additions (IAM, CMT, PIY, SCR, RPL):
    ("iam_jit", collect_iam_jit),
    ("iam_response_wiring", collect_iam_response_wiring),
    ("pipeline_gates", collect_pipeline_gates),
    ("supply_chain_scanning", collect_supply_chain_scanning),
    ("restore_testing", collect_restore_testing),
    ("bucket_versioning", collect_bucket_versioning),
]
