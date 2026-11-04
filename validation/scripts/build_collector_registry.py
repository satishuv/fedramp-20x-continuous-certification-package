# Build the collector registry: a machine-readable map from each Key
# Security Indicator (KSI) to concrete read-only AWS checks, derived from
# traceability/aws-service-ksi-map.json.
#
# Layer 1 of the automation design: deterministic collectors only. Each
# check is one of:
#   config_managed_rule  - an AWS Config managed rule named in the guidance
#                          (backtick-quoted); collectable today via
#                          config:DescribeComplianceByConfigRule.
#   described_method     - a verify or validate method described in prose;
#                          carried for traceability until a dedicated
#                          collector implements it.
# Pipeline position: run after build_notes.py (needs the service map).
# Deterministic: output is pinned to the dataset version, no run timestamps.

import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SERVICE_MAP = os.path.join(BASE, "traceability", "aws-service-ksi-map.json")
OUT_DIR = os.path.join(BASE, "automation", "collectors")
OUT = os.path.join(OUT_DIR, "registry.json")
# Stage 1 triage: which pending KSIs now have a real read-only collector
# (bucket_a) versus a provider-deployed Config custom rule (bucket_b). The
# registry reads this so the collectable-now count regenerates deterministically
# instead of being hand-edited.
CLASSIFICATION = os.path.join(OUT_DIR, "pending-ksi-classification.json")
# Pinned allowlist of real AWS Config managed-rule IDs. The generator extracts
# backtick-quoted tokens from guidance prose; prose is not a safe source of
# executable rule identities (a shorthand like "aurora" is not a managed rule).
# Any extracted token NOT on this allowlist aborts the build (fail-closed) so a
# bogus identifier can never become a config_managed_rule check target.
KNOWN_RULES_FILE = os.path.join(
    BASE, "automation", "config-rules", "known-config-managed-rules.json")


def load_known_config_rules():
    with open(KNOWN_RULES_FILE, encoding="utf-8") as f:
        return set(json.load(f).get("config_managed_rule_ids", []))


# Optional customer overlay (Max's request): a provider with custom AWS Config
# rules that are not referenced in the FedRAMP guidance prose can map them to
# KSIs WITHOUT editing code. Drop a file at
# automation/config-rules/customer-config-rules.json of the shape:
#   {"KSI-CNA-MAT": [{"rule_name": "my-org-ingress-check",
#                     "description": "custom ingress rule",
#                     "type": "custom"}],
#    ...}
# Each entry becomes an additional config_managed_rule check on that KSI, and
# its rule_name is trusted as a real rule (it is the customer's own deployed
# rule, not a managed-rule-catalog token), so it bypasses the managed-rule
# allowlist gate. The file is git-excluded in a real engagement (a customer's
# rule names are their data); it is absent in the public template.
CUSTOMER_RULES_FILE = os.path.join(
    BASE, "automation", "config-rules", "customer-config-rules.json")


def load_customer_rules():
    """Return {ksi_id: [ {rule_name, description?, type?}, ... ]} or {} if no
    overlay is present. Malformed entries are skipped with a warning rather than
    aborting, so a typo in the customer file does not brick the build."""
    if not os.path.exists(CUSTOMER_RULES_FILE):
        return {}
    try:
        with open(CUSTOMER_RULES_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        print(f"WARNING: could not read {CUSTOMER_RULES_FILE}: {e}; ignoring overlay.")
        return {}
    out = {}
    for kid, entries in (data.items() if isinstance(data, dict) else []):
        if not isinstance(entries, list):
            continue
        clean = []
        for ent in entries:
            if isinstance(ent, str):
                clean.append({"rule_name": ent})
            elif isinstance(ent, dict) and ent.get("rule_name"):
                clean.append(ent)
        if clean:
            out[kid] = clean
    return out

# Service names recognized in guidance prose, longest match first.
SERVICES = [
    "AWS IAM Identity Center", "AWS Identity and Access Management Access Analyzer",
    "IAM Access Analyzer", "AWS Security Hub", "AWS CloudTrail", "Amazon CloudWatch",
    "Amazon EventBridge", "AWS Config", "AWS Lambda", "Amazon Inspector",
    "AWS Key Management Service", "AWS KMS", "AWS Backup", "Amazon GuardDuty",
    "AWS Organizations", "AWS Systems Manager", "Amazon S3", "AWS CodePipeline",
    "AWS CodeBuild", "AWS CloudFormation", "AWS Secrets Manager",
    "AWS Certificate Manager", "Amazon Macie", "AWS WAF", "AWS Shield",
    "Amazon Detective", "AWS Audit Manager", "AWS Artifact", "Amazon VPC",
    "AWS Network Firewall", "Amazon Route 53", "AWS Firewall Manager",
    "Amazon ECR", "Amazon EC2", "AWS Step Functions", "Amazon SNS",
    "Amazon Athena", "AWS Glue", "Amazon QuickSight", "AWS Control Tower",
    "Amazon Security Lake", "AWS Resource Explorer", "IAM",
]

RULE_PAT = re.compile(r"`([a-z0-9][a-z0-9-]*)`")

# Explicit posture-metric source allowlist: collector service-key -> the KSIs
# that service's posture LEGITIMATELY measures. This is the authoritative
# routing for KMT metric history, derived from the collector-to-KSI mapping the
# collectors' own docstrings declare ("Maps: ...") and the bucket_a signals in
# pending-ksi-classification.json - NOT from prose service-name matching.
#
# Why this exists (finding: generic service -> KSI metric fan-out): routing a
# posture service to every KSI whose prose happens to name it let unrelated
# posture (e.g. generic S3/Config/IAM) manufacture daily metric history for a
# KSI it says nothing about (e.g. KSI-CED-RAT employee training). A service now
# contributes a metric to a KSI ONLY if that KSI id appears here. A KSI whose
# assurance is document/process evidence (bucket_b) has NO posture source and
# therefore accrues no automated metric history from generic posture.
#
# Service keys MUST match automation/collectors/service_registry.py exactly.
#
# AUD-F16: every key is CHECK-SCOPED ("service:check"). A bare service key
# routed every fact of that service, so a good-looking unrelated check lifted a
# KSI: Access Analyzer PRESENT (1/1) improved KSI-IAM-ELP while the analyzer's
# active findings (the actual least-privilege signal) were open; generic S3
# encryption fed data-removal; generic Backup plans fed recovery TESTING; a
# CloudTrail SIEM-capture count fed resource INTEGRITY. The check names are the
# collectors' `_fact(service, check, ...)` names; method_ids.assert_check_scoped
# refuses a registry with any bare key, and test_collector_registry_routes
# asserts every route names a check a collector actually emits.
METRIC_SOURCE_MAP = {
    # intended-state / immutable-redeploy signal: stack drift status
    "cloudformation:drift": ["KSI-CNA-EIS", "KSI-SVC-ACM", "KSI-CMT-RMV"],
    # test/approval stages present in delivery pipelines
    "codepipeline:pipeline_gates": ["KSI-CMT-VTD", "KSI-PIY-RSD"],
    # codified-baseline compliance (conformance packs) and rule compliance
    "config:conformance_compliance": ["KSI-CNA-IBP", "KSI-MLA-EVC"],
    "config:rule_compliance": ["KSI-MLA-EVC", "KSI-SVC-EIS"],
    "wafv2:web_acls": ["KSI-CNA-RVP"],
    "ec2:security_groups": ["KSI-CNA-ULN"],
    # F03: check-scoped so an unrelated IAM check (e.g. password_policy, which
    # measures IAM-APM, not just-in-time authorization) cannot score IAM-JIT.
    "iam:role_session_duration": ["KSI-IAM-JIT"],
    "iam:long_lived_keys": ["KSI-IAM-JIT"],
    # least privilege is measured by the ABSENCE of active Access Analyzer
    # findings, never by the analyzer merely existing
    "accessanalyzer:active_findings": ["KSI-IAM-ELP"],
    "guardduty:response_detector": ["KSI-IAM-SUS"],
    "events:response_rules": ["KSI-IAM-SUS"],
    "cloudtrail:siem_capture": ["KSI-MLA-OSM"],
    "securityhub:siem_aggregation": ["KSI-MLA-OSM"],
    # resource integrity: log-file validation and immutable image tags
    "cloudtrail:log_validation": ["KSI-SVC-VRI"],
    "ecr:image_immutability": ["KSI-SVC-VRI"],
    # residual risk / exposure: encryption at rest, public access blocked, key rotation
    "kms:key_rotation": ["KSI-SVC-PRR"],
    "s3:encryption": ["KSI-SVC-PRR"],
    "s3:public_access_block": ["KSI-SVC-PRR"],
    # removal of unwanted data: lifecycle expiry and TTL, not encryption
    "s3:lifecycle": ["KSI-SVC-RUD"],
    "dynamodb:ttl": ["KSI-SVC-RUD"],
    # recovery TESTING is a restore-testing plan, not the existence of backups
    "backup:restore_testing": ["KSI-RPL-TRC"],
    # supply-chain scanning coverage and enablement
    "inspector2:coverage": ["KSI-SCR-MIT", "KSI-SCR-MON"],
    "inspector2:scanning_status": ["KSI-SCR-MIT", "KSI-SCR-MON"],
    # Stage 4 platform-hardening use case. Image hardening: scan-on-push is
    # upstream-vulnerability monitoring of third-party layers (SCR-MON) and a
    # provider-best-practice comparison (CNA-IBP); a tested Image Builder
    # recipe is the redeploy-not-modify path (CMT-RMV). Certificates and
    # parameters are the secrets-management signal (SVC-ASM); encrypted
    # parameters also secure information at rest (SVC-SIN).
    "ecr:scan_on_push": ["KSI-CNA-IBP", "KSI-SCR-MON"],
    "imagebuilder:pipelines": ["KSI-CNA-IBP", "KSI-CMT-RMV"],
    "acm:renewal_eligible": ["KSI-SVC-ASM"],
    "acm:expiring_soon": ["KSI-SVC-ASM"],
    "ssm:secure_string": ["KSI-SVC-ASM", "KSI-SVC-SIN"],
    "ssm:customer_key": ["KSI-SVC-SIN"],
}


def metric_service_keys_for(kid):
    """The collector service-keys whose posture legitimately measures this KSI,
    inverted from METRIC_SOURCE_MAP. Empty for a KSI with no posture source."""
    return sorted(k for k, kids in METRIC_SOURCE_MAP.items() if kid in kids)


def find_services(text):
    found = []
    for s in SERVICES:
        if s in text and s not in found:
            # skip bare IAM if a more specific IAM service already matched
            if s == "IAM" and any("IAM" in f or "Identity" in f for f in found):
                continue
            found.append(s)
    return found


def main():
    smap = json.load(open(SERVICE_MAP, encoding="utf-8"))
    # Load the Stage 1 triage. bucket_a KSIs now have a real read-only
    # collector, so their described-method checks are collectable now.
    # bucket_b KSIs are provider-deployed Config custom rules, not repo
    # collectors, so they stay not-collectable and are flagged provider_deployed.
    bucket_a, bucket_b = set(), set()
    if os.path.exists(CLASSIFICATION):
        cls = json.load(open(CLASSIFICATION, encoding="utf-8"))
        bucket_a = set(cls.get("bucket_a", {}).get("ksis", {}).keys())
        bucket_b = set(cls.get("bucket_b", {}).get("ksis", {}).keys())
    registry = {}
    total_rules = 0
    customer_rules = load_customer_rules()  # Max's overlay: {ksi_id: [entries]}
    known_rules = load_known_config_rules()
    unknown_rule_tokens = {}
    for kid, e in sorted(smap["ksis"].items()):
        checks = []
        for source in ("verify", "validate"):
            text = e[f"{source}_method"]
            rules = RULE_PAT.findall(text)
            for rule in rules:
                # Fail-closed vocabulary gate: a backtick token that is not a
                # known AWS Config managed rule is NOT emitted as a rule check.
                # Unknown tokens are collected and abort the build below, so a
                # prose shorthand (e.g. "aurora") can never become a check.
                if rule not in known_rules:
                    unknown_rule_tokens.setdefault(rule, []).append(f"{kid}:{source}")
                    continue
                checks.append({
                    "check_id": f"{kid}:{source}:config:{rule}",
                    "type": "config_managed_rule",
                    "service": "AWS Config",
                    "target": rule,
                    "source": source,
                    "collectable_now": True,
                })
            total_rules += sum(1 for r in rules if r in known_rules)
            # A described method becomes collectable now when a read-only
            # collector was built for this KSI (bucket_a). Bucket_b keeps it
            # false and records that it is provider-deployed infrastructure.
            method_check = {
                "check_id": f"{kid}:{source}:method",
                "type": "described_method",
                "services": find_services(text),
                "description": text,
                "source": source,
                "collectable_now": kid in bucket_a,
            }
            if kid in bucket_a:
                method_check["collector"] = "automation/collectors/collectors.py"
            if kid in bucket_b:
                method_check["provider_deployed"] = True
                method_check["deploy"] = "automation/config-rules/ (Config custom rule)"
                # PR-6: a bucket_b (document/process-evidence) KSI has NO API
                # posture source, so its automated method must declare the
                # OUTCOME it measures, not merely assert the artifact exists. The
                # provider-deployed rule/Lambda emits a measurable signal; bind
                # it as an explicit outcome-metric contract so the metric layer
                # scores the outcome (compliant / within-interval / coverage),
                # never bare existence. metric_id keys the per-method telemetry
                # series (same convention the VVK binding gate checks), so a
                # declared method with no emitted outcome cannot read as ready.
                if source == "verify":
                    method_check["outcome_metric"] = {
                        "metric_id": f"{kid}-config-rule",
                        "signal": "config_rule_compliance",
                        "unit": "compliant_fraction",
                        "pass_when": "COMPLIANT",
                        "emitted_by": "AWS Config custom rule (Lambda-backed)",
                        "description": (
                            "Fraction of evaluations reporting COMPLIANT: the "
                            "reviewed artifact exists AND is current within the "
                            "defined review interval. A stale or missing artifact "
                            "evaluates NON_COMPLIANT and scores 0, not passing."),
                    }
                else:
                    method_check["outcome_metric"] = {
                        "metric_id": f"{kid}-coverage-collector",
                        "signal": "cloudwatch_coverage",
                        "unit": "coverage_fraction",
                        "pass_when": ">= threshold",
                        "emitted_by": "EventBridge-scheduled Lambda -> CloudWatch metric",
                        "description": (
                            "Coverage/freshness percentage the scheduled check "
                            "emits (e.g. workforce coverage, days-since-review). "
                            "Scores the measured fraction; a below-threshold or "
                            "stale value is not passing."),
                    }
            checks.append(method_check)
        # Max's overlay: append customer custom Config rules mapped to this KSI.
        # Each is a real deployed rule the customer owns, so it is collectable
        # now and trusted (not gated against the managed-rule allowlist).
        for ent in customer_rules.get(kid, []):
            checks.append({
                "check_id": f"{kid}:custom:config:{ent['rule_name']}",
                "type": "config_managed_rule",
                "service": "AWS Config",
                "target": ent["rule_name"],
                "source": "verify",
                "collectable_now": True,
                "custom": True,
                "description": ent.get("description",
                                       f"Customer custom Config rule {ent['rule_name']}"),
            })
            total_rules += 1
        registry[kid] = {
            "name": e["name"],
            "family": e["family"],
            "family_name": e["family_name"],
            "services": find_services(
                e["aws_implementation"] + " " + e["verify_method"] + " "
                + e["validate_method"]),
            "metric_service_keys": metric_service_keys_for(kid),
            "checks": checks,
        }
    # Fail-closed vocabulary gate: any backtick token pulled from the guidance
    # prose that is not a known AWS Config managed rule aborts the build. This
    # is what stops a prose shorthand (e.g. "aurora") from silently becoming a
    # config_managed_rule check target. To add a genuinely new rule, add its id
    # to automation/config-rules/known-config-managed-rules.json (after
    # confirming it against the AWS Config managed-rules catalog).
    if unknown_rule_tokens:
        lines = "; ".join(f"`{tok}` (in {', '.join(sorted(where))})"
                          for tok, where in sorted(unknown_rule_tokens.items()))
        print("ERROR: guidance prose contains backtick token(s) that are not "
              "known AWS Config managed rules and were rejected: " + lines)
        print("If a token IS a real AWS Config managed rule, add it to "
              "automation/config-rules/known-config-managed-rules.json. "
              "Otherwise fix the prose in traceability/aws-service-ksi-map.json.")
        return 3
    doc = {
        "meta": {
            "title": "KSI collector registry (Layer 1: deterministic read-only checks)",
            "derived_from": "traceability/aws-service-ksi-map.json",
            "dataset_version": smap["meta"]["dataset_version"],
            "ksis": len(registry),
            "config_managed_rule_checks": total_rules,
            "boundary": (
                "Collectors are read-only by design and produce facts, "
                "never statuses. A status changes only through deterministic "
                "checks plus human sign-off; generative output is never "
                "deterministic telemetry (FedRAMP definitions)."
            ),
        },
        "ksis": registry,
    }
    collectable = sum(1 for k in registry.values()
                      for c in k["checks"] if c["collectable_now"])
    ksis_collectable = sum(
        1 for k in registry.values()
        if any(c["collectable_now"] for c in k["checks"]))
    ksis_provider_deployed = sum(
        1 for k in registry.values()
        if any(c.get("provider_deployed") for c in k["checks"]))
    doc["meta"]["ksis_collectable_now"] = ksis_collectable
    doc["meta"]["ksis_provider_deployed_only"] = ksis_provider_deployed
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=1)
    print(f"registry: {len(registry)} KSIs, {ksis_collectable} collectable now "
          f"(KSI level), {ksis_provider_deployed} provider-deployed only, "
          f"{collectable} collectable checks, "
          f"{sum(len(k['checks']) for k in registry.values())} checks total")
    return 0


if __name__ == "__main__":
    sys.exit(main())
