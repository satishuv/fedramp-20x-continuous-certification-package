#!/usr/bin/env python3
"""Canonical collector-service routing registry.

Single source of truth mapping every service name a production collector emits
(collectors.py _fact("<service>", ...)) to its human display name for downstream
routing (deterministic prefill, AI drafting context, provenance). Metric history
buckets by whatever service it sees and does not need a whitelist, but prefill/AI
DO look services up by name, so a service that collectors emit but this registry
omits would have its telemetry silently unrouted.

The invariant test (test_service_registry.py) asserts that every service the
collectors emit is either present here (routed) or explicitly listed as
telemetry-only, so this cannot drift out of sync again.

Service keys MUST match the collector's emitted names exactly (securityhub,
accessanalyzer, inspector2 - not security_hub / access_analyzer / inspector).
"""

# service key -> human display name (routed downstream into prefill/AI).
SERVICE_DISPLAY_NAMES = {
    "securityhub": "AWS Security Hub",
    "accessanalyzer": "Access Analyzer",
    "inspector2": "Amazon Inspector",
    "guardduty": "Amazon GuardDuty",
    "backup": "AWS Backup",
    "kms": "AWS Key Management Service",
    "config": "AWS Config",
    "cloudtrail": "AWS CloudTrail",
    "s3": "Amazon S3",
    "iam": "IAM",
    "cloudformation": "AWS CloudFormation",
    "wafv2": "AWS WAF",
    "ec2": "Amazon EC2",
    "ecr": "Amazon ECR",
    "dynamodb": "Amazon DynamoDB",
    "events": "Amazon EventBridge",
    "codepipeline": "AWS CodePipeline",
    # Stage 4 platform-hardening use case (image, certificate, secrets):
    "imagebuilder": "EC2 Image Builder",
    "acm": "AWS Certificate Manager",
    "ssm": "AWS Systems Manager Parameter Store",
}

# Services intentionally collected as raw telemetry only, with no downstream
# prefill/AI routing (none today; kept so the invariant test can distinguish a
# deliberate telemetry-only service from an accidental omission).
TELEMETRY_ONLY_SERVICES = set()


def display_name(service):
    return SERVICE_DISPLAY_NAMES.get(service, service)
