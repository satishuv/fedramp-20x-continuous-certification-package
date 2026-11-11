#!/usr/bin/env python3
"""Generate deployable artifacts for the 11 provider-deployed Config custom rules.

Reads ../rules-manifest.json and emits, deterministically, BOTH:
  - cloudformation.yaml : one Lambda (the shared evidence_existence_rule
    handler), an execution role, the config.amazonaws.com invoke permission,
    and 11 AWS::Config::ConfigRule resources (one per manifest rule).
  - cdk_stack.py / cdk_app.py : a FUNCTIONAL CDK v2 (Python) reference stack,
    also read from the manifest so the two artifacts never drift. It is not
    security-hardened to parity with cloudformation.yaml (the canonical hardened
    path); see the cdk_stack.py docstring for the specific gaps.

Offline and deterministic: no AWS calls, stable ordering (manifest order),
so re-running produces byte-identical output. This is a code generator, not a
deployer.

Trust boundary, unchanged: these rules report whether a provider-produced
evidence artifact exists and is fresh. A COMPLIANT result is telemetry, never a
compliance determination or an assessment. The provider owns the evidence
bucket and the review cadence; the default max_age_days values are suggestions
the provider confirms, not FedRAMP-asserted intervals.

Usage:
  python automation/config-rules/deploy/generate_templates.py         # writes both
  python automation/config-rules/deploy/generate_templates.py --stdout # print CFN
"""

import argparse
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, "..", "rules-manifest.json")
CFN_OUT = os.path.join(HERE, "cloudformation.yaml")
CDK_STACK_OUT = os.path.join(HERE, "cdk_stack.py")
CDK_APP_OUT = os.path.join(HERE, "cdk_app.py")


def load_manifest():
    with open(MANIFEST, encoding="utf-8") as f:
        return json.load(f)


def _logical_id(rule_name):
    """Deterministic CloudFormation logical id from a rule name.
    'sdr-ced-rat-training-records' -> 'SdrCedRatTrainingRecords'."""
    return "".join(part.capitalize() for part in rule_name.split("-"))


def build_cfn(manifest):
    """Return the CloudFormation template as a plain dict (ordered by manifest)."""
    rules = manifest["rules"]
    handler = manifest["meta"]["handler"]  # evidence_existence_rule.lambda_handler

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": ("FedRAMP 20x SDR: provider-deployed Config custom rules "
                        "(evidence-existence). A COMPLIANT result is telemetry, "
                        "not a compliance determination."),
        "Parameters": {
            "EvidenceBucket": {
                "Type": "String",
                "Description": "S3 bucket (in your account) holding evidence artifacts.",
            },
            "LambdaCodeS3Bucket": {
                "Type": "String",
                "Description": "S3 bucket holding the packaged Lambda zip.",
            },
            "LambdaCodeS3Key": {
                "Type": "String",
                "Description": "S3 key of the packaged Lambda zip.",
            },
        },
        "Resources": {},
    }

    # Customer-managed KMS key encrypting the Lambda log group at rest.
    template["Resources"]["EvidenceRuleLogKey"] = {
        "Type": "AWS::KMS::Key",
        "Properties": {
            "Description": "CMK encrypting the evidence-existence Lambda log group.",
            "EnableKeyRotation": True,
            "KeyPolicy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowAccountAdmin",
                        "Effect": "Allow",
                        "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
                        "Action": "kms:*",
                        "Resource": "*",
                    },
                    {
                        "Sid": "AllowCloudWatchLogs",
                        "Effect": "Allow",
                        "Principal": {"Service": {"Fn::Sub": "logs.${AWS::Region}.amazonaws.com"}},
                        "Action": [
                            "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*",
                            "kms:GenerateDataKey*", "kms:Describe*",
                        ],
                        "Resource": "*",
                    },
                    {
                        # The Lambda service writes failed invocations to the
                        # KMS-encrypted dead-letter queue on the function's behalf.
                        "Sid": "AllowLambdaDeadLetterQueue",
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": ["kms:GenerateDataKey*", "kms:Decrypt"],
                        "Resource": "*",
                        "Condition": {"StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}},
                    },
                ],
            },
        },
    }

    # Explicit, encrypted, retained log group for the function.
    template["Resources"]["EvidenceRuleLogGroup"] = {
        "Type": "AWS::Logs::LogGroup",
        "Properties": {
            "LogGroupName": {"Fn::Sub": "/aws/lambda/${EvidenceRuleFunction}"},
            "RetentionInDays": 365,
            "KmsKeyId": {"Fn::GetAtt": ["EvidenceRuleLogKey", "Arn"]},
        },
    }

    # Execution role: read-only on the evidence bucket + Config PutEvaluations
    # + basic Lambda logging. No write on the evidence data.
    template["Resources"]["EvidenceRuleRole"] = {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            },
            "ManagedPolicyArns": [
                {"Fn::Sub": "arn:${AWS::Partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"}
            ],
            "Policies": [{
                "PolicyName": "evidence-existence-readonly",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject", "s3:GetObjectTagging"],
                            "Resource": {"Fn::Sub":
                                         "arn:${AWS::Partition}:s3:::${EvidenceBucket}/*"},
                        },
                        {
                            "Effect": "Allow",
                            "Action": "config:PutEvaluations",
                            "Resource": "*",
                        },
                        {
                            "Effect": "Allow",
                            "Action": [
                                "xray:PutTraceSegments",
                                "xray:PutTelemetryRecords",
                            ],
                            "Resource": "*",
                        },
                        {
                            "Effect": "Allow",
                            "Action": "sqs:SendMessage",
                            "Resource": {"Fn::GetAtt": ["EvidenceRuleDeadLetterQueue", "Arn"]},
                        },
                    ],
                },
            }],
        },
    }

    # Dead-letter queue for the evidence rule (SAST review 2026-11-10,
    # CKV_AWS_116). Encrypted with the same customer managed key as the log
    # group; 14-day retention, the SQS maximum, so a stuck rule is visible for
    # the whole Config evaluation cycle.
    template["Resources"]["EvidenceRuleDeadLetterQueue"] = {
        "Type": "AWS::SQS::Queue",
        "Properties": {
            "KmsMasterKeyId": {"Fn::GetAtt": ["EvidenceRuleLogKey", "Arn"]},
            "MessageRetentionPeriod": 1209600,
        },
    }

    # VPC placement (CKV_AWS_117) is deliberately NOT applied: the function
    # calls only the S3 and Config service endpoints and touches no VPC
    # resource, so a VPC adds a NAT path and cost with no isolation gained.
    # The skip is recorded on the resource so a scanner reads the reason.
    template["Resources"]["EvidenceRuleFunction"] = {
        "Type": "AWS::Lambda::Function",
        "DependsOn": ["EvidenceRuleLogGroup"],
        "Metadata": {
            "checkov": {"skip": [{"id": "CKV_AWS_117",
                                  "comment": "Calls only S3 and Config service endpoints; "
                                             "no VPC resources are accessed, so VPC placement adds a NAT path and no isolation."}]},
        },
        "Properties": {
            "Handler": handler,
            "Runtime": "python3.12",
            "Timeout": 30,
            "ReservedConcurrentExecutions": 10,
            "TracingConfig": {"Mode": "Active"},
            # A failed evaluation is itself telemetry (SAST review 2026-11-10,
            # CKV_AWS_116): invocations Lambda could not complete land in a
            # KMS-encrypted dead-letter queue instead of vanishing, so a stuck
            # rule is visible rather than silently NOT_APPLICABLE.
            "DeadLetterConfig": {"TargetArn": {"Fn::GetAtt": ["EvidenceRuleDeadLetterQueue", "Arn"]}},
            "LoggingConfig": {
                "LogFormat": "JSON",
                "ApplicationLogLevel": "INFO",
                "SystemLogLevel": "INFO",
                "LogGroup": {"Fn::Sub": "/aws/lambda/${EvidenceRuleFunction}"},
            },
            "Role": {"Fn::GetAtt": ["EvidenceRuleRole", "Arn"]},
            "Code": {
                "S3Bucket": {"Ref": "LambdaCodeS3Bucket"},
                "S3Key": {"Ref": "LambdaCodeS3Key"},
            },
        },
    }

    # AWS Config must be permitted to invoke the function. SourceAccount pins
    # the permission to THIS account's Config service (CKV_AWS_364: a service
    # principal alone would let Config in any account invoke the function).
    template["Resources"]["EvidenceRuleInvokePermission"] = {
        "Type": "AWS::Lambda::Permission",
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": {"Fn::GetAtt": ["EvidenceRuleFunction", "Arn"]},
            "Principal": "config.amazonaws.com",
            "SourceAccount": {"Ref": "AWS::AccountId"},
        },
    }

    # One ConfigRule per manifest entry, in manifest order.
    for rule in rules:
        lid = _logical_id(rule["rule_name"]) + "Rule"
        template["Resources"][lid] = {
            "Type": "AWS::Config::ConfigRule",
            "DependsOn": ["EvidenceRuleInvokePermission"],
            "Properties": {
                "ConfigRuleName": rule["rule_name"],
                "Description": (f"{rule['ksi_id']}: {rule['evidence']}. "
                               "Presence+freshness telemetry, not a determination."),
                "InputParameters": {
                    "evidence_bucket": {"Ref": "EvidenceBucket"},
                    "evidence_key": f"{rule['rule_name']}/evidence",
                    "max_age_days": rule["default_max_age_days"],
                },
                "Source": {
                    "Owner": "CUSTOM_LAMBDA",
                    "SourceIdentifier": {"Fn::GetAtt":
                                         ["EvidenceRuleFunction", "Arn"]},
                    "SourceDetails": [{
                        "EventSource": "aws.config",
                        "MessageType": "ScheduledNotification",
                        "MaximumExecutionFrequency": "TwentyFour_Hours",
                    }],
                },
            },
        }
    return template


CDK_STACK_TEMPLATE = '''\
#!/usr/bin/env python3
"""CDK v2 (Python) stack for the Config evidence rule, generated from
rules-manifest.json by generate_templates.py. This is a FUNCTIONAL reference
deployment (Lambda + role + Config rule); it is NOT security-hardened to parity
with cloudformation.yaml, which is the canonical hardened path and additionally
provides a KMS-encrypted Lambda log group with 365-day retention, X-Ray active
tracing, and reserved Lambda concurrency. Use cloudformation.yaml for a hardened
deployment, or add those properties to this stack before using it as one. Do not
edit by hand; re-run the generator. A COMPLIANT result from these rules is
telemetry, not a compliance determination.
"""

import json
import os

from aws_cdk import App, Stack, CfnParameter, Duration, Aws
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_config as config
from constructs import Construct

MANIFEST = os.path.join(os.path.dirname(__file__), "..", "rules-manifest.json")


class EvidenceRulesStack(Stack):
    def __init__(self, scope: Construct, cid: str, **kw) -> None:
        super().__init__(scope, cid, **kw)
        with open(MANIFEST, encoding="utf-8") as f:
            manifest = json.load(f)

        evidence_bucket = CfnParameter(self, "EvidenceBucket", type="String")
        code_bucket = CfnParameter(self, "LambdaCodeS3Bucket", type="String")
        code_key = CfnParameter(self, "LambdaCodeS3Key", type="String")

        role = iam.Role(
            self, "EvidenceRuleRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[iam.ManagedPolicy.from_aws_managed_policy_name(
                "service-role/AWSLambdaBasicExecutionRole")],
        )
        role.add_to_policy(iam.PolicyStatement(
            actions=["s3:GetObject", "s3:GetObjectTagging"],
            resources=[f"arn:{Aws.PARTITION}:s3:::{evidence_bucket.value_as_string}/*"]))
        role.add_to_policy(iam.PolicyStatement(
            actions=["config:PutEvaluations"], resources=["*"]))

        code_src = s3.Bucket.from_bucket_name(
            self, "CodeBucket", code_bucket.value_as_string)
        fn = lambda_.Function(
            self, "EvidenceRuleFunction",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler=manifest["meta"]["handler"],
            timeout=Duration.seconds(30),
            role=role,
            code=lambda_.Code.from_bucket(code_src, code_key.value_as_string),
        )
        fn.add_permission(
            "ConfigInvoke",
            principal=iam.ServicePrincipal("config.amazonaws.com"),
            action="lambda:InvokeFunction")

        for rule in manifest["rules"]:
            config.CfnConfigRule(
                self, _cdk_id(rule["rule_name"]),
                config_rule_name=rule["rule_name"],
                description=f"{rule['ksi_id']}: {rule['evidence']}",
                input_parameters=json.dumps({
                    "evidence_bucket": evidence_bucket.value_as_string,
                    "evidence_key": f"{rule['rule_name']}/evidence",
                    "max_age_days": rule["default_max_age_days"],
                }),
                source=config.CfnConfigRule.SourceProperty(
                    owner="CUSTOM_LAMBDA",
                    source_identifier=fn.function_arn,
                    source_details=[config.CfnConfigRule.SourceDetailProperty(
                        event_source="aws.config",
                        message_type="ScheduledNotification",
                        maximum_execution_frequency="TwentyFour_Hours")]))


def _cdk_id(rule_name: str) -> str:
    return "".join(p.capitalize() for p in rule_name.split("-")) + "Rule"
'''

CDK_APP_TEMPLATE = '''\
#!/usr/bin/env python3
"""CDK app entry point. Generated by generate_templates.py.
  cdk deploy -c evidenceBucket=... (after `pip install aws-cdk-lib constructs`)
"""

from aws_cdk import App
from cdk_stack import EvidenceRulesStack

app = App()
EvidenceRulesStack(app, "FedrampSdrEvidenceRules")
app.synth()
'''


def write_all():
    import yaml
    manifest = load_manifest()
    cfn = build_cfn(manifest)
    with open(CFN_OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("# Generated by generate_templates.py from rules-manifest.json. "
                "Do not edit by hand.\n")
        yaml.safe_dump(cfn, f, sort_keys=False, default_flow_style=False)
    with open(CDK_STACK_OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(CDK_STACK_TEMPLATE)
    with open(CDK_APP_OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(CDK_APP_TEMPLATE)
    n = len(manifest["rules"])
    return n


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--stdout", action="store_true",
                    help="Print the CloudFormation template instead of writing files")
    args = ap.parse_args(argv)
    if args.stdout:
        import yaml
        print(yaml.safe_dump(build_cfn(load_manifest()), sort_keys=False))
        return 0
    n = write_all()
    print(f"Generated cloudformation.yaml (+{n} ConfigRules), cdk_stack.py, cdk_app.py")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
