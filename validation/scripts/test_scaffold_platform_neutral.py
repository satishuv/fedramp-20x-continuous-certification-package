#!/usr/bin/env python3
# Regression test for MCE-10: cloud-neutral SCG and CPO scaffolds.
#
# Grounded finding (2026-10-14): the story was written on the premise that the
# Secure Configuration Guide scaffold and the Certification Package Overview
# name AWS services a non-AWS offering does not have. Reading the generators
# showed both are already platform-neutral: build_scg.render and
# build_cpo.build_cpo / render_md take every fact from the offering profile and
# the pinned dataset and name no cloud product. This test pins that property so
# a later edit cannot quietly add one, and exercises the non-AWS shape the
# profile can express today (no partition, no regions, a neutral IaC value).
# The AWS-flavoured generated text lives elsewhere (the explainer notes layer
# that build_sdr copies into the SDR extension companion); that is MCE-16.
#
# Acceptance criteria exercised:
#   AC1  a profile shaped for another platform yields SCG sections with no AWS
#        service name, and this test asserts their absence (and the absence of
#        every other cloud vendor's name: the scaffold is a scaffold)
#   AC2  the AWS profile yields outputs byte-identical to the committed artifacts
#   AC3  every field the pinned CPO schema requires is present for both shapes
#
# Run: python validation/scripts/test_scaffold_platform_neutral.py

import copy
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
import build_scg  # noqa: E402
import build_cpo  # noqa: E402

_fail = 0
SCHEMA_DIR = os.path.join(BASE, "artifacts", "schemas", "official")
CPO_SCHEMA = "fedramp-certification-package-overview-schema-2026-06-24.json"

# Cloud product and vendor tokens that must not appear in a scaffold. Word-bound
# so that, for example, "IAM" does not match inside another word. Third-party
# names are limited to those THIRD_PARTY_NOTICE.md registers, so this file
# itself passes the naming guard; the scaffolds never say any of them, so a hit
# of any kind is a defect.
_VENDOR = re.compile(
    r"\b(AWS|Amazon|S3|KMS|CloudTrail|GuardDuty|Security Hub|CloudWatch|EC2|VPC|"
    r"Systems Manager|Inspector|IAM Identity Center|Google Cloud|Azure|Oracle Cloud|OCI)\b")


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _schema_errors(doc):
    import jsonschema
    from referencing import Registry, Resource
    schema = _load(os.path.join(SCHEMA_DIR, CPO_SCHEMA))
    common = _load(os.path.join(SCHEMA_DIR, "fedramp-common-definitions-schema-2026-06-24.json"))
    reg = Registry().with_resources([
        (schema["$id"], Resource.from_contents(schema)),
        (common["$id"], Resource.from_contents(common)),
    ])
    return [e.message for e in jsonschema.Draft202012Validator(schema, registry=reg).iter_errors(doc)]


def _non_aws_shape(profile):
    """The non-AWS offering the profile can express today: no partition, no
    AWS regions, a neutral infrastructure-as-code value. Every other fact is
    the provider's own and platform-free."""
    p = copy.deepcopy(profile)
    for k in ("aws_partition", "primary_region", "dr_region"):
        p.pop(k, None)
    p["iac_technology"] = "Declarative infrastructure definitions (provider-chosen tool)"
    p["offering_name"] = "Harbor Records Service (fictional)"
    p["business_purpose"] = "A fictional records-management service hosted on the provider's own platform."
    return p


print("MCE-10: cloud-neutral SCG and CPO scaffolds")

aws_profile = _load(build_scg.PROFILE)
other_profile = _non_aws_shape(aws_profile)

# ---- AC1: no vendor name in the SCG for the non-AWS shape (and the AWS one) --
for label, prof in (("AWS template profile", aws_profile), ("non-AWS-shaped profile", other_profile)):
    scg = build_scg.render(prof)
    hits = sorted(set(m.group(0) for m in _VENDOR.finditer(scg)))
    check(f"SCG scaffold for the {label} names no cloud product or vendor (hits: {hits})", not hits)
    check(f"SCG scaffold for the {label} keeps every SCG-CSO-RSC / SCG-CSO-AUP section",
          all(h in scg for h in ("## Recommendations for secure configuration (SCG-CSO-RSC)",
                                 "## Customer responsibilities",
                                 "## Use instructions (SCG-CSO-AUP)",
                                 "## Change and version history")))
    check(f"SCG scaffold for the {label} states it is not a compliance claim",
          "not a compliance claim" in scg and "not a compliance determination" in scg)

scg_other = build_scg.render(other_profile)
check("the non-AWS SCG carries the provider's own neutral IaC value, not an AWS default",
      "Declarative infrastructure definitions (provider-chosen tool)" in scg_other
      and "Terraform" not in scg_other)

# ---- AC3: every pinned-schema-required CPO field present for both shapes -----
for label, prof in (("AWS template profile", aws_profile), ("non-AWS-shaped profile", other_profile)):
    doc = build_cpo.build_cpo(prof)
    errs = _schema_errors(doc)
    check(f"CPO for the {label} is valid against the pinned CPO schema (errors: {errs[:2]})", not errs)
    rendered = build_cpo.render_md(prof, doc)
    blob = json.dumps(doc, ensure_ascii=False) + "\n" + rendered
    hits = sorted(set(m.group(0) for m in _VENDOR.finditer(blob)))
    check(f"CPO JSON and rendering for the {label} name no cloud product or vendor (hits: {hits})",
          not hits)

# The non-AWS shape must not degrade the CPO relative to the AWS shape: same
# top-level members, same set of CDS-CSO-PUB required-information keys.
doc_aws = build_cpo.build_cpo(aws_profile)
doc_other = build_cpo.build_cpo(other_profile)
check("the non-AWS CPO has the same top-level members as the AWS CPO",
      set(doc_aws) == set(doc_other))
_ri_aws = doc_aws.get("requiredInformation") or doc_aws.get("required_information") or {}
_ri_other = doc_other.get("requiredInformation") or doc_other.get("required_information") or {}
check("the non-AWS CPO carries the same required-information keys as the AWS CPO",
      (set(_ri_aws) == set(_ri_other)) if isinstance(_ri_aws, dict) and isinstance(_ri_other, dict)
      else type(_ri_aws) is type(_ri_other))

# ---- AC2: the AWS profile reproduces the committed artifacts byte for byte ---
with open(build_scg.OUT_MD, encoding="utf-8", newline="") as fh:
    committed_scg = fh.read()
check("SCG for the AWS profile is byte-identical to the committed package/scg artifact",
      build_scg.render(aws_profile) == committed_scg)
with open(build_cpo.OUT_JSON, encoding="utf-8") as fh:
    committed_cpo = json.load(fh)
check("CPO JSON for the AWS profile equals the committed package/cpo/cpo.json",
      doc_aws == committed_cpo)
with open(build_cpo.OUT_MD, encoding="utf-8", newline="") as fh:
    committed_cpo_md = fh.read()
check("CPO rendering for the AWS profile is byte-identical to the committed package/cpo/cpo.md",
      build_cpo.render_md(aws_profile, doc_aws) == committed_cpo_md)

# ---- The generators themselves carry no vendor name in emitted text ----------
for mod in (build_scg, build_cpo):
    with open(mod.__file__, encoding="utf-8") as fh:
        src = fh.read()
    # Strip comments and docstrings loosely: only string literals matter for
    # emitted text, so scan the whole file and report what it finds.
    hits = sorted(set(m.group(0) for m in _VENDOR.finditer(src)))
    check(f"{os.path.basename(mod.__file__)} source contains no cloud product or vendor token (hits: {hits})",
          not hits)

print(f"\n{'FAIL' if _fail else 'PASS'}: {_fail} failing check(s)")
sys.exit(1 if _fail else 0)
