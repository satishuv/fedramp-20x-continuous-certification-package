#!/usr/bin/env python3
# Regression test for MCE-09 / AUD-F73: the evidence store the package expects,
# stated as PROPERTIES with one attestation each (sdr.EVIDENCE_STORE_PROPERTIES,
# sdr.evidence_store_attestation_findings).
#
# Finding closed here: `evidence_store_profile: production-assurance` was the
# provider's whole declaration of a tamper-evident store, a single word with no
# field behind it, and the only guidance on what the store had to be named one
# storage product. A provider on another platform had nothing to attest and
# nothing platform-neutral to read. Now the profile carries one attestation per
# property (versioned, write-once, separately administered, retention period,
# access logging), preflight reports an absent attestation as a READINESS
# finding worded as an expectation, and a production-assurance declaration with
# neither versioning nor write-once attested is the one blocker.
#
# Acceptance criteria exercised:
#   AC1  the properties are documented as properties, the AWS guidance sits under
#        an AWS implementation heading, and no property names a product
#   AC2  a declared store needs one attestation per property and no vendor name
#   AC3  an absent attestation is a finding worded as an expectation, never a
#        compliance determination
#
# Run: python validation/scripts/test_evidence_store_properties.py

import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
import sdr  # noqa: E402
import profile_contract as pc  # noqa: E402

_fail = 0

# Storage product names that must never appear in the property statements:
# the package asks what the store DOES, not which product does it.
_PRODUCT_TOKENS = ("s3", "amazon", "aws", "object lock", "bucket", "kms", "blob", "gcs",
                   "cloud storage", "oci", "azure", "google")
# Words that would turn an expectation into a determination.
_DETERMINATION = re.compile(r"\b(compliant|non-?compliant|satisfies|meets|violat\w*|"
                            r"fails? the (control|requirement))\b", re.I)


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def _full(**over):
    block = {"versioned": True, "write_once": True, "separately_administered": True,
             "retention_days": 400, "access_logging": True, "implementation": ""}
    block.update(over)
    return {"evidence_store_profile": "development", "evidence_store": block}


print("MCE-09 / AUD-F73: evidence store requirements as properties")

# ---- AC1: properties, not products -------------------------------------------
keys = [k for k, _, _ in sdr.EVIDENCE_STORE_PROPERTIES]
check("the five expected properties are defined once",
      keys == ["versioned", "write_once", "separately_administered", "retention_days",
               "access_logging"])
for key, expectation, _kind in sdr.EVIDENCE_STORE_PROPERTIES:
    low = expectation.lower()
    check(f"property {key}: its statement names no storage product",
          not any(tok in low for tok in _PRODUCT_TOKENS))

doc_path = os.path.join(BASE, "docs", "automation.md")
with open(doc_path, encoding="utf-8") as fh:
    doc = fh.read()
check("docs/automation.md states the store as properties under its own heading",
      "### The evidence store: properties the package expects" in doc)
check("docs/automation.md keeps the S3 guidance under an AWS implementation heading",
      "### AWS implementation of the store" in doc)
_props_start = doc.find("### The evidence store: properties the package expects")
_aws_start = doc.find("### AWS implementation of the store")
check("the properties section comes BEFORE the AWS implementation section",
      0 <= _props_start < _aws_start)
_props_text = doc[_props_start:_aws_start].lower()
check("the properties section names every property",
      all(k in _props_text for k in keys))
check("the properties section names no storage product (products live under the AWS heading)",
      not any(tok in _props_text for tok in ("amazon s3", "object lock", "bucket", "kms")))

# ---- AC2: one attestation per property, no vendor name -----------------------
check("evidence_store is an accepted optional profile field",
      "evidence_store" in pc.OPTIONAL_FIELDS)
with open(os.path.join(BASE, "profiles", "common", "offering-profile.json"), encoding="utf-8") as fh:
    template = json.load(fh)
tmpl_block = template.get("evidence_store")
check("the template profile carries an evidence_store block", isinstance(tmpl_block, dict))
check("the template block has exactly one field per property (plus note and implementation)",
      isinstance(tmpl_block, dict)
      and set(tmpl_block) == set(keys) | {"note", "implementation"})
check("the template block requires no vendor name (implementation is free text, empty is fine)",
      isinstance(tmpl_block, dict) and tmpl_block.get("implementation") == ""
      and not any(tok in str(tmpl_block.get(k, "")).lower()
                  for k in keys for tok in ("amazon s3", "bucket", "kms", "azure", "google", "oci")))

full = _full()
check("a fully attested store (no vendor named anywhere) yields no finding",
      sdr.evidence_store_attestation_findings(full) == [])
check("a fully attested store yields no finding under production-assurance either",
      sdr.evidence_store_attestation_findings(full, production=True) == [])

tmpl_findings = sdr.evidence_store_attestation_findings(template)
check("the template's TBD attestations yield exactly one 'absent' finding per property",
      [k for kind, k, _ in tmpl_findings if kind == "absent"] == keys
      and all(kind == "absent" for kind, _, _ in tmpl_findings))

# ---- AC3: absent -> expectation finding, never a determination ---------------
for key, _exp, kind in sdr.EVIDENCE_STORE_PROPERTIES:
    prof = _full()
    del prof["evidence_store"][key]
    found = sdr.evidence_store_attestation_findings(prof)
    check(f"absent {key}: exactly one finding, kind 'absent', naming the key",
          len(found) == 1 and found[0][0] == "absent" and found[0][1] == key
          and f"evidence_store.{key}" in found[0][2])
    check(f"absent {key}: worded as what the package EXPECTS, not a determination",
          found[0][2].startswith("the package expects")
          and not _DETERMINATION.search(found[0][2]))
    # A placeholder string (the template's TBD) is absent, not an attestation.
    prof = _full(**{key: "TBD: fill me"})
    found = sdr.evidence_store_attestation_findings(prof)
    check(f"TBD string for {key} counts as absent, never as attested",
          len(found) == 1 and found[0][0] == "absent" and found[0][1] == key)

# Booleans: an explicit false is an honest attestation that the property does
# not hold; still a finding, still an expectation, never a blocker by itself.
for key in ("versioned", "write_once", "separately_administered", "access_logging"):
    found = sdr.evidence_store_attestation_findings(_full(**{key: False}))
    check(f"{key}: false is reported as 'unattested' with expectation wording",
          len(found) == 1 and found[0][0] == "unattested" and found[0][1] == key
          and found[0][2].startswith("the package expects")
          and not _DETERMINATION.search(found[0][2]))

# Retention: whole days >= 1; a bool, zero, negative or string is absent.
for bad in (0, -5, True, "365", 12.5, None):
    found = sdr.evidence_store_attestation_findings(_full(retention_days=bad))
    check(f"retention_days={bad!r} is not an attestation",
          len(found) == 1 and found[0][0] == "absent" and found[0][1] == "retention_days")
check("retention_days=1 is the smallest valid attestation",
      sdr.evidence_store_attestation_findings(_full(retention_days=1)) == [])

# No block at all: one finding under development, and under production-assurance
# the declaration of a tamper-evident store has nothing behind it.
none = {"evidence_store_profile": "development"}
found = sdr.evidence_store_attestation_findings(none)
check("no evidence_store block: one 'absent' finding naming the block",
      len(found) == 1 and found[0][0] == "absent" and found[0][1] == "evidence_store"
      and found[0][2].startswith("the package expects"))
found = sdr.evidence_store_attestation_findings(none, production=True)
check("no evidence_store block under production-assurance adds the contradiction",
      [k for k, _, _ in found] == ["absent", "contradiction"])

# Contradiction: production-assurance + neither versioning nor write-once.
found = sdr.evidence_store_attestation_findings(_full(versioned=False, write_once=False),
                                                production=True)
check("production-assurance with versioned=false AND write_once=false is a contradiction",
      any(k == "contradiction" for k, _, _ in found))
found = sdr.evidence_store_attestation_findings(_full(versioned=False, write_once=False))
check("the same attestations under the development profile are findings only",
      all(k == "unattested" for k, _, _ in found) and len(found) == 2)
for keep in ("versioned", "write_once"):
    other = "write_once" if keep == "versioned" else "versioned"
    found = sdr.evidence_store_attestation_findings(_full(**{other: False}), production=True)
    check(f"production-assurance with only {keep} attested true is NOT a contradiction",
          not any(k == "contradiction" for k, _, _ in found))
found = sdr.evidence_store_attestation_findings(_full(versioned=False, write_once=False),
                                                production=True)
check("the contradiction message names the declaration, not a compliance verdict",
      all(not _DETERMINATION.search(m) for _, _, m in found)
      and any("production-assurance" in m for k, _, m in found if k == "contradiction"))

# ---- Preflight wiring: findings are warnings, the contradiction is a blocker --
with open(os.path.join(BASE, "sdr.py"), encoding="utf-8") as fh:
    src = fh.read()
_call = src.find("evidence_store_attestation_findings(offering, production=_production)")
check("preflight calls the helper with the live production flag", _call > 0)
_wiring = src[_call:_call + 700]
check("preflight routes 'contradiction' to blockers and everything else to warnings",
      'if _kind == "contradiction":' in _wiring
      and "blockers.append" in _wiring and "warnings.append" in _wiring)
check("the preflight warning says the assessor assesses the store (advisory wording)",
      "the assessor assesses the store" in _wiring and "advisory" in _wiring)

# ---- The fictional Class C sample attests every property --------------------
sample_src_path = os.path.join(BASE, "examples", "sample-offering-class-c", "build_class_c_sample.py")
with open(sample_src_path, encoding="utf-8") as fh:
    sample_src = fh.read()
check("the Class C sample builder attests every store property",
      all(f'"{k}":' in sample_src for k in keys))
check("the Class C sample carries the production-assurance contradiction probe",
      "_production_store_attests_no_tamper_evidence" in sample_src)

print(f"\n{'FAIL' if _fail else 'PASS'}: {_fail} failing check(s)")
sys.exit(1 if _fail else 0)
