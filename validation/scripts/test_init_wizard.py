# Tests for the `sdr.py init` offering-profile wizard (Max's feature).
# Uses an ISOLATED temp profile so no tracked file is mutated (audit RULE 9).
#
#   python validation/scripts/test_init_wizard.py

import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import types

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
import sdr  # noqa: E402
import profile_contract as pc  # noqa: E402

_fail = 0


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def _tmp_profile():
    d = tempfile.mkdtemp()
    p = os.path.join(d, "offering-profile.json")
    shutil.copyfile(sdr.OFFERING_PROFILE, p)
    return p


def _args(**kw):
    a = types.SimpleNamespace(non_interactive=True, set=None)
    for k, v in kw.items():
        setattr(a, k, v)
    return a


def _run_with_profile(profile_path, args):
    orig = sdr.OFFERING_PROFILE
    sdr.OFFERING_PROFILE = profile_path
    try:
        return sdr.cmd_init(args)
    finally:
        sdr.OFFERING_PROFILE = orig


def test_set_writes_fields():
    p = _tmp_profile()
    rc = _run_with_profile(p, _args(set=["organization_name=Contoso Federal",
                                         "certification_class=c"]))
    prof = json.load(open(p, encoding="utf-8"))
    check("init --set returns 0", rc == 0)
    check("organization_name written", prof["organization_name"] == "Contoso Federal")
    check("certification_class written", prof["certification_class"] == "c")


def test_invalid_class_rejected_no_write():
    p = _tmp_profile()
    before = open(p, encoding="utf-8").read()
    rc = _run_with_profile(p, _args(set=["certification_class=z"]))
    after = open(p, encoding="utf-8").read()
    check("invalid class returns non-zero", rc == 1)
    check("invalid class writes nothing", before == after)


def test_result_profile_is_valid_json():
    p = _tmp_profile()
    _run_with_profile(p, _args(set=["offering_name=Widget Cloud"]))
    try:
        json.load(open(p, encoding="utf-8"))
        ok = True
    except ValueError:
        ok = False
    check("written profile is valid JSON", ok)


def test_no_values_leaves_profile_unchanged():
    p = _tmp_profile()
    before = open(p, encoding="utf-8").read()
    rc = _run_with_profile(p, _args(set=[]))
    after = open(p, encoding="utf-8").read()
    check("no values returns 0", rc == 0)
    check("no values leaves profile byte-identical", before == after)


# ---- The contract-driven wizard (profile_contract is the one definition) -------

def _capture(fn):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = fn()
    return rc, buf.getvalue()


def test_every_required_question_is_asked():
    """The wizard's question list IS the contract's REQUIRED_FIELDS, in order,
    so a field preflight blocks on is always a field the wizard asked for."""
    asked = [k for k, _q in sdr.INIT_QUESTIONS]
    required = [k for k, _src, _q in pc.REQUIRED_FIELDS]
    check("wizard asks exactly the contract's required fields, in order", asked == required)
    check("contract has no required field without a FedRAMP source",
          all(src.startswith(("cpo:", "cr26:")) or len(src.split("-")) == 3
              for _k, src, _q in pc.REQUIRED_FIELDS))


def test_gap_report_lists_every_unanswered_required_field():
    p = _tmp_profile()
    rc, text = _capture(lambda: _run_with_profile(p, _args(set=[])))
    prof = json.load(open(p, encoding="utf-8"))
    expected = [f for f, _src in pc.required_gaps(prof)]
    check("gap report names every unanswered required field",
          all(f"  - {f}  [" in text for f in expected))
    expected_blocks = [(b, m) for b, _s, missing in pc.class_gaps(prof) for m in missing]
    check("gap report names every unanswered class-conditional sub-field",
          all((f"  - {b}.{m}  [" in text) or (b == m and f"  - {m}  [" in text)
              for b, m in expected_blocks))
    check("gap report shows Class B at the template default", "for Class B" in text)


def test_invalid_shapes_are_refused_and_nothing_is_written():
    p = _tmp_profile()
    before = open(p, encoding="utf-8").read()
    rc, text = _capture(lambda: _run_with_profile(p, _args(set=[
        "deployment_model=GovCloud",         # not a CPO deploymentModel enum value
        "assessor_id=12345",                 # schema pattern is exactly 6 digits
        "offering_website=notaurl",          # URL field
        "next_ocr_date=31/12/2026",          # date field
        "fedramp_independent_assessment.completed_at=yesterday",
        "organization_name=Would Be Written If Any Answer Were Accepted",
    ])))
    after = open(p, encoding="utf-8").read()
    check("invalid answers return 1", rc == 1)
    check("one invalid answer blocks the whole write (profile byte-identical)", before == after)
    for key in ("deployment_model", "assessor_id", "offering_website", "next_ocr_date",
                "fedramp_independent_assessment.completed_at"):
        check(f"error names {key}", f"  - {key}:" in text)


def test_enum_answers_are_normalized_to_schema_tokens():
    """build_cpo.py silently assumes a value for anything outside the CPO enum,
    so the wizard must store the exact schema token."""
    p = _tmp_profile()
    rc = _run_with_profile(p, _args(set=["service_model=saas",
                                         "deployment_model=government community cloud",
                                         "certification_class=C"]))
    prof = json.load(open(p, encoding="utf-8"))
    check("service_model normalized to 'SaaS'", prof["service_model"] == "SaaS")
    check("deployment_model normalized to the schema enum token",
          prof["deployment_model"] == "Government Community Cloud")
    check("certification_class lower-cased", prof["certification_class"] == "c")


def test_contacts_are_structured_and_nested_blocks_keep_their_notes():
    p = _tmp_profile()
    rc = _run_with_profile(p, _args(set=[
        "security_contact.name=Security Operations", "security_contact.email=sec@x.example",
        "sales_contact=Federal Sales <sales@x.example>",
        "fedramp_independent_assessment.assessor_name=Acme Assessors",
        "fedramp_independent_assessment.completed_at=2026-09-20",
        "availability_reporting.human_readable_uri=https://status.x.example/",
    ]))
    prof = json.load(open(p, encoding="utf-8"))
    check("dotted contact answers become a {name, email} object",
          prof["security_contact"] == {"name": "Security Operations", "email": "sec@x.example"})
    check("a plain 'Name <email>' contact string is kept as given",
          prof["sales_contact"] == "Federal Sales <sales@x.example>")
    fia = prof["fedramp_independent_assessment"]
    check("nested answers land inside the block", fia["assessor_name"] == "Acme Assessors"
          and fia["completed_at"] == "2026-09-20")
    check("the block's note and unanswered sub-fields survive",
          "note" in fia and str(fia["assessment_report_sha256"]).startswith("TBD"))
    check("availability_reporting keeps history_days untouched",
          str(prof["availability_reporting"]["history_days"]).startswith("TBD"))


def test_class_decides_which_blocks_are_required():
    p = _tmp_profile()
    rc, text_a = _capture(lambda: _run_with_profile(p, _args(set=["certification_class=a"])))
    check("Class A asks the alternative-framework block (FRC-CLA-ASF)",
          "external_assessment.framework  [FRC-CLA-ASF]" in text_a
          and "external_assessment.assessment_date  [FRC-CLA-ASF]" in text_a)
    check("Class A does not require the FedRAMP independent assessment (FRC-APP-FIA is MAY)",
          "FRC-APP-FIA" not in text_a)
    check("Class A does not require availability reporting (CDS-CSO-AVR is SHOULD)",
          "CDS-CSO-AVR" not in text_a)
    check("Class A does not require CPO metadata (CPO-CSO-MTD does not resolve for Class A)",
          "CPO-CSO-MTD" not in text_a)
    check("a framework outside FRC-CLA-ASF is refused (SOC 2 Type I is not eligible)",
          _run_with_profile(p, _args(set=["external_assessment.framework=SOC 2 Type I"])) == 1)
    check("an FRC-CLA-ASF framework is accepted",
          _run_with_profile(p, _args(set=["external_assessment.framework=SOC 2 Type II"])) == 0)
    rc, text_c = _capture(lambda: _run_with_profile(p, _args(set=["certification_class=c"])))
    check("Class C requires FRC-APP-FIA", "fedramp_independent_assessment.assessor_name  [FRC-APP-FIA]" in text_c)
    check("FRC-APP-FIA asks who and when only (name, Recognition id, date)",
          [s for s, _q in dict((b, q) for b, _s, _c, q in pc.CLASS_CONDITIONAL)["fedramp_independent_assessment"]]
          == ["assessor_name", "assessor_fedramp_id", "completed_at"])
    check("Class C requires CPO-CSO-OSA", "overall_assessment_summary  [CPO-CSO-OSA]" in text_c)
    check("Class C requires CDS-CSO-AVR", "availability_reporting.human_readable_uri  [CDS-CSO-AVR]" in text_c)
    check("Class C requires all four CPO-CSO-MTD items",
          all(f"cpo_metadata.{k}  [CPO-CSO-MTD]" in text_c
              for k in ("cpo_responsible_official", "cpo_version", "cpo_last_updated", "cpo_source_of_update")))
    check("Class C does not ask the Class A block", "FRC-CLA-ASF" not in text_c)


def test_fully_answered_profile_has_no_contract_gaps():
    """A complete scripted run must leave required_gaps and class_gaps empty,
    which is exactly what package-preflight's profile blockers are built from."""
    p = _tmp_profile()
    sets = [
        "organization_name=Contoso Federal LLC", "offering_name=Contoso Gov Analytics",
        "offering_abbreviation=CGA", "business_purpose=Analytics for agencies.",
        "service_model=SaaS", "deployment_model=Government Community Cloud",
        "certification_type=FedRAMP 20x", "certification_class=b",
        "fedramp_package_id=F2026123456", "offering_website=https://contoso.example/cga",
        "offering_logo_uri=https://contoso.example/cga/logo.png",
        "security_contact.name=Security Operations", "security_contact.email=security@contoso.example",
        "sales_contact.name=Federal Sales", "sales_contact.email=fedsales@contoso.example",
        "assessor=Acme Assessors LLC", "assessor_id=123456", "next_ocr_date=2027-01-15",
        "uei_number=ABC123DEF456", "business_category=analytics, Data Management",
        "documentation_overview=Admin guide, API reference and SCG on the trust center.",
        "certification_package_overview_uri=https://trust.contoso.example/cpo.json",
        "trust_center_uri=https://trust.contoso.example/",
        "secure_config_guide_uri=https://trust.contoso.example/scg",
        "provider_verified_at=now",
        "fedramp_independent_assessment.assessor_name=Acme Assessors LLC",
        "fedramp_independent_assessment.assessor_fedramp_id=123456",
        "fedramp_independent_assessment.completed_at=2026-09-20",
        "overall_assessment_summary=The assessor's summary text, supplied verbatim.",
        "availability_reporting.human_readable_uri=https://status.contoso.example/",
        "availability_reporting.machine_readable_uri=https://status.contoso.example/feed.json",
        "cpo_responsible_official=Jane Doe, CISO, jane@contoso.example", "cpo_version=1.0",
        "cpo_last_updated=now", "cpo_source_of_update=Compliance team",
    ]
    rc, text = _capture(lambda: _run_with_profile(p, _args(set=sets)))
    prof = json.load(open(p, encoding="utf-8"))
    check("full run returns 0", rc == 0)
    check("no required gaps remain", pc.required_gaps(prof) == [])
    check("no class-conditional gaps remain", pc.class_gaps(prof) == [])
    check("wizard reports every required field answered",
          "Every FedRAMP-required profile field is answered for Class B" in text)
    check("'now' became an ISO-8601 UTC datetime",
          prof["provider_verified_at"].endswith("+00:00"))
    check("business categories stored as the schema's enum list",
          prof["business_category"] == ["Analytics", "Data Management"])
    check("a free-text business category is refused",
          _run_with_profile(p, _args(set=["business_category=Widgets"])) == 1)


def test_wizard_never_asks_what_the_tool_may_not_decide():
    asked = {k for k, _q in sdr.INIT_QUESTIONS}
    asked |= {sub for _b, _s, _c, qs in pc.CLASS_CONDITIONAL for sub, _q in qs}
    forbidden = {"implementation_status", "assessment", "status", "compliant"}
    check("no question is about implementation status or the assessor's assessment",
          not (asked & forbidden))
    check("no operational field without a FedRAMP source is asked",
          not (asked & {"primary_region", "dr_region", "aws_partition", "iac_technology",
                        "incident_contact"}))


def main():
    for t in (test_set_writes_fields, test_invalid_class_rejected_no_write,
              test_result_profile_is_valid_json,
              test_no_values_leaves_profile_unchanged,
              test_every_required_question_is_asked,
              test_gap_report_lists_every_unanswered_required_field,
              test_invalid_shapes_are_refused_and_nothing_is_written,
              test_enum_answers_are_normalized_to_schema_tokens,
              test_contacts_are_structured_and_nested_blocks_keep_their_notes,
              test_class_decides_which_blocks_are_required,
              test_fully_answered_profile_has_no_contract_gaps,
              test_wizard_never_asks_what_the_tool_may_not_decide):
        print(t.__name__)
        t()
    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: init wizard ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
