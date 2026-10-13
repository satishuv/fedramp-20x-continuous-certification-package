#!/usr/bin/env python3
"""Class scope of the offering-profile contract (AUD-F51) and the policy that a
CDS-CSO-PUB listing never makes a field unconditional on its own (AUD-F52).

Every exemption and every backing the contract declares is checked against the
sources that justify it, not against the contract's own words:

  * the engine's class profiles (profiles/class-<x>/profile.json) say which
    classes resolve SCG-CSO-RSC;
  * the pinned CR26 dataset says FRC-APP-FIA's force per class and whether
    CDS-CSO-PUB qualifies its items as "available and applicable";
  * the official CPO schema says which members are required.

Then the behaviour: a Class A profile with no FedRAMP Recognized assessor and
no Secure Configuration Guide has no profile gap, publishes an explicit
not-applicable statement for both CDS-CSO-PUB items, and builds a schema-valid
CPO without the two optional members; Class B/C still block on both.
"""
import copy
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, BASE)

import profile_contract as pc  # noqa: E402
import build_cpo  # noqa: E402
import sdr  # noqa: E402  (artifact-wording markers: one definition)

DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
CPO_SCHEMA = os.path.join(BASE, "artifacts", "schemas", "official",
                          "fedramp-certification-package-overview-schema-2026-06-24.json")
COMMON_SCHEMA = os.path.join(BASE, "artifacts", "schemas", "official",
                             "fedramp-common-definitions-schema-2026-06-24.json")
TEMPLATE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
CLASSES = ("a", "b", "c")

PASS = FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}" + (f": {detail}" if detail else ""))


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def find_rule(node, rid):
    if isinstance(node, dict):
        if rid in node and isinstance(node[rid], dict):
            return node[rid]
        for v in node.values():
            r = find_rule(v, rid)
            if r is not None:
                return r
    return None


def class_rule_ids(cls):
    rules = load(os.path.join(BASE, "profiles", f"class-{cls}", "profile.json")).get("rules") or []
    if isinstance(rules, dict):
        return set(rules.keys())
    return {r.get("rule_id") for r in rules if isinstance(r, dict)}


def rule_force_at(rule, cls):
    vbc = rule.get("varies_by_class") or {}
    if cls in vbc and isinstance(vbc[cls], dict):
        return vbc[cls].get("force")
    return rule.get("force")


def filled_profile(cls, **overrides):
    """A fully answered profile at `cls` (every REQUIRED field real), then overrides."""
    prof = load(TEMPLATE)
    prof.update({
        "certification_class": cls,
        "organization_name": "Contoso Federal Cloud LLC",
        "offering_name": "Contoso Secure Platform",
        "offering_abbreviation": "CSP",
        "business_purpose": "A fictional government-only PaaS.",
        "service_model": "PaaS",
        "deployment_model": "Government-Only Cloud",
        "certification_type": "FedRAMP 20x",
        "fedramp_package_id": "FR-2026-CSP-0001",
        "offering_website": "https://contoso.gov",
        "offering_logo_uri": "https://contoso.gov/logo.png",
        "security_contact": {"name": "Contoso Security Operations", "email": "security@contoso.gov"},
        "sales_contact": {"name": "Contoso Federal Sales", "email": "sales@contoso.gov"},
        "assessor": "Acme FedRAMP Assessors LLC",
        "assessor_id": "482913",
        "next_ocr_date": "2027-01-15",
        "uei_number": "J7X9QK2M4N81",
        "business_category": ["Data Management"],
        "documentation_overview": "User guide and API reference at https://contoso.gov/docs.",
        "certification_package_overview_uri": "https://contoso.gov/cpo.json",
        "trust_center_uri": "https://contoso.gov/trust",
        "secure_config_guide_uri": "https://contoso.gov/scg",
        "selected_optional_rules": [],
        "external_assessment": {"framework": "SOC 2 Type II", "assessment_date": "2026-08-01"},
    })
    prof.update(overrides)
    return prof


def gap_fields(prof):
    return [f for f, _src in pc.required_gaps(prof)]


def cpo_schema_errors(doc):
    import jsonschema
    from referencing import Registry, Resource
    schema = load(CPO_SCHEMA)
    common = load(COMMON_SCHEMA)
    registry = Registry().with_resources([
        (schema["$id"], Resource.from_contents(schema)),
        (common["$id"], Resource.from_contents(common)),
    ])
    v = jsonschema.Draft202012Validator(schema, registry=registry)
    return [f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message[:120]}" for e in v.iter_errors(doc)]


def main():
    ds = load(DATASET)
    schema = load(CPO_SCHEMA)
    sources = {f: src for f, src, _q in pc.REQUIRED_FIELDS}

    print("== AUD-F51: every class exemption is a dataset / engine fact")
    # Rule-sourced exemptions: the rule resolves exactly at the non-exempt classes.
    for field, exempt in pc.FIELD_CLASS_EXEMPT.items():
        src = sources[field]
        if src.startswith("cpo:") or src == "CDS-CSO-PUB":
            continue
        for cls in CLASSES:
            applies = src in class_rule_ids(cls)
            check(f"{field}: {src} {'resolves' if applies else 'does not resolve'} at Class "
                  f"{cls.upper()} and the contract {'requires' if cls not in exempt else 'exempts'} it",
                  applies == (cls not in exempt))
    # The FIA-backed fields: exempt exactly where FRC-APP-FIA is MAY.
    fia = find_rule(ds, "FRC-APP-FIA")
    for field in pc.FIA_SELECTED_FIELDS:
        exempt = pc.FIELD_CLASS_EXEMPT.get(field, ())
        for cls in CLASSES:
            force = rule_force_at(fia, cls)
            check(f"{field}: FRC-APP-FIA is {force} at Class {cls.upper()}, contract "
                  f"{'exempts' if cls in exempt else 'requires'}",
                  (force == "MAY") == (cls in exempt))
    check("exemption is fail-closed for an unknown class",
          pc.field_required_at("secure_config_guide_uri", {"certification_class": "d"})
          and pc.field_required_at("assessor", {"certification_class": "zz"})
          and pc.field_required_at("assessor_id", {"certification_class": ""}))
    # The package manifest's class scope is prose; the letters are tokens.
    check("manifest 'Class B and C' is required at B and C and NOT at A "
          "(the A in CLASS and AND is not a class)",
          sdr.manifest_component_required("Class B and C", "b")
          and sdr.manifest_component_required("Class B and C", "c")
          and not sdr.manifest_component_required("Class B and C", "a")
          and not sdr.manifest_component_required("Class B and C", "d"))
    check("manifest 'Class A' is required at A only; True at every class; None nowhere",
          sdr.manifest_component_required("Class A", "a")
          and not sdr.manifest_component_required("Class A", "b")
          and sdr.manifest_component_required(True, "a")
          and not sdr.manifest_component_required(None, "c"))
    manifest = load(os.path.join(BASE, "package", "certification-package-manifest.json"))
    scg_req = manifest["certification_package"]["secure_configuration_guide"]["required_for_initial_package"]
    check("the committed manifest scopes the SCG component to exactly the classes where "
          "SCG-CSO-RSC resolves",
          all(sdr.manifest_component_required(scg_req, c) == ("SCG-CSO-RSC" in class_rule_ids(c))
              for c in CLASSES))

    print("== AUD-F52: a CDS-CSO-PUB listing never makes a field unconditional by itself")
    pub = find_rule(ds, "CDS-CSO-PUB")
    check("CDS-CSO-PUB still qualifies its items as 'available and applicable' "
          "(if FedRAMP drops the qualifier this policy needs review)",
          "available and applicable" in str(pub.get("statement")))
    for field, src in sources.items():
        if src != "CDS-CSO-PUB":
            continue
        identity = field in pc.IDENTITY_REQUIRED
        if not identity:
            check(f"{field} (CDS-CSO-PUB, no backing MUST) accepts a justified N/A",
                  not pc.required_gaps(filled_profile("b", **{field: "N/A: none exists for this offering"})))
            continue
        backing = pc.CDS_CSO_PUB_BACKING.get(field)
        check(f"{field} is identity-required, so it names a backing MUST requirement", backing is not None)
        if not backing:
            continue
        rid, part = backing
        rule = find_rule(ds, rid)
        check(f"{field}: backing rule {rid} exists in the dataset", rule is not None)
        if rule is None:
            continue
        if part == "artifact":
            arts = [s for v in (rule.get("artifacts") or {}).values() for s in (v or [])]
            unconditional = [s for s in arts
                             if not any(m in s.lower() for m in sdr._ARTIFACT_CONDITIONAL_MARKERS)]
            check(f"{field}: {rid} carries an unconditional artifact backing the item "
                  f"and is MUST at every class",
                  bool(unconditional) and all(rule_force_at(rule, c) == "MUST" for c in CLASSES))
        elif part == "force":
            for cls in CLASSES:
                required = pc.field_required_at(field, {"certification_class": cls})
                check(f"{field}: identity-required at Class {cls.upper()} iff {rid} is MUST there",
                      required == (rule_force_at(rule, cls) == "MUST"))
    # The one cpo:-sourced field whose schema member is optional must be class-scoped.
    top_required = set(schema.get("required") or [])
    for field, src in sources.items():
        if not src.startswith("cpo:"):
            continue
        obj = src[len("cpo:"):].split(".")[0].split("[")[0]
        member = src[len("cpo:"):].split(".")[1] if "." in src else None
        obj_required = obj in top_required
        member_required = (member is None
                           or member in set((schema["properties"][obj].get("required") or [])))
        unconditional = field not in pc.FIELD_CLASS_EXEMPT
        if obj_required and member_required:
            check(f"{field}: schema requires {src}, contract requires it at every class",
                  unconditional)
        else:
            check(f"{field}: schema does NOT require {src} ({obj} optional), so the contract "
                  "must scope it by class",
                  not unconditional)

    print("== behaviour: profile gaps by class")
    for cls in ("b", "c"):
        gaps = gap_fields(filled_profile(cls, secure_config_guide_uri="TBD: not yet published"))
        check(f"Class {cls.upper()} without an SCG URL has the gap", gaps == ["secure_config_guide_uri"])
        gaps = gap_fields(filled_profile(cls, assessor="TBD", assessor_id="TBD"))
        check(f"Class {cls.upper()} without a FedRAMP assessor has both gaps",
              gaps == ["assessor", "assessor_id"])
        gaps = gap_fields(filled_profile(cls, assessor="N/A: alternative framework only"))
        check(f"Class {cls.upper()} assessor refuses a justified N/A (identity-required)",
              gaps == ["assessor"])
    a_no_scg = filled_profile("a", secure_config_guide_uri="TBD: not published")
    check("Class A without an SCG URL has no gap (SCG-CSO-RSC does not apply)",
          gap_fields(a_no_scg) == [])
    a_no_assessor = filled_profile("a", assessor="TBD", assessor_id="TBD",
                                   secure_config_guide_uri="TBD")
    check("Class A, FRC-APP-FIA not selected: no gap for assessor, assessor_id or SCG",
          gap_fields(a_no_assessor) == [])
    check("Class A still requires everything FedRAMP requires of it",
          gap_fields(filled_profile("a", trust_center_uri="TBD", next_ocr_date="TBD",
                                    certification_package_overview_uri="TBD"))
          == ["next_ocr_date", "certification_package_overview_uri", "trust_center_uri"])
    a_fia = filled_profile("a", assessor="TBD", assessor_id="TBD",
                           selected_optional_rules=["FRC-APP-FIA"])
    check("Class A with FRC-APP-FIA selected requires the assessor again",
          gap_fields(a_fia) == ["assessor", "assessor_id"])
    check("Class A with FRC-APP-FIA selected and a real assessor has no gap",
          gap_fields(filled_profile("a", selected_optional_rules=["FRC-APP-FIA"])) == [])
    check("Class A with FRC-APP-FIA selected still does not require the SCG",
          gap_fields(filled_profile("a", selected_optional_rules=["FRC-APP-FIA"],
                                    secure_config_guide_uri="TBD")) == [])

    print("== behaviour: the published CDS-CSO-PUB items")
    pub_a = pc.derive_public_information(a_no_assessor)
    scg_item = pub_a["link_to_secure_configuration_guidance"]
    ass_item = pub_a["current_fedramp_recognized_independent_assessment_service"]
    check("Class A SCG item is an explicit not-applicable statement naming the rules",
          scg_item.startswith("Not applicable at Class A") and "SCG-CSO-RSC" in scg_item
          and "FRC-CLA-MFR" in scg_item and not pc.is_hollow(scg_item))
    check("Class A assessor item is an explicit not-applicable statement naming FRC-APP-FIA "
          "and the alternative framework",
          ass_item.startswith("Not applicable at Class A") and "FRC-APP-FIA" in ass_item
          and "SOC 2 Type II" in ass_item and not pc.is_hollow(ass_item))
    pub_a_scg = pc.derive_public_information(filled_profile("a", assessor="TBD", assessor_id="TBD"))
    check("Class A publishes a Secure Configuration Guide the provider supplied anyway",
          pub_a_scg["link_to_secure_configuration_guidance"] == "https://contoso.gov/scg")
    pub_b = pc.derive_public_information(filled_profile("b", assessor="TBD", assessor_id="TBD",
                                                        secure_config_guide_uri="TBD"))
    check("Class B publishes TBD for both while unanswered (preflight blocks on them)",
          pub_b["link_to_secure_configuration_guidance"] == pc.TBD
          and pub_b["current_fedramp_recognized_independent_assessment_service"] == pc.TBD)
    pub_a_fia = pc.derive_public_information(filled_profile("a", selected_optional_rules=["FRC-APP-FIA"]))
    check("Class A with a selected FIA publishes the real assessor",
          pub_a_fia["current_fedramp_recognized_independent_assessment_service"]
          == "Acme FedRAMP Assessors LLC (FedRAMP assessor ID 482913)")

    print("== behaviour: the generated CPO")
    doc_a = build_cpo.build_cpo(copy.deepcopy(a_no_assessor))
    check("Class A CPO omits the optional assessor member when no assessment is required",
          "assessor" not in doc_a)
    check("Class A CPO omits the optional secureConfigurationGuidance member",
          "secureConfigurationGuidance" not in doc_a["serviceProperties"])
    errs = cpo_schema_errors(doc_a)
    check("Class A CPO without the two members validates against the official schema",
          errs == [], "; ".join(errs[:3]))
    check("Class A CPO records no generator assumption for the omitted members",
          not any("assessor" in s.lower() or "secure" in s.lower()
                  for s in doc_a.get("_cpoAssumptions", [])))
    md_a = build_cpo.render_md(a_no_assessor, doc_a)
    check("Class A CPO Markdown states both items as not applicable in the header lines",
          any(l.startswith("Secure Configuration Guidance: Not applicable at Class A") for l in md_a.splitlines())
          and any(l.startswith("Not applicable at Class A: no FedRAMP Recognized") for l in md_a.splitlines()))
    doc_a_fia = build_cpo.build_cpo(filled_profile("a", selected_optional_rules=["FRC-APP-FIA"]))
    check("Class A CPO with a selected FIA carries the assessor",
          doc_a_fia.get("assessor") == {"name": "Acme FedRAMP Assessors LLC", "assessorID": "482913"})
    doc_a_scg = build_cpo.build_cpo(filled_profile("a", assessor="TBD", assessor_id="TBD"))
    check("Class A CPO carries a Secure Configuration Guide the provider supplied anyway",
          doc_a_scg["serviceProperties"].get("secureConfigurationGuidance", {}).get("url")
          == "https://contoso.gov/scg")
    doc_b = build_cpo.build_cpo(filled_profile("b", assessor="TBD", assessor_id="TBD",
                                               secure_config_guide_uri="TBD"))
    check("Class B CPO keeps both members as placeholders while unanswered",
          doc_b.get("assessor", {}).get("assessorID") == "000000"
          and "secureConfigurationGuidance" in doc_b["serviceProperties"])
    sp_keys = list(doc_b["serviceProperties"].keys())
    check("Class B CPO member order is unchanged (secureConfigurationGuidance before the OCR date)",
          sp_keys.index("secureConfigurationGuidance") < sp_keys.index("nextOngoingCertificationReportDate"))
    doc_t = build_cpo.build_cpo(load(TEMPLATE))
    check("the committed template (Class B) still emits both members",
          "assessor" in doc_t and "secureConfigurationGuidance" in doc_t["serviceProperties"])

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
