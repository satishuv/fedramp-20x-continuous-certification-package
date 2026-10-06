#!/usr/bin/env python3
"""Generate the Certification Package Overview (CPO).

CPO-CSO-OVR requires providers to supply a Certification Package Overview in
both human-readable and JSON formats, carrying the information required by a
set of related rules (CPO-CSO-MTD, CDS-CSO-PUB/SVC, MAS-CSO-*, CMU-CSO-CMD,
CDS-CSO-IRP, IVV-CSO-ICP). This builds the JSON against the official
fedramp-certification-package-overview-schema and a plain-text rendering.

Every provider-specific value comes from profiles/common/offering-profile.json,
and anything unprovided is an honest TBD placeholder. Where the official CPO
schema requires an enum value the profile has not supplied (deployment model,
service type) or a date (next Ongoing Certification Report), the generator emits
a schema-valid assumption AND records it in the doc's _cpoAssumptions list, so
it is never silently presented as a real provider fact. sdr.py preflight blocks
submission while the underlying profile fields are TBD, so an assumed value can
never reach a "submission ready" package. A green schema validation means the
document is well-formed, never that its contents are true or that the provider
is certified.

    python validation/scripts/build_cpo.py

Pipeline position: after build_sdr.py. Outputs:
    package/cpo/cpo.json   schema-valid Certification Package Overview
    package/cpo/cpo.md     human-readable rendering
"""

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
from fedramp_time import add_calendar_months  # noqa: E402
import profile_contract as _pc  # noqa: E402  (one place per fact; CDS-CSO-PUB derivation)
PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
OUT_JSON = os.path.join(BASE, "package", "cpo", "cpo.json")
OUT_MD = os.path.join(BASE, "package", "cpo", "cpo.md")

TBD = "TBD: Information has not been provided."
TBD_URI = "https://example.provider.gov-placeholder/tbd"


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def dump_json(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=1)


def val(v):
    return v if v not in (None, "") else TBD


DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")


def _required_information_map(profile):
    """Derive the CPO-CSO-OVR required-information list from the dataset (the
    rules whose information the CPO MUST include) and pair each with the
    provider's content pointer. The provider supplies a cpo_required_information
    map keyed by rule id (e.g. CDS-CSO-SVC) in the offering profile; anything
    unset is a TBD the CPO semantic validator/preflight will flag. Tracks
    upstream: if FedRAMP changes the referenced list, this map changes with it."""
    import re as _re
    try:
        ds = load(DATASET)
    except (OSError, ValueError):
        return {}
    def _find(node, target):
        if isinstance(node, dict):
            if target in node:
                return node[target]
            for v in node.values():
                r = _find(v, target)
                if r is not None:
                    return r
        elif isinstance(node, list):
            for v in node:
                r = _find(v, target)
                if r is not None:
                    return r
        return None
    ovr = _find(ds, "CPO-CSO-OVR") or {}
    refs = ovr.get("following_information", []) or []
    provider = profile.get("cpo_required_information", {}) or {}

    # Applicability: CPO-CSO-OVR itself says its referenced rules "may not all
    # apply to every class/type" and non-applicable information is not required.
    # The resolved class profile is the authoritative applicable-rule set, so a
    # referenced rule that is not in this class's profile is not emitted (this is
    # what keeps Class A - which resolves only CDS-CSO-PUB and MAS-CSO-IIR of the
    # OVR set - from carrying seven meaningless N/A entries).
    cls_short = (profile.get("certification_class") or "b").lower()
    try:
        cprof = load(os.path.join(BASE, "profiles", f"class-{cls_short}", "profile.json"))
        applicable_rules = {r["rule_id"] for r in (cprof.get("rules") or [])}
    except (OSError, ValueError, KeyError):
        applicable_rules = None  # cannot scope: fall back to emitting all

    out = {"cr26_rule": "CPO-CSO-OVR",
           "note": "Each referenced rule's information must appear in the CPO "
                   "unless the rule does not apply to this class/type. The "
                   "applicable set is the intersection of CPO-CSO-OVR's "
                   "referenced rules with this class's resolved rule set.",
           "items": []}
    for ref in refs:
        m = _re.search(r"([A-Z]{3}-[A-Z]{3}-[A-Z]{3})", ref)
        rid = m.group(1) if m else ref
        if applicable_rules is not None and rid not in applicable_rules:
            continue  # not applicable to this class/type - omit per CPO-CSO-OVR
        if rid == "CDS-CSO-PUB":
            # One place per fact: the 16 published items are derived from the
            # profile fields that already carry them (package id, service and
            # deployment model, contacts, website, logo, description, SCG and
            # trust-center links, next OCR date, assessor); a provider-supplied
            # value under cpo_required_information["CDS-CSO-PUB"] wins when real.
            content = _pc.derive_public_information(profile)
        else:
            content = val(provider.get(rid))
        out["items"].append({
            "rule": rid,
            "description": ref,
            "provider_content": content,
        })
    return out


def _contact(contact_type, value):
    """CPO contactInfo from a profile contact: a string ('name <email>') maps to
    contactName; a dict {name, email, phone} maps to the schema's three members.
    Only members with a real value are emitted (the schema requires contactType
    alone; a TBD contactName keeps preflight blocking as before)."""
    out = {"contactType": contact_type}
    if isinstance(value, dict):
        name, email, phone = (str(value.get(k, "")).strip() for k in ("name", "email", "phone"))
        real_name = name if name and not _pc.is_tbd(name) else None
        real_email = email if email and not _pc.is_tbd(email) else None
        out["contactName"] = val(real_name or real_email)
        if real_email:
            out["contactEmail"] = real_email
        if phone and not _pc.is_tbd(phone):
            # Schema pattern is ###-###-####; normalize a 10-digit number into it,
            # omit anything that cannot be expressed that way (the schema would
            # reject it, and a phone is not what CDS-CSO-PUB requires).
            normalized = _pc.normalize_phone(phone)
            if normalized:
                out["contactPhone"] = normalized
    else:
        out["contactName"] = val(value)
    return out


def _repository(desc, url=None):
    # Minimal valid `repository` object per the CPO schema. A provider-supplied
    # url overrides the TBD placeholder; a TBD/unset value keeps the placeholder
    # so preflight blocks on an unfilled trust center / SCG.
    if not url or str(url).strip().startswith("TBD"):
        url = TBD_URI
    return {
        "repositoryType": ["Website"],
        "url": url,
        "repositoryDescription": desc,
        "authenticationRequired": False,
    }


def build_cpo(profile):
    cls = (profile.get("certification_class") or "b").upper()
    # certificationType enum is '20x' or 'Rev5'. Map the offering profile's
    # human label to the schema token.
    ctype = "Rev5" if "rev5" in (profile.get("certification_type") or "").lower() else "20x"

    # Any value the generator has to assume (because the profile is unset or
    # TBD) is recorded here so it is visible, not silently presented as a real
    # provider fact. sdr.py preflight already blocks submission while the
    # underlying profile fields are TBD, so these assumptions can never reach a
    # "submission ready" package.
    assumptions = []

    def _unset(v):
        return v is None or str(v).strip() == "" or str(v).strip().startswith("TBD")

    # deploymentModel must be one of the schema's enum values.
    DEPLOY_ENUM = {"public cloud": "Public Cloud", "government-only cloud": "Government-Only Cloud",
                   "hybrid cloud": "Hybrid Cloud", "community cloud": "Community Cloud",
                   "government community cloud": "Government Community Cloud"}
    raw_deploy = profile.get("deployment_model")
    deploy = DEPLOY_ENUM.get((raw_deploy or "").lower())
    if deploy is None:
        deploy = "Public Cloud"
        assumptions.append("deploymentModel assumed 'Public Cloud' because the "
                           "offering profile deployment_model is unset/unknown")
    # serviceType enum is SaaS/PaaS/IaaS.
    raw_stype = profile.get("service_model")
    stype = {"SAAS": "SaaS", "PAAS": "PaaS", "IAAS": "IaaS"}.get((raw_stype or "").upper())
    if stype is None:
        stype = "PaaS"
        assumptions.append("serviceType assumed 'PaaS' because the offering "
                           "profile service_model is unset/unknown")
    # nextOngoingCertificationReportDate: OCRs are due every 3 months
    # (CCM-OCR-AVL). Rather than a hard-coded past date, derive a plausible
    # FUTURE placeholder from the pinned dataset date + 3 months, and mark it.
    next_ocr = profile.get("next_ocr_date")
    if _unset(next_ocr):
        import datetime as _dt
        base = "-".join((profile.get("dataset_version") or "2026-01-01").split(".")[:3])
        try:
            d = _dt.date.fromisoformat(base)
        except ValueError:
            d = _dt.date.today()
        # add 3 calendar months as a placeholder cadence anchor (CCM-OCR-AVL
        # states the cadence in months, not days)
        next_ocr = add_calendar_months(d, 3).isoformat()
        assumptions.append(f"nextOngoingCertificationReportDate is a placeholder "
                           f"({next_ocr}) derived from the dataset date + 3 months "
                           f"(CCM-OCR-AVL cadence); the provider must set next_ocr_date")
    # assessorID must be exactly 6 digits; use a clearly-placeholder value.
    aid = profile.get("assessor_id")
    if not (isinstance(aid, str) and aid.isdigit() and len(aid) == 6):
        aid = "000000"
    # A TBD profile value is UNSET for the schema's purposes: the raw marker text
    # fails `logo`'s image-extension pattern and `website`'s uri format, so each
    # falls back to the same clearly-placeholder value an empty field does.
    # package-preflight blocks on the TBD profile field either way.
    website = profile.get("offering_website")
    logo = profile.get("offering_logo_uri")
    pkg_id = profile.get("fedramp_package_id")
    doc = {
        "serviceIdentification": {
            "fedRampPackageId": "TBD-PACKAGE-ID" if _unset(pkg_id) else pkg_id,
            "providerName": val(profile.get("organization_name")),
            "serviceName": val(profile.get("offering_name")),
            "serviceAcronym": val(profile.get("offering_abbreviation")),
            "serviceDescription": val(profile.get("business_purpose")),
            "certificationType": ctype,
            "website": TBD_URI if _unset(website) else website,
            # logo must end in an image extension per schema; placeholder .png.
            "logo": ("https://example.provider.gov-placeholder/logo.png"
                     if _unset(logo) else logo),
        },
        "serviceProperties": {
            "serviceType": [stype],
            "deploymentModel": deploy,
            "trustCenter": _repository(
                "FedRAMP-compatible trust center for Certification Data (CDS-CSO-UTC).",
                profile.get("trust_center_uri")),
            "secureConfigurationGuidance": _repository(
                "Secure Configuration Guide (SCG-CSO-RSC).",
                profile.get("secure_config_guide_uri")),
            "nextOngoingCertificationReportDate": next_ocr,
        },
        # contactInformation must contain at least a Security and a Sales
        # contact (CDS-CSO-PUB). A contact may be a string or {name, email, phone}.
        "contactInformation": [
            _contact("Security", profile.get("security_contact")),
            _contact("Sales", profile.get("sales_contact")),
        ],
        "assessor": {
            "name": val(profile.get("assessor")),
            "assessorID": aid,
        },
    }
    # CDS-CSO-PUB items the schema models as optional members: emitted only when
    # the provider supplied a real value (a justified 'N/A: <reason>' is kept out
    # of the schema member and lives in the derived public-information object).
    uei = profile.get("uei_number")
    if not _pc.is_hollow(uei) and not str(uei).strip().lower().startswith(("n/a", "not applicable")):
        doc["serviceIdentification"]["ueiNumber"] = str(uei).strip()
    cat = profile.get("business_category")
    cats = _pc.business_categories(cat)
    if cats:
        doc["serviceProperties"]["businessCategory"] = cats
    elif not _pc.is_hollow(cat) and not str(cat).strip().lower().startswith(("n/a", "not applicable")):
        # Free text the schema enum does not contain: keep it OUT of the schema
        # member (it would fail validation) and say so; it still appears in the
        # derived CDS-CSO-PUB public-information object.
        assumptions.append(f"businessCategory omitted: profile business_category {cat!r} is not "
                           "one of the CPO schema's enum values; answer with `sdr.py init`")
    # CPO-CSO-MTD (MUST): basic metadata - responsible official, version,
    # last-updated, source of update. Carried as a provider extension.
    doc["xCpoMetadata"] = {
        "cr26_rule": "CPO-CSO-MTD",
        "responsible_official": val(profile.get("cpo_responsible_official")),
        "version": val(profile.get("cpo_version")),
        "last_updated": val(profile.get("cpo_last_updated")),
        "source_of_update": val(profile.get("cpo_source_of_update")),
    }
    # CPO-CSO-OVR (MUST): the CPO must include the information required by the
    # referenced rules. Derive that list from the dataset so it tracks upstream,
    # and record the provider's per-rule content pointer. Applicability note
    # (from the rule) is preserved: a rule that does not apply is not required.
    doc["xCpoRequiredInformation"] = _required_information_map(profile)
    doc["_cpoNote"] = (
        f"Class {cls} Certification Package Overview scaffold. Required by "
        "CPO-CSO-OVR. Fill provider values in profiles/common/offering-profile.json; "
        "TBD markers show what a human still owes. Not a compliance claim.")
    # CPO-CSO-OSA: Class B/C MUST include the assessor's overall assessment
    # summary (from IVV-IAS-OSA) in the CPO, without inappropriate modification.
    # Carried as a provider extension since the official CPO schema has no slot.
    summary = profile.get("overall_assessment_summary")
    if summary:
        doc["xOverallAssessmentSummary"] = {
            "cr26_rule": "CPO-CSO-OSA",
            "source_rule": "IVV-IAS-OSA (assessor-supplied)",
            "summary": summary,
        }
    if assumptions:
        doc["_cpoAssumptions"] = assumptions
    return doc


def render_md(profile, doc):
    L = []
    a = L.append
    si = doc["serviceIdentification"]
    a("Certification Package Overview")
    a(_pc.offering_title(profile))
    a("")
    a(f"Provider: {si['providerName']}")
    a(f"Certification type: {si['certificationType']}")
    a(f"Certification class: Class {(profile.get('certification_class') or 'b').upper()}")
    a(f"Service description: {si['serviceDescription']}")
    a(f"Website: {si['website']}")
    a("")
    a("Service properties")
    sp = doc["serviceProperties"]
    a(f"Service type: {', '.join(sp['serviceType'])}")
    a(f"Deployment model: {sp['deploymentModel']}")
    a(f"Next Ongoing Certification Report date: {sp['nextOngoingCertificationReportDate']}")
    a(f"Trust center: {sp['trustCenter']['url']}")
    a(f"Secure Configuration Guidance: {sp['secureConfigurationGuidance']['url']}")
    a("")
    a("Assessor")
    a(f"Name: {doc['assessor']['name']}")
    a("")
    mtd = doc.get("xCpoMetadata", {})
    a("Certification Package Overview metadata (CPO-CSO-MTD)")
    a(f"Responsible official: {mtd.get('responsible_official')}")
    a(f"Version: {mtd.get('version')}")
    a(f"Last updated: {mtd.get('last_updated')}")
    a(f"Source of update: {mtd.get('source_of_update')}")
    a("")
    summary = doc.get("xOverallAssessmentSummary")
    if summary:
        a("Overall assessment summary (CPO-CSO-OSA)")
        a(str(summary.get("summary")))
        a("")
    req = doc.get("xCpoRequiredInformation", {})
    a("Required information included in this Certification Package Overview (CPO-CSO-OVR)")
    for item in req.get("items", []):
        a(f"- {item.get('rule')} ({item.get('description')}): {item.get('provider_content')}")
    a("")
    a("This Certification Package Overview is a generated scaffold required by "
      "CPO-CSO-OVR. TBD markers indicate information a human must still supply. "
      "A schema-valid document is not a compliance determination.")
    return "\n".join(L)


def main():
    profile = load(PROFILE)
    cls = (profile.get("certification_class") or "b").lower()
    if cls == "d":
        print("Class D is FedRAMP pending; no CPO is generated.")
        return 1
    doc = build_cpo(profile)
    dump_json(doc, OUT_JSON)
    os.makedirs(os.path.dirname(OUT_MD), exist_ok=True)
    with open(OUT_MD, "w", encoding="utf-8", newline="\n") as f:
        f.write(render_md(profile, doc))
    print(f"CPO written: {os.path.relpath(OUT_JSON, BASE)} and .md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
