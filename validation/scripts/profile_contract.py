"""The offering-profile input contract, traced field by field to FedRAMP.

One definition, used by `sdr.py init` (asks the questions), `package-preflight`
(blocks on what is missing) and `build_cpo.py` (derives the CDS-CSO-PUB public
information from the same fields, so no fact is typed twice).

Every REQUIRED field names its FedRAMP source: a property of the official
Certification Package Overview schema (`cpo:` prefix, path inside the schema) or
a CR26 rule id. A field with no FedRAMP source is never required; it is either an
operational input the generators print (AWS partition and regions, IaC
technology) or it was removed. `validation/scripts/test_profile_traceability.py`
checks every source here against the pinned schema and dataset, so a field
cannot claim a requirement that does not exist.

Nothing in this module decides compliance; it decides what the package cannot
be submitted WITHOUT, which is what FedRAMP wrote down.
"""
import json
import os
import re

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OFFERING_PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
CPO_SCHEMA = os.path.join(BASE, "artifacts", "schemas", "official",
                          "fedramp-certification-package-overview-schema-2026-06-24.json")

TBD = "TBD: Information has not been provided."


def _cpo_schema():
    try:
        with open(CPO_SCHEMA, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def business_category_enum():
    """The CPO schema's serviceProperties.businessCategory item enum, read from
    the PINNED schema so the wizard and the builder can never accept or emit a
    category FedRAMP does not list. Empty if the schema is unavailable."""
    sp = ((_cpo_schema().get("properties") or {}).get("serviceProperties") or {})
    cat = (sp.get("properties") or {}).get("businessCategory") or {}
    return tuple((cat.get("items") or {}).get("enum") or ())


def business_categories(value):
    """Normalize a profile business_category (string, comma/semicolon separated,
    or list) to the list of schema enum values it names, case-insensitive.
    Returns [] when nothing matches, so a free-text category never reaches the
    CPO (the schema would reject it); the text still appears in the derived
    public-information object."""
    enum = business_category_enum()
    by_lower = {e.lower(): e for e in enum}
    if value is None or is_hollow(value):
        return []
    parts = value if isinstance(value, list) else re.split(r"[;,]", str(value))
    out = []
    for p in parts:
        hit = by_lower.get(str(p).strip().lower())
        if hit and hit not in out:
            out.append(hit)
    return out


CONTACT_PHONE_PATTERN = re.compile(r"^[0-9]{3}-[0-9]{3}-[0-9]{4}$")


def normalize_phone(value):
    """CPO contactInfo.contactPhone is '###-###-####'. Accepts that form, or any
    input with exactly ten digits (optionally with a leading +1 / 1), which is
    reformatted. Returns None when the number cannot be expressed that way."""
    s = str(value or "").strip()
    if CONTACT_PHONE_PATTERN.match(s):
        return s
    digits = re.sub(r"\D", "", s)
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) == 10:
        return f"{digits[:3]}-{digits[3:6]}-{digits[6:]}"
    return None

# ---- Required at every class: (field, FedRAMP source, plain-English question) ----
# Order is the order `sdr.py init` asks them.
REQUIRED_FIELDS = [
    ("organization_name", "cpo:serviceIdentification.providerName",
     "Legal name of the organization (the Cloud Service Provider)?"),
    ("offering_name", "cpo:serviceIdentification.serviceName",
     "Name of the cloud service offering?"),
    ("offering_abbreviation", "cpo:serviceIdentification.serviceAcronym",
     "Short acronym for the offering (FedRAMP lists it beside the name)?"),
    ("business_purpose", "cpo:serviceIdentification.serviceDescription",
     "One or two sentences: what does the offering do? (published as the overall service description)"),
    ("service_model", "cpo:serviceProperties.serviceType",
     "Service model: SaaS, PaaS or IaaS?"),
    ("deployment_model", "cpo:serviceProperties.deploymentModel",
     "Deployment model, exactly one of: Public Cloud, Government-Only Cloud, Hybrid Cloud, "
     "Community Cloud, Government Community Cloud?"),
    ("certification_type", "cpo:serviceIdentification.certificationType",
     "Certification type: 'FedRAMP 20x' (this framework resolves 20x rules only)?"),
    ("certification_class", "cr26:varies_by_class",
     "Certification class you are seeking: a, b or c? (every FRC-APP and class-varying rule resolves by it)"),
    ("fedramp_package_id", "cpo:serviceIdentification.fedRampPackageId",
     "FedRAMP package ID (assigned by FedRAMP; leave blank until you have it)?"),
    ("offering_website", "cpo:serviceIdentification.website",
     "Public product website URL?"),
    ("offering_logo_uri", "cpo:serviceIdentification.logo",
     "URL of the product logo image (.png/.svg/.jpg)?"),
    ("security_contact", "cpo:contactInformation[Security]",
     "Security contact (this is the FedRAMP Security Inbox owner, AFC-CSO-INB)"),
    ("sales_contact", "cpo:contactInformation[Sales]",
     "Sales contact (FedRAMP requires one published Sales contact)"),
    ("assessor", "CDS-CSO-PUB",
     "Name of your FedRAMP Recognized independent assessment service?"),
    ("assessor_id", "cpo:assessor.assessorID",
     "That assessor's 6-digit FedRAMP assessor ID?"),
    ("next_ocr_date", "CDS-CSO-PUB",
     "Date of your next Ongoing Certification Report (YYYY-MM-DD)?"),
    ("uei_number", "CDS-CSO-PUB",
     "Unique Entity Identifier (UEI) from SAM.gov? (type 'N/A: <reason>' if you have none; "
     "the schema then leaves ueiNumber blank)"),
    ("business_category", "CDS-CSO-PUB",
     "Business category(ies) from FedRAMP's fixed list, comma-separated (for example "
     "'Analytics, Data Management'; type 'list' to see the 36 values; 'N/A: <reason>' if none applies)?"),
    ("documentation_overview", "CDS-CSO-PUB",
     "One or two sentences describing the documentation you supply for the offering?"),
    ("certification_package_overview_uri", "CDS-CSO-PUB",
     "URL where the machine-readable Certification Package Overview will be published?"),
    ("trust_center_uri", "CDS-CSO-UTC",
     "URL of your FedRAMP-compatible trust center landing page?"),
    ("secure_config_guide_uri", "SCG-CSO-RSC",
     "URL of your published Secure Configuration Guide?"),
]

# Fields that must name a REAL entity or location: even a justified 'N/A: <reason>'
# is missing here (preflight uses the stricter identity predicate). The UEI,
# business category and documentation overview are listed by CDS-CSO-PUB as
# information that is "available and applicable", so a justified N/A is allowed
# for those three and they are deliberately NOT in this set.
IDENTITY_REQUIRED = {
    "organization_name", "offering_name", "security_contact", "sales_contact",
    "assessor", "assessor_id", "offering_website", "offering_logo_uri",
    "fedramp_package_id", "certification_package_overview_uri",
    "trust_center_uri", "secure_config_guide_uri",
}

# ---- Required by class: nested blocks (field, FedRAMP source, classes, questions) ----
CLASS_CONDITIONAL = [
    ("provider_verified_at", "FRC-APP-FCP", ("a", "b", "c"),
     [("provider_verified_at", "When did the provider last verify and validate the offering "
                               "(ISO-8601 datetime, or 'now')? Must be within 7 days at submission")]),
    ("fedramp_independent_assessment", "FRC-APP-FIA", ("b", "c"),
     # The rule: an assessment "completed by a FedRAMP Recognized independent
     # assessment service within the previous 3 months". That is WHO (the name
     # and the Recognition id that evidences "Recognized") and WHEN. The report
     # and summary URIs in the template are reference pointers the repo offers,
     # not something the rule requires, so they are not asked here.
     [("assessor_name", "Independent assessment: assessor organization name?"),
      ("assessor_fedramp_id", "Independent assessment: assessor's FedRAMP Recognition id?"),
      ("completed_at", "Independent assessment: completion date (YYYY-MM-DD; within 3 months at submission)?")]),
    ("overall_assessment_summary", "CPO-CSO-OSA", ("b", "c"),
     [("overall_assessment_summary", "The assessor's overall assessment summary (IVV-IAS-OSA), "
                                     "pasted verbatim? (leave blank until the assessor supplies it)")]),
    ("availability_reporting", "CDS-CSO-AVR", ("b", "c"),
     [("human_readable_uri", "Availability status page URL (human-readable, 30 days history)?"),
      ("machine_readable_uri", "Availability status feed URL (machine-readable)?")]),
    ("cpo_metadata", "CPO-CSO-MTD", ("b", "c"),
     # The rule lists four items. Class A is excluded because CPO-CSO-MTD does
     # not resolve for a Class A package (its applicable CPO-CSO-OVR set is
     # CDS-CSO-PUB and MAS-CSO-IIR only), which is also how preflight gates it.
     [("cpo_responsible_official", "Name, title and contact of the official accountable for the package?"),
      ("cpo_version", "Package version label (for example 1.0)?"),
      ("cpo_last_updated", "Date and time of the package's last update (ISO-8601, or 'now')?"),
      ("cpo_source_of_update", "Source of this update (team or system producing it)?")]),
    ("external_assessment", "FRC-CLA-ASF", ("a",),
     # The rule: a certification "from one of the following alternative security
     # frameworks within the past 12 months" (FedRAMP Rev5 including FedRAMP
     # Ready, SOC 2 Type II, GovRAMP). WHICH framework and WHEN; preflight then
     # checks the FRC-CLA-EAM materials, which are structured records added to
     # the profile's external_assessment.materials list, not wizard answers.
     [("framework", "Class A: alternative framework relied on, one of: FedRAMP Rev5, FedRAMP Ready, "
                    "SOC 2 Type II, GovRAMP?"),
      ("assessment_date", "Class A: date that assessment was completed (YYYY-MM-DD; within 12 months)?")]),
]

# ---- Optional: operational inputs the generators print; never blockers ----
OPTIONAL_FIELDS = {
    "profile_note", "evidence_sources", "provider_verified_at", "dr_region",
    "primary_region", "aws_partition", "iac_technology", "incident_contact",
    "materials_item_schema", "note", "selected_optional_rules",
    "_selected_optional_rules_note", "selected_optional_ksis",
    "_selected_optional_ksis_note", "evidence_freshness_policy_days",
    "expected_evidence_signer", "telemetry_min_coverage", "mot_max_gap_days",
    "evidence_store_profile", "_evidence_store_profile_note",
    "metric_history_exception", "cpo_last_updated", "secure_config_guide_machine_uri",
    "application_prerequisites", "sdr_version", "schema_version", "dataset_version",
    "cpo_required_information", "external_assessment", "fedramp_independent_assessment",
    "overall_assessment_summary", "availability_reporting", "cpo_responsible_official",
    "cpo_version", "cpo_source_of_update", "certification_path",
}

# Fields this contract REMOVED from the template (no FedRAMP rule, no consumer).
# Kept here so the traceability test can assert they stay gone.
REMOVED_FIELDS = ("management_plane", "federal_information_types", "evidence_retention")

# ---- CDS-CSO-PUB: derive the 16 published items from the fields above ----
# Keys are the dataset's following_information phrases normalized exactly as
# sdr.py's `_norm_key` does (text before any parenthetical, lowercase, non-alnum
# to underscore). A new upstream item with no entry here is simply not derived,
# so preflight flags it and the provider supplies it under
# cpo_required_information["CDS-CSO-PUB"].
PUBLIC_INFORMATION_SOURCES = {
    "fedramp_id": ("fedramp_package_id",),
    "service_model": ("service_model",),
    "deployment_model": ("deployment_model",),
    "business_category": ("business_category",),
    "uei_number": ("uei_number",),
    "sales_contact_information": ("sales_contact",),
    "security_contact_information": ("security_contact",),
    "product_website_link": ("offering_website",),
    "link_to_product_logo": ("offering_logo_uri",),
    "overall_service_description": ("business_purpose",),
    "detailed_list_of_specific_services_and_their_security_categories":
        ("cpo_required_information", "CDS-CSO-SVC"),
    "link_to_secure_configuration_guidance": ("secure_config_guide_uri",),
    "overview_of_documentation_supplied_by_the_provider_for_the_cloud_service_offering":
        ("documentation_overview",),
    "link_to_trust_center_landing_page_that_includes_instructions_on_accessing_information_in_the_trust_center":
        ("trust_center_uri",),
    "next_ongoing_certification_report_date": ("next_ocr_date",),
    "current_fedramp_recognized_independent_assessment_service": ("assessor", "assessor_id"),
}


# ---- Value predicates (shared with preflight) ----------------------------------

def contact_text(v):
    """A contact is a string ('name <email>') or a dict {name, email, phone}.
    Returns the display string, or '' when nothing real is present."""
    if isinstance(v, dict):
        parts = [str(v.get(k, "")).strip() for k in ("name", "email", "phone")]
        parts = [p for p in parts if p and not is_tbd(p)]
        return ", ".join(parts)
    return "" if v is None else str(v).strip()


def is_tbd(v):
    s = "" if v is None else str(v).strip()
    low = s.lower()
    return (not s or s.startswith("TBD") or "placeholder" in low
            or "has not been provided" in low or s.startswith("DRAFT (")
            or s.startswith("Example (") or s.startswith("Example:"))


_BARE = {"n/a", "na", "none", "nil", "null", "unknown", "tbc", "?", ".", "-", "--",
         "...", "x", "see documentation", "see docs", "not applicable", "not-applicable"}


def is_hollow(v):
    """TBD, or a bare non-answer; a justified 'N/A: <reason>' is NOT hollow.
    A list (business categories) is hollow when empty or all-hollow."""
    if isinstance(v, list):
        return not any(not is_hollow(x) for x in v)
    if isinstance(v, dict):
        return is_hollow(contact_text(v)) if any(k in v for k in ("name", "email", "phone")) \
            else not any(not is_hollow(x) for x in v.values())
    if is_tbd(v):
        return True
    s = str(v).strip()
    low = s.lower()
    if low in _BARE:
        return True
    for m in ("n/a", "na", "not applicable", "not-applicable", "none"):
        if low.startswith(m):
            rest = s[len(m):].lstrip(" :.-").strip()
            return len(rest) < 3
    return False


def is_missing_identity(v):
    """Stricter: an identity / contact / URL field must name a real thing; any
    N/A form is missing."""
    if isinstance(v, dict):
        v = contact_text(v)
    if is_tbd(v):
        return True
    low = str(v).strip().lower()
    if low in _BARE:
        return True
    return any(low.startswith(m) for m in ("n/a", "na ", "not applicable", "not-applicable", "none"))


def field_missing(field, value):
    return is_missing_identity(value) if field in IDENTITY_REQUIRED else is_hollow(value)


def required_gaps(profile):
    """[(field, source)] for every REQUIRED field still unanswered."""
    return [(f, src) for f, src, _q in REQUIRED_FIELDS if field_missing(f, profile.get(f))]


def class_gaps(profile):
    """[(block, source, missing_subfields)] for the class-conditional blocks that
    apply to this profile's class and are not yet answered. Mirrors what
    package-preflight blocks on; preflight remains the authority (it also checks
    freshness windows), this is the wizard's and the report's summary."""
    cls = str(profile.get("certification_class") or "b").strip().lower()
    out = []
    for block, src, classes, questions in CLASS_CONDITIONAL:
        if cls not in classes:
            continue
        if block == "cpo_metadata":
            missing = [k for k, _q in questions if is_hollow(profile.get(k))]
        elif block in ("provider_verified_at", "overall_assessment_summary"):
            missing = [block] if is_hollow(profile.get(block)) else []
        else:
            node = profile.get(block) or {}
            missing = [k for k, _q in questions if is_missing_identity((node or {}).get(k))]
        if missing:
            out.append((block, src, missing))
    return out


def derive_public_information(profile):
    """The CDS-CSO-PUB object (16 items keyed like the dataset phrases), derived
    from the profile fields; a provider-supplied value under
    cpo_required_information["CDS-CSO-PUB"] wins when it is real."""
    supplied = ((profile.get("cpo_required_information") or {}).get("CDS-CSO-PUB") or {})
    if not isinstance(supplied, dict):
        supplied = {}
    out = {}
    for key, path in PUBLIC_INFORMATION_SOURCES.items():
        if path[0] == "cpo_required_information":
            val = (profile.get("cpo_required_information") or {}).get(path[1])
        elif key == "current_fedramp_recognized_independent_assessment_service":
            name, aid = profile.get("assessor"), profile.get("assessor_id")
            val = None if is_hollow(name) else (
                f"{name} (FedRAMP assessor ID {aid})" if not is_hollow(aid) else str(name))
        else:
            val = profile.get(path[0])
        if isinstance(val, dict):
            val = contact_text(val) or None
        elif isinstance(val, list):
            val = ", ".join(str(x) for x in val if not is_hollow(x)) or None
        if not is_hollow(supplied.get(key)):
            out[key] = supplied[key]
        else:
            out[key] = TBD if val is None or is_hollow(val) else str(val)
    # Carry through any extra provider-supplied keys (an upstream item this map
    # does not know yet).
    for k, v in supplied.items():
        out.setdefault(k, v)
    return out


PLACEHOLDER_CPO_URI = "https://example.provider.gov-placeholder/cpo.json"


def cpo_uri(profile):
    """The Certification Package Overview URI every artifact references
    (certificationPackageOverviewUri). A TBD or empty profile value resolves to
    one clearly-placeholder URI so the schemas' uri format holds and every
    artifact and the consistency validator see the SAME value; package-preflight
    blocks on the TBD profile field, so the placeholder can never reach a
    submission-ready package."""
    v = profile.get("certification_package_overview_uri")
    return PLACEHOLDER_CPO_URI if is_tbd(v) else str(v).strip()


def offering_title(profile):
    """The 'Name (ACR)' title line every deliverable prints. Until the wizard has
    the real name, the title says so briefly instead of repeating the TBD marker
    text twice; the marker itself stays in the profile, where `sdr.py init` and
    package-preflight report it."""
    name = profile.get("offering_name")
    acr = profile.get("offering_abbreviation")
    if is_hollow(name):
        return "Offering name not yet provided (TBD)"
    return f"{name} ({acr})" if not is_hollow(acr) else str(name)


def load_profile(path=OFFERING_PROFILE):
    with open(path, encoding="utf-8") as f:
        return json.load(f)
