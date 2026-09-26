# Validate generated SDR JSON against the official FedRAMP SDR schema and run
# framework quality checks. Captures results per KSI, as required by the owner.
#
# Checks:
#   1. Official schema validation of sdr-class-<x>.json (resolves the cross-file
#      reference to the common definitions schema locally).
#   2. Coverage: every rule in the class profile appears in the SDR; every KSI
#      in the KSI profile appears in the SDR.
#   3. Per-KSI structural checks: required fields present, tests match the
#      minimum automated method count for the class (reported, not failed,
#      while the template is in TBD state).
#   4. Markdown-symbol detection in the human-readable rendering.
#   5. Sensitive-pattern detection (AWS account IDs, access keys, secrets).
#   6. Content fidelity: every statement, name, force, and family expansion
#      in the profile, official JSON, extensions, plain text, and docx is
#      compared against the canonical dataset (independent resolution, so
#      the validator does not trust the builders it checks).
#
# Output: validation/reports/validation-report.json plus per-KSI results in
# validation/reports/ksi-test-results.json. Exit code 1 on any hard failure.

import html
import json
import os
import re
import sys
import zipfile

# Single source of truth for FRC-CSX-VVK force/minimum (same directory).
from fedramp_constants import VVK_FORCE
# Single source of truth for FRC-CSX-VVK automated-method counting, shared with
# build_assurance_graph.py so the reviewer-facing report cannot diverge.
from verification_methods import count_automated_methods

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Shared Class B KSI-scope resolver (single source of truth). sdr.py guards
# execution under __main__, so importing it has no side effects.
if BASE not in sys.path:
    sys.path.insert(0, BASE)
from sdr import submitted_ksi_ids  # noqa: E402
SCHEMA_DIR = os.path.join(BASE, "artifacts", "schemas", "official")
SDR_SCHEMA = os.path.join(SCHEMA_DIR, "fedramp-security-decision-record-schema-2026-06-24.json")
COMMON_SCHEMA = os.path.join(SCHEMA_DIR, "fedramp-common-definitions-schema-2026-06-24.json")
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
REPORTS = os.path.join(BASE, "validation", "reports")

# KSIs whose statements are empty in the official dataset (FedRAMP pending).
EMPTY_STATEMENT_KSIS = {"KSI-CNA-EIS", "KSI-MLA-ALA", "KSI-SVC-PRR",
                        "KSI-SVC-RUD", "KSI-SVC-VCM"}

MD_PATTERNS = [
    (re.compile(r"^#{1,6} ", re.M), "markdown heading"),
    (re.compile(r"\*\*[^*\n]+\*\*"), "bold markers"),
    (re.compile(r"^\s*\* ", re.M), "asterisk bullet"),
    (re.compile(r"`[^`\n]+`"), "backticks"),
    (re.compile(r"^\|.+\|$", re.M), "markdown table"),
]

SENSITIVE_PATTERNS = [
    # A real AWS account ID is a standalone 12-digit number. Exclude a 12-digit
    # run that sits inside a hyphen-delimited hex token (a UUID), where it is
    # adjacent to hex/hyphen context on either side; those are identifiers in
    # generated files (e.g. OSCAL uuid fields), not account IDs. Real account
    # IDs appear surrounded by whitespace, quotes, or path/colon separators and
    # still match.
    (re.compile(r"(?<![0-9A-Fa-f-])\d{12}(?![0-9A-Fa-f-])"), "possible AWS account ID"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID"),
    (re.compile(r"-----BEGIN (RSA |EC )?PRIVATE KEY-----"), "private key"),
    # AUD-F28: an internal hostname or IP in the customer-facing package
    # identifies a real environment as surely as an account id does. The
    # evidence export boundary scrubs these before they can enter an entry;
    # this gate is the independent backstop over the whole generated bundle.
    (re.compile(r"\barn:aws[a-z-]*:"), "AWS resource ARN"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "IPv4 address"),
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}\b"), "IPv6 address"),
    (re.compile(r"\b[a-z0-9][a-z0-9-]*\.(?:internal|local|corp|lan|intranet|"
                r"ec2\.internal|compute\.internal)\b", re.I), "internal hostname"),
]


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def validate_schema(doc):
    import jsonschema
    from referencing import Registry, Resource

    sdr_schema = load(SDR_SCHEMA)
    common = load(COMMON_SCHEMA)
    registry = Registry().with_resources(
        [
            (sdr_schema["$id"], Resource.from_contents(sdr_schema)),
            (common["$id"], Resource.from_contents(common)),
        ]
    )
    validator = jsonschema.Draft202012Validator(sdr_schema, registry=registry)
    errors = [
        {"path": "/".join(str(p) for p in e.absolute_path), "message": e.message[:200]}
        for e in validator.iter_errors(doc)
    ]
    return errors


def norm(s):
    return re.sub(r"\s+", " ", (s or "").strip())


def docx_body_text(path):
    """Extract the document body text from a docx (tag-stripped, XML entities
    unescaped, whitespace-normalized)."""
    with zipfile.ZipFile(path) as z:
        xml = z.read("word/document.xml").decode("utf-8")
    return norm(html.unescape(re.sub(r"<[^>]+>", " ", xml)))


def canonical_maps():
    """Rule and KSI lookup maps built directly from the canonical dataset."""
    ds = load(DATASET)
    rules = {}
    rule_provenance = {}  # rid -> (applicability, subset), to catch collisions
    collisions = []
    for fam, famblock in ds["FRR"].items():
        for applicability, subsets in famblock.get("data", {}).items():
            for subset, items in subsets.items():
                for rid, rule in items.items():
                    if isinstance(rule, dict) and re.match(r"^[A-Z]{3}-[A-Z]{3}-[A-Z]{3}$", rid):
                        if rid in rules:
                            # A rule id must be unique across branches; a
                            # collision would silently drop one definition.
                            collisions.append((rid, rule_provenance[rid],
                                               (applicability, subset)))
                        rules[rid] = rule
                        rule_provenance[rid] = (applicability, subset)
    if collisions:
        # Surface rather than silently overwrite; the caller treats this as a
        # hard fidelity problem.
        rules["__collisions__"] = collisions
    ksis = {}
    fam_names_ksi = {}
    for fam, famblock in ds["KSI"].items():
        fam_names_ksi[fam] = famblock.get("name")
        for kid, k in famblock.get("indicators", {}).items():
            if kid.startswith("KSI-"):
                ksis[kid] = k
    fam_names_frr = {f: ds["FRR"][f].get("info", {}).get("name") for f in ds["FRR"]}
    return rules, ksis, fam_names_frr, fam_names_ksi


def resolve_canonical(rule, cls):
    """Same resolution semantics as build_profiles.resolve_for_class,
    re-implemented independently so the validator does not trust the
    builder it is checking."""
    vbc = rule.get("varies_by_class")
    if vbc:
        v = vbc.get(cls)
        if v and v.get("statement"):
            return {"statement": v["statement"], "force": v.get("force")}
        if rule.get("statement"):
            return {"statement": rule["statement"], "force": rule.get("force")}
        return None
    if rule.get("statement"):
        return {"statement": rule["statement"], "force": rule.get("force")}
    return None


def content_fidelity(cls, class_profile, sdr):
    """Compare every generated statement, name, force, and family expansion
    against the canonical dataset. Returns a list of mismatch descriptions."""
    problems = []
    rules, ksis, fam_frr, fam_ksi = canonical_maps()

    # A rule id resolving in more than one applicability/subset branch is a
    # dataset-fidelity problem: one definition would silently overwrite the
    # other. canonical_maps records it; consume it as a HARD failure so an
    # upstream dataset that introduces such a collision cannot be adopted
    # silently. (Today's CR26 does not trigger this.)
    collisions = rules.pop("__collisions__", None)
    if collisions:
        for rid, first, second in collisions:
            problems.append(f"rule {rid} resolves in more than one dataset branch "
                            f"({first} and {second}); one definition would overwrite "
                            "the other (dataset-fidelity collision)")
    for e in class_profile["rules"]:
        rid = e["rule_id"]
        rule = rules.get(rid)
        if rule is None:
            problems.append(f"profile {rid}: not found in canonical dataset")
            continue
        can = resolve_canonical(rule, cls)
        if can is None:
            problems.append(f"profile {rid}: no canonical statement resolvable for class {cls.upper()}")
            continue
        if e.get("statement") != can["statement"]:
            problems.append(f"profile {rid}: statement differs from dataset")
        if e.get("name") != rule.get("name"):
            problems.append(f"profile {rid}: name differs from dataset")
        if e.get("force") != can["force"]:
            problems.append(f"profile {rid}: force {e.get('force')} vs dataset {can['force']}")
        if e.get("family_name") != fam_frr.get(e["family"]):
            problems.append(f"profile {rid}: family_name differs from dataset")

    for entry in sdr["fedRampRequirements"]:
        rid = entry["frrID"]
        pe = entry.get("providerExtensions", {})
        rule = rules.get(rid, {})
        if pe.get("ruleName") not in (None, rule.get("name")):
            problems.append(f"sdr json {rid}: providerExtensions.ruleName differs from dataset")
        if pe.get("familyName") not in (None, fam_frr.get(pe.get("family"))):
            problems.append(f"sdr json {rid}: providerExtensions.familyName differs from dataset")
    for entry in sdr["keySecurityIndicators"]:
        kid = entry["ksiId"]
        pe = entry.get("providerExtensions", {})
        if pe.get("ksiName") not in (None, ksis.get(kid, {}).get("name")):
            problems.append(f"sdr json {kid}: providerExtensions.ksiName differs from dataset")

    ext_path = os.path.join(BASE, "sdr", "json", f"sdr-class-{cls}-extensions.json")
    ext = load(ext_path)
    for rid, entry in ext["frr"].items():
        rule = rules.get(rid)
        can = resolve_canonical(rule, cls) if rule else None
        if can is None:
            continue
        if entry.get("name") != rule.get("name"):
            problems.append(f"extensions {rid}: name differs from dataset")
        wilf = entry.get("guidance", {}).get("what_it_looks_for")
        if norm(wilf) != norm(can["statement"]):
            problems.append(f"extensions {rid}: what_it_looks_for differs from canonical statement")

    txt = open(os.path.join(BASE, "sdr", "human-readable", f"sdr-class-{cls}.txt"),
               encoding="utf-8").read()
    txt_norm = norm(txt)
    for entry in sdr["keySecurityIndicators"]:
        kid = entry["ksiId"]
        st = ksis.get(kid, {}).get("statement")
        if st:
            if norm(st) not in txt_norm:
                problems.append(f"txt: KSI {kid} statement not found verbatim")
        elif kid not in EMPTY_STATEMENT_KSIS:
            problems.append(f"txt: KSI {kid} has an unexpected empty canonical statement")

    docx_path = os.path.join(BASE, "sdr", "human-readable", f"sdr-class-{cls}-authoring.docx")
    if os.path.exists(docx_path):
        dx = docx_body_text(docx_path)
        for e in class_profile["rules"]:
            rule = rules.get(e["rule_id"])
            can = resolve_canonical(rule, cls) if rule else None
            if can and can["statement"] and norm(can["statement"]) not in dx:
                problems.append(f"docx: rule {e['rule_id']} statement not found verbatim")
    else:
        problems.append(f"docx: {os.path.basename(docx_path)} missing")

    return problems


def main():
    profile = load(os.path.join(BASE, "profiles", "common", "offering-profile.json"))
    active_cls = profile["certification_class"].lower()
    # AUD-F23: validate any supported class, not only the active one. The CI
    # regenerates the inactive classes' SDR outputs but the authoritative
    # validator ran only against the profile's class, so Class A/C artifacts had
    # weaker checks. SDR_VALIDATE_CLASS mirrors build_sdr.py's SDR_BUILD_CLASS;
    # when it names a class other than the active one, the reports go to a
    # gitignored matrix directory so the committed canonical reports (which
    # describe the active class) are untouched.
    cls = (os.environ.get("SDR_VALIDATE_CLASS") or active_cls).lower()
    reports_dir = REPORTS if cls == active_cls else os.path.join(REPORTS, "matrix", f"class-{cls}")
    # Tests may redirect the reports entirely (SDR_REPORTS_DIR) so a test-driven
    # run never rewrites the committed canonical reports.
    reports_dir = os.environ.get("SDR_REPORTS_DIR") or reports_dir
    if cls == "d":
        # Match build_sdr.py and build_docx.py: Class D is FedRAMP pending
        # (20x Program path coming in 2027, specifics set during the Phase 4
        # Pilot), so no SDR exists to validate.
        print("Class D is FedRAMP pending; no SDR is generated or validated. "
              "See profiles/class-d-future/readiness-register.json.")
        return 1
    sdr = load(os.path.join(BASE, "sdr", "json", f"sdr-class-{cls}.json"))
    class_profile = load(os.path.join(BASE, "profiles", f"class-{cls}", "profile.json"))
    ksi_profile = load(os.path.join(BASE, "profiles", "common", "ksi-profile.json"))
    # The official SDR flattens ksiTests to strings, which destroys whether a
    # test was automated. FRC-CSX-VVK counts AUTOMATED methods, so read the
    # authoring source (records-store) where a test may be a structured
    # {method/method_id, automated, cadence} record before it is flattened.
    records = load(os.path.join(BASE, "sdr", "records", "records-store.json")) or {}
    records_ksi = records.get("ksi", {}) or {}

    dataset_version = class_profile["meta"]["dataset_version"]
    # Deterministic: reports are stamped with the dataset version, not a run
    # timestamp, so an unchanged pipeline yields byte-identical reports.
    stamp = f"deterministic check against dataset {dataset_version}"
    report = {"generated": stamp, "class": cls.upper(), "checks": [], "hard_failures": 0}

    def check(name, passed, detail, hard=True):
        # Result vocabulary is legible to a non-author reader (e.g. an assessor):
        #   PASS      - the check passed.
        #   FAIL      - a HARD failure; blocks the build (counted in hard_failures).
        #   ADVISORY  - a non-hard SHOULD-level shortfall; reported, never blocks.
        # Emitting "FAIL" for an advisory shortfall alongside hard_failures 0 is
        # confusing; ADVISORY makes the severity unambiguous. Downstream tooling
        # should treat hard_failures (or result == "FAIL") as the blocking signal.
        if passed:
            result = "PASS"
        elif hard:
            result = "FAIL"
        else:
            result = "ADVISORY"
        report["checks"].append({"check": name, "result": result, "detail": detail})
        if not passed and hard:
            report["hard_failures"] += 1

    # 1. Official schema validation
    errors = validate_schema(sdr)
    check("official_schema_validation", not errors,
          f"{len(errors)} schema errors" + (f"; first: {errors[0]}" if errors else ""))

    # 1b. Dataset version agreement. The profile meta records the dataset
    # version it was built from; the pinned dataset carries its own
    # info.version. If someone swaps the dataset file without rebuilding the
    # profiles, every report would still stamp the stale profile version and
    # the mismatch would go unnoticed. Assert they agree so the version the
    # README and badge advertise is provably the version on disk.
    dataset_info_version = load(DATASET).get("info", {}).get("version")
    check("dataset_version_agreement", dataset_info_version == dataset_version,
          f"pinned dataset info.version {dataset_info_version} vs profile "
          f"dataset_version {dataset_version}"
          + ("" if dataset_info_version == dataset_version
             else " (rebuild profiles after swapping the dataset)"))

    # 1c. Pinned-schema version guard. FedRAMP edits schema files in place
    # without renaming them, so the filename proves nothing; the $schemaVersion
    # inside is the real signal. Assert each pinned schema still carries the
    # $id and $schemaVersion the framework was built against, so a swapped or
    # upstream-bumped schema is caught at the gate, not only by the daily drift
    # hash job. Update EXPECTED_SCHEMAS deliberately when adopting a new schema.
    EXPECTED_SCHEMAS = {
        SDR_SCHEMA: {
            "$id": "https://fedramp.gov/schemas/fedramp-security-decision-record-schema-2026-06-24.json",
            "$schemaVersion": "1.1.1",
        },
        COMMON_SCHEMA: {
            "$id": "https://fedramp.gov/schemas/fedramp-common-definitions-schema-2026-06-24.json",
            "$schemaVersion": "0.4.0",
        },
        os.path.join(SCHEMA_DIR, "fedramp-certification-package-overview-schema-2026-06-24.json"): {
            "$id": "https://fedramp.gov/schemas/fedramp-certification-package-overview-schema-2026-06-24.json",
            "$schemaVersion": "0.1.6",
        },
        os.path.join(SCHEMA_DIR, "fedramp-ongoing-certification-report-schema-2026-06-24.json"): {
            "$id": "https://fedramp.gov/schemas/fedramp-ongoing-certification-report-schema-2026-06-24.json",
            "$schemaVersion": "0.2.1",
        },
        os.path.join(SCHEMA_DIR, "fedramp-incident-report-schema-2026-06-24.json"): {
            "$id": "https://fedramp.gov/schemas/fedramp-incident-report-schema-2026-06-24.json",
            "$schemaVersion": "0.2.1",
        },
        os.path.join(SCHEMA_DIR, "fedramp-significant-change-notifications-schema-2026-06-24.json"): {
            "$id": "https://fedramp.gov/schemas/fedramp-significant-change-notifications-schema-2026-06-24.json",
            "$schemaVersion": "0.1.3",
        },
        os.path.join(SCHEMA_DIR, "fedramp-accepted-vulnerability-info-schema-2026-06-24.json"): {
            "$id": "https://fedramp.gov/schemas/fedramp-accepted-vulnerability-info-schema-2026-06-24.json",
            "$schemaVersion": "0.1.1",
        },
        os.path.join(SCHEMA_DIR, "fedramp-vulnerability-detail-report-schema-2026-06-24.json"): {
            "$id": "https://fedramp.gov/schemas/fedramp-vulnerability-detail-report-schema-2026-06-24.json",
            "$schemaVersion": "0.1.1",
        },
        os.path.join(SCHEMA_DIR, "fedramp-historical-ver-activity-schema-2026-06-24.json"): {
            "$id": "https://fedramp.gov/schemas/fedramp-historical-ver-activity-schema-2026-06-24.json",
            "$schemaVersion": "0.1.1",
        },
    }
    schema_problems = []
    for path, expected in EXPECTED_SCHEMAS.items():
        doc = load(path)
        for key, want in expected.items():
            got = doc.get(key)
            if got != want:
                schema_problems.append(
                    f"{os.path.basename(path)} {key} {got} vs expected {want}")
    check("pinned_schema_version_guard", not schema_problems,
          "; ".join(schema_problems) if schema_problems
          else f"all {len(EXPECTED_SCHEMAS)} pinned schemas match expected $id and $schemaVersion")

    # 2. Coverage
    profile_ids = {r["rule_id"] for r in class_profile["rules"]}
    if cls == "a":
        # The submitted Class A SDR excludes FRC-CLA-OFR optional (MAY) rules
        # unless the provider explicitly opted them in via
        # offering-profile selected_optional_rules (default empty). Mirror that
        # here so expected == submitted: an unselected optional rule is
        # legitimately absent, not a coverage miss.
        selected = set(profile.get("selected_optional_rules") or [])
        profile_ids = {r["rule_id"] for r in class_profile["rules"]
                       if r.get("class_a_obligation") != "optional"
                       or r["rule_id"] in selected}
    sdr_ids = {r["frrID"] for r in sdr["fedRampRequirements"]}
    missing_rules = sorted(profile_ids - sdr_ids)
    extra_rules = sorted(sdr_ids - profile_ids)
    check("rule_coverage", not missing_rules and not extra_rules,
          f"missing: {missing_rules[:5]} extra: {extra_rules[:5]} "
          f"({len(sdr_ids)}/{len(profile_ids)} rules)")

    if cls == "a":
        # Class A KSI applicability is enumerated by FRC-CLA-MFR; expected set
        # comes from the tier map in the class-a profile meta.
        ksi_ids = set(class_profile["meta"]["class_a_ksis"].keys())
    elif cls == "b":
        # Class B: optional-at-B KSIs are opt-in, so the expected set is the
        # shared submitted set (baseline + selected optional) - matching what
        # the builder emits. Uses the same resolver the builder/preflight use.
        selected_ksi = list(profile.get("selected_optional_ksis") or [])
        ksi_ids = submitted_ksi_ids(ksi_profile["indicators"], cls, selected_ksi)
    else:
        ksi_ids = {k["ksi_id"] for k in ksi_profile["indicators"]}
    sdr_ksi = {k["ksiId"] for k in sdr["keySecurityIndicators"]}
    check("ksi_coverage", ksi_ids == sdr_ksi,
          f"{len(sdr_ksi)}/{len(ksi_ids)} KSIs present")

    # 3. Per-KSI results
    min_methods = {k["ksi_id"]: k["minimum_automated_methods"][f"class_{cls}"]
                   for k in ksi_profile["indicators"]}
    ksi_results = []
    for k in sdr["keySecurityIndicators"]:
        kid = k["ksiId"]
        required_fields = ["ksiId", "ksiImplementation", "ksiValidation",
                           "ksiAssessment", "ksiTests", "ksiEvidence"]
        fields_ok = all(f in k for f in required_fields)
        test_count = len(k.get("ksiTests", []))
        # FRC-CSX-VVK counts AUTOMATED methods, which the flattened ksiTests
        # strings cannot express. Count them from the authoring source instead.
        authoring_tests = (records_ksi.get(kid, {}) or {}).get("tests", [])
        automated_count, string_tests, _tot = count_automated_methods(authoring_tests)
        needed = min_methods.get(kid, 0)
        is_populated = not any("TBD" in s for s in k.get("ksiImplementation", []))
        # In a populated record, only counted automated methods satisfy the
        # minimum. In template (TBD) state, the requirement is not yet asserted,
        # so report the raw test_count informationally and do not hard-fail.
        effective = automated_count if is_populated else max(automated_count, test_count)
        ksi_results.append({
            "ksi_id": kid,
            "schema_fields_present": fields_ok,
            "implementation_status": k.get("ksiImplementationStatus"),
            "tests_defined": test_count,
            "automated_methods": automated_count,
            "unclassified_string_tests": string_tests,
            "minimum_automated_methods_for_class": needed,
            "meets_test_minimum": effective >= needed,
            "content_state": ("template_tbd" if not is_populated else "populated"),
            "checked": stamp,
        })
    all_fields = all(r["schema_fields_present"] for r in ksi_results)
    check("ksi_required_fields", all_fields, "all KSIs carry the six schema-required fields")

    # FRC-CSX-VVK normative force per class, verified verbatim against the
    # canonical dataset: Class A = MAY (optional), Class B = SHOULD (>= 1
    # automated method per KSI), Class C = MUST (>= 2), Class D = MUST (>= 4).
    # The count below the class minimum is reported, but whether falling short
    # is a genuine FedRAMP shortfall depends on the force: at Class C it is a
    # MUST shortfall; at Class B it is a SHOULD the provider is expected to meet
    # but which FedRAMP does not mandate. Never label a Class B SHOULD as a
    # FedRAMP requirement. This repository may still treat >= 1 as a release
    # policy stricter than FedRAMP, but that is repository policy, not a MUST.
    force = VVK_FORCE.get(cls, "SHOULD")
    below_min = [r["ksi_id"] for r in ksi_results if not r["meets_test_minimum"]]
    # A shortfall is a hard failure only where FedRAMP force is MUST (Class C/D)
    # AND the record is populated (not template TBD). In template state the
    # count is informational for every class.
    populated_below = [r["ksi_id"] for r in ksi_results
                       if not r["meets_test_minimum"] and r["content_state"] == "populated"]
    vvk_hard = force == "MUST" and bool(populated_below)
    check("ksi_test_minimums", not below_min,
          f"{len(below_min)} KSIs below the FRC-CSX-VVK AUTOMATED-method minimum "
          f"for class {cls.upper()} (counted from distinct automated authoring "
          f"methods, not raw ksiTests strings; FedRAMP force: {force}; "
          + ("MUST shortfall on populated records is a hard failure"
             if force == "MUST" else
             "SHOULD at this class, so this is an expectation, not a FedRAMP "
             "requirement; repository release policy may still require it")
          + (f"; {len(populated_below)} populated KSIs short"
             if populated_below else "; all shortfalls are template TBD state")
          + ")",
          hard=vvk_hard)

    # 4. Markdown detection in human-readable output
    txt = open(os.path.join(BASE, "sdr", "human-readable", f"sdr-class-{cls}.txt"),
               encoding="utf-8").read()
    md_hits = [label for pat, label in MD_PATTERNS if pat.search(txt)]
    check("no_markdown_in_human_readable", not md_hits, f"hits: {md_hits}")

    # 5. Sensitive patterns across generated artifacts. Docx files are
    # scanned via their extracted document text, never as raw bytes, so
    # compressed binary runs cannot false-positive as account IDs.
    hits = []
    # Scan the full customer bundle, not just sdr/: the delivered package also
    # includes the CPO, OCR, SCG, event artifacts, the release manifest, and the
    # crosswalk, and a leaked account id or key in any of those would ship.
    scan_roots = [
        os.path.join(BASE, "sdr"),
        os.path.join(BASE, "package"),
        os.path.join(BASE, "artifacts", "release-manifest.json"),
        os.path.join(BASE, "traceability"),
    ]
    scan_files = []
    for root in scan_roots:
        if os.path.isfile(root):
            scan_files.append(root)
        elif os.path.isdir(root):
            for r, _dirs, files in os.walk(root):
                scan_files.extend(os.path.join(r, fn) for fn in files)
    for path in scan_files:
        fn = os.path.basename(path)
        if fn.endswith(".docx"):
            content = docx_body_text(path)
        else:
            content = open(path, encoding="utf-8", errors="ignore").read()
        for pat, label in SENSITIVE_PATTERNS:
            if pat.search(content):
                hits.append(f"{fn}: {label}")
    check("no_sensitive_patterns", not hits, f"hits: {hits}")

    # 6. Content fidelity against the canonical dataset: every statement,
    # name, and force in the profile, the official JSON extensions, the
    # plain-text rendering, and the authoring docx must match the dataset
    # character for character (whitespace-normalized for renderings).
    fidelity_problems = content_fidelity(cls, class_profile, sdr)
    check("content_fidelity_against_dataset", not fidelity_problems,
          f"{len(fidelity_problems)} mismatches"
          + (f"; first: {fidelity_problems[0]}" if fidelity_problems else
             " (all statements, names, and forces match the dataset)"))
    if fidelity_problems:
        report["fidelity_problems"] = fidelity_problems[:50]

    # 7. Semantic completeness (CR26), independent of JSON-schema validity.
    # The official FedRAMP schema is intentionally minimal and permits extra
    # fields, so a zero-error schema result proves FORMAT conformance
    # (FRC-CSO-JSN), not that every required SDR-CSO-FRR / SDR-CSX-KSI /
    # SDR-CSX-KMT information item is present in the submitted document. This
    # gate checks that each required semantic element EXISTS on every entry
    # (presence, not truth: a TBD placeholder counts as present-but-unfilled;
    # an ABSENT key is a completeness defect). It never asserts the content is
    # correct: that remains the human assessor's determination.
    frr_required = ["implementationRisk", "verification", "independentVerification",
                    "independentValidation", "assessorResponses", "ruleArtifacts"]
    ksi_required = ["measures", "resultingCustomerRisk", "operatingCycle",
                    "measuresVerification", "automationVerification", "historicalMetrics"]
    sem_problems = []
    for entry in sdr["fedRampRequirements"]:
        sem = entry.get("providerExtensions", {}).get("xFedRampSemantic")
        if sem is None:
            sem_problems.append(f"{entry['frrID']}: missing xFedRampSemantic block")
            continue
        for f in frr_required:
            if f not in sem:
                sem_problems.append(f"{entry['frrID']}: missing SDR-CSO-FRR item {f}")
    # SDR-CSX-KMT historical metrics are required in the SDR for Class B and C;
    # Class A MAY include them. So the historicalMetrics block must be present
    # for B/C; for A its absence is acceptable.
    for entry in sdr["keySecurityIndicators"]:
        sem = entry.get("providerExtensions", {}).get("xFedRampSemantic")
        if sem is None:
            sem_problems.append(f"{entry['ksiId']}: missing xFedRampSemantic block")
            continue
        for f in ksi_required:
            if f == "historicalMetrics" and cls == "a":
                continue
            if f not in sem:
                sem_problems.append(f"{entry['ksiId']}: missing SDR-CSX item {f}")
        hm = sem.get("historicalMetrics", {})
        if cls in ("b", "c"):
            for mf in ("last30Days", "upToOneYear"):
                if mf not in hm:
                    sem_problems.append(f"{entry['ksiId']}: missing SDR-CSX-KMT {mf}")
            if cls == "c":
                # SDR-CSX-KMT Class C MUST supply "All daily metric data up to
                # the past year (where available)" IN the SDR - the actual data
                # (dailyData), not merely a pointer. The reference URI stays as
                # an optional external pointer alongside it. Presence, not truth:
                # the key must exist ("where available" is the provider's factual
                # determination, not this generator's).
                if "dailyData" not in hm:
                    sem_problems.append(f"{entry['ksiId']}: missing SDR-CSX-KMT dailyData (Class C: all daily metric data in the SDR)")
                # dailyDataReference is an OPTIONAL external pointer (CR26
                # requires the daily DATA, not a URL), so its absence is not a
                # completeness defect and is intentionally not required here.
    check("semantic_completeness_cr26", not sem_problems,
          f"{len(sem_problems)} required semantic elements absent from the "
          "submitted SDR"
          + (f"; first: {sem_problems[0]}" if sem_problems else
             " (every SDR-CSO-FRR and SDR-CSX-KSI/KMT required item is present; "
             "presence only, not a correctness or compliance determination)"))
    if sem_problems:
        report["semantic_problems"] = sem_problems[:50]

    # 8. Stale NIST identity-guidance reference guard. CR26's July 14 update
    # cites "the most recent NIST Digital Identity Guidelines" rather than a
    # fixed revision, and SP 800-63-4 (final, July 2025) supersedes 800-63-3.
    # New normative material must not cite 800-63-3 as current. The pinned
    # dataset is excluded from this scan: FedRAMP owns its own text, and if the
    # canonical dataset ever contained 800-63-3 that is a FedRAMP fact to
    # mirror, not a repository defect. This scans the framework's own generated
    # deliverables and authored docs.
    stale_ref = re.compile(r"800[- ]?63[- ]?3\b")
    stale_hits = []
    scan_roots = [os.path.join(BASE, "sdr"), os.path.join(BASE, "docs"),
                  os.path.join(BASE, "traceability")]
    for root in scan_roots:
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if not fn.endswith((".json", ".txt", ".md", ".csv")):
                    continue
                path = os.path.join(dirpath, fn)
                try:
                    content = open(path, encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                if stale_ref.search(content):
                    stale_hits.append(os.path.relpath(path, BASE))
    check("no_stale_nist_800_63_3", not stale_hits,
          f"stale 800-63-3 references in: {stale_hits}" if stale_hits
          else "no stale SP 800-63-3 reference in generated or authored content "
               "(current edition is SP 800-63-4)")

    # 9. Evidence linkage for populated MUST work. For a KSI whose record is
    # populated (not template TBD) and whose FRC-CSX-VVK force at this class is
    # MUST (Class C/D), require at least one evidence entry. This makes the
    # "every implemented MUST has traceable evidence" expectation an explicit
    # gate rather than only a readiness-scanner observation. Template TBD
    # records and lower-force classes are reported, not failed.
    force = VVK_FORCE.get(cls, "SHOULD")
    linkage_gaps = []
    for k in sdr["keySecurityIndicators"]:
        impl = k.get("ksiImplementation", [])
        populated = not any("TBD" in s for s in impl)
        if not populated:
            continue
        if not (k.get("ksiEvidence") or []):
            linkage_gaps.append(k["ksiId"])
    linkage_hard = force == "MUST" and bool(linkage_gaps)
    check("evidence_linkage_for_populated_musts", not linkage_gaps,
          (f"{len(linkage_gaps)} populated KSIs have no evidence entry "
           f"(force {force} at class {cls.upper()}"
           + ("; hard failure" if linkage_hard else
              "; reported, hard only at Class C/D where the force is MUST")
           + f"): {linkage_gaps[:5]}")
          if linkage_gaps else
          "every populated KSI carries at least one evidence entry",
          hard=linkage_hard)

    # 10. Sources lock consistency. references/sources.lock.json records a
    # SHA-256 for each pinned source; assert it still matches the file on disk,
    # so the lock cannot silently disagree with what is pinned. This complements
    # the daily drift-check workflow (which compares against upstream) by
    # guarding the local pin-to-lock agreement at the build gate.
    import hashlib
    lock_path = os.path.join(BASE, "references", "sources.lock.json")
    lock_problems = []
    if os.path.exists(lock_path):
        lock = load(lock_path)
        for key, entry in (lock.get("sources") or {}).items():
            rel = entry.get("pinned_path")
            want = entry.get("sha256")
            if not rel or not want:
                continue
            fpath = os.path.join(BASE, rel)
            if not os.path.exists(fpath):
                lock_problems.append(f"{key}: pinned_path {rel} missing")
                continue
            with open(fpath, "rb") as fh:
                got = hashlib.sha256(fh.read()).hexdigest()
            if got != want:
                lock_problems.append(f"{key}: {rel} sha256 {got[:12]} != lock {want[:12]}")
        check("sources_lock_consistency", not lock_problems,
              "; ".join(lock_problems) if lock_problems
              else "every pinned source matches its recorded sha256 in sources.lock.json")
    else:
        check("sources_lock_consistency", True,
              "no sources.lock.json present (skipped)", hard=False)

    os.makedirs(reports_dir, exist_ok=True)
    with open(os.path.join(reports_dir, "validation-report.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump(report, f, indent=1)
    with open(os.path.join(reports_dir, "ksi-test-results.json"), "w",
              encoding="utf-8", newline="\n") as f:
        json.dump({"generated": stamp, "class": cls.upper(), "results": ksi_results}, f, indent=1)

    for c in report["checks"]:
        print(f"{c['result']}: {c['check']} | {c['detail']}")
    print("hard failures:", report["hard_failures"])
    return 1 if report["hard_failures"] else 0


if __name__ == "__main__":
    sys.exit(main())
