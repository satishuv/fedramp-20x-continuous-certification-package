#!/usr/bin/env python3
"""Import AWS Config and Security Hub EXPORTS as collector facts (offline).

The live collector (automation/collectors/collect_facts.py) needs read-only
credentials into the customer's account. On many engagements the consultant
never gets those; the customer runs a few read-only AWS CLI commands in their
own environment and hands over the JSON. This module turns those exports into
the SAME facts-store shape the live collector writes, so the deterministic
prefill, the metric appender, the drafter and the review step consume them
through their existing paths with no new routing, and it derives dated
OBSERVATIONS for the vulnerability-detection rules so a rule narrative can be
proposed from the provider's own findings instead of only the official
how-to-comply text.

Inputs (AWS CLI JSON, auto-detected by top-level key; pass any subset):
  ComplianceByConfigRules      aws configservice describe-compliance-by-config-rule
  ConfigRules                  aws configservice describe-config-rules
  ConfigRulesEvaluationStatus  aws configservice describe-config-rule-evaluation-status
  Findings                     aws securityhub get-findings

Mapping as data. A deployed Config rule name becomes a framework managed-rule
id (the collector registry's config_managed_rule targets) through, in order:
  1. the exact managed-rule id (a rule deployed under its catalog name);
  2. Security Hub's service-linked convention `securityhub-<id>-<suffix>`
     (documented: the service-linked rule adds `securityhub` before the
     original rule name and a unique identifier after it);
  3. the rule's Source.SourceIdentifier from a ConfigRules export, resolved
     through the pinned catalog identifiers in
     automation/config-rules/known-config-managed-rules.json (read from the
     AWS Config Developer Guide; four identifiers are not a transform of the
     name, for example restricted-ssh is INCOMING_SSH_DISABLED);
  4. the provider's own map, automation/importers/config-rule-name-map.json.
A name that matches none of these is NOT guessed. It goes to the review queue
(printed, and stored under meta.unmapped_config_rules in the facts file) for
the provider to add to the map and re-import.

Boundary, identical to the collector's:
  - Facts are telemetry, never statuses. Nothing here writes the record store,
    sets implementation_status, or writes assessment.
  - No identifiers that could carry specifics: no finding titles or ids, no
    resource ids, no ARNs, no account ids. Counts, states, standards, dates.
  - No network. No credentials. The export is produced by the customer.
  - The observation time is taken from the export itself (latest finding
    UpdatedAt / rule LastSuccessfulEvaluationTime). An export that carries no
    timestamp needs --observed-at; the importer refuses to stamp "now" on data
    of unknown age, because freshness gates downstream depend on that date.
  - One source per region. If a live collection for the region exists in the
    facts store, the import is refused: the metric appender sums posture facts
    for the same route across files, so two sources for one scope would
    double-count it.

Usage:
  python automation/importers/import_findings.py --region us-east-1 exports/*.json
  python automation/importers/import_findings.py --region us-east-1 exports/*.json --write
Exit codes: 0 ok, 1 input or mapping error, 2 no observation time, 4 nothing
evaluated (same meaning as the collector's EXIT_NO_EVALUATED).
"""
import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REGISTRY = os.path.join(BASE, "automation", "collectors", "registry.json")
FACTS_DIR = os.path.join(BASE, "automation", "facts")
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
NAME_MAP = os.path.join(BASE, "automation", "importers", "config-rule-name-map.json")
VOCABULARY = os.path.join(BASE, "automation", "config-rules", "known-config-managed-rules.json")

sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))
from collect_facts import EXIT_NO_EVALUATED, collection_outcome  # noqa: E402

# Export kinds, keyed by the AWS CLI's top-level response member.
KINDS = {
    "ComplianceByConfigRules": "config-compliance",
    "ConfigRules": "config-rules",
    "ConfigRulesEvaluationStatus": "config-evaluation-status",
    "Findings": "securityhub-findings",
}

# CR26 rules the observations are offered to. Each is checked against the
# pinned dataset at import time (dataset_rule_ids), never trusted from here.
#   VDR-CSO-DET  vulnerability detection, which the rule says includes
#                "automated control testing" and persistently verifying that
#                resources operate as intended: Security Hub control checks
#                and Config rule evaluations are that activity's output.
#   VDR-CSO-RES  vulnerability response: track, monitor, mitigate, remediate
#                detected vulnerabilities; the Workflow states carry tracking.
#   VDR-CSO-ADT  automated services for detection and response.
#   VDR-TFR-MVX  persistent machine verification and validation (20x): the
#                evaluation cadence Config records per rule.
OBSERVED_RULES = ("VDR-CSO-DET", "VDR-CSO-RES", "VDR-CSO-ADT", "VDR-TFR-MVX")

EVALUATED = ("COMPLIANT", "NON_COMPLIANT", "INSUFFICIENT_DATA", "NOT_APPLICABLE")
# Worst-wins precedence when one framework id is deployed under several names.
_PRECEDENCE = {"NON_COMPLIANT": 0, "COMPLIANT": 1, "INSUFFICIENT_DATA": 2,
               "NOT_APPLICABLE": 3}
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
_WORKFLOWS = ("NEW", "NOTIFIED", "SUPPRESSED", "RESOLVED")


class RefusedInput(Exception):
    """An input the importer refuses (unreadable, undetected, bad mapping)."""


def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError) as e:
        raise RefusedInput(f"{path}: not readable JSON ({type(e).__name__})") from e


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_kind(doc):
    """The export kind from its top-level key, or None."""
    if not isinstance(doc, dict):
        return None
    hits = [k for k in KINDS if k in doc]
    return KINDS[hits[0]] if len(hits) == 1 else None


def parse_ts(value):
    """A tz-aware datetime from an AWS CLI timestamp, or None. The CLI emits
    ISO-8601 strings (fraction and Z or +00:00); a numeric epoch is accepted
    for exports produced through the SDK with a custom encoder."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


# ---- Config rule name mapping (data, never a guess) --------------------------

def registry_rule_checks(registry):
    """framework managed-rule id -> [check_id, ...], as the collector builds it."""
    out = {}
    for entry in registry["ksis"].values():
        for check in entry["checks"]:
            if check.get("collectable_now") and check["type"] == "config_managed_rule":
                out.setdefault(check["target"], []).append(check["check_id"])
    return out


def load_name_map(path, known_ids):
    """The provider's name map {deployed name: framework id}. Every value must
    be a framework id the registry routes; anything else is a typo that could
    never route and is refused rather than silently dropped."""
    if not os.path.exists(path):
        return {}
    doc = load_json(path)
    names = doc.get("names") if isinstance(doc, dict) else None
    if not isinstance(names, dict):
        raise RefusedInput(f"{path}: expected an object with a 'names' map")
    bad = {n: v for n, v in names.items() if v not in known_ids}
    if bad:
        raise RefusedInput(
            f"{path}: these map values are not framework managed-rule ids and "
            f"cannot route: {json.dumps(bad, sort_keys=True)}")
    return dict(names)


_SH_LINKED = re.compile(r"^securityhub-(?P<body>.+)-(?P<suffix>[0-9a-zA-Z]+)$")


def catalog_identifiers(path=VOCABULARY):
    """{catalog identifier: framework managed-rule id}, from the pinned
    vocabulary (read from the AWS Config Developer Guide, one page per rule).
    The identifier is not derivable from the name (restricted-ssh is
    INCOMING_SSH_DISABLED), so this is data, never a transform."""
    doc = load_json(path)
    pairs = doc.get("config_managed_rule_identifiers") or {}
    if not isinstance(pairs, dict) or not pairs:
        raise RefusedInput(f"{path}: config_managed_rule_identifiers is missing")
    return {ident: name for name, ident in pairs.items()}


def map_rule_name(name, known_ids, source_identifiers, name_map, by_identifier=None):
    """Resolve a deployed Config rule name to a framework managed-rule id, or
    None. `source_identifiers` is {deployed name: Source.SourceIdentifier}
    from a ConfigRules export (may be empty); `by_identifier` is the pinned
    {catalog identifier: framework id} map (catalog_identifiers())."""
    if name in known_ids:
        return name
    m = _SH_LINKED.match(name)
    if m and m.group("body") in known_ids:
        return m.group("body")
    ident = source_identifiers.get(name)
    if isinstance(ident, str) and by_identifier:
        candidate = by_identifier.get(ident.strip())
        if candidate in known_ids:
            return candidate
    return name_map.get(name)


# ---- Export readers ----------------------------------------------------------

def read_exports(paths):
    """Load every export, detect its kind, refuse unknown shapes. Returns
    (by_kind, files) where by_kind maps kind -> list of documents (several
    exports of one kind, e.g. two regions' findings, are all kept) and files
    is the provenance list [{name, sha256, kind}]."""
    by_kind = {}
    files = []
    for p in paths:
        doc = load_json(p)
        kind = detect_kind(doc)
        if kind is None:
            raise RefusedInput(
                f"{p}: not a recognised export. Expected exactly one of the "
                f"top-level keys {sorted(KINDS)} (AWS CLI output, unmodified).")
        by_kind.setdefault(kind, []).append(doc)
        files.append({"name": os.path.basename(p), "sha256": sha256_file(p),
                      "kind": kind})
    return by_kind, files


def config_compliance(docs):
    """{deployed rule name: ComplianceType or 'UNKNOWN'}, plus whether any
    export was cut short (a top-level NextToken means the CLI was run without
    its default pagination, so the view is partial)."""
    rows = {}
    partial = False
    for doc in docs:
        if doc.get("NextToken"):
            partial = True
        for r in doc.get("ComplianceByConfigRules") or []:
            name = r.get("ConfigRuleName")
            if not name:
                continue
            ct = (r.get("Compliance") or {}).get("ComplianceType") or "UNKNOWN"
            rows[name] = ct if ct in EVALUATED else "UNKNOWN"
    return rows, partial


def config_source_identifiers(docs):
    out = {}
    for doc in docs:
        for r in doc.get("ConfigRules") or []:
            name = r.get("ConfigRuleName")
            ident = (r.get("Source") or {}).get("SourceIdentifier")
            if name and (r.get("Source") or {}).get("Owner") == "AWS" and ident:
                out[name] = ident
    return out


def config_evaluation_status(docs):
    """{deployed rule name: {last_success: dt|None, last_failed: dt|None,
    error_code: str|None}}"""
    out = {}
    for doc in docs:
        for r in doc.get("ConfigRulesEvaluationStatus") or []:
            name = r.get("ConfigRuleName")
            if not name:
                continue
            out[name] = {
                "last_success": parse_ts(r.get("LastSuccessfulEvaluationTime")),
                "last_failed": parse_ts(r.get("LastFailedEvaluationTime")),
                "error_code": r.get("LastErrorCode") or None,
            }
    return out


def securityhub_summary(docs):
    """Counts over an ASFF findings export. Nothing identifying is kept."""
    s = {"findings": 0, "active": 0, "active_failed": 0, "regions": set(),
         "standards": set(), "products": set(), "controls_failed": set(),
         "severity_active_failed": {k: 0 for k in _SEVERITIES},
         "workflow_active": {k: 0 for k in _WORKFLOWS},
         "workflow_all": {k: 0 for k in _WORKFLOWS},
         "latest_updated": None, "partial": False}
    for doc in docs:
        if doc.get("NextToken"):
            s["partial"] = True
        for f in doc.get("Findings") or []:
            s["findings"] += 1
            comp = f.get("Compliance") or {}
            wf = (f.get("Workflow") or {}).get("Status")
            sev = ((f.get("Severity") or {}).get("Label") or "").upper()
            active = f.get("RecordState") == "ACTIVE"
            if f.get("Region"):
                s["regions"].add(f["Region"])
            if f.get("ProductName"):
                s["products"].add(str(f["ProductName"]))
            for st in comp.get("AssociatedStandards") or []:
                if isinstance(st, dict) and st.get("StandardsId"):
                    s["standards"].add(st["StandardsId"])
            if wf in _WORKFLOWS:
                s["workflow_all"][wf] += 1
            if active:
                s["active"] += 1
                if wf in _WORKFLOWS:
                    s["workflow_active"][wf] += 1
                if comp.get("Status") == "FAILED":
                    s["active_failed"] += 1
                    if sev in s["severity_active_failed"]:
                        s["severity_active_failed"][sev] += 1
                    if comp.get("SecurityControlId"):
                        s["controls_failed"].add(comp["SecurityControlId"])
            ts = parse_ts(f.get("UpdatedAt"))
            if ts and (s["latest_updated"] is None or ts > s["latest_updated"]):
                s["latest_updated"] = ts
    return s


# ---- Fact builders (collector-shaped) ----------------------------------------

def _fact(service, check, status, detail, region, collected_at, measured=None,
          total=None, scope_total=None, partial=False):
    """The collector's posture-fact shape (collectors._fact), with the import's
    observation time instead of 'now'."""
    f = {"service": service, "check": check, "status": status, "detail": detail,
         "region": region, "collected_at": collected_at}
    if measured is not None and total is not None:
        f["measured"] = measured
        f["total"] = total
        f["evaluated_total"] = total
    if scope_total is not None:
        f["scope_total"] = scope_total
        f["unknown_total"] = max(scope_total - (total or 0), 0)
    if partial:
        f["partial"] = True
    return f


def build_config_facts(compliance, rule_checks, source_identifiers, name_map,
                       eval_status, region, collected_at, by_identifier=None):
    """Collector-shaped config facts for the framework ids the export covers,
    plus the unmapped review queue. Several deployed instances of one id
    aggregate worst-wins (any NON_COMPLIANT wins; COMPLIANT beats
    INSUFFICIENT_DATA beats NOT_APPLICABLE)."""
    known = set(rule_checks)
    per_id = {}
    unmapped = []
    for name, ct in sorted(compliance.items()):
        fid = map_rule_name(name, known, source_identifiers, name_map, by_identifier)
        if fid is None:
            unmapped.append(name)
            continue
        per_id.setdefault(fid, []).append((name, ct))
    facts = []
    for fid, instances in sorted(per_id.items()):
        evaluated = [ct for _, ct in instances if ct in EVALUATED]
        ct = min(evaluated, key=_PRECEDENCE.get) if evaluated else "UNKNOWN"
        fact = {"rule": fid, "check_ids": rule_checks[fid],
                "collected_at": collected_at, "region": region,
                "compliance_type": ct, "source": "import",
                "instances": len(instances),
                "deployed_names": sorted(n for n, _ in instances)}
        last = [eval_status[n]["last_success"] for n, _ in instances
                if n in eval_status and eval_status[n]["last_success"]]
        if last:
            fact["last_evaluated_at"] = iso(max(last))
        facts.append(fact)
    return facts, unmapped


def build_posture_facts(compliance, partial_cfg, sh, region, collected_at):
    facts = []
    if compliance:
        compliant = sum(1 for ct in compliance.values() if ct == "COMPLIANT")
        noncompliant = sum(1 for ct in compliance.values() if ct == "NON_COMPLIANT")
        scope = len(compliance)
        if partial_cfg:
            facts.append(_fact("config", "rule_compliance", "OBSERVED_PARTIAL",
                               f"Export cut short (NextToken present); {compliant} of "
                               f"{compliant + noncompliant} rule(s) report COMPLIANT "
                               f"among {scope}+ seen. Bounded sample, not scorable.",
                               region, collected_at, scope_total=scope, partial=True))
        elif compliant + noncompliant == 0:
            facts.append(_fact("config", "rule_compliance", "UNKNOWN",
                               f"None of {scope} rule(s) carry a COMPLIANT or "
                               "NON_COMPLIANT result in the export", region, collected_at))
        else:
            facts.append(_fact("config", "rule_compliance", "OBSERVED",
                               f"{compliant} of {compliant + noncompliant} rule(s) report "
                               f"COMPLIANT ({scope} in scope, "
                               f"{scope - compliant - noncompliant} unevaluated); "
                               "from a describe-compliance-by-config-rule export",
                               region, collected_at, measured=compliant,
                               total=compliant + noncompliant, scope_total=scope))
    if sh and sh["findings"]:
        more = "+" if sh["partial"] else ""
        facts.append(_fact("securityhub", "failed_findings", "OBSERVED",
                           f"{sh['active_failed']}{more} active failed control findings "
                           f"(get-findings export, {sh['findings']} finding(s) in "
                           f"{len(sh['regions']) or 1} region(s))", region, collected_at))
        # A get-findings export can only be produced while Security Hub is
        # enabled in the calling region (the API refuses otherwise), so the
        # aggregation point is on. Inference stated in the detail.
        facts.append(_fact("securityhub", "siem_aggregation", "ENABLED",
                           "Security Hub is enabled as the aggregation point "
                           "(inferred: a get-findings export exists for this region)",
                           region, collected_at))
    return facts


def dataset_rule_ids(dataset_path=DATASET):
    """Every FRR rule id in the pinned dataset, across all applicability
    branches (all, 20x, rev5). Reading only one branch hides real ids."""
    ds = load_json(dataset_path)
    ids = set()
    for family in (ds.get("FRR") or {}).values():
        for branch in (family.get("data") or {}).values():
            for subset in (branch or {}).values():
                ids.update(k for k in (subset or {}) if isinstance(k, str))
    return ids


def build_rule_observations(compliance, config_facts, eval_status, sh, observed,
                            region):
    """Dated, count-only observations per rule id, as text the drafter may
    quote into a labelled proposal. Each cites its source and date."""
    obs = {}
    when = iso(observed)

    def add(rid, source, text):
        obs.setdefault(rid, []).append({"observed_at": when, "source": source,
                                        "region": region, "text": text})

    if compliance:
        n = len(compliance)
        nc = sum(1 for ct in compliance.values() if ct == "NON_COMPLIANT")
        mapped = len(config_facts)
        add("VDR-CSO-DET", "aws-config-export",
            f"AWS Config evaluates {n} rule(s) in this region; {nc} report "
            f"NON_COMPLIANT; {mapped} map to the framework's recognised managed rules.")
        add("VDR-CSO-ADT", "aws-config-export",
            f"AWS Config rule evaluation is in use ({n} rule(s) deployed).")
    if eval_status:
        succ = [v["last_success"] for v in eval_status.values() if v["last_success"]]
        if succ:
            within7 = sum(1 for d in succ if observed - d <= timedelta(days=7))
            within3 = sum(1 for d in succ if observed - d <= timedelta(days=3))
            failed_after = sum(
                1 for v in eval_status.values()
                if v["last_failed"] and v["last_success"] and v["last_failed"] > v["last_success"])
            add("VDR-TFR-MVX", "aws-config-export",
                f"Of {len(succ)} rule(s) with a recorded last successful evaluation, "
                f"{within7} evaluated within 7 days and {within3} within 3 days of the "
                f"export time; oldest last success {iso(min(succ))[:10]}; "
                f"{failed_after} rule(s) whose last failed evaluation is more recent "
                "than their last success.")
    if sh and sh["findings"]:
        sev = sh["severity_active_failed"]
        add("VDR-CSO-DET", "securityhub-export",
            f"Security Hub reports {sh['active_failed']} active finding(s) with "
            f"Compliance.Status FAILED ({sev['CRITICAL']} critical, {sev['HIGH']} high, "
            f"{sev['MEDIUM']} medium, {sev['LOW']} low) across "
            f"{len(sh['controls_failed'])} distinct control(s); "
            f"{len(sh['standards'])} standard(s) associated.")
        wa, wl = sh["workflow_active"], sh["workflow_all"]
        add("VDR-CSO-RES", "securityhub-export",
            f"Workflow states on active findings: NEW {wa['NEW']}, NOTIFIED "
            f"{wa['NOTIFIED']}, SUPPRESSED {wa['SUPPRESSED']}; RESOLVED across all "
            f"records in the export: {wl['RESOLVED']}.")
        products = sorted(sh["products"])[:8]
        add("VDR-CSO-ADT", "securityhub-export",
            "Security Hub aggregates automated findings"
            + (f" from: {', '.join(products)}" if products else "")
            + (f"; standards enabled: {', '.join(sorted(sh['standards'])[:6])}"
               if sh["standards"] else "") + ".")
    return obs


# ---- Driver -------------------------------------------------------------------

def build_store(paths, region, observed_at=None, registry_path=REGISTRY,
                name_map_path=NAME_MAP, dataset_path=DATASET,
                vocabulary_path=VOCABULARY):
    """Assemble the facts store document from the exports. Pure apart from
    reading the input files; raises RefusedInput on refused input."""
    registry = load_json(registry_path)
    rule_checks = registry_rule_checks(registry)
    name_map = load_name_map(name_map_path, set(rule_checks))
    by_identifier = catalog_identifiers(vocabulary_path)
    by_kind, files = read_exports(paths)

    compliance, partial_cfg = config_compliance(by_kind.get("config-compliance", []))
    source_identifiers = config_source_identifiers(by_kind.get("config-rules", []))
    eval_status = config_evaluation_status(by_kind.get("config-evaluation-status", []))
    sh = securityhub_summary(by_kind["securityhub-findings"]) \
        if "securityhub-findings" in by_kind else None

    # Observation time: from the export, else the caller's --observed-at.
    candidates = [v["last_success"] for v in eval_status.values() if v["last_success"]]
    if sh and sh["latest_updated"]:
        candidates.append(sh["latest_updated"])
    explicit = parse_ts(observed_at) if observed_at else None
    if observed_at and explicit is None:
        raise RefusedInput(f"--observed-at {observed_at!r} is not an ISO-8601 time")
    observed = explicit or (max(candidates) if candidates else None)
    if observed is None:
        return None, files  # caller reports the missing time (exit 2)
    collected_at = iso(observed)

    config_facts, unmapped = build_config_facts(
        compliance, rule_checks, source_identifiers, name_map, eval_status,
        region, collected_at, by_identifier)
    posture_facts = build_posture_facts(compliance, partial_cfg, sh, region, collected_at)
    observations = build_rule_observations(compliance, config_facts, eval_status, sh,
                                           observed, region)
    valid_ids = dataset_rule_ids(dataset_path)
    bad = sorted(set(observations) - valid_ids)
    if bad:
        raise RefusedInput(f"observation rule ids not in the pinned dataset: {bad}")

    outcome = collection_outcome(config_facts, posture_facts)
    outcome["status"] = "OK" if outcome["evaluated"] else "FAILED_NO_EVALUATED_OUTCOME"
    digest = hashlib.sha256("|".join(f["sha256"] for f in files).encode("utf-8"))
    store = {
        "meta": {
            "collected_at": collected_at,
            "run_id": "import-" + digest.hexdigest()[:16],
            "region": region,
            "identity_arn": None,
            "source": "import",
            "import_files": files,
            "observed_at_source": "explicit" if explicit else "export",
            "registry_dataset_version": registry["meta"]["dataset_version"],
            "collection_outcome": outcome,
            "unmapped_config_rules": unmapped,
            "note": ("Facts imported from customer-produced AWS CLI exports; "
                     "telemetry, not statuses. Never commit this file."),
        },
        "facts": config_facts,
        "posture_facts": posture_facts,
        "rule_observations": observations,
    }
    return store, files


def out_path(facts_dir, region):
    return os.path.join(facts_dir, f"facts-{region}-import.json")


def live_path(facts_dir, region):
    return os.path.join(facts_dir, f"facts-{region}.json")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Import AWS Config / Security Hub exports as collector facts (offline).")
    ap.add_argument("exports", nargs="+", help="AWS CLI JSON export file(s)")
    ap.add_argument("--region", required=True,
                    help="the region the exports were taken in (the facts' scope)")
    ap.add_argument("--observed-at", default=None,
                    help="ISO-8601 time the exports were taken; needed only when the "
                         "exports carry no timestamp of their own")
    ap.add_argument("--write", action="store_true",
                    help="write automation/facts/facts-<region>-import.json")
    ap.add_argument("--out-dir", default=FACTS_DIR, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    if os.path.exists(live_path(args.out_dir, args.region)):
        print(f"Refusing: a live collection exists for {args.region} "
              f"({os.path.relpath(live_path(args.out_dir, args.region), BASE)}). The "
              "metric appender sums posture facts per route across files, so an import "
              "for the same region would double-count that scope. Use the live "
              "collection, or remove it deliberately and re-run the import.")
        return 1
    try:
        store, files = build_store(args.exports, args.region, args.observed_at)
    except RefusedInput as e:
        print(f"Import refused: {e}")
        return 1
    if store is None:
        print("The exports carry no observation time (no finding UpdatedAt, no rule "
              "LastSuccessfulEvaluationTime). Pass --observed-at <ISO-8601> for when "
              "they were taken; the importer will not stamp data of unknown age as "
              "fresh.")
        return 2

    meta = store["meta"]
    print(f"exports: {', '.join(f['name'] + ' (' + f['kind'] + ')' for f in files)}")
    print(f"observed at {meta['collected_at']} ({meta['observed_at_source']}); "
          f"region {args.region}")
    print(f"config facts: {len(store['facts'])} framework rule(s) mapped; "
          f"posture facts: {len(store['posture_facts'])}; "
          f"evaluated outcomes: {meta['collection_outcome']['evaluated']}")
    for f in store["facts"]:
        print(f"  {f['rule']}: {f['compliance_type']} ({f['instances']} instance(s))")
    for pf in store["posture_facts"]:
        print(f"  {pf['service']}.{pf['check']}: {pf['status']}")
    if meta["unmapped_config_rules"]:
        print(f"review queue: {len(meta['unmapped_config_rules'])} Config rule name(s) "
              "map to no framework id (add them to "
              f"{os.path.relpath(NAME_MAP, BASE)} if they are managed rules under "
              "another name):")
        for n in meta["unmapped_config_rules"]:
            print(f"  {n}")
    if store["rule_observations"]:
        print("rule observations (offered to the drafter as labelled proposals):")
        for rid, items in sorted(store["rule_observations"].items()):
            for o in items:
                print(f"  {rid} [{o['source']}]: {o['text']}")

    if args.write:
        os.makedirs(args.out_dir, exist_ok=True)
        path = out_path(args.out_dir, args.region)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(store, fh, indent=1, default=str)
        print(f"wrote {os.path.relpath(path, BASE)} (git-excluded). Next: "
              "python automation/prefill/prefill_from_facts.py --write and "
              "python automation/ai/draft_narratives.py --write, then "
              "python sdr.py review --walk.")
    else:
        print("dry run; pass --write to store these facts.")
    if meta["collection_outcome"]["evaluated"] == 0:
        print("FAIL. The exports carry no evaluated outcome (no COMPLIANT / "
              "NON_COMPLIANT rule, no finding). Nothing about the boundary was "
              "observed; this is not an empty success.")
        return EXIT_NO_EVALUATED
    return 0


if __name__ == "__main__":
    sys.exit(main())
