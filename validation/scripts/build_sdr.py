# Generate the Security Decision Record for the class selected in the offering
# profile, in both official-schema JSON and human-readable plain text.
#
# Pipeline position: build_catalogs.py -> build_profiles.py -> build_sdr.py -> validate_sdr.py
#
# Inputs:
#   profiles/common/offering-profile.json   central customization profile (selects class)
#   profiles/class-<x>/profile.json         resolved provider rules for the class
#   profiles/common/ksi-profile.json        all KSI indicators with per-class minimums
#   sdr/records/records-store.json          statement content per rule and KSI
#                                           (scaffolded with honest TBD markers on first run)
#
# Outputs:
#   sdr/json/sdr-class-<x>.json             official FedRAMP SDR schema document
#   sdr/json/sdr-class-<x>-extensions.json  provider operational metadata companion
#   sdr/human-readable/sdr-class-<x>.txt    plain-text rendering, no markdown symbols
#
# The official JSON contains only schema-defined properties so it stays portable.
# Everything richer lives in the extensions companion, keyed by frrID and ksiId.

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
KSI_PROFILE = os.path.join(BASE, "profiles", "common", "ksi-profile.json")
RECORDS = os.path.join(BASE, "sdr", "records", "records-store.json")

# Shared Class B KSI-scope resolver, single source of truth used by the builder,
# validator, scanner, assurance-graph, and preflight so every layer scopes the
# submitted SDR identically. sdr.py guards execution under __main__, so importing
# it has no side effects.
if BASE not in sys.path:
    sys.path.insert(0, BASE)
from sdr import submitted_ksi_ids, _utc_today  # noqa: E402
import profile_contract as _pc  # noqa: E402  (offering_title: honest title while the name is TBD)

TBD = "TBD: Information has not been provided."


def ksi_statement_for_class(k, cls):
    """Resolve a KSI's security-outcome statement for a certification class.

    Five KSIs in CR26 (KSI-CNA-EIS, KSI-MLA-ALA, KSI-SVC-PRR, KSI-SVC-RUD,
    KSI-SVC-VCM) carry a null top-level statement and put the real, class-varying
    text under varies_by_class[b|c]. Emitting the top-level statement for those
    silently drops the requirement text (or mislabels it "FedRAMP pending").
    Prefer the class-specific statement; fall back to the top-level one; return
    None only if neither exists."""
    vbc = k.get("varies_by_class")
    if isinstance(vbc, dict):
        variant = vbc.get((cls or "").lower())
        if isinstance(variant, dict) and variant.get("statement"):
            return variant["statement"]
    return k.get("statement")


def _test_to_str(t):
    """Render one KSI test entry as a readable string. A test may be a plain
    string OR a structured record (e.g. {method, automated, cadence}); a
    provider recording structured automated methods must not crash the
    human-readable build. Coerce a dict to 'method (automated, cadence)'."""
    if isinstance(t, str):
        return t
    if isinstance(t, dict):
        method = t.get("method") or t.get("name") or t.get("description") or "test"
        bits = []
        if t.get("automated") is True:
            bits.append("automated")
        elif t.get("automated") is False:
            bits.append("manual")
        if t.get("cadence"):
            bits.append(str(t["cadence"]))
        return f"{method}" + (f" ({', '.join(bits)})" if bits else "")
    return str(t)


# The official SDR schema constrains frr/ksiImplementationStatus to exactly
# these three values. The record store uses a richer AUTHORING vocabulary
# (Planned, Gap, Exception, Not Applicable, Needs validation, FedRAMP pending,
# TBD, ...). Map the authoring status to the official enum for the schema field,
# and preserve the authoring nuance in the extension (xFedRampSemantic /
# xAuthoringStatus) so meaning is not lost. Only an explicit Implemented /
# Partially Implemented counts as implemented; every other authoring state is
# an honest "Not Implemented" in the official field.
_OFFICIAL_STATUSES = {"Implemented", "Not Implemented", "Partially Implemented"}


def official_status(authoring_status):
    s = str(authoring_status or "").strip()
    if s in _OFFICIAL_STATUSES:
        return s
    if s.lower() in ("partially implemented", "partial"):
        return "Partially Implemented"
    return "Not Implemented"


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def dump(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, indent=1)


def scaffold_records(rules, ksis):
    """Create the record store with honest placeholders. Existing content is
    never overwritten; this only runs when the store does not exist."""
    store = {
        "store_note": (
            "Statement content for every rule and KSI. Generic template text and "
            "TBD markers only in the public template. Reference-architecture "
            "examples are labeled as assumptions, never as confirmed implementations."
        ),
        "frr": {},
        "ksi": {},
    }
    for r in rules:
        store["frr"][r["rule_id"]] = {
            "implementation_status": "Not Implemented",
            "implementation": [TBD],
            "validation": [TBD],
            "assessment": [
                "TBD: Independent assessment has not been performed."
            ],
            # SDR-CSO-FRR requires seven information items per rule, but the
            # official schema carries only frrImplementation, frrValidation and
            # frrAssessment. Items 4 to 7 (independent verification, independent
            # validation, responses to assessor comments, rule-specific
            # artifacts) have no official field, so they live here.
            "extension": {
                "owner": TBD,
                "verification": TBD,
                "validation_frequency": TBD,
                "failure_condition": TBD,
                "failure_response": TBD,
                "evidence_freshness": TBD,
                "exception_reference": "None recorded",
                "independent_verification": TBD,
                "independent_validation": TBD,
                "assessor_responses": "None recorded",
                "rule_artifacts": [],
                "senior_official_acceptance": "Not required: rule is followed",
                "customer_risk": TBD,
                "responsibility": {
                    "aws": TBD,
                    "provider": TBD,
                    "customer": TBD,
                },
            },
        }
    for k in ksis:
        pending = k["content_status"].startswith("FedRAMP pending")
        store["ksi"][k["ksi_id"]] = {
            "implementation_status": "Not Implemented",
            "implementation": [
                "FedRAMP pending: this indicator has no statement in the official dataset yet."
                if pending
                else TBD
            ],
            "validation": [TBD],
            "assessment": ["TBD: Independent assessment has not been performed."],
            "tests": [],
            "evidence": [],
            # SDR-CSX-KMT. Class A MAY include historical metrics; Class B and
            # Class C MUST. Daily data is Class C only. The collector should
            # write these rather than a human.
            "historical_metrics": {
                "last_30_days": TBD,
                "up_to_one_year": TBD,
                # Class C MUST supply the actual daily metric data up to the past
                # year (where available), SDR-CSX-KMT. daily_data holds the
                # normalized in-SDR series (list of {date, value/status}), which
                # the collector should write; daily_data_reference is an optional
                # external pointer retained alongside it.
                "daily_data": [],
                "daily_data_reference": TBD,
            },
            "extension": {
                "owner": TBD,
                "measures": TBD,
                # SDR-CSX-KSI alternative: the reason and resulting customer risk
                # when measures are not available for this indicator.
                "resulting_customer_risk": TBD,
                "operating_cycle": TBD,
                "metric_source": TBD,
                "pass_condition": TBD,
                "failure_condition": TBD,
                "failure_response": TBD,
                "known_limitation": TBD,
                # SDR-CSX-KSI items 3 and 4: verification that the measures
                # demonstrate the indicator, and that the automation behind
                # them is accurate and sufficient (or that automation is not
                # necessary). Neither has an official schema field.
                "measures_verification": TBD,
                "automation_verification": TBD,
                "assessor_responses": "None recorded",
                "customer_responsibility": TBD,
                "aws_responsibility": TBD,
                "provider_responsibility": TBD,
                "exception_reference": "None recorded",
            },
        }
    return store


def build_official(profile, rules, ksis, records, metric_history=None, cls=None):
    # metadata block is official as of schema 1.1.1 (2026-07-14 in-place
    # update to the 2026-06-24 schema file), per SDR-CSO-MTD.
    # Each entry also carries a providerExtensions object with the rule name
    # and the family short form spelled out. The official schema does not set
    # additionalProperties, so extra properties are permitted; keeping them in
    # one clearly isolated object preserves portability of the official fields.
    fam_names = load_family_names()
    # Deterministic: lastUpdated comes from the offering profile (bump
    # sdr_last_updated when record content changes), falling back to the
    # dataset version date, never a run timestamp.
    dataset_date = "-".join(profile["dataset_version"].split(".")[:3])
    last_updated = profile.get("sdr_last_updated") or f"{dataset_date}T00:00:00+00:00"
    doc = {
        # One resolver (profile_contract.cpo_uri): the schema types this as a URI,
        # so a TBD profile value becomes the shared placeholder; preflight blocks.
        "certificationPackageOverviewUri": _pc.cpo_uri(profile),
        "metadata": {
            "version": profile["sdr_version"],
            "lastUpdated": last_updated,
            "updateSource": "build_sdr.py generator",
        },
        "fedRampRequirements": [],
        "keySecurityIndicators": [],
    }
    # Finding 7: when optional IV&V is used, the Class A package includes the
    # IV&V Assessment Summary in the SDR (IVV-IAS-OSA), alongside the CPO's
    # overall summary. Emit it into the submitted document (not a sidecar) when
    # the offering selects IVV-CSO-FIA at Class A, or at B/C where the FedRAMP
    # independent assessment is mandatory and its summary applies. Carried in a
    # clearly-isolated provider-extension object on the metadata block; the
    # official schema permits extra properties.
    _cls = str(cls or profile.get("certification_class", "")).strip().lower()
    _selected = set(profile.get("selected_optional_rules") or [])
    _ivv_used = ("IVV-CSO-FIA" in _selected) if _cls == "a" else _cls in ("b", "c")
    if _ivv_used:
        _fia = profile.get("fedramp_independent_assessment") or {}
        doc["metadata"]["xIndependentAssessmentSummary"] = {
            "assessorName": _fia.get("assessor_name", TBD),
            "assessorFedrampId": _fia.get("assessor_fedramp_id", TBD),
            "completedAt": _fia.get("completed_at", TBD),
            "assessmentSummaryUri": _fia.get("assessment_summary_uri", TBD),
            "basis": ("IVV-CSO-FIA (selected optional Class A IV&V; IVV-IAS-OSA)"
                      if _cls == "a" else "FRC-APP-FIA / IVV-IAS-OSA"),
        }
    for r in rules:
        rec = records["frr"].get(r["rule_id"], {})
        fam = r["family"]
        doc["fedRampRequirements"].append(
            {
                "frrID": r["rule_id"],
                "frrImplementationStatus": official_status(rec.get("implementation_status")),
                "frrImplementation": rec.get("implementation", [TBD]),
                "frrValidation": rec.get("validation", [TBD]),
                "frrAssessment": rec.get("assessment", [TBD]),
                "providerExtensions": {
                    "ruleName": r["name"],
                    "family": fam,
                    "familyName": fam_names["frr"].get(fam, fam),
                    # SDR-CSO-FRR requires seven information items per applicable
                    # rule, but the official schema carries only frrImplementation,
                    # frrValidation and frrAssessment. The remaining required
                    # items (implementation/nonimplementation risk, independent
                    # verification, independent validation, responses to
                    # independent-review comments, and rule-specific artifacts)
                    # have no dedicated official field. The official schema does
                    # not set additionalProperties, so extra fields are permitted;
                    # they are carried here, inside the submitted document, so the
                    # required information travels WITH the SDR rather than in a
                    # separate sidecar a consumer might miss.
                    "xFedRampSemantic": frr_semantic(rec),
                    "xAuthoringStatus": rec.get("implementation_status", "Not Implemented"),
                },
            }
        )
    for k in ksis:
        rec = records["ksi"].get(k["ksi_id"], {})
        doc["keySecurityIndicators"].append(
            {
                "ksiId": k["ksi_id"],
                "ksiImplementationStatus": official_status(rec.get("implementation_status")),
                "ksiImplementation": rec.get("implementation", [TBD]),
                "ksiValidation": rec.get("validation", [TBD]),
                "ksiAssessment": rec.get("assessment", [TBD]),
                "ksiTests": [_test_to_str(t) for t in rec.get("tests", [])],
                "ksiEvidence": rec.get("evidence", []),
                "providerExtensions": {
                    "ksiName": k["name"],
                    "family": k["family"],
                    "familyName": k["family_name"],
                    # SDR-CSX-KSI requires five information items per KSI
                    # (measures/objectives, their cycle, verification of the
                    # measures, verification of the supporting automation, and
                    # validation) and SDR-CSX-KMT requires historical metrics by
                    # class. Only ksiValidation/ksiAssessment map to official
                    # fields, so the rest is carried here inside the submitted
                    # document.
                    "xFedRampSemantic": ksi_semantic(
                        rec, _derive_daily_data(k["ksi_id"], metric_history or {}),
                        _derive_per_metric(k["ksi_id"], metric_history or {})),
                    "xAuthoringStatus": rec.get("implementation_status", "Not Implemented"),
                },
            }
        )
    return doc


def _val(v):
    """Normalize a record value for emission: None becomes the TBD marker so a
    required field is never silently absent from the submitted document."""
    return v if v not in (None, "") else TBD


def frr_semantic(rec):
    """Assemble the SDR-CSO-FRR semantic block from a record-store entry so
    every required information item reaches the submitted SDR. Missing values
    surface as the honest TBD marker rather than disappearing."""
    ext = rec.get("extension", {})
    return {
        "implementationRisk": _val(ext.get("customer_risk")),
        # SDR-CSO-FRR item 1, not-followed branch: the reason for NOT following
        # the rule is a distinct required element from the resulting customer
        # risk. Preflight requires nonimplementation_reason; without emitting it
        # here the reason could pass the gate yet vanish from the submitted SDR
        # (a false-ready path). Emit it so the reason reaches the deliverable.
        # "Not applicable: rule is followed" for a followed rule keeps the slot
        # honest without implying an unstated reason.
        "nonimplementationReason": ext.get(
            "nonimplementation_reason", "Not applicable: rule is followed"),
        "verification": _val(ext.get("verification")),
        "validationFrequency": _val(ext.get("validation_frequency")),
        "independentVerification": _val(ext.get("independent_verification")),
        "independentValidation": _val(ext.get("independent_validation")),
        "assessorResponses": ext.get("assessor_responses", "None recorded"),
        "ruleArtifacts": ext.get("rule_artifacts", []),
        "seniorOfficialAcceptance": ext.get(
            "senior_official_acceptance", "Not required: rule is followed"),
        "owner": _val(ext.get("owner")),
    }


def _derive_daily_data(kid, metric_history):
    """Derive the in-SDR dailyData series for one KSI DIRECTLY from the
    immutable metric-history.json snapshot (append_metrics's durable store),
    not from a hand-authored records-store field. This is the SDR-CSX-KMT
    Class C MUST ("All daily metric data up to the past year, where available")
    generated from the same durable data the MOT gate reads, so the submitted
    daily series cannot diverge from the persistence history and no human has to
    duplicate it into the store.

    metric_history is {"ksis": {kid: {"series": [{"date","status"/"value",...}]}}}
    (or a bare {kid: {...}} map). Returns the KSI's observations within the past
    365 days, date-sorted, as a list of {date, ...} dicts (the raw datapoint
    shape append_metrics wrote). Returns [] when no history exists for the KSI
    (the "where available" qualifier: absent history is not a fabricated series).
    """
    if not isinstance(metric_history, dict):
        return []
    ksis = metric_history.get("ksis", metric_history)
    if not isinstance(ksis, dict):
        return []
    entry = ksis.get(kid)
    series = entry.get("series") if isinstance(entry, dict) else entry
    if not isinstance(series, list):
        return []
    import datetime as _dd
    # F11: datapoints are UTC-stamped by the collectors (datetime.now(timezone.utc)),
    # so the window ceiling MUST be the UTC calendar day. Using the host's local
    # date.today() on a machine west of UTC drops a genuine current-day UTC
    # observation from the submitted series near midnight (silent under-report,
    # invisible in UTC CI). Same two-clock class as F10.
    _u = _utc_today()
    cutoff = (_u - _dd.timedelta(days=365)).isoformat()
    _today = _u.isoformat()
    out = []
    for pt in series:
        if not isinstance(pt, dict):
            continue
        d = str(pt.get("date", ""))[:10]
        # Finding 12: reject future-dated observations from the submitted series;
        # a datapoint dated after today is not a real historical measurement.
        if d and cutoff <= d <= _today:
            out.append(pt)
    out.sort(key=lambda p: str(p.get("date", "")))
    return out


def _summarize_series(series):
    """Summarize a daily datapoint series the SAME way append_metrics.summarize
    does, so a summary DERIVED at build time from metric-history.json is
    identical to what the appender computes: {days_observed, avg_passing_fraction}.
    A datapoint is {passing, total}. Empty series -> zero observed / None avg.

    This is finding-1/2's fix: the 30-day and 1-year summaries emitted into the
    SDR are computed from the immutable durable history (the same store dailyData
    comes from), NOT read from a hand-authored records-store field that could
    claim '100% passing' while the history contains failures. Deriving both from
    one source makes the claimed summary and the daily data provably consistent.
    """
    if not isinstance(series, list) or not series:
        return {"days_observed": 0, "avg_passing_fraction": None}
    fracs = []
    for p in series:
        if isinstance(p, dict) and p.get("total"):
            fracs.append(p["passing"] / p["total"])
    avg = round(sum(fracs) / len(fracs), 4) if fracs else None
    return {"days_observed": len(series), "avg_passing_fraction": avg}


def _window_summaries(daily_series):
    """Slice a derived daily series (already the past-365-day window from
    _derive_daily_data) into the EXACT FedRAMP windows and summarize each:
      last30 = the 30 dates today-29..today; lastYear = >= 12 calendar months.
    Returns (last30_summary, year_summary) or (None, None) when no series."""
    if not isinstance(daily_series, list) or not daily_series:
        return None, None
    import datetime as _ws
    today = _utc_today()  # F11: UTC ceiling, consistent with UTC-stamped datapoints
    cut30 = (today - _ws.timedelta(days=29)).isoformat()
    # 12 calendar months before today (month-clamped), matching append_metrics.
    y = today.year + (today.month - 1 - 12) // 12
    m = (today.month - 1 - 12) % 12 + 1
    last_day = 31 if m == 12 else (_ws.date(y, m + 1, 1) - _ws.timedelta(days=1)).day
    year_start = _ws.date(y, m, min(today.day, last_day)).isoformat()
    last30 = [p for p in daily_series if str(p.get("date", ""))[:10] >= cut30]
    last_year = [p for p in daily_series if str(p.get("date", ""))[:10] >= year_start]
    return _summarize_series(last30), _summarize_series(last_year)


def _derive_per_metric(kid, metric_history):
    """Build the in-SDR perMetric block for one KSI from metric-history.json
    (finding 3): FedRAMP SDR-CSX-KMT asks for a summary of EACH metric, so emit
    one entry per metric_id with its objective, source, 30-day and 1-year
    summaries, and daily series (past-year window). Returns [] when the KSI has
    no per-metric history (older histories without a "metrics" map, or a KSI
    absent from history) - the KSI-level aggregate summaries still carry the
    rollup, so this is additive detail, never a regression."""
    if not isinstance(metric_history, dict):
        return []
    ksis = metric_history.get("ksis", metric_history)
    entry = ksis.get(kid) if isinstance(ksis, dict) else None
    metrics = entry.get("metrics") if isinstance(entry, dict) else None
    if not isinstance(metrics, dict) or not metrics:
        return []
    import datetime as _dm
    _u_dm = _utc_today()  # F11: UTC ceiling, consistent with UTC-stamped datapoints
    cutoff = (_u_dm - _dm.timedelta(days=365)).isoformat()
    _today_dm = _u_dm.isoformat()
    out = []
    for mid in sorted(metrics):
        m = metrics[mid]
        if not isinstance(m, dict):
            continue
        series = m.get("series") if isinstance(m.get("series"), list) else []
        daily = sorted((p for p in series
                        if isinstance(p, dict)
                        and cutoff <= str(p.get("date", ""))[:10] <= _today_dm),
                       key=lambda p: str(p.get("date", "")))
        out.append({
            "metricId": mid,
            "objective": m.get("objective", ""),
            "source": m.get("source", ""),
            "last30Days": m.get("last_30_days"),
            "upToOneYear": m.get("up_to_one_year"),
            "dailyData": daily,
        })
    return out


def ksi_semantic(rec, daily_series=None, per_metric=None):
    """Assemble the SDR-CSX-KSI and SDR-CSX-KMT semantic block from a
    record-store entry. Historical metrics (Class B/C MUST) are emitted here
    instead of being dropped from the generated document.

    daily_series, when provided, is the KSI's dailyData DERIVED from the
    immutable metric-history.json snapshot (see _derive_daily_data). It is
    preferred over any hand-authored historical_metrics.daily_data so the
    submitted daily series is the durable persistence data, not a duplicate a
    human could let drift.

    SDR-CSX-KSI, verbatim: "Explanation of measures (and their objectives) that
    demonstrate the Key Security Indicator, OR an explanation of the reason and
    resulting risk to customers for not having measures available." So the block
    carries resultingCustomerRisk alongside measures - the not-having-measures
    alternative was previously absent from the semantic model, so a validator
    could not even see it, let alone confirm it was answered.

    SDR-CSX-KMT Class C, verbatim, MUST supply "All daily metric data up to the
    past year (where available)" - the actual data, not merely a reference. The
    block emits dailyData (the normalized in-SDR series) in addition to the
    optional dailyDataReference URI."""
    ext = rec.get("extension", {})
    hm = rec.get("historical_metrics", {})
    # Derive the 30-day and 1-year summaries from the durable daily series (the
    # same metric-history.json snapshot dailyData comes from) so the submitted
    # summary cannot contradict the daily data. Fall back to a hand-authored
    # historical_metrics summary ONLY when no history was threaded in (a KSI
    # genuinely absent from history), never preferring the hand value over real
    # data. This closes finding 1 (summary source of truth) and finding 2 (the
    # windows are sliced exactly, see _window_summaries).
    derived_30, derived_year = _window_summaries(daily_series)
    last30 = derived_30 if derived_30 is not None else _val(hm.get("last_30_days"))
    up_to_year = derived_year if derived_year is not None else _val(hm.get("up_to_one_year"))
    return {
        "measures": _val(ext.get("measures")),
        # SDR-CSX-KSI item 1, no-measures branch: the reason for not having
        # measures is a distinct required element from the resulting risk.
        # Preflight requires measures_unavailable_reason; emit it so it reaches
        # the SDR rather than passing the gate and disappearing (finding 1).
        "measuresUnavailableReason": ext.get(
            "measures_unavailable_reason", "Not applicable: measures are available"),
        "resultingCustomerRisk": _val(ext.get("resulting_customer_risk")
                                      or ext.get("customer_risk")),
        "operatingCycle": _val(ext.get("operating_cycle")),
        "measuresVerification": _val(ext.get("measures_verification")),
        "automationVerification": _val(ext.get("automation_verification")),
        "assessorResponses": ext.get("assessor_responses", "None recorded"),
        "owner": _val(ext.get("owner")),
        "historicalMetrics": {
            "last30Days": last30,
            "upToOneYear": up_to_year,
            # Class C MUST supply the actual daily data up to the past year
            # (where available), not only a pointer. dailyData is DERIVED from
            # the immutable metric-history.json snapshot (daily_series) so it
            # cannot diverge from the durable persistence data; it falls back to
            # a hand-authored historical_metrics.daily_data only when no history
            # was threaded in. The dailyDataReference URI is retained as an
            # OPTIONAL external pointer (CR26 does not require a URL).
            "dailyData": (daily_series if isinstance(daily_series, list) and daily_series
                          else (hm.get("daily_data") if isinstance(hm.get("daily_data"), list) else [])),
            "dailyDataReference": _val(hm.get("daily_data_reference")),
            # Per-metric identity (finding 3): a summary of EACH metric, derived
            # from the durable per-metric history. Empty when no per-metric
            # history exists (the KSI aggregate summaries above still apply).
            "perMetric": per_metric if isinstance(per_metric, list) else [],
        },
    }


def load_notes():
    rule_notes = {}
    ksi_notes = {}
    rn_path = os.path.join(BASE, "traceability", "rule-notes.json")
    kn_path = os.path.join(BASE, "traceability", "ksi-notes.json")
    if os.path.exists(rn_path):
        rule_notes = load(rn_path)["rules"]
    if os.path.exists(kn_path):
        ksi_notes = load(kn_path)["indicators"]
    return rule_notes, ksi_notes


def load_family_names():
    path = os.path.join(BASE, "traceability", "family-names.json")
    if os.path.exists(path):
        return load(path)
    return {"frr": {}, "ksi": {}}


def expand_family(code, names):
    full = names.get(code)
    return f"{code} ({full})" if full and full != code else code


def build_extensions(profile, rules, ksis, records, cls):
    rule_notes, ksi_notes = load_notes()
    fam_names = load_family_names()
    ext = {
        "extension_note": (
            "Provider operational metadata companion to the official SDR JSON. "
            "Nonstandard fields live here so the official document remains "
            "schema-portable. Keyed by frrID and ksiId."
        ),
        "metadata": {
            "offering": profile["offering_name"],
            "certification_class": cls.upper(),
            "certification_path": profile["certification_path"],
            "aws_partition": profile["aws_partition"],
            "regions": [profile["primary_region"], profile["dr_region"]],
            "sdr_version": profile["sdr_version"],
            "schema_version": profile["schema_version"],
            "dataset_version": profile["dataset_version"],
            "generated": f"deterministic build from dataset {profile['dataset_version']}",
            "source_of_update": "build_sdr.py generator",
        },
        "frr": {},
        "ksi": {},
    }
    for r in rules:
        rec = records["frr"].get(r["rule_id"], {})
        note = rule_notes.get(r["rule_id"], {})
        entry = {
            "name": r["name"],
            "force": r["force"],
            "family": r["family"],
            "family_name": fam_names["frr"].get(r["family"], r["family"]),
            "guidance": {
                "what_it_looks_for": r["statement"],
                "official_notes": note.get("official_notes", []),
                "how_to_comply": note.get("how_to_comply_guidance", ""),
                "evidence_required": note.get("evidence_required", []),
                "evidence_source": note.get("evidence_source", ""),
                "note": ("How to comply is SAS advisory guidance, not FedRAMP "
                         "text. Fill the TBD fields below with the provider's "
                         "real implementation, validation, and owner."),
            },
            **rec.get("extension", {}),
        }
        if r.get("class_a_obligation"):
            entry["class_a_obligation"] = r["class_a_obligation"]
        ext["frr"][r["rule_id"]] = entry
    for k in ksis:
        rec = records["ksi"].get(k["ksi_id"], {})
        note = ksi_notes.get(k["ksi_id"], {})
        ext["ksi"][k["ksi_id"]] = {
            "name": k["name"],
            "family": k["family"],
            "family_name": k["family_name"],
            "content_status": k["content_status"],
            "minimum_automated_methods": k["minimum_automated_methods"][f"class_{cls}"],
            "historical_metrics_required": k["historical_metrics"][f"class_{cls}"],
            "guidance": {
                "what_it_looks_for": note.get("what_it_looks_for", ""),
                "how_to_comply": note.get("how_to_comply_guidance", ""),
                "evidence_required": note.get("evidence_required", []),
                "nist_controls": note.get("nist_controls", []),
                "note": ("How to comply is SAS advisory guidance, not FedRAMP "
                         "text. Fill the TBD fields below with the provider's "
                         "real implementation, validation, tests, and owner."),
            },
            **rec.get("extension", {}),
        }
    return ext


def render_human(profile, rules, ksis, records, cls, metric_history=None):
    fam_names = load_family_names()
    L = []
    a = L.append
    a("SECURITY DECISION RECORD")
    a(_pc.offering_title(profile))
    a("")
    a(f"Certification type: {profile['certification_type']}")
    a(f"Certification class: Class {cls.upper()}")
    a(f"Certification path: {profile['certification_path']} Certification")
    a(f"AWS partition: {profile['aws_partition']}")
    a(f"Primary region: {profile['primary_region']}")
    a(f"Disaster recovery region: {profile['dr_region']}")
    a(f"SDR version: {profile['sdr_version']}")
    a(f"Generated from dataset version: {profile['dataset_version']}")
    a("Source of update: build_sdr.py generator")
    a("")
    a("This is a generic template record. Statements marked TBD require real")
    a("implementation facts before this record can support an assessment.")
    a("Reference architecture content is an assumption, not a confirmed system.")
    a("")
    # Mirror the JSON metadata.xIndependentAssessmentSummary block in the
    # human-readable SDR so the two formats stay consistent (FedRAMP requires the
    # Assessment Summary in the SDR when optional IV&V is used at Class A, and it
    # applies at B/C). IV&V is used when Class A explicitly selects IVV-CSO-FIA,
    # or at Class B/C where FRC-APP-FIA / IVV-IAS-OSA apply.
    _selected_h = set(profile.get("selected_optional_rules") or [])
    _ivv_used_h = ("IVV-CSO-FIA" in _selected_h) if cls == "a" else cls in ("b", "c")
    if _ivv_used_h:
        _fia_h = profile.get("fedramp_independent_assessment") or {}
        _basis_h = ("IVV-CSO-FIA (selected optional Class A IV&V; IVV-IAS-OSA)"
                    if cls == "a" else "FRC-APP-FIA / IVV-IAS-OSA")
        a("Independent Assessment Summary")
        a(f"Assessor name: {_fia_h.get('assessor_name', TBD)}")
        a(f"Assessor FedRAMP Recognized ID: {_fia_h.get('assessor_fedramp_id', TBD)}")
        a(f"Assessment completed at: {_fia_h.get('completed_at', TBD)}")
        a(f"Assessment summary reference: {_fia_h.get('assessment_summary_uri', TBD)}")
        a(f"Basis: {_basis_h}")
        a("")
    a("1. FedRAMP Requirements")
    a("")
    for i, r in enumerate(rules, 1):
        rec = records["frr"].get(r["rule_id"], {})
        a(f"1.{i} {r['rule_id']} {r['name'] or ''}")
        a(f"FedRAMP rule: {r['rule_id']}")
        a(f"Rule family: {expand_family(r['family'], fam_names['frr'])}")
        a(f"Force: {r['force'] or 'stated in rule text'}")
        if r.get("class_a_obligation"):
            a(f"Class A obligation: {r['class_a_obligation']} (per FRC-CLA-MFR, RFR, or OFR)")
        a(f"Status: {official_status(rec.get('implementation_status'))}")
        _auth = str(rec.get('implementation_status') or '').strip()
        if _auth and official_status(_auth) != _auth:
            a(f"Authoring status: {_auth}")
        for s in rec.get("implementation", []):
            a(f"Implementation: {s}")
        for s in rec.get("validation", []):
            a(f"Validation: {s}")
        for s in rec.get("assessment", []):
            a(f"Independent assessment: {s}")
        ext = rec.get("extension", {})
        a(f"Implementation or nonimplementation risk: {_val(ext.get('customer_risk'))}")
        a("Reason for not following the rule (if not followed): "
          f"{ext.get('nonimplementation_reason', 'Not applicable: rule is followed')}")
        a(f"Verification: {_val(ext.get('verification'))}")
        a(f"Independent verification: {_val(ext.get('independent_verification'))}")
        a(f"Independent validation: {_val(ext.get('independent_validation'))}")
        a(f"Responses to independent review comments: {ext.get('assessor_responses', 'None recorded')}")
        a("Senior official acceptance (if not implemented): "
          f"{ext.get('senior_official_acceptance', 'Not required: rule is followed')}")
        arts = ext.get("rule_artifacts", [])
        a(f"Rule-specific artifacts: {'; '.join(str(x) for x in arts) if arts else 'None recorded'}")
        a(f"Owner: {ext.get('owner', TBD)}")
        a("")
    a("2. Key Security Indicators")
    a("")
    for i, k in enumerate(ksis, 1):
        rec = records["ksi"].get(k["ksi_id"], {})
        ext = rec.get("extension", {})
        hm = rec.get("historical_metrics", {})
        a(f"2.{i} {k['ksi_id']} {k['name'] or ''}")
        a(f"KSI: {k['ksi_id']}")
        a(f"Family: {k['family']} ({k['family_name']})")
        _stmt = ksi_statement_for_class(k, cls)
        if _stmt:
            # The human-readable SDR forbids markdown; the dataset marks the
            # class-B optional variants with "**Optional:**". Render as plain
            # text (JSON keeps the verbatim dataset statement).
            _stmt_plain = _stmt.replace("**", "")
            a(f"Security outcome: {_stmt_plain}")
        else:
            a("Security outcome: FedRAMP pending, no statement in the official dataset yet.")
        a(f"Status: {official_status(rec.get('implementation_status'))}")
        _kauth = str(rec.get('implementation_status') or '').strip()
        if _kauth and official_status(_kauth) != _kauth:
            a(f"Authoring status: {_kauth}")
        for s in rec.get("implementation", []):
            a(f"Implementation: {s}")
        for s in rec.get("validation", []):
            a(f"Validation: {s}")
        for s in rec.get("assessment", []):
            a(f"Independent assessment: {s}")
        a(f"Measures and objectives: {_val(ext.get('measures'))}")
        a("Reason measures are unavailable (if none): "
          f"{ext.get('measures_unavailable_reason', 'Not applicable: measures are available')}")
        a("Resulting customer risk if measures unavailable: "
          f"{_val(ext.get('resulting_customer_risk') or ext.get('customer_risk'))}")
        a(f"Measurement cycle: {_val(ext.get('operating_cycle'))}")
        a(f"Verification of measures: {_val(ext.get('measures_verification'))}")
        a(f"Verification of supporting automation: {_val(ext.get('automation_verification'))}")
        a(f"Minimum automated methods for this class: {k['minimum_automated_methods'][f'class_{cls}']}")
        a(f"Historical metrics required for this class: {k['historical_metrics'][f'class_{cls}']}")
        # Findings 3/12 (human<->machine parity): derive the 30-day and 1-year
        # summaries from the SAME immutable metric-history series the JSON SDR
        # uses, NOT the hand-authored records-store field. Otherwise the human
        # SDR could print "100% passing" while the JSON derives 82% from real
        # history - a CDS-CSO-CBF consistency violation. Fall back to the hand
        # value only when the KSI has no history (identical rule to ksi_semantic).
        _ds = _derive_daily_data(k["ksi_id"], metric_history or {})
        _d30, _dyr = _window_summaries(_ds)
        _s30 = _d30 if _d30 is not None else _val(hm.get("last_30_days"))
        _syr = _dyr if _dyr is not None else _val(hm.get("up_to_one_year"))
        a(f"Historical metrics, 30-day summary: {_s30}")
        a(f"Historical metrics, up to one year: {_syr}")
        # Class C MUST supply the actual daily data (SDR-CSX-KMT). The
        # machine-readable SDR carries the full derived series; the human-
        # readable rendering states the count and window (CDS-CSO-CBF: the two
        # views must be consistent) plus the optional external reference.
        _daily = _ds  # same derived past-year series used for the summaries above
        if _daily:
            _first = str(_daily[0].get("date", ""))[:10]
            _last = str(_daily[-1].get("date", ""))[:10]
            a(f"Historical metrics, daily data (Class C): {len(_daily)} daily "
              f"observation(s) up to the past year ({_first} to {_last})")
        else:
            a("Historical metrics, daily data (Class C): none available")
        a(f"Historical metrics, daily data reference (optional): {_val(hm.get('daily_data_reference'))}")
        # Finding 3 (human parity): the JSON SDR carries a perMetric block
        # (summary of EACH metric). Render its human counterpart so a per-metric
        # detail that exists in the machine-readable output is not invisible in
        # the human-readable one. Empty when the KSI has no per-metric history.
        _pm = _derive_per_metric(k["ksi_id"], metric_history or {})
        if _pm:
            a(f"Per-metric summary ({len(_pm)} metric(s)):")
            for _m in _pm:
                _o = _m.get("objective") or "no objective recorded"
                _s = _m.get("source") or "no source recorded"
                a(f"  Metric {_m['metricId']}: 30-day {_m.get('last30Days')}; "
                  f"up-to-one-year {_m.get('upToOneYear')}; "
                  f"{len(_m.get('dailyData') or [])} daily observation(s); "
                  f"objective: {_o}; source: {_s}")
        tests = rec.get("tests", [])
        a(f"Tests: {'; '.join(_test_to_str(t) for t in tests) if tests else 'None defined yet'}")
        a(f"Owner: {ext.get('owner', TBD)}")
        a("")
    return "\n".join(L)


def main():
    profile = load(PROFILE)
    cls = (os.environ.get("SDR_BUILD_CLASS") or profile["certification_class"]).lower()
    if cls not in ("a", "b", "c"):
        print(f"Class {cls.upper()} SDR generation is not supported: "
              "Class D is FedRAMP pending (Phase 4 pilot).")
        return 1
    class_profile = load(os.path.join(BASE, "profiles", f"class-{cls}", "profile.json"))
    rules = class_profile["rules"]
    ksis = load(KSI_PROFILE)["indicators"]
    if cls == "a":
        # FRC-CLA-OFR optional (MAY) rules are extra credit: FedRAMP's Class A
        # guidance says all MUST and SHOULD rules belong in the SDR, and MAY
        # rules are optional (fully reviewed if included). Default to opt-IN:
        # an optional rule enters the SUBMITTED SDR only when the provider
        # explicitly lists its rule_id in offering-profile selected_optional_rules
        # (default empty). The class-A profile and traceability catalog still
        # carry all 41 rules; this shapes only what is submitted.
        selected = set(profile.get("selected_optional_rules") or [])
        before = len(rules)
        rules = [r for r in rules
                 if r.get("class_a_obligation") != "optional" or r["rule_id"] in selected]
        dropped = before - len(rules)
        if dropped:
            print(f"Class A: excluded {dropped} optional (MAY) rule(s) not in "
                  f"selected_optional_rules; {len(selected)} explicitly selected")
        # Class A KSI applicability is enumerated by FRC-CLA-MFR; only the
        # listed KSIs go into the Class A SDR. The tier map is written into
        # the class-a profile meta by build_profiles.py.
        ksi_tier = class_profile["meta"]["class_a_ksis"]
        ksis = [k for k in ksis if k["ksi_id"] in ksi_tier]
    elif cls == "b":
        # Class B optional-KSI scoping (opt-in, parallel to Class A MAY rules):
        # five KSIs carry a varies_by_class 'b' "**Optional:**" statement
        # (CNA-EIS, MLA-ALA, SVC-PRR, SVC-RUD, SVC-VCM) and are mandatory only
        # at Class C/D. An optional-at-B KSI enters the SUBMITTED Class B SDR
        # only when the provider lists its ksi_id in offering-profile
        # selected_optional_ksis (default empty). Uses the same shared resolver
        # preflight/validator/scanner use, so every layer submits the same set.
        selected_ksi = list(profile.get("selected_optional_ksis") or [])
        keep = submitted_ksi_ids(ksis, cls, selected_ksi)
        before = len(ksis)
        ksis = [k for k in ksis if k["ksi_id"] in keep]
        dropped = before - len(ksis)
        if dropped:
            print(f"Class B: excluded {dropped} optional KSI(s) not in "
                  f"selected_optional_ksis; {len(selected_ksi)} explicitly selected")

    if os.path.exists(RECORDS):
        records = load(RECORDS)
        # merge-scaffold any rules or KSIs not yet in the store (for example
        # the FRC CLA rules that only appear in the Class A profile), without
        # touching existing content
        fresh = scaffold_records(rules, ksis)
        added = 0
        for rid, entry in fresh["frr"].items():
            if rid not in records["frr"]:
                records["frr"][rid] = entry
                added += 1
        for kid, entry in fresh["ksi"].items():
            if kid not in records["ksi"]:
                records["ksi"][kid] = entry
                added += 1
        if added:
            print(f"record store: {added} new entries scaffolded")
        # Backfill extension sub-keys added to the scaffold since the store was
        # written. Existing values are never touched, so authored content
        # survives; only absent keys are created, with their TBD placeholder.
        # Without this, a new SDR-CSO-FRR information item would only ever
        # appear on rules added after the change.
        added_keys = 0
        for kind in ("frr", "ksi"):
            for rid, entry in records[kind].items():
                template = fresh[kind].get(rid, {})
                for key, value in template.items():
                    if key == "extension":
                        ext = entry.setdefault("extension", {})
                        for ek, ev in value.items():
                            if ek not in ext:
                                ext[ek] = ev
                                added_keys += 1
                    elif key not in entry:
                        entry[key] = value
                        added_keys += 1
        if added_keys:
            print(f"record store: {added_keys} new extension fields backfilled")
    else:
        records = scaffold_records(rules, ksis)
        print("record store scaffolded:", RECORDS)

    # Backfill guidance into the record store so the file the provider edits
    # carries the instructions next to the fields being filled. Guidance is
    # regenerated every run (never author into it); authored content in the
    # other fields is never touched.
    rule_notes, ksi_notes = load_notes()
    fam_names = load_family_names()
    ksi_fam_by_id = {k["ksi_id"]: (k["family"], k["family_name"]) for k in ksis}
    for rid, entry in records["frr"].items():
        note = rule_notes.get(rid, {})
        rule = next((r for r in rules if r["rule_id"] == rid), None)
        fam = rule["family"] if rule else rid.split("-")[0]
        entry["fill_guidance"] = {
            "read_me": ("Fill implementation, validation, and the extension "
                        "fields below with the provider's real facts, then run "
                        "build_sdr.py to regenerate all outputs. Do not edit "
                        "the generated files in sdr/json or sdr/human-readable."),
            "rule_family": expand_family(fam, fam_names["frr"]),
            "what_it_looks_for": (rule["statement"] if rule else "See rule catalog."),
            "how_to_comply": note.get("how_to_comply_guidance", ""),
            "evidence_required": note.get("evidence_required", []),
        }
    for kid, entry in records["ksi"].items():
        note = ksi_notes.get(kid, {})
        fam_code, fam_name = ksi_fam_by_id.get(
            kid, (kid.split("-")[1], fam_names["ksi"].get(kid.split("-")[1], "")))
        entry["fill_guidance"] = {
            "read_me": ("Fill implementation, validation, tests, and the "
                        "extension fields below with the provider's real facts, "
                        "then run build_sdr.py to regenerate all outputs."),
            "ksi_family": f"{fam_code} ({fam_name})" if fam_name else fam_code,
            "what_it_looks_for": note.get("what_it_looks_for", ""),
            "how_to_comply": note.get("how_to_comply_guidance", ""),
            "evidence_required": note.get("evidence_required", []),
        }
    dump(records, RECORDS)

    # Load the immutable durable metric history (append_metrics's store) so
    # the Class C in-SDR dailyData is DERIVED from it, not hand-duplicated.
    # Git-excluded telemetry: absent in a clean tree (the "where available"
    # qualifier then yields empty dailyData), restored from S3 on the release
    # path before build.
    _mh_path = os.path.join(BASE, "automation", "metrics", "metric-history.json")
    metric_history = load(_mh_path) if os.path.exists(_mh_path) else {}

    official = build_official(profile, rules, ksis, records, metric_history, cls)
    ext = build_extensions(profile, rules, ksis, records, cls)
    text = render_human(profile, rules, ksis, records, cls, metric_history)

    dump(official, os.path.join(BASE, "sdr", "json", f"sdr-class-{cls}.json"))
    dump(ext, os.path.join(BASE, "sdr", "json", f"sdr-class-{cls}-extensions.json"))
    txt_path = os.path.join(BASE, "sdr", "human-readable", f"sdr-class-{cls}.txt")
    os.makedirs(os.path.dirname(txt_path), exist_ok=True)
    with open(txt_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)

    print(f"class: {cls.upper()}")
    print("rules in SDR:", len(official["fedRampRequirements"]))
    print("ksis in SDR:", len(official["keySecurityIndicators"]))
    print("outputs written to sdr/json and sdr/human-readable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
