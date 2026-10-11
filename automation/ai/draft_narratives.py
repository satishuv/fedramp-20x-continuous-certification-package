"""AI narrative drafting (Layer 3, OPT-IN) -- assists, never decides.

Drafts a first-pass `implementation` / `validation` narrative for each KSI from
the collected facts plus the KSI's official guidance, so authoring 46 KSIs
becomes a review task. This module is OPTIONAL: the deterministic pipeline
(collect -> pre-fill -> build -> validate) runs identically whether this module
is present, enabled, or absent.

The hard boundary, enforced here in code (mirrors prefill_from_facts.py):
  - Never sets or changes `implementation_status` (human judgment + sign-off).
  - Never writes `assessment` (accredited independent assessor only).
  - Never writes `tests` or `evidence` (those are deterministic telemetry from
    the collectors, not AI-authored).
  - Never edits the record store in place. It writes a proposed copy to a
    SEPARATE AI-draft sidecar and prints a unified diff. A human reviews,
    edits, and applies by hand.
  - Only drafts into fields that are still TBD/empty. Author-written prose is
    never overwritten.

Backend is pluggable and there is NO default network call. The default drafter
is a deterministic, offline TEMPLATE drafter (no model, no network) so this
module and its tests run with zero AI backend. A provider who wants real LLM
drafting supplies a drafter (e.g. Amazon Bedrock) explicitly; nothing here is
wired to an endpoint, and no data leaves the provider's boundary by default.

Usage:
  python automation/ai/draft_narratives.py            # print the diff (stub drafter)
  python automation/ai/draft_narratives.py --write     # write the AI sidecar
  # A real backend is opt-in via --drafter bedrock (requires the provider to
  # have configured Bedrock access); absent that, the offline stub is used.
"""
import argparse
import copy
import difflib
import inspect
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REGISTRY = os.path.join(BASE, "automation", "collectors", "registry.json")
FACTS_DIR = os.path.join(BASE, "automation", "facts")
RECORD_STORE = os.path.join(BASE, "sdr", "records", "records-store.json")
# Distinct sidecar name so an AI draft is never confused with the deterministic
# pre-fill sidecar or the real record store. Git-ignored like other sidecars.
AI_SIDECAR = os.path.join(BASE, "sdr", "records", "records-store.ai-draft.json")

TBD_MARKERS = ("TBD:", "TBD ", "Information has not been provided", "FedRAMP pending")

# AUD-F38: a labelled DRAFT / Example proposal is draftable too (it is not the
# provider's confirmed fact), and the readiness predicates treat it as
# unanswered until `sdr.py review` accepts it. Single definition shared with
# preflight, the validator and the scanner.
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
from unreviewed_text import is_unreviewed, strip_label  # noqa: E402

OFFERING_PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")

# Fields this module may DRAFT into. Deliberately excludes implementation_status,
# assessment, tests, and evidence. Guarded again at write time.
DRAFTABLE_FIELDS = ("implementation", "validation")
FORBIDDEN_FIELDS = ("implementation_status", "assessment", "tests", "evidence")

DRAFT_LABEL = "DRAFT (AI-assisted, unverified -- review before use): "
# A curated template example carries a known narrative; the drafter keeps the
# narrative and only re-labels it as a reviewable proposal.
EXAMPLE_LABEL = "DRAFT (reference-architecture example, unverified -- review before use): "


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def is_tbd(value):
    if isinstance(value, str):
        return (any(m in value for m in TBD_MARKERS) or value.strip() == ""
                or is_unreviewed(value))
    if isinstance(value, list):
        return len(value) == 0 or all(is_tbd(v) for v in value)
    return False


def _profile_value(profile, key):
    """A profile value that is real (not TBD / placeholder / proposal), else None."""
    v = (profile or {}).get(key)
    if not isinstance(v, str):
        return None
    s = v.strip()
    if not s or any(m in s for m in TBD_MARKERS) or is_unreviewed(s) \
            or "placeholder" in s.lower():
        return None
    return s


def load_profile_context():
    """The offering-profile values a rule narrative may name. Read-only; only
    values the provider actually filled are used (template examples are not)."""
    profile = load(OFFERING_PROFILE, {}) or {}
    return {
        "organization": _profile_value(profile, "organization_name"),
        "offering": _profile_value(profile, "offering_name"),
        "security_contact": _profile_value(profile, "security_contact"),
        "incident_contact": _profile_value(profile, "incident_contact"),
        "trust_center_uri": _profile_value(profile, "trust_center_uri"),
        "primary_region": _profile_value(profile, "primary_region"),
        "certification_class": _profile_value(profile, "certification_class"),
    }


def load_all_posture_facts():
    """Merge posture facts from every facts-*.json, keyed by service. Read-only."""
    by_service = {}
    if not os.path.isdir(FACTS_DIR):
        return by_service
    for fn in sorted(os.listdir(FACTS_DIR)):
        if not (fn.startswith("facts-") and fn.endswith(".json")):
            continue
        store = load(os.path.join(FACTS_DIR, fn), {})
        for pf in store.get("posture_facts", []):
            by_service.setdefault(pf.get("service"), []).append(pf)
    return by_service


def load_all_config_facts():
    """Config-rule facts from every facts-*.json, keyed by framework rule name,
    the same way prefill reads them. Read-only. AUD-F49: the drafter read only
    posture facts, so a KSI whose only collected facts were Config-rule
    evaluations was told 'no automated facts collected for this indicator yet'
    one screen after prefill had proposed those very evaluations as its tests."""
    by_rule = {}
    if not os.path.isdir(FACTS_DIR):
        return by_rule
    for fn in sorted(os.listdir(FACTS_DIR)):
        if not (fn.startswith("facts-") and fn.endswith(".json")):
            continue
        store = load(os.path.join(FACTS_DIR, fn), {})
        for fact in store.get("facts", []):
            if fact.get("rule"):
                by_rule[fact["rule"]] = fact
    return by_rule


def config_facts_for_ksi(ksi_entry, config_by_rule):
    """This KSI's Config-rule facts (registry checks of type config_managed_rule
    with a real evaluated outcome), rendered in the posture-fact shape the
    drafters already format: service.check=status (detail)."""
    out = []
    for check in ksi_entry.get("checks", []):
        if check.get("type") != "config_managed_rule":
            continue
        fact = (config_by_rule or {}).get(check.get("target"))
        if not fact:
            continue
        ct = str(fact.get("compliance_type", ""))
        if ct.startswith("ERROR") or ct in ("RULE_NOT_DEPLOYED", "UNKNOWN", ""):
            continue
        when = fact.get("last_evaluated_at") or fact.get("collected_at") or ""
        out.append({
            "service": "config",
            "check": check.get("target"),
            "status": ct,
            "detail": f"AWS Config rule {check.get('target')}, region {fact.get('region')}, "
                      f"last evaluated {str(when)[:10]}",
        })
    return out


def _load_observations(key):
    """Dated observations per id from every facts-*.json under `key`
    (`rule_observations` or `ksi_observations`), as written by the importers
    in automation/importers/. Identical texts from several files are kept
    once. Read-only; empty when nothing was imported."""
    by_id = {}
    seen = set()
    if not os.path.isdir(FACTS_DIR):
        return by_id
    for fn in sorted(os.listdir(FACTS_DIR)):
        if not (fn.startswith("facts-") and fn.endswith(".json")):
            continue
        store = load(os.path.join(FACTS_DIR, fn), {})
        for rid, items in (store.get(key) or {}).items():
            for o in items or []:
                text = o.get("text") if isinstance(o, dict) else None
                if not text or (rid, text) in seen:
                    continue
                seen.add((rid, text))
                by_id.setdefault(rid, []).append(o)
    return by_id


def load_rule_observations():
    """Count-only observations per FRR rule id derived by an export import
    (automation/importers/import_findings.py, import_landing_zone.py)."""
    return _load_observations("rule_observations")


def load_ksi_observations():
    """Observations per KSI id: the provider's own Rev5 SSP narrative for the
    controls the dataset ties to the indicator (import_oscal_ssp.py) and the
    landing zone's declared configuration (import_landing_zone.py)."""
    return _load_observations("ksi_observations")


# ---- Pluggable drafter interface -------------------------------------------
#
# A drafter takes (kind, ksi_id, ksi_guidance, facts, observations) and returns
# a short prose draft string, or None to decline. It MUST NOT perform any AWS
# calls or make a compliance claim; it drafts descriptive prose for a human to
# verify. `observations` are the imported texts for this KSI (the provider's
# own Rev5 SSP narrative, the landing zone's declared configuration), or None.

# Quoted imported observations per KSI proposal: at most this many items and
# this many characters in total. The reviewer edits from here; the full source
# document stays the provider's reference.
MAX_KSI_OBSERVATIONS = 6
MAX_KSI_OBSERVATION_CHARS = 2400


def _ksi_observations_block(observations):
    """The provider's own imported texts for one KSI, quoted with source and
    date, bounded, or '' when there are none."""
    items = [o for o in (observations or []) if isinstance(o, dict) and o.get("text")]
    if not items:
        return ""
    parts = []
    used = 0
    for o in items[:MAX_KSI_OBSERVATIONS]:
        when = str(o.get("observed_at") or "")[:10]
        src = o.get("source") or "import"
        piece = f"[{src}, {when}] {str(o['text']).strip()}"
        if used + len(piece) > MAX_KSI_OBSERVATION_CHARS and parts:
            break
        if len(piece) > MAX_KSI_OBSERVATION_CHARS:
            piece = piece[:MAX_KSI_OBSERVATION_CHARS].rsplit(" ", 1)[0] + "..."
        parts.append(piece)
        used += len(piece)
    omitted = len(items) - len(parts)
    return (" From the provider's own imported sources, quoted for review (a declared "
            "configuration or a Rev5 narrative is material for the record, not a 20x "
            "status): " + " | ".join(parts)
            + (f" ({omitted} more imported statement(s) not quoted; see the facts store.)"
               if omitted > 0 else ""))


class TemplateDrafter:
    """Default offline drafter: deterministic, no model, no network. Produces a
    plainly-labeled DRAFT that stitches the KSI guidance, the observed facts and
    any imported observations into review-ready prose. It never asserts the
    control is met."""

    name = "template"

    def draft(self, kind, ksi_id, guidance, facts, observations=None):
        looks = guidance.get("what_it_looks_for") or guidance.get("aws_implementation") or ""
        observed = "; ".join(
            f"{f['service']}.{f['check']}={f['status']} ({f['detail']})"
            for f in facts[:6]
        ) or "no automated facts collected for this indicator yet"
        verb = "implements" if kind == "implementation" else "validates"

        def _clip(s, n):
            s = s.strip()
            return s if len(s) <= n else s[:s.rfind(" ", 0, n)].rstrip() + "..."

        return (
            f"DRAFT (AI-assisted, unverified -- review before use): This is a "
            f"proposed {kind} narrative for {ksi_id}, to be confirmed and edited "
            f"by the provider. Intended measure: {_clip(looks, 280)} "
            f"Observed automated posture that may support how the offering {verb} "
            f"this: {_clip(observed, 280)}."
            + _ksi_observations_block(observations)
            + " A passing observation is telemetry, "
            f"not a compliance conclusion; the provider must confirm accuracy and "
            f"completeness before relying on this text."
        )


class BedrockDrafter:
    """OPT-IN real LLM drafter via Amazon Bedrock. Not wired by default; the
    provider must have Bedrock access configured. Kept minimal and clearly
    isolated: it only drafts prose and cannot touch AWS posture or the record
    store. If boto3/Bedrock is unavailable, construction fails loudly so the
    caller falls back to the offline stub rather than silently degrading."""

    name = "bedrock"

    def __init__(self, model_id="anthropic.claude-3-5-sonnet-20240620-v1:0",
                 region=None):
        import boto3  # opt-in dependency; only imported if this drafter is chosen
        self._client = boto3.client("bedrock-runtime", region_name=region)
        self._model_id = model_id

    def draft(self, kind, ksi_id, guidance, facts, observations=None):
        import json as _json
        looks = guidance.get("what_it_looks_for") or guidance.get("aws_implementation") or ""
        observed = "; ".join(
            f"{f['service']}.{f['check']}={f['status']} ({f['detail']})"
            for f in facts[:6]
        )
        imported = "\n".join(
            f"- [{o.get('source')}, {str(o.get('observed_at') or '')[:10]}] {o.get('text')}"
            for o in (observations or [])[:MAX_KSI_OBSERVATIONS]
            if isinstance(o, dict) and o.get("text"))
        prompt = (
            "You are drafting a FedRAMP SDR narrative for a human to review and "
            "edit. Draft ONLY a descriptive " + kind + " narrative. Do NOT claim "
            "the control is met, do NOT assign a status, do NOT invent facts "
            "beyond those given. Prefix the output with 'DRAFT (AI-assisted, "
            "unverified):'.\n\n"
            f"KSI: {ksi_id}\nIntended measure: {looks}\n"
            f"Observed automated posture: {observed or 'none collected'}\n"
            + (f"Provider's own imported statements (quote or paraphrase, never "
               f"extend):\n{imported}\n" if imported else "")
        )
        body = _json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 400,
            "messages": [{"role": "user", "content": prompt}],
        })
        resp = self._client.invoke_model(modelId=self._model_id, body=body)
        payload = _json.loads(resp["body"].read())
        text = "".join(part.get("text", "") for part in payload.get("content", []))
        # Defensive: ensure the draft label is present even if the model omits it.
        if "DRAFT" not in text:
            text = "DRAFT (AI-assisted, unverified -- review before use): " + text
        return text


def get_drafter(name):
    if name == "bedrock":
        return BedrockDrafter()
    return TemplateDrafter()


# ---- Drafting (never touches status/assessment/tests/evidence) --------------

def posture_facts_for_ksi(ksi_entry, posture_by_service, service_map):
    named = set(ksi_entry.get("services", []))
    out = []
    for svc_key, svc_label in service_map.items():
        if not any(svc_label in n for n in named):
            continue
        for pf in posture_by_service.get(svc_key, []):
            status = pf.get("status", "")
            if status.startswith("ERROR") or status in (
                    "NONE", "NO_COVERAGE", "NOT_ENABLED", "NO_KEYS"):
                continue
            out.append(pf)
    return out


def _accepts_observations(drafter):
    """True when the drafter's draft() takes the observations argument. A
    provider-written drafter on the older 4-argument interface keeps working;
    the caller then appends the quoted imports itself (deterministic text, not
    model output), so an import is never silently dropped."""
    try:
        params = inspect.signature(drafter.draft).parameters
    except (TypeError, ValueError):
        return False
    return len(params) >= 5 or any(
        p.kind == inspect.Parameter.VAR_POSITIONAL for p in params.values())


def draft_ksi(kid, record, ksi_entry, posture_by_service, drafter, service_map,
              observations=None, config_by_rule=None):
    """Draft implementation/validation prose into TBD fields only. Returns
    (changed, notes). Mutates the record on the proposed copy only.
    `observations` are the imported texts for this KSI, if any; `config_by_rule`
    the collected Config-rule facts (AUD-F49), rendered first because they are
    this indicator's own checks rather than service-wide posture."""
    facts = (config_facts_for_ksi(ksi_entry, config_by_rule)
             + posture_facts_for_ksi(ksi_entry, posture_by_service, service_map))
    # The record carries the dataset-derived guidance (what_it_looks_for is the
    # KSI statement); the collector registry entry does not, so reading only
    # the registry left every proposal's "Intended measure" empty.
    guidance = (record.get("fill_guidance") or ksi_entry.get("fill_guidance") or ksi_entry)
    notes = []
    changed = False
    takes_obs = _accepts_observations(drafter)
    for field in DRAFTABLE_FIELDS:
        if not is_tbd(record.get(field, "")):
            continue  # never overwrite author-written prose
        if takes_obs:
            text = drafter.draft(field, kid, guidance, facts, observations)
        else:
            text = drafter.draft(field, kid, guidance, facts)
            if text and observations:
                text = text.rstrip() + _ksi_observations_block(observations)
        if text:
            record[field] = [text] if isinstance(record.get(field), list) else text
            changed = True
            source = drafter.name + (" + imported observations" if observations else "")
            notes.append(f"{kid}: drafted {field} ({source})")
    return changed, notes


def _assert_boundary(before_record, after_record, kid):
    """Hard guard: the forbidden fields must be byte-identical before/after."""
    for field in FORBIDDEN_FIELDS:
        if before_record.get(field) != after_record.get(field):
            raise AssertionError(
                f"BOUNDARY VIOLATION on {kid}: AI drafting changed '{field}', "
                "which it must never touch. Aborting.")


# ---- Rule (FRR) drafting -----------------------------------------------------
#
# The FRR entries are process rules (security inbox, notifications, trust
# center, change reporting, ...). No collector observes them, so a rule draft
# is built from (a) the curated reference-architecture example a fork may
# still carry for that field, when present, else (b) the CR26-derived
# fill_guidance (what_it_looks_for / how_to_comply / evidence_required), with
# the offering profile's REAL values named where they belong, and (c) when the
# provider imported AWS Config / Security Hub exports, the dated count-only
# observations the importer derived for the vulnerability-detection rules, so
# the proposal names the provider's own findings rather than only the official
# how-to text. Either way the text is a labelled proposal: the readiness
# predicates treat it as unanswered until a named human accepts it in
# `sdr.py review`.

# At most this many observations are quoted into one proposal.
MAX_OBSERVATIONS = 4


def _clip(s, n):
    s = (s or "").strip()
    return s if len(s) <= n else s[:s.rfind(" ", 0, n)].rstrip() + "..."


def _existing_example(value):
    """The curated example narrative in a field, label removed, or None."""
    items = value if isinstance(value, list) else [value]
    for item in items:
        if isinstance(item, str) and item.strip().startswith("Example ("):
            body = strip_label(item)
            if body:
                return body
    return None


def _observations_sentence(observations):
    """One sentence quoting the provider's own dated observations, or ''."""
    parts = []
    for o in (observations or [])[:MAX_OBSERVATIONS]:
        if not isinstance(o, dict) or not o.get("text"):
            continue
        when = str(o.get("observed_at") or "")[:10]
        src = o.get("source") or "export"
        parts.append(f"[{src}, {when}] {_clip(o['text'], 300)}")
    if not parts:
        return ""
    return (" Observed from the provider's own exports (counts and dates only, "
            "telemetry not a verdict): " + " ".join(parts))


def draft_rule_text(kind, rule_id, record, guidance, context, observations=None):
    """Deterministic, offline proposal for one rule field. Returns the labelled
    DRAFT string, or None when the guidance carries nothing to draft from.
    `observations` are the importer's dated texts for this rule, if any."""
    example = _existing_example(record.get(kind))
    if example:
        return EXAMPLE_LABEL + example
    looks = (guidance.get("what_it_looks_for") or "").strip()
    how = (guidance.get("how_to_comply") or "").strip()
    evidence = guidance.get("evidence_required") or []
    if not (looks or how or evidence):
        return None
    who = context.get("organization") or "the provider"
    what = context.get("offering") or "the offering"
    if kind == "implementation":
        body = (f"Proposed implementation narrative for {rule_id}, to be confirmed "
                f"or edited by {who} for {what}. Requirement: {_clip(looks, 300)} "
                f"Proposed approach: {_clip(how, 420)}")
        contacts = []
        if "inbox" in (looks + how).lower() and context.get("security_contact"):
            contacts.append(f"security contact {context['security_contact']}")
        if "incident" in (looks + how).lower() and context.get("incident_contact"):
            contacts.append(f"incident contact {context['incident_contact']}")
        if "trust center" in (looks + how).lower() and context.get("trust_center_uri"):
            contacts.append(f"trust center {context['trust_center_uri']}")
        if contacts:
            body += " Offering-profile values that apply: " + "; ".join(contacts) + "."
    else:
        ev = "; ".join(str(e) for e in evidence[:4]) or "the artifacts the rule names"
        body = (f"Proposed validation narrative for {rule_id}, to be confirmed or "
                f"edited by {who}. Validation approach: produce and retain {_clip(ev, 300)} "
                f"on the cadence stated in the implementation, review it against the "
                f"requirement ({_clip(looks, 200)}), and record each check and any miss.")
    body += _observations_sentence(observations)
    body += (" A proposal is not a compliance conclusion; the provider must confirm "
             "accuracy and completeness before relying on this text.")
    return DRAFT_LABEL + body


def draft_rule(rule_id, record, context, observations=None):
    """Draft implementation/validation prose into unanswered rule fields only
    (TBD, or a labelled Example / DRAFT proposal). Returns (changed, notes).
    Mutates the record on the proposed copy only; the boundary is enforced by
    the caller with _assert_boundary, exactly as for KSIs."""
    guidance = record.get("fill_guidance", {}) or {}
    notes = []
    changed = False
    for field in DRAFTABLE_FIELDS:
        current = record.get(field, "")
        if not is_tbd(current):
            continue  # never overwrite author-written prose
        text = draft_rule_text(field, rule_id, record, guidance, context, observations)
        if not text:
            continue
        record[field] = [text] if isinstance(current, list) else text
        changed = True
        if text.startswith(EXAMPLE_LABEL):
            source = "example"
        elif observations:
            source = "guidance + imported observations"
        else:
            source = "guidance"
        notes.append(f"{rule_id}: drafted {field} ({source})")
    return changed, notes


def main():
    ap = argparse.ArgumentParser(
        description="OPT-IN AI narrative drafting (reviewable diff; assists, never decides).")
    ap.add_argument("--write", action="store_true",
                    help="write the proposed AI-draft sidecar file")
    ap.add_argument("--drafter", default="template", choices=["template", "bedrock"],
                    help="drafting backend; 'template' is offline/default, "
                         "'bedrock' is opt-in and requires provider Bedrock access")
    ap.add_argument("--scope", default="all", choices=["all", "ksi", "rules"],
                    help="draft KSI narratives (needs collected facts), FRR rule "
                         "narratives (from the curated example or the CR26-derived "
                         "guidance plus the offering profile), or both (default)")
    args = ap.parse_args()

    registry = load(REGISTRY)
    store = load(RECORD_STORE)
    if registry is None or store is None:
        print("Could not load the registry or the record store.")
        return 2

    want_ksi = args.scope in ("all", "ksi")
    want_rules = args.scope in ("all", "rules")

    posture_by_service = load_all_posture_facts()
    config_by_rule = load_all_config_facts()
    ksi_observations = load_ksi_observations() if want_ksi else {}
    if want_ksi and not posture_by_service and not config_by_rule and not ksi_observations:
        if args.scope == "ksi":
            print("No facts found in automation/facts/. Run the collector first "
                  "(read-only): python automation/collectors/collect_facts.py --profile <ReadOnly>, "
                  "or import the provider's Rev5 SSP / landing-zone configuration "
                  "(automation/importers/).")
            return 1
        print("No facts found in automation/facts/; KSI narratives are skipped "
              "(run the read-only collector or an importer first). Rule narratives are drafted.")
        want_ksi = False
    if want_ksi and ksi_observations:
        print(f"Imported observations found for {len(ksi_observations)} KSI(s); those "
              "proposals quote the provider's own sources.")

    try:
        drafter = get_drafter(args.drafter)
    except Exception as e:  # noqa: BLE001 - a missing backend must fall back cleanly
        print(f"Could not initialize drafter '{args.drafter}' ({type(e).__name__}); "
              "falling back to the offline template drafter.")
        drafter = TemplateDrafter()

    # Import the deterministic prefill's service map so AI and prefill agree on
    # which service informs which KSI. Kept as the single source of truth.
    sys.path.insert(0, os.path.join(BASE, "automation", "prefill"))
    try:
        import prefill_from_facts as pf
        service_map = pf.POSTURE_SERVICE_KEYS
    except Exception:  # noqa: BLE001
        service_map = {}

    proposed = copy.deepcopy(store)
    ksi_records = proposed.get("ksi", {})
    all_notes = []
    drafted = 0
    if want_ksi:
        for kid, ksi_entry in registry.get("ksis", {}).items():
            record = ksi_records.get(kid)
            if record is None:
                continue
            before = copy.deepcopy(record)
            changed, notes = draft_ksi(kid, record, ksi_entry, posture_by_service,
                                       drafter, service_map, ksi_observations.get(kid),
                                       config_by_rule)
            _assert_boundary(before, record, kid)  # enforce the boundary per KSI
            if changed:
                drafted += 1
            all_notes.extend(notes)

    rules_drafted = 0
    if want_rules:
        context = load_profile_context()
        observations = load_rule_observations()
        if observations:
            print(f"Imported observations found for {len(observations)} rule(s); "
                  "those proposals quote the provider's own export counts.")
        for rule_id, record in sorted(proposed.get("frr", {}).items()):
            before = copy.deepcopy(record)
            changed, notes = draft_rule(rule_id, record, context,
                                        observations.get(rule_id))
            _assert_boundary(before, record, rule_id)  # same boundary for rules
            if changed:
                rules_drafted += 1
            all_notes.extend(notes)

    if drafted == 0 and rules_drafted == 0:
        print("No narratives were drafted (fields already authored, or no "
              "matching facts). AI drafting only fills unanswered implementation/"
              "validation prose (TBD, or a labelled Example / DRAFT proposal).")
        return 0

    before = json.dumps(store, indent=1, ensure_ascii=False).splitlines(keepends=True)
    after = json.dumps(proposed, indent=1, ensure_ascii=False).splitlines(keepends=True)
    sys.stdout.writelines(difflib.unified_diff(
        before, after,
        fromfile="records-store.json (current)",
        tofile="records-store.json (proposed AI draft)"))

    print(f"\nAI draft summary (drafter={drafter.name}):")
    for note in all_notes:
        print(f"  {note}")
    print(f"\n{drafted} KSI(s) and {rules_drafted} rule(s) received a DRAFT "
          "implementation/validation narrative.")
    print("This is an AI-ASSISTED PROPOSAL. implementation_status, assessment, "
          "tests, and evidence were NOT touched. Every draft is unverified; the "
          "readiness predicates treat a labelled DRAFT as unanswered until a named "
          "human accepts it with `python sdr.py review --walk`.")

    if args.write:
        with open(AI_SIDECAR, "w", encoding="utf-8", newline="\n") as f:
            json.dump(proposed, f, indent=1)
        print(f"\nWrote AI draft to {os.path.relpath(AI_SIDECAR, BASE)} "
              "(git-excluded). Review each proposal with "
              "`python sdr.py review --walk --reviewer \"<name>\" --role \"<role>\"`; "
              "accept, edit or reject, nothing enters the record store otherwise.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
