"""Review step: accept, edit or reject every proposed narrative without editing JSON.

Why this exists
---------------
The collectors (``records-store.prefilled.json``) and the drafter
(``records-store.ai-draft.json``) write PROPOSALS into git-excluded sidecars, and
the template itself carries labelled ``Example (...)`` / ``Example:`` values.
Until now the only way to turn a proposal into the provider's record was to
copy it into ``records-store.json`` by hand. This module replaces that with one
decision per field, made by a NAMED human:

  accept   the proposal becomes the record (label stripped)
  edit     the human's corrected text becomes the record
  reject   the record is left exactly as it was
  skip     decide later

Every decision is appended to ``sdr/reviews/field-review-log.json`` with who,
when, the source of the proposal, its provenance, and the SHA-256 of the
proposed text and of what was applied. ``validate_reviews.py`` checks the log:
a human reviewer, an allowed decision, and that an accepted or edited field's
CURRENT value still hashes to what the reviewer applied (a later silent edit
invalidates the review).

What this module never does
---------------------------
It never writes ``implementation_status`` or ``assessment`` (a status needs a
passing deterministic check plus the sign-off in the review register; the
assessment belongs to the assessor). It never applies anything without a named
reviewer and role. It never accepts on the pipeline's behalf: ``--accept-all``
exists for the deterministic prefill (collector facts, not prose) and still
records the named human who chose it.

Usage (via ``sdr.py review``):
  python sdr.py review --list
  python sdr.py review --walk --reviewer "Jane Doe" --role "Compliance lead"
  python sdr.py review --decisions decisions.json --reviewer ... --role ...
"""
import copy
import datetime as _dt
import hashlib
import json
import os
import sys
import uuid

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
RECORD_STORE = os.path.join(BASE, "sdr", "records", "records-store.json")
PREFILL_SIDECAR = os.path.join(BASE, "sdr", "records", "records-store.prefilled.json")
AI_SIDECAR = os.path.join(BASE, "sdr", "records", "records-store.ai-draft.json")
FIELD_REVIEW_LOG = os.path.join(BASE, "sdr", "reviews", "field-review-log.json")

sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
from unreviewed_text import is_unreviewed, strip_label  # noqa: E402

# Fields a review decision may write. Narrative prose, the extension's
# human-stated facts, and (prefill only) the structured KSI tests/evidence.
# implementation_status and assessment are NEVER reviewable here.
NARRATIVE_FIELDS = ("implementation", "validation")
EXTENSION_FIELDS = (
    "owner", "verification", "validation_frequency", "failure_condition",
    "failure_response", "evidence_freshness", "customer_risk",
    "independent_verification", "independent_validation", "measures",
    "operating_cycle", "metric_source", "pass_condition", "method",
)
STRUCTURED_FIELDS = ("tests", "evidence")  # prefill only
FORBIDDEN_FIELDS = ("implementation_status", "assessment")

DECISIONS = ("accepted", "edited", "rejected")
# Mirrors validate_reviews.py: a reviewer must be a human identity.
FORBIDDEN_REVIEWERS = {"", "deterministic", "pipeline", "sdr.py", "automation",
                       "ci", "github-actions", "bot", "system", "ai", "drafter",
                       "collector", "prefill"}


class ReviewError(Exception):
    pass


def _load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _sha256(value):
    canon = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _get(record, path):
    node = record
    for part in path:
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def _set(record, path, value):
    node = record
    for part in path[:-1]:
        node = node.setdefault(part, {})
    node[path[-1]] = value


def _field_key(section, record_id, path):
    return f"{section}/{record_id}." + ".".join(path)


def _strip(value):
    if isinstance(value, list):
        return [strip_label(v) if isinstance(v, str) else v for v in value]
    return strip_label(value) if isinstance(value, str) else value


# ---- Proposal discovery ------------------------------------------------------

def _reviewable_paths(section, record):
    paths = [(f,) for f in NARRATIVE_FIELDS]
    ext = record.get("extension")
    if isinstance(ext, dict):
        paths += [("extension", f) for f in EXTENSION_FIELDS if f in ext]
        resp = ext.get("responsibility")
        if isinstance(resp, dict):
            paths += [("extension", "responsibility", k) for k in sorted(resp)]
    if section == "ksi":
        paths += [(f,) for f in STRUCTURED_FIELDS]
    return paths


def proposals(store, prefill=None, ai_draft=None):
    """Every pending proposal, in a stable order. Each item:
    {key, section, record_id, path, current, proposed, source, provenance}.

    Sources, in precedence order for the same field: ``prefill`` (collector
    facts, deterministic) beats ``ai-draft`` (prose) beats ``template-example``
    (a labelled value already in the store). A sidecar value identical to the
    store is not a proposal. A sidecar may propose only reviewable paths; a
    difference on a forbidden path is reported as a violation, never applied.
    """
    out = []
    violations = []
    for section in ("frr", "ksi"):
        records = store.get(section, {}) or {}
        for record_id in sorted(records):
            record = records[record_id]
            seen = set()
            for src_name, sidecar in (("prefill", prefill), ("ai-draft", ai_draft)):
                if not sidecar:
                    continue
                cand = (sidecar.get(section, {}) or {}).get(record_id)
                if not isinstance(cand, dict):
                    continue
                for f in FORBIDDEN_FIELDS:
                    if f in cand and cand.get(f) != record.get(f):
                        violations.append(
                            f"{src_name} sidecar proposes {section}/{record_id}.{f}, "
                            "which is never reviewable here; ignored")
                for path in _reviewable_paths(section, record):
                    if path in seen:
                        continue
                    if src_name == "ai-draft" and path[0] in STRUCTURED_FIELDS:
                        continue  # prose drafter may not propose tests/evidence
                    prop = _get(cand, path)
                    cur = _get(record, path)
                    if prop is None or prop == cur:
                        continue
                    seen.add(path)
                    out.append({
                        "key": _field_key(section, record_id, path),
                        "section": section, "record_id": record_id, "path": list(path),
                        "current": cur, "proposed": prop, "source": src_name,
                        "provenance": _provenance(src_name, sidecar, section, record_id, path),
                    })
            # Labelled examples already in the store are proposals too.
            for path in _reviewable_paths(section, record):
                if path in seen or path[0] in STRUCTURED_FIELDS:
                    continue
                cur = _get(record, path)
                if cur is not None and is_unreviewed(cur):
                    seen.add(path)
                    out.append({
                        "key": _field_key(section, record_id, path),
                        "section": section, "record_id": record_id, "path": list(path),
                        "current": cur, "proposed": cur, "source": "template-example",
                        "provenance": {"note": "labelled example shipped in the template"},
                    })
    return out, violations


def _provenance(src_name, sidecar, section, record_id, path):
    meta = sidecar.get("meta") or sidecar.get("store_note") or {}
    prov = {"sidecar": src_name}
    if isinstance(meta, dict):
        for k in ("generated_at", "facts_sha256", "run_id", "drafter", "collector"):
            if k in meta:
                prov[k] = meta[k]
    if src_name == "ai-draft":
        prov["drafter_label"] = "DRAFT"
    return prov


# ---- Applying decisions ------------------------------------------------------

def _check_reviewer(reviewer, role):
    r = (reviewer or "").strip()
    if r.lower() in FORBIDDEN_REVIEWERS or len(r) < 3:
        raise ReviewError("a review needs a named human reviewer (--reviewer), "
                          f"got {reviewer!r}")
    if not (role or "").strip():
        raise ReviewError("a review needs the reviewer's role (--role)")


def _now():
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


def apply_decisions(store, items, decisions, reviewer, role, log=None, now=None):
    """Apply ``decisions`` ({key: {"decision": ..., "text": ...}}) to ``store``.

    Returns (new_store, new_log, applied_count). Pure with respect to its
    inputs (deep copies); the caller persists. Raises ReviewError on a
    forbidden path, an unknown decision, an edit without text, or a
    non-human reviewer. Unknown keys in ``decisions`` are an error too: a
    typo must not silently do nothing.
    """
    _check_reviewer(reviewer, role)
    by_key = {it["key"]: it for it in items}
    unknown = sorted(set(decisions) - set(by_key))
    if unknown:
        raise ReviewError("decisions name fields that are not pending proposals: "
                          + ", ".join(unknown[:5]))
    new_store = copy.deepcopy(store)
    new_log = copy.deepcopy(log) if log else {"log_note": LOG_NOTE, "reviews": []}
    new_log.setdefault("reviews", [])
    stamp = now or _now()
    applied = 0
    for key in sorted(decisions):
        d = decisions[key] or {}
        decision = d.get("decision")
        if decision not in DECISIONS:
            raise ReviewError(f"{key}: decision must be one of {DECISIONS}, got {decision!r}")
        it = by_key[key]
        path = tuple(it["path"])
        if path[0] in FORBIDDEN_FIELDS:
            raise ReviewError(f"{key}: {path[0]} is never reviewable here")
        record = new_store[it["section"]][it["record_id"]]
        entry = {
            "review_id": f"FR-{uuid.uuid4().hex[:12]}",
            "field": key,
            "section": it["section"],
            "record_id": it["record_id"],
            "decision": decision,
            "reviewer": reviewer.strip(),
            "role": role.strip(),
            "reviewed_at": stamp,
            "source": it["source"],
            "provenance": it["provenance"],
            "proposed_sha256": _sha256(it["proposed"]),
        }
        if decision == "accepted":
            value = _strip(it["proposed"])
            if is_unreviewed(value):
                raise ReviewError(f"{key}: accepted text still carries a proposal label")
            _set(record, path, value)
            entry["applied_sha256"] = _sha256(value)
            applied += 1
        elif decision == "edited":
            text = d.get("text")
            if not isinstance(text, str) or len(text.strip()) < 3:
                raise ReviewError(f"{key}: an edit needs the reviewer's text")
            if is_unreviewed(text):
                raise ReviewError(f"{key}: edited text may not start with a proposal label")
            cur = _get(record, path)
            value = [text.strip()] if isinstance(cur, list) else text.strip()
            _set(record, path, value)
            entry["applied_sha256"] = _sha256(value)
            applied += 1
        else:  # rejected: record untouched
            entry["applied_sha256"] = None
            if d.get("reason"):
                entry["reason"] = str(d["reason"])[:500]
        new_log["reviews"].append(entry)
    return new_store, new_log, applied


LOG_NOTE = (
    "Field-level review log. Each entry records ONE named human's decision on ONE "
    "proposed field (from the collector prefill sidecar, the AI-draft sidecar, or a "
    "labelled example shipped in the template): accepted (proposal applied, label "
    "stripped), edited (the reviewer's text applied) or rejected (record untouched). "
    "applied_sha256 binds the decision to the exact value written; "
    "validate_reviews.py fails when a reviewed field was changed afterwards without "
    "a new decision. This log is not approval of a rule or KSI (that is the review "
    "register) and never records implementation_status or assessment."
)


def write_store(store, path=None):
    path = path or RECORD_STORE  # resolved at call time (tests redirect it)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(store, f, indent=1, ensure_ascii=False)
        f.write("\n")


def write_log(log, path=None):
    path = path or FIELD_REVIEW_LOG
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(log, f, indent=1, ensure_ascii=False)
        f.write("\n")


# ---- Interactive walk --------------------------------------------------------

def _fmt(value, width=600):
    s = json.dumps(value, ensure_ascii=False, indent=1) if isinstance(value, (list, dict)) \
        else str(value)
    return s if len(s) <= width else s[:width] + " ..."


def walk(items, reviewer, role, prompt=input, out=print):
    """Interactive one-key-per-field review. Returns the decisions dict.
    ``prompt``/``out`` are injectable for tests."""
    decisions = {}
    total = len(items)
    for i, it in enumerate(items, 1):
        out("")
        out(f"[{i}/{total}] {it['key']}   source: {it['source']}")
        out(f"  current : {_fmt(it['current'])}")
        if it["source"] != "template-example":
            out(f"  proposed: {_fmt(it['proposed'])}")
        out(f"  on accept: {_fmt(_strip(it['proposed']), 300)}")
        while True:
            ans = (prompt("  [a]ccept  [e]dit  [r]eject  [s]kip  [q]uit > ") or "").strip().lower()
            if ans in ("a", "accept"):
                decisions[it["key"]] = {"decision": "accepted"}
                break
            if ans in ("e", "edit"):
                text = prompt("  your text > ").strip()
                if len(text) < 3 or is_unreviewed(text):
                    out("  need real text (not a label); try again")
                    continue
                decisions[it["key"]] = {"decision": "edited", "text": text}
                break
            if ans in ("r", "reject"):
                reason = prompt("  reason (optional) > ").strip()
                decisions[it["key"]] = {"decision": "rejected", "reason": reason}
                break
            if ans in ("s", "skip", ""):
                break
            if ans in ("q", "quit"):
                return decisions
            out("  a / e / r / s / q")
    return decisions


# ---- Entry point used by sdr.py ---------------------------------------------

def run(args, out=print, prompt=input):
    store = _load(RECORD_STORE)
    if store is None:
        out("Could not load sdr/records/records-store.json")
        return 2
    prefill = _load(PREFILL_SIDECAR)
    ai_draft = _load(AI_SIDECAR)
    items, violations = proposals(store, prefill, ai_draft)
    for v in violations:
        out(f"WARNING: {v}")
    if getattr(args, "source", None):
        items = [it for it in items if it["source"] == args.source]
    if getattr(args, "only", None):
        items = [it for it in items if it["key"].startswith(args.only)]

    if not items:
        out("No pending proposals. Run the collector + prefill, or the drafter "
            "(python automation/ai/draft_narratives.py --write), to create some.")
        return 0

    if getattr(args, "list", False) or not (
            getattr(args, "walk", False) or getattr(args, "decisions", None)
            or getattr(args, "accept_all", False)):
        by_src = {}
        for it in items:
            by_src[it["source"]] = by_src.get(it["source"], 0) + 1
        out(f"Pending proposals: {len(items)}  "
            + "  ".join(f"{k}={v}" for k, v in sorted(by_src.items())))
        for it in items[:200]:
            out(f"  {it['key']}  [{it['source']}]")
        if len(items) > 200:
            out(f"  ... {len(items) - 200} more")
        out("")
        out("Decide with: python sdr.py review --walk --reviewer \"<name>\" --role \"<role>\"")
        return 0

    reviewer = getattr(args, "reviewer", None)
    role = getattr(args, "role", None)
    try:
        _check_reviewer(reviewer, role)
    except ReviewError as e:
        out(f"REFUSED: {e}")
        return 2

    if getattr(args, "decisions", None):
        decisions = _load(args.decisions)
        if not isinstance(decisions, dict):
            out(f"Could not read decisions file {args.decisions}")
            return 2
    elif getattr(args, "accept_all", False):
        if args.accept_all != "prefill":
            out("REFUSED: --accept-all applies only to 'prefill' (deterministic collector "
                "facts). Prose proposals are decided one at a time.")
            return 2
        decisions = {it["key"]: {"decision": "accepted"}
                     for it in items if it["source"] == "prefill"}
        if not decisions:
            out("No prefill proposals pending.")
            return 0
    else:
        decisions = walk(items, reviewer, role, prompt=prompt, out=out)
        if not decisions:
            out("No decisions made; nothing written.")
            return 0

    log = _load(FIELD_REVIEW_LOG)
    try:
        new_store, new_log, applied = apply_decisions(
            store, items, decisions, reviewer, role, log=log)
    except ReviewError as e:
        out(f"REFUSED: {e}")
        return 2
    write_store(new_store)
    write_log(new_log)
    rejected = sum(1 for d in decisions.values() if d.get("decision") == "rejected")
    out("")
    out(f"Applied {applied} field(s) to the record store; rejected {rejected}; "
        f"{len(decisions)} decision(s) recorded in sdr/reviews/field-review-log.json "
        f"by {reviewer.strip()} ({role.strip()}).")
    out("Rebuild with `python sdr.py all`. implementation_status and assessment were "
        "not touched: a status still needs its passing check and the sign-off in the "
        "review register.")
    return 0
