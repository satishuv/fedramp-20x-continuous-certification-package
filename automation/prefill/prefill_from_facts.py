# Deterministic fact-to-field pre-fill (Layer 2 core, no LLM).
#
# Reads a collected facts store and the collector registry, and proposes
# additions to each KSI's `tests`, `evidence`, and `extension`.
# `automation_verification` field, every proposed line carrying provenance back
# to the dated collector fact that justifies it. This turns the authoring task
# (writing 46 KSIs from a blank template) into a review task.
#
# The hard boundary, enforced here in code:
#   - Never sets or changes `implementation_status`. A status is a human
#     judgment plus sign-off; a passing telemetry fact is not that.
#   - Never writes `assessment` (accredited independent assessor only).
#   - Never edits the record store in place. It writes a proposed copy to a
#     sidecar file and prints a unified diff. A human reviews and applies.
#   - Only proposes for facts that are dated and not ERROR/None. A missing or
#     failed fact leaves the field as the provider must author it.
#
# Usage:
#   python automation/prefill/prefill_from_facts.py            # print the diff
#   python automation/prefill/prefill_from_facts.py --write    # write sidecar
#
# The sidecar (records-store.prefilled.json) is git-excluded like the facts
# store; the provider diffs it, keeps the lines that are right, and edits the
# real record store by hand. Nothing here decides compliance.

import argparse
import copy
import difflib
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REGISTRY = os.path.join(BASE, "automation", "collectors", "registry.json")
FACTS_DIR = os.path.join(BASE, "automation", "facts")
RECORD_STORE = os.path.join(BASE, "sdr", "records", "records-store.json")
SIDECAR = os.path.join(BASE, "sdr", "records", "records-store.prefilled.json")

TBD_MARKERS = ("TBD:", "TBD ", "Information has not been provided")

# Map a collector posture service to the KSI families it most directly informs.
# Used only to attach a posture fact to the right KSIs when the registry's
# per-KSI service list names that service. This is a hint for provenance, not
# a compliance decision.
#
# Sourced from the single canonical service registry
# (automation/collectors/service_registry.py) so it never drifts behind the
# collector's emitted services; test_service_registry.py asserts every
# collector-emitted service is registered or explicitly telemetry-only.
# The canonical service registry lists every posture service key a collector
# can emit. metric_service_keys allowlist entries are validated against it so a
# typo'd key (which would silently route nothing) is caught, not ignored.
# Sourced from automation/collectors/service_registry.py so it never drifts.
sys.path.insert(0, os.path.join(BASE, "automation", "collectors"))
try:
    from service_registry import SERVICE_DISPLAY_NAMES as KNOWN_SERVICE_KEYS
except Exception as exc:  # fail loud: silent unrouted telemetry is the failure
    raise RuntimeError(
        "prefill_from_facts could not import the canonical service registry "
        "(automation/collectors/service_registry.py); refusing to prefill with "
        "an empty routing map that would silently drop posture telemetry: "
        + str(exc)
    )
# AUD-F18: the SAME identity the metric engine keys per-method history by and
# the VVK binding gate compares. Prefill writes it as each test's method_id.
sys.path.insert(0, os.path.join(BASE, "automation", "metrics"))
from method_ids import config_method_id, posture_method_id, parse_service_key  # noqa: E402
# AUD-F58: proposed evidence objects are built by the ONE canonical evidence
# factory the collector path uses (bound displayed fields + sanitized source
# fact + recomputable xEvidenceContentHash), never hand-assembled here. A
# hand-built object has no digest for the integrity gate to recompute and no
# source fact for a reviewer to trace, so once a human accepted it the record
# carried evidence the gate could never verify.
from evidence_wiring import fact_to_evidence  # noqa: E402

# Env names shared with the collector path (collect_multi_account.py).
SCOPE_KEY_ENV = "SDR_EVIDENCE_SCOPE_KEY"
LOCATION_BASE_ENV = "SDR_EVIDENCE_LOCATION_BASE"


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def is_tbd(value):
    if isinstance(value, str):
        return any(m in value for m in TBD_MARKERS) or value.strip() == ""
    if isinstance(value, list):
        return len(value) == 0 or all(is_tbd(v) for v in value)
    return False


def load_all_facts():
    """Merge every facts-*.json in the facts store into one view keyed by the
    collector check_id (config rules) and by service (posture facts)."""
    config_by_rule = {}
    posture_by_service = {}
    if not os.path.isdir(FACTS_DIR):
        return config_by_rule, posture_by_service, None
    latest_ts = None
    for fn in sorted(os.listdir(FACTS_DIR)):
        if not fn.startswith("facts-") or not fn.endswith(".json"):
            continue
        store = load(os.path.join(FACTS_DIR, fn), {})
        latest_ts = store.get("meta", {}).get("collected_at") or latest_ts
        for fact in store.get("facts", []):
            config_by_rule[fact.get("rule")] = fact
        for pf in store.get("posture_facts", []):
            posture_by_service.setdefault(pf.get("service"), []).append(pf)
    return config_by_rule, posture_by_service, latest_ts


def config_facts_for_ksi(ksi_entry, config_by_rule):
    """Dated Config-rule facts that back this KSI, from the registry checks."""
    out = []
    for check in ksi_entry.get("checks", []):
        if check.get("type") != "config_managed_rule":
            continue
        fact = config_by_rule.get(check.get("target"))
        if not fact:
            continue
        ct = fact.get("compliance_type", "")
        if ct.startswith("ERROR") or ct in ("RULE_NOT_DEPLOYED", "UNKNOWN", ""):
            continue
        out.append((check, fact))
    return out


def posture_facts_for_ksi(ksi_entry, posture_by_service):
    """Posture facts whose (service, check) is in this KSI's EXPLICIT
    `metric_service_keys` allowlist. This is the same per-KSI binding the metric
    engine uses (introduced to stop generic AWS posture fanning out to a KSI by
    prose service-name mention); prefill must honor it too, or it would author
    telemetry the metric layer refuses to score. AUD-F16: every entry is
    check-scoped ("service:check"); a bare service key is refused. Skips
    ERROR/None/partial facts so only real, complete observations pre-fill. An
    empty allowlist means no posture routes to this KSI (its evidence comes from
    its config-rule methods)."""
    allow = list(ksi_entry.get("metric_service_keys") or [])
    routes = []
    for key in allow:
        service, check = parse_service_key(key)
        if not check:
            raise RuntimeError(
                f"{ksi_entry.get('ksi_id') or 'KSI'} metric_service_keys entry "
                f"{key!r} routes a whole service; entries must be service:check")
        routes.append((service, check))
    unknown = {s for s, _ in routes} - set(KNOWN_SERVICE_KEYS)
    if unknown:
        raise RuntimeError(
            f"{ksi_entry.get('ksi_id') or 'KSI'} metric_service_keys names "
            f"unknown service key(s) {sorted(unknown)} not in the canonical "
            "service registry; a typo here would silently route no posture. "
            "Fix the key or register the service.")
    out = []
    for service, check in routes:
        for pf in posture_by_service.get(service, []):
            if pf.get("check") != check:
                continue
            status = pf.get("status", "")
            if (status.startswith("ERROR") or pf.get("partial") is True
                    or status in ("NONE", "NO_COVERAGE", "NOT_ENABLED", "NO_KEYS",
                                  "OBSERVED_PARTIAL", "UNKNOWN")):
                continue
            out.append(pf)
    return out


def config_fact_as_collector_fact(check, fact):
    """Render one Config-rule fact in the collector fact shape evidence_wiring
    binds (service / check / status / detail / region / observation time), so
    the proposed evidence object is derived by the same factory as every other
    collector observation. The scope identity fields the multi-account
    collector stamps (account, scope, run_id) are carried through untouched:
    the factory derives the opaque scope and refuses an account-tagged fact
    that cannot be scoped (AUD-F27); the raw account never enters the object."""
    out = {
        "service": "config",
        "check": check.get("target"),
        "status": fact.get("compliance_type"),
        "detail": (f"AWS Config rule {check.get('target')} evaluated "
                   f"{fact.get('compliance_type')}; collected read-only by the SDR "
                   f"collector (check {check.get('check_id')})"),
        "region": fact.get("region") or "unknown",
    }
    for key in ("collected_at", "observed_at", "timestamp", "account", "scope", "run_id"):
        if fact.get(key) is not None:
            out[key] = fact[key]
    return out


def prefill_ksi(kid, record, ksi_entry, config_by_rule, posture_by_service,
                location_base=None, scope_key=None):
    """Return (changed, notes). Mutates `record` in place on the proposed copy.
    Only fills fields that are still in TBD/empty template state.

    location_base: the provider's evidence-store base URI; proposed evidence
    pointers are concrete URLs under it. Without it the pointer is an explicit
    sdr://placeholder/ pseudo-URI that preflight refuses, and because the
    pointer is a bound (hashed) field the entry must be RE-DERIVED with the real
    base rather than edited by hand. scope_key: deployment-private key for
    account-tagged facts (AUD-F27)."""
    notes = []
    cfg = config_facts_for_ksi(ksi_entry, config_by_rule)
    posture = posture_facts_for_ksi(ksi_entry, posture_by_service)
    if not cfg and not posture:
        return False, notes

    changed = False

    # tests: propose one STRUCTURED automated method per backing fact, only if
    # the tests list is still empty/template. AUD-F18: plain strings counted as
    # ZERO automated methods to the FRC-CSX-VVK validator and could never bind
    # to telemetry, so the real collector -> prefill -> preflight path never
    # reached Class C readiness; only the hand-wired sample did. Each record
    # carries automated:true and a method_id that is EXACTLY the key the metric
    # engine writes the per-method series under (config: the registry check_id;
    # posture: posture:<service>:<check>), so the binding gate finds it.
    if is_tbd(record.get("tests", [])):
        new_tests = []
        for check, fact in cfg:
            new_tests.append({
                "method_id": config_method_id(check),
                # AUD-F48: plain text. A backtick here reached the human-readable
                # SDR on accept and failed the no_markdown_in_human_readable gate.
                "method": (f"Automated (collector): AWS Config rule {check['target']} "
                           f"evaluated continuously ({check['source']} method); last "
                           f"observed {fact['compliance_type']} on {fact['collected_at']}."),
                "automated": True,
                "cadence": "continuous (AWS Config evaluation; collected each run)",
                "source": "AWS Config",
                "provenance": check["check_id"],
                "last_observed": fact["collected_at"],
            })
        for pf in posture:
            new_tests.append({
                "method_id": posture_method_id(pf["service"], pf["check"]),
                "method": (f"Automated (collector): read-only {pf['service']}.{pf['check']} "
                           f"posture check; last observed {pf['status']} on "
                           f"{pf['collected_at']}. {pf['detail']}."),
                "automated": True,
                "cadence": "each collector run (scheduled)",
                "source": KNOWN_SERVICE_KEYS.get(pf["service"], pf["service"]),
                "provenance": f"{pf['service']}.{pf['check']}",
                "last_observed": pf["collected_at"],
            })
        if new_tests:
            record["tests"] = new_tests
            changed = True
            notes.append(f"{kid}: filled {len(new_tests)} structured automated "
                         "method(s) from facts")

    # evidence: append evidence OBJECTS, only if still empty, derived by the
    # canonical factory (AUD-F58). The official SDR schema requires ksiEvidence
    # items to be objects with an evidenceType from a fixed enum; the factory
    # emits that shape plus the bound sanitized source fact and the
    # recomputable xEvidenceContentHash the live integrity gate verifies. It is
    # still telemetry: it does not assert the KSI is met. A fact the factory
    # refuses (account-tagged with no scope) raises; it is never skipped silently.
    if is_tbd(record.get("evidence", [])):
        collector_facts = [config_fact_as_collector_fact(check, fact) for check, fact in cfg]
        collector_facts.extend(dict(pf) for pf in posture)
        new_ev = []
        for cf in collector_facts:
            ev = fact_to_evidence(cf, location_base, scope_key=scope_key)
            if ev is not None:
                new_ev.append(ev)
        if new_ev:
            record["evidence"] = new_ev
            changed = True
            notes.append(f"{kid}: filled {len(new_ev)} evidence object(s)")

    # extension.automation_verification: a single dated summary line, only if TBD.
    ext = record.get("extension", {})
    if isinstance(ext, dict) and is_tbd(ext.get("automation_verification", "")):
        n = len(cfg) + len(posture)
        ext["automation_verification"] = (
            f"Draft from collectors: {n} automated read-only check(s) observed "
            "for this indicator. Review each and confirm it demonstrates the "
            "measure before relying on it; a passing check is telemetry, not a "
            "compliance conclusion.")
        changed = True
        notes.append(f"{kid}: drafted automation_verification")

    return changed, notes


def main():
    ap = argparse.ArgumentParser(
        description="Deterministic fact-to-field pre-fill (reviewable diff).")
    ap.add_argument("--write", action="store_true",
                    help="write the proposed record store to the sidecar file")
    ap.add_argument("--location-base", default=os.environ.get(LOCATION_BASE_ENV),
                    help="evidence-store base URI for proposed evidence pointers "
                         f"(default: ${LOCATION_BASE_ENV}); without it pointers are "
                         "sdr://placeholder/ pseudo-URIs that preflight refuses")
    args = ap.parse_args()
    scope_key = os.environ.get(SCOPE_KEY_ENV) or None
    location_base = args.location_base or None

    registry = load(REGISTRY)
    store = load(RECORD_STORE)
    if registry is None or store is None:
        print("Could not load the registry or the record store.")
        return 2

    config_by_rule, posture_by_service, latest_ts = load_all_facts()
    if not config_by_rule and not posture_by_service:
        print("No facts found in automation/facts/. Run the collector first:")
        print("    python automation/collectors/collect_facts.py --profile <ReadOnly>")
        return 1

    proposed = copy.deepcopy(store)
    ksi_records = proposed.get("ksi", {})
    all_notes = []
    filled = 0
    for kid, ksi_entry in registry.get("ksis", {}).items():
        record = ksi_records.get(kid)
        if record is None:
            continue
        changed, notes = prefill_ksi(kid, record, ksi_entry,
                                     config_by_rule, posture_by_service,
                                     location_base=location_base, scope_key=scope_key)
        if changed:
            filled += 1
        all_notes.extend(notes)

    if filled == 0:
        print("No KSI fields were pre-filled. Either no backing facts matched, "
              "or the fields were already populated (pre-fill only touches "
              "TBD/empty template fields).")
        return 0

    before = json.dumps(store, indent=1, ensure_ascii=False).splitlines(keepends=True)
    after = json.dumps(proposed, indent=1, ensure_ascii=False).splitlines(keepends=True)
    diff = difflib.unified_diff(
        before, after,
        fromfile="records-store.json (current)",
        tofile="records-store.json (proposed pre-fill)")
    sys.stdout.writelines(diff)

    print(f"\nPre-fill summary (facts collected {latest_ts}):")
    for note in all_notes:
        print(f"  {note}")
    print(f"\n{filled} KSI(s) had at least one field pre-filled from facts.")
    print("This is a PROPOSAL. implementation_status and assessment were not "
          "touched. Review each line, then hand-edit the real record store; a "
          "passing check is telemetry, not a compliance conclusion.")

    if args.write:
        with open(SIDECAR, "w", encoding="utf-8", newline="\n") as f:
            json.dump(proposed, f, indent=1)
        print(f"\nWrote proposed record store to {os.path.relpath(SIDECAR, BASE)} "
              "(git-excluded). Diff it against the real store and apply what is "
              "correct by hand.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
