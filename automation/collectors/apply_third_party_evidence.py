#!/usr/bin/env python3
"""Apply enabled third-party evidence sources (CrowdStrike Falcon, Wiz) to the
record store, per the opt-in flags in the offering profile.

This is OPT-IN and does nothing unless a source is enabled in
profiles/common/offering-profile.json under evidence_sources. For each enabled
source it reads the customer-produced export file, runs the matching adapter,
and attaches the resulting evidence to that source's mapped KSIs in
sdr/records/records-store.json.

Trust boundary (unchanged): only the ksi `evidence` array is touched. No
implementation, validation, or assessment status is set. If a source is
enabled but its export file is absent, the source is skipped with a message,
not an error, so a fresh clone with the flag on but no export still builds.

    python automation/collectors/apply_third_party_evidence.py

Run before build_sdr.py so the attached evidence flows into the SDR. Offline:
reads only local files, no network, no credentials.

A source may also be MAPPING-DRIVEN (MCE-02): its evidence_sources entry
carries `mapping_path` (an adapter-mapping.schema.json file) beside
`export_path`; the adapter is built from the mapping at run time, so adding a
source is a JSON file, not Python. The entry's key must equal the mapping's
`name`. An export with no records is reported as a collection outcome of
not-run and attaches nothing. Set SDR_EVIDENCE_SCOPE_KEY when an export carries
raw scope identifiers (account, tenant, subscription, compartment, project,
organization, host); without it such facts are refused, never exported raw.

Evidence pointers (AUD-F80): every entry's evidenceLocation is built under the
provider's evidence-store base URI, SDR_EVIDENCE_LOCATION_BASE (or
--location-base), the same variable the collector path (prefill_from_facts.py)
reads. Without it the pointers are sdr://placeholder/ pseudo-URIs, which
package-preflight refuses at Class C; the driver says so when it applies them.
"""

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence_wiring as ew  # noqa: E402
import mapping_adapter as ma  # noqa: E402
import thirdparty_adapters  # noqa: E402,F401  (registers the adapters)

PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
RECORDS = os.path.join(BASE, "sdr", "records", "records-store.json")
# Env names shared with the collector path (collect_multi_account.py,
# prefill_from_facts.py).
SCOPE_KEY_ENV = "SDR_EVIDENCE_SCOPE_KEY"
LOCATION_BASE_ENV = "SDR_EVIDENCE_LOCATION_BASE"


def _obs_key(ev):
    """A change signal for an evidence entry at a given location: its content
    hash if present, else its observation timestamp, else its text."""
    if not isinstance(ev, dict):
        return None
    return (ev.get("xEvidenceContentHash")
            or ev.get("collected_at") or ev.get("observed_at")
            or ev.get("evidenceText"))


def _is_newer(new_ev, prior_ev):
    """True when new_ev is a DIFFERENT (updated) observation than prior_ev at the
    same location - a changed content hash or a later timestamp. Identical
    observations are not 'newer' and do not replace."""
    nk, pk = _obs_key(new_ev), _obs_key(prior_ev)
    if nk is None or pk is None:
        return nk != pk
    if nk == pk:
        return False
    # Prefer a timestamp comparison when both carry one; otherwise a differing
    # content hash is itself the change signal -> replace.
    nt = new_ev.get("collected_at") or new_ev.get("observed_at")
    pt = prior_ev.get("collected_at") or prior_ev.get("observed_at")
    if nt and pt:
        return str(nt) >= str(pt)
    return True


def _upsert_evidence(existing, incoming):
    """Merge `incoming` third-party evidence into `existing`, returning
    (merged_list, attached_count).

    Preserves EVERY existing entry verbatim, including entries with no
    evidenceLocation (manual/prefill evidence is legitimate and the official SDR
    schema does not require evidenceLocation). Only entries that DO carry an
    evidenceLocation are candidates for location-based upsert: an incoming entry
    replaces an existing one at the same location when it is a newer observation;
    a new location is appended; an incoming entry with no location is appended.
    Existing order is preserved; upserts replace in place."""
    merged = []
    idx_by_loc = {}
    for e in existing:
        loc = e.get("evidenceLocation") if isinstance(e, dict) else None
        merged.append(e)
        if loc:  # only track keyable (located) entries; location-less kept as-is
            idx_by_loc[loc] = len(merged) - 1
    attached = 0
    for ev in incoming:
        loc = ev.get("evidenceLocation") if isinstance(ev, dict) else None
        if not loc:
            merged.append(ev)
            attached += 1
            continue
        if loc in idx_by_loc:
            prior = merged[idx_by_loc[loc]]
            if _is_newer(ev, prior):
                merged[idx_by_loc[loc]] = ev  # replace stale in place
                attached += 1
            # else identical/older: keep existing
        else:
            merged.append(ev)
            idx_by_loc[loc] = len(merged) - 1
            attached += 1
    return merged, attached


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def apply_sources(profile, records, *, base=None, scope_key=None, location_base=None, log=print):
    """Apply every ENABLED evidence source in `profile` to `records` in place.
    Returns (exit_code, total_attached). Reads only the export files the
    profile names (relative to `base`, default the repository root); writes
    nothing. The fictional samples drive this with in-memory profile and
    records, so the evidence they carry comes through the same path a
    provider's run uses (MCE-12)."""
    base = base or BASE
    sources = (profile or {}).get("evidence_sources", {}) or {}
    enabled = [(name, cfg) for name, cfg in sources.items()
               if isinstance(cfg, dict) and cfg.get("enabled")]
    if not enabled:
        log("No third-party evidence sources enabled (evidence_sources all off). "
            "Nothing to do.")
        return 0, 0
    if not location_base:
        # AUD-F80: a pointer with no store base is a placeholder preflight
        # refuses at Class C; say so once rather than attach it silently.
        log(f"NOTE: no evidence-store base URI ({LOCATION_BASE_ENV} / --location-base); "
            "every attached pointer is an sdr://placeholder/ pseudo-URI that package-preflight "
            "refuses at Class C. Set the base to the provider's evidence store.")
    total_attached = 0
    for name, cfg in enabled:
        # Mapping-driven source (MCE-02): a mapping file declares the adapter;
        # registration is refused, naming the problem, when the mapping or its
        # KSI targets are wrong.
        mapping_rel = cfg.get("mapping_path")
        if mapping_rel:
            try:
                adapter = ma.register_mapping_adapter(ma.load_mapping(os.path.join(base, mapping_rel)))
            except (ma.MappingError, ew.EvidenceExportError, OSError, ValueError) as e:
                log(f"'{name}': mapping refused, record store untouched. {e}")
                return 1, total_attached
            if adapter.name != name:
                log(f"'{name}': the mapping at {mapping_rel} declares name {adapter.name!r}; "
                    "the evidence_sources key must match. Record store untouched.")
                return 1, total_attached
        else:
            adapter = ew.get_adapter(name)
        if adapter is None:
            log(f"WARNING: enabled source '{name}' has no registered adapter; skipping.")
            continue
        export_rel = cfg.get("export_path")
        export_path = os.path.join(base, export_rel) if export_rel else None
        if not export_path or not os.path.exists(export_path):
            log(f"'{name}' enabled but export not found at {export_rel}; skipping. "
                "Produce the export in your own environment (no API client here).")
            continue
        if mapping_rel:
            with open(export_path, encoding="utf-8") as f:
                raw = f.read()
        else:
            raw = load(export_path)
        try:
            evidence = adapter.to_evidence(raw, location_base=location_base, scope_key=scope_key)
        except ew.EvidenceExportError as e:
            # Fact contract or scope refusal (MCE-01): nothing is written, the
            # offending field is named, and the exit is non-zero.
            log(f"'{name}': refused, record store untouched. {e}")
            return 1, total_attached
        if mapping_rel and adapter.collection_outcome() == "not-run":
            log(f"'{name}': export at {export_rel} contained no records; collection outcome "
                "not-run. Nothing attached: an empty export is not a clean posture.")
            continue
        if mapping_rel:
            skipped = adapter.health().get("skipped_undeclared") or 0
            if skipped:
                names = adapter.health().get("undeclared_checks") or []
                shown = ", ".join(names[:10]) + (" ..." if len(names) > 10 else "")
                log(f"'{name}': {skipped} record(s) whose check is not declared in the mapping "
                    f"yielded no fact (undeclared_checks: skip): {shown}")
        # MCE-03: an entry is attached ONLY to the KSIs its (service, check)
        # pair is declared for, the same bindings the provenance gate reads. An
        # entry whose pair binds nothing is reported and not attached.
        bindings = adapter.source_bindings()
        per_ksi = {}
        unbound = []
        for ev in evidence:
            sf = ev.get("xSourceFact") or {}
            key = f"{sf.get('service')}:{sf.get('check')}"
            kids = bindings.get(key) or set()
            if not kids:
                unbound.append(key)
                continue
            for kid in sorted(kids):
                per_ksi.setdefault(kid, []).append(ev)
        if unbound:
            log(f"'{name}': {len(unbound)} evidence entr{'y' if len(unbound) == 1 else 'ies'} "
                f"with no declared KSI binding not attached: {', '.join(sorted(set(unbound)))}")
        attached = 0
        for kid, evs in sorted(per_ksi.items()):
            rec = records.get("ksi", {}).get(kid)
            if rec is None:
                continue
            existing = rec.get("evidence", []) or []
            rec["evidence"], n = _upsert_evidence(existing, evs)
            attached += n
        total_attached += attached
        log(f"'{name}': {len(evidence)} evidence entries applied to "
            f"{len(per_ksi)} KSI(s) by declared binding ({attached} attached after de-dup).")
    return 0, total_attached


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Apply the enabled evidence sources to the record store.")
    ap.add_argument("--location-base", default=os.environ.get(LOCATION_BASE_ENV),
                    help="evidence-store base URI for the attached evidence pointers "
                         f"(default: ${LOCATION_BASE_ENV}); without it pointers are "
                         "sdr://placeholder/ pseudo-URIs that preflight refuses (AUD-F80)")
    args = ap.parse_args(argv)
    profile = load(PROFILE)
    if not any(isinstance(cfg, dict) and cfg.get("enabled")
               for cfg in (profile.get("evidence_sources", {}) or {}).values()):
        print("No third-party evidence sources enabled (evidence_sources all off). "
              "Nothing to do.")
        return 0
    if not os.path.exists(RECORDS):
        print("Record store not found; run build_sdr.py once first.")
        return 1
    records = load(RECORDS)
    code, total_attached = apply_sources(
        profile, records, base=BASE, scope_key=os.environ.get(SCOPE_KEY_ENV) or None,
        location_base=args.location_base or None)
    if code != 0:
        return code
    if total_attached:
        with open(RECORDS, "w", encoding="utf-8", newline="\n") as f:
            json.dump(records, f, indent=1)
        print(f"Record store updated: {total_attached} evidence entries attached. "
              "Run build_sdr.py to regenerate the SDR. A human still owns the status.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
