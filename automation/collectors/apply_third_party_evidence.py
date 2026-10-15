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
organization); without it such facts are refused, never exported raw.
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


def main():
    profile = load(PROFILE)
    sources = profile.get("evidence_sources", {})
    enabled = [(name, cfg) for name, cfg in sources.items()
               if isinstance(cfg, dict) and cfg.get("enabled")]
    if not enabled:
        print("No third-party evidence sources enabled (evidence_sources all off). "
              "Nothing to do.")
        return 0
    if not os.path.exists(RECORDS):
        print("Record store not found; run build_sdr.py once first.")
        return 1
    records = load(RECORDS)
    scope_key = os.environ.get("SDR_EVIDENCE_SCOPE_KEY") or None
    total_attached = 0
    for name, cfg in enabled:
        # Mapping-driven source (MCE-02): a mapping file declares the adapter;
        # registration is refused, naming the problem, when the mapping or its
        # KSI targets are wrong.
        mapping_rel = cfg.get("mapping_path")
        if mapping_rel:
            try:
                adapter = ma.register_mapping_adapter(ma.load_mapping(os.path.join(BASE, mapping_rel)))
            except (ma.MappingError, ew.EvidenceExportError, OSError, ValueError) as e:
                print(f"'{name}': mapping refused, record store untouched. {e}")
                return 1
            if adapter.name != name:
                print(f"'{name}': the mapping at {mapping_rel} declares name {adapter.name!r}; "
                      "the evidence_sources key must match. Record store untouched.")
                return 1
        else:
            adapter = ew.get_adapter(name)
        if adapter is None:
            print(f"WARNING: enabled source '{name}' has no registered adapter; skipping.")
            continue
        export_rel = cfg.get("export_path")
        export_path = os.path.join(BASE, export_rel) if export_rel else None
        if not export_path or not os.path.exists(export_path):
            print(f"'{name}' enabled but export not found at {export_rel}; skipping. "
                  "Produce the export in your own environment (no API client here).")
            continue
        if mapping_rel:
            with open(export_path, encoding="utf-8") as f:
                raw = f.read()
        else:
            raw = load(export_path)
        try:
            evidence = adapter.to_evidence(raw, scope_key=scope_key)
        except ew.EvidenceExportError as e:
            # Fact contract or scope refusal (MCE-01): nothing is written, the
            # offending field is named, and the exit is non-zero.
            print(f"'{name}': refused, record store untouched. {e}")
            return 1
        if mapping_rel and adapter.collection_outcome() == "not-run":
            print(f"'{name}': export at {export_rel} contained no records; collection outcome "
                  "not-run. Nothing attached: an empty export is not a clean posture.")
            continue
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
            print(f"'{name}': {len(unbound)} evidence entr{'y' if len(unbound) == 1 else 'ies'} "
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
        print(f"'{name}': {len(evidence)} evidence entries applied to "
              f"{len(per_ksi)} KSI(s) by declared binding ({attached} attached after de-dup).")
    if total_attached:
        with open(RECORDS, "w", encoding="utf-8", newline="\n") as f:
            json.dump(records, f, indent=1)
        print(f"Record store updated: {total_attached} evidence entries attached. "
              "Run build_sdr.py to regenerate the SDR. A human still owns the status.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
