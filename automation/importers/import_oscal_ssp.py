#!/usr/bin/env python3
"""Import an existing Rev5 System Security Plan (OSCAL JSON) as KSI observations.

A provider moving from Rev5 to 20x already holds assessed narrative for every
NIST SP 800-53 control: the implementation descriptions in its OSCAL SSP. The
CR26 dataset lists, for each Key Security Indicator, the 800-53 controls it
draws on (`KSI.<family>.indicators.<id>.controls`, OSCAL ids such as `ac-2.2`).
This module joins the two, so each KSI's proposal in `sdr.py review` quotes
the provider's own Rev5 text for exactly the controls FedRAMP ties to that
indicator, instead of a paraphrase of the official guidance.

Input: one OSCAL System Security Plan in JSON (root key `system-security-plan`;
field names per NIST OSCAL v1.1.x: control-implementation.implemented-
requirements[].control-id, statements[].statement-id, by-components[].
description, implementation-status.state, system-implementation.components[]).
FedRAMP's `implementation-status` prop on an implemented requirement is read as
informational text only.

Mapping as data. The join key is the dataset's own control list, read from
the pinned dataset at import time; nothing here invents a control-to-KSI
relationship. An SSP control that no KSI lists is reported, not mapped.

Boundary, identical to the collectors':
  - The SSP's implementation-status NEVER becomes a 20x implementation_status.
    It is quoted as text ("Rev5 SSP declares: implemented") for the reviewer;
    the 20x status is a human decision in the review register.
  - Nothing here writes the record store. It writes KSI observations into a
    facts file; the drafter turns them into labelled DRAFT proposals; a named
    human accepts, edits or rejects each one.
  - Narrative only. No party names, no addresses, no system ids, no inventory
    are carried over; component titles are kept (they are the provider's own
    architecture vocabulary and the reviewer needs them to read the text).
  - The observation time is the SSP's own metadata.last-modified (or
    --observed-at); the importer will not stamp a document of unknown age.

Usage:
  python automation/importers/import_oscal_ssp.py path/to/ssp.json
  python automation/importers/import_oscal_ssp.py path/to/ssp.json --write
Exit codes: 0 ok, 1 refused input, 2 no observation time, 4 no control mapped.
"""
import argparse
import hashlib
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FACTS_DIR = os.path.join(BASE, "automation", "facts")
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from import_findings import RefusedInput, iso, load_json, parse_ts, sha256_file  # noqa: E402

EXIT_NOTHING_MAPPED = 4
SOURCE = "rev5-oscal-ssp"
# One by-component description is quoted up to this many characters; the
# reviewer edits from here, the full SSP stays the provider's reference.
MAX_TEXT = 700
MAX_TEXTS_PER_KSI = 6

_CONTROL_ID = re.compile(r"^[a-z]{2}-\d+(\.\d+)?$")


def normalize_control_id(value):
    """OSCAL control ids are lowercase tokens: ac-2, ac-2.2. Tolerate the
    human forms AC-2, AC-02, AC-2(2), AC-02(02) found in exported SSPs."""
    s = str(value or "").strip().lower()
    m = re.match(r"^([a-z]{2})-0*(\d+)(?:[.(]0*(\d+)\)?)?$", s)
    if not m:
        return None
    fam, num, enh = m.groups()
    return f"{fam}-{int(num)}" + (f".{int(enh)}" if enh else "")


def ksi_controls(dataset_path=DATASET):
    """{ksi id: [control ids]} from the pinned dataset, every family."""
    ds = load_json(dataset_path)
    out = {}
    for family in (ds.get("KSI") or {}).values():
        for kid, entry in (family.get("indicators") or {}).items():
            controls = []
            for c in entry.get("controls") or []:
                n = normalize_control_id(c)
                if n:
                    controls.append(n)
            out[kid] = controls
    if not out:
        raise RefusedInput(f"{dataset_path}: no KSI indicators found")
    return out


def controls_to_ksis(mapping):
    rev = {}
    for kid, controls in mapping.items():
        for c in controls:
            rev.setdefault(c, []).append(kid)
    return {c: sorted(k) for c, k in rev.items()}


def load_ssp(path):
    doc = load_json(path)
    ssp = doc.get("system-security-plan") if isinstance(doc, dict) else None
    if not isinstance(ssp, dict):
        raise RefusedInput(f"{path}: not an OSCAL SSP (no top-level 'system-security-plan')")
    if not isinstance((ssp.get("control-implementation") or {}).get("implemented-requirements"), list):
        raise RefusedInput(f"{path}: SSP has no control-implementation.implemented-requirements")
    return ssp


def _plain(markup):
    """markup-multiline is Markdown-ish text; collapse whitespace, keep words."""
    s = re.sub(r"\s+", " ", str(markup or "")).strip()
    return s


def _status_text(obj):
    """OSCAL implementation-status.state, else a FedRAMP-style prop."""
    st = (obj.get("implementation-status") or {}).get("state")
    if st:
        return str(st)
    for p in obj.get("props") or []:
        if isinstance(p, dict) and p.get("name") == "implementation-status" and p.get("value"):
            return str(p["value"])
    return None


def component_titles(ssp):
    out = {}
    for c in (ssp.get("system-implementation") or {}).get("components") or []:
        if isinstance(c, dict) and c.get("uuid"):
            out[c["uuid"]] = _plain(c.get("title")) or "component"
    return out


def extract_control_texts(ssp):
    """{control id: {"status": str|None, "texts": [{"where", "component", "text"}]}}
    from every implemented requirement, its requirement-level by-components
    and its statement-level by-components. Empty descriptions are skipped."""
    titles = component_titles(ssp)
    out = {}
    skipped = []
    for req in ssp["control-implementation"]["implemented-requirements"]:
        if not isinstance(req, dict):
            continue
        cid = normalize_control_id(req.get("control-id"))
        if not cid:
            skipped.append(str(req.get("control-id")))
            continue
        entry = out.setdefault(cid, {"status": None, "texts": []})
        entry["status"] = entry["status"] or _status_text(req)
        for bc in req.get("by-components") or []:
            text = _plain(bc.get("description")) if isinstance(bc, dict) else ""
            if text:
                entry["texts"].append({
                    "where": cid, "component": titles.get(bc.get("component-uuid"), "component"),
                    "text": text, "status": _status_text(bc)})
        for st in req.get("statements") or []:
            if not isinstance(st, dict):
                continue
            where = str(st.get("statement-id") or cid)
            for bc in st.get("by-components") or []:
                text = _plain(bc.get("description")) if isinstance(bc, dict) else ""
                if text:
                    entry["texts"].append({
                        "where": where, "component": titles.get(bc.get("component-uuid"), "component"),
                        "text": text, "status": _status_text(bc)})
    return out, skipped


def _clip(s, n):
    s = (s or "").strip()
    return s if len(s) <= n else s[:s.rfind(" ", 0, n)].rstrip() + "..."


def build_ksi_observations(control_texts, mapping, observed_iso):
    """{ksi id: [observation]} where each observation quotes one SSP
    by-component description for a control the dataset ties to that KSI.
    Returns (observations, coverage, unmapped): coverage per KSI counts the
    controls the dataset lists, the SSP implements, and those with text;
    unmapped lists SSP controls no KSI references (reported, never mapped)."""
    by_control = controls_to_ksis(mapping)
    obs = {}
    coverage = {}
    for kid, controls in mapping.items():
        implemented = [c for c in controls if c in control_texts]
        with_text = [c for c in implemented if control_texts[c]["texts"]]
        coverage[kid] = {"dataset_controls": len(controls),
                         "ssp_implemented": len(implemented),
                         "ssp_with_text": len(with_text),
                         "missing_from_ssp": [c for c in controls if c not in control_texts]}
        texts = []
        for c in with_text:
            declared = control_texts[c]["status"]
            for t in control_texts[c]["texts"]:
                texts.append({
                    "observed_at": observed_iso, "source": SOURCE, "control": c,
                    "statement": t["where"], "component": t["component"],
                    "declared_status": t["status"] or declared,
                    "text": (f"{c} ({t['where']}; {t['component']}"
                             + (f"; Rev5 SSP declares: {t['status'] or declared}"
                                if (t["status"] or declared) else "")
                             + f"): {_clip(t['text'], MAX_TEXT)}"),
                })
        if texts:
            obs[kid] = texts
    # Controls the SSP implements that no KSI lists: reported, never mapped.
    unmapped = sorted(c for c in control_texts if c not in by_control)
    return obs, coverage, unmapped


def build_store(ssp_path, observed_at=None, dataset_path=DATASET):
    ssp = load_ssp(ssp_path)
    meta = ssp.get("metadata") or {}
    explicit = parse_ts(observed_at) if observed_at else None
    if observed_at and explicit is None:
        raise RefusedInput(f"--observed-at {observed_at!r} is not an ISO-8601 time")
    observed = explicit or parse_ts(meta.get("last-modified"))
    if observed is None:
        return None
    observed_iso = iso(observed)
    mapping = ksi_controls(dataset_path)
    control_texts, skipped_ids = extract_control_texts(ssp)
    observations, coverage, unmapped = build_ksi_observations(control_texts, mapping, observed_iso)
    digest = sha256_file(ssp_path)
    return {
        "meta": {
            "collected_at": observed_iso,
            "run_id": "import-ssp-" + digest[:16],
            "region": "global",
            "identity_arn": None,
            "source": SOURCE,
            "import_files": [{"name": os.path.basename(ssp_path), "sha256": digest,
                              "kind": "oscal-ssp"}],
            "observed_at_source": "explicit" if explicit else "ssp-last-modified",
            "ssp": {"title": _plain(meta.get("title")) or None,
                    "version": meta.get("version"),
                    "oscal_version": meta.get("oscal-version"),
                    "system_name": _plain((ssp.get("system-characteristics") or {}).get("system-name")) or None,
                    "implemented_requirements": len(control_texts),
                    "unparseable_control_ids": skipped_ids},
            "ksi_coverage": coverage,
            "unmapped_controls": unmapped,
            "collection_outcome": {"evaluated": 0, "unevaluated": 0, "errors": 0,
                                   "status": "NARRATIVE_ONLY"},
            "note": ("KSI observations imported from the provider's Rev5 OSCAL SSP; "
                     "narrative to review, never a status. Never commit this file."),
        },
        "facts": [],
        "posture_facts": [],
        "ksi_observations": observations,
    }


def out_path(facts_dir):
    return os.path.join(facts_dir, "facts-rev5-ssp-import.json")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Import a Rev5 OSCAL SSP as KSI narrative observations (offline).")
    ap.add_argument("ssp", help="OSCAL System Security Plan JSON file")
    ap.add_argument("--observed-at", default=None,
                    help="ISO-8601 time to stamp when the SSP carries no metadata.last-modified")
    ap.add_argument("--write", action="store_true",
                    help="write automation/facts/facts-rev5-ssp-import.json")
    ap.add_argument("--out-dir", default=FACTS_DIR, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    try:
        store = build_store(args.ssp, args.observed_at)
    except RefusedInput as e:
        print(f"Import refused: {e}")
        return 1
    if store is None:
        print("The SSP carries no metadata.last-modified. Pass --observed-at <ISO-8601> for "
              "its date; the importer will not stamp a document of unknown age.")
        return 2
    m = store["meta"]
    obs = store["ksi_observations"]
    print(f"SSP: {m['ssp']['title'] or '(untitled)'} version {m['ssp']['version']} "
          f"(OSCAL {m['ssp']['oscal_version']}); system {m['ssp']['system_name'] or '(unnamed)'}")
    print(f"observed at {m['collected_at']} ({m['observed_at_source']})")
    print(f"{m['ssp']['implemented_requirements']} implemented requirement(s) read; "
          f"{len(obs)} of {len(m['ksi_coverage'])} KSIs receive SSP narrative")
    for kid in sorted(m["ksi_coverage"]):
        c = m["ksi_coverage"][kid]
        if c["ssp_with_text"]:
            print(f"  {kid}: {c['ssp_with_text']} of {c['dataset_controls']} dataset "
                  f"control(s) carry SSP text ({len(obs.get(kid, []))} statement(s))")
    gaps = {k: c for k, c in m["ksi_coverage"].items() if c["missing_from_ssp"]}
    if gaps:
        print(f"{len(gaps)} KSI(s) list controls the SSP does not implement (shown for the "
              "first five):")
        for kid in sorted(gaps)[:5]:
            print(f"  {kid}: {', '.join(gaps[kid]['missing_from_ssp'])}")
    if m["unmapped_controls"]:
        print(f"{len(m['unmapped_controls'])} SSP control(s) that no KSI lists (left as is): "
              + ", ".join(m["unmapped_controls"][:12])
              + (" ..." if len(m["unmapped_controls"]) > 12 else ""))
    if m["ssp"]["unparseable_control_ids"]:
        print(f"unparseable control ids skipped: {m['ssp']['unparseable_control_ids']}")
    if args.write:
        os.makedirs(args.out_dir, exist_ok=True)
        path = out_path(args.out_dir)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(store, fh, indent=1)
        print(f"wrote {os.path.relpath(path, BASE)} (git-excluded). Next: "
              "python automation/ai/draft_narratives.py --write --scope ksi, then "
              "python sdr.py review --walk.")
    else:
        print("dry run; pass --write to store these observations.")
    if not obs:
        print("FAIL. No SSP control maps to any KSI with text. Nothing to propose.")
        return EXIT_NOTHING_MAPPED
    return 0


if __name__ == "__main__":
    sys.exit(main())
