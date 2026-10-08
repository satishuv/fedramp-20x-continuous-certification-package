#!/usr/bin/env python3
"""Update sources.lock.json from the pinned files CURRENTLY on disk.

Used by the drift-adopt workflow and by any manual adoption of an upstream
change: after a new upstream file is copied into its pinned path, the file and
the old lock hash disagree, and validate_upstream / sources_lock_consistency
(correctly) hard-fail on that mismatch. This regenerates the lock from the files
on disk so the update becomes a coherent, reviewable PR. It does NOT disable the
lock check - it produces the new lock as part of the change. Never hand-edit a
hash; run this instead, and commit the result with the pinned file.

What is refreshed:

  * cr26_consolidated_rules: version (dataset info.version) and sha256, plus
    --upstream-commit provenance when given.
  * cr26_rules_schema: sha256 (and --upstream-commit).
  * Every other entry with a pinned_path: sha256 recomputed from disk, and when
    the pinned file is a JSON schema carrying "$schemaVersion", schema_version
    is set to it (FedRAMP edits schema files in place without renaming, so the
    version inside the file is the only reliable signal).
  * verified_current_on: only when --verified-on is given. That field claims
    the pins were checked against upstream on that date, which this offline
    script cannot know; the caller (the drift workflow, or a human who just
    diffed against upstream) asserts it explicitly.
  * Curated dataset_version pins (AUD-F40): hand-maintained inputs that record
    the dataset they track (offering profile, sample profile, pending-KSI
    classification, Config rules manifest) advance to the dataset's
    info.version with a one-line textual edit, formatting untouched. The AWS
    service-KSI map's pin is a VERIFICATION claim, so it advances only after
    this script re-verifies the map's KSI ids, names and families against the
    new dataset; otherwise it is HELD and reported, and
    test_dataset_version_consistency.py fails until a human re-verifies it.
    Without this, swapping the dataset left the offering pin behind and the
    build's own consistency check stopped the drift workflow before it could
    open its adoption PR (2026-10-07 run).

    python validation/scripts/update_sources_lock.py [--upstream-commit SHA]
                                                      [--verified-on YYYY-MM-DD]
"""

import argparse
import collections
import datetime
import hashlib
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
LOCK = os.path.join(BASE, "references", "sources.lock.json")

# ---- Curated dataset_version pins (AUD-F40) --------------------------------
# Inputs, not build outputs: nothing regenerates them, so an adoption must
# advance them or validate_package_consistency fails deep inside the build on
# "assurance graph dataset NEW != offering OLD". Shared with
# test_dataset_version_consistency.py so the updater and the test cannot drift.
TRACKING_PINS = (
    "profiles/common/offering-profile.json",
    "examples/sample-offering/offering-profile.sample.json",
    "automation/collectors/pending-ksi-classification.json",
    "automation/config-rules/rules-manifest.json",
)
# The service map's provenance says its KSI set was verified against the pinned
# dataset. That pin is only advanced once the verification has been redone.
VERIFIED_PIN = "traceability/aws-service-ksi-map.json"
CURATED_PINS = TRACKING_PINS + (VERIFIED_PIN,)

_PIN_RE = re.compile(r'"dataset_version"\s*:\s*"([^"]*)"')


def declared_pin(doc):
    """The dataset_version a curated document declares (meta first, then top level)."""
    if not isinstance(doc, dict):
        return None
    meta = doc.get("meta")
    if isinstance(meta, dict) and "dataset_version" in meta:
        return meta["dataset_version"]
    return doc.get("dataset_version")


def _rewrite_pin(path, version):
    """Advance the file's dataset_version to `version` by editing exactly that
    value in the raw text (indentation, key order and line endings untouched).
    Proves the edit changed nothing else by comparing parsed documents.
    Returns the previous value."""
    with open(path, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8")
    m = _PIN_RE.search(text)
    if not m:
        raise ValueError(f"{path}: no dataset_version pin to advance")
    old = m.group(1)
    if old == version:
        return old
    new_text = text[:m.start(1)] + version + text[m.end(1):]
    before = json.loads(text.lstrip("\ufeff"))
    after = json.loads(new_text.lstrip("\ufeff"))
    if declared_pin(after) != version:
        raise ValueError(f"{path}: the first dataset_version in the file is not its pin")
    if isinstance(before.get("meta"), dict) and "dataset_version" in before["meta"]:
        before["meta"]["dataset_version"] = version
    else:
        before["dataset_version"] = version
    if before != after:
        raise ValueError(f"{path}: refusing an edit that changes more than the pin")
    with open(path, "wb") as f:
        f.write(new_text.encode("utf-8"))
    return old


def _dataset_ksis(ds):
    """{ksi_id: (name, family, family_name)} from the dataset's KSI section."""
    out = {}
    for fam, node in (ds.get("KSI") or {}).items():
        if not isinstance(node, dict) or not isinstance(node.get("indicators"), dict):
            continue
        for kid, ind in node["indicators"].items():
            out[kid] = ((ind or {}).get("name"), fam, node.get("name"))
    return out


def service_map_differences(ds, smap):
    """Every way the service map's KSI ids, names and families disagree with
    the dataset. Empty means the map's verification claim holds for `ds`."""
    want = _dataset_ksis(ds)
    have = {kid: (e.get("name"), e.get("family"), e.get("family_name"))
            for kid, e in ((smap.get("ksis") or {}).items())}
    diffs = [f"{kid}: in dataset, not in map" for kid in sorted(set(want) - set(have))]
    diffs += [f"{kid}: in map, not in dataset" for kid in sorted(set(have) - set(want))]
    for kid in sorted(set(have) & set(want)):
        if have[kid] != want[kid]:
            diffs.append(f"{kid}: map {have[kid]} != dataset {want[kid]}")
    return diffs


def refresh_dataset_pins(version, ds):
    """Advance every curated dataset_version pin to `version`. Returns
    (changes, holds): `holds` names a pin left behind because its verification
    claim does not hold for `ds`. A curated file absent from the layout (tests,
    trimmed checkouts) is skipped, never invented."""
    changes, holds = [], []
    for rel in TRACKING_PINS:
        path = os.path.join(BASE, rel)
        if not os.path.isfile(path):
            continue
        old = _rewrite_pin(path, version)
        if old != version:
            changes.append(f"{rel} dataset_version {old} -> {version}")
    path = os.path.join(BASE, VERIFIED_PIN)
    if os.path.isfile(path):
        with open(path, "rb") as f:
            smap = json.loads(f.read().decode("utf-8-sig"))
        diffs = service_map_differences(ds, smap)
        if diffs:
            shown = "; ".join(diffs[:5]) + (f"; +{len(diffs) - 5} more" if len(diffs) > 5 else "")
            holds.append(f"{VERIFIED_PIN} dataset_version HELD at {declared_pin(smap)}: "
                         f"its KSI set differs from dataset {version} ({shown}). "
                         "Re-verify the map by hand, then advance its pin.")
        else:
            old = _rewrite_pin(path, version)
            if old != version:
                changes.append(f"{VERIFIED_PIN} dataset_version {old} -> {version} "
                               "(KSI ids, names and families re-verified unchanged)")
    return changes, holds


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _schema_version(path):
    """Return the file's $schemaVersion, or None if it is not a JSON schema."""
    try:
        with open(path, "rb") as f:
            doc = json.loads(f.read().decode("utf-8-sig"))
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    return doc.get("$schemaVersion")


def refresh_lock(lock, upstream_commit=None, verified_on=None):
    """Refresh every pinned entry in `lock` in place; return a change summary."""
    changes = []
    sources = lock["sources"]

    ds = json.load(open(DATASET, encoding="utf-8"))
    version = ds.get("info", {}).get("version")
    entry = sources["cr26_consolidated_rules"]
    if entry.get("version") != version:
        changes.append(f"cr26_consolidated_rules version {entry.get('version')} -> {version}")
    entry["version"] = version
    digest = _sha256(DATASET)
    if entry.get("sha256") != digest:
        changes.append(f"cr26_consolidated_rules sha256 -> {digest[:12]}")
    entry["sha256"] = digest
    if upstream_commit:
        entry["upstream_commit"] = upstream_commit

    # Also refresh the rules-schema lock entry so a dataset+schema adoption is
    # atomic and validate_upstream's schema-hash check passes on the new pair.
    schema_path = os.path.join(BASE, "references", "fedramp-consolidated-rules.schema.json")
    if os.path.isfile(schema_path) and "cr26_rules_schema" in sources:
        sc = sources["cr26_rules_schema"]
        sc_digest = _sha256(schema_path)
        if sc.get("sha256") != sc_digest:
            changes.append(f"cr26_rules_schema sha256 -> {sc_digest[:12]}")
        sc["sha256"] = sc_digest
        if upstream_commit:
            sc["upstream_commit"] = upstream_commit

    # Every other pinned entry: hash from disk, schema_version from the file.
    for key, ent in sources.items():
        if key in ("cr26_consolidated_rules", "cr26_rules_schema"):
            continue
        rel = ent.get("pinned_path")
        if not rel:
            continue
        path = os.path.join(BASE, rel)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"{key}: pinned_path {rel} is missing on disk")
        digest = _sha256(path)
        if ent.get("sha256") != digest:
            changes.append(f"{key} sha256 -> {digest[:12]}")
        ent["sha256"] = digest
        sv = _schema_version(path)
        if sv is not None and "schema_version" in ent and ent["schema_version"] != sv:
            changes.append(f"{key} schema_version {ent['schema_version']} -> {sv}")
            ent["schema_version"] = sv

    if verified_on:
        datetime.date.fromisoformat(verified_on)  # reject a malformed date
        if lock.get("verified_current_on") != verified_on:
            changes.append(f"verified_current_on -> {verified_on}")
        lock["verified_current_on"] = verified_on
    return changes


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--upstream-commit")
    ap.add_argument("--verified-on", metavar="YYYY-MM-DD",
                    help="date the pins were verified current against upstream")
    args = ap.parse_args(argv)

    lock = json.load(open(LOCK, encoding="utf-8"), object_pairs_hook=collections.OrderedDict)
    changes = refresh_lock(lock, args.upstream_commit, args.verified_on)
    with open(LOCK, "w", encoding="utf-8", newline="\n") as f:
        json.dump(lock, f, indent=1)
    if changes:
        print("sources.lock updated:")
        for c in changes:
            print(f"  {c}")
    else:
        print("sources.lock already matches every pinned file on disk (no change)")
    # AUD-F40: the curated pins advance with the dataset in the same adoption.
    ds = json.load(open(DATASET, encoding="utf-8"))
    version = ds.get("info", {}).get("version")
    pin_changes, holds = refresh_dataset_pins(version, ds)
    for c in pin_changes:
        print(f"  {c}")
    for h in holds:
        print(f"HOLD: {h}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
