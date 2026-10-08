# Dataset-version consistency test for curated data files.
#
# Finding: automation/collectors/pending-ksi-classification.json and
# automation/config-rules/rules-manifest.json hardcoded the OLD dataset version
# 2026.07.14.01 while the canonical pin advanced to 2026.09.13.02. These are
# curated data files (not build-generated), so nothing forced them current.
# This test pins their dataset_version to the canonical pinned dataset so the
# drift is caught in CI instead of read by a human.
#
# AUD-F40 widened the list to EVERY curated pin and moved its definition into
# update_sources_lock.py, the script that advances the pins during an adoption,
# so the test and the updater cannot disagree about which files carry a pin.
# The 2026-10-07 drift run swapped the dataset, left the offering profile's pin
# at the old version, and the build's own consistency check stopped the
# adoption PR; this test now names that file directly. The AWS service-KSI
# map's pin is a verification claim, so the test also re-runs the verification
# (KSI ids, names, families against the dataset) rather than trusting the pin.
#
# The canonical version is the pinned dataset's info.version (the same value
# validate_sdr.py's dataset_version_agreement trusts).
#
# Run: python validation/scripts/test_dataset_version_consistency.py

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import update_sources_lock as usl  # noqa: E402

# Curated data files that declare a dataset_version and must track the pin.
CURATED = [os.path.join(*rel.split("/")) for rel in usl.CURATED_PINS]

_fail = 0


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def _dataset():
    return json.load(open(os.path.join(BASE, "references",
                                       "fedramp-consolidated-rules.json"), encoding="utf-8"))


def canonical_version():
    return _dataset().get("info", {}).get("version")


def _load(path):
    with open(os.path.join(BASE, path), "rb") as f:
        return json.loads(f.read().decode("utf-8-sig"))


def _declared(path):
    return usl.declared_pin(_load(path))


def main():
    ds = _dataset()
    pin = ds.get("info", {}).get("version")
    check("canonical pinned dataset version resolves", bool(pin))
    for rel in CURATED:
        got = _declared(rel)
        check(f"{rel} dataset_version == {pin} (got {got}; run "
              f"validation/scripts/update_sources_lock.py after adopting a dataset)",
              got == pin)
    # The service map's pin claims its KSI set was verified against the dataset.
    # Re-run that verification instead of trusting the claim.
    diffs = usl.service_map_differences(ds, _load(usl.VERIFIED_PIN))
    check(f"{usl.VERIFIED_PIN} KSI ids, names and families match dataset {pin}"
          + (f" ({len(diffs)} difference(s); first: {diffs[0]})" if diffs else ""),
          not diffs)
    print(f"\n{'PASS' if not _fail else 'FAIL'}: dataset-version consistency "
          f"({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
