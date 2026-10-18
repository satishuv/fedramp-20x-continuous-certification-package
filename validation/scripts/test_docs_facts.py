# Offline test: the facts the documentation states about the pinned dataset and
# the reproducibility gate MUST equal what is on disk (finding F86).
#
# The dataset advanced to 2026.10.13.01 on 2026-10-13 (PR #241) and the README
# badge, the README pin sentence, docs/automation.md and docs/comparison.md kept
# advertising the previous release. validate_sdr.py's dataset_version_agreement
# check compares the dataset against the PROFILES only, although its comment
# promised the README and badge were covered; nothing read the prose. In the same
# way, three docs still called Word files the byte-determinism exception after
# AUD-F35 made .docx byte-reproducible and CI began hashing it in the double
# build. A repository whose product is auditable truth cannot carry hand-synced
# truth in four documents: this test derives every fact from the authoritative
# file and fails on any document that disagrees.
#
# Scope, deliberately narrow: only sentences that CLAIM a current pin are checked
# ("Pinned to `X`", "pinned CR26 dataset `X`", "dataset at version `X`",
# "verified against the pinned CR26 dataset `X`"). Historical references (release
# tag examples such as v1.4.0-cr26-2026.09.13.02, changelog entries) are not pin
# claims and stay untouched.
#
# Run: python validation/scripts/test_docs_facts.py

import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
README = os.path.join(BASE, "README.md")
DOCS_DIR = os.path.join(BASE, "docs")

_fail = 0


def check(name, cond, detail=""):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}" + (f": {detail}" if detail else ""))


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def dataset_facts():
    """Derive the headline facts from the dataset by its real nesting:
    FRR > process > data > applicability (all, 20x, rev5) > subset > id;
    KSI > family > indicators > id."""
    with open(DATASET, encoding="utf-8") as fh:
        ds = json.load(fh)
    version = ds["info"]["version"]
    total = in_scope = rev5_only = 0
    for pdata in ds.get("FRR", {}).values():
        data = pdata.get("data", {}) if isinstance(pdata, dict) else {}
        for app, subsets in data.items():
            if not isinstance(subsets, dict):
                continue
            for rules in subsets.values():
                if not isinstance(rules, dict):
                    continue
                for rule in rules.values():
                    if not isinstance(rule, dict):
                        continue
                    if "statement" not in rule and "varies_by_class" not in rule:
                        continue
                    total += 1
                    if app in ("all", "20x"):
                        in_scope += 1
                    elif app == "rev5":
                        rev5_only += 1
    families = 0
    indicators = 0
    for fdata in ds.get("KSI", {}).values():
        if not isinstance(fdata, dict):
            continue
        inds = fdata.get("indicators", {})
        if isinstance(inds, dict) and inds:
            families += 1
            indicators += len(inds)
    return {
        "version": version,
        "total": total,
        "in_scope": in_scope,
        "rev5_only": rev5_only,
        "families": families,
        "indicators": indicators,
    }


# A sentence claims a CURRENT pin when it uses one of these forms around a
# version string. Each pattern captures the version it names.
_VERSION = r"(\d{4}\.\d{2}\.\d{2}\.\d{2})"
PIN_CLAIM_PATTERNS = [
    re.compile(r"[Pp]inned to (?:the )?(?:CR26 )?(?:dataset )?(?:`|<code>)?" + _VERSION),
    re.compile(r"[Pp]inned CR26 dataset (?:`|<code>)?" + _VERSION),
    re.compile(r"CR26 dataset at version (?:`|<code>)?" + _VERSION),
    re.compile(r"CR26%20dataset-" + _VERSION),  # the shields.io badge
]

# A document may not describe Word output as the byte-determinism exception:
# the .docx has been byte-reproducible since AUD-F35 and is hashed in CI.
STALE_DOCX_PHRASES = [
    "Word files are the exception",
    "Word files are the documented exception",
    "cannot be byte-stable",
]


def main():
    facts = dataset_facts()
    v = facts["version"]
    print(f"dataset on disk: {v}; FRR {facts['in_scope']} of {facts['total']} in 20x scope, "
          f"{facts['rev5_only']} rev5-only; KSI {facts['indicators']} in "
          f"{facts['families']} families")

    check("dataset derivation is non-empty (a zero here means the walk is wrong, not the docs)",
          facts["total"] > 0 and facts["indicators"] > 0 and facts["families"] > 0)

    docs = {"README.md": read(README)}
    for name in sorted(os.listdir(DOCS_DIR)):
        if name.endswith(".md"):
            docs[os.path.join("docs", name)] = read(os.path.join(DOCS_DIR, name))

    # 1. Every current-pin claim names the version on disk.
    claims = 0
    for rel, text in docs.items():
        for pat in PIN_CLAIM_PATTERNS:
            for m in pat.finditer(text):
                claims += 1
                line = text.count("\n", 0, m.start()) + 1
                check(f"{rel}:{line} pin claim names the dataset on disk",
                      m.group(1) == v, f"says {m.group(1)}, dataset is {v}")
    check("at least one pin claim exists (README badge and pin sentence)", claims >= 2,
          f"found {claims}")

    # 2. The README's derived counts equal the dataset-derived counts.
    readme = docs["README.md"]
    m = re.search(r"(\d+) rules in 20x scope out of (\d+) total entries, the remaining (\d+) "
                  r"being rev5-only, plus (\d+) Key Security Indicators across (\d+) families",
                  readme)
    check("README states the derived-counts sentence", m is not None)
    if m:
        got = tuple(int(x) for x in m.groups())
        want = (facts["in_scope"], facts["total"], facts["rev5_only"],
                facts["indicators"], facts["families"])
        check("README counts equal the dataset-derived counts", got == want,
              f"README {got} vs dataset {want}")

    # 3. No document still calls Word output the determinism exception.
    for rel, text in docs.items():
        for phrase in STALE_DOCX_PHRASES:
            idx = text.find(phrase)
            check(f"{rel} does not say '{phrase}'", idx < 0,
                  f"line {text.count(chr(10), 0, idx) + 1}" if idx >= 0 else "")

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: docs_facts ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
