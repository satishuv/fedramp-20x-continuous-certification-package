"""Rule fingerprints: what a review decision was taken AGAINST.

Review finding 8 (2026-11-09): a dataset adoption regenerated requirement text
and opened a PR naming the records to re-examine, but the record store did not
know which dataset version its answers targeted, no review was tied to the rule
text it approved, and preflight never asked for a re-review. An approval could
silently outlive the rule it approved.

Every field-review-log entry now carries ``dataset_version`` and
``rule_sha256``: the version of the pinned dataset and the hash of the resolved
rule or indicator text (statement and force for the active class) at the moment
the decision was taken. ``validate_reviews.py`` recomputes the fingerprint from
the pinned dataset and hard-fails a populated field whose latest decision was
taken against a different one: that field needs re-review. Entries written
before this existed carry no fingerprint and are reported once as advisory, so
an existing provider's log is not bricked by the upgrade.

One definition, every consumer: the review tool, the sample log helper and the
gate all import this module. Nothing here decides compliance.
"""
import hashlib
import json
import os
import re

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
OFFERING = os.path.join(BASE, "profiles", "common", "offering-profile.json")

RULE_RE = re.compile(r"^[A-Z]{3}-[A-Z]{3}-[A-Z]{3}$")
KSI_RE = re.compile(r"^KSI-[A-Z]{3}-[A-Z]{3}$")

_CACHE = {}


def load_dataset(path=None):
    path = path or DATASET
    if path not in _CACHE:
        with open(path, encoding="utf-8") as f:
            _CACHE[path] = json.load(f)
    return _CACHE[path]


def dataset_version(ds=None):
    ds = ds or load_dataset()
    return (ds.get("info") or {}).get("version")


def active_class():
    try:
        with open(OFFERING, encoding="utf-8") as f:
            return (json.load(f).get("certification_class") or "b").lower()
    except (OSError, ValueError):
        return "b"


def _rules(ds):
    out = {}
    for fam in (ds.get("FRR") or {}).values():
        for subsets in (fam.get("data") or {}).values():
            for items in subsets.values():
                for rid, rule in items.items():
                    if isinstance(rule, dict) and RULE_RE.match(rid):
                        out[rid] = rule
    return out


def _ksis(ds):
    out = {}
    for fam in (ds.get("KSI") or {}).values():
        if isinstance(fam, dict):
            for kid, ind in (fam.get("indicators") or {}).items():
                if isinstance(ind, dict) and KSI_RE.match(kid):
                    out[kid] = ind
    return out


def resolved_text(record_id, cls=None, ds=None):
    """(statement, force) of a rule or indicator for ``cls``, or None when the
    identifier does not resolve in the dataset."""
    ds = ds or load_dataset()
    cls = (cls or active_class()).lower()
    node = _rules(ds).get(record_id) if RULE_RE.match(record_id) else _ksis(ds).get(record_id)
    if node is None:
        return None
    vbc = node.get("varies_by_class") or {}
    per = vbc.get(cls) or {}
    statement = per.get("statement") or node.get("statement") or ""
    force = per.get("force") or node.get("force") or ""
    return statement, force


def fingerprint(record_id, cls=None, ds=None):
    """sha256 over the rule's or indicator's requirement text as FedRAMP
    publishes it: the top-level statement and force plus every class variant.
    Deliberately NOT narrowed to one class: a provider that changes its
    certification class has not had a rule changed under it, so the same
    decision stays valid, while any edit FedRAMP makes to the statement or
    force at any class moves the fingerprint. ``cls`` is accepted for call-site
    compatibility and ignored. None when the identifier does not resolve."""
    ds = ds or load_dataset()
    node = _rules(ds).get(record_id) if RULE_RE.match(record_id) else _ksis(ds).get(record_id)
    if node is None:
        return None
    variants = {}
    for c, per in (node.get("varies_by_class") or {}).items():
        if isinstance(per, dict):
            variants[c] = {"statement": per.get("statement"), "force": per.get("force")}
    canon = json.dumps({"id": record_id, "statement": node.get("statement"),
                        "force": node.get("force"), "varies_by_class": variants},
                       sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()


def stamp(record_id, cls=None, ds=None):
    """The two fields a review entry records about the rule it judged."""
    ds = ds or load_dataset()
    return {"dataset_version": dataset_version(ds), "rule_sha256": fingerprint(record_id, cls, ds)}
