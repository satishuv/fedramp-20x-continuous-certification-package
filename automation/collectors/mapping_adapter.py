#!/usr/bin/env python3
"""Declarative evidence adapter: a provider adds a source by writing a mapping
file, not Python (MCE-02).

A mapping file (schema: adapter-mapping.schema.json, beside this module) says
where in a customer-produced EXPORT the check id, the source's status, the
observation time and the location live, how the source's status vocabulary
normalizes to PASS / FAIL / UNKNOWN, and which KSIs the facts support. From it
this module builds an EvidenceAdapter that:

  - is OFFLINE by construction: it reads a file the customer already exported
    from their own environment. There is no client, no credential, no socket;
    a test proves no socket is opened.
  - yields facts that meet the published fact contract
    (fact-contract.schema.json), checked by EvidenceAdapter.to_evidence before
    any conversion, so a record with no observation time is refused, never
    given an invented timestamp.
  - normalizes status FAIL-CLOSED: a source value with no entry in the
    normalization table becomes UNKNOWN. Never PASS. The source's raw state is
    kept in `detail` so a reader sees what the source actually said.
  - registers only when every KSI target exists in the pinned KSI profile;
    an unknown id refuses registration naming the id.
  - reports an EMPTY export as a collection outcome of not-run, so an export
    with no records is never read as a clean posture.
  - never decides a status. A fact is telemetry; validators evaluate; humans
    assess. The raw scope identifier of a record (account, tenant,
    subscription, compartment, project, organization) rides on the fact under
    its declared kind, so the fact contract's raw-scope rule applies to it.

Check identifiers that are not slug-safe (paths, GUIDs with braces, spaces) are
made slug-safe deterministically, with a short digest of the original appended
so two different identifiers never collapse onto one check.

export_format "xccdf" (MCE-07) reads an XCCDF 1.1/1.2 results document or an
ARF result data stream through xccdf_reader.py: one record per rule-result,
the rule id as the check, the standard's result vocabulary normalized by the
standard's own semantics (only `pass` is PASS, only `fail` is FAIL; a mapping
table that relabels a standard value is refused), and the scan target carried
only as a raw `host` scope so it is replaced by an opaque scope before export.
A benchmark scan reports every rule in the benchmark, so such a mapping sets
undeclared_checks to "skip": rule-results the provider has not bound yield no
fact and are counted in health(), never exported unbound and never silent.

Run the tests:
    python automation/collectors/test_mapping_adapter.py
    python automation/collectors/test_xccdf_adapter.py
"""

import csv
import hashlib
import io
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence_wiring as ew  # noqa: E402
import xccdf_reader  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
MAPPING_SCHEMA_PATH = os.path.join(HERE, "adapter-mapping.schema.json")
KSI_PROFILE_PATH = os.path.join(HERE, "..", "..", "profiles", "common", "ksi-profile.json")

NORMALIZED = ("PASS", "FAIL", "UNKNOWN")
UNMAPPED_STATUS = "UNKNOWN"

_SLUG_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SLUG_BAD_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


class MappingError(ValueError):
    """A mapping file that cannot be turned into an adapter is refused, loudly,
    naming what is wrong. Nothing is registered."""


# --- mapping validation -------------------------------------------------------

_SCHEMA = None


def mapping_schema():
    global _SCHEMA
    if _SCHEMA is None:
        with open(MAPPING_SCHEMA_PATH, encoding="utf-8") as f:
            _SCHEMA = json.load(f)
    return _SCHEMA


def validate_mapping(mapping):
    """Problems with a mapping dict against adapter-mapping.schema.json, each
    naming the offending field. [] means valid. Pure."""
    if not isinstance(mapping, dict):
        return ["mapping is not an object"]
    import jsonschema  # a hard requirement of the repository
    problems = []
    validator = jsonschema.Draft202012Validator(mapping_schema())
    for err in sorted(validator.iter_errors(mapping), key=lambda e: list(e.absolute_path)):
        where = "/".join(str(p) for p in err.absolute_path) or "(mapping)"
        problems.append(f"field '{where}': {err.message}")
    if not problems and mapping.get("export_format") == "xccdf":
        # MCE-07 AC2: the XCCDF result vocabulary is the standard's, not the
        # provider's. notchecked / error / fixed can never be relabelled PASS.
        for p in xccdf_reader.normalization_disagreements(mapping.get("status_normalization")):
            problems.append(f"field 'status_normalization/{p}")
    return problems


def load_ksi_ids(ksi_profile_path=None):
    """The pinned KSI ids (profiles/common/ksi-profile.json). The profile is the
    one KSI catalog the package layer uses; targets are checked against it, not
    against a shape rule."""
    path = ksi_profile_path or KSI_PROFILE_PATH
    with open(path, encoding="utf-8") as f:
        prof = json.load(f)
    return frozenset(i["ksi_id"] for i in prof.get("indicators", []) if isinstance(i, dict))


# --- record access --------------------------------------------------------------

def get_path(record, path):
    """Resolve a dotted path (JSON) or a column name (CSV row) in a record.
    Returns None when any segment is missing. List elements by index."""
    if record is None:
        return None
    if isinstance(record, dict) and path in record:
        return record[path]
    cur = record
    for seg in str(path).split("."):
        if isinstance(cur, dict):
            if seg not in cur:
                return None
            cur = cur[seg]
        elif isinstance(cur, list):
            if not seg.isdigit() or int(seg) >= len(cur):
                return None
            cur = cur[int(seg)]
        else:
            return None
    return cur


def read_export(text, export_format, records_path=None):
    """Parse an export's TEXT into a list of record dicts. Pure: no file or
    network access here (the caller reads the file). Raises MappingError on a
    document that does not have the declared shape."""
    if export_format == "jsonl":
        records = []
        for n, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except ValueError as e:
                raise MappingError(f"jsonl line {n} is not valid JSON: {e}")
            if not isinstance(obj, dict):
                raise MappingError(f"jsonl line {n} is not a JSON object")
            records.append(obj)
        return records
    if export_format == "csv":
        reader = csv.DictReader(io.StringIO(text))
        return [dict(row) for row in reader]
    if export_format == "json":
        try:
            doc = json.loads(text) if text.strip() else []
        except ValueError as e:
            raise MappingError(f"json export is not valid JSON: {e}")
        if isinstance(doc, dict):
            if not records_path:
                raise MappingError("json export is an object but the mapping names no records_path")
            doc = get_path(doc, records_path)
            if doc is None:
                raise MappingError(f"records_path {records_path!r} not found in the json export")
        if not isinstance(doc, list):
            raise MappingError("json export records are not an array")
        bad = [i for i, r in enumerate(doc) if not isinstance(r, dict)]
        if bad:
            raise MappingError(f"json export record(s) {bad[:5]} are not objects")
        return doc
    if export_format == "xccdf":
        try:
            return xccdf_reader.read_xccdf_results(text)
        except xccdf_reader.XccdfReadError as e:
            raise MappingError(str(e))
    raise MappingError(f"unsupported export_format {export_format!r}")


def slug_for(value):
    """Deterministic slug-safe form of an identifier. An already-safe value is
    returned as is; otherwise unsafe characters become '-', the result is
    bounded, and an 8-hex digest of the ORIGINAL is appended so distinct
    identifiers never collapse. Returns None for an empty identifier."""
    s = str(value).strip() if value is not None else ""
    if not s:
        return None
    if _SLUG_OK.match(s) and ".." not in s:
        return s
    digest = hashlib.sha256(s.encode("utf-8")).hexdigest()[:8]
    core = _SLUG_BAD_CHARS.sub("-", s).replace("..", "-").strip("-._")
    core = core[:48] if core else "id"
    if not core[0].isalnum():
        core = "x" + core
    return f"{core}-{digest}"


def normalize_status(value, table):
    """PASS / FAIL / UNKNOWN for a source status value via the mapping's table:
    exact match first, then case-insensitive. No entry -> UNKNOWN. Never PASS
    for an unmapped value (MCE-02 AC3)."""
    if value is None:
        return UNMAPPED_STATUS
    s = str(value).strip()
    if s in table:
        return table[s]
    lowered = {str(k).strip().lower(): v for k, v in table.items()}
    return lowered.get(s.lower(), UNMAPPED_STATUS)


# --- the adapter ------------------------------------------------------------------

class MappingAdapter(ew.EvidenceAdapter):
    """An EvidenceAdapter built from a validated mapping dict. `raw` passed to
    collect() / to_evidence() is the export's TEXT (str) or an already-parsed
    list of record dicts; the caller reads the file so this class never touches
    the filesystem or the network."""

    def __init__(self, mapping):
        problems = validate_mapping(mapping)
        if problems:
            raise MappingError("mapping refused: " + "; ".join(problems))
        self.mapping = mapping
        self.name = mapping["name"]
        self.service = mapping["service"]
        self.version = mapping.get("version", "1.0.0")
        self.source_type = mapping.get("source_type", "generic")
        self.evidence_type = mapping.get("evidence_type", "Report")
        self.supported_evidence_types = [self.evidence_type]
        self.freshness_policy_days = int(mapping.get("freshness_policy_days", 1))
        self._fields = mapping["fields"]
        self._table = dict(mapping["status_normalization"])
        if mapping["export_format"] == "xccdf":
            # The provider's table has been checked to agree with the standard
            # (validate_mapping); the standard's full table is what applies, so
            # a value the provider omitted (e.g. `fail`) is never left to the
            # generic unmapped -> UNKNOWN rule, which would hide a failure.
            self._table = xccdf_reader.canonical_normalization()
        self._undeclared = mapping.get("undeclared_checks", "refuse")
        self._targets = list(mapping["ksi_targets"])
        # MCE-03: declared check vocabulary, kept in the slug form facts carry,
        # and the per-check KSI bindings (check_bindings narrows ksi_targets).
        self._raw_checks = list(mapping["checks"])
        self.checks = tuple(slug_for(c) for c in self._raw_checks)
        self._bindings = {}
        for raw_check in self._raw_checks:
            slug = slug_for(raw_check)
            narrowed = (mapping.get("check_bindings") or {}).get(raw_check)
            self._bindings[f"{self.service}:{slug}"] = set(narrowed if narrowed else self._targets)
        self._last = {"status": "not-run", "records": 0, "facts": 0,
                      "skipped_undeclared": 0, "undeclared_checks": [],
                      "last_error": None, "last_success": None}

    # contract v2 metadata
    def ksi_targets(self):
        return list(self._targets)

    def source_bindings(self):
        """{'service:check': set(ksi_ids)}: exactly the declared pairs."""
        return {k: set(v) for k, v in self._bindings.items()}

    def describe(self):
        d = super().describe()
        d["export_format"] = self.mapping["export_format"]
        d["undeclared_checks"] = self._undeclared
        d["ksi_targets"] = self.ksi_targets()
        d["checks"] = list(self.checks)
        d["source_bindings"] = {k: sorted(v) for k, v in sorted(self._bindings.items())}
        d["documentation"] = self.mapping.get("documentation")
        return d

    def health(self):
        h = super().health()
        h.update({k: v for k, v in self._last.items() if k != "facts"})
        h["facts_yielded"] = self._last["facts"]
        return h

    # collection
    def records(self, raw):
        if isinstance(raw, list):
            return raw
        if isinstance(raw, (str, bytes)):
            text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
            return read_export(text, self.mapping["export_format"],
                               self.mapping.get("records_path"))
        raise MappingError(f"adapter {self.name!r}: raw must be export text or a list of records")

    def fact_for(self, index, rec):
        f = self._fields
        check = slug_for(get_path(rec, f["check"]))
        if check is None:
            raise ew.EvidenceExportError(
                f"adapter {self.name!r}: record {index} has no value at check path "
                f"{f['check']!r}; refusing to export a check named 'unknown'")
        raw_status = get_path(rec, f["status"])
        status = normalize_status(raw_status, self._table)
        observed = get_path(rec, f["observed_at"])
        if observed in (None, ""):
            observed_at = None  # refused by the fact contract: never invented here
        else:
            observed_at = observed if isinstance(observed, str) else str(observed)
        location = get_path(rec, f["location"]) if f.get("location") else None
        region = slug_for(location) if location not in (None, "") else "global"
        summary = get_path(rec, f["detail"]) if f.get("detail") else None
        source_state = "" if raw_status is None else str(raw_status).strip()
        detail = f"source state: {source_state or '(none)'}"
        if summary not in (None, ""):
            detail = f"{detail}. {summary}"
        fact = {
            "service": self.service,
            "check": check,
            "status": status,
            "detail": detail,
            "region": region,
            "observed_at": observed_at,
        }
        scope_spec = f.get("scope")
        if scope_spec:
            raw_scope = get_path(rec, scope_spec["path"])
            if raw_scope not in (None, ""):
                fact[scope_spec["kind"]] = raw_scope
        return fact

    def collect(self, raw):
        records = self.records(raw)
        self._last.update({"records": len(records), "facts": 0, "skipped_undeclared": 0,
                           "undeclared_checks": [], "last_error": None})
        if not records:
            # AC4: an empty export is a collection that did not run, not a clean
            # posture. No facts, and health says so.
            self._last.update({"status": "not-run",
                               "last_error": "export contained no records"})
            return
        facts = [self.fact_for(i, rec) for i, rec in enumerate(records)]
        if self._undeclared == "skip":
            # A record whose check the provider has not declared yields no fact.
            # It is counted and its check named in health(), so a scan whose
            # rules are mostly unbound is visible as such, and nothing unbound
            # is ever exported (MCE-03; MCE-07 for benchmark scans).
            declared = set(self.checks)
            skipped = sorted({f["check"] for f in facts if f["check"] not in declared})
            facts = [f for f in facts if f["check"] in declared]
            self._last.update({"skipped_undeclared": len(skipped),
                               "undeclared_checks": skipped})
        self._last.update({"status": "collected", "facts": len(facts),
                           "last_success": facts[-1].get("observed_at") if facts else None})
        for fact in facts:
            yield fact

    def collection_outcome(self):
        """'not-run' until a collection with at least one record happened."""
        return self._last["status"]


def build_adapter(mapping, ksi_ids=None, ksi_profile_path=None):
    """Validate the mapping, verify every KSI id it binds (ksi_targets and
    check_bindings) against the pinned KSI profile and every check_bindings key
    against the declared checks, and return an UNREGISTERED MappingAdapter.
    Refuses, naming the problem, rather than building a partially-correct
    adapter."""
    adapter = MappingAdapter(mapping)
    known = ksi_ids if ksi_ids is not None else load_ksi_ids(ksi_profile_path)
    bound_ids = set(adapter.ksi_targets())
    for kids in adapter.source_bindings().values():
        bound_ids |= set(kids)
    unknown = sorted(k for k in bound_ids if k not in known)
    if unknown:
        raise MappingError(
            f"mapping {mapping.get('name')!r} names KSI id(s) not in the pinned KSI "
            f"profile: {', '.join(unknown)}; refusing to register the adapter")
    undeclared = sorted(k for k in (mapping.get("check_bindings") or {}) if k not in mapping["checks"])
    if undeclared:
        raise MappingError(
            f"mapping {mapping.get('name')!r} binds check(s) it does not declare in `checks`: "
            f"{', '.join(undeclared)}; refusing to register the adapter")
    return adapter


def register_mapping_adapter(mapping, ksi_ids=None, ksi_profile_path=None):
    """build_adapter, then register the service's evidenceType and the adapter
    under its name. Returns the registered instance."""
    adapter = build_adapter(mapping, ksi_ids=ksi_ids, ksi_profile_path=ksi_profile_path)
    ew.register_service_evidence_type(adapter.service, adapter.evidence_type)
    return ew.register_adapter(adapter)


def register_from_profile(profile, base):
    """Register every ENABLED mapping-driven source the offering profile
    declares (evidence_sources entries carrying mapping_path), so the
    provenance gate and preflight see the same bindings the apply driver used.
    Returns {name: adapter}. A source whose mapping cannot be loaded or whose
    key does not equal the mapping's name raises MappingError: a gate that
    silently skipped it would read that source's evidence as unbound without
    saying why."""
    out = {}
    sources = (profile or {}).get("evidence_sources") or {}
    for name, cfg in sorted(sources.items()):
        if not isinstance(cfg, dict) or not cfg.get("enabled") or not cfg.get("mapping_path"):
            continue
        path = os.path.join(base, cfg["mapping_path"])
        try:
            mapping = load_mapping(path)
        except (OSError, ValueError) as e:
            raise MappingError(f"evidence source {name!r}: mapping at {cfg['mapping_path']} "
                               f"cannot be read: {e}")
        if mapping.get("name") != name:
            raise MappingError(f"evidence source {name!r}: the mapping at {cfg['mapping_path']} "
                               f"declares name {mapping.get('name')!r}; the key must match")
        existing = ew.get_adapter(name)
        if isinstance(existing, MappingAdapter) and existing.mapping == mapping:
            out[name] = existing
            continue
        out[name] = register_mapping_adapter(mapping)
    return out


def load_mapping(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main(argv=None):
    """Offline dry run: python mapping_adapter.py MAPPING.json EXPORT -- prints
    the facts the export would yield (no record store, nothing written)."""
    import argparse
    ap = argparse.ArgumentParser(description=main.__doc__)
    ap.add_argument("mapping")
    ap.add_argument("export")
    args = ap.parse_args(argv)
    adapter = build_adapter(load_mapping(args.mapping))
    with open(args.export, encoding="utf-8") as f:
        text = f.read()
    facts = ew.require_conforming_facts(adapter.collect(text), who=f"adapter '{adapter.name}'")
    print(json.dumps({"adapter": adapter.describe(), "outcome": adapter.collection_outcome(),
                      "health": adapter.health(), "facts": facts}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
