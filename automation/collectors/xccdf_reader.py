#!/usr/bin/env python3
"""Pure reader for XCCDF results documents (MCE-07): one record per
<rule-result>, for the mapping-driven adapter's export_format "xccdf".

Format grounding (read in-session, not from memory):
  - NIST XCCDF 1.2 schema, https://csrc.nist.gov/schema/xccdf/1.2/xccdf_1.2.xsd
    (captured 2026-10-15): a <TestResult> "normally appears as the child of
    the <Benchmark> element, although it may also appear as the top-level
    element of an XCCDF results document"; its @end-time is "Time when testing
    was completed and the results recorded"; <target> is the "Name or
    description of the target system ... applications should include the fully
    qualified DNS name whenever possible"; a <rule-result> carries @idref (the
    Rule id), @severity, @weight, @time ("Time when application of this
    instance of the referenced Rule was completed") and a <result> whose
    allowed values are pass, fail, error, unknown, notapplicable, notchecked,
    notselected, informational and fixed.
  - OpenSCAP user manual, https://static.open-scap.org/openscap-1.3/oscap_user_manual.html
    (captured 2026-10-15): the scanner writes either an XCCDF results file or a
    result data stream (ARF) that wraps the same <TestResult>.

The reader therefore matches <TestResult> elements by namespace and local
name wherever they sit (Benchmark child, top level, or inside an ARF report),
so one code path reads both output forms and both XCCDF namespaces (1.1 and
1.2). It is pure: text in, list of dicts out, no file or network access.

Fail-closed choices:
  - A document carrying a DOCTYPE is refused. Scanner output never has one, and
    refusing it removes the entity-expansion class of XML attacks without a
    third-party parser.
  - A rule-result with no @time inherits its TestResult's @end-time; with
    neither, `time` is None and the fact contract refuses the record. A
    timestamp is never invented here.
  - The target host name is carried ONLY in the `target` field, so the mapping
    can route it to the raw-scope path (kind "host"); it is never copied into
    `summary`, so no hostname can reach a fact's detail (MCE-07 AC3).

The XCCDF result vocabulary is closed and its semantics are the standard's,
not a provider's: only `pass` is a pass and only `fail` is a fail. Every other
value (including `fixed`, which the standard defines as "had failed, but was
then fixed", with no re-check implied) normalizes to UNKNOWN (MCE-07 AC2).
"""

import re
import xml.etree.ElementTree as ET

XCCDF_NAMESPACES = (
    "http://checklists.nist.gov/xccdf/1.2",
    "http://checklists.nist.gov/xccdf/1.1",
)

# The standard's result enumeration -> the adapter's three-valued form. Keys
# are the exact lower-case tokens the schema allows.
XCCDF_RESULT_NORMALIZATION = {
    "pass": "PASS",
    "fail": "FAIL",
    "error": "UNKNOWN",
    "unknown": "UNKNOWN",
    "notapplicable": "UNKNOWN",
    "notchecked": "UNKNOWN",
    "notselected": "UNKNOWN",
    "informational": "UNKNOWN",
    "fixed": "UNKNOWN",
}

# Fields every record carries (a mapping's `fields` paths name these).
RECORD_FIELDS = ("rule_id", "result", "time", "target", "benchmark", "profile",
                 "severity", "weight", "test_result", "summary")

_DOCTYPE_RE = re.compile(r"<!DOCTYPE", re.IGNORECASE)
_NS_RE = re.compile(r"^\{([^}]*)\}(.*)$")


class XccdfReadError(ValueError):
    """The text is not an XCCDF results document this reader can use."""


def _split(tag):
    m = _NS_RE.match(tag or "")
    return (m.group(1), m.group(2)) if m else ("", tag or "")


def _child_text(elem, local_name):
    """Text of the first child in the element's own namespace with this local
    name, stripped; None when absent or empty."""
    ns, _ = _split(elem.tag)
    for child in elem:
        cns, cname = _split(child.tag)
        if cns == ns and cname == local_name:
            text = (child.text or "").strip()
            return text or None
    return None


def _children(elem, local_name):
    ns, _ = _split(elem.tag)
    return [c for c in elem if _split(c.tag) == (ns, local_name)]


def _attr(elem, name):
    v = elem.get(name)
    if v is None:
        return None
    v = v.strip()
    return v or None


def parse_document(text):
    """Parse XCCDF results TEXT (str or UTF-8 bytes) into an ElementTree root.
    Refuses a DOCTYPE and anything that is not well-formed XML."""
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    if not isinstance(text, str):
        raise XccdfReadError("xccdf export must be text")
    if _DOCTYPE_RE.search(text):
        raise XccdfReadError("xccdf export carries a DOCTYPE declaration; refused "
                             "(scanner results never do, and a DOCTYPE enables entity "
                             "expansion attacks)")
    try:
        return ET.fromstring(text)
    except ET.ParseError as e:
        raise XccdfReadError(f"xccdf export is not well-formed XML: {e}")


def test_results(root):
    """Every <TestResult> in an XCCDF namespace, wherever it sits in the
    document (Benchmark child, top level, or wrapped in an ARF report)."""
    out = []
    for elem in root.iter():
        ns, name = _split(elem.tag)
        if name == "TestResult" and ns in XCCDF_NAMESPACES:
            out.append(elem)
    return out


def _benchmark_ref(tr):
    """The Benchmark id this TestResult records results for: the <benchmark>
    child's @id, else its @href, else the enclosing Benchmark element's @id
    (when the TestResult is a Benchmark child)."""
    for b in _children(tr, "benchmark"):
        ref = _attr(b, "id") or _attr(b, "href")
        if ref:
            return ref
    return None


def read_xccdf_results(text):
    """One record dict per <rule-result> across every <TestResult> in the
    document, in document order. Raises XccdfReadError when the text is not an
    XCCDF results document (no TestResult at all). A TestResult with no
    rule-results contributes nothing; the caller treats an empty list as a
    collection that did not run."""
    root = parse_document(text)
    results = test_results(root)
    root_ns, root_name = _split(root.tag)
    if not results:
        raise XccdfReadError(
            f"xccdf export has no TestResult element in an XCCDF namespace (root is "
            f"<{root_name}> in namespace {root_ns or '(none)'}); refusing to read it as "
            "scan results")
    # Benchmark id fallback: TestResult nested in a Benchmark root.
    enclosing_benchmark = _attr(root, "id") if root_name == "Benchmark" else None
    records = []
    for tr in results:
        end_time = _attr(tr, "end-time")
        target = _child_text(tr, "target")
        profile = None
        for p in _children(tr, "profile"):
            profile = _attr(p, "idref")
            if profile:
                break
        benchmark = _benchmark_ref(tr) or enclosing_benchmark
        tr_id = _attr(tr, "id")
        for rr in _children(tr, "rule-result"):
            rule_id = _attr(rr, "idref")
            result = _child_text(rr, "result")
            severity = _attr(rr, "severity")
            weight = _attr(rr, "weight")
            parts = []
            if severity:
                parts.append(f"severity {severity}")
            if profile:
                parts.append(f"profile {profile}")
            if benchmark:
                parts.append(f"benchmark {benchmark}")
            records.append({
                "rule_id": rule_id,
                "result": result.lower() if isinstance(result, str) else result,
                "time": _attr(rr, "time") or end_time,
                "target": target,
                "benchmark": benchmark,
                "profile": profile,
                "severity": severity,
                "weight": weight,
                "test_result": tr_id,
                # Never the target: the host reaches a fact only through the
                # raw-scope path the mapping declares (MCE-07 AC3).
                "summary": "; ".join(parts) if parts else None,
            })
    return records


def canonical_normalization():
    """A copy of the standard's result normalization (callers must not mutate
    the module table)."""
    return dict(XCCDF_RESULT_NORMALIZATION)


def normalization_disagreements(table):
    """Keys in a provider-supplied status_normalization table that name an
    XCCDF result value (case-insensitively) but disagree with the standard's
    normalization, as 'key: given -> expected' strings. [] means the table
    agrees. A key outside the XCCDF vocabulary is reported too: the vocabulary
    is closed, so an extra key is a typo that would otherwise silently never
    match."""
    problems = []
    for key, given in (table or {}).items():
        k = str(key).strip().lower()
        expected = XCCDF_RESULT_NORMALIZATION.get(k)
        if expected is None:
            problems.append(f"{key}: not an XCCDF result value (allowed: "
                            f"{', '.join(XCCDF_RESULT_NORMALIZATION)})")
        elif given != expected:
            problems.append(f"{key}: {given} -> must be {expected} (the XCCDF standard "
                            "defines this value; a provider table may not relabel it)")
    return problems
