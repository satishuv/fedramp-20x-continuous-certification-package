#!/usr/bin/env python3
"""Turn read-only collector facts into SDR evidence entries.

This wires the collector telemetry into the official SDR schema's
`keySecurityIndicators[].ksiEvidence[]` array. Each entry it produces is a
valid `evidence` object per the FedRAMP SDR schema:
    evidenceType         (enum: Log/Report/Screenshot/Configuration/Policy/
                          Procedure/Audit Record)
    evidenceDescription  human-readable, non-sensitive summary
    evidenceLocation     URI to the underlying artifact (Config export,
                          CloudTrail record, etc.)
    evidenceText         short inline telemetry summary
    lastUpdated          date the fact was observed

TRUST BOUNDARY (unchanged): this helper NEVER sets or changes an
implementation/validation/assessment status. A fact is telemetry, not a
determination. `evidenceLocation` is populated as a source POINTER; when the
collector cannot know the durable artifact URI, it emits a clearly-marked
placeholder (a `sdr://` pseudo-URI naming the source) that a human replaces
with the real evidence-store location. It never fabricates an https URL that
implies an artifact exists where none does.

Offline by construction: pure functions over the fact dicts the collectors
emit (service/check/status/detail/region/observed_at). No AWS, no network.

INTEGRITY BINDING (AUD-F26). The content hash - and therefore any signature over
it - is computed over the BOUND CANONICAL PAYLOAD: every field a reader uses to
interpret the observation (evidenceType, evidenceDescription, evidenceLocation,
evidenceText, lastUpdated, xSourceFact). Before this the digest covered only
the sanitized source fact, so `evidenceDescription` could be rewritten from a
resource-specific observation to "All customer resources fully compliant" and
the entry still classified `verified`: a positive statement beside a verified
digest that did not attest to that statement. Now a change to ANY displayed
field changes the hash and fails verification.

SCOPE IDENTITY (AUD-F27). Multi-account collection tags facts with the raw AWS
account id. That id is sensitive (it must never enter the public package), but
silently dropping it collapsed two accounts' observations of the same
service/check/region onto one evidence location, so `attach_evidence` kept the
first (a PASS) and discarded the second (a FAIL). An account-tagged fact now
carries an OPAQUE scope id (HMAC-SHA256 under a deployment-private key, or a
caller-supplied slug-safe alias) in the signed payload AND the evidence object
key, plus the run id when the collector stamped one. A fact tagged with an
account but no way to derive a scope is REFUSED, never silently exported.

INPUT BOUNDARY (AUD-F28). Free-form collector `detail` was copied verbatim into
`evidenceDescription` and (first 120 chars) into `xSourceFact.summary`, so a
third-party adapter or caller could put an internal hostname or IP into the
customer-facing package and the generated-artifact sensitive-pattern gate
(account id / access key / private key only) would not notice. Every free-text
field is now scrubbed (ARN, access key, key material, email, URL, IPv6, IPv4,
account id, hostname, long opaque token) and length-bounded before it enters an
evidence entry, and every identifier that becomes part of the object key must
be slug-safe. A scrub is conservative by design: it may redact a harmless
dotted token, it never lets an identifying one through.
"""

import hashlib
import hmac
import re
import uuid


class EvidenceExportError(ValueError):
    """A fact that cannot be exported safely is refused, loudly. Silent drop
    (the pre-AUD-F27 behaviour) hid a lost observation; silent export leaked."""


# Every field a reader uses to interpret the observation. The content hash is
# computed over exactly this projection of the finished entry, in this order
# of precedence: nothing outside it is attested, nothing inside it can change
# without changing the digest.
BOUND_FIELDS = ("evidenceType", "evidenceDescription", "evidenceLocation",
                "evidenceText", "lastUpdated", "xSourceFact")

# Identifiers that become path segments of the evidence object key.
_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ACCOUNT_RE = re.compile(r"^\d{12}$")

# Bounded lengths for free text that enters the public package.
DETAIL_MAX = 240
SUMMARY_MAX = 120
STATUS_MAX = 80

# Conservative scrub, most specific first. Labels are what a reviewer sees.
_SCRUB_PATTERNS = (
    (re.compile(r"\barn:aws[a-zA-Z-]*:[^\s\"'<>]*"), "arn"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "access-key"),
    (re.compile(r"-----BEGIN[^-]*-----(?:.|\n)*?-----END[^-]*-----|-----BEGIN[^-]*-----"),
     "key-material"),
    (re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"), "email"),
    (re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'<>]+"), "url"),
    # IPv6: full form (5-8 groups) or a compressed form containing '::' with at
    # least one hex group. A clock time such as 12:00:00 (3 groups, no '::') is
    # deliberately NOT matched.
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}\b"), "ip"),
    (re.compile(r"(?:(?:[0-9a-fA-F]{1,4}:){1,6}:(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{0,4}"
                r"|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})"), "ip"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "ip"),
    (re.compile(r"(?<![0-9A-Fa-f-])\d{12}(?![0-9A-Fa-f-])"), "account"),
    # Hostname / FQDN: two or more dot-separated labels ending in an alphabetic
    # TLD. Decimal numbers (1.5), percentages and 'e.g.' do not match.
    (re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b"), "host"),
    # Long opaque tokens (secrets, session ids, base64 blobs).
    (re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{32,}(?![A-Za-z0-9+/=_-])"), "token"),
)


def scrub_text(text, limit=DETAIL_MAX):
    """Return `text` with identifying or secret-shaped tokens replaced by
    `[redacted:<kind>]` and truncated to `limit` characters. Non-strings become
    ''. Conservative: a false redaction costs a little readability; a miss
    would put an identifier in the customer-facing package."""
    if not isinstance(text, str) or not text:
        return ""
    out = text
    for pat, label in _SCRUB_PATTERNS:
        out = pat.sub(f"[redacted:{label}]", out)
    out = " ".join(out.split())  # collapse whitespace/newlines
    return out[:limit]


def scrub_hits(text):
    """Labels of every scrub pattern that would fire on `text` (for tests and
    for callers that want to reject rather than redact)."""
    if not isinstance(text, str) or not text:
        return []
    return [label for pat, label in _SCRUB_PATTERNS if pat.search(text)]


def _require_slug(value, what):
    """An identifier that becomes part of the evidence object key must be
    slug-safe: no path separators, no whitespace, no traversal, bounded."""
    s = str(value)
    if not _SLUG_RE.match(s) or ".." in s:
        raise EvidenceExportError(
            f"{what} {s[:40]!r} is not a safe identifier (allowed: letters, digits, "
            "'.', '_', '-', max 64 chars, no '..'); refusing to build an evidence "
            "object key from it")
    return s


def scope_id(account, scope_key):
    """Opaque, non-reversible identifier for an account scope.

    HMAC-SHA256(scope_key, account), truncated, prefixed 'scope-'. The key is
    private to the deployment (an environment secret; never in the repo or the
    package). A plain SHA-256 of a 12-digit account id would be brute-forceable
    in minutes, which is why the id is KEYED. The scope -> account map that an
    assessor needs lives in the git-excluded private facts store
    (collect_multi_account.py writes it beside the facts), never in the SDR.
    """
    if not scope_key:
        raise EvidenceExportError(
            "scope_key is required to derive an opaque scope id for an "
            "account-tagged fact (set SDR_EVIDENCE_SCOPE_KEY or pass scope_key)")
    if isinstance(scope_key, str):
        scope_key = scope_key.encode("utf-8")
    acct = str(account).strip()
    if not acct:
        raise EvidenceExportError("account is empty; cannot derive a scope id")
    digest = hmac.new(bytes(scope_key), acct.encode("utf-8"), hashlib.sha256).hexdigest()
    return "scope-" + digest[:16]


def new_run_id():
    """A slug-safe identifier for one collection run."""
    return "run-" + uuid.uuid4().hex[:16]


def canonical_payload(entry):
    """The exact object the content hash (and any signature) is over: the
    BOUND_FIELDS projection of a finished evidence entry. A reviewer or CI
    recomputes evidence_hash(canonical_payload(entry)) and compares it to
    xEvidenceContentHash; a change to any bound field fails the comparison."""
    if not isinstance(entry, dict):
        return {}
    return {k: entry[k] for k in BOUND_FIELDS if k in entry}


# collector service -> (SDR evidenceType, source-kind used to build the pointer)
_SERVICE_EVIDENCE = {
    "config": ("Configuration", "aws-config"),
    "cloudtrail": ("Audit Record", "aws-cloudtrail"),
    "securityhub": ("Report", "aws-securityhub"),
    "accessanalyzer": ("Report", "aws-accessanalyzer"),
    "inspector2": ("Report", "aws-inspector"),
    "guardduty": ("Log", "aws-guardduty"),
    "backup": ("Configuration", "aws-backup"),
    "kms": ("Configuration", "aws-kms"),
    "cloudformation": ("Configuration", "aws-cloudformation"),
    "wafv2": ("Configuration", "aws-wafv2"),
    "ec2": ("Configuration", "aws-ec2"),
    "ecr": ("Configuration", "aws-ecr"),
    "s3": ("Configuration", "aws-s3"),
    "s3control": ("Configuration", "aws-s3control"),
    "dynamodb": ("Configuration", "aws-dynamodb"),
    "iam": ("Policy", "aws-iam"),
    "events": ("Configuration", "aws-eventbridge"),
    "codepipeline": ("Configuration", "aws-codepipeline"),
    # Optional third-party evidence sources (opt-in; see thirdparty_adapters.py).
    "crowdstrike": ("Log", "crowdstrike-falcon"),
    "wiz": ("Report", "wiz"),
}

_DEFAULT_TYPE = "Report"

# Statuses that indicate the read itself failed; these do not become evidence
# (a failed read is not evidence of anything about the control).
_ERROR_PREFIX = "ERROR"


def evidence_hash(artifact):
    """SHA-256 of an evidence artifact, for tamper-evident traceability.

    Accepts bytes, str, or a JSON-serializable object (dict/list). Objects are
    hashed over their canonical (sorted-key, compact) JSON encoding so the same
    logical content always yields the same digest regardless of key order or
    whitespace. Returns a lowercase hex digest string prefixed 'sha256:'.

    This is a traceability aid, not a security control: it lets a reviewer
    confirm the evidence object in the SDR is the same bytes that were
    collected, and lets CI detect a silently-edited evidence artifact. It never
    sets a status or makes a determination.
    """
    import hashlib
    import json as _json

    if isinstance(artifact, bytes):
        data = artifact
    elif isinstance(artifact, str):
        data = artifact.encode("utf-8")
    else:
        data = _json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _pointer(service, check, region, location_base=None, scope=None, run_id=None):
    """Build the evidenceLocation.

    If the caller supplies a real evidence-store base URI, the pointer is a
    concrete https URL under it. Otherwise it is an explicit `sdr://` pseudo-URI
    that names the AWS source and is obviously a placeholder for a human to
    replace, never a fake https link.

    The key embeds the opaque scope (when the fact is account-tagged) and the
    run id (when the collector stamped one), so two accounts' observations of
    the same service/check/region - or two runs of the same scope - never share
    a pointer (AUD-F27). Every segment is slug-checked by the caller.
    """
    parts = [service, check]
    if scope:
        parts.append(scope)
    parts.append(region)
    if run_id:
        parts.append(run_id)
    slug = "/".join(parts)
    if location_base:
        base = location_base.rstrip("/")
        return f"{base}/{slug}.json"
    return f"sdr://placeholder/{slug}  (replace with the real evidence-store URI)"


def _sanitize_fact_for_evidence(fact):
    """Return a non-sensitive projection of a collector fact for inclusion in
    the public evidence object (xSourceFact). Keeps only an explicit allowlist
    of fields that describe WHAT was checked and the outcome - never raw
    resource ARNs, account ids, IPs, or full API payloads that could identify a
    real environment or aid a threat actor (CDS-CSO-* sensitivity guidance).
    Detailed raw material stays in the git-excluded private facts store.

    `scope` is the OPAQUE scope id (never the account), `run_id` the collection
    run; both are part of the observation's identity (AUD-F27). Free text is
    scrubbed and bounded before it is kept (AUD-F28)."""
    if not isinstance(fact, dict):
        return {}
    ALLOW = ("service", "check", "region", "scope", "run_id",
             "collected_at", "observed_at", "timestamp")
    out = {k: fact[k] for k in ALLOW if k in fact}
    if "status" in fact:
        out["status"] = scrub_text(str(fact["status"]), STATUS_MAX)
    # A short, human summary is allowed but scrubbed and truncated; never the
    # full detail.
    detail = fact.get("detail")
    if isinstance(detail, str) and detail:
        out["summary"] = scrub_text(detail, SUMMARY_MAX)
    return out


def fact_to_evidence(fact, location_base=None, scope_key=None):
    """Convert one collector fact into an SDR evidence dict, or None if the
    fact records a read error (which is not evidence).

    scope_key: deployment-private key used to derive an opaque scope id for an
    account-tagged fact that does not already carry `scope`. A fact tagged with
    `account` that has neither is REFUSED (EvidenceExportError): the raw account
    must not enter the package and dropping it collides scopes (AUD-F27).
    """
    if not isinstance(fact, dict):
        return None
    status = str(fact.get("status", ""))
    if status.startswith(_ERROR_PREFIX):
        return None
    service = _require_slug(fact.get("service", "unknown"), "service")
    check = _require_slug(fact.get("check", "unknown"), "check")
    region = _require_slug(fact.get("region", "unknown"), "region")

    # Scope identity (AUD-F27). Never the account itself.
    account = fact.get("account")
    scope = fact.get("scope")
    if scope is not None:
        scope = _require_slug(scope, "scope")
        if _ACCOUNT_RE.match(scope):
            raise EvidenceExportError(
                "scope must be an opaque identifier, not a 12-digit AWS account id; "
                "derive it with evidence_wiring.scope_id(account, scope_key)")
    elif account:
        if not scope_key:
            raise EvidenceExportError(
                f"fact {service}:{check} is tagged with an AWS account but carries no "
                "opaque scope and no scope_key was supplied; refusing to export it "
                "(dropping the account collides scopes, exporting it leaks it). "
                "Set SDR_EVIDENCE_SCOPE_KEY / pass scope_key, or stamp fact['scope'].")
        scope = scope_id(account, scope_key)
    run_id = fact.get("run_id")
    if run_id is not None:
        run_id = _require_slug(run_id, "run_id")

    ev_type, _kind = _SERVICE_EVIDENCE.get(service, (_DEFAULT_TYPE, service))
    status_text = scrub_text(status, STATUS_MAX)
    detail = scrub_text(fact.get("detail", ""), DETAIL_MAX)
    # The live AWS collector emits collected_at; synthetic/test facts may use
    # observed_at or timestamp. Prefer collected_at so a real collected fact's
    # lastUpdated is populated and the timestamp is captured in xSourceFact.
    observed = (fact.get("collected_at")
                or fact.get("observed_at")
                or fact.get("timestamp"))

    # Sanitize once (with the derived scope/run stamped, never the account) and
    # persist the projection, so a reviewer/CI recompute over the bound payload
    # matches xEvidenceContentHash.
    projected = dict(fact)
    projected.pop("account", None)
    if scope:
        projected["scope"] = scope
    if run_id:
        projected["run_id"] = run_id
    sanitized = _sanitize_fact_for_evidence(projected)
    evidence = {
        "evidenceType": ev_type,
        "evidenceDescription": f"{service}:{check} = {status_text}. {detail}".strip(),
        "evidenceLocation": _pointer(service, check, region, location_base,
                                     scope=scope, run_id=run_id),
        "evidenceText": f"{service}:{check} status={status_text} region={region}"
                        + (f" scope={scope}" if scope else ""),
        # Persist a SANITIZED source fact. The full raw fact can identify a real
        # environment and the facts store is git-excluded for that reason; CDS
        # rules say not to include sensitive detail likely to help a threat
        # actor. So xSourceFact carries an explicit allowlist of non-sensitive
        # fields.
        "xSourceFact": sanitized,
    }
    if observed:
        # SDR schema wants a date (not datetime) for evidence lastUpdated.
        evidence["lastUpdated"] = str(observed)[:10]
    # Tamper-evident digest over the BOUND CANONICAL PAYLOAD - every displayed
    # field plus the sanitized fact - computed LAST so nothing set above escapes
    # it (AUD-F26). A reviewer or CI recomputes evidence_hash(canonical_payload(e))
    # to confirm the entry reflects the fact that was collected AND that no
    # displayed assertion has been edited since. Carried in the extension
    # namespace so the official evidence object stays schema-clean.
    evidence["xEvidenceContentHash"] = evidence_hash(canonical_payload(evidence))
    return evidence


def facts_to_evidence(facts, location_base=None, scope_key=None):
    """Map a list of collector facts to a list of SDR evidence entries,
    dropping read-error facts. An unexportable fact raises (see
    fact_to_evidence); it is never silently skipped."""
    out = []
    for f in facts or []:
        ev = fact_to_evidence(f, location_base, scope_key=scope_key)
        if ev is not None:
            out.append(ev)
    return out


def observation_identity(entry):
    """The identity `attach_evidence` de-duplicates on: WHERE the evidence
    points, WHICH scope observed it, and WHICH observation (run id, else the
    observation timestamp). Two accounts' opposite findings for the same
    service/check/region, or two runs of one scope, are distinct observations
    and are both kept (AUD-F27); the identical observation attached twice is
    kept once."""
    if not isinstance(entry, dict):
        return None
    sf = entry.get("xSourceFact") or {}
    if not isinstance(sf, dict):
        sf = {}
    observation = (sf.get("run_id") or sf.get("collected_at")
                   or sf.get("observed_at") or sf.get("timestamp")
                   or entry.get("lastUpdated"))
    return (entry.get("evidenceLocation"), sf.get("scope"), observation)


def attach_evidence(ksi_record, facts, location_base=None, replace=False,
                    scope_key=None):
    """Populate a records-store KSI entry's `evidence` list from facts.

    ksi_record is one value from records["ksi"][ksi_id]. This ONLY touches the
    `evidence` array; implementation_status and every statement field are left
    exactly as they were. Returns the number of evidence entries added.

    replace=False appends, de-duplicated by observation_identity (location,
    scope, observation); replace=True swaps the evidence list for the freshly
    derived one. Either way every distinct scope's observation survives.
    """
    if not isinstance(ksi_record, dict):
        raise TypeError("ksi_record must be a dict")
    new = facts_to_evidence(facts, location_base, scope_key=scope_key)
    if replace:
        ksi_record["evidence"] = new
        return len(new)
    existing = ksi_record.get("evidence", []) or []
    seen = {observation_identity(e) for e in existing if isinstance(e, dict)}
    added = 0
    for ev in new:
        ident = observation_identity(ev)
        if ident in seen:
            continue
        existing.append(ev)
        seen.add(ident)
        added += 1
    ksi_record["evidence"] = existing
    return added


# --- Evidence adapters -----------------------------------------------------
#
# An adapter reads raw data from ONE source (a scan CSV, a config export, a
# vulnerability report) and yields collector-shaped fact dicts. Those facts
# flow through fact_to_evidence, so every adapter's output lands in the SDR as
# a schema-valid evidence object with a content hash, using the same trust
# boundary as the AWS collectors: telemetry only, never a status determination.
#
# To add a source, subclass EvidenceAdapter, implement collect(), and register
# it. This is the extension point the reviews asked for; the AWS collectors are
# one producer of facts, adapters are another.

_ADAPTERS = {}


class EvidenceAdapter:
    """Base class for an evidence source. Subclasses set `name` and implement
    `collect(raw)`, returning an iterable of collector-shaped fact dicts:
        {service, check, status, detail, region, observed_at}
    The fact is hashed and mapped to an SDR evidence object downstream.

    Adapter contract v2 (metadata only, backward compatible): subclasses may
    declare `version`, `source_type`, `supported_evidence_types`, and
    `freshness_policy_days`. describe() returns that metadata so a caller can
    enumerate adapter capabilities without instantiating a collection, and
    health() returns a default healthy record a real adapter overrides. None of
    this makes an adapter decide PASS/FAIL: adapters gather facts, validators
    evaluate, humans assess."""

    name = "abstract"
    service = "adapter"
    version = "1.0.0"
    source_type = "generic"
    supported_evidence_types = ["Report"]
    freshness_policy_days = 1

    def collect(self, raw):  # pragma: no cover - abstract
        raise NotImplementedError

    def to_evidence(self, raw, location_base=None, scope_key=None):
        """Run collect() and map every fact to an SDR evidence object."""
        return facts_to_evidence(list(self.collect(raw)), location_base,
                                 scope_key=scope_key)

    def describe(self):
        """Adapter capability metadata (contract v2). Pure, no collection."""
        return {
            "name": self.name,
            "version": self.version,
            "service": self.service,
            "source_type": self.source_type,
            "supported_evidence_types": list(self.supported_evidence_types),
            "freshness_policy_days": self.freshness_policy_days,
        }

    def health(self):
        """Default health record. A real adapter overrides this with its last
        collection outcome; the default distinguishes 'not yet run' from a
        failure so a broken collector is never read as clean posture."""
        return {
            "adapter": self.name,
            "status": "not-run",
            "last_success": None,
            "last_error": None,
        }


def register_adapter(adapter):
    """Register an EvidenceAdapter instance (or subclass) under its name."""
    inst = adapter() if isinstance(adapter, type) else adapter
    if not isinstance(inst, EvidenceAdapter):
        raise TypeError("adapter must be an EvidenceAdapter")
    _ADAPTERS[inst.name] = inst
    return inst


def get_adapter(name):
    return _ADAPTERS.get(name)


def list_adapters():
    return sorted(_ADAPTERS)


class CsvCountAdapter(EvidenceAdapter):
    """Reference adapter: turns a metric name and an observed/total count into a
    single evidence fact (e.g. a vulnerability-scan patch-coverage row). Pure,
    offline, illustrative. `raw` is a dict:
        {check, observed, total, region?, observed_at?, detail?}"""

    name = "csv-count"
    service = "scan"

    def collect(self, raw):
        observed = raw.get("observed", 0)
        total = raw.get("total", 0)
        pct = round(100.0 * observed / total, 2) if total else 0.0
        yield {
            "service": self.service,
            "check": raw.get("check", "count"),
            "status": f"{pct}%",
            "detail": raw.get("detail", f"{observed} of {total}"),
            "region": raw.get("region", "global"),
            "observed_at": raw.get("observed_at"),
        }


register_adapter(CsvCountAdapter)
