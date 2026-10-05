"""Metric-history integrity: hash-chained, run-attested observations (AUD-F37).

The metric history is the evidence behind SDR-CSX-KMT (daily data, 30-day and
1-year summaries) and FRC-CSX-MOT (persistent validation over 6/18 months). It
is a JSON file. Before this module, nothing distinguished a datapoint the
collector produced on the day from one typed into the file afterwards, and the
FRC-CSX-VVK binding gate accepted a method as "working" because its series key
existed. A provider could meet "two working automated methods" and "six months
of persistent validation" by editing a file.

Three mechanisms, all offline and deterministic:

1. Run provenance. Every observation carries `run_id` (stamped by the collector
   into the facts store meta) and `facts_sha256` (digest of the facts store the
   appender consumed). An observation with neither is UNATTESTED: it did not
   come through the collector -> appender path.

2. Hash chain. Every observation carries `prev_hash` (the previous observation's
   `hash` for that KSI, or the KSI's pruning anchor) and `hash`, the SHA-256 of
   its canonical content (every field but `hash`). Editing, inserting or
   deleting any past observation breaks every later link. Pruning old
   observations advances `meta.chain_anchor[ksi]` to the hash of the newest
   pruned observation, so a retained window still verifies from its anchor.

3. One digest. `history_digest(history)` is the SHA-256 over the sorted chain
   heads; `publish_history.py` can sign it with the separate signer's KMS key
   (`meta.history_signature`) and preflight verifies that signature offline
   against the independently pinned public key. Re-chaining a tampered history
   is cheap; re-signing it needs the signer principal.

`verify_history(history)` reports every break as a (code, ksi, detail) tuple.
Codes: chain-break, bad-hash, missing-chain, unattested, unbacked-point,
bad-anchor, head-mismatch. Preflight decides which are HARD by class and
evidence-store profile (see sdr.py); this module only measures.
"""
import hashlib
import json

CHAIN_FIELDS = ("prev_hash", "hash")
PROVENANCE_FIELDS = ("run_id", "facts_sha256")


def canonical(obj):
    """Deterministic JSON for hashing: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def observation_hash(obs):
    """Hash of an observation's content: every field except `hash` itself
    (so `prev_hash` and the provenance ARE covered)."""
    body = {k: v for k, v in obs.items() if k != "hash"}
    return "sha256:" + sha256_hex(canonical(body))


def chain_observation(obs, prev_hash, provenance=None):
    """Return a NEW observation dict linked to prev_hash and stamped with the
    run provenance, with its hash computed last. Never mutates the input."""
    out = dict(obs)
    out.pop("hash", None)
    out["prev_hash"] = prev_hash
    if provenance:
        for k in PROVENANCE_FIELDS:
            if provenance.get(k):
                out[k] = provenance[k]
    out["hash"] = observation_hash(out)
    return out


def is_attested(obs):
    return bool(obs.get("run_id")) and bool(obs.get("facts_sha256"))


def chain_head(entry, anchor=None):
    """The hash the next observation of this KSI must link to."""
    obs = entry.get("observations") or []
    if obs:
        return obs[-1].get("hash")
    return anchor


def history_digest(history):
    """One SHA-256 over every KSI's chain head (sorted by KSI id) plus the
    pruning anchors. Changes when any observation anywhere changes."""
    heads = {}
    anchors = (history.get("meta") or {}).get("chain_anchor") or {}
    for kid, entry in sorted((history.get("ksis") or {}).items()):
        heads[kid] = chain_head(entry, anchors.get(kid))
    return "sha256:" + sha256_hex(canonical({"heads": heads, "anchors": anchors}))


def verify_history(history):
    """Return a list of (code, ksi, detail) problems; empty means intact.

    - bad-hash:       an observation's hash does not match its content (edited).
    - chain-break:    prev_hash does not equal the previous observation's hash
                      (inserted, deleted or reordered observation).
    - bad-anchor:     the first retained observation does not link to the
                      KSI's recorded pruning anchor.
    - missing-chain:  an observation carries no chain fields (pre-F37 or
                      hand-written).
    - unattested:     an observation carries no run provenance.
    - unbacked-point: a series point whose date has no observation behind it
                      (a rollup that nothing produced).
    - head-mismatch:  meta.chain_heads disagrees with the observation log.
    """
    problems = []
    meta = history.get("meta") or {}
    anchors = meta.get("chain_anchor") or {}
    recorded_heads = meta.get("chain_heads") or {}
    for kid, entry in sorted((history.get("ksis") or {}).items()):
        obs = entry.get("observations") or []
        prev = anchors.get(kid)
        for i, o in enumerate(obs):
            if not all(k in o for k in CHAIN_FIELDS):
                problems.append(("missing-chain", kid, f"observation {i} ({o.get('date')}) has no chain fields"))
                prev = None
                continue
            if o.get("hash") != observation_hash(o):
                problems.append(("bad-hash", kid, f"observation {i} ({o.get('date')}) content does not match its hash"))
            if i == 0:
                if o.get("prev_hash") != prev:
                    code = "bad-anchor" if prev else "chain-break"
                    problems.append((code, kid, f"first retained observation ({o.get('date')}) does not link to "
                                                f"{'the pruning anchor' if prev else 'a chain start (prev_hash must be null)'}"))
            elif o.get("prev_hash") != prev:
                problems.append(("chain-break", kid, f"observation {i} ({o.get('date')}) does not link to its predecessor"))
            if not is_attested(o):
                problems.append(("unattested", kid, f"observation {i} ({o.get('date')}) carries no run provenance"))
            prev = o.get("hash")
        obs_dates = {o.get("date") for o in obs}
        for p in entry.get("series") or []:
            if p.get("date") not in obs_dates:
                problems.append(("unbacked-point", kid, f"series point {p.get('date')} has no observation behind it"))
        if kid in recorded_heads and recorded_heads[kid] != chain_head(entry, anchors.get(kid)):
            problems.append(("head-mismatch", kid, "meta.chain_heads disagrees with the observation log"))
    return problems


def record_heads(history):
    """Write meta.chain_heads and meta.history_digest from the observation log.
    Called by the appender after every run."""
    meta = history.setdefault("meta", {})
    anchors = meta.get("chain_anchor") or {}
    meta["chain_heads"] = {kid: chain_head(entry, anchors.get(kid))
                           for kid, entry in sorted((history.get("ksis") or {}).items())}
    meta["history_digest"] = history_digest(history)
    return meta["history_digest"]


def facts_store_digest(paths):
    """SHA-256 over the raw bytes of the facts store file(s) consumed by a run,
    in sorted path order; the provenance value stamped on each observation."""
    h = hashlib.sha256()
    for p in sorted(paths):
        with open(p, "rb") as f:
            h.update(f.read())
    return "sha256:" + h.hexdigest()


def rechain(history, provenance=None):
    """Rebuild every chain from scratch in observation order (anchors reset).

    This is the ONE operation that can turn an unchained history into a
    chained one, and it is exactly what a tamperer would do, which is why it is
    not called anywhere in the collection path and why production assurance
    requires the history digest to be SIGNED by the separate signer: anyone can
    rechain, only the signer principal can re-sign. Used by the fictional
    sample builders (labelled as such) and by tests."""
    meta = history.setdefault("meta", {})
    meta["chain_anchor"] = {}
    for kid, entry in (history.get("ksis") or {}).items():
        prev = None
        chained = []
        for o in entry.get("observations") or []:
            o2 = chain_observation(o, prev, provenance)
            chained.append(o2)
            prev = o2["hash"]
        entry["observations"] = chained
    record_heads(history)
    return history
