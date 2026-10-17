"""Resolve deployed AWS Config rule names to the framework's managed-rule ids.

AUD-F84. The registry names each collectable Config check by the AWS managed
rule's catalog name (``encrypted-volumes``). An account rarely deploys a rule
under that bare name: Security Hub deploys ``securityhub-encrypted-volumes-<hash>``,
a conformance pack deploys ``encrypted-volumes-conformance-pack-<id>``, and a
provider's own template may use any name. The first live collection against a
real account found 29 of the registry's 34 rules running under such names and
reported all 34 as ``RULE_NOT_DEPLOYED``, because ``collect_facts.py`` matched
the exact ``ConfigRuleName`` only. The offline importer had already solved the
same problem for exports; this module is that logic, shared by both paths so
a deployed-name resolution cannot drift between them.

Three ways a deployed name resolves, in order:

1. the exact managed-rule id (deployed under its catalog name);
2. the Security Hub linked-rule shape ``securityhub-<id>-<suffix>``;
3. the rule's ``Source.SourceIdentifier`` (AWS-owned rules only), looked up in
   the pinned catalog-identifier vocabulary
   (``automation/config-rules/known-config-managed-rules.json``). The identifier
   is not derivable from the name (``restricted-ssh`` is
   ``INCOMING_SSH_DISABLED``), so this is data read from the AWS Config
   Developer Guide, never a transform.

Several deployed instances of one id aggregate worst-wins: any NON_COMPLIANT
wins; COMPLIANT beats INSUFFICIENT_DATA beats NOT_APPLICABLE. A custom rule
(``Source.Owner`` not ``AWS``) never resolves through its identifier, because
a Lambda ARN says nothing about which managed rule it imitates.

Pure functions; no AWS client is created here. ``resolve_deployed_names`` takes
the already-listed ``describe_config_rules`` rows.
"""
import json
import os
import re

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VOCABULARY = os.path.join(BASE, "automation", "config-rules",
                          "known-config-managed-rules.json")

EVALUATED = ("COMPLIANT", "NON_COMPLIANT", "INSUFFICIENT_DATA", "NOT_APPLICABLE")
# Worst-wins precedence when one framework id is deployed under several names.
PRECEDENCE = {"NON_COMPLIANT": 0, "COMPLIANT": 1, "INSUFFICIENT_DATA": 2,
              "NOT_APPLICABLE": 3}
SH_LINKED = re.compile(r"^securityhub-(?P<body>.+)-(?P<suffix>[0-9a-zA-Z]+)$")


class VocabularyError(ValueError):
    """The pinned identifier vocabulary is missing or malformed."""


def catalog_identifiers(path=VOCABULARY):
    """{catalog identifier: framework managed-rule id}, from the pinned
    vocabulary (read from the AWS Config Developer Guide, one page per rule)."""
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    pairs = doc.get("config_managed_rule_identifiers") or {}
    if not isinstance(pairs, dict) or not pairs:
        raise VocabularyError(f"{path}: config_managed_rule_identifiers is missing")
    return {ident: name for name, ident in pairs.items()}


def map_rule_name(name, known_ids, source_identifiers, name_map=None,
                  by_identifier=None):
    """Resolve one deployed Config rule name to a framework managed-rule id, or
    None. ``source_identifiers`` is {deployed name: Source.SourceIdentifier}
    for AWS-owned rules (may be empty); ``by_identifier`` is
    catalog_identifiers(); ``name_map`` is an optional operator-supplied
    {deployed name: framework id} override."""
    if name in known_ids:
        return name
    m = SH_LINKED.match(name)
    if m and m.group("body") in known_ids:
        return m.group("body")
    ident = (source_identifiers or {}).get(name)
    if isinstance(ident, str) and by_identifier:
        candidate = by_identifier.get(ident.strip())
        if candidate in known_ids:
            return candidate
    return (name_map or {}).get(name)


def source_identifiers_from_rules(rules):
    """{deployed name: SourceIdentifier} for the AWS-owned rules in a list of
    ``describe_config_rules`` ``ConfigRules`` rows."""
    out = {}
    for r in rules or []:
        name = r.get("ConfigRuleName")
        src = r.get("Source") or {}
        if name and src.get("Owner") == "AWS" and src.get("SourceIdentifier"):
            out[name] = src["SourceIdentifier"]
    return out


def resolve_deployed_names(rules, known_ids, by_identifier, name_map=None):
    """{framework id: sorted [deployed names]} for every deployed rule that
    resolves, from ``describe_config_rules`` rows. Rules that resolve to no
    framework id are omitted (they are the account's business, not the
    registry's)."""
    sids = source_identifiers_from_rules(rules)
    out = {}
    for r in rules or []:
        name = r.get("ConfigRuleName")
        if not name:
            continue
        fid = map_rule_name(name, known_ids, sids, name_map, by_identifier)
        if fid is not None:
            out.setdefault(fid, []).append(name)
    return {fid: sorted(names) for fid, names in out.items()}


def worst_wins(compliance_types):
    """Aggregate several deployed instances' compliance types into one, by
    PRECEDENCE; 'UNKNOWN' when none is an evaluated outcome."""
    evaluated = [ct for ct in compliance_types if ct in EVALUATED]
    return min(evaluated, key=PRECEDENCE.get) if evaluated else "UNKNOWN"
