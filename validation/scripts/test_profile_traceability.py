"""Profile traceability: every offering-profile requirement the tool enforces is
traced to a FedRAMP source that actually exists.

The contract (validation/scripts/profile_contract.py) claims a FedRAMP source
for every REQUIRED field: a property path in the official Certification Package
Overview schema (`cpo:`) or a CR26 rule id. This test holds the contract to that
claim against the PINNED copies of both, so the tool can never block a provider
on a requirement FedRAMP did not write down, and never drift when the upstream
schema or rule set changes.

    python validation/scripts/test_profile_traceability.py
"""
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
import profile_contract as pc  # noqa: E402

CPO_SCHEMA = os.path.join(BASE, "artifacts", "schemas", "official",
                          "fedramp-certification-package-overview-schema-2026-06-24.json")
TEMPLATE = os.path.join(BASE, "profiles", "common", "offering-profile.json")

_fail = 0


def check(name, cond, detail=""):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}{(': ' + detail) if detail else ''}")


def _load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---- CPO schema property paths -------------------------------------------------

def _schema_paths(schema):
    """Every `a.b.c` property path in the schema, following local $refs and
    array items. `contactInformation[Security]` style sources are checked by
    their base path plus the schema's own `contains` constraint."""
    paths = set()

    def resolve(node):
        if isinstance(node, dict) and "$ref" in node:
            tgt = schema
            for part in node["$ref"].lstrip("#/").split("/"):
                tgt = tgt.get(part, {}) if isinstance(tgt, dict) else {}
            return tgt
        return node

    def walk(node, prefix):
        node = resolve(node)
        if not isinstance(node, dict):
            return
        for k, v in (node.get("properties") or {}).items():
            path = f"{prefix}.{k}" if prefix else k
            paths.add(path)
            walk(v, path)
        if "items" in node:
            walk(node["items"], prefix)
        for branch in ("allOf", "anyOf", "oneOf"):
            for sub in node.get(branch) or []:
                walk(sub, prefix)

    walk(schema, "")
    return paths


def _contact_types_required(schema):
    """The contactType const values the schema's `contains` clauses demand."""
    out = set()
    ci = (schema.get("properties") or {}).get("contactInformation") or {}
    for clause in ci.get("allOf") or []:
        const = (((clause.get("contains") or {}).get("properties") or {})
                 .get("contactType") or {}).get("const")
        if const:
            out.add(const)
    return out


# ---- CR26 rule lookup ------------------------------------------------------------

def _rule_location(ds, rule_id):
    """FRR.<process>.data.<applicability>.<subset> for a rule id, or None. Rule
    ids are LEAF KEYS under the applicability branches (all / 20x / rev5)."""
    for proc, pnode in (ds.get("FRR") or {}).items():
        data = pnode.get("data") if isinstance(pnode, dict) else None
        for appl, anode in (data or {}).items():
            if not isinstance(anode, dict):
                continue
            for subset, snode in anode.items():
                if isinstance(snode, dict) and rule_id in snode:
                    return f"FRR.{proc}.data.{appl}.{subset}", snode[rule_id]
    return None, None


def _norm_key(phrase):
    """Mirror of sdr.py's `_norm_key`: text before any parenthetical, lowercase,
    non-alphanumerics to underscores."""
    import re
    head = phrase.split("(")[0]
    return re.sub(r"[^a-z0-9]+", "_", head.strip().lower()).strip("_")


def main():
    schema = _load(CPO_SCHEMA)
    ds = _load(pc.DATASET)
    template = _load(TEMPLATE)
    paths = _schema_paths(schema)
    contact_types = _contact_types_required(schema)

    print("required fields trace to a real FedRAMP source")
    for field, src, question in pc.REQUIRED_FIELDS:
        check(f"{field} has a plain-English question", bool(question and question.strip()))
        if src.startswith("cpo:"):
            path = src[4:]
            if "[" in path:
                base, ctype = path[:-1].split("[")
                check(f"{field} -> schema {base} contains a '{ctype}' contact",
                      base in paths and ctype in contact_types,
                      f"schema contact types required: {sorted(contact_types)}")
            else:
                check(f"{field} -> schema property {path} exists", path in paths)
        elif src.startswith("cr26:"):
            check(f"{field} -> structural ({src})", src == "cr26:varies_by_class")
        else:
            loc, _node = _rule_location(ds, src)
            check(f"{field} -> CR26 rule {src} exists", loc is not None)
            if loc:
                check(f"{field} -> {src} is in 20x scope (applicability all or 20x)",
                      ".data.all." in loc or ".data.20x." in loc, loc)

    print("class-conditional blocks trace to a real CR26 rule, with the dataset's class force")
    for block, src, classes, questions in pc.CLASS_CONDITIONAL:
        loc, node = _rule_location(ds, src)
        check(f"{block} -> CR26 rule {src} exists", loc is not None)
        check(f"{block} has at least one question", len(questions) >= 1)
        if not node:
            continue
        # Where the dataset varies the force by class, a block required at a
        # class must not be a MAY there (a MAY is never a blocker).
        vbc = node.get("varies_by_class") or {}
        for cls in classes:
            text = json.dumps(vbc.get(cls, "")) if vbc else json.dumps(node.get("force", ""))
            check(f"{block} at Class {cls.upper()} is not a MAY-only rule",
                  "MAY" not in text.upper() or "MUST" in text.upper() or "SHOULD" in text.upper(),
                  text[:120])

    print("CDS-CSO-PUB derivation covers the dataset's published items exactly")
    loc, pub = _rule_location(ds, "CDS-CSO-PUB")
    items = (pub or {}).get("following_information") or []
    dataset_keys = {_norm_key(p) for p in items}
    map_keys = set(pc.PUBLIC_INFORMATION_SOURCES)
    check("every dataset item has a derivation source", dataset_keys <= map_keys,
          f"missing: {sorted(dataset_keys - map_keys)}")
    check("no derivation source for an item the dataset does not list", map_keys <= dataset_keys,
          f"extra: {sorted(map_keys - dataset_keys)}")
    check("the dataset lists 16 CDS-CSO-PUB items (pinned anchor)", len(items) == 16, str(len(items)))
    for key, path in pc.PUBLIC_INFORMATION_SOURCES.items():
        src_field = path[0]
        known = ({f for f, _s, _q in pc.REQUIRED_FIELDS} | pc.OPTIONAL_FIELDS
                 | {"cpo_required_information"})
        check(f"derivation {key} reads a profile field the contract knows ({src_field})",
              src_field in known)

    print("the template profile matches the contract")
    for field, _src, _q in pc.REQUIRED_FIELDS:
        check(f"template carries required field {field}", field in template)
    for block, _src, _classes, questions in pc.CLASS_CONDITIONAL:
        if block in ("provider_verified_at", "overall_assessment_summary"):
            check(f"template carries {block}", block in template)
        elif block == "cpo_metadata":
            for sub, _q in questions:
                check(f"template carries {sub}", sub in template)
        else:
            node = template.get(block)
            check(f"template carries block {block} with every asked sub-field",
                  isinstance(node, dict) and all(sub in node for sub, _q in questions),
                  f"{block} keys: {sorted(node) if isinstance(node, dict) else node}")
    for field in pc.REMOVED_FIELDS:
        check(f"removed field {field} stays out of the template", field not in template)
    unknown = [k for k in template
               if k not in {f for f, _s, _q in pc.REQUIRED_FIELDS} and k not in pc.OPTIONAL_FIELDS]
    check("every template key is either required (traced) or declared optional", not unknown,
          f"untraced keys: {unknown}")
    check("no required template value is assistant-written example prose",
          not any(str(template.get(f, "")).startswith(("Example", "Reference architecture"))
                  for f, _s, _q in pc.REQUIRED_FIELDS))

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: profile traceability ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
