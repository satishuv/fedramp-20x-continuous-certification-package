#!/usr/bin/env python3
"""Import a Landing Zone Accelerator (LZA) configuration as declared observations.

A landing zone built with the Landing Zone Accelerator on AWS is described by a
set of YAML files (global-config.yaml, security-config.yaml, ...). Those files
state what the provider's platform is configured to do: which detection
services are enabled everywhere, which AWS Config rules are deployed, how
CloudTrail and the IAM password policy are set. That is first-rate material
for a KSI implementation narrative, and it exists already, so it should arrive
as a proposal rather than be typed again.

What it is NOT: evidence. A YAML file declares intent; it does not observe the
account. Everything this module emits is labelled "Landing zone configuration
declares ..." and lands only as KSI / rule OBSERVATIONS for the drafter. It
never produces a config fact or a posture fact, never contributes to a metric,
and never touches a status. The live collector or an export import is what
observes the account afterwards.

Files read (field names verified against the LZA Universal Configuration,
modules/base/default, and the LZA SecurityConfig / GlobalConfig references):
  security-config.yaml  centralSecurityServices.{guardduty, securityHub, macie,
                        ebsDefaultVolumeEncryption, s3PublicAccessBlock,
                        scpRevertChangesConfig}, accessAnalyzer,
                        iamPasswordPolicy, awsConfig.{enableConfigurationRecorder,
                        ruleSets[].rules[].{name, identifier, remediation}}
  global-config.yaml    homeRegion, enabledRegions, controlTower.{enable,
                        landingZone.logging.organizationTrail},
                        logging.{cloudtrail.{enable, organizationTrail,
                        organizationTrailSettings}, sessionManager},
                        cloudwatchLogRetentionInDays, backup.vaults
Other LZA files (network, iam, organization, customizations) are not read.

Mapping as data, through the framework's own routing, nothing new:
  - a declared Config rule's `identifier` resolves to a framework managed rule
    through the catalog identifiers pinned in
    automation/config-rules/known-config-managed-rules.json; the collector
    registry then says which KSIs carry that rule as a check. Identifiers the
    framework does not recognise are listed, never guessed.
  - a declared service (GuardDuty, Security Hub, Config, CloudTrail, Access
    Analyzer, IAM, S3, Backup) reaches exactly the KSIs whose registry
    `metric_service_keys` route that service, the same allowlist prefill and
    the metric engine use.
  - two dataset rules receive declared-architecture observations:
    VDR-CSO-ADT (automated detection services) and VDR-CSO-DFR (design
    decisions that mitigate vulnerabilities by default). Both ids are checked
    against the pinned dataset at import time.

The configuration carries no timestamp, so --observed-at (the date the files
were taken from the landing-zone repository) is required.

Usage:
  python automation/importers/import_landing_zone.py path/to/lza-config/ --observed-at 2026-10-01
  python automation/importers/import_landing_zone.py global-config.yaml security-config.yaml --observed-at 2026-10-01 --write
Exit codes: 0 ok, 1 refused input, 2 no observation time, 4 nothing declared
that the framework routes.
"""
import argparse
import hashlib
import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FACTS_DIR = os.path.join(BASE, "automation", "facts")
REGISTRY = os.path.join(BASE, "automation", "collectors", "registry.json")
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
VOCABULARY = os.path.join(BASE, "automation", "config-rules", "known-config-managed-rules.json")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from import_findings import (RefusedInput, catalog_identifiers, dataset_rule_ids,  # noqa: E402
                             iso, load_json, parse_ts, sha256_file)
sys.path.insert(0, os.path.join(BASE, "automation", "metrics"))
from method_ids import parse_service_key  # noqa: E402

EXIT_NOTHING_ROUTED = 4
SOURCE = "lza-config"
PREFIX = "Landing zone configuration declares"
FILE_KINDS = {"global-config": "global", "security-config": "security"}
OBSERVED_RULES = ("VDR-CSO-ADT", "VDR-CSO-DFR")


def load_yaml_file(path):
    try:
        import yaml  # PyYAML, declared in requirements.txt
    except ImportError as e:  # pragma: no cover - the dependency is pinned
        raise RefusedInput("PyYAML is not installed (pip install -r requirements.txt)") from e
    try:
        with open(path, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        raise RefusedInput(f"{path}: not readable YAML ({type(e).__name__})") from e
    if not isinstance(doc, dict):
        raise RefusedInput(f"{path}: expected a YAML mapping at the top level")
    return doc


def detect_kind(path):
    stem = os.path.splitext(os.path.basename(path))[0].lower()
    return FILE_KINDS.get(stem)


def resolve_inputs(paths):
    """Accept a directory (picks the known files) or explicit files."""
    files = []
    for p in paths:
        if os.path.isdir(p):
            for fn in sorted(os.listdir(p)):
                if detect_kind(fn) and fn.lower().endswith((".yaml", ".yml")):
                    files.append(os.path.join(p, fn))
        else:
            files.append(p)
    if not files:
        raise RefusedInput("no global-config.yaml or security-config.yaml found")
    by_kind = {}
    manifest = []
    for p in files:
        kind = detect_kind(p)
        if kind is None:
            raise RefusedInput(f"{p}: not a file this importer reads "
                               "(global-config.yaml or security-config.yaml)")
        if kind in by_kind:
            raise RefusedInput(f"two {kind}-config files given; pass one landing zone at a time")
        by_kind[kind] = load_yaml_file(p)
        manifest.append({"name": os.path.basename(p), "sha256": sha256_file(p),
                         "kind": f"lza-{kind}-config"})
    return by_kind, manifest


def _get(d, *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def _on(d, *keys):
    return _get(d, *keys, default=None) is True


# ---- Declared signals, per service -------------------------------------------

def declared_services(security, global_cfg):
    """{service key: [declared sentence, ...]} using the collectors' service
    keys (securityhub, guardduty, config, cloudtrail, accessanalyzer, iam, s3,
    backup) so they route through the registry allowlist."""
    out = {}
    css = _get(security, "centralSecurityServices", default={}) or {}
    gd = css.get("guardduty") or {}
    if isinstance(gd, dict) and "enable" in gd:
        parts = [f"GuardDuty {'enabled' if gd.get('enable') is True else 'disabled'} for the organization"]
        if gd.get("enable") is True:
            if _on(gd, "s3Protection", "enable"):
                parts.append("S3 protection on")
            if _on(gd, "eksProtection", "enable"):
                parts.append("EKS protection on")
            if _on(gd, "exportConfiguration", "enable"):
                parts.append(f"findings exported to {_get(gd, 'exportConfiguration', 'destinationType') or 'a destination'}"
                             + (f" every {_get(gd, 'exportConfiguration', 'exportFrequency')}"
                                if _get(gd, "exportConfiguration", "exportFrequency") else ""))
            ex = gd.get("excludeRegions") or []
            if ex:
                parts.append(f"{len(ex)} region(s) excluded")
        out.setdefault("guardduty", []).append(f"{PREFIX} " + "; ".join(parts) + ".")
    sh = css.get("securityHub") or {}
    if isinstance(sh, dict) and "enable" in sh:
        parts = [f"Security Hub {'enabled' if sh.get('enable') is True else 'disabled'} for the organization"]
        if sh.get("enable") is True:
            if sh.get("regionAggregation") is True:
                parts.append("cross-region aggregation on")
            names = [str(s.get("name")) for s in (sh.get("standards") or [])
                     if isinstance(s, dict) and s.get("enable") is True and s.get("name")]
            if names:
                parts.append("standards enabled: " + ", ".join(names))
            ex = sh.get("excludeRegions") or []
            if ex:
                parts.append(f"{len(ex)} region(s) excluded")
        out.setdefault("securityhub", []).append(f"{PREFIX} " + "; ".join(parts) + ".")
    if _on(security, "accessAnalyzer", "enable"):
        out.setdefault("accessanalyzer", []).append(
            f"{PREFIX} IAM Access Analyzer enabled for the organization.")
    pp = security.get("iamPasswordPolicy") if isinstance(security, dict) else None
    if isinstance(pp, dict) and pp:
        bits = []
        if "minimumPasswordLength" in pp:
            bits.append(f"minimum length {pp['minimumPasswordLength']}")
        if "passwordReusePrevention" in pp:
            bits.append(f"reuse prevention {pp['passwordReusePrevention']}")
        if "maxPasswordAge" in pp:
            bits.append(f"maximum age {pp['maxPasswordAge']} days")
        req = [k.replace("require", "").lower() for k in
               ("requireUppercaseCharacters", "requireLowercaseCharacters",
                "requireSymbols", "requireNumbers") if pp.get(k) is True]
        if req:
            bits.append("requires " + ", ".join(req))
        out.setdefault("iam", []).append(
            f"{PREFIX} an IAM password policy: " + "; ".join(bits) + ".")
    if _on(css, "s3PublicAccessBlock", "enable"):
        ex = _get(css, "s3PublicAccessBlock", "excludeAccounts", default=[]) or []
        out.setdefault("s3", []).append(
            f"{PREFIX} account-level S3 Block Public Access enabled"
            + (f" ({len(ex)} account(s) excluded)" if ex else "") + ".")
    cfg = security.get("awsConfig") if isinstance(security, dict) else None
    if isinstance(cfg, dict) and "enableConfigurationRecorder" in cfg:
        out.setdefault("config", []).append(
            f"{PREFIX} the AWS Config configuration recorder "
            f"{'enabled' if cfg.get('enableConfigurationRecorder') is True else 'not enabled'} "
            "by the accelerator"
            + (" (Control Tower manages Config in enrolled accounts)"
               if _on(global_cfg, "controlTower", "enable") else "") + ".")
    # CloudTrail: in a Control Tower landing zone the organization trail is
    # Control Tower's; LZA's own trail block is then disabled. Read both.
    ct_lz = _on(global_cfg, "controlTower", "landingZone", "logging", "organizationTrail")
    lza_ct = _get(global_cfg, "logging", "cloudtrail", default={}) or {}
    lza_org = lza_ct.get("organizationTrail") is True and lza_ct.get("enable") is True
    if ct_lz or lza_org or ("enable" in lza_ct):
        if ct_lz:
            parts = ["an organization-wide CloudTrail trail managed by AWS Control Tower"]
        elif lza_org:
            parts = ["an organization-wide CloudTrail trail managed by the accelerator"]
            st = lza_ct.get("organizationTrailSettings") or {}
            on = [k for k in ("multiRegionTrail", "globalServiceEvents", "managementEvents",
                              "s3DataEvents", "lambdaDataEvents", "sendToCloudWatchLogs")
                  if st.get(k) is True]
            if on:
                parts.append("settings on: " + ", ".join(on))
        else:
            parts = ["no organization-wide CloudTrail trail (accelerator trail disabled)"]
        acct = _get(global_cfg, "logging", "account")
        if acct:
            parts.append(f"centralized logging account: {acct}")
        ret = global_cfg.get("cloudwatchLogRetentionInDays") if isinstance(global_cfg, dict) else None
        if ret is not None:
            parts.append(f"CloudWatch Logs retention {ret} days")
        sm = _get(global_cfg, "logging", "sessionManager", default={}) or {}
        if sm.get("sendToCloudWatchLogs") is True or sm.get("sendToS3") is True:
            dest = [d for d, k in (("CloudWatch Logs", "sendToCloudWatchLogs"), ("S3", "sendToS3"))
                    if sm.get(k) is True]
            parts.append("Session Manager activity logged to " + " and ".join(dest))
        out.setdefault("cloudtrail", []).append(f"{PREFIX} " + "; ".join(parts) + ".")
    vaults = _get(global_cfg, "backup", "vaults", default=[]) or []
    if vaults:
        out.setdefault("backup", []).append(
            f"{PREFIX} {len(vaults)} AWS Backup vault(s) deployed by the accelerator.")
    return out


def declared_defaults(security):
    """By-default mitigations for VDR-CSO-DFR: encryption and public-access
    defaults, SCP integrity, Macie."""
    css = _get(security, "centralSecurityServices", default={}) or {}
    bits = []
    if _on(css, "ebsDefaultVolumeEncryption", "enable"):
        bits.append("EBS default volume encryption")
    if _on(css, "s3PublicAccessBlock", "enable"):
        bits.append("account-level S3 Block Public Access")
    if _on(css, "scpRevertChangesConfig", "enable"):
        bits.append("automatic revert of manual service control policy changes")
    if _on(css, "macie", "enable"):
        bits.append("Macie sensitive-data discovery")
    if _on(security, "ssmSettings", "blockPublicDocumentSharing", "enable"):
        bits.append("blocked public sharing of Systems Manager documents")
    return bits


def declared_config_rules(security, by_identifier, registry):
    """(mapped, unrecognised): mapped is {framework id: {"identifiers", "names",
    "remediation"}} for declared rules the framework recognises; unrecognised
    lists catalog identifiers it does not. Rule names carry accelerator
    prefixes, so the catalog identifier is the join key."""
    mapped = {}
    unrecognised = []
    total = 0
    for rs in _get(security, "awsConfig", "ruleSets", default=[]) or []:
        for rule in (rs.get("rules") or []) if isinstance(rs, dict) else []:
            if not isinstance(rule, dict):
                continue
            total += 1
            ident = str(rule.get("identifier") or "").strip()
            fid = by_identifier.get(ident) if ident else None
            if fid is None:
                unrecognised.append(ident or str(rule.get("name")))
                continue
            m = mapped.setdefault(fid, {"identifier": ident, "names": [], "remediation": False})
            m["names"].append(str(rule.get("name")))
            if isinstance(rule.get("remediation"), dict):
                m["remediation"] = True
    return mapped, sorted(set(unrecognised)), total


def route_to_ksis(registry, services, mapped_rules):
    """KSI observations through the registry's own routing."""
    obs = {}
    for kid, entry in registry["ksis"].items():
        routed = set()
        for key in entry.get("metric_service_keys") or []:
            service, _check = parse_service_key(key)
            routed.add(service)
        texts = []
        for service in sorted(routed):
            texts.extend(services.get(service, []))
        rule_ids = sorted({c["target"] for c in entry.get("checks", [])
                           if c.get("type") == "config_managed_rule" and c.get("target") in mapped_rules})
        if rule_ids:
            auto = [r for r in rule_ids if mapped_rules[r]["remediation"]]
            texts.append(f"{PREFIX} AWS Config rule(s) this indicator relies on: "
                         + ", ".join(rule_ids)
                         + (f" (automated remediation declared for {', '.join(auto)})" if auto else "")
                         + ".")
        if texts:
            obs[kid] = texts
    return obs


def build_store(paths, observed_at, registry_path=REGISTRY, vocabulary_path=VOCABULARY,
                dataset_path=DATASET):
    explicit = parse_ts(observed_at) if observed_at else None
    if observed_at and explicit is None:
        raise RefusedInput(f"--observed-at {observed_at!r} is not an ISO-8601 time")
    if explicit is None:
        return None
    observed_iso = iso(explicit)
    by_kind, manifest = resolve_inputs(paths)
    security = by_kind.get("security") or {}
    global_cfg = by_kind.get("global") or {}
    registry = load_json(registry_path)
    by_identifier = catalog_identifiers(vocabulary_path)

    services = declared_services(security, global_cfg)
    mapped_rules, unrecognised, total_rules = declared_config_rules(security, by_identifier, registry)
    ksi_texts = route_to_ksis(registry, services, mapped_rules)

    def wrap(texts):
        return [{"observed_at": observed_iso, "source": SOURCE, "text": t} for t in texts]

    ksi_observations = {k: wrap(v) for k, v in sorted(ksi_texts.items())}
    rule_observations = {}
    detect = [s for s in ("guardduty", "securityhub", "config", "accessanalyzer") if s in services]
    if detect or mapped_rules:
        rule_observations["VDR-CSO-ADT"] = wrap([
            f"{PREFIX} automated detection services for the organization: "
            + ", ".join({"guardduty": "GuardDuty", "securityhub": "Security Hub",
                         "config": "AWS Config", "accessanalyzer": "IAM Access Analyzer"}[s]
                        for s in detect)
            + (f"; {total_rules} AWS Config rule(s) declared, {len(mapped_rules)} of them "
               "framework-recognised" if total_rules else "") + "."])
    defaults = declared_defaults(security)
    if defaults:
        rule_observations["VDR-CSO-DFR"] = wrap([
            f"{PREFIX} by-default mitigations: " + ", ".join(defaults) + "."])
    bad = sorted(set(rule_observations) - dataset_rule_ids(dataset_path))
    if bad:
        raise RefusedInput(f"observation rule ids not in the pinned dataset: {bad}")

    digest = hashlib.sha256("|".join(f["sha256"] for f in manifest).encode("utf-8")).hexdigest()
    return {
        "meta": {
            "collected_at": observed_iso,
            "run_id": "import-lza-" + digest[:16],
            "region": str(global_cfg.get("homeRegion") or "global"),
            "identity_arn": None,
            "source": SOURCE,
            "import_files": manifest,
            "observed_at_source": "explicit",
            "landing_zone": {
                "home_region": global_cfg.get("homeRegion"),
                "enabled_regions": len(global_cfg.get("enabledRegions") or [])
                if isinstance(global_cfg.get("enabledRegions"), list) else None,
                "control_tower": _on(global_cfg, "controlTower", "enable"),
                "config_rules_declared": total_rules,
                "config_rules_recognised": sorted(mapped_rules),
                "config_rule_identifiers_unrecognised": unrecognised,
                "services_declared": sorted(services),
            },
            "collection_outcome": {"evaluated": 0, "unevaluated": 0, "errors": 0,
                                   "status": "DECLARED_ONLY"},
            "note": ("Declared configuration imported from Landing Zone Accelerator files; "
                     "intent for the narrative, never evidence, never a status. "
                     "Never commit this file."),
        },
        "facts": [],
        "posture_facts": [],
        "ksi_observations": ksi_observations,
        "rule_observations": rule_observations,
    }


def out_path(facts_dir):
    return os.path.join(facts_dir, "facts-landing-zone-import.json")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Import LZA configuration files as declared KSI / rule observations (offline).")
    ap.add_argument("paths", nargs="+",
                    help="an LZA config directory, or global-config.yaml / security-config.yaml")
    ap.add_argument("--observed-at", default=None,
                    help="ISO-8601 date the files were taken from the landing-zone repository")
    ap.add_argument("--write", action="store_true",
                    help="write automation/facts/facts-landing-zone-import.json")
    ap.add_argument("--out-dir", default=FACTS_DIR, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    try:
        store = build_store(args.paths, args.observed_at)
    except RefusedInput as e:
        print(f"Import refused: {e}")
        return 1
    if store is None:
        print("A landing-zone configuration carries no timestamp. Pass --observed-at "
              "<ISO-8601> for the date the files were taken from the repository.")
        return 2
    m = store["meta"]
    lz = m["landing_zone"]
    print(f"files: {', '.join(f['name'] for f in m['import_files'])}; declared as of "
          f"{m['collected_at']}; home region {lz['home_region']}, "
          f"{lz['enabled_regions']} enabled region(s), Control Tower "
          f"{'on' if lz['control_tower'] else 'off'}")
    print(f"services declared: {', '.join(lz['services_declared']) or 'none'}")
    print(f"Config rules declared: {lz['config_rules_declared']}; framework-recognised: "
          f"{len(lz['config_rules_recognised'])}")
    for r in lz["config_rules_recognised"]:
        print(f"  {r}")
    if lz["config_rule_identifiers_unrecognised"]:
        print(f"{len(lz['config_rule_identifiers_unrecognised'])} declared identifier(s) the "
              "framework does not reference (left as is): "
              + ", ".join(lz["config_rule_identifiers_unrecognised"][:10])
              + (" ..." if len(lz["config_rule_identifiers_unrecognised"]) > 10 else ""))
    print(f"KSIs receiving declared observations: {len(store['ksi_observations'])}; "
          f"rules: {', '.join(sorted(store['rule_observations'])) or 'none'}")
    for kid, items in sorted(store["ksi_observations"].items()):
        print(f"  {kid}: {len(items)} declaration(s)")
    if args.write:
        os.makedirs(args.out_dir, exist_ok=True)
        path = out_path(args.out_dir)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(store, fh, indent=1)
        print(f"wrote {os.path.relpath(path, BASE)} (git-excluded). Next: "
              "python automation/ai/draft_narratives.py --write, then "
              "python sdr.py review --walk.")
    else:
        print("dry run; pass --write to store these observations.")
    if not store["ksi_observations"] and not store["rule_observations"]:
        print("FAIL. Nothing declared that the framework routes to a KSI or rule.")
        return EXIT_NOTHING_ROUTED
    return 0


if __name__ == "__main__":
    sys.exit(main())
