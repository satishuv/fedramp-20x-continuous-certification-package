#!/usr/bin/env python3
"""Offline tests for the Landing Zone Accelerator configuration importer.

The fixture mirrors the LZA Universal Configuration (modules/base/default):
security-config.yaml centralSecurityServices / accessAnalyzer /
iamPasswordPolicy / awsConfig.ruleSets, global-config.yaml controlTower /
logging / backup. Run:
    python automation/importers/test_import_landing_zone.py
"""
import copy
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(BASE, "automation", "ai"))
import import_landing_zone as lz  # noqa: E402
import draft_narratives as dn  # noqa: E402

REGISTRY = json.load(open(lz.REGISTRY, encoding="utf-8"))
RECORD_STORE = json.load(open(os.path.join(BASE, "sdr", "records", "records-store.json"),
                              encoding="utf-8"))
SECRET_EMAIL = "soc-alerts@acme.example"

SECURITY = """
centralSecurityServices:
  delegatedAdminAccount: Audit
  ebsDefaultVolumeEncryption:
    enable: true
    excludeRegions: []
  s3PublicAccessBlock:
    enable: true
    excludeAccounts: []
  scpRevertChangesConfig:
    enable: true
  macie:
    enable: true
  guardduty:
    enable: true
    excludeRegions: []
    s3Protection:
      enable: true
    eksProtection:
      enable: false
    exportConfiguration:
      enable: true
      destinationType: S3
      exportFrequency: SIX_HOURS
  securityHub:
    enable: true
    regionAggregation: true
    standards:
      - name: AWS Foundational Security Best Practices v1.0.0
        enable: true
      - name: NIST Special Publication 800-53 Revision 5
        enable: true
      - name: CIS AWS Foundations Benchmark v1.2.0
        enable: false
accessAnalyzer:
  enable: true
iamPasswordPolicy:
  requireUppercaseCharacters: true
  requireLowercaseCharacters: true
  requireSymbols: true
  requireNumbers: true
  minimumPasswordLength: 14
  passwordReusePrevention: 24
  maxPasswordAge: 90
awsConfig:
  enableConfigurationRecorder: true
  useServiceLinkedRole: true
  ruleSets:
    - deploymentTargets:
        organizationalUnits: [Root]
      rules:
        - name: "{{ AcceleratorPrefix }}-cloudtrail-enabled"
          identifier: CLOUD_TRAIL_ENABLED
        - name: "{{ AcceleratorPrefix }}-restricted-ssh"
          identifier: INCOMING_SSH_DISABLED
        - name: "{{ AcceleratorPrefix }}-emr-kerberos-enabled"
          identifier: EMR_KERBEROS_ENABLED
        - name: "{{ AcceleratorPrefix }}-encrypted-volumes"
          identifier: ENCRYPTED_VOLUMES
          remediation:
            automatic: true
            targetId: "{{ AcceleratorPrefix }}-Fix"
    - deploymentTargets:
        accounts: [Management]
      rules:
        - name: "{{ AcceleratorPrefix }}-cloudwatch-log-group-encrypted"
          identifier: CLOUDWATCH_LOG_GROUP_ENCRYPTED
"""

GLOBAL = """
homeRegion: us-gov-west-1
enabledRegions:
  - us-gov-west-1
  - us-gov-east-1
cloudwatchLogRetentionInDays: 365
controlTower:
  enable: true
  landingZone:
    version: "4.0"
    logging:
      loggingBucketRetentionDays: 365
      organizationTrail: true
snsTopics:
  topics:
    - name: SecurityHigh
      emailAddresses:
        - %s
backup:
  vaults:
    - name: "{{ AcceleratorPrefix }}-BackupVault"
logging:
  account: LogArchive
  cloudtrail:
    enable: false
    organizationTrail: false
  sessionManager:
    sendToCloudWatchLogs: true
    sendToS3: false
""" % SECRET_EMAIL


def write_configs(tmp, security=SECURITY, global_cfg=GLOBAL):
    paths = []
    for name, text in (("security-config.yaml", security), ("global-config.yaml", global_cfg)):
        if text is None:
            continue
        p = os.path.join(tmp, name)
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        paths.append(p)
    return paths


def _store(tmp, **kw):
    write_configs(tmp, **kw)
    return lz.build_store([tmp], "2026-10-01")


def test_directory_input_picks_the_two_known_files_only():
    with tempfile.TemporaryDirectory() as tmp:
        write_configs(tmp)
        open(os.path.join(tmp, "network-config.yaml"), "w").write("vpcs: []\n")
        by_kind, manifest = lz.resolve_inputs([tmp])
    assert set(by_kind) == {"security", "global"}
    assert sorted(m["kind"] for m in manifest) == ["lza-global-config", "lza-security-config"]


def test_unknown_file_and_bad_yaml_are_refused():
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "iam-config.yaml")
        open(p, "w").write("x: 1\n")
        for paths in ([p], ):
            try:
                lz.resolve_inputs(paths)
                raised = False
            except lz.RefusedInput:
                raised = True
            assert raised
        bad = os.path.join(tmp, "security-config.yaml")
        open(bad, "w").write("centralSecurityServices: [unclosed\n")
        try:
            lz.resolve_inputs([bad])
            raised = False
        except lz.RefusedInput:
            raised = True
        assert raised
        try:
            lz.resolve_inputs([os.path.join(tmp, "empty")])
            raised = False
        except lz.RefusedInput:
            raised = True
        assert raised


def test_declared_services_read_verified_fields():
    import yaml
    sec = yaml.safe_load(SECURITY)
    glo = yaml.safe_load(GLOBAL)
    s = lz.declared_services(sec, glo)
    assert set(s) == {"guardduty", "securityhub", "accessanalyzer", "iam", "s3", "config",
                      "cloudtrail", "backup"}
    gd = s["guardduty"][0]
    assert gd.startswith(lz.PREFIX) and "S3 protection on" in gd and "EKS protection" not in gd
    assert "exported to S3 every SIX_HOURS" in gd
    sh = s["securityhub"][0]
    assert "cross-region aggregation on" in sh
    assert "AWS Foundational Security Best Practices v1.0.0, NIST Special Publication 800-53 Revision 5" in sh
    assert "CIS" not in sh  # disabled standard not listed
    assert "minimum length 14; reuse prevention 24; maximum age 90 days" in s["iam"][0]
    ct = s["cloudtrail"][0]
    assert "managed by AWS Control Tower" in ct  # LZA trail off, Control Tower trail on
    assert "centralized logging account: LogArchive" in ct
    assert "CloudWatch Logs retention 365 days" in ct
    assert "Session Manager activity logged to CloudWatch Logs" in ct
    assert "Control Tower manages Config" in s["config"][0]
    assert "1 AWS Backup vault(s)" in s["backup"][0]


def test_lza_managed_trail_settings_when_control_tower_absent():
    import yaml
    glo = yaml.safe_load(GLOBAL)
    glo["controlTower"]["enable"] = False
    del glo["controlTower"]["landingZone"]
    glo["logging"]["cloudtrail"] = {"enable": True, "organizationTrail": True,
                                    "organizationTrailSettings": {"multiRegionTrail": True,
                                                                  "managementEvents": True,
                                                                  "s3DataEvents": False}}
    s = lz.declared_services(yaml.safe_load(SECURITY), glo)
    ct = s["cloudtrail"][0]
    assert "managed by the accelerator" in ct and "multiRegionTrail, managementEvents" in ct
    assert "s3DataEvents" not in ct
    assert "Control Tower manages Config" not in s["config"][0]


def test_config_rules_resolve_by_catalog_identifier_never_by_name():
    import yaml
    by_ident = lz.catalog_identifiers()
    mapped, unrecognised, total = lz.declared_config_rules(yaml.safe_load(SECURITY), by_ident, REGISTRY)
    assert total == 5
    assert set(mapped) == {"cloudtrail-enabled", "restricted-ssh", "encrypted-volumes",
                           "cloudwatch-log-group-encrypted"}
    assert mapped["restricted-ssh"]["identifier"] == "INCOMING_SSH_DISABLED"  # irregular id
    assert mapped["encrypted-volumes"]["remediation"] is True
    assert mapped["cloudtrail-enabled"]["remediation"] is False
    assert unrecognised == ["EMR_KERBEROS_ENABLED"]


def test_routing_uses_the_registry_allowlist_and_checks_only():
    with tempfile.TemporaryDirectory() as tmp:
        store = _store(tmp)
    obs = store["ksi_observations"]
    assert obs, "declared services must reach at least one KSI"
    for kid, items in obs.items():
        entry = REGISTRY["ksis"][kid]
        routed = {k.split(":")[0] for k in entry.get("metric_service_keys") or []}
        targets = {c["target"] for c in entry["checks"] if c.get("type") == "config_managed_rule"}
        for o in items:
            text = o["text"]
            assert text.startswith(lz.PREFIX), text
            if "AWS Config rule(s) this indicator relies on" in text:
                named = text.split("relies on: ", 1)[1].split(" (")[0].rstrip(".").split(", ")
                assert set(named) <= targets, (kid, named)
            else:
                svc = {"GuardDuty": "guardduty", "Security Hub": "securityhub",
                       "IAM Access Analyzer": "accessanalyzer", "IAM password": "iam",
                       "S3 Block Public": "s3", "configuration recorder": "config",
                       "CloudTrail": "cloudtrail", "Backup vault": "backup"}
                hit = [v for k, v in svc.items() if k in text]
                assert hit and hit[0] in routed, (kid, text[:80], routed)
    # KSI-MLA-OSM routes securityhub:siem_aggregation and cloudtrail:siem_capture.
    osm = " ".join(o["text"] for o in obs["KSI-MLA-OSM"])
    assert "Security Hub enabled" in osm and "CloudTrail trail" in osm
    # KSI-SVC-SIN carries encrypted-volumes as a config check.
    sin = " ".join(o["text"] for o in obs["KSI-SVC-SIN"])
    assert "encrypted-volumes" in sin and "automated remediation declared for encrypted-volumes" in sin


def test_rule_observations_are_dataset_ids_and_declared_wording():
    with tempfile.TemporaryDirectory() as tmp:
        store = _store(tmp)
    ro = store["rule_observations"]
    assert set(ro) == {"VDR-CSO-ADT", "VDR-CSO-DFR"}
    adt = ro["VDR-CSO-ADT"][0]["text"]
    assert "GuardDuty, Security Hub, AWS Config, IAM Access Analyzer" in adt
    assert "5 AWS Config rule(s) declared, 4 of them framework-recognised" in adt
    dfr = ro["VDR-CSO-DFR"][0]["text"]
    assert "EBS default volume encryption" in dfr and "service control policy" in dfr
    assert "Macie" in dfr
    ids = lz.dataset_rule_ids()
    assert set(ro) <= ids


def test_declared_never_becomes_a_fact_or_metric_and_nothing_identifying_leaks():
    with tempfile.TemporaryDirectory() as tmp:
        store = _store(tmp)
    assert store["facts"] == [] and store["posture_facts"] == []
    assert store["meta"]["collection_outcome"]["status"] == "DECLARED_ONLY"
    assert store["meta"]["collection_outcome"]["evaluated"] == 0
    blob = json.dumps(store)
    assert SECRET_EMAIL not in blob
    assert store["meta"]["landing_zone"]["control_tower"] is True
    assert store["meta"]["landing_zone"]["enabled_regions"] == 2
    assert store["meta"]["region"] == "us-gov-west-1"


def test_drafter_quotes_declared_configuration_with_boundary_intact():
    with tempfile.TemporaryDirectory() as tmp:
        store = _store(tmp)
    rec = copy.deepcopy(RECORD_STORE["ksi"]["KSI-SVC-SIN"])
    rec["implementation"] = ["TBD: Information has not been provided."]
    rec["validation"] = ["TBD: Information has not been provided."]
    entry = REGISTRY["ksis"]["KSI-SVC-SIN"]
    changed, notes = dn.draft_ksi("KSI-SVC-SIN", rec, entry, {}, dn.TemplateDrafter(), {},
                                  store["ksi_observations"]["KSI-SVC-SIN"])
    assert changed and notes[0].endswith("(template + imported observations)")
    text = rec["implementation"][0]
    assert text.startswith(dn.DRAFT_LABEL)
    assert "[lza-config, 2026-10-01] Landing zone configuration declares" in text
    for field in dn.FORBIDDEN_FIELDS:
        assert rec.get(field) == RECORD_STORE["ksi"]["KSI-SVC-SIN"].get(field)


def test_security_only_and_global_only_inputs_work():
    with tempfile.TemporaryDirectory() as tmp:
        write_configs(tmp, global_cfg=None)
        store = lz.build_store([tmp], "2026-10-01")
        assert store["ksi_observations"] and store["meta"]["region"] == "global"
    with tempfile.TemporaryDirectory() as tmp:
        write_configs(tmp, security=None)
        store = lz.build_store([tmp], "2026-10-01")
        assert "KSI-MLA-OSM" in store["ksi_observations"]  # CloudTrail route
        assert "VDR-CSO-DFR" not in store["rule_observations"]


def _run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = lz.main(argv)
    return code, buf.getvalue()


def test_cli_requires_observed_at_and_writes():
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "facts")
        paths = write_configs(tmp)
        code, text = _run(paths + ["--out-dir", out])
        assert code == 2 and "--observed-at" in text
        code, text = _run(paths + ["--out-dir", out, "--observed-at", "2026-10-01", "--write"])
        assert code == 0
        saved = json.load(open(lz.out_path(out), encoding="utf-8"))
        assert saved["meta"]["run_id"].startswith("import-lza-")
        code, text = _run([tmp, "--out-dir", out, "--observed-at", "nope"])
        assert code == 1 and "Import refused" in text
        empty = os.path.join(tmp, "nothing")
        os.makedirs(empty)
        open(os.path.join(empty, "security-config.yaml"), "w").write("cloudWatch: {}\n")
        code, text = _run([empty, "--out-dir", out, "--observed-at", "2026-10-01"])
        assert code == lz.EXIT_NOTHING_ROUTED


def main():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
