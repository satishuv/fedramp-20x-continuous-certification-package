# Tests for automation/assessment/gap_assessment.py. Offline: they use the
# deterministic --demo store and hand-built facts, never an AWS account.
import json
import os
import subprocess
import sys
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "automation", "assessment"))
import gap_assessment as ga  # noqa: E402

REGISTRY = ga.load_json(ga.REGISTRY)
PROFILE = ga.load_json(ga.KSI_PROFILE)


def test_applicable_counts_match_dataset_anchors():
    # Satish-verified anchors for dataset 2026.10.13.01: Class A resolves 7
    # KSIs, Class B 41 (46 minus the 5 marked Optional), Class C all 46.
    assert len(ga.applicable_ksis(PROFILE, "a")) == 7
    assert len(ga.applicable_ksis(PROFILE, "b")) == 41
    assert len(ga.applicable_ksis(PROFILE, "c")) == 46
    b_optional = set(ga.applicable_ksis(PROFILE, "c")) - set(ga.applicable_ksis(PROFILE, "b"))
    assert b_optional == {"KSI-CNA-EIS", "KSI-MLA-ALA", "KSI-SVC-PRR", "KSI-SVC-RUD", "KSI-SVC-VCM"}


def test_classify_every_status():
    collectable = {"checks": [{"collectable_now": True}]}
    doc_only = {"checks": [{"collectable_now": False, "provider_deployed": True}]}
    assert ga.classify(collectable, {"passing": 3, "total": 3}) == ga.PASSING
    assert ga.classify(collectable, {"passing": 1, "total": 3}) == ga.PARTIAL
    assert ga.classify(collectable, {"passing": 0, "total": 3}) == ga.FAILING
    assert ga.classify(collectable, None) == ga.NOT_OBSERVED
    assert ga.classify(doc_only, None) == ga.PROVIDER_EVIDENCE


def test_statuses_partition_every_applicable_ksi():
    store = ga.demo_store(REGISTRY)
    tmp = tempfile.mkdtemp(prefix="gap-t-")
    with open(os.path.join(tmp, "facts-us-east-1.json"), "w", encoding="utf-8") as f:
        json.dump(store, f)
    saved = ga.am.FACTS_DIR
    try:
        ga.am.FACTS_DIR = tmp
        cbr, pbs = ga.am.load_facts()
    finally:
        ga.am.FACTS_DIR = saved
    for cls, n in (("a", 7), ("b", 41), ("c", 46)):
        res = ga.assess(REGISTRY, PROFILE, cls, cbr, pbs, "test")
        assert res["meta"]["ksis_applicable"] == n
        assert sum(res["summary"]["counts"].values()) == n
        assert len(res["ksis"]) == n
        assert sum(f["ksis"] for f in res["families"]) == n


def test_scoring_agrees_with_metric_appender():
    """The gap view must never disagree with SDR-CSX-KMT metric history: both
    call datapoint_for_ksi on the same inputs."""
    store = ga.demo_store(REGISTRY)
    tmp = tempfile.mkdtemp(prefix="gap-t-")
    with open(os.path.join(tmp, "facts-us-east-1.json"), "w", encoding="utf-8") as f:
        json.dump(store, f)
    saved = ga.am.FACTS_DIR
    try:
        ga.am.FACTS_DIR = tmp
        cbr, pbs = ga.am.load_facts()
    finally:
        ga.am.FACTS_DIR = saved
    res = ga.assess(REGISTRY, PROFILE, "c", cbr, pbs, "test")
    for row in res["ksis"]:
        dp = ga.am.datapoint_for_ksi(REGISTRY["ksis"][row["ksi_id"]], cbr, pbs)
        if dp is None:
            assert row["total"] == 0
        else:
            assert (row["passing"], row["total"]) == (dp["passing"], dp["total"])


def test_non_compliant_in_one_region_cannot_hide_behind_another():
    kid = next(k for k, v in REGISTRY["ksis"].items()
               if any(c.get("type") == "config_managed_rule" for c in v["checks"]))
    rule = next(c["target"] for c in REGISTRY["ksis"][kid]["checks"]
                if c.get("type") == "config_managed_rule")
    cbr = {rule: [{"rule": rule, "region": "us-east-1", "compliance_type": "COMPLIANT"},
                  {"rule": rule, "region": "us-west-2", "compliance_type": "NON_COMPLIANT"}]}
    res = ga.assess(REGISTRY, PROFILE, "c", cbr, {}, "test")
    row = next(r for r in res["ksis"] if r["ksi_id"] == kid)
    assert row["status"] in (ga.PARTIAL, ga.FAILING)
    assert any("us-west-2" in x for x in row["failing_checks"])


def test_highest_risk_ranks_by_failing_checks_then_controls():
    store = ga.demo_store(REGISTRY)
    tmp = tempfile.mkdtemp(prefix="gap-t-")
    with open(os.path.join(tmp, "facts-us-east-1.json"), "w", encoding="utf-8") as f:
        json.dump(store, f)
    saved = ga.am.FACTS_DIR
    try:
        ga.am.FACTS_DIR = tmp
        cbr, pbs = ga.am.load_facts()
    finally:
        ga.am.FACTS_DIR = saved
    res = ga.assess(REGISTRY, PROFILE, "c", cbr, pbs, "test")
    keys = [(-(r["total"] - r["passing"]), -r["controls"], r["ksi_id"])
            for r in res["summary"]["highest_risk"]]
    assert keys == sorted(keys)
    assert all(r["status"] in (ga.FAILING, ga.PARTIAL) for r in res["summary"]["highest_risk"])


def test_html_is_ascii_labels_demo_and_avoids_status_words():
    out = tempfile.mkdtemp(prefix="gap-out-")
    rc = subprocess.run([sys.executable, os.path.join(BASE, "automation", "assessment",
                                                      "gap_assessment.py"),
                         "--class", "c", "--demo", "--out", out],
                        capture_output=True, text=True).returncode
    assert rc == 0
    with open(os.path.join(out, "gap-assessment-class-c.html"), encoding="utf-8") as f:
        page = f.read()
    assert all(ord(ch) < 128 for ch in page), "HTML must be ASCII-only"
    assert "DEMO DATA" in page
    assert "Of the <strong>46</strong> KSIs that apply at Class C" in page
    assert "not a compliance determination" in page
    # The record-store vocabulary is reserved for human sign-off.
    for word in ("Implemented", "Compliant with", "meets FedRAMP"):
        assert word not in page


def test_cli_refuses_to_run_without_a_facts_store():
    empty = tempfile.mkdtemp(prefix="gap-empty-")
    rc = subprocess.run([sys.executable, os.path.join(BASE, "automation", "assessment",
                                                      "gap_assessment.py"),
                         "--class", "b", "--facts-dir", empty, "--out", empty],
                        capture_output=True, text=True)
    assert rc.returncode == 3
    assert "collect_facts.py" in rc.stderr
