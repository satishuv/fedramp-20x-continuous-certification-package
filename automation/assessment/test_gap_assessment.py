# Tests for automation/assessment/gap_assessment.py (Class C only). Offline:
# they use the deterministic --demo store and hand-built facts, never an AWS
# account.
import json
import os
import subprocess
import sys
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCRIPT = os.path.join(BASE, "automation", "assessment", "gap_assessment.py")
sys.path.insert(0, os.path.join(BASE, "automation", "assessment"))
import gap_assessment as ga  # noqa: E402

REGISTRY = ga.load_json(ga.REGISTRY)
PROFILE = ga.load_json(ga.KSI_PROFILE)


def _demo_inputs():
    store = ga.demo_store(REGISTRY)
    tmp = tempfile.mkdtemp(prefix="gap-t-")
    with open(os.path.join(tmp, "facts-us-east-1.json"), "w", encoding="utf-8") as f:
        json.dump(store, f)
    saved = ga.am.FACTS_DIR
    try:
        ga.am.FACTS_DIR = tmp
        return ga.am.load_facts()
    finally:
        ga.am.FACTS_DIR = saved


def test_all_46_ksis_apply_and_minimum_is_two_methods():
    # Dataset anchors for 2026.10.13.01: 46 KSIs in 10 families; FRC-CSX-VVK
    # Class C minimum of 2 automated validation methods per KSI.
    app = ga.applicable_ksis(PROFILE)
    assert len(app) == 46
    assert len({ind["family"] for ind in app.values()}) == 10
    assert all(ga.min_methods(ind) == 2 for ind in app.values())


def test_classify_every_status():
    collectable = {"checks": [{"collectable_now": True}]}
    doc_only = {"checks": [{"collectable_now": False, "provider_deployed": True}]}
    assert ga.classify(collectable, {"passing": 3, "total": 3}) == ga.PASSING
    assert ga.classify(collectable, {"passing": 1, "total": 3}) == ga.PARTIAL
    assert ga.classify(collectable, {"passing": 0, "total": 3}) == ga.FAILING
    assert ga.classify(collectable, None) == ga.NOT_OBSERVED
    assert ga.classify(doc_only, None) == ga.PROVIDER_EVIDENCE


def test_statuses_partition_every_ksi():
    cbr, pbs = _demo_inputs()
    res = ga.assess(REGISTRY, PROFILE, cbr, pbs, "test")
    assert res["meta"]["class"] == "C"
    assert res["meta"]["ksis_applicable"] == 46
    assert sum(res["summary"]["counts"].values()) == 46
    assert len(res["ksis"]) == 46
    assert sum(f["ksis"] for f in res["families"]) == 46


def test_scoring_agrees_with_metric_appender():
    """The gap view must never disagree with SDR-CSX-KMT metric history: both
    call datapoint_for_ksi on the same inputs."""
    cbr, pbs = _demo_inputs()
    res = ga.assess(REGISTRY, PROFILE, cbr, pbs, "test")
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
    res = ga.assess(REGISTRY, PROFILE, cbr, {}, "test")
    row = next(r for r in res["ksis"] if r["ksi_id"] == kid)
    assert row["status"] in (ga.PARTIAL, ga.FAILING)
    assert any("us-west-2" in x for x in row["failing_checks"])


def test_highest_risk_ranks_by_failing_checks_then_controls():
    cbr, pbs = _demo_inputs()
    res = ga.assess(REGISTRY, PROFILE, cbr, pbs, "test")
    keys = [(-(r["total"] - r["passing"]), -r["controls"], r["ksi_id"])
            for r in res["summary"]["highest_risk"]]
    assert keys == sorted(keys)
    assert all(r["status"] in (ga.FAILING, ga.PARTIAL) for r in res["summary"]["highest_risk"])


def test_html_is_ascii_labels_demo_and_avoids_status_words():
    out = tempfile.mkdtemp(prefix="gap-out-")
    rc = subprocess.run([sys.executable, SCRIPT, "--demo", "--out", out],
                        capture_output=True, text=True).returncode
    assert rc == 0
    with open(os.path.join(out, "gap-assessment.html"), encoding="utf-8") as f:
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
    rc = subprocess.run([sys.executable, SCRIPT, "--facts-dir", empty, "--out", empty],
                        capture_output=True, text=True)
    assert rc.returncode == 3
    assert "collect_facts.py" in rc.stderr
