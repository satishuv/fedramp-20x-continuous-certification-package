"""Fail-closed collection loop: regressions for review items 2, 3 and 4.

Offline, no account. Covers:
  AUD-F29  collect_facts: a run with zero evaluated outcomes is a FAILED run
           (exit 4), never an empty success.
  AUD-F31  living-sdr-loop.yml: the ephemeral Actions runner RESTORES and
           PUBLISHES the durable metric history and REFUSES to run without a
           persistence target, so a night's datapoints are never discarded.
  AUD-F32  both scheduled loops alarm on failure: the Actions loop files an
           issue, the AWS template notifies on a failed collector/drift build.
  AUD-F34  the single release-gate definition audits the hash-locked closure
           for known vulnerabilities (pip-audit), on every gate path.
  AUD-F43  drift-check.yml: the adoption hand-off is fail-visible. A refused
           push is an error; a refused PR creation posts the branch, compare
           link and review body on the drift issue and exits non-zero.

Run: python automation/collectors/test_collection_fail_closed.py
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(BASE, "audit"))

import collect_facts as cf  # noqa: E402
import release_gate as rg  # noqa: E402

LOOP = os.path.join(BASE, ".github", "workflows", "living-sdr-loop.yml")
VALIDATE_WF = os.path.join(BASE, ".github", "workflows", "validate.yml")
PIPELINE = os.path.join(BASE, "automation", "pipeline", "sdr-pipeline.yaml")
BUILDSPEC_VALIDATE = os.path.join(BASE, "automation", "pipeline", "buildspec-validate.yml")


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


# ---- AUD-F29: collector outcome ------------------------------------------

def test_f29_all_errored_run_is_a_failed_collection():
    facts = [{"rule": "r1", "compliance_type": "ERROR:AccessDenied"},
             {"rule": "r2", "compliance_type": "RULE_NOT_DEPLOYED"}]
    posture = [{"service": "kms", "check": "collector", "status": "ERROR"},
               {"service": "guardduty", "check": "detector", "status": "UNKNOWN"}]
    out = cf.collection_outcome(facts, posture)
    assert out == {"evaluated": 0, "unevaluated": 4, "errors": 2}, out
    assert cf.EXIT_NO_EVALUATED == 4


def test_f29_one_evaluated_outcome_is_not_a_failed_collection():
    facts = [{"rule": "r1", "compliance_type": "ERROR:AccessDenied"}]
    posture = [{"service": "kms", "check": "key_rotation", "status": "OBSERVED",
                "measured": 3, "total": 3}]
    out = cf.collection_outcome(facts, posture)
    assert out["evaluated"] == 1 and out["unevaluated"] == 1, out
    # NON_COMPLIANT is an evaluated outcome too (a definite negative is still
    # an observation of the boundary).
    out2 = cf.collection_outcome([{"compliance_type": "NON_COMPLIANT"}], [])
    assert out2["evaluated"] == 1, out2


def test_f29_main_returns_exit_4_when_nothing_evaluated():
    """Drive main() with a fake boto3 whose every call is denied: the facts
    store is written for diagnosis, meta carries the verdict, exit is 4."""
    import json
    import tempfile
    import types

    class _Denied(Exception):
        def __init__(self):
            super().__init__("denied")
            self.response = {"Error": {"Code": "AccessDeniedException"}}

    class _Client:
        def get_caller_identity(self):
            return {"Arn": "arn:aws:sts::000000000000:assumed-role/ReadOnly/x"}

        def describe_compliance_by_config_rule(self, **kw):
            raise _Denied()

    class _Session:
        region_name = "us-east-1"

        def __init__(self, profile_name=None, region_name=None):
            pass

        def client(self, name):
            return _Client()

    fake_boto3 = types.ModuleType("boto3")
    fake_boto3.Session = _Session
    fake_exc = types.ModuleType("botocore.exceptions")
    for name in ("ProfileNotFound", "NoCredentialsError", "BotoCoreError"):
        setattr(fake_exc, name, type(name, (Exception,), {}))
    fake_exc.ClientError = _Denied
    fake_botocore = types.ModuleType("botocore")
    fake_botocore.exceptions = fake_exc

    tmp = tempfile.mkdtemp(prefix="cf-f29-")
    saved_mods = {k: sys.modules.get(k) for k in ("boto3", "botocore", "botocore.exceptions", "collectors")}
    saved = (cf.FACTS_DIR, sys.argv)
    try:
        sys.modules["boto3"] = fake_boto3
        sys.modules["botocore"] = fake_botocore
        sys.modules["botocore.exceptions"] = fake_exc
        # Every posture collector raises -> ERROR facts only.
        fake_collectors = types.ModuleType("collectors")

        def _boom(session, region):
            raise RuntimeError("denied")
        fake_collectors.COLLECTORS = [("kms", _boom), ("guardduty", _boom)]
        sys.modules["collectors"] = fake_collectors
        cf.FACTS_DIR = os.path.join(tmp, "facts")
        sys.argv = ["collect_facts.py", "--region", "us-east-1"]
        rc = cf.main()
        assert rc == 4, rc
        with open(os.path.join(cf.FACTS_DIR, "facts-us-east-1.json"), encoding="utf-8") as f:
            store = json.load(f)
        oc = store["meta"]["collection_outcome"]
        assert oc["status"] == "FAILED_NO_EVALUATED_OUTCOME" and oc["evaluated"] == 0, oc
    finally:
        cf.FACTS_DIR, sys.argv = saved
        for k, v in saved_mods.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


# ---- AUD-F31 / AUD-F32: the Actions loop ---------------------------------

def test_f31_actions_loop_restores_and_publishes_history():
    wf = _read(LOOP)
    steps = wf.split("\n      - name: ")
    restore_i = next(i for i, s in enumerate(steps) if "publish_history.py restore" in s)
    append_i = next(i for i, s in enumerate(steps) if "append_metrics.py" in s)
    publish_i = next(i for i, s in enumerate(steps) if "publish_history.py publish" in s)
    # restore, append and publish live in ONE step so the CAS retry re-restores.
    assert restore_i == append_i == publish_i, (restore_i, append_i, publish_i)
    assert "--bucket \"$SDR_METRIC_HISTORY_BUCKET\"" in wf
    assert re.search(r"publish_history\.py publish[^\n]*\n[^\n]*--bucket", wf), "publish must target the bucket"
    assert "If-Match" in wf or "compare-and-swap" in wf


def test_f31_actions_loop_refuses_to_run_without_a_bucket():
    wf = _read(LOOP)
    guard = wf.find("Refuse to run without a persistence target")
    collect = wf.find("collect_facts.py")
    assert 0 < guard < collect, "the persistence guard must precede collection"
    assert 'if [ -z "$SDR_METRIC_HISTORY_BUCKET" ]' in wf
    assert "SDR_METRIC_HISTORY_BUCKET: ${{ vars.SDR_METRIC_HISTORY_BUCKET }}" in wf


def test_f32_actions_loop_files_an_issue_on_failure():
    wf = _read(LOOP)
    assert "issues: write" in wf
    tail = wf[wf.find("Open an issue on failure"):]
    assert "if: failure()" in tail
    assert "gh issue create" in tail and "gh issue comment" in tail


def test_f29_f30_actions_loop_does_not_mask_the_new_exit_codes():
    """The collector and appender exit 4 on an empty run; the workflow must let
    that fail the job (no `|| true` on either, and set -e in the loop)."""
    wf = _read(LOOP)
    for line in wf.splitlines():
        if "collect_facts.py" in line or "append_metrics.py" in line:
            assert "|| true" not in line and "|| echo" not in line, line
    loop_step = wf[wf.find("Restore, append, publish"):wf.find("Pre-fill draft fields")]
    assert "set -e" in loop_step


# ---- AUD-F32: the AWS template -------------------------------------------

def test_f32_aws_template_notifies_on_failed_scheduled_builds():
    tpl = _read(PIPELINE)
    i = tpl.find("ScheduledBuildFailureNotification:")
    assert i > 0, "failure rule for the scheduled CodeBuild projects is missing"
    rule = tpl[i:tpl.find("\n  NotificationTopicPolicy:")]
    assert 'source: ["aws.codebuild"]' in rule
    assert '"CodeBuild Build State Change"' in rule
    for status in ("FAILED", "FAULT", "TIMED_OUT", "STOPPED"):
        assert f'"{status}"' in rule, status
    assert "!Ref DriftCheckProject" in rule
    assert "!Ref CollectorProject" in rule
    assert "Arn: !Ref NotificationTopic" in rule
    # The topic policy must let EventBridge publish (it already did for the
    # pipeline rule; keep it that way).
    policy = tpl[tpl.find("NotificationTopicPolicy:"):]
    assert "events.amazonaws.com" in policy


# ---- AUD-F34: dependency vulnerability audit in the single gate ----------

def test_f34_pip_audit_is_a_hard_security_step_on_every_path():
    names = [name for name, _argv in rg.SECTIONS["security"]]
    assert "pip-audit" in names, names
    argv = dict(rg.SECTIONS["security"])["pip-audit"]
    assert "pip_audit" in argv and "requirements.lock" in argv, argv
    assert "--require-hashes" in argv and "--strict" in argv, argv
    pin = rg.SECURITY_TOOL_PINS["pip-audit"]
    for path in (VALIDATE_WF, BUILDSPEC_VALIDATE):
        assert f"pip-audit=={pin}" in _read(path), path


# ---- AUD-F43: the drift workflow's review hand-off is fail-visible ---------

DRIFT_WF = os.path.join(BASE, ".github", "workflows", "drift-check.yml")


def _drift_regenerate_step():
    wf = _read(DRIFT_WF)
    start = wf.find("Regenerate from the new dataset and open a review PR")
    assert start > 0
    return wf[start:]


def test_f43_drift_workflow_has_no_fail_open_handoff():
    """The 2026-10-09 run pushed the adoption branch, GitHub refused the PR
    ("GitHub Actions is not permitted to create or approve pull requests"),
    and the step printed "PR may already exist" and exited 0. Neither the push
    nor the PR creation may swallow a failure as benign any more."""
    step = _drift_regenerate_step()
    assert "PR may already exist" not in step
    assert "branch may already exist" not in step
    for line in step.splitlines():
        if "gh pr create" in line or "git push" in line:
            assert "|| echo" not in line and "|| true" not in line and "exit 0; }" not in line, line


def test_f43_drift_workflow_hands_review_to_the_issue_and_fails():
    """When the PR cannot be opened the branch is already on the remote, so the
    review path must still exist: the compare link and the full review body go
    on the drift issue (or a new issue), the step records an error annotation,
    and exits non-zero. An already-open PR for the branch is the one benign
    case and is checked for explicitly, not assumed."""
    step = _drift_regenerate_step()
    assert 'gh pr list --head "$BRANCH"' in step, "an existing PR must be detected, not assumed"
    assert "git ls-remote --exit-code --heads origin" in step, "an existing branch must be detected, not assumed"
    assert "compare/main...${BRANCH}" in step
    assert "gh issue comment" in step and "gh issue create" in step
    assert "::error::PR creation refused" in step
    # The refusal path ends in exit 1, after the hand-off.
    tail = step[step.find("PR creation refused"):]
    assert "exit 1" in tail
    # The setting the refusal usually comes from is named for the operator.
    assert "Allow GitHub Actions to create and approve pull requests" in step


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
