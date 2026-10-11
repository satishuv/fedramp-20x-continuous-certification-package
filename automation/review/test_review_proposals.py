"""Tests for automation/review/review_proposals.py (the typing-to-reviewing step).

Offline, no AWS. The two guarantees under test:

  1. Nothing enters the record store except through a NAMED human's accept or
     edit decision, the DRAFT / Example label is stripped on accept, and
     implementation_status / assessment can never be written here.
  2. Every decision is recorded bound to the hash of what was written, and
     validate_reviews.py fails when a reviewed field is changed afterwards.

Run: python automation/review/test_review_proposals.py
"""
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
import review_proposals as rp  # noqa: E402
from unreviewed_text import is_unreviewed  # noqa: E402

DRAFT = "DRAFT (AI-assisted, unverified -- review before use): The FedRAMP inbox reaches the on-call rotation."
EXAMPLE = "Example (reference architecture, replace with your real implementation): A monthly synthetic test email."
TBD = "TBD: Information has not been provided."


def store():
    return {
        "frr": {
            "AFC-CSO-INB": {
                "implementation_status": "Not Implemented",
                "implementation": [TBD],
                "validation": [EXAMPLE],
                "assessment": [TBD],
                "extension": {"owner": "Example: Security Operations Manager",
                              "verification": TBD,
                              "responsibility": {"aws": TBD, "provider": TBD, "customer": TBD}},
            },
        },
        "ksi": {
            "KSI-IAM-SUS": {
                "implementation_status": "Not Implemented",
                "implementation": [TBD], "validation": [TBD], "assessment": [TBD],
                "tests": [], "evidence": [],
                "extension": {"owner": TBD},
            },
        },
    }


def ai_draft(base):
    d = copy.deepcopy(base)
    d["frr"]["AFC-CSO-INB"]["implementation"] = [DRAFT]
    d["ksi"]["KSI-IAM-SUS"]["implementation"] = [DRAFT]
    d["ksi"]["KSI-IAM-SUS"]["implementation_status"] = "Implemented"  # must be refused
    return d


def prefill(base):
    p = copy.deepcopy(base)
    p["meta"] = {"facts_sha256": "sha256:" + "ab" * 32, "run_id": "run-1"}
    p["ksi"]["KSI-IAM-SUS"]["tests"] = [{"method_id": "iam:mfa_enforced", "automated": True,
                                         "method": "IAM credential report, daily"}]
    return p


def test_discovers_proposals_from_both_sidecars_and_template_examples():
    s = store()
    items, violations = rp.proposals(s, prefill(s), ai_draft(s))
    keys = {it["key"]: it for it in items}
    assert "frr/AFC-CSO-INB.implementation" in keys and keys["frr/AFC-CSO-INB.implementation"]["source"] == "ai-draft"
    assert keys["frr/AFC-CSO-INB.validation"]["source"] == "template-example"
    assert keys["frr/AFC-CSO-INB.extension.owner"]["source"] == "template-example"
    assert keys["ksi/KSI-IAM-SUS.tests"]["source"] == "prefill"
    assert keys["ksi/KSI-IAM-SUS.tests"]["provenance"]["run_id"] == "run-1"
    assert "ksi/KSI-IAM-SUS.implementation_status" not in keys
    assert any("implementation_status" in v for v in violations), violations
    print("PASS: test_discovers_proposals_from_both_sidecars_and_template_examples")


def test_accept_strips_label_and_edit_writes_text_and_reject_leaves_untouched():
    s = store()
    items, _ = rp.proposals(s, prefill(s), ai_draft(s))
    decisions = {
        "frr/AFC-CSO-INB.implementation": {"decision": "accepted"},
        "frr/AFC-CSO-INB.validation": {"decision": "accepted"},
        "frr/AFC-CSO-INB.extension.owner": {"decision": "edited", "text": "Head of Security Operations"},
        "ksi/KSI-IAM-SUS.implementation": {"decision": "rejected", "reason": "not how we do it"},
        "ksi/KSI-IAM-SUS.tests": {"decision": "accepted"},
    }
    new, log, applied = rp.apply_decisions(s, items, decisions, "Jane Doe", "Compliance lead",
                                           now="2026-10-05T23:00:00+00:00")
    rec = new["frr"]["AFC-CSO-INB"]
    assert rec["implementation"] == ["The FedRAMP inbox reaches the on-call rotation."]
    assert rec["validation"] == ["A monthly synthetic test email."]
    assert rec["extension"]["owner"] == "Head of Security Operations"
    assert not is_unreviewed(rec["implementation"]) and not is_unreviewed(rec["validation"])
    assert new["ksi"]["KSI-IAM-SUS"]["implementation"] == [TBD]  # rejected: untouched
    assert new["ksi"]["KSI-IAM-SUS"]["tests"][0]["method_id"] == "iam:mfa_enforced"
    assert new["ksi"]["KSI-IAM-SUS"]["implementation_status"] == "Not Implemented"
    assert applied == 4
    assert s["frr"]["AFC-CSO-INB"]["implementation"] == [TBD]  # input store not mutated
    entries = {e["field"]: e for e in log["reviews"]}
    assert entries["frr/AFC-CSO-INB.implementation"]["applied_sha256"] == rp._sha256(rec["implementation"])
    assert entries["ksi/KSI-IAM-SUS.implementation"]["applied_sha256"] is None
    assert entries["ksi/KSI-IAM-SUS.implementation"]["reason"] == "not how we do it"
    assert all(e["reviewer"] == "Jane Doe" and e["role"] == "Compliance lead" for e in log["reviews"])
    assert all(e["reviewed_at"] == "2026-10-05T23:00:00+00:00" for e in log["reviews"])
    print("PASS: test_accept_strips_label_and_edit_writes_text_and_reject_leaves_untouched")


def _raises(fn, needle):
    try:
        fn()
    except rp.ReviewError as e:
        assert needle in str(e), str(e)
        return
    raise AssertionError(f"expected ReviewError containing {needle!r}")


def test_refusals():
    s = store()
    items, _ = rp.proposals(s, prefill(s), ai_draft(s))
    ok = {"frr/AFC-CSO-INB.implementation": {"decision": "accepted"}}
    _raises(lambda: rp.apply_decisions(s, items, ok, "pipeline", "x"), "named human")
    _raises(lambda: rp.apply_decisions(s, items, ok, "", "x"), "named human")
    _raises(lambda: rp.apply_decisions(s, items, ok, "Jane Doe", ""), "role")
    _raises(lambda: rp.apply_decisions(s, items, {"frr/AFC-CSO-INB.implementation": {"decision": "approved"}},
                                       "Jane Doe", "lead"), "decision must be")
    _raises(lambda: rp.apply_decisions(s, items, {"frr/AFC-CSO-INB.extension.owner": {"decision": "edited"}},
                                       "Jane Doe", "lead"), "needs the reviewer's text")
    _raises(lambda: rp.apply_decisions(s, items, {"frr/AFC-CSO-INB.extension.owner":
                                                   {"decision": "edited", "text": "DRAFT (x): y"}},
                                       "Jane Doe", "lead"), "proposal label")
    _raises(lambda: rp.apply_decisions(s, items, {"frr/NOPE.implementation": {"decision": "accepted"}},
                                       "Jane Doe", "lead"), "not pending proposals")
    # A forged item on a forbidden path is refused even if handed in directly.
    forged = items + [{"key": "frr/AFC-CSO-INB.implementation_status", "section": "frr",
                       "record_id": "AFC-CSO-INB", "path": ["implementation_status"],
                       "current": "Not Implemented", "proposed": "Implemented",
                       "source": "ai-draft", "provenance": {}}]
    _raises(lambda: rp.apply_decisions(s, forged, {"frr/AFC-CSO-INB.implementation_status":
                                                    {"decision": "accepted"}}, "Jane Doe", "lead"),
            "never reviewable")
    print("PASS: test_refusals")


def test_walk_is_one_key_per_field_and_quit_stops():
    s = store()
    items, _ = rp.proposals(s, None, ai_draft(s))
    answers = iter(["a", "e", "Our own validation text", "r", "", "q"])
    printed = []
    decisions = rp.walk(items, "Jane Doe", "lead", prompt=lambda _p: next(answers), out=printed.append)
    assert decisions[items[0]["key"]] == {"decision": "accepted"}
    assert decisions[items[1]["key"]] == {"decision": "edited", "text": "Our own validation text"}
    assert decisions[items[2]["key"]]["decision"] == "rejected"
    assert len(decisions) == 3  # the 4th was skipped, then quit
    assert any("on accept:" in line for line in printed)
    print("PASS: test_walk_is_one_key_per_field_and_quit_stops")


def _validate_reviews_in(tmp_base):
    """Run validate_reviews.py against a temp copy of the repo layout."""
    env = dict(os.environ)
    out = subprocess.run([sys.executable, os.path.join(tmp_base, "validation", "scripts", "validate_reviews.py")],
                         capture_output=True, text=True, env=env)
    return out.returncode, out.stdout + out.stderr


def test_end_to_end_through_run_and_validator_binding():
    """Drive run() on temp files exactly as sdr.py does, then prove the validator
    accepts the log, and fails once a reviewed field is edited behind its back."""
    tmp = tempfile.mkdtemp(prefix="sdr-review-")
    try:
        for rel in ("sdr/records", "sdr/reviews", "validation/scripts", "traceability"):
            os.makedirs(os.path.join(tmp, rel), exist_ok=True)
        for fn in ("validate_reviews.py", "unreviewed_text.py"):
            shutil.copy(os.path.join(BASE, "validation", "scripts", fn),
                        os.path.join(tmp, "validation", "scripts", fn))
        s = store()
        with open(os.path.join(tmp, "sdr", "records", "records-store.json"), "w", encoding="utf-8") as f:
            json.dump(s, f)
        with open(os.path.join(tmp, "sdr", "records", "records-store.ai-draft.json"), "w", encoding="utf-8") as f:
            json.dump(ai_draft(s), f)
        with open(os.path.join(tmp, "sdr", "reviews", "review-register.json"), "w", encoding="utf-8") as f:
            json.dump({"reviews": []}, f)
        decisions_path = os.path.join(tmp, "decisions.json")
        with open(decisions_path, "w", encoding="utf-8") as f:
            json.dump({"frr/AFC-CSO-INB.implementation": {"decision": "accepted"},
                       "frr/AFC-CSO-INB.extension.owner": {"decision": "edited",
                                                           "text": "Head of Security Operations"}}, f)
        saved = (rp.RECORD_STORE, rp.PREFILL_SIDECAR, rp.AI_SIDECAR, rp.FIELD_REVIEW_LOG)
        rp.RECORD_STORE = os.path.join(tmp, "sdr", "records", "records-store.json")
        rp.PREFILL_SIDECAR = os.path.join(tmp, "sdr", "records", "records-store.prefilled.json")
        rp.AI_SIDECAR = os.path.join(tmp, "sdr", "records", "records-store.ai-draft.json")
        rp.FIELD_REVIEW_LOG = os.path.join(tmp, "sdr", "reviews", "field-review-log.json")
        try:
            printed = []
            args = types.SimpleNamespace(list=False, walk=False, decisions=decisions_path, accept_all=None,
                                         source=None, only=None, reviewer="Jane Doe", role="Compliance lead")
            rc = rp.run(args, out=printed.append)
            assert rc == 0, printed
            # Without a reviewer the same decisions are refused and nothing is written.
            before = open(rp.RECORD_STORE, encoding="utf-8").read()
            args2 = types.SimpleNamespace(list=False, walk=False, decisions=decisions_path, accept_all=None,
                                          source=None, only=None, reviewer=None, role=None)
            rc2 = rp.run(args2, out=printed.append)
            assert rc2 == 2 and open(rp.RECORD_STORE, encoding="utf-8").read() == before
            # --accept-all is refused for prose sources.
            args3 = types.SimpleNamespace(list=False, walk=False, decisions=None, accept_all="ai-draft",
                                          source=None, only=None, reviewer="Jane Doe", role="lead")
            assert rp.run(args3, out=printed.append) == 2
        finally:
            rp.RECORD_STORE, rp.PREFILL_SIDECAR, rp.AI_SIDECAR, rp.FIELD_REVIEW_LOG = saved
        written = json.load(open(os.path.join(tmp, "sdr", "records", "records-store.json"), encoding="utf-8"))
        assert written["frr"]["AFC-CSO-INB"]["implementation"] == ["The FedRAMP inbox reaches the on-call rotation."]
        assert written["frr"]["AFC-CSO-INB"]["extension"]["owner"] == "Head of Security Operations"
        log = json.load(open(os.path.join(tmp, "sdr", "reviews", "field-review-log.json"), encoding="utf-8"))
        assert len(log["reviews"]) == 2
        rc, text = _validate_reviews_in(tmp)
        assert rc == 0, text
        assert "2 field decision(s) bound" in text, text
        # Silent edit after review: the validator must fail on the stale decision.
        written["frr"]["AFC-CSO-INB"]["implementation"] = ["Someone changed this later."]
        with open(os.path.join(tmp, "sdr", "records", "records-store.json"), "w", encoding="utf-8") as f:
            json.dump(written, f)
        rc, text = _validate_reviews_in(tmp)
        assert rc == 1 and "changed after it was accepted" in text, text
        # A log entry claiming the pipeline decided is refused.
        log["reviews"][0]["reviewer"] = "pipeline"
        with open(os.path.join(tmp, "sdr", "reviews", "field-review-log.json"), "w", encoding="utf-8") as f:
            json.dump(log, f)
        rc, text = _validate_reviews_in(tmp)
        assert rc == 1 and "not a human identity" in text, text
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("PASS: test_end_to_end_through_run_and_validator_binding")


def test_f46_decided_proposals_are_not_re_asked_until_the_proposal_changes():
    """AUD-F46. Exercising the consultant flow: after accepting one prose proposal
    and rejecting another, `review --list` still counted both as pending and
    `--walk` asked them again, because the store never equals a labelled
    sidecar value (accept strips the label; reject writes nothing). The log
    knows the hash of what was decided; a proposal with that hash is decided."""
    s = store()
    items, _ = rp.proposals(s, prefill(s), ai_draft(s))
    decisions = {
        "frr/AFC-CSO-INB.implementation": {"decision": "accepted"},
        "ksi/KSI-IAM-SUS.implementation": {"decision": "rejected", "reason": "not how we do it"},
        "ksi/KSI-IAM-SUS.tests": {"decision": "accepted"},
    }
    new, log, _ = rp.apply_decisions(s, items, decisions, "Jane Doe", "Compliance lead")
    again, _ = rp.proposals(new, prefill(s), ai_draft(s))
    keys = {it["key"] for it in again}
    # The sidecar still differs from the store for both prose fields...
    assert "frr/AFC-CSO-INB.implementation" in keys and "ksi/KSI-IAM-SUS.implementation" in keys
    assert "ksi/KSI-IAM-SUS.tests" not in keys  # structured accept makes store == sidecar
    # ...but the log says a named human already decided these very proposals.
    pending, decided = rp.split_decided(again, log)
    assert {it["key"] for it in decided} == {"frr/AFC-CSO-INB.implementation",
                                             "ksi/KSI-IAM-SUS.implementation"}
    assert not ({it["key"] for it in pending} & {it["key"] for it in decided})
    assert "frr/AFC-CSO-INB.validation" in {it["key"] for it in pending}  # never decided
    # A changed proposal for a decided field is pending again (new drafter run).
    changed = ai_draft(s)
    changed["ksi"]["KSI-IAM-SUS"]["implementation"] = [DRAFT + " Revised after new facts."]
    again2, _ = rp.proposals(new, prefill(s), changed)
    pending2, decided2 = rp.split_decided(again2, log)
    assert "ksi/KSI-IAM-SUS.implementation" in {it["key"] for it in pending2}
    assert "frr/AFC-CSO-INB.implementation" in {it["key"] for it in decided2}
    # No log at all: nothing is decided (first run of a fresh clone).
    p0, d0 = rp.split_decided(again, None)
    assert len(p0) == len(again) and not d0
    # Authorship guard: a sidecar proposes only what its producer writes.
    srcs = {it["key"]: it["source"] for it in again}
    assert srcs["frr/AFC-CSO-INB.implementation"] == "ai-draft"  # not the stale prefill TBD
    stale_ai = ai_draft(s)
    stale_ai["frr"]["AFC-CSO-INB"]["extension"]["owner"] = "Example: Someone Else"  # drafter never writes this
    stale_ai["frr"]["AFC-CSO-INB"]["validation"] = ["Unlabelled text is not drafter output."]
    items3, _ = rp.proposals(new, prefill(s), stale_ai)
    by_key = {it["key"]: it for it in items3}
    assert by_key["frr/AFC-CSO-INB.extension.owner"]["source"] == "template-example"
    assert by_key["frr/AFC-CSO-INB.validation"]["source"] == "template-example"
    print("PASS: test_f46_decided_proposals_are_not_re_asked_until_the_proposal_changes")


def test_f46_run_list_and_walk_skip_decided_unless_all():
    """The same guarantee through run(): the list count drops after decisions,
    the decided count is printed, and --all brings them back."""
    tmp = tempfile.mkdtemp(prefix="sdr-review-f46-")
    try:
        os.makedirs(os.path.join(tmp, "sdr", "records"))
        os.makedirs(os.path.join(tmp, "sdr", "reviews"))
        s = store()
        with open(os.path.join(tmp, "sdr", "records", "records-store.json"), "w", encoding="utf-8") as f:
            json.dump(s, f)
        with open(os.path.join(tmp, "sdr", "records", "records-store.ai-draft.json"), "w", encoding="utf-8") as f:
            json.dump(ai_draft(s), f)
        with open(os.path.join(tmp, "sdr", "records", "records-store.prefilled.json"), "w", encoding="utf-8") as f:
            json.dump(prefill(s), f)  # a full snapshot of the store, as prefill writes it
        decisions_path = os.path.join(tmp, "decisions.json")
        with open(decisions_path, "w", encoding="utf-8") as f:
            json.dump({"frr/AFC-CSO-INB.implementation": {"decision": "accepted"},
                       "ksi/KSI-IAM-SUS.implementation": {"decision": "rejected"}}, f)
        saved = (rp.RECORD_STORE, rp.PREFILL_SIDECAR, rp.AI_SIDECAR, rp.FIELD_REVIEW_LOG)
        rp.RECORD_STORE = os.path.join(tmp, "sdr", "records", "records-store.json")
        rp.PREFILL_SIDECAR = os.path.join(tmp, "sdr", "records", "records-store.prefilled.json")
        rp.AI_SIDECAR = os.path.join(tmp, "sdr", "records", "records-store.ai-draft.json")
        rp.FIELD_REVIEW_LOG = os.path.join(tmp, "sdr", "reviews", "field-review-log.json")
        try:
            def run(**kw):
                printed = []
                base = dict(list=False, walk=False, decisions=None, accept_all=None, source=None,
                            only=None, reviewer="Jane Doe", role="Compliance lead")
                base.update(kw)
                rc = rp.run(types.SimpleNamespace(**base), out=printed.append)
                return rc, "\n".join(printed)
            rc, before = run(list=True)
            assert rc == 0 and "Pending proposals: 5" in before, before
            rc, _ = run(decisions=decisions_path)
            assert rc == 0
            rc, after = run(list=True)
            assert rc == 0 and "Pending proposals: 3" in after, after
            assert "Decided earlier and not re-asked: 2" in after, after
            assert "frr/AFC-CSO-INB.implementation" not in after
            # The stale prefill snapshot (implementation still TBD) is NOT a
            # proposal to revert the accepted narrative, and accept-all prefill
            # touches the structured field only. The demo run lost an accepted
            # narrative exactly here.
            assert "[prefill]" in after and after.count("[prefill]") == 1, after
            rc, applied = run(accept_all="prefill")
            assert rc == 0 and "Applied 1 field(s)" in applied, applied
            written = json.load(open(rp.RECORD_STORE, encoding="utf-8"))
            assert written["frr"]["AFC-CSO-INB"]["implementation"] == [
                "The FedRAMP inbox reaches the on-call rotation."], written["frr"]["AFC-CSO-INB"]
            assert written["ksi"]["KSI-IAM-SUS"]["tests"][0]["method_id"] == "iam:mfa_enforced"
            rc, everything = run(list=True, all=True)
            assert "Pending proposals: 4" in everything and "frr/AFC-CSO-INB.implementation" in everything
            # The walk sees only the two undecided fields.
            seen = []
            rp_walk = rp.walk
            try:
                rp.walk = lambda items, *a, **k: (seen.extend(it["key"] for it in items) or {})
                run(walk=True)
            finally:
                rp.walk = rp_walk
            assert set(seen) == {"frr/AFC-CSO-INB.validation", "frr/AFC-CSO-INB.extension.owner"}, seen
        finally:
            rp.RECORD_STORE, rp.PREFILL_SIDECAR, rp.AI_SIDECAR, rp.FIELD_REVIEW_LOG = saved
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("PASS: test_f46_run_list_and_walk_skip_decided_unless_all")


def test_f47_structured_tests_and_evidence_cannot_be_edited_into_prose():
    """AUD-F47. An `e` on a prefill tests/evidence item wrapped the reviewer's
    sentence into the list of schema objects: ksiEvidence items must be objects
    and FRC-CSX-VVK counts a plain-string test as zero automated methods, so the
    record the gate then rejected was created by the review step itself."""
    s = store()
    items, _ = rp.proposals(s, prefill(s), ai_draft(s))
    _raises(lambda: rp.apply_decisions(
        s, items, {"ksi/KSI-IAM-SUS.tests": {"decision": "edited", "text": "We check MFA weekly."}},
        "Jane Doe", "lead"), "accepted or rejected as collected")
    # Accept and reject still work on the structured item.
    new, _, applied = rp.apply_decisions(
        s, items, {"ksi/KSI-IAM-SUS.tests": {"decision": "accepted"}}, "Jane Doe", "lead")
    assert applied == 1 and new["ksi"]["KSI-IAM-SUS"]["tests"][0]["method_id"] == "iam:mfa_enforced"
    # The walk does not offer edit on a structured item and explains an 'e'.
    structured = [it for it in items if it["key"] == "ksi/KSI-IAM-SUS.tests"]
    prompts, printed = [], []
    answers = iter(["e", "a"])

    def prompt(p):
        prompts.append(p)
        return next(answers)
    decisions = rp.walk(structured, "Jane Doe", "lead", prompt=prompt, out=printed.append)
    assert decisions == {"ksi/KSI-IAM-SUS.tests": {"decision": "accepted"}}
    assert all("[e]dit" not in p for p in prompts), prompts
    assert any("prose cannot replace them" in line for line in printed), printed
    # Prose items still offer edit.
    prose = [it for it in items if it["key"] == "frr/AFC-CSO-INB.implementation"]
    prompts2 = []
    rp.walk(prose, "Jane Doe", "lead", prompt=lambda p: (prompts2.append(p), "s")[1], out=lambda _l: None)
    assert any("[e]dit" in p for p in prompts2)
    print("PASS: test_f47_structured_tests_and_evidence_cannot_be_edited_into_prose")


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
