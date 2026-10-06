"""AUD-F38 regression: a labelled DRAFT / Example proposal is unanswered everywhere.

Reproduced at 35aa70c: ``Example (reference architecture, ...)`` text in three
template rules, and any ``DRAFT (...)`` text the drafter writes, counted as a
populated, answered narrative in sdr.py preflight (``_answered``),
validate_sdr.py (``"TBD" in s``) and the scanner (``state()``). A package whose
168 rule narratives were all machine drafts would have read as fully populated.

This test pins the shared definition and every consumer of it. Mutation
MUT-F38 removes "DRAFT (" from the prefix list; this test must go RED.

Run: python validation/scripts/test_unreviewed_text.py
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(BASE, "automation", "sdrscan"))
sys.path.insert(0, os.path.join(BASE, "automation", "ai"))
import unreviewed_text as ut  # noqa: E402
import checks  # noqa: E402  (scanner)
import draft_narratives as dn  # noqa: E402

DRAFT = "DRAFT (AI-assisted, unverified -- review before use): The inbox reaches the on-call rotation."
EXAMPLE_LONG = "Example (reference architecture, replace with your real implementation): A monthly synthetic test email."
EXAMPLE_SHORT = "Example: Security Operations Manager"
REAL = "The FedRAMP security inbox is a monitored distribution list reaching the on-call rotation."


def test_shared_predicate():
    for v in (DRAFT, EXAMPLE_LONG, EXAMPLE_SHORT, [DRAFT], [EXAMPLE_LONG, DRAFT], "  " + DRAFT):
        assert ut.is_unreviewed(v), v
    for v in (REAL, [REAL], [REAL, DRAFT], "", None, 3, [], "Examples of this include x"):
        assert not ut.is_unreviewed(v), v
    assert ut.strip_label(DRAFT) == "The inbox reaches the on-call rotation."
    assert ut.strip_label(EXAMPLE_LONG) == "A monthly synthetic test email."
    assert ut.strip_label(EXAMPLE_SHORT) == "Security Operations Manager"
    assert ut.strip_label(REAL) == REAL
    for v in (DRAFT, EXAMPLE_LONG, EXAMPLE_SHORT):
        assert not ut.is_unreviewed(ut.strip_label(v)), v  # accepting clears the label
    print("PASS: test_shared_predicate")


def test_scanner_treats_proposals_as_placeholder():
    for v in (DRAFT, EXAMPLE_LONG, EXAMPLE_SHORT, [DRAFT]):
        assert checks.state(v) == "placeholder", v
        assert not checks.stated(v)
    assert checks.state(REAL) == "populated"
    assert "unreviewed" in checks._why(DRAFT)
    print("PASS: test_scanner_treats_proposals_as_placeholder")


def _preflight_predicates():
    """Pull _is_tbd / _answered out of sdr.py's preflight by executing the
    command against a store whose only populated narratives are proposals.
    Cheaper and more honest: run `sdr.py package-preflight` and read the report
    text for the three Example rules."""
    out = subprocess.run([sys.executable, os.path.join(BASE, "sdr.py"), "package-preflight"],
                         capture_output=True, text=True, cwd=BASE)
    return out.stdout + out.stderr


def test_preflight_does_not_count_proposals_as_answered():
    """The template ships Example text as the implementation of AFC-CSO-INB,
    FRC-CSO-JSN and VDR-CSO-DET (status Not Implemented). For a not-followed
    rule the implementation narrative may carry the reason, so at 35aa70c the
    Example text SATISFIED the 'reason-not-followed' element and preflight did
    not list it. It must now be listed as missing for every such rule."""
    store = json.load(open(os.path.join(BASE, "sdr", "records", "records-store.json"), encoding="utf-8"))
    example_rules = [k for k, v in store["frr"].items()
                     if ut.is_unreviewed(v.get("implementation"))
                     and str(v.get("implementation_status", "")).startswith("Not Implemented")]
    assert example_rules, "fixture drift: the template no longer ships Example implementations"
    text = _preflight_predicates()
    checked = 0
    for rid in example_rules:
        marker = f"{rid} (missing: "
        if marker not in text:
            continue  # rule not applicable at the active class; preflight does not list it
        gaps = text[text.index(marker) + len(marker):].split(")", 3)[0]
        assert "reason-not-followed" in gaps, (
            f"{rid}: the Example implementation text still counts as the reason: {gaps!r}")
        checked += 1
    assert checked >= 1, f"none of {example_rules} is reported by preflight at the active class"
    print(f"PASS: test_preflight_does_not_count_proposals_as_answered ({checked} of "
          f"{len(example_rules)} example rules applicable at the active class)")


def test_validate_sdr_populated_predicate():
    """validate_sdr.py's two populated checks use the shared predicate."""
    src = open(os.path.join(HERE, "validate_sdr.py"), encoding="utf-8").read()
    assert src.count("is_unreviewed(s)") >= 2, "validate_sdr.py populated checks must call is_unreviewed"
    assert "from unreviewed_text import is_unreviewed" in src
    print("PASS: test_validate_sdr_populated_predicate")


def test_drafter_rule_path_keeps_boundary_and_labels():
    rec = {
        "implementation_status": "Not Implemented",
        "implementation": ["TBD: Information has not been provided."],
        "validation": [EXAMPLE_LONG],
        "assessment": ["TBD: Independent assessment has not been performed."],
        "extension": {"owner": EXAMPLE_SHORT},
        "fill_guidance": {"what_it_looks_for": "Providers MUST maintain a FedRAMP Security Inbox.",
                          "how_to_comply": "Stand up a dedicated, monitored inbox as a distribution list.",
                          "evidence_required": ["Email address to receive messages from FedRAMP"]},
    }
    before = {k: rec[k] for k in dn.FORBIDDEN_FIELDS if k in rec}
    ctx = {"organization": "Acme Cloud", "offering": "Widgets", "security_contact": "security@acme.example",
           "incident_contact": None, "trust_center_uri": None}
    changed, notes = dn.draft_rule("AFC-CSO-INB", rec, ctx)
    assert changed and len(notes) == 2
    impl, val = rec["implementation"][0], rec["validation"][0]
    assert impl.startswith("DRAFT (") and val.startswith("DRAFT (")
    assert ut.is_unreviewed(impl) and ut.is_unreviewed(val)  # a draft is never an answer
    assert "Acme Cloud" in impl and "security@acme.example" in impl  # profile values named
    assert "A monthly synthetic test email." in val  # curated example kept, re-labelled
    assert "compliance conclusion" in impl
    for k, v in before.items():
        assert rec[k] == v, f"drafter changed forbidden field {k}"
    assert rec["extension"]["owner"] == EXAMPLE_SHORT  # extension untouched by the drafter
    # Author-written prose is never overwritten.
    rec2 = dict(rec, implementation=[REAL], validation=[REAL])
    changed2, _ = dn.draft_rule("AFC-CSO-INB", rec2, ctx)
    assert not changed2 and rec2["implementation"] == [REAL]
    # Template example values in the PROFILE are not treated as real facts.
    assert dn._profile_value({"organization_name": "TBD: Information has not been provided"}, "organization_name") is None
    assert dn._profile_value({"organization_name": "Example: Acme"}, "organization_name") is None
    assert dn._profile_value({"organization_name": "Acme Cloud"}, "organization_name") == "Acme Cloud"
    print("PASS: test_drafter_rule_path_keeps_boundary_and_labels")


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
