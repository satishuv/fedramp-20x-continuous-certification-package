#!/usr/bin/env python3
"""Mutation tests -- the anti-circular-verification gate (HARD-MODE protocol).

A passing regression test proves nothing if the test cannot actually detect the
defect it claims to guard. This runner RE-INTRODUCES each closed defect into the
PRODUCTION code by textual patch, runs the named regression test, and asserts the
test goes RED. If a mutation SURVIVES (test still green), that is a test-coverage
defect and this runner exits non-zero.

Every mutation restores the file afterward via `git checkout --`, so the tree is
left clean.

    python audit/mutation_tests.py

A mutation whose target text is not present on this commit is reported SKIP and
SKIP FAILS THE GATE (AUD-F13). The earlier behaviour let a skip pass, which meant
a harmless refactor that changed the target text silently switched off the
protection for a closed defect while the ledger still said mutation_verified. A
skip now has exactly two honest resolutions: retarget the mutation to the
refactored code, or (if the defect is on an unmerged branch) run the gate on that
branch. The runner also cross-checks the defect ledger: every CLOSED,
mutation_verified defect must map to exactly one runner entry, every runner
entry must map to such a defect, and each must be KILLED, or the gate fails.

Bytecode cache. Python validates a cached `__pycache__/*.pyc` by source SIZE and
source mtime in WHOLE SECONDS only. A mutation whose replacement has the same
length as the text it replaces (MUT-F10 is exactly 50 -> 50 characters) leaves
the size unchanged, so if an earlier step compiled the ORIGINAL module and the
mutated file lands in the same wall-clock second, the interpreter loads the
original bytecode and the regression "passes" against unmutated code. That is a
false SURVIVED that has nothing to do with the test. CI hit it on main twice
(validate-sdr run 35993242564). The runner therefore purges every __pycache__
before each mutated test run and forbids pyc writes during it
(PYTHONDONTWRITEBYTECODE), so a test can only ever exercise the source on disk.
`-B` alone is NOT enough: it stops writing pycs but still READS a stale one.
"""
import json
import os
import shutil
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def _write(p, s):
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)


def _read_bytes(p):
    with open(p, "rb") as f:
        return f.read()


def _restore(rel, original_bytes=None):
    """Put the pre-mutation source back. The saved original bytes are the
    authoritative restore: writing them back returns the file to EXACTLY what it
    was, committed or not. `git checkout --` is only the fallback when no bytes
    were saved or the write-back somehow did not take: on a tree with
    uncommitted edits (a developer running the self-test locally) a blind
    checkout would replace those edits with HEAD, which is data loss, not a
    restore. Verify loudly either way."""
    path = os.path.join(BASE, rel)
    if original_bytes is not None:
        with open(path, "wb") as f:
            f.write(original_bytes)
        if _read_bytes(path) == original_bytes:
            return
    subprocess.run(["git", "checkout", "--", rel], cwd=BASE,
                   capture_output=True, text=True)
    if original_bytes is not None and _read_bytes(path) != original_bytes:
        raise RuntimeError(f"restore of {rel} failed: working tree still differs "
                           "from the saved original")


def _purge_bytecode(root=BASE):
    """Remove every __pycache__ under root so no cached bytecode can stand in
    for the source on disk. .git is skipped; nothing there is ours to touch."""
    for dirpath, dirnames, _files in os.walk(root):
        if ".git" in dirnames:
            dirnames.remove(".git")
        if "__pycache__" in dirnames:
            shutil.rmtree(os.path.join(dirpath, "__pycache__"), ignore_errors=True)
            dirnames.remove("__pycache__")


def _no_bytecode_env():
    env = dict(os.environ)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


MUTATIONS = [
    ("MUT-F04",
     "automation/metrics/append_metrics.py",
     'scope = (rule, fact.get("region"), fact.get("account"))',
     'scope = (rule,)  # MUTATION',
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F01",
     "validation/scripts/validate_evidence.py",
     "    signer_required = bool(trusted_signer",
     "    source, kind = _resolve_source(e)\n    if source is None:\n        return ('finding', 'MUT unverifiable')\n    signer_required = bool(trusted_signer",
     "validation/scripts/test_evidence_integrity.py"),
    ("MUT-F06",
     "sdr.py",
     "    gappy = (largest > max_gap_days or trailing > max_gap_days\n             or leading > max_gap_days)",
     "    gappy = (largest > max_gap_days or trailing > max_gap_days)  # MUTATION",
     "validation/scripts/test_mot_continuity.py"),
    ("MUT-F05",
     "automation/metrics/append_metrics.py",
     "                          today, cls, require_fresh=True, min_coverage=min_cov,",
     "                          today, cls, require_fresh=False, min_coverage=min_cov,  # MUTATION",
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F07",
     "automation/metrics/append_metrics.py",
     '    except ValueError as e:\n        return {}, f"metric history is not valid JSON: {e}"',
     '    except ValueError as e:\n        return {}, None  # MUTATION',
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F02",
     "validation/scripts/verification_methods.py",
     "            if not ident:\n                # F02: an automated method with no method_id is uncountable and\n                # unbindable; surface it informationally, do not count it.\n                strings += 1\n                continue",
     "            if not ident:\n                seen.add(str(id(t)))  # MUTATION count id-less automated\n                continue",
     "validation/scripts/test_vvk_automated_methods.py"),
    ("MUT-F03",
     "automation/metrics/append_metrics.py",
     '            if check_filter and pf.get("check") != check_filter:\n                continue  # F03: check-scoped key rejects other checks',
     '            if False:  # MUTATION drop check filter\n                continue',
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F08",
     "automation/collectors/collectors.py",
     '            if "ServerSideEncryptionConfigurationNotFound" in name:\n                checked += 1  # evaluated: no encryption configured\n            else:\n                unmeasured += 1',
     '            checked += 1  # MUTATION count any error as evaluated\n            if False:\n                unmeasured += 1',
     "automation/collectors/test_collectors.py"),
    ("MUT-F09",
     "automation/collectors/collectors.py",
     '        if more:\n            # Bounded sample: report the enabling signal WITHOUT a full-coverage',
     '        if False:  # MUTATION ignore bounded-sample partial\n            # Bounded sample: report the enabling signal WITHOUT a full-coverage',
     "automation/collectors/test_collectors.py"),
    ("MUT-F10",
     "sdr.py",
     "    return _d.datetime.now(_d.timezone.utc).date()",
     "    return _d.date.today()  # MUTATION local clock",
     "validation/scripts/test_utc_clock.py"),
    ("MUT-F11",
     "validation/scripts/build_sdr.py",
     "    _u = _utc_today()\n    cutoff = (_u - _dd.timedelta(days=365)).isoformat()\n    _today = _u.isoformat()",
     "    cutoff = (_dd.date.today() - _dd.timedelta(days=365)).isoformat()  # MUTATION local clock\n    _today = _dd.date.today().isoformat()",
     "validation/scripts/test_build_sdr_utc_window.py"),
    ("MUT-F12",
     "audit/release_gate.py",
     '        ("mutation-runner",\n         [sys.executable, "audit/mutation_tests.py"]),\n',
     '        # MUTATION: mutation runner dropped from the release gate\n',
     "automation/pipeline/test_release_gate.py"),
    ("MUT-F13",
     "audit/mutation_tests.py",
     "    if skipped:\n        # AUD-F13",
     "    if False:  # MUTATION skips pass\n        # AUD-F13",
     "audit/test_mutation_runner.py"),
    ("MUT-F14",
     "audit/mutation_tests.py",
     "    problems = []\n    runner_ids = [m[0] for m in mutations]",
     "    return []  # MUTATION ledger never reconciled\n    runner_ids = [m[0] for m in mutations]",
     "audit/test_mutation_runner.py"),
    ("MUT-F15",
     "automation/collectors/collectors.py",
     "        if token is None:\n            return items, False\n        params[param] = token",
     "        return items, False  # MUTATION first page only\n        params[param] = token",
     "automation/collectors/test_collectors.py"),
    ("MUT-F16",
     "automation/metrics/append_metrics.py",
     "        if not check:\n            raise ValueError(",
     "        if False:  # MUTATION accept bare service routes\n            raise ValueError(",
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F17",
     "automation/metrics/append_metrics.py",
     "            if scope > 0 and (evaluated / scope) < min_coverage:\n                return None",
     "            if False:  # MUTATION ignore evaluated coverage\n                return None",
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F18",
     "automation/prefill/prefill_from_facts.py",
     '                "method_id": posture_method_id(pf["service"], pf["check"]),',
     '                "method_id": f"{pf[\'service\']}-collector",  # MUTATION own id scheme',
     "automation/prefill/test_binding_e2e.py"),
    ("MUT-F19",
     "automation/metrics/append_metrics.py",
     '    existing = next((p for p in series if p["date"] == date_str), None)',
     '    existing = None  # MUTATION same-day point replaces earlier run',
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F20",
     "automation/metrics/publish_history.py",
     '    if etag:\n        params["IfMatch"] = etag\n    else:\n        params["IfNoneMatch"] = "*"',
     '    if False:  # MUTATION unconditional overwrite\n        params["IfMatch"] = etag',
     "automation/metrics/test_publish_history.py"),
    ("MUT-F21",
     "sdr.py",
     "    if not 1 <= days <= MOT_MAX_GAP_DAYS_CEILING:\n        return None,",
     "    if False:  # MUTATION any tolerance accepted\n        return None,",
     "validation/scripts/test_mot_continuity.py"),
    ("MUT-F22",
     "audit/requirements_oracle.py",
     "            if expected[rid].get(field) != actual[rid].get(field):",
     "            if False:  # MUTATION field differences ignored",
     "audit/test_requirements_oracle.py"),
    ("MUT-F23",
     "validation/scripts/validate_sdr.py",
     '    cls = (os.environ.get("SDR_VALIDATE_CLASS") or active_cls).lower()',
     '    cls = active_cls  # MUTATION always the active class',
     "validation/scripts/test_validate_class_matrix.py"),
    ("MUT-F24",
     "validation/scripts/validate_sdr.py",
     '        json.dump({"generated": stamp, "class": cls.upper(), "results": ksi_results}, f, indent=1)',
     '        json.dump({"generated": stamp, "class": cls.upper(), "ksi_results": ksi_results}, f, indent=1)  # MUTATION',
     "validation/scripts/test_assurance_graph_method_count.py"),
    ("MUT-F25",
     "validation/scripts/build_sbom.py",
     "    lock = _parse_lock(LOCK)",
     "    lock = None  # MUTATION ignore the committed lock",
     "validation/scripts/test_lock_closure.py"),
    ("MUT-F26",
     "automation/collectors/evidence_wiring.py",
     '    evidence["xEvidenceContentHash"] = evidence_hash(canonical_payload(evidence))',
     '    evidence["xEvidenceContentHash"] = evidence_hash(evidence["xSourceFact"])  # MUTATION unbound digest',
     "validation/scripts/test_evidence_integrity.py"),
    ("MUT-F27",
     "automation/collectors/evidence_wiring.py",
     "    parts = [service, check]\n    if scope:\n        parts.append(scope)",
     "    parts = [service, check]\n    if False:  # MUTATION scope dropped from the pointer\n        parts.append(scope)",
     "automation/collectors/test_evidence_wiring.py"),
    ("MUT-F28",
     "automation/collectors/evidence_wiring.py",
     '        out["summary"] = scrub_text(detail, SUMMARY_MAX)',
     '        out["summary"] = detail[:SUMMARY_MAX]  # MUTATION verbatim detail',
     "automation/collectors/test_evidence_wiring.py"),
    # Fail-closed collection loop (review items 2, 3, 4).
    ("MUT-F29",
     "automation/collectors/collect_facts.py",
     '    if outcome["evaluated"] == 0:',
     '    if False:  # MUTATION an all-errored run reports success again',
     "automation/collectors/test_collection_fail_closed.py"),
    ("MUT-F30",
     "automation/metrics/append_metrics.py",
     '    if appended:\n        meta["last_run"] = date_str',
     '    if True:  # MUTATION last_run advances on an empty run\n        meta["last_run"] = date_str',
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F31",
     ".github/workflows/living-sdr-loop.yml",
     '            python automation/metrics/publish_history.py restore --bucket "$SDR_METRIC_HISTORY_BUCKET"\n',
     '            # MUTATION history never restored: every night starts empty\n',
     "automation/collectors/test_collection_fail_closed.py"),
    ("MUT-F32",
     "automation/pipeline/sdr-pipeline.yaml",
     "            - !If [CollectorOn, !Ref CollectorProject, !Ref \"AWS::NoValue\"]\n      State: ENABLED\n      Targets:\n        - Id: sns\n          Arn: !Ref NotificationTopic\n\n  NotificationTopicPolicy:",
     "      State: ENABLED\n      Targets:\n        - Id: sns\n          Arn: !Ref NotificationTopic\n\n  NotificationTopicPolicy:",
     "automation/collectors/test_collection_fail_closed.py"),
    ("MUT-F33",
     "sdr.py",
     "    gap = (today - max(dates)).days\n    return gap if gap > threshold else None",
     "    return None  # MUTATION staleness never reported",
     "validation/scripts/test_mot_continuity.py"),
    ("MUT-F34",
     "audit/release_gate.py",
     '        ("pip-audit",\n         [sys.executable, "-m", "pip_audit", "-r", "requirements.lock",',
     '        ("pip-audit-disabled",  # MUTATION vulnerability audit dropped from the gate\n         [sys.executable, "-c", "pass", "requirements.lock",',
     "automation/collectors/test_collection_fail_closed.py"),
    # Word-document integrity and sample residue (review items 1 and 5).
    ("MUT-F35",
     "validation/scripts/build_docx.py",
     "            info = zipfile.ZipInfo(name, date_time=ZIP_FIXED_DATETIME)",
     "            info = zipfile.ZipInfo(name, date_time=_dt.datetime.now().timetuple()[:6])  # MUTATION wall clock",
     "validation/scripts/test_docx_integrity.py"),
    ("MUT-F36",
     "validation/scripts/build_inactive_classes.py",
     'PER_CLASS_STEPS = ("build_sdr.py", "build_docx.py")',
     'PER_CLASS_STEPS = ("build_sdr.py",)  # MUTATION inactive Word documents never rebuilt',
     "validation/scripts/test_docx_integrity.py"),
    # Attested metric history (review item 6).
    ("MUT-F37",
     "automation/metrics/history_integrity.py",
     '    body = {k: v for k, v in obs.items() if k != "hash"}',
     '    body = {k: v for k, v in obs.items() if k not in ("hash", "prev_hash", "passing", "total")}  # MUTATION hash no longer covers content or linkage',
     "automation/metrics/test_history_integrity.py"),
    # AUD-F38: a labelled proposal is unanswered until a human accepts it.
    ("MUT-F38",
     "validation/scripts/unreviewed_text.py",
     '    "DRAFT (",      # draft_narratives.py output',
     '    # "DRAFT (",  # MUTATION machine drafts count as answers',
     "validation/scripts/test_unreviewed_text.py"),
    # AUD-F39: a content minimum binds at the class the offering submits; the
    # inactive-class matrix run reports it, never fails on it.
    ("MUT-F39",
     "validation/scripts/validate_sdr.py",
     '    vvk_hard = force == "MUST" and bool(populated_below) and not inactive_run',
     '    vvk_hard = force == "MUST" and bool(populated_below)  # MUTATION inactive-class run fails a Class B offering on Class C minimums',
     "validation/scripts/test_validate_class_matrix.py"),
    # AUD-F40: an adoption advances the curated dataset_version pins with the
    # dataset; the 2026-10-07 drift run left them behind and could not open its PR.
    ("MUT-F40",
     "validation/scripts/update_sources_lock.py",
     '    pin_changes, holds = refresh_dataset_pins(version, ds)',
     '    pin_changes, holds = [], []  # MUTATION the adoption leaves every curated pin at the old dataset',
     "validation/scripts/test_update_sources_lock.py"),
    # AUD-F41: the dataset diff compares every key of a rule, not a chosen list;
    # the 2026.10.05.01 adoption summary missed the PAIN N0 rating, three notes
    # and two notification changes.
    ("MUT-F41",
     "validation/scripts/dataset_diff.py",
     '    keys = (set(old_rule) | set(new_rule)) - {HISTORY_KEY}',
     '    keys = {"force", "statement"}  # MUTATION compare the pre-F41 field list only',
     "validation/scripts/test_dataset_diff.py"),
    # AUD-F42: a store record whose rule or KSI the dataset no longer defines is
    # reported; the 2026.10.08.01 adoption left FRC-CSX-MOT behind in silence.
    ("MUT-F42",
     "validation/scripts/build_sdr.py",
     '    rules = sorted(r for r in (records.get("frr") or {}) if rule_ids and r not in rule_ids)',
     '    return [], []  # MUTATION orphaned records are never reported\n    rules = sorted(r for r in (records.get("frr") or {}) if rule_ids and r not in rule_ids)',
     "validation/scripts/test_orphan_records.py"),
    # AUD-F43: the drift workflow's PR hand-off is fail-visible; the 2026-10-09
    # run swallowed GitHub's refusal as "PR may already exist" and exited 0.
    ("MUT-F43",
     ".github/workflows/drift-check.yml",
     '          if gh pr create --title "CR26 dataset update: adopt $NEWVER" --body "$BODY"; then\n            exit 0\n          fi\n',
     '          gh pr create --title "CR26 dataset update: adopt $NEWVER" --body "$BODY" || echo "PR may already exist for this dataset version."  # MUTATION fail-open hand-off\n          exit 0\n',
     "automation/collectors/test_collection_fail_closed.py"),
    # AUD-F44: a dataset adoption advances the markdown-changelog baseline in
    # the adoption commit; the 2026.10.08.01 adoption left it behind and the
    # next scheduled run (38051982680) re-reported the entry as drift (#211).
    ("MUT-F44",
     ".github/workflows/drift-check.yml",
     '          python validation/scripts/markdown_changelog.py --file /tmp/changelog.md \\\n            --version "$NEWVER" --entry-out /tmp/changelog-entry.txt \\\n            --write-baseline .github/.markdown-changelog-baseline\n',
     '          echo "(changelog entry unavailable)" > /tmp/changelog-entry.txt  # MUTATION adoption forgets the markdown baseline\n',
     "automation/collectors/test_collection_fail_closed.py"),
    # AUD-F45: `init --set` accepts the dotted key its own gap report prints for
    # a flat block and refuses a key that is not a question; the consultant-flow
    # exercise lost all four CPO-CSO-MTD answers to a silent ignore.
    ("MUT-F45",
     "sdr.py",
     '            given = [k for k in (target_key, f"{block}.{sub}") if k in overrides]\n            if given:\n                resp = overrides[given[0]]\n                consumed.update(given)\n',
     '            given = [k for k in (target_key,) if k in overrides]\n            if given:\n                resp = overrides[given[0]]\n                consumed.update(set(overrides))  # MUTATION bare key only; unknown keys silently ignored\n',
     "validation/scripts/test_init_wizard.py"),
    # AUD-F46: a sidecar proposes only what its producer authors; the stale
    # snapshot it was copied from is not a proposal. The exercise's
    # `--accept-all prefill` reverted an accepted narrative to TBD.
    ("MUT-F46",
     "automation/review/review_proposals.py",
     '                    if not _authored_by(src_name, path, prop):\n',
     '                    if False:  # MUTATION any snapshot difference is a proposal from that sidecar\n',
     "automation/review/test_review_proposals.py"),
    # AUD-F47: structured tests/evidence are accepted or rejected as collected;
    # an edit wrapped prose into the list of schema objects.
    ("MUT-F47",
     "automation/review/review_proposals.py",
     '            if path[0] in STRUCTURED_FIELDS:\n                # AUD-F47: tests and evidence are lists of schema objects',
     '            if False:  # MUTATION prose may replace structured tests/evidence\n                # AUD-F47: tests and evidence are lists of schema objects',
     "automation/review/test_review_proposals.py"),
    # AUD-F48: prefilled text carries no markdown; backticks around the rule
    # name failed the human-readable hygiene gate once the facts were accepted.
    ("MUT-F48",
     "automation/prefill/prefill_from_facts.py",
     '                "method": (f"Automated (collector): AWS Config rule {check[\'target\']} "\n',
     '                "method": (f"Automated (collector): AWS Config rule `{check[\'target\']}` "  # MUTATION markdown in human-readable text\n',
     "automation/prefill/test_prefill.py"),
    # AUD-F49: the drafter's observed posture includes the indicator's own
    # Config-rule facts; it claimed none were collected one item after prefill
    # proposed them as the indicator's tests.
    ("MUT-F49",
     "automation/ai/draft_narratives.py",
     '    facts = (config_facts_for_ksi(ksi_entry, config_by_rule)\n             + posture_facts_for_ksi(ksi_entry, posture_by_service, service_map))\n',
     '    facts = posture_facts_for_ksi(ksi_entry, posture_by_service, service_map)  # MUTATION config-rule facts invisible to the drafter\n',
     "automation/ai/test_draft_narratives.py"),
    # AUD-F50: the CPO-CSO-OVR list's CPO-CSO-MTD item derives from the four
    # profile fields the wizard asks; it read only a separate pointer, so a
    # wizard-complete profile still blocked preflight on CPO-CSO-MTD.
    ("MUT-F50",
     "validation/scripts/build_cpo.py",
     '        elif rid == "CPO-CSO-MTD":\n            # Same principle (AUD-F50)',
     '        elif False:  # MUTATION CPO-CSO-MTD read only from the cpo_required_information pointer\n            # Same principle (AUD-F50)',
     "validation/scripts/test_profile_traceability.py"),
    # AUD-F51: the profile contract is class-aware; a class-blind required_gaps
    # demanded a FedRAMP Recognized assessor and a Secure Configuration Guide of
    # a Class A provider on the alternative-framework path.
    ("MUT-F51",
     "validation/scripts/profile_contract.py",
     "            if field_required_at(f, profile) and field_missing(f, profile.get(f))]",
     "            if field_missing(f, profile.get(f))]  # MUTATION class-blind required fields",
     "validation/scripts/test_profile_contract_classes.py"),
    # AUD-F53 (component gate): the manifest's "Class B and C" is matched by
    # class letter tokens; the substring form found the A in CLASS and AND, so
    # the SCG scaffold blocked every Class A package.
    ("MUT-F53",
     "sdr.py",
     '    return str(cls).upper() in set(re.findall(r"\\b([A-D])\\b", req.upper()))',
     '    return str(cls).upper() in req.upper()  # MUTATION substring class match',
     "validation/scripts/test_profile_contract_classes.py"),
    # AUD-F52: a CDS-CSO-PUB listing never makes a field unconditional on its
    # own; dropping the assessor_id exemption makes an optional CPO schema
    # member (assessor) identity-required at every class, which the policy test
    # checks against the schema's required list and FRC-APP-FIA's class force.
    ("MUT-F52",
     "validation/scripts/profile_contract.py",
     '    "assessor_id": ("a",),\n}',
     '}  # MUTATION assessor_id unconditional at every class',
     "validation/scripts/test_profile_contract_classes.py"),
    # AUD-F54: a rule's artifacts are classified per obligation; the joined
    # string let one "if applicable" item make a mandatory sibling advisory.
    ("MUT-F54",
     "sdr.py",
     '    kinds = [k for _t, k in artifact_obligations(strs)]\n    if not kinds:\n        return None\n',
     '    kinds = [_classify_artifact_text(" ".join(strs))] if strs else []  # MUTATION rule-level joined classification\n    if not kinds:\n        return None\n',
     "validation/scripts/test_artifact_obligations.py"),
    # AUD-F55: the class table in docs/certification-classes.md is rendered from
    # the canonical data; a hand edit that restores the stale "Class B KMT is
    # MUST" statement must fail the docs gate.
    ("MUT-F55",
     "docs/certification-classes.md",
     "| `MAY` include | `SHOULD` include 30-day and one-year summaries |",
     "| `MAY` include | `MUST` include 30-day and one-year summaries |",
     "validation/scripts/test_docs_class_table.py"),
    # AUD-F56: a MAS-by-KSI cell is demonstrated only when the provider's
    # reference resolves into the KSI record; a reference that resolves to
    # nothing must read as unresolved, never as coverage.
    ("MUT-F56",
     "validation/scripts/build_mas_coverage.py",
     "                    if refs and not missing and not unbound:\n                        cell[\"status\"] = \"demonstrated\"",
     "                    if refs:  # MUTATION any reference counts as coverage\n                        cell[\"status\"] = \"demonstrated\"",
     "validation/scripts/test_mas_coverage.py"),
    # AUD-F57: under a signing-required signer a hashless entry is a HARD
    # downgrade (hash + signature deleted). The mutation restores the old
    # behaviour: the hashless soft return is taken before the signer is consulted.
    ("MUT-F57",
     "validation/scripts/validate_evidence.py",
     "    if not h:\n        if signer_required:",
     "    if not h:  # MUTATION hashless is always soft\n        if False:",
     "validation/scripts/test_evidence_integrity.py"),
    # AUD-F58: prefill proposes evidence through the canonical factory so the
    # entry carries a recomputable digest. The mutation strips the digest from
    # every proposed entry (the pre-F58 hand-built shape).
    ("MUT-F58",
     "automation/prefill/prefill_from_facts.py",
     "            ev = fact_to_evidence(cf, location_base, scope_key=scope_key)",
     "            ev = fact_to_evidence(cf, location_base, scope_key=scope_key)\n"
     "            ev and ev.pop(\"xEvidenceContentHash\", None)  # MUTATION hashless proposal",
     "automation/prefill/test_prefill.py"),
    # AUD-F59: under production-assurance an evidence entry counts toward
    # linkage only when VERIFIED. The mutation lets findings (hashless,
    # unresolvable, placeholder) count, listing only hard failures.
    ("MUT-F59",
     "sdr.py",
     "            if outcome != \"verified\":",
     "            if outcome == \"hard\":  # MUTATION findings count as linkage",
     "validation/scripts/test_production_evidence_linkage.py"),
    # AUD-F60: the signature block records key_reference(key id), never the
    # KMS ARN that carries the signer's account id into the scanned package.
    ("MUT-F60",
     "automation/collectors/sign_evidence.py",
     "        \"keyId\": key_reference(key_id),",
     "        \"keyId\": key_id,  # MUTATION record the ARN verbatim",
     "automation/collectors/test_sign_evidence.py"),
    ("MUT-F61",
     "audit/release_gate.py",
     '        ("class-c-attack-harness",\n         [sys.executable,\n'
     '          "examples/sample-offering-class-c/build_class_c_sample.py", "--attack"]),\n',
     '        # MUTATION: attack harness dropped from the release gate (manual run again)\n',
     "automation/pipeline/test_release_gate.py"),
    # AUD-F62..F64: orthogonal provenance. Each mutation disables ONE semantic
    # gate; the regression tampers that dimension with a recomputed, re-signed
    # digest, so the generic hash tripwire cannot be what kills it.
    ("MUT-F62",
     "validation/scripts/validate_evidence.py",
     '    if f"{service}:{check}" in slot["keys"]:\n        return ("bound", "")\n'
     '    return ("unbound", f"SOURCE NOT BOUND - {service}:{check} is not',
     '    if f"{service}:{check}" in slot["keys"]:\n        return ("bound", "")\n'
     '    return ("bound", "")  # MUTATION any source binds to any KSI\n'
     '    return ("unbound", f"SOURCE NOT BOUND - {service}:{check} is not',
     "validation/scripts/test_provenance_mutations.py"),
    ("MUT-F63",
     "validation/scripts/validate_evidence.py",
     '    if loc.endswith(expected_tail):\n        return ("bound", "")',
     '    if True:  # MUTATION pointer never compared to the source fact\n        return ("bound", "")',
     "validation/scripts/test_provenance_mutations.py"),
    ("MUT-F64",
     "sdr.py",
     '    if now <= hard_expiry:\n        return "stale"\n    return "expired"',
     '    if now <= hard_expiry:\n        return "stale"\n    return "stale"  # MUTATION evidence never expires',
     "validation/scripts/test_provenance_mutations.py"),
    ("MUT-F65",
     "validation/scripts/class_support.py",
     'SUPPORTED_CLASSES = ("a", "b", "c")\n',
     'SUPPORTED_CLASSES = ("a", "b", "c", "d")  # MUTATION Class D treated as supported\n',
     "validation/scripts/test_class_support.py"),
    ("MUT-F66",
     "audit/release_gate.py",
     '    overall = "FAIL" if failed else "PASS"\n    write_results(records, wanted, overall)\n',
     '    overall = "FAIL" if failed else "PASS"\n    # MUTATION: gate results never written\n',
     "automation/pipeline/test_release_gate.py"),
    ("MUT-F67",
     "validation/scripts/build_rule_test_map.py",
     '            if rid not in known:\n                unresolved["rule_ids"].append({"id": rid, "source": d.get("id")})\n                continue\n',
     '            if rid not in known:\n                continue  # MUTATION unresolved ids dropped silently\n',
     "validation/scripts/test_rule_test_map.py"),
    # MCE-01 (AUD-F68/F69): the adapter fact contract and the platform-neutral
    # raw-scope refusal. F68 makes a contract violation pass through to
    # conversion; F69 narrows the raw-scope refusal back to the AWS account
    # field, so a tenant/subscription/project identifier would export raw.
    ("MUT-F68",
     "automation/collectors/evidence_wiring.py",
     '    if bad:\n        raise FactContractError(',
     '    if False:  # MUTATION contract violations never refuse\n        raise FactContractError(',
     "automation/collectors/test_fact_contract.py"),
    ("MUT-F69",
     "automation/collectors/evidence_wiring.py",
     '    raw_ids = [(k, fact[k]) for k in raw_scope_fields()\n',
     '    raw_ids = [(k, fact[k]) for k in ("account",)  # MUTATION only AWS accounts are scopes\n',
     "automation/collectors/test_fact_contract.py"),
    # MCE-02 (AUD-F70/F71): the mapping-driven adapter's two fail-closed
    # invariants. F70 makes an unmapped source status default to PASS; F71
    # reports an empty export as a completed collection.
    ("MUT-F70",
     "automation/collectors/mapping_adapter.py",
     'UNMAPPED_STATUS = "UNKNOWN"\n',
     'UNMAPPED_STATUS = "PASS"  # MUTATION unmapped source states read as passing\n',
     "automation/collectors/test_mapping_adapter.py"),
    ("MUT-F71",
     "automation/collectors/mapping_adapter.py",
     '            self._last.update({"status": "not-run",\n'
     '                               "last_error": "export contained no records"})\n',
     '            self._last.update({"status": "collected",  # MUTATION empty export counts as collected\n'
     '                               "last_error": None})\n',
     "automation/collectors/test_mapping_adapter.py"),
    # MCE-03 (AUD-F72): adapters bind exactly the (service, check) pairs they
    # declare. Removing one check's registry binding must fail the regression
    # (and the Class C attack probe that attaches that check under its KSI).
    ("MUT-F72",
     "automation/collectors/thirdparty_adapters.py",
     '    checks = ("sensor_coverage", "open_detections", "prevention_policy")\n',
     '    checks = ("sensor_coverage", "prevention_policy")  # MUTATION one check binding removed\n',
     "validation/scripts/test_adapter_source_bindings.py"),
    # AUD-F73 / MCE-09: the evidence store as attested PROPERTIES. The one
    # blocker is a production-assurance declaration with neither versioning nor
    # write-once attested. Mutation: that contradiction never fires, so a
    # tamper-evident declaration with nothing behind it reaches READY. The
    # regression's contradiction checks (and the Class C probe) must go RED.
    ("MUT-F73",
     "sdr.py",
     '    if production and attested.get("versioned") is False and attested.get("write_once") is False:\n',
     '    if False and production and attested.get("versioned") is False and attested.get("write_once") is False:  # MUTATION contradiction disabled\n',
     "validation/scripts/test_evidence_store_properties.py"),
    # AUD-F74 / MCE-08: the pluggable signer contract. The software-key signer
    # is no longer treated as not-separately-administered, so a PEM key held by
    # the collecting pipeline passes production-assurance; the regression's AC4
    # checks and the Class C probe go RED. (The key-reference GUID refusal is
    # proven by hand in the PR: one runner id per defect is the ledger rule.)
    ("MUT-F74",
     "automation/collectors/signers.py",
     'NOT_SEPARATELY_ADMINISTERED = ("software-key",)\n',
     'NOT_SEPARATELY_ADMINISTERED = ()  # MUTATION software key treated as separately administered\n',
     "automation/collectors/test_signers.py"),
    # AUD-F75 / MCE-07: the fact contract's raw-scope list had no kind for an
    # on-premises scan target, so a host-keyed fact would have been exported
    # with its hostname silently dropped (one shared scope for every host,
    # the AUD-F27 collision) instead of refused without a scope key. Mutation:
    # `host` leaves x-rawScopeFields; the regression's refusal check goes RED.
    ("MUT-F75",
     "automation/collectors/fact-contract.schema.json",
     '"x-rawScopeFields": ["account", "tenant", "subscription", "compartment", "project", "organization", "host"],\n',
     '"x-rawScopeFields": ["account", "tenant", "subscription", "compartment", "project", "organization"],\n',
     "automation/collectors/test_xccdf_adapter.py"),
    # AUD-F76 / MCE-07: the XCCDF result vocabulary is the standard's. Mutation:
    # the agreement check never reports a disagreement, so a provider table that
    # relabels notchecked / error / fixed as PASS registers; the regression's
    # AC2 refusal checks go RED.
    ("MUT-F76",
     "automation/collectors/xccdf_reader.py",
     '        elif given != expected:\n',
     '        elif False and given != expected:  # MUTATION relabelled standard values accepted\n',
     "automation/collectors/test_xccdf_adapter.py"),
    # AUD-F77 / MCE-04: a findings export carries one record PER RESOURCE, so
    # two findings of one category in one scope and region resolved to ONE
    # evidence pointer and the record store kept only the later observation (a
    # resolved finding replaced a still-active one). Mutation: the adapter path
    # stops refusing a batch whose facts share a pointer; the regression's
    # refusal check goes RED (the batch converts, two entries at one pointer).
    ("MUT-F77",
     "automation/collectors/evidence_wiring.py",
     '        shared = pointer_collisions(evidence)\n        if shared:\n',
     '        shared = pointer_collisions(evidence)\n        if False and shared:  # MUTATION colliding batch converts silently\n',
     "automation/collectors/test_scc_adapter.py"),
    # (Second AUD-F77 guarantee, the KEYED record id, is proven by hand in the
    # PR: record_ref switched to a plain SHA-256 of the name fails the
    # regression's two-keys-two-ids check. Not a runner entry: one runner id per
    # defect is the ledger rule.)
    # AUD-F78 / MCE-16: every how_to_comply note copied into the SDR extension,
    # the records store and the human-readable SDR is labelled as implementation
    # guidance for the platform the notes layer names, never as the provider's
    # own statement. Mutation: the guidance note stops reading the platform
    # from the note; the regression's label checks go RED.
    ("MUT-F78",
     "validation/scripts/build_sdr.py",
     '    platform = note.get("guidance_platform") or "the platform named in the notes layer"\n',
     '    platform = "the platform named in the notes layer"  # MUTATION platform label dropped\n',
     "validation/scripts/test_platform_labelled_notes.py"),
    # AUD-F79 / MCE-12: the provenance gate bound every source the REPOSITORY
    # knows (AWS collector registry, Config-rules manifest, every registered
    # adapter), not the sources the OFFERING declares it operates, so an
    # offering with no AWS platform could attach a valid signed entry claiming
    # an AWS Config rule. Mutation: the platform rule always says AWS; the
    # regression's non-AWS checks go RED.
    ("MUT-F79",
     "validation/scripts/validate_evidence.py",
     '    aws = declares_aws_platform(profile)\n',
     '    aws = True  # MUTATION every offering binds the AWS sources\n',
     "validation/scripts/test_offering_scoped_sources.py"),
    # (Second AUD-F79 guarantee, an adapter binds only when the profile ENABLES
    # it, is proven by hand in the PR: the enabled filter in
    # _registered_adapters replaced by every registered adapter fails the
    # regression's disabled-Falcon check. Not a runner entry: one runner id per
    # defect is the ledger rule.)
    # AUD-F80 / MCE-12: the adapter apply path never supplied an evidence
    # location base, so every adapter-derived pointer was an sdr://placeholder/
    # pseudo-URI that package-preflight refuses at Class C. Mutation: the
    # pre-fix call (no location_base); the regression's pointer checks go RED.
    ("MUT-F80",
     "automation/collectors/apply_third_party_evidence.py",
     '            evidence = adapter.to_evidence(raw, location_base=location_base, scope_key=scope_key)\n',
     '            evidence = adapter.to_evidence(raw, scope_key=scope_key)  # MUTATION base dropped\n',
     "validation/scripts/test_offering_scoped_sources.py"),
    # AUD-F81 / MCE-12: the AUD-F63 pointer check predated the AUD-F77 record
    # segment, so every entry from a source that reports one record per
    # resource was pointer-unbound and production-assurance was unsatisfiable
    # for it. Mutation: the classifier ignores the record again; the
    # regression's per-record pointer check goes RED.
    ("MUT-F81",
     "validation/scripts/validate_evidence.py",
     '    if sf.get("record"):\n        parts.append(sf.get("record"))\n',
     '    if False and sf.get("record"):  # MUTATION record segment ignored by the pointer check\n        parts.append(sf.get("record"))\n',
     "validation/scripts/test_provenance_mutations.py"),
    ("MUT-F82",
     "automation/metrics/append_metrics.py",
     "        service, check = parse_service_key(key)\n        for pf in posture_by_service.get(service, []):\n            if check and pf.get(\"check\") != check:\n                continue\n            if _obs_date(pf.get(\"collected_at\")) == today:\n",
     "        service, check = key, None  # MUTATION freshness looks the raw check-scoped key up again\n        for pf in posture_by_service.get(service, []):\n            if check and pf.get(\"check\") != check:\n                continue\n            if _obs_date(pf.get(\"collected_at\")) == today:\n",
     "automation/metrics/test_append_metrics.py"),
    ("MUT-F83",
     "automation/collectors/collectors.py",
     '    "access-analyzer:ListAnalyzers",\n    "access-analyzer:ListFindings",\n',
     '    "accessanalyzer:ListAnalyzers",  # MUTATION boto3 client name used as the IAM prefix again\n    "accessanalyzer:ListFindings",\n',
     "automation/collectors/test_collectors.py"),
    ("MUT-F84",
     "automation/collectors/collect_facts.py",
     '        names = deployed.get(rule, []) if resolution == "deployed-names" else [rule]\n',
     '        names = [rule]  # MUTATION exact ConfigRuleName only; deployed names ignored again\n',
     "automation/collectors/test_config_rule_resolution.py"),
    ("MUT-F85",
     "automation/collectors/collect_multi_account.py",
     "    if registry is not None:\n",
     "    if registry is not None and False:  # MUTATION fan-out skips the Config rule unit again\n",
     "automation/collectors/test_multi_account_config_rules.py"),
    ("MUT-F86",
     "README.md",
     "CR26%20dataset-2026.10.13.01-0b7285",
     "CR26%20dataset-2026.10.08.01-0b7285",
     "validation/scripts/test_docs_facts.py"),
]


def run_one(mid, rel, find, repl, test):
    """Apply one mutation, run its regression test against the source on disk,
    restore. Returns 'killed', 'survived' or 'skipped'."""
    path = os.path.join(BASE, rel)
    original_bytes = _read_bytes(path)
    src = _read(path)
    if find not in src:
        print(f"SKIP {mid}: target code not present on this commit")
        return "skipped"
    _write(path, src.replace(find, repl, 1))
    try:
        # No cached bytecode may answer for the mutated source (see module doc).
        _purge_bytecode()
        r = subprocess.run([sys.executable, test], cwd=BASE, env=_no_bytecode_env(),
                           capture_output=True, text=True, timeout=1800)
    finally:
        _restore(rel, original_bytes)
        _purge_bytecode()
    if r.returncode != 0:
        print(f"KILLED {mid}: mutation detected (test red, rc={r.returncode})")
        return "killed"
    print(f"SURVIVED {mid}: NOT DETECTED -- test-coverage DEFECT")
    return "survived"


LEDGER = os.path.join(BASE, "audit", "defect-ledger.json")


def _ledger_mutation_ids(ledger):
    """Return {mutation_id: defect_id} for every CLOSED defect the ledger claims
    is mutation_verified. The ledger's `mutation` field is free text that starts
    with the runner id ("MUT-F04: scope key -> ..."); the id is the first token
    up to the colon. A CLOSED + mutation_verified defect with no parseable id is
    itself a ledger defect and is reported under the empty id."""
    out = {}
    for d in (ledger or {}).get("defects", []):
        if d.get("status") != "CLOSED" or d.get("mutation_verified") is not True:
            continue
        text = str(d.get("mutation") or "")
        mid = text.split(":", 1)[0].strip()
        if not mid.startswith("MUT-"):
            mid = ""
        out.setdefault(mid, []).append(d.get("id"))
    return out


def reconcile_ledger(outcomes, mutations=None, ledger=None):
    """Cross-check the ledger against what the runner actually executed.

    outcomes: {mutation_id: 'killed'|'survived'|'skipped'} from this run.
    Returns a list of problem strings; empty means the ledger and the runner
    agree and every claimed mutation was executed and killed. The invariant:
    CLOSED + mutation_verified  <=>  exactly one runner entry, executed, KILLED.
    """
    mutations = MUTATIONS if mutations is None else mutations
    if ledger is None:
        with open(LEDGER, encoding="utf-8") as f:
            ledger = json.load(f)
    problems = []
    runner_ids = [m[0] for m in mutations]
    counts = {}
    for mid in runner_ids:
        counts[mid] = counts.get(mid, 0) + 1
    for mid, n in counts.items():
        if n > 1:
            problems.append(f"{mid}: {n} runner entries share one id (must be exactly one)")
    claimed = _ledger_mutation_ids(ledger)
    for mid, defect_ids in sorted(claimed.items()):
        if not mid:
            problems.append(f"{defect_ids}: CLOSED + mutation_verified but no MUT- id in "
                            "the `mutation` field")
            continue
        if mid not in counts:
            problems.append(f"{mid}: ledger says mutation_verified for {defect_ids} but the "
                            "runner has no such mutation (false claim)")
            continue
        outcome = outcomes.get(mid)
        if outcome != "killed":
            problems.append(f"{mid}: ledger says mutation_verified for {defect_ids} but this "
                            f"run's outcome was {outcome!r} (must be 'killed')")
    for mid in counts:
        if mid not in claimed:
            problems.append(f"{mid}: runner entry has no CLOSED + mutation_verified ledger "
                            "defect (unledgered mutation)")
    return problems


def gate_verdict(survived, skipped, problems):
    """The gate's exit code from the three failure classes. Pure, so each rule
    is testable on its own: survivors fail (coverage hole), skips fail
    (AUD-F13: the mutation did not run), ledger problems fail (AUD-F14)."""
    rc = 0
    if survived:
        print("FAIL: surviving mutations mean the regression tests are insufficient.")
        rc = 1
    if skipped:
        # AUD-F13: a skip is a mutation that did NOT run. Passing here would let
        # a refactor silently disarm a closed defect's protection.
        print("FAIL: skipped mutations did not execute: " + ", ".join(skipped)
              + ". Retarget them to the current code (or run on the branch that "
                "carries the defect fix).")
        rc = 1
    if problems:
        print("FAIL: defect ledger and mutation runner disagree:")
        for p in problems:
            print("  - " + p)
        rc = 1
    return rc


def run(mutations=None, ledger=None):
    mutations = MUTATIONS if mutations is None else mutations
    survived, killed, skipped = [], [], []
    outcomes = {}
    for mid, rel, find, repl, test in mutations:
        outcome = run_one(mid, rel, find, repl, test)
        outcomes[mid] = outcome
        {"killed": killed, "survived": survived, "skipped": skipped}[outcome].append(mid)
    print("\n--- mutation summary ---")
    print(f"killed={len(killed)} survived={len(survived)} skipped={len(skipped)}")
    problems = reconcile_ledger(outcomes, mutations=mutations, ledger=ledger)
    rc = gate_verdict(survived, skipped, problems)
    if rc == 0:
        print("All mutations executed and detected; ledger reconciled.")
    return rc


if __name__ == "__main__":
    sys.exit(run())
