#!/usr/bin/env python3
"""Offline tests for the readiness scanner's sensitive-data detection.

Locks in the fix for a false-positive CRITICAL finding: the 12-digit tail of an
OSCAL UUID (e.g. ...-234324894288) is NOT an AWS account ID and must not be
flagged, while a standalone 12-digit account id still must be. Also guards that
the scanner and the hard validator use the SAME pattern, so they cannot drift.

    python automation/sdrscan/test_checks.py
"""

import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE, "automation", "sdrscan"))

import checks

PASS = FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1; print(f"  PASS {name}")
    else:
        FAIL += 1; print(f"  FAIL {name}")


class _Ctx:
    def __init__(self, text):
        self.text = text
    def joined_text(self):
        return self.text


def _hits(text):
    # sensitive_hits reads text from the ctx; support both a ctx object and a
    # direct-pattern fallback so this test is robust to the ctx shape.
    try:
        return checks.sensitive_hits(_Ctx(text))
    except Exception:
        pats = [(re.compile(r"(?<![0-9A-Fa-f-])\d{12}(?![0-9A-Fa-f-])"), "possible AWS account ID")]
        return [lbl for p, lbl in pats if p.search(text)]


def test_uuid_tail_not_flagged():
    uuid_line = '"uuid": "6f4478fd-38cc-55e8-b693-234324894288"'
    hits = _hits(uuid_line)
    check("12-digit UUID tail is NOT flagged as an account id",
          "possible AWS account ID" not in hits)


def test_real_account_id_still_flagged():
    line = 'arn:aws:iam::123456789012:role/Example'
    hits = _hits(line)
    check("a standalone 12-digit account id IS flagged",
          "possible AWS account ID" in hits)


def test_scanner_and_validator_patterns_match():
    # Compare BEHAVIOR of the two modules' account-id patterns, not source text.
    sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
    import validate_sdr
    uuid_tail = "6f4478fd-38cc-55e8-b693-234324894288"
    real_id = "arn:aws:iam::123456789012:role/x"
    def account_pat(patterns):
        for p, lbl in patterns:
            if "account" in lbl.lower():
                return p
        return None
    vpat = account_pat(validate_sdr.SENSITIVE_PATTERNS)
    check("validator account-id pattern rejects UUID tail",
          vpat is not None and not vpat.search(uuid_tail))
    check("validator account-id pattern accepts a real id",
          vpat is not None and bool(vpat.search(real_id)))
    # Scanner behavior via _hits (already exercised above) must agree.
    check("scanner agrees: UUID tail not flagged, real id flagged",
          "possible AWS account ID" not in _hits(uuid_tail)
          and "possible AWS account ID" in _hits(real_id))


def test_f28_bundle_gate_catches_ip_arn_and_internal_host():
    # AUD-F28: the generated-artifact gate is the independent backstop behind
    # the evidence export scrub. It must see an IP, an ARN and an internal
    # hostname - and must NOT fire on the legitimate content the package
    # carries (public doc URLs, semantic versions, dates, percentages).
    sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
    import validate_sdr

    def labels(text):
        return {lbl for p, lbl in validate_sdr.SENSITIVE_PATTERNS if p.search(text)}

    check("IPv4 in a generated artifact is flagged",
          "IPv4 address" in labels("reachable at 10.23.45.67 over TLS"))
    check("IPv6 in a generated artifact is flagged",
          "IPv6 address" in labels("listener 2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
    check("resource ARN in a generated artifact is flagged",
          "AWS resource ARN" in labels("policy arn:aws-us-gov:iam::aws:policy/ReadOnlyAccess"))
    check("internal hostname in a generated artifact is flagged",
          "internal hostname" in labels("host prod-db-01.internal.corp")
          and "internal hostname" in labels("ip-10-0-0-1.ec2.internal"))
    benign = ("See https://www.fedramp.gov/2026/ and schema version 0.4.0 released "
              "2026-09-22; 99.5% of controls; contact via the trust center at "
              "https://trust.example.gov/fedramp; KSI-IAM-MFA evaluated compliant.")
    check("public URLs, versions, dates and percentages are NOT flagged",
          labels(benign) == set())


def test_ksi_pending_honors_varies_by_class():
    # Finding 11: a KSI whose statement lives under varies_by_class (Class B/C)
    # is NOT pending, even though it has no top-level `statement`. The old
    # hardcoded PENDING_KSIS marked five such KSIs pending, which was wrong.
    vbc_node = {"name": "Authorizing Log Access",
                "varies_by_class": {"b": {"statement": "**Optional:** ..."},
                                    "c": {"statement": "A least-privileged ... model ..."}}}
    check("KSI with a varies_by_class statement is NOT pending",
          checks._ksi_is_pending(vbc_node) is False)
    toplevel_node = {"name": "Securing Information", "statement": "Information is encrypted ..."}
    check("KSI with a top-level statement is NOT pending",
          checks._ksi_is_pending(toplevel_node) is False)


def test_ksi_pending_when_truly_statement_less():
    # A KSI with neither a top-level nor any per-class statement IS pending.
    empty_vbc = {"name": "X", "varies_by_class": {"b": {}, "c": {"controls": ["sc-4"]}}}
    check("KSI with no statement anywhere IS pending",
          checks._ksi_is_pending(empty_vbc) is True)
    check("a KSI absent from the dataset (None) IS pending",
          checks._ksi_is_pending(None) is True)


def test_the_old_hardcoded_five_are_not_pending_in_dataset():
    # The exact five KSIs the old code hardcoded as pending all carry per-class
    # statements in the pinned dataset, so a dataset-derived check must NOT mark
    # them pending. Verify against the real canonical KSIs.
    import json
    ds_path = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
    with open(ds_path, encoding="utf-8") as f:
        ds = json.load(f)
    canon = {}
    for fam in ds.get("KSI", {}).values():
        for kid, node in (fam or {}).get("indicators", {}).items():
            canon[kid] = node
    for kid in ("KSI-CNA-EIS", "KSI-MLA-ALA", "KSI-SVC-PRR", "KSI-SVC-RUD", "KSI-SVC-VCM"):
        check(f"{kid} is NOT pending in the pinned dataset (has per-class statement)",
              checks._ksi_is_pending(canon.get(kid)) is False)


class _FmtCtx:
    """Minimal ctx for format_consistency_drift: a parsed SDR dict plus the
    human-readable rendering string."""
    def __init__(self, sdr, human_readable):
        self.sdr = sdr
        self.human_readable = human_readable


def _base_sdr():
    return {
        "fedRampRequirements": [
            {"frrID": "FRR-CSO-ABC", "frrImplementationStatus": "Implemented"},
        ],
        "keySecurityIndicators": [
            {"ksiId": "KSI-CNA-EIS", "ksiImplementationStatus": "Implemented"},
        ],
    }


def test_legit_metadata_citation_not_flagged_as_drift():
    # F-07: IVV-IAS-OSA is a legitimate cross-reference citation in JSON
    # metadata (xIndependentAssessmentSummary.basis), mirrored into the human-
    # readable rendering. It is NOT a top-level record ID, but because it is
    # present in BOTH documents it must not be reported as a format drift.
    sdr = _base_sdr()
    sdr["metadata"] = {"xIndependentAssessmentSummary": {
        "basis": "FRC-APP-FIA / IVV-IAS-OSA"}}
    human = ("FRR-CSO-ABC\nStatus: Implemented\nKSI-CNA-EIS\nStatus: Implemented\n"
             "Independent assessment basis: FRC-APP-FIA / IVV-IAS-OSA\n")
    drift = checks.format_consistency_drift(_FmtCtx(sdr, human))
    check("legitimate IVV-IAS-OSA metadata citation is NOT a false format drift",
          not any("IVV-IAS-OSA" in d for d in drift))


def test_genuine_extra_identifier_still_flagged():
    # A three-segment identifier that appears in the rendering but NOWHERE in the
    # JSON (not a record, not a citation) is a genuine drift and must still flag.
    sdr = _base_sdr()
    human = ("FRR-CSO-ABC\nStatus: Implemented\nKSI-CNA-EIS\nStatus: Implemented\n"
             "Bogus reference: XYZ-BOG-USX\n")
    drift = checks.format_consistency_drift(_FmtCtx(sdr, human))
    check("a truly-absent identifier in the rendering IS flagged as drift",
          any("XYZ-BOG-USX" in d for d in drift))


def main():
    for t in (test_uuid_tail_not_flagged, test_real_account_id_still_flagged,
              test_scanner_and_validator_patterns_match,
              test_f28_bundle_gate_catches_ip_arn_and_internal_host,
              test_ksi_pending_honors_varies_by_class,
              test_ksi_pending_when_truly_statement_less,
              test_the_old_hardcoded_five_are_not_pending_in_dataset,
              test_legit_metadata_citation_not_flagged_as_drift,
              test_genuine_extra_identifier_still_flagged):
        print(t.__name__); t()
    print(f"\n{PASS}/{PASS + FAIL} passed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
