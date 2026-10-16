"""MCE-17: implementation guidance notes for platforms other than AWS, shipped
as removable data files under guidance/platforms/ and selected by the offering
profile's `guidance_platform`.

What this proves:
  AC1  every shipped platform file is complete and self-describing: a platform
       label, a capture date, a services table (name -> vendor documentation
       URL, https, every name registered in THIRD_PARTY_NOTICE.md and used by
       at least one note), a family override for every FRR family whose
       built-in text names an AWS service (CMU, IEC, MAS, VDR) and nothing
       outside the FRR families, and a note for every KSI in the catalog,
       no more, no fewer;
  AC2  the wording gates hold on every guidance string of every platform file,
       whether or not the string names a vendor: no AWS service name leaks
       into another platform's notes, no comparative or evaluative term from
       the naming guard's lexicon, no compliance-determination verb, no URL in
       the note body (the services table carries them), no em or en dash;
  AC3  selection is fail-closed: no `guidance_platform` or "AWS" yields the
       built-in guidance; a shipped label yields that file's KSI notes, the
       neutral family base plus the file's overrides, and its sources; an
       unknown label is a hard error that names the platforms available and
       never falls back to AWS;
  AC4  end to end through build_notes.main(): a profile selecting a platform
       produces rule and KSI notes labelled with that platform, with per-note
       documentation references for every service the note names and the
       sources recorded at the top level; rebuilding with the real (AWS)
       profile restores the committed artifacts byte for byte;
  AC5  the downstream labels (SDR extension guidance note, DOCX label) read the
       platform from the note, so a Google Cloud, Microsoft Azure or Oracle
       Cloud Infrastructure package is labelled as that platform's examples.

Run:
    python validation/scripts/test_platform_guidance_notes.py
"""

import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, BASE)
import build_notes as bn  # noqa: E402
import build_sdr as bs  # noqa: E402
import build_docx as bd  # noqa: E402
import test_third_party_names as guard  # noqa: E402

_fail = 0

# Families whose built-in (AWS) text names an AWS service; a platform file
# must override each of them or its rule notes would carry AWS guidance under
# another platform's label.
AWS_FAMILIES = {"CMU", "IEC", "MAS", "VDR"}

# AWS service names that must not appear in another platform's notes.
AWS_TOKENS = [
    "AWS", "Amazon", "CloudTrail", "GuardDuty", "Security Hub", "CloudWatch", "EventBridge",
    "Inspector", "IAM Identity Center", "Systems Manager", "Resource Explorer", "Secrets Manager",
    "PrivateLink", "Shield", "S3", "EC2", "ECR", "Lambda", "STS", "Trusted Advisor", "Access Analyzer",
    "cfn-guard", "Config rules", "Config conformance",
]
AWS_RE = re.compile(r"(?<![A-Za-z0-9_])(?:" + "|".join(re.escape(t) for t in AWS_TOKENS) + r")(?![A-Za-z0-9_])")
# A note may describe how to evidence an indicator; it may not say a product
# complies with, satisfies or meets a requirement.
DETERMINATION_RE = re.compile(r"\b(?:complies|compliant|satisf(?:y|ies)|meets|fulfil?ls?)\b", re.IGNORECASE)
DASHES = ("\u2014", "\u2013")


def check(name, cond, detail=""):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name} {detail}")


def _load(*parts):
    with open(os.path.join(BASE, *parts), encoding="utf-8") as f:
        return json.load(f)


def _read_bytes(*parts):
    with open(os.path.join(BASE, *parts), "rb") as f:
        return f.read()


def platform_files():
    out = {}
    for name in sorted(os.listdir(bn.PLATFORM_DIR)):
        if name.endswith(".json"):
            out[name] = _load("guidance", "platforms", name)
    return out


def main():
    files = platform_files()
    ksi_ids = {k["ksi_id"] for k in _load("traceability", "ksi-catalog.json")["indicators"]}
    frr_families = set(_load("references", "fedramp-consolidated-rules.json")["FRR"].keys())
    with open(os.path.join(BASE, guard.NOTICE), encoding="utf-8") as f:
        registered = set(guard.parse_notice(f.read()))

    print("== AC1: every shipped platform file is complete and self-describing")
    check("three platform files are shipped (Google Cloud, Microsoft Azure, Oracle Cloud Infrastructure)",
          sorted(d["platform"] for d in files.values())
          == ["Google Cloud", "Microsoft Azure", "Oracle Cloud Infrastructure"],
          str(sorted(d.get("platform") for d in files.values())))
    for name, data in files.items():
        label = data.get("platform")
        check(f"{name}: platform label, capture date (YYYY-MM-DD) and note present",
              bool(label) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", data.get("captured") or "") is not None
              and len(data.get("note") or "") > 100)
        services = data.get("services") or {}
        check(f"{name}: services table is non-empty and every URL is https",
              services and all(u.startswith("https://") for u in services.values()))
        unregistered = sorted(s for s in services if s not in registered)
        check(f"{name}: every service name is registered in {guard.NOTICE}", not unregistered, str(unregistered))
        all_text = " ".join(list((data.get("family_guidance") or {}).values())
                            + list((data.get("ksi_guidance") or {}).values()))
        unused = sorted(s for s in services if s not in all_text)
        check(f"{name}: every registered service is named by at least one note (no dead registration)",
              not unused, str(unused))
        fam = set((data.get("family_guidance") or {}).keys())
        check(f"{name}: family overrides cover every AWS-specific family and stay inside the FRR families",
              AWS_FAMILIES <= fam <= frr_families, f"missing={sorted(AWS_FAMILIES - fam)} unknown={sorted(fam - frr_families)}")
        kg = set((data.get("ksi_guidance") or {}).keys())
        check(f"{name}: one note per KSI in the catalog ({len(ksi_ids)}), no extras",
              kg == ksi_ids, f"missing={sorted(ksi_ids - kg)} extra={sorted(kg - ksi_ids)}")

    print("== AC2: wording gates on every guidance string")
    for name, data in files.items():
        strings = {**{f"family {k}": v for k, v in (data.get("family_guidance") or {}).items()},
                   **{k: v for k, v in (data.get("ksi_guidance") or {}).items()}}
        leaks = [(k, AWS_RE.search(v).group(0)) for k, v in strings.items() if AWS_RE.search(v)]
        check(f"{name}: no AWS service name in any note", not leaks, str(leaks[:5]))
        evaluative = [(k, guard.LEXICON_RE.search(v).group(0)) for k, v in strings.items() if guard.LEXICON_RE.search(v)]
        check(f"{name}: no comparative or evaluative term in any note (stricter than the guard: every note, vendor named or not)",
              not evaluative, str(evaluative[:5]))
        determinations = [(k, DETERMINATION_RE.search(v).group(0)) for k, v in strings.items() if DETERMINATION_RE.search(v)]
        check(f"{name}: no compliance-determination verb in any note", not determinations, str(determinations[:5]))
        urls = [k for k, v in strings.items() if "http" in v]
        check(f"{name}: no URL inside a note body (the services table carries them)", not urls, str(urls[:5]))
        raw = _read_bytes("guidance", "platforms", name).decode("utf-8")
        check(f"{name}: no em or en dash anywhere in the file", not any(d in raw for d in DASHES))
        check(f"{name}: every note ends with an Evidence sentence",
              all(" Evidence: " in v for k, v in strings.items() if not k.startswith("family")),
              str([k for k, v in strings.items() if not k.startswith("family") and " Evidence: " not in v][:5]))

    print("== AC3: fail-closed selection")
    label, fam, kg, src, pfile = bn.select_platform({})
    check("no guidance_platform: the built-in AWS guidance, no sources, no file",
          label == "AWS" and fam is bn.FAMILY_GUIDANCE and kg is bn.KSI_GUIDANCE and src is None and pfile is None)
    label2, fam2, kg2, src2, pfile2 = bn.select_platform({"guidance_platform": "AWS"})
    check("guidance_platform AWS: identical to absent", (label2, fam2 is fam, kg2 is kg, src2, pfile2) == ("AWS", True, True, None, None))
    label3, fam3, kg3, src3, pfile3 = bn.select_platform({"guidance_platform": "Google Cloud"})
    check("a shipped label resolves to its file", label3 == "Google Cloud" and pfile3 == "google-cloud.json"
          and src3["file"] == "guidance/platforms/google-cloud.json" and src3["services"])
    check("neutral families come from the built-in base, AWS-specific families from the file",
          fam3["AFC"] == bn.FAMILY_GUIDANCE_NEUTRAL["AFC"] and "AWS" not in fam3["CMU"]
          and fam3["CMU"] != bn.FAMILY_GUIDANCE_AWS["CMU"] and set(fam3) == set(bn.FAMILY_GUIDANCE))
    check("the file's KSI guidance covers the catalog", set(kg3) == ksi_ids)
    try:
        bn.select_platform({"guidance_platform": "Nimbus Cloud"})
        err = None
    except SystemExit as e:
        err = str(e)
    check("an unknown label is a hard error that names the platforms available and never falls back to AWS",
          err is not None and "Nimbus Cloud" in err and "Google Cloud" in err and "Microsoft Azure" in err
          and "Oracle Cloud Infrastructure" in err and "never substitutes AWS" in err, str(err)[:200])
    try:
        bn.select_platform({"guidance_platform": ["Google Cloud"]})
        err2 = None
    except SystemExit as e:
        err2 = str(e)
    check("a non-string label is a hard error", err2 is not None)
    check("references list only the services a note actually names, with their URLs",
          bn.guidance_references("Rotate secrets in Secret Manager.", src3) == [
              {"name": "Secret Manager", "url": src3["services"]["Secret Manager"]}]
          and bn.guidance_references("No service named.", src3) == []
          and bn.guidance_references("Secret Manager", None) == [])

    print("== AC4: end to end through build_notes.main(), then byte-identical restore")
    before = {p: _read_bytes("traceability", p) for p in ("rule-notes.json", "ksi-notes.json")}
    real_profile = bn.PROFILE
    tmp_profile = os.path.join(BASE, "traceability", "_mce17_profile.tmp.json")
    with open(tmp_profile, "w", encoding="utf-8") as f:
        json.dump({**_load("profiles", "common", "offering-profile.json"), "guidance_platform": "Microsoft Azure"}, f)
    try:
        bn.PROFILE = tmp_profile
        rc = bn.main()
        rn = _load("traceability", "rule-notes.json")
        kn = _load("traceability", "ksi-notes.json")
    finally:
        bn.PROFILE = real_profile
        os.remove(tmp_profile)
        rc_restore = bn.main()
    check("the platform build returns 0", rc == 0)
    check("every rule and KSI note is labelled Microsoft Azure",
          {v["guidance_platform"] for v in rn["rules"].values()} == {"Microsoft Azure"}
          and {v["guidance_platform"] for v in kn["indicators"].values()} == {"Microsoft Azure"})
    check("the guidance label names the platform",
          all("typical Microsoft Azure approaches" in v["guidance_label"] for v in kn["indicators"].values()))
    check("no KSI note carries an AWS service name",
          not any(AWS_RE.search(v["how_to_comply_guidance"]) for v in kn["indicators"].values()))
    check("no rule note carries an AWS service name (the four AWS families are overridden)",
          not any(AWS_RE.search(v["how_to_comply_guidance"]) for v in rn["rules"].values()))
    lmc = kn["indicators"]["KSI-CMT-LMC"]
    check("a note naming services carries one documentation reference per service named",
          {r["name"] for r in lmc["guidance_references"]} == {"Azure Monitor", "Activity Log", "Log Analytics", "Azure Resource Graph"}
          and all(r["url"].startswith("https://learn.microsoft.com/") for r in lmc["guidance_references"]),
          str(lmc.get("guidance_references")))
    check("the top level records the platform and its sources (file, capture date, services)",
          kn.get("guidance_platform") == "Microsoft Azure" and kn["guidance_sources"]["file"] == "guidance/platforms/azure.json"
          and kn["guidance_sources"]["captured"] and rn.get("guidance_sources", {}).get("services"))
    after = {p: _read_bytes("traceability", p) for p in ("rule-notes.json", "ksi-notes.json")}
    check("rebuilding with the real profile restores both committed artifacts byte for byte",
          rc_restore == 0 and after == before)
    check("the committed artifacts carry no guidance_sources (the AWS layer keeps its shape)",
          "guidance_sources" not in json.loads(after["ksi-notes.json"]))

    print("== AC5: downstream labels read the platform from the note")
    for label in ("Google Cloud", "Microsoft Azure", "Oracle Cloud Infrastructure"):
        check(f"extension guidance note and DOCX label name {label}",
              bs._guidance_note({"guidance_platform": label}, "x").startswith(
                  f"How to comply is SAS advisory guidance describing typical {label}")
              and bd._how_to_comply_label({"guidance_platform": label})
              == f"How to comply (SAS guidance, {label} implementation examples, not the provider's statement):")

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: MCE-17 platform guidance notes ({_fail} failure(s))")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
