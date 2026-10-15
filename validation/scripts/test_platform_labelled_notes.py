"""MCE-16: platform-labelled implementation notes and optional AWS metadata in
the SDR extension and the human-readable outputs.

What this proves:
  AC1  every how_to_comply note copied into the SDR extension (FRR and KSI
       guidance blocks) and into the records store's fill_guidance carries
       `how_to_comply_platform` naming the platform the notes layer declares
       (today "AWS"), and the guidance note sentence names that platform and
       says it is not the provider's statement; the DOCX label names it too;
  AC2  an offering profile with no aws_partition, primary_region or dr_region
       builds the extension and the human-readable SDR without raising, with
       those members and lines omitted, never invented;
  AC3  a profile that declares the AWS fields yields the committed extension
       metadata members in their committed order and the committed
       human-readable header lines (the generators are pure functions; the
       committed artifacts are compared by the build parity step);
  AC4  removing the platform label is detected (MUT-F78 in the runner; the
       by-hand check here reads the label from a built extension).
Also: every note in traceability/*-notes.json carries guidance_platform, and
the one value in use is "AWS" (the notes layer is AWS-only until a provider on
another platform contributes grounded content).

Run:
    python validation/scripts/test_platform_labelled_notes.py
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, BASE)
import build_sdr as bs  # noqa: E402
import build_docx as bd  # noqa: E402

_fail = 0


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


def _inputs():
    profile = _load("profiles", "common", "offering-profile.json")
    rules = _load("profiles", f"class-{profile['certification_class'].lower()}", "profile.json")["rules"]
    ksis = _load("profiles", "common", "ksi-profile.json")["indicators"]
    records = _load("sdr", "records", "records-store.json")
    return profile, rules, ksis, records


def main():
    profile, rules, ksis, records = _inputs()
    cls = profile["certification_class"].lower()

    print("== notes layer")
    rn = _load("traceability", "rule-notes.json")["rules"]
    kn = _load("traceability", "ksi-notes.json")["indicators"]
    platforms = {v.get("guidance_platform") for v in rn.values()} | {v.get("guidance_platform") for v in kn.values()}
    check("every rule and KSI note carries guidance_platform", None not in platforms and "" not in platforms)
    check("the notes layer names exactly one platform today, AWS", platforms == {"AWS"}, str(platforms))

    print("== AC1: labels in the extension and the records store")
    ext = bs.build_extensions(profile, rules, ksis, records, cls)
    frr_ok = all(e["guidance"].get("how_to_comply_platform") == "AWS"
                 and "AWS implementation approaches" in e["guidance"]["note"]
                 and "not the provider's own statement" in e["guidance"]["note"]
                 for e in ext["frr"].values())
    ksi_ok = all(e["guidance"].get("how_to_comply_platform") == "AWS"
                 and "AWS implementation approaches" in e["guidance"]["note"]
                 and "not the provider's own statement" in e["guidance"]["note"]
                 for e in ext["ksi"].values())
    check(f"every FRR guidance block ({len(ext['frr'])}) names the platform and disclaims the provider's voice", frr_ok)
    check(f"every KSI guidance block ({len(ext['ksi'])}) names the platform and disclaims the provider's voice", ksi_ok)
    check("the platform comes from the note, not the profile",
          bs._guidance_note({"guidance_platform": "ExamplePlatform"}, "x").startswith(
              "How to comply is SAS advisory guidance describing typical ExamplePlatform"))
    check("a note with no platform is labelled as unnamed, never defaulted to AWS",
          "the platform named in the notes layer" in bs._guidance_note({}, "x")
          and "AWS" not in bs._guidance_note({}, "x"))
    fg_ok = all((rec.get("fill_guidance") or {}).get("how_to_comply_platform") == "AWS"
                for rec in records["ksi"].values() if rec.get("fill_guidance"))
    check("the committed records store's fill_guidance carries the platform on every KSI", fg_ok)
    check("the DOCX label names the platform and disclaims the provider's voice",
          bd._how_to_comply_label({"guidance_platform": "AWS"})
          == "How to comply (SAS guidance, AWS implementation examples, not the provider's statement):")

    print("== AC2: a profile with no platform metadata builds")
    neutral = dict(profile)
    for k in ("aws_partition", "primary_region", "dr_region"):
        neutral.pop(k, None)
    try:
        ext_n = bs.build_extensions(neutral, rules, ksis, records, cls)
        human_n = bs.render_human(neutral, rules, ksis, records, cls)
        raised = None
    except Exception as e:  # noqa: BLE001
        ext_n, human_n, raised = None, "", e
    check("build_extensions and render_human do not raise without the AWS fields", raised is None, str(raised))
    check("the extension metadata omits aws_partition and regions rather than inventing them",
          raised is None and "aws_partition" not in ext_n["metadata"] and "regions" not in ext_n["metadata"])
    check("the human-readable header omits the partition and region lines",
          raised is None and "AWS partition:" not in human_n and "Primary region:" not in human_n
          and "Disaster recovery region:" not in human_n)
    check("the guidance labels still name AWS for a non-AWS profile (the notes are AWS examples)",
          raised is None and all(e["guidance"]["how_to_comply_platform"] == "AWS" for e in ext_n["ksi"].values()))
    half = dict(profile)
    half.pop("dr_region", None)
    check("a half-declared region pair yields no regions member (never a one-region invention)",
          "regions" not in bs._platform_metadata(half)
          and bs._platform_metadata(half).get("aws_partition") == profile["aws_partition"])

    print("== AC3: a profile with the AWS fields keeps the committed members and order")
    md = ext["metadata"]
    check("metadata carries aws_partition and regions in the committed order",
          list(md.keys())[:6] == ["offering", "certification_class", "certification_path", "aws_partition",
                                  "regions", "sdr_version"]
          and md["aws_partition"] == profile["aws_partition"]
          and md["regions"] == [profile["primary_region"], profile["dr_region"]])
    human = bs.render_human(profile, rules, ksis, records, cls)
    check("the human-readable header carries the three platform lines",
          f"AWS partition: {profile['aws_partition']}" in human
          and f"Primary region: {profile['primary_region']}" in human
          and f"Disaster recovery region: {profile['dr_region']}" in human)
    committed = _load("sdr", "json", f"sdr-class-{cls}-extensions.json")
    check("the committed extension metadata equals a fresh build's metadata (AC3 parity for the active class)",
          committed["metadata"] == md, json.dumps(md)[:200])

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: platform-labelled notes ({_fail} failures)")
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
