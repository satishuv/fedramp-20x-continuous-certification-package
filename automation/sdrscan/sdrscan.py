# sdrscan: an assessment-readiness scanner for FedRAMP 20x Security Decision
# Records, built the way Prowler is built.
#
# Prowler scans a cloud account and reports one finding per resource per check,
# with severity, remediation and compliance-framework mapping, in several output
# formats. sdrscan does the same thing for the documentation FedRAMP actually
# asks for. Its resources are the Security Decision Record, each applicable
# FedRAMP Rule (FRR) and each Key Security Indicator (KSI); its compliance
# framework is the FedRAMP Consolidated Rules for 2026 (CR26) dataset pinned in
# references/.
#
# Why this exists rather than just a pass/fail build gate: CDS-CSO-CBF requires
# providers to use automation to keep human-readable and machine-readable
# Certification Data consistent, and FRC-CSX-VVR requires automated methods to
# persistently verify and validate the accuracy and completeness of the record.
# A scanner that produces per-resource findings is how you satisfy those two
# rules with evidence rather than assertion.
#
# Relationship to validation/scripts/validate_sdr.py: that script is the build
# gate. It answers "is the generated package structurally sound and faithful to
# the dataset", returns a single exit code, and runs on every commit. sdrscan
# answers the different question "what is still missing before an assessor signs
# this", at per-resource granularity, and is meant to be read by a human or fed
# into a dashboard. Neither replaces the other; the gate protects the build, the
# scanner drives the work.
#
# Usage:
#   python automation/sdrscan/sdrscan.py
#   python automation/sdrscan/sdrscan.py --only-fails --severity critical,high
#   python automation/sdrscan/sdrscan.py --check frr_owner_assigned
#   python automation/sdrscan/sdrscan.py --list-checks
#   python automation/sdrscan/sdrscan.py --output-formats json,csv,html,txt
#
# Exit codes follow Prowler: 0 clean, 3 findings failed, 1 the scan itself
# could not run. Use --ignore-exit-code-3 in pipelines that report rather than
# gate.

import argparse
import csv
import html as html_mod
import json
import os
import re
import sys
import zipfile
from datetime import date, datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
import class_support  # noqa: E402  (AUD-F65: the one class-support state)

OFFERING = os.path.join(BASE, "profiles", "common", "offering-profile.json")

import checks as checkmod  # noqa: E402  (path set above)

VERSION = "1.0.0"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
STATUS_ORDER = ["FAIL", "MANUAL", "MUTED", "PASS"]

SCHEMA_DIR = os.path.join(BASE, "artifacts", "schemas", "official")
SDR_SCHEMA = os.path.join(SCHEMA_DIR,
                          "fedramp-security-decision-record-schema-2026-06-24.json")
COMMON_SCHEMA = os.path.join(SCHEMA_DIR,
                             "fedramp-common-definitions-schema-2026-06-24.json")
DATASET = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
OUT_DIR = os.path.join(BASE, "validation", "reports", "sdrscan")
CATALOG = os.path.join(HERE, "check-catalog.json")
MUTELIST = os.path.join(HERE, "mutelist.json")

ANSI = {"FAIL": "\033[31m", "PASS": "\033[32m", "MANUAL": "\033[33m",
        "MUTED": "\033[90m", "bold": "\033[1m", "off": "\033[0m"}


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def norm(s):
    return re.sub(r"\s+", " ", (s or "").strip())


def docx_body_text(path):
    with zipfile.ZipFile(path) as z:
        xml = z.read("word/document.xml").decode("utf-8")
    return norm(html_mod.unescape(re.sub(r"<[^>]+>", " ", xml)))


class Context:
    """Everything the checks read, loaded once. Checks never touch the
    filesystem themselves, so a check can never accidentally depend on state
    another check wrote."""

    def __init__(self, cls):
        self.cls = cls
        self.offering = load(OFFERING)
        self.class_profile = load(os.path.join(BASE, "profiles", f"class-{cls}",
                                               "profile.json"))
        self.ksi_profile = load(os.path.join(BASE, "profiles", "common",
                                             "ksi-profile.json"))
        self.sdr = load(os.path.join(BASE, "sdr", "json", f"sdr-class-{cls}.json"))
        self.ext = load(os.path.join(BASE, "sdr", "json",
                                     f"sdr-class-{cls}-extensions.json"))
        self.records = load(os.path.join(BASE, "sdr", "records",
                                         "records-store.json"))
        txt_path = os.path.join(BASE, "sdr", "human-readable", f"sdr-class-{cls}.txt")
        self.human_readable = (open(txt_path, encoding="utf-8").read()
                               if os.path.exists(txt_path) else None)
        ds = load(DATASET)
        self.dataset_version = ds["info"]["version"]
        self.canonical_rules, self.canonical_ksis = self._canonical(ds)
        self.schema_errors = self._schema_errors()
        self.fidelity_failures = self._fidelity()
        self.scannable_text = self._scannable()
        self.record_age_days = self._age()

    @staticmethod
    def _canonical(ds):
        rules = {}
        for famblock in ds["FRR"].values():
            for subsets in famblock.get("data", {}).values():
                for items in subsets.values():
                    for rid, rule in items.items():
                        if isinstance(rule, dict) and re.match(
                                r"^[A-Z]{3}-[A-Z]{3}-[A-Z]{3}$", rid):
                            rules[rid] = rule
        ksis = {}
        for famblock in ds["KSI"].values():
            for kid, k in famblock.get("indicators", {}).items():
                if kid.startswith("KSI-"):
                    ksis[kid] = k
        return rules, ksis

    def _schema_errors(self):
        try:
            import jsonschema
            from referencing import Registry, Resource
        except ImportError:
            return [{"path": "", "message": "jsonschema and referencing are not "
                                            "installed, so schema validation was skipped"}]
        sdr_schema, common = load(SDR_SCHEMA), load(COMMON_SCHEMA)
        registry = Registry().with_resources([
            (sdr_schema["$id"], Resource.from_contents(sdr_schema)),
            (common["$id"], Resource.from_contents(common)),
        ])
        validator = jsonschema.Draft202012Validator(sdr_schema, registry=registry)
        return [{"path": "/".join(str(p) for p in e.absolute_path),
                 "message": e.message[:200]}
                for e in validator.iter_errors(self.sdr)]

    def _resolve(self, rule):
        vbc = rule.get("varies_by_class")
        if vbc:
            v = vbc.get(self.cls)
            if v and v.get("statement"):
                return v["statement"]
        return rule.get("statement")

    def _fidelity(self):
        """Per-resource fidelity, so a paraphrased rule fails on that rule
        rather than sinking one aggregate check."""
        fails = {}
        for entry in self.class_profile["rules"]:
            rid = entry["rule_id"]
            rule = self.canonical_rules.get(rid)
            if rule is None:
                fails[rid] = "rule is not present in the canonical dataset"
                continue
            want = self._resolve(rule)
            if entry.get("statement") != want:
                fails[rid] = "statement text differs from the canonical dataset"
            elif entry.get("name") != rule.get("name"):
                fails[rid] = "rule name differs from the canonical dataset"
        for entry in self.sdr.get("keySecurityIndicators", []):
            kid = entry["ksiId"]
            can = self.canonical_ksis.get(kid)
            if can is None:
                fails[kid] = "indicator is not present in the canonical dataset"
                continue
            ext_name = self.ext["ksi"].get(kid, {}).get("name")
            if ext_name and ext_name != can.get("name"):
                fails[kid] = "indicator name differs from the canonical dataset"
            st = can.get("statement")
            if st and self.human_readable and norm(st) not in norm(self.human_readable):
                fails[kid] = ("indicator statement does not appear verbatim in "
                              "the human-readable rendering")
        return fails

    def _scannable(self):
        out = {}
        for root, _d, files in os.walk(os.path.join(BASE, "sdr")):
            for fn in files:
                path = os.path.join(root, fn)
                try:
                    out[fn] = (docx_body_text(path) if fn.endswith(".docx")
                               else open(path, encoding="utf-8", errors="ignore").read())
                except (OSError, KeyError, zipfile.BadZipFile):
                    continue
        return out

    def _age(self):
        """Days between metadata.lastUpdated and the pinned dataset date. Using
        the dataset date rather than today keeps the scan deterministic, so the
        same inputs always produce the same report."""
        stamp = (self.sdr.get("metadata") or {}).get("lastUpdated")
        if not stamp:
            return None
        try:
            when = datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).date()
        except ValueError:
            return None
        try:
            parts = self.dataset_version.split(".")
            pinned = date(int(parts[0]), int(parts[1]), int(parts[2]))
        except (ValueError, IndexError):
            return None
        return abs((pinned - when).days)


def load_mutelist():
    """Muting requires a justification and an expiry, so a muted finding is an
    auditable decision rather than a way to hide a gap. An EXPIRED or unparseable
    expiry is fail-closed: the mute is dropped so the finding surfaces again."""
    if not os.path.exists(MUTELIST):
        return {}
    raw = load(MUTELIST)
    muted = {}
    import datetime as _dt
    today = _dt.date.today()
    for e in raw.get("mutes", []):
        if not e.get("justification") or not e.get("expires"):
            continue
        try:
            expires = _dt.date.fromisoformat(str(e["expires"])[:10])
        except (ValueError, TypeError):
            # Unparseable expiry: do not honor the mute (fail closed).
            continue
        if expires <= today:
            # Expired: the suppression no longer applies; the finding surfaces.
            continue
        muted[(e["check_id"], e.get("resource_id", "*"))] = e
    return muted


def build_findings(ctx, mutes):
    findings = []
    for check_id, resource_id, resource_name, ok, detail in checkmod.run_all(ctx):
        meta = checkmod.METADATA.get(check_id)
        if meta is None:
            continue
        if ctx.cls not in meta["applies_to_classes"]:
            continue
        if ok is True:
            status = "PASS"
        elif ok == "MANUAL":
            status = "MANUAL"
        else:
            status = "FAIL"
        mute = mutes.get((check_id, resource_id)) or mutes.get((check_id, "*"))
        if status == "FAIL" and mute:
            status = "MUTED"
        findings.append({
            "findingId": f"{check_id}/{resource_id}",
            "checkId": check_id,
            "checkTitle": meta["title"],
            "status": status,
            "statusDetail": detail,
            "severity": meta["severity"],
            "resourceType": meta["resource_type"],
            "resourceId": resource_id,
            "resourceName": resource_name,
            "certificationClass": ctx.cls.upper(),
            "fedRampBasis": meta["fedramp_basis"],
            "fedRampRequirement": meta["requirement"],
            "risk": meta["risk"],
            # Resolve the placeholders in the metadata location so a reader can
            # copy the path straight into an editor instead of working out
            # which rule the finding was about.
            "remediation": {
                "description": meta["remediation"],
                "location": (meta["location"]
                             .replace("<rule>", resource_id)
                             .replace("<indicator>", resource_id)
                             .replace("<class>", ctx.cls)),
            },
            "muted": status == "MUTED",
            "muteJustification": (mute or {}).get("justification"),
            "muteExpires": (mute or {}).get("expires"),
        })
    findings.sort(key=lambda f: (STATUS_ORDER.index(f["status"]),
                                 SEVERITY_ORDER.index(f["severity"]),
                                 f["checkId"], f["resourceId"]))
    return findings


def summarise(findings):
    counts = {s: 0 for s in STATUS_ORDER}
    by_sev = {s: {"FAIL": 0, "PASS": 0, "MANUAL": 0, "MUTED": 0}
              for s in SEVERITY_ORDER}
    for f in findings:
        counts[f["status"]] += 1
        by_sev[f["severity"]][f["status"]] += 1
    decided = counts["PASS"] + counts["FAIL"]
    return {
        "total": len(findings),
        "pass": counts["PASS"],
        "fail": counts["FAIL"],
        "manual": counts["MANUAL"],
        "muted": counts["MUTED"],
        "by_severity": by_sev,
        # Readiness counts only findings the record can decide by itself.
        # MANUAL findings need a person, so including them would let a record
        # look better simply by having more undecidable checks.
        "readiness_percent": (round(100.0 * counts["PASS"] / decided, 1)
                              if decided else 0.0),
    }


def rule_rollup(findings):
    """Per-rule record-completeness view: for each FedRAMP rule cited by any
    check, how many findings the record satisfies, has a gap on, or leaves for a
    human. This describes RECORD COMPLETENESS, not a compliance verdict; the
    assessor and the program decide compliance, never this scanner."""
    roll = {}
    for f in findings:
        for basis in f["fedRampBasis"]:
            r = roll.setdefault(basis, {"fedramp_id": basis, "PASS": 0, "FAIL": 0,
                                        "MANUAL": 0, "MUTED": 0, "checks": set()})
            r[f["status"]] += 1
            r["checks"].add(f["checkId"])
    for r in roll.values():
        r["checks"] = sorted(r["checks"])
        # Record-focused language, deliberately NOT "MET / NOT MET" which reads
        # as a compliance determination.
        r["status"] = ("RECORD GAP" if r["FAIL"] else
                       "HUMAN REVIEW" if r["MANUAL"] or r["MUTED"] else "RECORD COMPLETE")
    return [roll[k] for k in sorted(roll)]


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_json(path, doc):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, indent=1)


def write_csv(path, findings):
    cols = ["findingId", "status", "severity", "checkId", "checkTitle",
            "resourceType", "resourceId", "resourceName", "certificationClass",
            "fedRampBasis", "statusDetail", "risk", "remediation", "location",
            "muted", "muteJustification"]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(cols)
        for x in findings:
            w.writerow([
                x["findingId"], x["status"], x["severity"], x["checkId"],
                x["checkTitle"], x["resourceType"], x["resourceId"],
                x["resourceName"], x["certificationClass"],
                ";".join(x["fedRampBasis"]), x["statusDetail"], x["risk"],
                x["remediation"]["description"], x["remediation"]["location"],
                "yes" if x["muted"] else "no", x["muteJustification"] or "",
            ])


def write_compliance_csv(path, rollup):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["fedramp_id", "status", "failing", "passing",
                    "needs_human", "muted", "checks"])
        for r in rollup:
            w.writerow([r["fedramp_id"], r["status"], r["FAIL"], r["PASS"],
                        r["MANUAL"], r["MUTED"], ";".join(r["checks"])])


def write_text(path, doc):
    """Plain-text report, no markup, so it can be pasted into a ticket or
    printed. This is deliberately not the SDR's human-readable deliverable; it
    is a scan report about that deliverable."""
    s, lines = doc["summary"], []
    a = lines.append
    a("FEDRAMP 20x SECURITY DECISION RECORD SCAN REPORT")
    a("")
    a(f"Offering: {doc['scan']['offering']}")
    a(f"Certification class: {doc['scan']['certificationClass']}")
    a(f"Certification path: {doc['scan']['certificationPath']}")
    a(f"Rules dataset: {doc['scan']['datasetVersion']}")
    a(f"Scanner: sdrscan {doc['scan']['sdrscanVersion']}")
    a(f"Generated: {doc['scan']['generated']}")
    a("")
    a("1. Summary")
    a("")
    a(f"Findings: {s['total']}")
    a(f"Passing: {s['pass']}")
    a(f"Failing: {s['fail']}")
    a(f"Needs human confirmation: {s['manual']}")
    a(f"Muted with justification: {s['muted']}")
    a(f"Record completeness: {s['readiness_percent']} percent of decidable findings "
      "pass (how much of the record is filled with defensible facts, not a "
      "compliance or security score)")
    a("")
    a("Failing findings by severity:")
    for sev in SEVERITY_ORDER:
        a(f"  {sev}: {s['by_severity'][sev]['FAIL']}")
    a("")
    a("2. Failing findings")
    a("")
    fails = [f for f in doc["findings"] if f["status"] == "FAIL"]
    if not fails:
        a("None. Every decidable check passes.")
        a("")
    for i, f in enumerate(fails, 1):
        a(f"2.{i} {f['checkId']} on {f['resourceId']}")
        a(f"Severity: {f['severity']}")
        a(f"Resource: {f['resourceType']} {f['resourceId']} {f['resourceName']}")
        a(f"Finding: {f['statusDetail']}")
        a(f"FedRAMP basis: {', '.join(f['fedRampBasis'])}")
        a(f"Requirement: {f['fedRampRequirement']}")
        a(f"Risk: {f['risk']}")
        a(f"Remediation: {f['remediation']['description']}")
        a(f"Location: {f['remediation']['location']}")
        a("")
    a("3. Findings needing human confirmation")
    a("")
    manual = [f for f in doc["findings"] if f["status"] == "MANUAL"]
    if not manual:
        a("None.")
        a("")
    for i, f in enumerate(manual, 1):
        a(f"3.{i} {f['checkId']} on {f['resourceId']}")
        a(f"Question: {f['statusDetail']}")
        a(f"FedRAMP basis: {', '.join(f['fedRampBasis'])}")
        a("")
    a("4. FedRAMP rule coverage")
    a("")
    for i, r in enumerate(doc["fedRampRuleRollup"], 1):
        a(f"4.{i} {r['fedramp_id']}: {r['status']} "
          f"(failing {r['FAIL']}, passing {r['PASS']}, needs human {r['MANUAL']})")
    a("")
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines))


def write_html(path, doc):
    """Single self-contained file, no external assets, no network calls, so it
    can be attached to a package or opened from a locked-down workstation."""
    e = html_mod.escape
    s = doc["summary"]
    rows = []
    for f in doc["findings"]:
        rows.append(
            f"<tr class='{f['status'].lower()}'>"
            f"<td>{f['status']}</td><td>{f['severity']}</td>"
            f"<td>{e(f['resourceId'])}</td><td>{e(f['checkTitle'])}</td>"
            f"<td>{e(f['statusDetail'])}</td>"
            f"<td>{e(', '.join(f['fedRampBasis']))}</td>"
            f"<td>{e(f['remediation']['description'])}<br>"
            f"<code>{e(f['remediation']['location'])}</code></td></tr>")
    roll = "".join(
        f"<tr><td>{e(r['fedramp_id'])}</td><td>{r['status']}</td>"
        f"<td>{r['FAIL']}</td><td>{r['PASS']}</td><td>{r['MANUAL']}</td></tr>"
        for r in doc["fedRampRuleRollup"])
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>SDR scan report, class {e(doc['scan']['certificationClass'])}</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#111}}
 h1{{font-size:1.4rem}} h2{{font-size:1.1rem;margin-top:2rem}}
 table{{border-collapse:collapse;width:100%;margin-top:.5rem}}
 th,td{{border:1px solid #ddd;padding:.4rem .5rem;text-align:left;vertical-align:top}}
 th{{background:#f4f4f4}} code{{font-size:.85em;color:#555}}
 .cards{{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}}
 .card{{border:1px solid #ddd;border-radius:6px;padding:.75rem 1rem;min-width:8rem}}
 .card b{{display:block;font-size:1.6rem}}
 tr.fail td:first-child{{color:#b00020;font-weight:600}}
 tr.pass td:first-child{{color:#1b7f2a}}
 tr.manual td:first-child{{color:#8a6100}}
 tr.muted td{{color:#888}}
</style></head><body>
<h1>FedRAMP 20x Security Decision Record scan report</h1>
<p>{e(doc['scan']['offering'])}, certification class
 {e(doc['scan']['certificationClass'])},
 {e(doc['scan']['certificationPath'])} path.<br>
 Rules dataset {e(doc['scan']['datasetVersion'])}, sdrscan
 {e(doc['scan']['sdrscanVersion'])}. {e(doc['scan']['generated'])}.</p>
<div class="cards">
 <div class="card"><b>{s['fail']}</b>failing</div>
 <div class="card"><b>{s['pass']}</b>passing</div>
 <div class="card"><b>{s['manual']}</b>needs a human</div>
 <div class="card"><b>{s['muted']}</b>muted</div>
 <div class="card"><b>{s['readiness_percent']}%</b>record complete</div>
</div>
<p>Readiness counts only findings the record can decide on its own. Findings
 that need a human are excluded so a record cannot look better by having more
 undecidable checks.</p>
<h2>Findings</h2>
<table><thead><tr><th>Status</th><th>Severity</th><th>Resource</th>
<th>Check</th><th>Detail</th><th>FedRAMP basis</th><th>Remediation</th>
</tr></thead><tbody>{''.join(rows)}</tbody></table>
<h2>FedRAMP rule coverage</h2>
<table><thead><tr><th>Rule</th><th>Status</th><th>Failing</th><th>Passing</th>
<th>Needs a human</th></tr></thead><tbody>{roll}</tbody></table>
<p>This report is a provider verification artifact produced under CDS-CSO-CBF
 and FRC-CSX-VVR. It is not a FedRAMP submission and FedRAMP publishes no
 schema for scan output.</p>
</body></html>
""")


def print_terminal(doc, only_fails, colour):
    def c(key, text):
        return f"{ANSI[key]}{text}{ANSI['off']}" if colour else text

    s = doc["summary"]
    print(c("bold", "sdrscan " + VERSION) +
          f"  class {doc['scan']['certificationClass']}"
          f"  dataset {doc['scan']['datasetVersion']}")
    print(f"{doc['scan']['offering']}\n")
    shown = 0
    for f in doc["findings"]:
        if only_fails and f["status"] not in ("FAIL", "MANUAL"):
            continue
        shown += 1
        print(f"{c(f['status'], f['status'].ljust(6))} "
              f"{f['severity'].ljust(13)} {f['resourceId'].ljust(14)} "
              f"{f['checkId']}")
        print(f"       {f['statusDetail']}")
        if f["status"] == "FAIL":
            print(f"       basis: {', '.join(f['fedRampBasis'])}")
            print(f"       fix:   {f['remediation']['description']}")
            print(f"       at:    {f['remediation']['location']}")
    if only_fails and not shown:
        print("No failing findings.\n")
    print()
    print(c("bold", "Summary"))
    print(f"  {c('FAIL', 'FAIL')}   {s['fail']}")
    print(f"  {c('PASS', 'PASS')}   {s['pass']}")
    print(f"  {c('MANUAL', 'MANUAL')} {s['manual']}")
    print(f"  {c('MUTED', 'MUTED')}  {s['muted']}")
    print(f"  record completeness {s['readiness_percent']} percent of decidable findings")
    worst = [sev for sev in SEVERITY_ORDER if s["by_severity"][sev]["FAIL"]]
    if worst:
        print("  failing severities: " +
              ", ".join(f"{sev} {s['by_severity'][sev]['FAIL']}" for sev in worst))


# ---------------------------------------------------------------------------

def main(argv=None):
    p = argparse.ArgumentParser(
        prog="sdrscan",
        description="Assessment-readiness scanner for FedRAMP 20x Security "
                    "Decision Records. Reports one finding per resource per "
                    "check, with the FedRAMP rule that makes each check a "
                    "requirement.")
    p.add_argument("--class", dest="cls", choices=["a", "b", "c"],
                   help="certification class to scan; defaults to the class in "
                        "profiles/common/offering-profile.json")
    p.add_argument("--check", action="append", default=[],
                   help="run only this check id; repeatable")
    p.add_argument("--exclude-check", action="append", default=[],
                   help="skip this check id; repeatable")
    p.add_argument("--severity",
                   help="comma-separated severities to report, for example "
                        "critical,high")
    p.add_argument("--resource-type", choices=["SDR", "FRR", "KSI"],
                   help="report only findings on this resource type")
    p.add_argument("--only-fails", action="store_true",
                   help="print only failing findings and findings needing a human")
    p.add_argument("--output-formats", default="json,csv,html,txt",
                   help="comma-separated: json, csv, html, txt, none")
    p.add_argument("--output-dir", default=OUT_DIR)
    p.add_argument("--list-checks", action="store_true",
                   help="print the check registry and exit")
    p.add_argument("--write-catalog", action="store_true",
                   help="regenerate check-catalog.json and exit")
    p.add_argument("--timestamp", action="store_true",
                   help="stamp the report with the real run time. Off by "
                        "default so repeated scans of unchanged inputs produce "
                        "byte-identical reports.")
    p.add_argument("--no-colour", action="store_true")
    p.add_argument("--ignore-exit-code-3", action="store_true",
                   help="always exit 0 when the scan itself ran successfully")
    args = p.parse_args(argv)

    if args.write_catalog:
        n = checkmod.write_catalog(CATALOG)
        print(f"wrote {n} checks to {CATALOG}")
        return 0

    if args.list_checks:
        for cid in sorted(checkmod.METADATA):
            m = checkmod.METADATA[cid]
            print(f"{m['severity'].ljust(13)} {cid.ljust(42)} {m['title']}")
            print(f"{''.ljust(13)} basis: {', '.join(m['fedramp_basis'])}, "
                  f"classes: {', '.join(x.upper() for x in m['applies_to_classes'])}")
        print(f"\n{len(checkmod.METADATA)} checks")
        return 0

    offering = load(OFFERING)
    cls = args.cls or offering["certification_class"].lower()
    _unsupported = class_support.unsupported_class_message(cls, 'readiness scan')
    if _unsupported:
        print(_unsupported)
        return 1

    try:
        ctx = Context(cls)
    except FileNotFoundError as exc:
        print(f"sdrscan cannot run: {exc}\n"
              f"Generate the record first: python validation/scripts/build_sdr.py")
        return 1

    findings = build_findings(ctx, load_mutelist())

    if args.check:
        findings = [f for f in findings if f["checkId"] in set(args.check)]
    if args.exclude_check:
        findings = [f for f in findings if f["checkId"] not in set(args.exclude_check)]
    if args.severity:
        keep = {s.strip().lower() for s in args.severity.split(",")}
        findings = [f for f in findings if f["severity"] in keep]
    if args.resource_type:
        want = {"SDR": "Security Decision Record", "FRR": "FedRAMP Rule",
                "KSI": "Key Security Indicator"}[args.resource_type]
        findings = [f for f in findings if f["resourceType"] == want]

    generated = (datetime.now(timezone.utc).isoformat(timespec="seconds")
                 if args.timestamp
                 else f"deterministic scan against dataset {ctx.dataset_version}")
    doc = {
        "reportNote": (
            "sdrscan findings. This is a provider verification artifact "
            "produced to satisfy CDS-CSO-CBF (automation keeps human-readable "
            "and machine-readable formats consistent) and FRC-CSX-VVR "
            "(automated methods persistently verify and validate the accuracy "
            "and completeness of the Security Decision Record). FedRAMP "
            "publishes no schema for scan output, so this format is the "
            "scanner's own, using FedRAMP identifiers and vocabulary "
            "throughout. It is not itself a FedRAMP submission."
        ),
        "scan": {
            "sdrscanVersion": VERSION,
            "offering": offering["offering_name"],
            "certificationClass": cls.upper(),
            "certificationPath": offering["certification_path"],
            "datasetVersion": ctx.dataset_version,
            "sdrSchema": os.path.basename(SDR_SCHEMA),
            "generated": generated,
        },
        "summary": summarise(findings),
        "fedRampRuleRollup": rule_rollup(findings),
        "findings": findings,
    }

    formats = {x.strip() for x in args.output_formats.split(",")} - {"", "none"}
    if formats:
        os.makedirs(args.output_dir, exist_ok=True)
        stem = os.path.join(args.output_dir, f"sdrscan-class-{cls}")
        if "json" in formats:
            write_json(f"{stem}.json", doc)
        if "csv" in formats:
            write_csv(f"{stem}.csv", findings)
            write_compliance_csv(f"{stem}-fedramp-rule-coverage.csv",
                                 doc["fedRampRuleRollup"])
        if "html" in formats:
            write_html(f"{stem}.html", doc)
        if "txt" in formats:
            write_text(f"{stem}.txt", doc)

    print_terminal(doc, args.only_fails, colour=not args.no_colour)
    if formats:
        print(f"\nreports written to {os.path.relpath(args.output_dir, BASE)}"
              f" as {', '.join(sorted(formats))}")

    if args.ignore_exit_code_3:
        return 0
    return 3 if doc["summary"]["fail"] else 0


if __name__ == "__main__":
    sys.exit(main())
