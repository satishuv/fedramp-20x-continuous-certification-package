# KSI gap assessment: score an existing environment's collected facts against
# the 46 Key Security Indicators of the pinned CR26 dataset, for one class.
#
# What it answers: "of the KSIs that apply at Class X, how many have every
# automated check passing, how many are partly passing, how many are failing,
# how many did the collectors not observe, which family is weakest, and where is
# the largest failing footprint?"
#
# Boundary (same as every automation layer in this repo):
#   - Input is the read-only facts store written by collect_facts.py (or a
#     --demo synthetic store, labelled as such everywhere it is shown).
#   - Scoring REUSES append_metrics.datapoint_for_ksi, so this view and the
#     SDR-CSX-KMT metric history can never disagree about a KSI.
#   - "Passing" means every automated check the collectors observed for that
#     KSI passed. It is NOT an implementation status and NOT a compliance
#     determination. A status changes only through human sign-off; FedRAMP
#     Certification decisions belong to the assessor and the agency.
#   - Output derives from a real account, so it is written to a git-excluded
#     directory by default.
#
# Usage:
#   python automation/assessment/gap_assessment.py
#   python automation/assessment/gap_assessment.py --facts-dir PATH --out DIR
#   python automation/assessment/gap_assessment.py --demo
#
# Class C only. It is the class most agencies will ask about (FedRAMP describes
# it as adequate for most Low and Moderate agency systems), every KSI applies at
# it, and it is the prerequisite for the Class D pilot (RFC-0033).

import argparse
import hashlib
import html
import json
import os
import sys
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REGISTRY = os.path.join(BASE, "automation", "collectors", "registry.json")
KSI_PROFILE = os.path.join(BASE, "profiles", "common", "ksi-profile.json")
DEFAULT_OUT = os.path.join(BASE, "automation", "assessment", "report")

sys.path.insert(0, os.path.join(BASE, "automation", "metrics"))
import append_metrics as am  # noqa: E402
from method_ids import config_method_id, parse_service_key, posture_method_id  # noqa: E402

CLASS = "c"
# Status vocabulary. Deliberately not "Implemented" / "Compliant": those words
# belong to the human-signed record store and the assessor.
PASSING = "passing"            # every observed automated check passed
PARTIAL = "partial"            # some observed checks passed, some failed
FAILING = "failing"            # every observed automated check failed
NOT_OBSERVED = "not_observed"  # collectable checks exist, none produced an outcome
PROVIDER_EVIDENCE = "provider_evidence"  # document/process KSI: no read-only collector
STATUS_ORDER = (PASSING, PARTIAL, FAILING, NOT_OBSERVED, PROVIDER_EVIDENCE)
STATUS_LABEL = {
    PASSING: "All automated checks passing",
    PARTIAL: "Partly passing",
    FAILING: "Failing",
    NOT_OBSERVED: "Not observed by collectors",
    PROVIDER_EVIDENCE: "Needs provider evidence (no read-only check)",
}


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def applicable_ksis(profile):
    """Every KSI in the dataset-built profile applies at Class C (46)."""
    return {ind["ksi_id"]: ind for ind in profile["indicators"]}


def ksi_statement(ind):
    vbc = ind.get("varies_by_class") or {}
    per = vbc.get(CLASS) or {}
    return per.get("statement") or ind.get("statement") or ""


def min_methods(ind):
    """FRC-CSX-VVK minimum automated validation methods at Class C (2)."""
    return int((ind.get("minimum_automated_methods") or {}).get(f"class_{CLASS}", 0))


def observed_method_ids(ksi_entry, config_by_rule, posture_by_service):
    """Distinct automated method ids that produced an EVALUATED outcome for the
    KSI, using the same scoring filters as the metric appender."""
    ids = set()
    for check in ksi_entry.get("checks", []):
        if check.get("type") != "config_managed_rule":
            continue
        facts = config_by_rule.get(check.get("target"))
        if facts and am._config_scope_score(facts)[1] > 0:
            ids.add(config_method_id(check))
    for key in ksi_entry.get("metric_service_keys", []) or []:
        service, chk = parse_service_key(key)
        for pf in posture_by_service.get(service, []):
            if chk and pf.get("check") != chk:
                continue
            if am._posture_score(pf) is not None:
                ids.add(posture_method_id(service, pf.get("check")))
    return sorted(ids)


def failing_checks(ksi_entry, config_by_rule, posture_by_service):
    """Human-readable list of what failed, for the per-KSI detail."""
    out = []
    for check in ksi_entry.get("checks", []):
        if check.get("type") != "config_managed_rule":
            continue
        for fact in config_by_rule.get(check.get("target")) or []:
            ct = fact.get("compliance_type", "")
            if ct == "NON_COMPLIANT":
                out.append(f"Config rule {check.get('target')} NON_COMPLIANT "
                           f"in {fact.get('region')}")
    for key in ksi_entry.get("metric_service_keys", []) or []:
        service, chk = parse_service_key(key)
        for pf in posture_by_service.get(service, []):
            if chk and pf.get("check") != chk:
                continue
            score = am._posture_score(pf)
            if score is None:
                continue
            p, t = score
            if p < t:
                out.append(f"{service}.{pf.get('check')}: {p} of {t} in good posture "
                           f"({pf.get('status')}) in {pf.get('region')}")
    return out


def classify(ksi_entry, dp):
    if dp is None:
        collectable = any(c.get("collectable_now") for c in ksi_entry.get("checks", []))
        return NOT_OBSERVED if collectable else PROVIDER_EVIDENCE
    if dp["passing"] == dp["total"]:
        return PASSING
    if dp["passing"] == 0:
        return FAILING
    return PARTIAL


def assess(registry, profile, config_by_rule, posture_by_service, source_note):
    applicable = applicable_ksis(profile)
    rows = []
    for kid in sorted(applicable):
        ind = applicable[kid]
        entry = registry["ksis"].get(kid, {})
        dp = am.datapoint_for_ksi(entry, config_by_rule, posture_by_service)
        status = classify(entry, dp)
        methods = observed_method_ids(entry, config_by_rule, posture_by_service)
        need = min_methods(ind)
        rows.append({
            "ksi_id": kid,
            "name": ind["name"],
            "family": ind["family"],
            "family_name": ind["family_name"],
            "statement": ksi_statement(ind),
            "controls": len(ind.get("controls") or []),
            "status": status,
            "passing": dp["passing"] if dp else 0,
            "total": dp["total"] if dp else 0,
            "pass_fraction": (dp["passing"] / dp["total"]) if dp else None,
            "coverage_gaps": (dp or {}).get("coverage_gaps", []),
            "automated_methods_observed": methods,
            "automated_methods_minimum": need,
            "meets_method_minimum": len(methods) >= need,
            "failing_checks": failing_checks(entry, config_by_rule, posture_by_service),
        })

    counts = {s: sum(1 for r in rows if r["status"] == s) for s in STATUS_ORDER}
    families = {}
    for r in rows:
        fam = families.setdefault(r["family"], {
            "family": r["family"], "family_name": r["family_name"],
            "ksis": 0, "passing_checks": 0, "total_checks": 0,
            "by_status": {s: 0 for s in STATUS_ORDER}})
        fam["ksis"] += 1
        fam["passing_checks"] += r["passing"]
        fam["total_checks"] += r["total"]
        fam["by_status"][r["status"]] += 1
    for fam in families.values():
        fam["pass_fraction"] = (fam["passing_checks"] / fam["total_checks"]
                                if fam["total_checks"] else None)
    observed_fams = [f for f in families.values() if f["total_checks"]]
    weakest = min(observed_fams, key=lambda f: (f["pass_fraction"], -f["total_checks"])) \
        if observed_fams else None
    strongest = max(observed_fams, key=lambda f: (f["pass_fraction"], f["total_checks"])) \
        if observed_fams else None

    # "Highest risk" is defined, not felt: the failing or partly-failing KSIs
    # ranked by failing-check count, then by the number of NIST controls the
    # KSI maps to in the dataset (a wider failing footprint).
    at_risk = [r for r in rows if r["status"] in (FAILING, PARTIAL)]
    at_risk.sort(key=lambda r: (-(r["total"] - r["passing"]), -r["controls"], r["ksi_id"]))

    method_short = [r for r in rows if r["total"] and not r["meets_method_minimum"]]

    return {
        "meta": {
            "title": "KSI gap assessment (automated-check view)",
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "class": CLASS.upper(),
            "dataset_version": registry["meta"]["dataset_version"],
            "profile_dataset_version": profile["meta"]["dataset_version"],
            "source": source_note,
            "ksis_in_dataset": profile["count"],
            "ksis_applicable": len(rows),
            "boundary": (
                "Passing means every automated check the collectors observed for the KSI "
                "passed. This is telemetry about an environment, not an implementation "
                "status and not a compliance determination. Statuses in the record store "
                "change only through human sign-off; FedRAMP Certification decisions "
                "belong to the assessor and the authorizing agency."),
        },
        "summary": {
            "counts": counts,
            "weakest_family": weakest,
            "strongest_family": strongest,
            "highest_risk": at_risk[:5],
            "method_minimum_shortfall": [
                {"ksi_id": r["ksi_id"], "observed": len(r["automated_methods_observed"]),
                 "minimum": r["automated_methods_minimum"]} for r in method_short],
            "total_checks_observed": sum(r["total"] for r in rows),
            "total_checks_passing": sum(r["passing"] for r in rows),
        },
        "families": sorted(families.values(), key=lambda f: f["family"]),
        "ksis": rows,
    }


# ---------------------------------------------------------------- demo store

def demo_store(registry, region="us-east-1"):
    """A deterministic synthetic facts store shaped like collect_facts.py output.
    Outcomes come from a hash of the rule or route name, so the demo is the
    same on every machine and never reflects a real account."""
    now = "2026-10-21T12:00:00+00:00"
    facts = []
    seen = set()
    for kid, entry in registry["ksis"].items():
        for check in entry.get("checks", []):
            if check.get("type") != "config_managed_rule":
                continue
            rule = check["target"]
            if rule in seen:
                continue
            seen.add(rule)
            h = int(hashlib.sha256(rule.encode()).hexdigest(), 16) % 10
            ct = "COMPLIANT" if h < 6 else ("NON_COMPLIANT" if h < 9 else "RULE_NOT_DEPLOYED")
            facts.append({"rule": rule, "check_ids": [check["check_id"]], "collected_at": now,
                          "region": region, "resolution": "deployed-names",
                          "compliance_type": ct, "instances": 0 if ct == "RULE_NOT_DEPLOYED" else 1})
    posture = []
    routes = set()
    for entry in registry["ksis"].values():
        for key in entry.get("metric_service_keys", []) or []:
            routes.add(parse_service_key(key))
    for service, chk in sorted(routes):
        h = int(hashlib.sha256(f"{service}:{chk}".encode()).hexdigest(), 16) % 10
        pf = {"service": service, "check": chk, "region": region, "collected_at": now}
        if h < 4:
            pf["status"] = "ENABLED"
        elif h < 7:
            total = 20
            pf.update({"status": "OBSERVED", "measured": 20 - (h - 3) * 4, "total": total,
                       "scope_total": total, "evaluated_total": total, "unknown_total": 0})
        elif h < 9:
            pf["status"] = "NOT_ENABLED"
        else:
            pf["status"] = "ERROR:AccessDenied"
        posture.append(pf)
    return {"meta": {"collected_at": now, "run_id": "run-demo", "region": region,
                     "identity_arn": "arn:aws:sts::000000000000:assumed-role/Demo/demo",
                     "registry_dataset_version": registry["meta"]["dataset_version"],
                     "note": "DEMO: synthetic facts, not a real account."},
            "facts": facts, "posture_facts": posture}


# ---------------------------------------------------------------- HTML

def _pct(x):
    return "n/a" if x is None else f"{round(x * 100)}%"


def render_html(result):
    m, s = result["meta"], result["summary"]
    c = s["counts"]
    n = m["ksis_applicable"]
    e = html.escape

    def bar(fraction, width=160):
        if fraction is None:
            return '<span class="muted">no observation</span>'
        w = int(width * fraction)
        return (f'<span class="bar"><span class="fill" style="width:{w}px"></span></span>'
                f' {_pct(fraction)}')

    weakest = s["weakest_family"]
    strongest = s["strongest_family"]
    weak_txt = (f'{e(weakest["family"])} ({e(weakest["family_name"])}): '
                f'{weakest["passing_checks"]} of {weakest["total_checks"]} checks passing, '
                f'{_pct(weakest["pass_fraction"])}') if weakest else "no family observed"
    strong_txt = (f'{e(strongest["family"])} ({e(strongest["family_name"])}): '
                  f'{strongest["passing_checks"]} of {strongest["total_checks"]} checks passing, '
                  f'{_pct(strongest["pass_fraction"])}') if strongest else "no family observed"

    risk_rows = "".join(
        f'<tr><td><code>{e(r["ksi_id"])}</code></td><td>{e(r["name"])}</td>'
        f'<td>{r["total"] - r["passing"]} of {r["total"]}</td><td>{r["controls"]}</td>'
        f'<td>{e("; ".join(r["failing_checks"][:3]) or "see detail")}</td></tr>'
        for r in s["highest_risk"]) or '<tr><td colspan="5">No failing or partly failing KSI observed.</td></tr>'

    fam_rows = "".join(
        f'<tr><td><code>{e(f["family"])}</code> {e(f["family_name"])}</td><td>{f["ksis"]}</td>'
        f'<td>{f["by_status"][PASSING]}</td><td>{f["by_status"][PARTIAL]}</td>'
        f'<td>{f["by_status"][FAILING]}</td><td>{f["by_status"][NOT_OBSERVED]}</td>'
        f'<td>{f["by_status"][PROVIDER_EVIDENCE]}</td><td>{bar(f["pass_fraction"])}</td></tr>'
        for f in result["families"])

    def ksi_row(r):
        fails = "".join(f"<li>{e(x)}</li>" for x in r["failing_checks"]) or "<li>none observed</li>"
        gaps = "".join(f"<li>{e(x)}</li>" for x in r["coverage_gaps"])
        methods = ", ".join(f"<code>{e(x)}</code>" for x in r["automated_methods_observed"]) or "none"
        meets = "yes" if r["meets_method_minimum"] else "NO"
        return (
            f'<details class="ksi {e(r["status"])}"><summary>'
            f'<span class="pill">{e(STATUS_LABEL[r["status"]])}</span> '
            f'<code>{e(r["ksi_id"])}</code> {e(r["name"])} '
            f'<span class="muted">({r["passing"]} of {r["total"]} checks)</span></summary>'
            f'<p class="stmt">{e(r["statement"])}</p>'
            f'<p><strong>Automated methods observed:</strong> {methods} '
            f'(minimum at Class {e(m["class"])}: {r["automated_methods_minimum"]}, met: {meets})</p>'
            f'<p><strong>Failing checks:</strong></p><ul>{fails}</ul>'
            + (f'<p><strong>Coverage gaps (withheld from scoring):</strong></p><ul>{gaps}</ul>' if gaps else "")
            + f'<p class="muted">Maps to {r["controls"]} NIST SP 800-53 controls in dataset {e(m["dataset_version"])}.</p>'
            '</details>')

    ksi_sections = ""
    for status in STATUS_ORDER:
        group = [r for r in result["ksis"] if r["status"] == status]
        if not group:
            continue
        ksi_sections += (f'<h3>{e(STATUS_LABEL[status])} ({len(group)})</h3>'
                         + "".join(ksi_row(r) for r in group))

    short = s["method_minimum_shortfall"]
    short_txt = ("All observed KSIs meet the Class minimum." if not short else
                 ", ".join(f'<code>{e(x["ksi_id"])}</code> ({x["observed"]} of {x["minimum"]})'
                           for x in short))

    demo_banner = ('<div class="demo">DEMO DATA: this page was produced from a synthetic facts '
                   'store and describes no real account.</div>') if "DEMO" in m["source"] else ""

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(m["title"])} - Class {e(m["class"])}</title>
<style>
 body{{font-family:Arial,Helvetica,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#1b1f23;background:#fff}}
 h1{{margin-bottom:.2rem}} h2{{margin-top:2rem;border-bottom:1px solid #d0d7de;padding-bottom:.3rem}}
 .muted{{color:#57606a}} .headline{{font-size:1.25rem;margin:.6rem 0 1rem}}
 .cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:.8rem}}
 .card{{border:1px solid #d0d7de;border-radius:8px;padding:.8rem}}
 .card .n{{font-size:2rem;font-weight:bold}} .card.passing .n{{color:#1a7f37}} .card.partial .n{{color:#9a6700}}
 .card.failing .n{{color:#cf222e}} .card.not_observed .n{{color:#57606a}} .card.provider_evidence .n{{color:#0969da}}
 table{{border-collapse:collapse;width:100%;margin:.6rem 0}} th,td{{border:1px solid #d0d7de;padding:.4rem .5rem;text-align:left;vertical-align:top;font-size:.93rem}}
 th{{background:#f6f8fa}} code{{background:#f6f8fa;padding:0 .25rem;border-radius:3px}}
 .bar{{display:inline-block;width:160px;height:10px;background:#eaeef2;border-radius:5px;vertical-align:middle}}
 .fill{{display:block;height:10px;background:#1a7f37;border-radius:5px}}
 details.ksi{{border:1px solid #d0d7de;border-radius:6px;padding:.4rem .7rem;margin:.4rem 0}}
 summary{{cursor:pointer}} .pill{{display:inline-block;font-size:.75rem;padding:.1rem .5rem;border-radius:10px;background:#eaeef2;margin-right:.4rem}}
 .passing .pill{{background:#dafbe1;color:#1a7f37}} .partial .pill{{background:#fff8c5;color:#9a6700}}
 .failing .pill{{background:#ffebe9;color:#cf222e}} .provider_evidence .pill{{background:#ddf4ff;color:#0969da}}
 .stmt{{font-style:italic}} .boundary{{background:#f6f8fa;border-left:4px solid #0969da;padding:.6rem .9rem;margin:1rem 0}}
 .demo{{background:#fff8c5;border:1px solid #9a6700;padding:.6rem .9rem;font-weight:bold;margin-bottom:1rem}}
 footer{{margin-top:2rem;font-size:.85rem;color:#57606a}}
</style></head><body>
{demo_banner}
<h1>{e(m["title"])}</h1>
<p class="muted">Class {e(m["class"])} | dataset {e(m["dataset_version"])} | generated {e(m["generated_at"])} | source: {e(m["source"])}</p>

<p class="headline">Of the <strong>{n}</strong> KSIs that apply at Class {e(m["class"])} (dataset has {m["ksis_in_dataset"]}),
all automated checks pass on <strong>{c[PASSING]}</strong>, <strong>{c[PARTIAL]}</strong> are partly passing,
<strong>{c[FAILING]}</strong> are failing, <strong>{c[NOT_OBSERVED]}</strong> were not observed by the collectors,
and <strong>{c[PROVIDER_EVIDENCE]}</strong> need provider-produced evidence that no read-only check can gather.</p>

<div class="cards">
 <div class="card passing"><div class="n">{c[PASSING]}</div>{e(STATUS_LABEL[PASSING])}</div>
 <div class="card partial"><div class="n">{c[PARTIAL]}</div>{e(STATUS_LABEL[PARTIAL])}</div>
 <div class="card failing"><div class="n">{c[FAILING]}</div>{e(STATUS_LABEL[FAILING])}</div>
 <div class="card not_observed"><div class="n">{c[NOT_OBSERVED]}</div>{e(STATUS_LABEL[NOT_OBSERVED])}</div>
 <div class="card provider_evidence"><div class="n">{c[PROVIDER_EVIDENCE]}</div>{e(STATUS_LABEL[PROVIDER_EVIDENCE])}</div>
</div>

<h2>Where to look first</h2>
<ul>
 <li><strong>Weakest family:</strong> {weak_txt}</li>
 <li><strong>Strongest family:</strong> {strong_txt}</li>
 <li><strong>Checks overall:</strong> {s["total_checks_passing"]} of {s["total_checks_observed"]} observed automated checks passing.</li>
 <li><strong>FRC-CSX-VVK automated-method minimum (Class {e(m["class"])}):</strong> {short_txt}</li>
</ul>

<h3>Highest risk: largest failing footprint</h3>
<p class="muted">Ranked by failing checks, then by how many NIST SP 800-53 controls the KSI maps to in the dataset.</p>
<table><tr><th>KSI</th><th>Name</th><th>Failing checks</th><th>Controls mapped</th><th>What failed</th></tr>{risk_rows}</table>

<h2>By family</h2>
<table><tr><th>Family</th><th>KSIs</th><th>Passing</th><th>Partial</th><th>Failing</th><th>Not observed</th><th>Provider evidence</th><th>Checks passing</th></tr>{fam_rows}</table>

<h2>Every applicable KSI</h2>
{ksi_sections}

<div class="boundary"><strong>Read this before quoting a number.</strong> {e(m["boundary"])}</div>
<footer>AWS Security Assurance Services provides advisory support only. This page is not legal advice and not a compliance determination.
Rules and KSIs: FedRAMP Consolidated Rules release {e(m["dataset_version"])} (github.com/FedRAMP/rules).</footer>
</body></html>
"""


# ---------------------------------------------------------------- CLI

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--facts-dir", default=None,
                    help="facts store directory (default automation/facts)")
    ap.add_argument("--out", default=DEFAULT_OUT, help="output directory")
    ap.add_argument("--demo", action="store_true",
                    help="use a deterministic synthetic facts store (no AWS); labelled DEMO")
    ap.add_argument("--registry", default=REGISTRY)
    ap.add_argument("--profile", default=KSI_PROFILE)
    args = ap.parse_args(argv)

    registry = load_json(args.registry)
    profile = load_json(args.profile)
    if registry["meta"]["dataset_version"] != profile["meta"]["dataset_version"]:
        print("ERROR: registry and ksi-profile were built from different dataset versions; "
              "run the profile build first.", file=sys.stderr)
        return 2

    if args.demo:
        store = demo_store(registry)
        import tempfile
        tmp = tempfile.mkdtemp(prefix="gap-demo-")
        with open(os.path.join(tmp, "facts-us-east-1.json"), "w", encoding="utf-8") as f:
            json.dump(store, f)
        facts_dir = tmp
        source = "DEMO synthetic facts store (no real account)"
    else:
        facts_dir = args.facts_dir or am.FACTS_DIR
        source = os.path.relpath(facts_dir, BASE) if facts_dir.startswith(BASE) else facts_dir
        if not os.path.isdir(facts_dir) or not any(
                fn.startswith("facts-") and fn.endswith(".json") for fn in os.listdir(facts_dir)):
            print(f"ERROR: no facts store in {facts_dir}. Run "
                  "automation/collectors/collect_facts.py first, or pass --demo.", file=sys.stderr)
            return 3

    saved = am.FACTS_DIR
    try:
        am.FACTS_DIR = facts_dir
        config_by_rule, posture_by_service = am.load_facts()
    finally:
        am.FACTS_DIR = saved

    result = assess(registry, profile, config_by_rule, posture_by_service, source)
    os.makedirs(args.out, exist_ok=True)
    jpath = os.path.join(args.out, "gap-assessment.json")
    hpath = os.path.join(args.out, "gap-assessment.html")
    with open(jpath, "w", encoding="utf-8", newline="\n") as f:
        json.dump(result, f, indent=1)
    with open(hpath, "w", encoding="utf-8", newline="\n") as f:
        f.write(render_html(result))

    c = result["summary"]["counts"]
    n = result["meta"]["ksis_applicable"]
    print(f"Class C: {n} applicable KSIs. passing={c[PASSING]} partial={c[PARTIAL]} "
          f"failing={c[FAILING]} not_observed={c[NOT_OBSERVED]} provider_evidence={c[PROVIDER_EVIDENCE]}")
    w = result["summary"]["weakest_family"]
    if w:
        print(f"weakest family: {w['family']} ({_pct(w['pass_fraction'])} of checks passing)")
    print(f"wrote {os.path.relpath(hpath, BASE)} and {os.path.relpath(jpath, BASE)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
