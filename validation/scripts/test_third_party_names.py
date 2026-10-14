#!/usr/bin/env python3
"""Third-party naming guard (MCE-15).

This repository is public and names other organizations' products only to
identify export formats its optional adapters read (THIRD_PARTY_NOTICE.md).
A public commit cannot be unpublished, so the care rules that can be checked
mechanically are checked here, in the validate suite, on every change:

  G1  Every name on the vendor WATCHLIST that appears in a tracked text file
      must be registered in THIRD_PARTY_NOTICE.md's table.
  G2  No sentence (prose files) or line (code and data files) that contains a
      registered name may also contain comparative, evaluative or endorsing
      language (the LEXICON below). Factual identification only.
  G3  No tracked image file may carry a vendor token in its name: no logos,
      icons or screenshots of any vendor product.
  G4  The notice table must parse and register at least the names the
      repository already uses.

Exempt from G2 only (visible here on purpose): THIRD_PARTY_NOTICE.md, because
it must say what is not implied, and this file, because it holds the lexicon.

The self-test re-injects every violation shape into synthetic input and fails
if any is missed; it runs on every invocation before the repository scan, so a
weakened guard cannot pass silently.

Run: python validation/scripts/test_third_party_names.py
Exit 0 when clean, 1 on findings or a failed self-test.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NOTICE = "THIRD_PARTY_NOTICE.md"
SELF = "validation/scripts/test_third_party_names.py"
G2_EXEMPT = {NOTICE, SELF}

# Names whose presence requires registration in the notice. Exact phrases,
# case-sensitive, matched on word boundaries so ordinary words ("tenable",
# "oracle" as in requirements oracle) and code identifiers never trip it.
WATCHLIST = [
    "CrowdStrike", "Falcon", "Wiz",
    "Google Cloud", "GCP", "Security Command Center",
    "Microsoft Azure", "Azure", "Microsoft Defender", "Azure Policy",
    "Oracle Cloud", "OCI Cloud Guard", "Cloud Guard",
    "OpenSCAP",
    "IBM Cloud", "Alibaba Cloud", "Okta", "Splunk", "Datadog", "Palo Alto",
    "Prisma Cloud", "Tenable", "Qualys", "Rapid7", "Snyk", "SentinelOne",
    "Fortinet", "Zscaler", "Lacework", "Orca Security", "Trend Micro",
    "Cloudflare", "VMware", "ServiceNow", "Vanta", "Drata", "Secureframe",
]

# Lower-case tokens for G3 (image file names).
IMAGE_TOKENS = [
    "crowdstrike", "falcon", "wiz", "google", "gcp", "microsoft", "azure",
    "defender", "oracle", "cloudguard", "cloud-guard", "openscap", "okta",
    "splunk", "datadog", "paloalto", "palo-alto", "prisma", "tenable", "qualys",
    "rapid7", "snyk", "sentinelone", "fortinet", "zscaler", "lacework", "orca",
    "trendmicro", "cloudflare", "vmware", "servicenow", "vanta", "drata",
]
IMAGE_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp")

# Comparative, evaluative or endorsing language. Matched case-insensitively on
# word boundaries within one sentence or line that also names a third party.
LEXICON = [
    r"better", r"best", r"worse", r"worst", r"superior", r"inferior",
    r"recommend(?:s|ed|ation)?", r"prefer(?:s|red|able)?", r"versus", r"vs\.?",
    r"compared? (?:to|with|against)", r"comparison", r"outperform(?:s|ed)?",
    r"leading", r"leader", r"weak(?:er|est)?", r"strong(?:er|est)?",
    r"more secure", r"less secure", r"instead of", r"rather than",
    r"alternative to", r"replace(?:s|d|ment)? (?:for|of)?", r"cheaper",
    r"more expensive", r"endorse(?:s|d|ment)?", r"partner(?:s|ship|ed)?",
    r"certified", r"approved", r"trusted", r"market", r"competitor(?:s)?",
    r"competitive", r"surpass(?:es|ed)?", r"lags?", r"(?:im)?mature",
    r"robust", r"seamless", r"industry[- ]leading", r"state[- ]of[- ]the[- ]art",
    r"best[- ]in[- ]class", r"world[- ]class", r"unmatched", r"inadequate",
    r"insufficient", r"superb", r"excellent", r"poor",
]
LEXICON_RE = re.compile(r"\b(?:" + "|".join(LEXICON) + r")\b", re.IGNORECASE)

PROSE_EXT = (".md", ".txt", ".rst", ".html", ".csv")
TEXT_SKIP_EXT = (".docx", ".pdf", ".zip", ".pyc", ".whl") + IMAGE_EXT
SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+|\n\s*\n")


def _word_re(phrase: str) -> re.Pattern:
    return re.compile(r"(?<![A-Za-z0-9_])" + re.escape(phrase) + r"(?![A-Za-z0-9_])")


def tracked_files(base: str) -> list[str]:
    try:
        out = subprocess.check_output(["git", "-C", base, "ls-files"], text=True, encoding="utf-8")
        files = [ln.strip() for ln in out.splitlines() if ln.strip()]
    except (OSError, subprocess.CalledProcessError):
        files = []
        for root, dirs, names in os.walk(base):
            dirs[:] = [d for d in dirs if d not in (".git", "build", "node_modules", "__pycache__")]
            for n in names:
                files.append(os.path.relpath(os.path.join(root, n), base).replace(os.sep, "/"))
    return sorted(files)


def parse_notice(text: str) -> list[str]:
    """Registered names: every comma-separated entry in the first column of the
    notice's table rows (rows start with '| ' and are not the header/separator)."""
    names: list[str] = []
    in_table = False
    for line in text.splitlines():
        if line.startswith("| Name as used"):
            in_table = True
            continue
        if not in_table:
            continue
        if not line.startswith("|"):
            if names:
                break
            continue
        if set(line.replace("|", "").strip()) <= {"-", " "}:
            continue
        first = line.split("|")[1].strip()
        names.extend(n.strip() for n in first.split(",") if n.strip())
    return names


def units(path: str, text: str) -> list[tuple[int, str]]:
    """(line_number, unit) pairs. Prose files: a table row is one unit, other
    lines are joined into paragraphs (blank line or table row ends one) and the
    paragraph is split into sentences. Code and data files: one line, one unit."""
    if not path.endswith(PROSE_EXT):
        return [(i, ln) for i, ln in enumerate(text.splitlines(), 1) if ln.strip()]
    out: list[tuple[int, str]] = []
    para: list[str] = []
    para_start = 1

    def flush():
        if para:
            joined = " ".join(s.strip() for s in para)
            for sent in SENTENCE_SPLIT.split(joined):
                if sent and sent.strip():
                    out.append((para_start, sent))
        para.clear()

    for i, ln in enumerate(text.splitlines(), 1):
        if ln.lstrip().startswith("|"):
            flush()
            out.append((i, ln))
        elif not ln.strip():
            flush()
        else:
            if not para:
                para_start = i
            para.append(ln)
    flush()
    return out


def unregistered_watchlist(registered: list[str]) -> list[str]:
    """Watchlist names not covered by a registered name. A longer registered
    phrase covers its shorter form ('Oracle Cloud Infrastructure' covers
    'Oracle Cloud'); the reverse never holds."""
    return [w for w in WATCHLIST if not any(w == r or w in r for r in registered)]


def scan(files: dict[str, str], registered: list[str]) -> list[str]:
    """files: relative path -> text (binary files are passed as None and only
    name-checked). Returns findings."""
    findings: list[str] = []
    reg_res = [(n, _word_re(n)) for n in registered]
    watch_res = [(n, _word_re(n)) for n in unregistered_watchlist(registered)]
    for path in sorted(files):
        low = path.lower()
        if low.endswith(IMAGE_EXT):
            name = os.path.basename(low)
            for tok in IMAGE_TOKENS:
                if tok in name:
                    findings.append(f"G3 {path}: image file name carries vendor token '{tok}'")
                    break
            continue
        text = files[path]
        if text is None or low.endswith(TEXT_SKIP_EXT):
            continue
        if path != SELF:
            for name, rx in watch_res:
                m = rx.search(text)
                if m:
                    lineno = text.count("\n", 0, m.start()) + 1
                    findings.append(f"G1 {path}:{lineno}: '{name}' is not registered in {NOTICE}")
        if path in G2_EXEMPT:
            continue
        for lineno, unit in units(path, text):
            hit_names = [n for n, rx in reg_res if rx.search(unit)]
            if not hit_names:
                continue
            m = LEXICON_RE.search(unit)
            if m:
                findings.append(
                    f"G2 {path}:{lineno}: sentence names {hit_names[0]!r} and uses "
                    f"evaluative term {m.group(0)!r}: {unit.strip()[:120]!r}")
    return findings


def load_repo(base: str) -> tuple[dict[str, str], list[str]]:
    files: dict[str, str] = {}
    for rel in tracked_files(base):
        full = os.path.join(base, rel)
        if not os.path.isfile(full):
            continue
        if rel.lower().endswith(TEXT_SKIP_EXT):
            files[rel] = None
            continue
        try:
            with open(full, "r", encoding="utf-8") as f:
                files[rel] = f.read()
        except (UnicodeDecodeError, OSError):
            files[rel] = None
    notice_text = files.get(NOTICE)
    registered = parse_notice(notice_text) if notice_text else []
    return files, registered


GOOD_NOTICE = (
    "# Notice\n\n| Name as used in this repository | Owner | Why it appears |\n|---|---|---|\n"
    "| Wiz | Wiz, Inc. | An adapter reads an export. |\n"
    "| Google Cloud, Security Command Center | Google LLC | A planned adapter. |\n"
)


def self_test() -> list[str]:
    fails: list[str] = []
    reg = parse_notice(GOOD_NOTICE)
    if reg != ["Wiz", "Google Cloud", "Security Command Center"]:
        fails.append(f"G4 notice parse: got {reg}")

    def expect(label: str, files: dict, needle: str | None):
        f = scan(files, reg)
        if needle is None:
            if f:
                fails.append(f"{label}: expected clean, got {f}")
        elif not any(needle in x for x in f):
            fails.append(f"{label}: expected a finding containing {needle!r}, got {f}")

    base = {NOTICE: GOOD_NOTICE}
    expect("clean prose", {**base, "docs/a.md": "The Wiz adapter reads a customer-produced export. It yields facts."}, None)
    expect("clean code", {**base, "x.py": "class WizAdapter:\n    name = 'wiz'  # reads a Wiz export\n"}, None)
    expect("ordinary word not a vendor", {**base, "y.py": "oracle = requirements_oracle()  # untenable, shortenable\n"}, None)
    expect("identifier not a bare name", {**base, "z.py": "FalconAdapter = 1\n"}, None)
    expect("G1 unregistered watchlist", {**base, "docs/b.md": "Export from Microsoft Azure."}, "G1 docs/b.md:1: 'Microsoft Azure'")
    expect("G1 unregistered single word", {**base, "docs/c.md": "Also Falcon exports."}, "'Falcon' is not registered")
    expect("G2 comparative prose", {**base, "docs/d.md": "Wiz is better than other scanners."}, "G2 docs/d.md:1")
    expect("G2 endorsement prose", {**base, "docs/e.md": "Fine first sentence. We recommend Google Cloud for this."}, "evaluative term 'recommend'")
    expect("G2 sentence boundary isolates", {**base, "docs/f.md": "Wiz exports are read offline. Strong tests are better."}, None)
    expect("G2 table rows are separate units", {**base, "docs/t.md": "| Guide | When |\n|---|---|\n| [A](a.md) | You run Wiz |\n| [B](b.md) | A capability comparison |\n"}, None)
    expect("G2 one table row with both", {**base, "docs/u.md": "| Guide | When |\n|---|---|\n| [A](a.md) | Wiz is the leading option |\n"}, "G2 docs/u.md:3")
    expect("G1 longer registered name covers shorter form", {**base, "docs/v.md": "Read a Google Cloud export."}, None)
    expect("G1 guard source exempt from watchlist", {**base, SELF: "WATCHLIST = ['Okta', 'Splunk']\n"}, None)
    expect("G2 code line", {**base, "w.py": "# Wiz is the leading scanner\n"}, "G2 w.py:1")
    expect("G2 versus", {**base, "docs/g.md": "Security Command Center vs. other tools."}, "evaluative term 'vs")
    expect("G2 exempt notice", {NOTICE: GOOD_NOTICE + "\nWiz is not endorsed, recommended or compared here.\n"}, None)
    expect("G3 image token", {**base, "docs/img/wiz-logo.png": None}, "G3 docs/img/wiz-logo.png")
    expect("G3 image token azure", {**base, "assets/azure_screenshot.svg": None}, "vendor token 'azure'")
    expect("G3 neutral image ok", {**base, "assets/architecture.png": None}, None)
    expect("binary skipped", {**base, "doc.docx": None}, None)
    return fails


def main() -> int:
    fails = self_test()
    if fails:
        print("SELF-TEST FAIL:")
        for x in fails:
            print("  " + x)
        return 1
    print("PASS: self-test (21 shapes: clean cases pass, every injected violation caught)")

    files, registered = load_repo(BASE)
    if NOTICE not in files or not registered:
        print(f"FAIL: {NOTICE} missing or its table registers no names")
        return 1
    print(f"PASS: {NOTICE} registers {len(registered)} name(s)")
    findings = scan(files, registered)
    for x in findings:
        print("FAIL: " + x)
    if findings:
        print(f"FAIL: third-party naming guard: {len(findings)} finding(s) across {len(files)} tracked files")
        return 1
    print(f"PASS: third-party naming guard: 0 findings across {len(files)} tracked files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
