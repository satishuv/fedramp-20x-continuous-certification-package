"""FedRAMP 2026-markdown changelog: entry lookup and drift-baseline advance.

The daily drift check hash-compares FedRAMP's narrative changelog
(github.com/FedRAMP/2026-markdown, changelog.md) against a committed baseline
in .github/.markdown-changelog-baseline, because guidance and timeline changes
land there without moving the structured dataset's hash. FedRAMP rebuilds that
markdown from fedramp/rules on every dataset release, so each release also adds
a changelog entry headed `## <version> (<date>)`.

Until AUD-F44 the adoption step advanced every dataset pin but not this
baseline, so the scheduled run after each adoption re-reported, as new drift,
the entry the adoption PR's reviewer had already covered (issue #211 after the
2026.10.08.01 adoption; a hand re-set in PR #205 after 2026.10.05.01). This
module gives the workflow and a human the same two operations:

  * `entry_for(text, version)`: the changelog section for one dataset version
    (heading line through the line before the next `## ` heading), or None.
  * `baseline_hash(data)`: SHA-256 of the file's raw bytes, which is exactly
    what the workflow's `sha256sum` compares, so a baseline written here is
    byte-for-byte what the check step computes.

Usage:
  python validation/scripts/markdown_changelog.py --file changelog.md \
      --version 2026.10.08.01 --entry-out /tmp/entry.txt \
      --write-baseline .github/.markdown-changelog-baseline
  python validation/scripts/markdown_changelog.py --fetch \
      --write-baseline .github/.markdown-changelog-baseline

With --version, --write-baseline advances the baseline ONLY when the changelog
contains an entry for that version: the reviewer of the adoption PR reads that
entry (it is placed in the PR body), so the daily check must not re-report it.
When FedRAMP has not published the entry yet (the dataset can move hours before
the markdown rebuild), the baseline is left alone so the daily check surfaces
the entry when it lands. Without --version the write is unconditional: that is
the human path for a markdown-only change, after reading it.

Exit codes: 0 on success (including "no entry yet"), 2 when --fetch cannot
download the changelog (never treated as drift, mirroring the workflow).
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import urllib.error
import urllib.request

CHANGELOG_URL = "https://raw.githubusercontent.com/FedRAMP/2026-markdown/main/changelog.md"
BASELINE_PATH = ".github/.markdown-changelog-baseline"


def entry_for(text: str, version: str) -> str | None:
    """Return the `## <version> ...` section of a changelog, or None.

    The heading must start with the exact version token (`## 2026.10.08.01`
    followed by whitespace, a parenthesis or end of line), so `2026.10.08.01`
    does not match a hypothetical `2026.10.08.010`. The section runs to the
    line before the next `## ` heading, trailing blank lines removed.
    """
    pattern = re.compile(r"^## " + re.escape(version) + r"(?=[\s(]|$)")
    lines = text.splitlines()
    start = next((i for i, line in enumerate(lines) if pattern.match(line)), None)
    if start is None:
        return None
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    section = lines[start:end]
    while section and not section[-1].strip():
        section.pop()
    return "\n".join(section)


def baseline_hash(data: bytes) -> str:
    """SHA-256 of the raw bytes, matching `sha256sum` on the same file."""
    return hashlib.sha256(data).hexdigest()


def fetch_changelog(url: str = CHANGELOG_URL, timeout: int = 30) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (https, fixed host)
        return resp.read()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--file", help="path to a downloaded FedRAMP 2026-markdown changelog.md")
    src.add_argument("--fetch", action="store_true", help=f"download {CHANGELOG_URL}")
    ap.add_argument("--version", help="dataset version whose changelog entry to extract")
    ap.add_argument("--entry-out", help="write the entry (or a 'no entry' line) to this file")
    ap.add_argument("--write-baseline", metavar="PATH",
                    help="write the changelog's SHA-256 here (with --version: only when the entry exists)")
    args = ap.parse_args(argv)

    if args.fetch:
        try:
            data = fetch_changelog()
        except (urllib.error.URLError, OSError, ValueError) as exc:
            print(f"changelog: DOWNLOAD FAILED (not treated as drift): {exc}", file=sys.stderr)
            return 2
    else:
        with open(args.file, "rb") as fh:
            data = fh.read()
    text = data.decode("utf-8", errors="replace")
    digest = baseline_hash(data)

    entry = None
    if args.version:
        entry = entry_for(text, args.version)
        if entry is None:
            entry_text = (f"(FedRAMP's 2026-markdown changelog has no entry for {args.version} yet; "
                          f"see {CHANGELOG_URL})")
        else:
            entry_text = entry
        print(f"changelog entry for {args.version}: {'found' if entry else 'not published yet'}")
        if args.entry_out:
            with open(args.entry_out, "w", encoding="utf-8") as fh:
                fh.write(entry_text + "\n")

    if args.write_baseline:
        if args.version and entry is None:
            print(f"baseline: unchanged (no entry for {args.version}; the daily check will surface it)")
        else:
            with open(args.write_baseline, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(digest + "\n")
            print(f"baseline: advanced to {digest} ({args.write_baseline})")
    else:
        print(f"changelog sha256: {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
