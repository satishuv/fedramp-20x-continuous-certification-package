"""Offline tests for markdown_changelog.py (AUD-F44). No network. Run:
    python validation/scripts/test_markdown_changelog.py
"""

import hashlib
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import markdown_changelog as mc  # noqa: E402

CHANGELOG = """# Changelog

Preamble text.

## 2026.10.08.01 (October 8, 2026)

This update does not make any significant changes; typos and convenience only.

- Removed FRC-CSX-MOT as duplicative with SDR-CSX-KMT
- Updated SDR-CSX-KMT to change from MUST to SHOULD for Class B


## 2026.10.05.01 (October 5, 2026)

Earlier entry.

## 2026.09.13.02 (September 13, 2026)

Oldest entry.
"""


def test_entry_for_returns_the_section_up_to_the_next_heading():
    entry = mc.entry_for(CHANGELOG, "2026.10.08.01")
    assert entry is not None
    assert entry.startswith("## 2026.10.08.01 (October 8, 2026)")
    assert "Removed FRC-CSX-MOT" in entry
    assert "2026.10.05.01" not in entry, "the next section must not leak in"
    assert not entry.endswith("\n"), "trailing blank lines are trimmed"


def test_entry_for_last_section_runs_to_end_of_file():
    entry = mc.entry_for(CHANGELOG, "2026.09.13.02")
    assert entry == "## 2026.09.13.02 (September 13, 2026)\n\nOldest entry."


def test_entry_for_requires_the_exact_version_token():
    assert mc.entry_for(CHANGELOG, "2026.10.08") is None, "a prefix is not the version"
    assert mc.entry_for(CHANGELOG, "2026.10.08.010") is None
    assert mc.entry_for(CHANGELOG, "2026.11.01.01") is None
    assert mc.entry_for(CHANGELOG, "FRC-CSX-MOT") is None, "body text is not a heading"


def test_baseline_hash_is_sha256_of_raw_bytes():
    data = CHANGELOG.encode("utf-8")
    assert mc.baseline_hash(data) == hashlib.sha256(data).hexdigest()
    # Bytes, not normalized text: a CRLF copy hashes differently, as sha256sum would.
    assert mc.baseline_hash(data.replace(b"\n", b"\r\n")) != mc.baseline_hash(data)


def _cli(tmp, *extra):
    src = os.path.join(tmp, "changelog.md")
    with open(src, "wb") as fh:
        fh.write(CHANGELOG.encode("utf-8"))
    baseline = os.path.join(tmp, "baseline")
    entry_out = os.path.join(tmp, "entry.txt")
    rc = mc.main(["--file", src, "--entry-out", entry_out, "--write-baseline", baseline, *extra])
    return rc, baseline, entry_out


def test_cli_with_version_present_writes_entry_and_advances_baseline():
    with tempfile.TemporaryDirectory() as tmp:
        rc, baseline, entry_out = _cli(tmp, "--version", "2026.10.08.01")
        assert rc == 0
        assert os.path.exists(baseline), "baseline must advance when the entry exists"
        with open(baseline, "rb") as fh:
            written = fh.read()
        assert written == (hashlib.sha256(CHANGELOG.encode("utf-8")).hexdigest() + "\n").encode(), \
            "the workflow's `cat` + sha256sum comparison expects hex plus one newline"
        with open(entry_out, encoding="utf-8") as fh:
            body = fh.read()
        assert body.startswith("## 2026.10.08.01")
        assert "Removed FRC-CSX-MOT" in body


def test_cli_with_version_absent_leaves_baseline_alone():
    """The dataset can move hours before FedRAMP rebuilds the markdown. If the
    entry is not published yet the baseline must NOT advance, so the daily
    check surfaces the entry for a human when it lands."""
    with tempfile.TemporaryDirectory() as tmp:
        rc, baseline, entry_out = _cli(tmp, "--version", "2026.11.01.01")
        assert rc == 0, "not-yet-published is not a failure"
        assert not os.path.exists(baseline), "baseline must not advance without the entry"
        with open(entry_out, encoding="utf-8") as fh:
            body = fh.read()
        assert "no entry for 2026.11.01.01 yet" in body


def test_cli_without_version_writes_baseline_unconditionally():
    """The human path after reading a markdown-only change."""
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "changelog.md")
        with open(src, "wb") as fh:
            fh.write(CHANGELOG.encode("utf-8"))
        baseline = os.path.join(tmp, "baseline")
        assert mc.main(["--file", src, "--write-baseline", baseline]) == 0
        with open(baseline, encoding="utf-8") as fh:
            assert fh.read().strip() == hashlib.sha256(CHANGELOG.encode("utf-8")).hexdigest()


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
