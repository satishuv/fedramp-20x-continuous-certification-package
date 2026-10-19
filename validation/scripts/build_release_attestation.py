#!/usr/bin/env python3
"""Emit artifacts/release-attestation.json: a release-time envelope that binds
the DETERMINISTIC release manifest to the exact git source that produced it,
WITHOUT mutating the manifest.

Why a separate file rather than stamping the manifest:
  - The human package signoff (checked by package-preflight) is bound to the
    SHA-256 of release-manifest.json's bytes. If a release step added git
    commit/tree INTO that manifest, its hash would change and the prior signoff
    would silently go stale.
  - The commit hash also cannot be known before the commit that contains the
    manifest (circular), and mutating the manifest breaks the CI
    regenerate-and-diff gate.

So the ordering is: build -> validate -> reproducibility -> human signoff (binds
the deterministic manifest) -> package-preflight (verifies that binding) ->
THIS attestation (binds that same manifest hash to the git commit/tree) -> tag.
The attestation references the manifest by hash; it never changes it.

Fail-closed provenance: because `sdr.py release` builds from the WORKING TREE,
this script refuses to write an attestation when (a) git provenance is
unavailable, (b) the tracked working tree differs from HEAD, or (c) untracked
non-ignored files are present - any of which would make "this commit is the
source that produced the manifest" materially false. The comparison covers
every tracked file, Word documents included: the .docx is byte-reproducible
since AUD-F35 (fixed zip entry timestamps, dataset-derived core properties) and
CI diffs and double-build hashes it like every other output, so an exclusion
here (removed in AUD-F94) would have attested a hand-edited Word document as
clean. The deployed CodePipeline is already protected because it
clones via CODEBUILD_CLONE_REF and runs a regenerate-and-diff gate; this closes
the equivalent hole in the local release path.

This file is NOT committed in ordinary builds (it names a specific commit and is
release-only); it is produced at release/publish time. Run:

    python validation/scripts/build_release_attestation.py
"""

import hashlib
import json
import os
import subprocess
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MANIFEST = os.path.join(BASE, "artifacts", "release-manifest.json")
ATTESTATION = os.path.join(BASE, "artifacts", "release-attestation.json")


def _git(*args):
    try:
        r = subprocess.run(["git", "-C", BASE, *args],
                           capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return None


def _worktree_status():
    """Return the tracked-tree cleanliness of the working directory relative to
    HEAD, as ('clean'|'dirty'|'unknown', dirty_paths).

    'clean' means the tracked working tree matches HEAD (both unstaged and
    staged), so the commit named in the attestation actually contains the bytes
    this release was built from. Every tracked file counts, *.docx included:
    the Word document is byte-reproducible (AUD-F35) and CI diffs it like any
    JSON file, so a differing .docx is a hand edit or sample residue, not noise.

    This does NOT flag untracked non-ignored files. `git clean_status` below
    surfaces them separately so an untracked module imported during the build
    is not silently ignored.
    """
    try:
        # Both worktree-vs-HEAD and index-vs-HEAD must be clean. `git diff` with
        # a pathspec exit code is 1 when differences exist, 0 when clean.
        unstaged = subprocess.run(
            ["git", "-C", BASE, "diff", "--quiet", "HEAD", "--", "."],
            capture_output=True, text=True, timeout=10)
        staged = subprocess.run(
            ["git", "-C", BASE, "diff", "--cached", "--quiet", "HEAD", "--", "."],
            capture_output=True, text=True, timeout=10)
    except Exception:  # noqa: BLE001
        return "unknown", []
    # returncode 0 = no diff (clean); 1 = diffs; anything else = error/unknown.
    if unstaged.returncode not in (0, 1) or staged.returncode not in (0, 1):
        return "unknown", []
    if unstaged.returncode == 0 and staged.returncode == 0:
        return "clean", []
    # Collect the specific dirty tracked paths for a useful error.
    names = subprocess.run(
        ["git", "-C", BASE, "diff", "--name-only", "HEAD", "--", "."],
        capture_output=True, text=True, timeout=10)
    cached_names = subprocess.run(
        ["git", "-C", BASE, "diff", "--cached", "--name-only", "HEAD", "--", "."],
        capture_output=True, text=True, timeout=10)
    paths = sorted(set(
        (names.stdout or "").split() + (cached_names.stdout or "").split()))
    return "dirty", paths


def _untracked_files():
    """Return untracked, non-ignored files. These are not a
    diff against HEAD, but an untracked .py imported at build time, or an
    untracked input, means the named commit does not fully describe the build
    context. Surface them so the operator decides."""
    try:
        r = subprocess.run(
            ["git", "-C", BASE, "ls-files", "--others", "--exclude-standard",
             "--", "."],
            capture_output=True, text=True, timeout=10)
    except Exception:  # noqa: BLE001
        return []
    if r.returncode != 0:
        return []
    return sorted((r.stdout or "").split())


def build_attestation():
    if not os.path.exists(MANIFEST):
        print("FAIL. No release-manifest.json; run the build first.")
        return None
    raw = open(MANIFEST, "rb").read()
    manifest_sha = "sha256:" + hashlib.sha256(raw).hexdigest()
    manifest = json.loads(raw)
    commit = _git("rev-parse", "HEAD")
    tree = _git("rev-parse", "HEAD^{tree}")
    worktree_state, dirty_paths = _worktree_status()
    untracked = _untracked_files()
    attestation = {
        "attestation_note": (
            "Binds the deterministic release-manifest.json (by SHA-256) to the "
            "exact git source that produced it. This file is release-only and "
            "does not modify the manifest, so a human signoff bound to the "
            "manifest hash stays valid. Not a compliance determination."),
        "release_tag": manifest.get("release_tag"),
        "framework_version": manifest.get("framework_version"),
        "dataset_version": manifest.get("dataset_version"),
        "release_manifest_sha256": manifest_sha,
        "source_commit": commit,
        "source_tree": tree,
        "git_available": bool(commit and tree),
        "worktree_clean": worktree_state == "clean",
        "worktree_state": worktree_state,
        "dirty_paths": dirty_paths,
        "untracked_paths": untracked,
    }
    return attestation


def main():
    att = build_attestation()
    if att is None:
        return 1
    # Fail-closed: a release attestation whose whole purpose is to bind the
    # manifest to the exact git source is meaningless without that source. If
    # the commit/tree cannot be resolved, do NOT write a hollow attestation with
    # null provenance and exit 0 - that would let sdr.py release and the
    # RELEASE_MODE publish path treat a provenance-less package as releasable.
    # Refuse instead, consistent with the repo's fail-closed philosophy.
    if not att["git_available"]:
        print("FAIL. git commit/tree unavailable (not a git checkout or git "
              "not on PATH); cannot bind the manifest to a source commit. A "
              "release attestation requires real provenance - refusing to "
              "write a null-provenance attestation. Run from a full git "
              "checkout (the CodePipeline source uses CODEBUILD_CLONE_REF so "
              "the .git metadata is present).")
        return 1
    # Fail-closed: the whole point of this file is to say the named commit/tree
    # IS the source that produced the manifest. `sdr.py release` builds from the
    # working tree, so if tracked files differ from HEAD, the package was built
    # from bytes that commit does NOT contain - the provenance statement would
    # be materially false. Refuse. Word documents are inside this check: the
    # .docx is byte-reproducible (AUD-F35), so a differing one is a hand edit or
    # sample residue, exactly what the attestation must not paper over. The
    # deployed CodePipeline is already protected here: it clones via
    # CODEBUILD_CLONE_REF and runs a regenerate-and-diff gate, so a tracked
    # change must live in the cloned commit; this closes the equivalent hole in
    # the LOCAL release path.
    if att["worktree_state"] == "dirty":
        print("FAIL. The tracked working tree differs from HEAD "
              f"({att['source_commit']}). `sdr.py release` builds from the "
              "working tree, so attesting this commit would bind the release to "
              "a source that does not contain the built bytes. Commit or stash "
              "the changes and rebuild before attesting. Differing tracked "
              "paths:")
        for p in att["dirty_paths"][:40]:
            print(f"    - {p}")
        return 1
    if att["worktree_state"] == "unknown":
        print("FAIL. Could not determine whether the tracked working tree "
              "matches HEAD (git diff did not run cleanly). Refusing to attest "
              "provenance that cannot be verified.")
        return 1
    if att["untracked_paths"]:
        print("FAIL. Untracked, non-ignored files are present; the named "
              f"commit ({att['source_commit']}) does not describe them, and an "
              "untracked module or input could have influenced the build. "
              "Commit, remove, or gitignore them before attesting:")
        for p in att["untracked_paths"][:40]:
            print(f"    - {p}")
        return 1
    with open(ATTESTATION, "w", encoding="utf-8", newline="\n") as f:
        json.dump(att, f, indent=1)
        f.write("\n")
    print(f"Release attestation written: {os.path.relpath(ATTESTATION, BASE)}")
    print(f"  manifest sha256 {att['release_manifest_sha256']}")
    print(f"  source commit   {att['source_commit']}")
    print("  worktree        clean (tracked tree matches HEAD, Word documents included)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
