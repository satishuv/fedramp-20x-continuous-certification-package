#!/usr/bin/env python3
"""Assert the publication pipeline hard-gates submission readiness.

The publish path is Validate -> Collect -> Human Approval -> Publish. The
validate buildspec only hard-gates package-preflight when RELEASE_MODE=true, so
the deployed ValidateProject MUST set it - otherwise a package with known
readiness blockers could reach Publish. This test parses the CloudFormation
template textually (no yaml dependency; CFN short tags are not plain YAML) and
confirms the wiring.

    python automation/pipeline/test_release_gate.py
"""

import os
import re
import sys
import json
import fnmatch

HERE = os.path.dirname(os.path.abspath(__file__))
PIPELINE = os.path.join(HERE, "sdr-pipeline.yaml")
BUILDSPEC = os.path.join(HERE, "buildspec-validate.yml")
BASE = os.path.dirname(os.path.dirname(HERE))
MANIFEST = os.path.join(BASE, "artifacts", "release-manifest.json")


def _bundle_globs(buildspec):
    """Extract the artifacts.files globs and exclude-paths from the buildspec."""
    files, excludes, section = [], [], None
    for line in buildspec.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue  # comments and blanks never open, close, or fill a section
        if s.startswith("files:"):
            section = "files"; continue
        if s.startswith("exclude-paths:"):
            section = "exclude"; continue
        if s.startswith("- "):
            if section:
                item = s[2:].strip().strip('"')
                (files if section == "files" else excludes).append(item)
            continue
        # A real (non-comment) key line at this or a lower indent closes the list.
        section = None
    return files, excludes


def _covered(path, globs):
    """True if path is matched by any bundle glob. Handles exact paths,
    'dir/**/*' recursive trees, 'dir/**/*.ext' recursive-with-suffix,
    'dir/name.*' suffix globs, and plain fnmatch."""
    for g in globs:
        if g == path:
            return True
        if g.endswith("/**/*"):
            prefix = g[:-len("/**/*")]
            if path == prefix or path.startswith(prefix + "/"):
                return True
        elif "/**/*." in g:
            # recursive tree restricted to a suffix, e.g. sdr/json/**/*.oscal.json
            prefix, suffix = g.split("/**/*.", 1)
            if path.startswith(prefix + "/") and path.endswith("." + suffix):
                return True
        elif "**" in g:
            pat = g.replace("/**/", "/").replace("**/", "").replace("/**", "")
            if fnmatch.fnmatch(path, pat):
                return True
        elif fnmatch.fnmatch(path, g):
            return True
    return False


def main():
    pipeline = open(PIPELINE, encoding="utf-8").read()
    buildspec = open(BUILDSPEC, encoding="utf-8").read()
    passed = failed = 0

    def check(name, cond):
        nonlocal passed, failed
        if cond:
            passed += 1; print(f"  PASS {name}")
        else:
            failed += 1; print(f"  FAIL {name}")

    # The buildspec must run package-preflight and hard-gate it under RELEASE_MODE.
    check("buildspec runs package-preflight",
          "package-preflight" in buildspec)
    check("buildspec hard-gates when RELEASE_MODE=true",
          re.search(r'RELEASE_MODE.*=.*true', buildspec) is not None
          and "exit 1" in buildspec)

    # Release-path parity: a RELEASE_MODE build must run the SAME full gate the
    # GitHub/local release runs - the offline test suite (full `sdr.py validate`,
    # NOT `validate --no-tests`) AND a double-build reproducibility check - so
    # the AWS release path is not weaker than the GitHub release gate.
    rel_branch = ""
    m_rel = re.search(r'if \[ "\$RELEASE_MODE" = "true" \];[\s\S]*?else', buildspec)
    if m_rel:
        rel_branch = m_rel.group(0)
    check("RELEASE_MODE build runs full validate (with tests), not --no-tests",
          "sdr.py validate" in rel_branch and "validate --no-tests" not in rel_branch)
    check("RELEASE_MODE build runs the reproducibility gate",
          "cmd_reproducibility" in rel_branch)

    # Class C/D SDR-CSX-KMT readiness turns on the durable metric history, which
    # is gitignored and lives only in the evidence bucket. The release build MUST
    # restore it BEFORE build/validate/preflight, fail-closed (a confirmed-missing
    # object is allowed as a first run; any other restore error aborts), or a
    # Class C release would evaluate readiness against an empty tree and block.
    check("buildspec restores metric-history before preflight",
          "metric-history.json" in buildspec
          and "s3 cp" in buildspec
          and re.search(r'EVIDENCE_BUCKET', buildspec) is not None)
    # The restore must precede the readiness evaluation, not follow it.
    check("metric-history restore runs before package-preflight",
          buildspec.find("metric-history.json") < buildspec.find("package-preflight"))
    # Fail-closed: only a confirmed-missing object proceeds; other errors abort.
    restore_seg = buildspec.split("python sdr.py build", 1)[0]
    check("metric-history restore is fail-closed (aborts on non-404 errors)",
          "NoSuchKey" in restore_seg and "exit 1" in restore_seg)

    # The ValidateProject in the publish pipeline must set RELEASE_MODE=true.
    vp = pipeline.split("ValidateProject:", 1)[-1].split("DriftCheckProject:", 1)[0]
    check("publish pipeline ValidateProject sets RELEASE_MODE",
          "RELEASE_MODE" in vp)
    check("ValidateProject RELEASE_MODE value is true",
          re.search(r'RELEASE_MODE[\s\S]{0,120}?"true"', vp) is not None
          or re.search(r'RELEASE_MODE[\s\S]{0,120}?true', vp) is not None)

    # The ValidateProject must pass EVIDENCE_BUCKET so the release build can
    # restore the durable metric history before the readiness evaluation.
    check("ValidateProject passes EVIDENCE_BUCKET to the release build",
          "EVIDENCE_BUCKET" in vp)

    # Class C/D manifest binding: the release manifest must fold the durable
    # metric history into its hashed inputs for Class C/D (it is readiness-
    # critical for SDR-CSX-KMT yet not a generated artifact), so the human
    # signoff bound to the manifest hash covers it. Verified against the builder
    # source rather than a live manifest (the repo's active class is B, where the
    # history is correctly NOT bound).
    brm_src = open(os.path.join(BASE, "validation", "scripts",
                                "build_release_manifest.py"), encoding="utf-8").read()
    check("release manifest binds metric-history for Class C/D",
          "automation/metrics/metric-history.json" in brm_src
          and re.search(r'cls in \("c", "d"\)', brm_src) is not None)

    # Full-clone IAM: if the Source stage produces a CODEBUILD_CLONE_REF (git
    # full clone) artifact, the CodeBuild *service role* consuming it MUST hold
    # UseConnection scoped to the connection - AWS fails the initial full-clone
    # build otherwise, and GetConnection/GetConnectionToken alone do not cover
    # it. This guards against the permission silently regressing.
    uses_full_clone = "CODEBUILD_CLONE_REF" in pipeline
    check("Source stage requests a git full clone (CODEBUILD_CLONE_REF)",
          uses_full_clone)
    if uses_full_clone:
        # ValidateProject consumes the full-clone artifact and runs under
        # CodeBuildRole; that role's policy must grant UseConnection.
        vp_role = re.search(r'ServiceRole:\s*!GetAtt\s+(\w+)\.Arn', vp)
        role_name = vp_role.group(1) if vp_role else None
        check("ValidateProject runs under a named CodeBuild service role",
              role_name is not None)
        # Isolate that role's definition block in the template.
        role_block = ""
        if role_name:
            m = re.search(
                r'^\s{2}' + re.escape(role_name) + r':\n[\s\S]*?(?=\n\s{2}\w+:\n)',
                pipeline, re.MULTILINE)
            role_block = m.group(0) if m else ""
        check(f"{role_name or 'ValidateProject role'} grants codeconnections:UseConnection",
              "codeconnections:UseConnection" in role_block)
        check(f"{role_name or 'ValidateProject role'} grants codestar-connections:UseConnection",
              "codestar-connections:UseConnection" in role_block)

    # Bundle-vs-manifest parity: every artifact the release manifest fingerprints
    # Active-class bundle: the publish path assembles the bundle from exactly
    # what the release manifest fingerprints (active class only), not from
    # all-class wildcards. Assert the buildspec publishes the assembled bundle
    # and runs the assembler.
    files, _excludes = _bundle_globs(buildspec)
    check("buildspec publishes the assembled active-class bundle",
          any("release-bundle" in g for g in files))
    check("buildspec does NOT publish all-class SDR wildcards",
          not any(g.startswith("sdr/json/**") or g.startswith("sdr/human-readable/**")
                  for g in files))
    check("buildspec runs the bundle assembler",
          "assemble_release_bundle.py" in buildspec)

    # Run the assembler and verify its output is manifest-complete and contains
    # no inactive-class SDR. This makes bundle<->manifest drift and inactive-class
    # leakage a test failure, not a silent inconsistency the customer discovers.
    import importlib.util
    spec_ab = importlib.util.spec_from_file_location(
        "arb", os.path.join(BASE, "validation", "scripts", "assemble_release_bundle.py"))
    arb = importlib.util.module_from_spec(spec_ab); spec_ab.loader.exec_module(arb)
    res = arb.assemble()
    manifest = json.load(open(MANIFEST, encoding="utf-8")) if os.path.exists(MANIFEST) else {}
    active = (manifest.get("certification_class") or "").lower()
    fingerprinted = sorted((manifest.get("artifacts") or {}).keys())
    copied = set(res["copied"]) if res else set()
    check("assembled bundle contains every fingerprinted artifact "
          + (f"(missing: {[p for p in fingerprinted if p not in copied][:5]})"
             if res and any(p not in copied for p in fingerprinted) else ""),
          bool(res) and not res["missing"] and all(p in copied for p in fingerprinted))
    stray = [p for p in copied if p.startswith("sdr/") and f"sdr-class-{active}" not in p]
    check("assembled bundle contains NO inactive-class SDR"
          + (f" (stray: {stray[:3]})" if stray else ""),
          not stray)
    check("the SBOM is in the assembled bundle",
          "artifacts/sbom.cdx.json" in copied)

    # The attestation must bind the manifest by hash and must NOT be produced by
    # mutating the manifest (the manifest's own source_commit stays null so a
    # signoff bound to its hash survives).
    spec = importlib.util.spec_from_file_location(
        "bra", os.path.join(BASE, "validation", "scripts", "build_release_attestation.py"))
    bra = importlib.util.module_from_spec(spec); spec.loader.exec_module(bra)
    att = bra.build_attestation()
    import hashlib
    manifest_sha = ("sha256:" + hashlib.sha256(open(MANIFEST, "rb").read()).hexdigest()
                    if os.path.exists(MANIFEST) else None)
    check("attestation binds the current manifest hash",
          att and att.get("release_manifest_sha256") == manifest_sha)
    check("attestation records real git provenance (commit non-null)",
          bool(att and att.get("source_commit")))
    check("attestation records real git provenance (tree non-null)",
          bool(att and att.get("source_tree")))
    check("attestation git_available is True",
          bool(att and att.get("git_available")))
    # Fail-closed contract: main() must refuse (non-zero) when provenance is
    # unavailable, rather than writing a null-provenance attestation and
    # exiting 0. Verify by forcing _git() to return None so git_available=False.
    _orig_git = bra._git
    try:
        bra._git = lambda *a, **k: None
        rc_no_prov = bra.main()
    finally:
        bra._git = _orig_git
    check("attestation main() fails closed when git provenance is unavailable",
          rc_no_prov != 0)

    # Fail-closed contract 2: `sdr.py release` builds from the WORKING TREE, so
    # main() must refuse (non-zero) when the tracked tree differs from HEAD -
    # attesting HEAD would bind the release to a commit that lacks the built
    # bytes. Simulate a dirty tree via the status helper; assert no attestation
    # is written and the exit is non-zero.
    _orig_ws = bra._worktree_status
    _orig_unt0 = bra._untracked_files
    _att_path = os.path.join(BASE, "artifacts", "release-attestation.json")
    _att_before = os.path.exists(_att_path)
    _att_mtime = os.path.getmtime(_att_path) if _att_before else None
    try:
        bra._worktree_status = lambda: ("dirty", ["profiles/common/offering-profile.json"])
        bra._untracked_files = lambda: []
        rc_dirty = bra.main()
    finally:
        bra._worktree_status = _orig_ws
        bra._untracked_files = _orig_unt0
    _att_untouched = (os.path.exists(_att_path) == _att_before and
                      (_att_mtime is None or os.path.getmtime(_att_path) == _att_mtime))
    check("attestation main() fails closed on a dirty tracked working tree",
          rc_dirty != 0)
    check("attestation not written/updated when the working tree is dirty",
          _att_untouched)

    # Fail-closed contract 3: untracked non-ignored files (e.g. an untracked
    # module imported at build time) mean the named commit does not describe the
    # build; main() must refuse. Force a clean tracked tree so this exercises
    # the untracked path specifically (not the dirty-tree path above).
    _orig_unt = bra._untracked_files
    _orig_ws2 = bra._worktree_status
    _att_before2 = os.path.exists(_att_path)
    _att_mtime2 = os.path.getmtime(_att_path) if _att_before2 else None
    try:
        bra._worktree_status = lambda: ("clean", [])
        bra._untracked_files = lambda: ["validation/scripts/rogue_helper.py"]
        rc_unt = bra.main()
    finally:
        bra._untracked_files = _orig_unt
        bra._worktree_status = _orig_ws2
    _att_untouched2 = (os.path.exists(_att_path) == _att_before2 and
                       (_att_mtime2 is None or os.path.getmtime(_att_path) == _att_mtime2))
    check("attestation main() fails closed on untracked non-ignored files",
          rc_unt != 0)
    check("attestation not written/updated when untracked files are present",
          _att_untouched2)

    # Positive control: with a clean tracked tree and no untracked files,
    # build_attestation reports worktree_clean=True. Forced clean so the check
    # holds during local editing too (in CI the merge commit is genuinely clean).
    _orig_ws3 = bra._worktree_status
    _orig_unt3 = bra._untracked_files
    try:
        bra._worktree_status = lambda: ("clean", [])
        bra._untracked_files = lambda: []
        att_clean = bra.build_attestation()
    finally:
        bra._worktree_status = _orig_ws3
        bra._untracked_files = _orig_unt3
    check("attestation records worktree_clean=True on a clean checkout",
          bool(att_clean and att_clean.get("worktree_clean") is True))

    check("manifest source_commit stays null (not mutated by release)",
          (manifest.get("source_provenance", {}) or {}).get("source_commit") is None)

    # ---- AUD-F12: ONE release gate, three executors, one definition. ---------
    # (a) The definition itself must carry every anti-circular step. This is
    #     the MUT-F12 target: dropping the mutation runner from the audit
    #     section must turn this red.
    spec_rg = importlib.util.spec_from_file_location(
        "release_gate", os.path.join(BASE, "audit", "release_gate.py"))
    rg = importlib.util.module_from_spec(spec_rg); spec_rg.loader.exec_module(rg)
    audit_steps = [name for name, _argv in rg.SECTIONS.get("audit", [])]
    security_steps = [name for name, _argv in rg.SECTIONS.get("security", [])]
    for required in ("requirements-oracle-selftest", "requirements-oracle",
                     "mutation-runner-selftest", "mutation-runner",
                     "tree-clean-after-mutation"):
        check(f"release gate audit section includes {required}",
              required in audit_steps)
    check("release gate security section includes bandit",
          "bandit" in security_steps)
    check("release gate refuses an unknown section (fails closed, not silently empty)",
          rg.run(["no-such-section"]) != 0)
    # Every argv must name an existing script or a module the gate can run.
    for section, steps in rg.SECTIONS.items():
        for name, argv in steps:
            target = next((a for a in argv if a.endswith(".py")), None)
            if target:
                check(f"release gate step {section}/{name} targets an existing script",
                      os.path.exists(os.path.join(BASE, target)))

    # (b) GitHub Actions: audit-gate and security-scan jobs execute the shared
    #     definition, and ONE aggregate job depends on all three sections and
    #     runs even when a dependency failed (a skipped required check blocks
    #     nothing).
    wf = open(os.path.join(BASE, ".github", "workflows", "validate.yml"),
              encoding="utf-8").read()
    jobs = re.split(r'^\s{2}(?=[a-z][a-z-]*:\s*$)', wf, flags=re.MULTILINE)
    job_text = {j.split(":", 1)[0].strip(): j for j in jobs if re.match(r'[a-z][a-z-]*:\s*$', j.split("\n", 1)[0])}
    check("CI has an audit-gate job that runs the shared release gate (audit)",
          "release_gate.py audit" in job_text.get("audit-gate", ""))
    check("CI has a security-scan job that runs the shared release gate (security)",
          "release_gate.py security" in job_text.get("security-scan", ""))
    agg = job_text.get("release-gate", "")
    check("CI has a release-gate aggregate job", bool(agg))
    needs = re.search(r'needs:\s*\[([^\]]*)\]', agg)
    needs_set = {n.strip() for n in needs.group(1).split(",")} if needs else set()
    check("release-gate needs validate + audit-gate + security-scan",
          needs_set == {"validate", "audit-gate", "security-scan"})
    check("release-gate runs even when a dependency failed (if: always())",
          re.search(r'if:\s*always\(\)', agg) is not None)
    check("release-gate fails unless every section result is success",
          '!= "success"' in agg and "exit 1" in agg)
    check("validate workflow is callable by the release workflow (workflow_call)",
          re.search(r'^\s+workflow_call:', wf, re.MULTILINE) is not None)

    # (c) AWS RELEASE_MODE executes the same definition.
    check("RELEASE_MODE build runs the shared release gate (audit + security)",
          "release_gate.py audit security" in rel_branch)

    # (d) `sdr.py release` executes the same definition and instructs a SIGNED
    #     tag (docs/versioning.md), not a plain unsigned one.
    sdr_src = open(os.path.join(BASE, "sdr.py"), encoding="utf-8").read()
    m_rel_fn = re.search(r'^def cmd_release\(.*?(?=^def )', sdr_src, re.MULTILINE | re.DOTALL)
    rel_fn = m_rel_fn.group(0) if m_rel_fn else ""
    check("sdr.py release runs the shared release gate (audit + security)",
          "release_gate.py" in rel_fn and '["audit", "security"]' in rel_fn)
    check("sdr.py release runs the gate BEFORE the reproducibility check",
          0 < rel_fn.find("release_gate.py") < rel_fn.find("cmd_reproducibility()"))
    check("sdr.py release instructs a signed tag (git tag -s)",
          "git tag -s" in rel_fn)
    check("sdr.py release no longer instructs a plain unsigned tag",
          re.search(r'To tag: git tag \{', rel_fn) is None)

    # (e) Tag-driven release workflow: refuses unsigned tags, re-runs the whole
    #     gate on the tagged commit, attaches manifest + attestation + SBOM.
    rw_path = os.path.join(BASE, ".github", "workflows", "release.yml")
    rw = open(rw_path, encoding="utf-8").read() if os.path.exists(rw_path) else ""
    check("release workflow exists and triggers on v* tags",
          'tags: ["v*"]' in rw)
    check("release workflow refuses a tag without a signature block",
          "SIGNATURE" in rw and "exit 1" in rw)
    check("release workflow refuses a tag that does not match the manifest release_tag",
          "release_tag" in rw)
    check("release workflow re-runs the full validate workflow on the tag",
          "uses: ./.github/workflows/validate.yml" in rw)
    check("release workflow attaches manifest, attestation and SBOM as assets",
          "release-manifest.json" in rw and "release-attestation.json" in rw
          and "sbom.cdx.json" in rw and "gh release" in rw)
    check("release workflow publish job needs the gate",
          re.search(r'needs:\s*\[verify-tag,\s*gate\]', rw) is not None)

    print(f"\n{passed}/{passed + failed} release-gate checks passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
