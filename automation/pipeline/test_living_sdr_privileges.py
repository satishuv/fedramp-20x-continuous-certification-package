# Offline test: the living-SDR loop keeps its cloud credential and its
# repository write in DIFFERENT jobs (finding F89).
#
# Until AUD-F89 one job held `id-token: write` (AWS OIDC) together with
# `contents: write`, `pull-requests: write` and `issues: write`, and executed
# repository-controlled Python against the provider's account with all of them
# in scope. A compromised collector dependency or a crafted API response could
# therefore push a branch and open a PR. This test parses the workflow and
# asserts the separation as structure, so a later edit that quietly adds a
# write to the AWS job, or an AWS step to the write job, goes RED.
#
# Run: python automation/pipeline/test_living_sdr_privileges.py

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LOOP = os.path.join(BASE, ".github", "workflows", "living-sdr-loop.yml")

_fail = 0


def check(name, cond, detail=""):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}" + (f": {detail}" if detail else ""))


WRITE_SCOPES = ("contents", "pull-requests", "issues")


def perms(job, top):
    """Effective permissions of a job: its own block, else the workflow's."""
    p = job.get("permissions", top)
    return p if isinstance(p, dict) else {}


def uses_aws(job):
    return any("configure-aws-credentials" in str(s.get("uses", "")) for s in job.get("steps", []))


def runs(job):
    return "\n".join(str(s.get("run", "")) for s in job.get("steps", []))


def main():
    with open(LOOP, encoding="utf-8") as fh:
        wf = yaml.safe_load(fh)
    top = wf.get("permissions", {})
    jobs = wf["jobs"]

    check("workflow-level permissions grant no write (least privilege by default)",
          isinstance(top, dict) and all(v != "write" for v in top.values()),
          f"top-level permissions: {top}")

    aws_jobs = [n for n, j in jobs.items() if uses_aws(j)]
    check("exactly one job assumes the AWS role", len(aws_jobs) == 1, f"{aws_jobs}")

    for name, job in jobs.items():
        p = perms(job, top)
        has_token = p.get("id-token") == "write"
        has_write = any(p.get(s) == "write" for s in WRITE_SCOPES)
        check(f"job '{name}' does not hold id-token: write together with a repository write",
              not (has_token and has_write), f"permissions: {p}")
        if uses_aws(job):
            check(f"AWS job '{name}' has contents: read, not write", p.get("contents") == "read",
                  f"permissions: {p}")
            check(f"AWS job '{name}' pushes nothing and opens nothing",
                  "git push" not in runs(job) and "gh pr create" not in runs(job)
                  and "gh issue" not in runs(job))
        if "git push" in runs(job) or "gh pr create" in runs(job):
            check(f"repository-writing job '{name}' holds no id-token",
                  p.get("id-token") != "write", f"permissions: {p}")
            check(f"repository-writing job '{name}' runs no AWS credential step", not uses_aws(job))
            check(f"repository-writing job '{name}' refuses a patch outside the deliverables",
                  "REFUSE" in runs(job) and "changed-paths" in runs(job))
            check(f"repository-writing job '{name}' applies the patch to the index before committing",
                  "git apply --index" in runs(job))
        if "gh issue create" in runs(job):
            check(f"alarm job '{name}' holds issues: write and nothing else writable",
                  p.get("issues") == "write"
                  and all(p.get(s) != "write" for s in ("contents", "pull-requests", "id-token")),
                  f"permissions: {p}")

    # The hand-off between the two domains is an artifact, and the write job
    # depends on the AWS job (it never runs on its own).
    writers = [n for n, j in jobs.items() if "git push" in runs(j)]
    check("there is exactly one repository-writing job", len(writers) == 1, f"{writers}")
    if writers and aws_jobs:
        w = jobs[writers[0]]
        needs = w.get("needs", [])
        needs = [needs] if isinstance(needs, str) else needs
        check("the writing job depends on the AWS job", aws_jobs[0] in needs, f"needs: {needs}")
        check("the AWS job hands over the diff as an artifact",
              any("upload-artifact" in str(s.get("uses", "")) for s in jobs[aws_jobs[0]]["steps"]))
        check("the writing job takes the diff from the artifact",
              any("download-artifact" in str(s.get("uses", "")) for s in w["steps"]))

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: living_sdr_privileges ({_fail} failures)")
    return 1 if _fail else 0


# ---- AUD-F93: the patch boundary is a positive allowlist ------------------------
#
# Until AUD-F93 the propose job refused a denylist (.github/, audit/,
# requirements*, references/, profiles/common/, four script extensions) and
# admitted every other tracked file: Makefile, pyproject.toml, LICENSE,
# .gitignore, any JSON outside the named roots. The boundary is now the committed
# automation/pipeline/living-sdr-allowed-paths.txt, read from the checkout of
# the default branch before the patch is applied.

ALLOWLIST_REL = "automation/pipeline/living-sdr-allowed-paths.txt"
ALLOWLIST = os.path.join(BASE, *ALLOWLIST_REL.split("/"))
MANIFEST = os.path.join(BASE, "artifacts", "release-manifest.json")

# Paths a regeneration must never be able to hand to the writing job.
GOVERNANCE_PATHS = [
    ".github/workflows/release.yml", ".github/release-allowed-signers",
    ".github/dependabot.yml", "audit/defect-ledger.json", "audit/mutation_tests.py",
    "audit/release_gate.py", "requirements.txt", "requirements.lock",
    "references/fedramp-consolidated-rules.json", "references/sources.lock.json",
    "profiles/common/offering-profile.json", "profiles/common/ksi-profile.json",
    "Makefile", "pyproject.toml", "LICENSE", ".gitignore", ".gitmodules",
    "README.md", "SECURITY.md", "sdr.py", "setup.py",
    "automation/collectors/collectors.py", "automation/pipeline/sdr-pipeline.yaml",
    "artifacts/schemas/official/fedramp-security-decision-record-schema-2026-06-24.json",
    ALLOWLIST_REL,
]


def _allow_rules():
    rules = []
    with open(ALLOWLIST, encoding="utf-8") as fh:
        for ln in fh:
            s = ln.strip()
            if s and not s.startswith("#"):
                rules.append(s)
    return rules


def _allowed_by_list(path, rules):
    """Mirror of the step's matching: a rule ending in '/' is a prefix, any
    other rule is one exact path; '..', scripts, workflows and the pinned
    schemas are refused regardless."""
    if ".." in path or path.endswith((".py", ".yml", ".yaml", ".sh")) \
            or path.startswith("artifacts/schemas/"):
        return False
    return any(path.startswith(r) if r.endswith("/") else path == r for r in rules)


def _propose_step_shell(wf):
    """The 'Refuse a patch' step's run: block of the propose job, verbatim."""
    for step in wf["jobs"]["propose"]["steps"]:
        if str(step.get("name", "")).startswith("Refuse a patch"):
            return step["run"], (step.get("env") or {}).get("ALLOWLIST", "")
    return "", ""


def main_f93():
    with open(LOOP, encoding="utf-8") as fh:
        wf = yaml.safe_load(fh)
    shell, env_allow = _propose_step_shell(wf)

    check("the propose job's boundary step names the committed allowlist as its env",
          env_allow == ALLOWLIST_REL, f"ALLOWLIST={env_allow!r}")
    check("the boundary step reads every rule of the allowlist (positive match, not a denylist)",
          'done < "$ALLOWLIST"' in shell and "allowed=1" in shell and "not in $ALLOWLIST" in shell)
    check("the boundary step refuses when the allowlist is missing or empty (fail closed)",
          'test -s "$ALLOWLIST"' in shell)
    check("the boundary step refuses '..' segments, scripts, workflows and pinned schemas unconditionally",
          "*..*" in shell and "*.py" in shell and "artifacts/schemas/*" in shell)
    check("the old denylist shape is gone",
          ".github/*|audit/*" not in shell)
    # AUD-F95: the object judged is the patch, not the sidecar.
    check("the boundary step derives the path set from the patch itself (git apply --numstat)",
          "git apply --numstat" in shell and "patch-paths.txt" in shell)
    check("the boundary step authorizes the patch-derived set, not changed-paths.txt",
          "authorize_paths /tmp/living-sdr/patch-paths.txt" in shell
          and "authorize_paths /tmp/living-sdr/changed-paths.txt" not in shell
          and 'done < /tmp/living-sdr/changed-paths.txt' not in shell)
    check("the sidecar is consistency telemetry: a disagreement with the patch is refused",
          "disagrees with the patch" in shell)
    check("the boundary step dry-runs the apply (git apply --check) before anything is staged",
          "git apply --check" in shell)
    check("renames and copies in the patch are refused (a regeneration rewrites in place)",
          "rename|copy" in shell)

    check("the allowlist is committed and non-empty", os.path.exists(ALLOWLIST) and _allow_rules() != [])
    rules = _allow_rules()
    check("the allowlist lives outside every prefix it allows (a patch cannot rewrite its own boundary)",
          not _allowed_by_list(ALLOWLIST_REL, rules))

    with open(MANIFEST, encoding="utf-8") as fh:
        fingerprinted = sorted(json.load(fh)["artifacts"])
    missing = [p for p in fingerprinted if not _allowed_by_list(p, rules)]
    check("every artifact the release manifest fingerprints is inside the allowlist",
          not missing, str(missing[:5]))
    leaked = [p for p in GOVERNANCE_PATHS if _allowed_by_list(p, rules)]
    check("no governance path is inside the allowlist (workflows, ledger, locks, pinned sources, "
          "profiles/common, Makefile, pyproject, LICENSE, .gitignore, .gitmodules, the list itself)",
          not leaked, str(leaked))

    # Decisive check: run the shipped shell verbatim when bash is available
    # (CI runners and WSL), in a throwaway clone, with REAL patches. AUD-F95:
    # the object judged must be the patch and the staged result, so each case
    # builds a patch by actually editing the named file in the clone; the
    # sidecar is written separately so it can be made to lie.
    bash = shutil.which("bash")
    if not bash:
        print("  SKIP verbatim shell cases (no bash on PATH)")
        return
    apply_shell = _apply_step_shell(wf)
    check("the propose job applies the patch in a step that re-authorizes the staged result",
          "git diff --cached --name-only" in apply_shell and "patch-paths.txt" in apply_shell)
    # (patch_target, sidecar_claim or None for honest, expect_ok)
    cases = [
        ("sdr/json/sdr-class-b.json", None, True),
        ("package/cpo/cpo.json", None, True),
        ("validation/reports/validation-report.json", None, True),
        ("automation/collectors/registry.json", None, True),
        ("Makefile", None, False), ("pyproject.toml", None, False), ("LICENSE", None, False),
        (".gitignore", None, False),
        ("automation/sdrscan/check-catalog.json", None, False),   # tracked JSON outside the roots
        ("profiles/common/offering-profile.json", None, False),
        ("artifacts/schemas/official/fedramp-common-definitions-schema-2026-06-24.json", None, False),
        ("sdr/json/evil.py", None, False),
        (ALLOWLIST_REL, None, False),
        # AUD-F95: the attack. The patch changes a forbidden file while the
        # sidecar claims an allowed one. Before F95 this PASSED.
        ("Makefile", "sdr/json/sdr-class-b.json", False),
        (".github/workflows/release.yml", "package/cpo/cpo.json", False),
        (ALLOWLIST_REL, "sdr/json/sdr-class-b.json", False),
        # The reverse lie: allowed patch, sidecar naming something else.
        ("sdr/json/sdr-class-b.json", "package/cpo/cpo.json", False),
    ]
    with tempfile.TemporaryDirectory() as td:
        clone = os.path.join(td, "clone")
        # No line-ending conversion in the throwaway clone: with
        # core.autocrlf=input on a Windows host the working copy and index
        # disagree byte-for-byte and `git apply --index` reports "does not
        # match index" for reasons unrelated to the workflow under test. The
        # ubuntu runner has no such conversion.
        subprocess.run(["git", "-c", "core.autocrlf=false", "clone", "-q", "--no-local", BASE, clone], check=True)
        subprocess.run(["git", "-C", clone, "config", "core.autocrlf", "false"], check=True)
        subprocess.run(["git", "-C", clone, "config", "user.email", "t@example.invalid"], check=True)
        subprocess.run(["git", "-C", clone, "config", "user.name", "t"], check=True)
        tmp = os.path.join(td, "living-sdr")
        os.makedirs(tmp)
        # The exchange directory is the one the collect job uploads to; the
        # step names its members through env (PATCH, SIDECAR). Read it there
        # and point every occurrence (env values and the shell's own temp
        # files) at ours for the run.
        step_env = _propose_step_env(wf)
        sidecar_env = step_env.get("SIDECAR", "")
        m_dir = re.match(r"(.+/)changed-paths\.txt$", sidecar_env)
        check("the boundary step names the sidecar and patch through env, in one exchange directory",
              m_dir is not None and step_env.get("PATCH", "").startswith(m_dir.group(1) if m_dir else "\0"))
        if not m_dir:
            return
        exchange = m_dir.group(1)
        step1 = os.path.join(td, "step1.sh"); step2 = os.path.join(td, "step2.sh")
        for path_, body in ((step1, shell), (step2, apply_shell)):
            with open(path_, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(body.replace(exchange, _posix(tmp) + "/"))
        env_prefix = (f'ALLOWLIST="{ALLOWLIST_REL}" PATCH="{_posix(tmp)}/regenerated.patch" '
                      f'SIDECAR="{_posix(tmp)}/changed-paths.txt"')

        def run_step(script, refresh=False):
            # `refresh`: the apply step runs `git apply --index`, which
            # compares against the index's stat cache. On this host the clone
            # is written by Windows git and the step runs under WSL git, two
            # programs with incompatible stat caches, so every entry reads
            # stale ("does not match index"). Refresh from the bash side first;
            # it changes no content and is a harness concern only (the ubuntu
            # runner uses one git throughout).
            pre = "git update-index -q --refresh; " if refresh else ""
            return subprocess.run([bash, "-c", f'cd "{_posix(clone)}" && {pre}{env_prefix} bash "{_posix(script)}"'],
                                  capture_output=True, text=True)

        for target, claim, expect_ok in cases:
            # Build a real patch: append to the target (creating it if it is
            # the one untracked case), diff, restore.
            tpath = os.path.join(clone, *target.split("/"))
            existed = os.path.exists(tpath)
            os.makedirs(os.path.dirname(tpath), exist_ok=True)
            with open(tpath, "ab") as fh:
                fh.write(b"\n# regenerated\n")
            if not existed:
                subprocess.run(["git", "-C", clone, "add", "-N", "--", target], check=True)
            patch = subprocess.run(["git", "-C", clone, "diff", "--binary", "--", "."],
                                   capture_output=True, text=True).stdout
            subprocess.run(["git", "-C", clone, "reset", "-q", "--hard", "HEAD"], check=True)
            subprocess.run(["git", "-C", clone, "clean", "-q", "-fd"], check=True)
            with open(os.path.join(tmp, "regenerated.patch"), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(patch)
            with open(os.path.join(tmp, "changed-paths.txt"), "w", encoding="utf-8", newline="\n") as fh:
                fh.write((claim or target) + "\n")
            r1 = run_step(step1)
            ok = r1.returncode == 0
            label = f"patch={target}" + (f" sidecar-claims={claim}" if claim else "")
            check(f"verbatim boundary {'admits' if expect_ok else 'refuses'} {label}",
                  ok == expect_ok, (r1.stdout + r1.stderr).strip()[-200:])
            if ok and expect_ok:
                r2 = run_step(step2, refresh=True)
                staged = subprocess.run(["git", "-C", clone, "diff", "--cached", "--name-only"],
                                        capture_output=True, text=True).stdout.split()
                check(f"verbatim apply stages exactly the authorized path for {target}",
                      r2.returncode == 0 and staged == [target], (r2.stdout + r2.stderr).strip()[-200:])
                subprocess.run(["git", "-C", clone, "reset", "-q", "--hard", "HEAD"], check=True)

        # AUD-F95, the second half: a patch whose declared file list disagrees
        # with what applying it stages cannot be built with git (the apply
        # follows the headers), so the staged re-check is exercised by
        # pre-staging a forbidden change in the clone before step 2 runs.
        tpath = os.path.join(clone, "sdr", "json", "sdr-class-b.json")
        with open(tpath, "ab") as fh:
            fh.write(b"\n# regenerated\n")
        patch = subprocess.run(["git", "-C", clone, "diff", "--binary", "--", "."],
                               capture_output=True, text=True).stdout
        subprocess.run(["git", "-C", clone, "reset", "-q", "--hard", "HEAD"], check=True)
        with open(os.path.join(tmp, "regenerated.patch"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(patch)
        with open(os.path.join(tmp, "changed-paths.txt"), "w", encoding="utf-8", newline="\n") as fh:
            fh.write("sdr/json/sdr-class-b.json\n")
        r1 = run_step(step1)
        check("staged-set probe: honest patch passes the boundary step", r1.returncode == 0,
              (r1.stdout + r1.stderr).strip()[-200:])
        with open(os.path.join(clone, "Makefile"), "ab") as fh:
            fh.write(b"\n# smuggled\n")
        subprocess.run(["git", "-C", clone, "add", "--", "Makefile"], check=True)
        r2 = run_step(step2, refresh=True)
        check("staged-set probe: the apply step refuses when the staged set exceeds the authorized set",
              r2.returncode != 0 and "Staged paths differ" in r2.stdout, (r2.stdout + r2.stderr).strip()[-200:])
        subprocess.run(["git", "-C", clone, "reset", "-q", "--hard", "HEAD"], check=True)


def _apply_step_shell(wf):
    """The apply step's run: block of the propose job, verbatim."""
    for step in wf["jobs"]["propose"]["steps"]:
        if str(step.get("name", "")).startswith("Apply the patch"):
            return step["run"]
    return ""


def _propose_step_env(wf):
    """The boundary step's env block (ALLOWLIST, PATCH, SIDECAR)."""
    for step in wf["jobs"]["propose"]["steps"]:
        if str(step.get("name", "")).startswith("Refuse a patch"):
            return dict(step.get("env") or {})
    return {}


def _posix(p):
    """A path bash can open: WSL bash needs /mnt/<drive>/..., Git bash takes
    the Windows path as-is; POSIX hosts pass through."""
    if os.name != "nt":
        return p
    drive, rest = os.path.splitdrive(p)
    rest = rest.replace("\\", "/")
    bash = shutil.which("bash") or ""
    if "system32" in bash.lower() or "wsl" in bash.lower():
        return f"/mnt/{drive[0].lower()}{rest}"
    return drive + rest


if __name__ == "__main__":
    rc = main()
    main_f93()
    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: living_sdr_privileges incl. F93 ({_fail} failures)")
    sys.exit(1 if _fail else 0)
