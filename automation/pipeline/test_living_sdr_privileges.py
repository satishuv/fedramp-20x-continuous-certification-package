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
    # (CI runners and WSL). Each case writes one path into changed-paths.txt;
    # tracked allowed paths must pass, every other case must be refused.
    bash = shutil.which("bash")
    if not bash:
        print("  SKIP verbatim shell cases (no bash on PATH)")
        return
    cases = [
        ("sdr/json/sdr-class-b.json", True),
        ("package/cpo/cpo.json", True),
        ("validation/reports/validation-report.json", True),
        ("automation/collectors/registry.json", True),
        ("Makefile", False), ("pyproject.toml", False), ("LICENSE", False),
        (".gitignore", False), (".gitmodules", False),
        ("automation/sdrscan/check-catalog.json", False),   # tracked JSON outside the roots
        ("profiles/common/offering-profile.json", False),
        ("artifacts/schemas/official/fedramp-common-definitions-schema-2026-06-24.json", False),
        ("sdr/../sdr.py", False),
        ("sdr/json/evil.py", False),
        (ALLOWLIST_REL, False),
    ]
    with tempfile.TemporaryDirectory() as td:
        tmp = os.path.join(td, "living-sdr")
        os.makedirs(tmp)
        # The step reads changed-paths.txt from the exchange directory the
        # collect job uploads to; read that directory out of the step text
        # (not hardcoded here) and point it at ours for the run.
        m_dir = re.search(r"(\S+/)changed-paths\.txt", shell)
        check("the boundary step reads changed-paths.txt from one exchange directory", m_dir is not None)
        if not m_dir:
            return
        shell_local = shell.replace(m_dir.group(1), _posix(tmp) + "/")
        script = os.path.join(td, "step.sh")
        with open(script, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(shell_local)
        for path, expect_ok in cases:
            with open(os.path.join(tmp, "changed-paths.txt"), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(path + "\n")
            # ALLOWLIST is set inside the bash command (WSL does not forward
            # arbitrary Windows environment variables).
            r = subprocess.run([bash, "-c",
                                f'cd "{_posix(BASE)}" && ALLOWLIST="{ALLOWLIST_REL}" bash "{_posix(script)}"'],
                               capture_output=True, text=True)
            ok = r.returncode == 0
            check(f"verbatim step {'admits' if expect_ok else 'refuses'} {path}",
                  ok == expect_ok, (r.stdout + r.stderr).strip()[-160:])


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
