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

import os
import sys

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


if __name__ == "__main__":
    sys.exit(main())
