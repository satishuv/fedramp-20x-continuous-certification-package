# Offline test: general code-quality telemetry and dependency-update automation
# exist and are honest about their status (finding F90).
#
# Until AUD-F90 the only static analysis in CI was Bandit (security patterns);
# there was no Ruff, no committed lint configuration and no Dependabot
# schedule. This test asserts the three pieces exist AND that the quality job
# is what it says it is: report-only (continue-on-error on its Ruff steps) and
# NOT a member of release-gate's `needs`, so a later edit that quietly makes a
# 166-finding baseline a hard gate, or quietly drops the job, goes RED. When
# the findings are fixed and the job becomes a gate, flip the expectations
# here in the same change and record the ratchet in pyproject.toml.
#
# Run: python validation/scripts/test_quality_telemetry.py

import os
import re
import sys

import yaml

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VALIDATE = os.path.join(BASE, ".github", "workflows", "validate.yml")
PYPROJECT = os.path.join(BASE, "pyproject.toml")
DEPENDABOT = os.path.join(BASE, ".github", "dependabot.yml")

_fail = 0


def check(name, cond, detail=""):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}" + (f": {detail}" if detail else ""))


def main():
    # 1. Ruff configuration: committed, tool-only, with the lint selection the
    #    baseline was measured under and no packaging tables.
    check("pyproject.toml exists", os.path.exists(PYPROJECT))
    py = open(PYPROJECT, encoding="utf-8").read() if os.path.exists(PYPROJECT) else ""
    check("pyproject.toml carries [tool.ruff] configuration", "[tool.ruff]" in py)
    check("pyproject.toml selects the E, F, I, B, UP families",
          re.search(r'select\s*=\s*\[\s*"E",\s*"F",\s*"I",\s*"B",\s*"UP"\s*\]', py) is not None)
    check("pyproject.toml adds no packaging metadata (the repo runs from a checkout)",
          "[project]" not in py and "[build-system]" not in py)
    check("pyproject.toml records the measured baseline so a ratchet has a number to beat",
          re.search(r"\b\d{2,3} findings\b", py) is not None)

    # 2. The quality job in validate.yml: present, report-only, outside the gate.
    with open(VALIDATE, encoding="utf-8") as fh:
        wf = yaml.safe_load(fh)
    jobs = wf["jobs"]
    check("validate.yml has a quality job", "quality" in jobs)
    q = jobs.get("quality", {})
    steps = q.get("steps", [])
    ruff_steps = [s for s in steps
                  if re.search(r"^\s*ruff (check|format)\b", str(s.get("run", "")), re.M)]
    check("quality job runs ruff check and ruff format --check",
          any("ruff check" in str(s.get("run")) for s in ruff_steps)
          and any("ruff format --check" in str(s.get("run")) for s in ruff_steps))
    check("every ruff step is report-only (continue-on-error: true)",
          ruff_steps and all(s.get("continue-on-error") is True for s in ruff_steps))
    check("ruff steps propagate ruff's exit status through tee (set -o pipefail)",
          ruff_steps and all("pipefail" in str(s.get("run")) for s in ruff_steps))
    check("ruff is installed at an exact pinned version",
          any(re.search(r"ruff==\d+\.\d+\.\d+", str(s.get("run", ""))) for s in steps))
    check("quality job uploads its report as an artifact",
          any("upload-artifact" in str(s.get("uses", "")) for s in steps))
    gate_needs = jobs["release-gate"]["needs"]
    check("quality is NOT a release-gate section while report-only", "quality" not in gate_needs,
          f"release-gate needs: {gate_needs}")
    check("release-gate still requires the five existing sections",
          set(gate_needs) >= {"validate", "audit-gate", "attack-gate", "attack-gate-non-aws",
                              "security-scan"})

    # 3. Dependabot: pip and github-actions, weekly, with the lock-regeneration
    #    note (an input bump without `make lock` never reaches the hashed CI).
    check("dependabot.yml exists", os.path.exists(DEPENDABOT))
    if os.path.exists(DEPENDABOT):
        with open(DEPENDABOT, encoding="utf-8") as fh:
            db = yaml.safe_load(fh)
        eco = {u["package-ecosystem"]: u for u in db.get("updates", [])}
        check("dependabot watches pip", "pip" in eco)
        check("dependabot watches github-actions", "github-actions" in eco)
        check("dependabot schedules are weekly",
              all(u.get("schedule", {}).get("interval") == "weekly" for u in eco.values()))
        text = open(DEPENDABOT, encoding="utf-8").read()
        check("dependabot.yml states that an input bump needs `make lock` before it reaches CI",
              "make lock" in text and "requirements.lock" in text)

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: quality_telemetry ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main())
