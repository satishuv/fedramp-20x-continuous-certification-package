#!/usr/bin/env python3
"""The Class C assessor-attack harness's probe list is pinned (MCE-12 AC2).

The harness (examples/sample-offering-class-c/build_class_c_sample.py) is
parametrized by a SamplePlatform so another platform's sample runs the SAME
probe list with the SAME gate pinned per probe. This test pins that list:
every probe's name, whether it must BLOCK or stay READY, and the substring the
probe requires in preflight's output (its gate pin), per platform, against a
committed golden. A probe added, removed, renamed or re-pinned by accident
fails here; a deliberate change regenerates the golden with --write-golden.

The run stubs _preflight_rc (no build, no preflight: a few seconds), fixes the
date and the throwaway signing key, and runs attack() twice: once with every
known pin present in the stubbed output (so block probes pass and their names
print) and once with none (so each pinned probe prints its pin). It never
writes to the repository.

Run:
    python validation/scripts/test_attack_harness_probes.py [--write-golden]
"""

import datetime as dt
import importlib.util
import io
import json
import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AWS_SAMPLE = os.path.join(BASE, "examples", "sample-offering-class-c", "build_class_c_sample.py")
GOLDEN = os.path.join(BASE, "examples", "sample-offering-class-c", "attack-probes.golden.json")

# Every pin any probe uses; a new pin must be added here so the "all pins
# present" run still passes every block probe (the test says so when not).
KNOWN_PINS = [
    "AUD-F73", "AUD-F74",
    "not PROVENANCE-BOUND (1 source (e.g.",
    "not PROVENANCE-BOUND (1 pointer (e.g.",
    "backed only by EXPIRED evidence",
    "the validation gate does not pass",
]

PLATFORMS = {
    # name -> (module path, attribute holding the platform factory or None for the default)
    "aws": (AWS_SAMPLE, None),
    "non-aws": (os.path.join(BASE, "examples", "sample-offering-class-c-non-aws",
                             "build_non_aws_class_c_sample.py"), "NonAwsPlatform"),
}

failures = []


def check(name, cond):
    print(("PASS: " if cond else "FAIL: ") + name)
    if not cond:
        failures.append(name)


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _parse(lines):
    out = []
    for ln in lines:
        expect = None
        if ln.startswith("  PASS (blocked) "):
            kind, name = "block", ln[len("  PASS (blocked) "):]
        elif ln.startswith("  PASS (ready, not over-blocked) "):
            kind, name = "ready", ln[len("  PASS (ready, not over-blocked) "):]
        elif ln.startswith("  PASS (ready) "):
            kind, name = "ready", ln[len("  PASS (ready) "):]
        elif ln.startswith("  FAIL (justified content wrongly BLOCKED) "):
            kind, name = "ready", ln[len("  FAIL (justified content wrongly BLOCKED) "):]
        elif ln.startswith("  FAIL (reached READY despite tamper) "):
            kind, name = "block", ln[len("  FAIL (reached READY despite tamper) "):]
        elif ln.startswith("  FAIL (blocked, but not by the expected gate "):
            m = re.match(r"  FAIL \(blocked, but not by the expected gate ('[^']*'|\"[^\"]*\")\) (.*)$", ln)
            kind, name, expect = "block", m.group(2), m.group(1)[1:-1]
        elif ln.startswith("  FAIL baseline"):
            kind, name = "ready", ln[len("  FAIL "):]
        else:
            raise AssertionError(f"unrecognised harness line: {ln!r}")
        out.append({"name": name, "kind": kind, "expect": expect})
    return out


def probe_list(platform_name):
    """[(name, kind, expect)] for the platform's attack(), without building."""
    path, attr = PLATFORMS[platform_name]
    aws = _load(AWS_SAMPLE, "build_class_c_sample")
    aws.TODAY = dt.date(2026, 10, 15)
    from cryptography.hazmat.primitives.asymmetric import ec
    fixed = ec.generate_private_key(ec.SECP256R1())
    real_gen = ec.generate_private_key
    ec.generate_private_key = lambda *a, **k: fixed
    platform = None
    if attr is not None:
        mod = _load(path, "sample_platform_" + platform_name)
        mod.TODAY = aws.TODAY
        platform = getattr(mod, attr)()
    mode = {"pins": True}

    def stub(store, profile, history, post_sign=None, signoff=None):
        return (1, " | ".join(KNOWN_PINS) if mode["pins"] else "")

    real_pf = aws._preflight_rc
    aws._preflight_rc = stub
    try:
        runs = []
        for pins in (True, False):
            mode["pins"] = pins
            buf = io.StringIO()
            real_out = sys.stdout
            sys.stdout = buf
            try:
                aws.attack(platform)
            finally:
                sys.stdout = real_out
            runs.append(_parse([ln for ln in buf.getvalue().splitlines()
                                if ln.startswith("  PASS") or ln.startswith("  FAIL")]))
    finally:
        aws._preflight_rc = real_pf
        ec.generate_private_key = real_gen
    with_pins, without = runs
    assert [p["name"] for p in with_pins] == [p["name"] for p in without]
    out = []
    for a, b in zip(with_pins, without):
        unknown_pin = (a["kind"] == "block" and a["expect"] is not None)
        if unknown_pin:
            raise AssertionError(f"probe {a['name']!r} pins {a['expect']!r}, which KNOWN_PINS lacks; add it")
        out.append({"name": a["name"], "kind": a["kind"], "expect": b["expect"]})
    return out


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    actual = {name: probe_list(name) for name in sorted(PLATFORMS)}
    if "--write-golden" in argv:
        with open(GOLDEN, "w", encoding="utf-8", newline="\n") as f:
            json.dump({"note": "Pinned probe list of the Class C assessor-attack harness per sample platform: "
                               "name, kind (block or ready) and the gate pin each probe requires. Regenerate "
                               "deliberately with test_attack_harness_probes.py --write-golden when a probe is "
                               "added or re-pinned; never a compliance statement.",
                       "platforms": actual}, f, indent=1)
            f.write("\n")
        print(f"golden written: {GOLDEN}")
        return 0
    with open(GOLDEN, encoding="utf-8") as f:
        golden = json.load(f)["platforms"]
    for name in sorted(PLATFORMS):
        got, want = actual[name], golden.get(name)
        check(f"{name}: a golden probe list exists", want is not None)
        if want is None:
            continue
        first = next((i for i, (g, w) in enumerate(zip(got, want)) if g != w), None)
        if got != want:
            i = first if first is not None else min(len(got), len(want))
            print(f"  first difference at {i}: got {got[i] if i < len(got) else None} "
                  f"want {want[i] if i < len(want) else None}")
        check(f"{name}: the probe list equals the golden ({len(want)} probes)", got == want)
        check(f"{name}: every ready probe is the baseline or a positive control, and there are at least 4",
              sum(1 for p in got if p["kind"] == "ready") >= 4
              and all("READY" in p["name"] or p["name"].startswith("baseline") for p in got if p["kind"] == "ready"))
        check(f"{name}: every provenance probe (AUD-F62/F63/F64, MCE-03, AUD-F79) is pinned to its own gate",
              all(p["expect"] for p in got if p["kind"] == "block"
                  and any(t in p["name"] for t in ("AUD-F62", "AUD-F63", "AUD-F64", "MCE-03", "AUD-F79"))))
    check("the AWS list carries the four adapter probes (Falcon pair, undeclared check, control, disabled Wiz)",
          sum(1 for p in actual["aws"] if "adapter" in p["name"].lower()) == 4)
    # MCE-12 AC2: every shared probe runs on the non-AWS platform with the same
    # name, kind and gate pin; the only AWS-only probes are the four adapter
    # probes, and the non-AWS list adds its own (AC3, AUD-F79, linkage, control).
    aws_shared = [p for p in actual["aws"] if "adapter" not in p["name"].lower()]
    non_aws = actual.get("non-aws", [])
    non_aws_shared = non_aws[:len(aws_shared)]
    check("non-aws: every shared probe is present, in order, with the same kind and gate pin (AC2)",
          non_aws_shared == aws_shared)
    extra = non_aws[len(aws_shared):]
    check("non-aws: the platform adds its own probes after the shared list (AC3, AUD-F79, linkage, control)",
          len(extra) == 4 and any("MCE-12 AC3" in p["name"] for p in extra)
          and any("AUD-F79" in p["name"] for p in extra)
          and sum(1 for p in extra if p["kind"] == "ready") == 1)
    if failures:
        print(f"\nFAIL: attack harness probes ({len(failures)} failure(s))")
        return 1
    print("\nPASS: attack harness probes (0 failures)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
