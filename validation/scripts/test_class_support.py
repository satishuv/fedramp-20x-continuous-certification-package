# One interpretation of a certification class (class_support.py, AUD-F65).
#
# Finding closed here: thirteen `if cls == "d"` guards with thirteen messages,
# two `not in ("a", "b", "c")` guards, and generic resolvers whose only special
# case was Class B, so "d" and any typo resolved to a plausible full rule / KSI
# set in sdr.submitted_ksi_ids, sdr.submitted_rule_ids and the MAS coverage
# resolver, while an unknown value fell through every `== "d"` guard into
# generic processing. Now: SUPPORTED a/b/c, FUTURE d, INVALID anything else,
# one message, and every entry point that resolves a class stops on it.
#
# Each entry point is driven IN PROCESS with a Class D offering profile and an
# invalid one (the module's offering-path constant is pointed at a temp file, or
# the class override environment variable is set), asserting exit 1, the one
# message, and no exception. The guards sit before any write, so nothing in
# the repository is touched.
#
# Run: python validation/scripts/test_class_support.py

import contextlib
import importlib
import io
import json
import os
import sys
import tempfile

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.join(BASE, "validation", "scripts"))
sys.path.insert(0, os.path.join(BASE, "automation", "sdrscan"))
import class_support as cs  # noqa: E402
import sdr  # noqa: E402

_fail = 0


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def test_state_function():
    S, F, I = cs.ClassState.SUPPORTED, cs.ClassState.FUTURE, cs.ClassState.INVALID
    check("a, b, c are SUPPORTED (any case, stripped)",
          all(cs.certification_class_state(v) is S for v in ("a", "b", "c", "A", " C ", "B\n")))
    check("d is FUTURE (any case)", all(cs.certification_class_state(v) is F for v in ("d", "D", " d")))
    check("anything else is INVALID, never pending D",
          all(cs.certification_class_state(v) is I for v in ("e", "", None, "ab", "zz", "class-b", "1")))
    check("supported classes are exactly a, b, c and future exactly d",
          tuple(cs.SUPPORTED_CLASSES) == ("a", "b", "c") and tuple(cs.FUTURE_CLASSES) == ("d",))


def test_messages_and_require():
    check("a supported class yields no message",
          all(cs.unsupported_class_message(v, "op") is None for v in ("a", "b", "c", "C")))
    m = cs.unsupported_class_message("d", "SDR generation")
    check("the FUTURE message carries the code, the operation and the readiness register path",
          cs.CODE_FUTURE in m and "SDR generation" in m and cs.READINESS_REGISTER in m)
    m = cs.unsupported_class_message("e", "SDR generation")
    check("the INVALID message carries its code and never the FUTURE code",
          cs.CODE_INVALID in m and cs.CODE_FUTURE not in m and "'e'" in m)
    check("require_supported_class returns the normalized letter", cs.require_supported_class(" B ", "op") == "b")
    for value, code in (("d", cs.CODE_FUTURE), ("e", cs.CODE_INVALID), ("", cs.CODE_INVALID)):
        try:
            cs.require_supported_class(value, "op")
            check(f"require_supported_class({value!r}) raises", False)
        except cs.UnsupportedCertificationClass as exc:
            check(f"require_supported_class({value!r}) raises with code {code}",
                  exc.code == code and exc.cls == cs.normalize_class(value) and code in str(exc))
    check("the exception is a ValueError (callers that catch broadly still catch it)",
          issubclass(cs.UnsupportedCertificationClass, ValueError))


def test_generic_resolvers_refuse_unsupported_classes():
    inds = [{"ksi_id": "KSI-X"}, {"ksi_id": "KSI-Y"}]
    rules = [{"rule_id": "R-1"}, {"rule_id": "R-2", "class_a_obligation": "optional"}]
    check("submitted_ksi_ids resolves Class C", sdr.submitted_ksi_ids(inds, "c") == {"KSI-X", "KSI-Y"})
    check("submitted_rule_ids resolves Class A (optional rule excluded)",
          sdr.submitted_rule_ids(rules, "a") == {"R-1"})
    for fn, args in ((sdr.submitted_ksi_ids, (inds,)), (sdr.submitted_rule_ids, (rules,))):
        for value, code in (("d", cs.CODE_FUTURE), ("e", cs.CODE_INVALID)):
            try:
                fn(*args, value)
                check(f"{fn.__name__}({value!r}) raises instead of returning a plausible set", False)
            except cs.UnsupportedCertificationClass as exc:
                check(f"{fn.__name__}({value!r}) raises {code}", exc.code == code)
    import build_mas_coverage as bmc
    ksi_profile = {"indicators": inds}
    check("MAS coverage resolves Class C to all KSIs",
          bmc.applicable_ksis_for_class("c", ksi_profile, {}, {}) == ["KSI-X", "KSI-Y"])
    try:
        bmc.applicable_ksis_for_class("d", ksi_profile, {}, {})
        check("MAS coverage refuses Class D instead of the all-KSIs branch", False)
    except cs.UnsupportedCertificationClass as exc:
        check("MAS coverage refuses Class D instead of the all-KSIs branch", exc.code == cs.CODE_FUTURE)


def _temp_profile(cls):
    real = json.load(open(os.path.join(BASE, "profiles", "common", "offering-profile.json"), encoding="utf-8"))
    real["certification_class"] = cls
    fd, path = tempfile.mkstemp(prefix="offering-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(real, f)
    return path


def _run(fn):
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = fn()
    except BaseException as exc:  # noqa: BLE001 - a traceback IS the failure under test
        return ("EXC", f"{type(exc).__name__}: {exc}", buf.getvalue())
    return (rc, "", buf.getvalue())


# (module, kind, detail): 'const' patches the module attribute holding the
# offering path; 'env' sets the class override variable; 'sdr' drives
# cmd_preflight through sdr.OFFERING_PROFILE.
ENTRY_POINTS = [
    ("build_scg", "const", "PROFILE"),
    ("build_cpo", "const", "PROFILE"),
    ("build_ocr", "const", "PROFILE"),
    ("build_events", "const", "PROFILE"),
    ("build_reports", "const", "OFFERING"),
    ("build_release_manifest", "const", "OFFERING"),
    ("build_applicability_decisions", "const", "OFFERING"),
    ("build_assurance_graph", "const", "PROFILE"),
    ("validate_assurance_graph", "const", "OFFERING"),
    ("validate_package_consistency", "const", "OFFERING"),
    ("sdrscan", "const", "OFFERING"),
    ("build_sdr", "env", "SDR_BUILD_CLASS"),
    ("build_docx", "env", "SDR_BUILD_CLASS"),
    ("validate_sdr", "env", "SDR_VALIDATE_CLASS"),
    ("sdr", "sdr", "OFFERING_PROFILE"),
]


def test_every_entry_point_stops_on_an_unsupported_class():
    for cls, code in (("d", cs.CODE_FUTURE), ("e", cs.CODE_INVALID)):
        path = _temp_profile(cls)
        try:
            for name, kind, detail in ENTRY_POINTS:
                mod = importlib.import_module(name)
                saved = None
                try:
                    if kind in ("const", "sdr"):
                        saved = getattr(mod, detail)
                        setattr(mod, detail, path)
                        if kind == "sdr":
                            import argparse
                            rc, err, text = _run(lambda: mod.cmd_preflight(argparse.Namespace()))
                        elif name == "sdrscan":
                            rc, err, text = _run(lambda: mod.main([]))
                        else:
                            rc, err, text = _run(mod.main)
                    else:
                        saved = os.environ.get(detail)
                        os.environ[detail] = cls
                        rc, err, text = _run(mod.main)
                finally:
                    if kind in ("const", "sdr"):
                        setattr(mod, detail, saved)
                    elif saved is None:
                        os.environ.pop(detail, None)
                    else:
                        os.environ[detail] = saved
                ok = rc == 1 and code in text and cs.CODE_FUTURE not in text.replace(code, "")
                check(f"{name} with class {cls!r}: exit 1, prints {code}, no exception"
                      + (f" [{err}]" if err else "") + ("" if ok else f" [rc={rc!r} out={text[-160:]!r}]"), ok)
        finally:
            os.remove(path)


def test_future_readiness_path_is_separate_and_present():
    reg_path = os.path.join(BASE, cs.READINESS_REGISTER)
    reg = json.load(open(reg_path, encoding="utf-8"))
    rules = reg.get("rules") if isinstance(reg, dict) else reg
    check("the Class D readiness register exists and lists rules",
          isinstance(rules, (list, dict)) and len(rules) > 0)
    src = open(os.path.join(BASE, "validation", "scripts", "build_profiles.py"), encoding="utf-8").read()
    check("the register is produced by the explicit future-readiness path (build_profiles.py), "
          "not a certification resolver", "class-d-future" in src and "submitted_ksi_ids" not in src)


def test_no_scattered_guards_remain():
    """The thirteen `== "d"` guards and two `not in ("a","b","c")` guards are
    gone from the entry points; the D-specific RULE branches at Class C/D
    (`in ("c", "d")`) legitimately remain, they encode dataset values."""
    leftovers = []
    roots = [os.path.join(BASE, "validation", "scripts"), os.path.join(BASE, "automation", "sdrscan"),
             BASE]
    for root in roots:
        for fn in os.listdir(root):
            if not fn.endswith(".py") or fn.startswith("test_"):
                continue
            text = open(os.path.join(root, fn), encoding="utf-8").read()
            if 'if cls == "d":' in text or 'if cls not in ("a", "b", "c"):' in text:
                leftovers.append(fn)
    check(f"no scattered Class D guard remains in an entry point: {leftovers}", leftovers == [])


def main():
    for t in (test_state_function, test_messages_and_require,
              test_generic_resolvers_refuse_unsupported_classes,
              test_every_entry_point_stops_on_an_unsupported_class,
              test_future_readiness_path_is_separate_and_present,
              test_no_scattered_guards_remain):
        print(t.__name__)
        t()
    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: class support ({_fail} failures)")
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
