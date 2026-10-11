# Guards the install path against dependency drift (F-08). requirements.txt is
# the single source of truth for runtime dependencies; setup.py's DEPS list and
# its import-presence check, and the Makefile install target, must all reflect
# it. The regression this catches: cryptography (added for offline ECDSA
# evidence verification) was pinned in requirements.txt but omitted from
# `make install` and setup.py, producing an environment that could not verify
# signatures. Run: python validation/scripts/test_install_dependencies.py

import os
import re
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Distribution name -> import module name where they differ.
IMPORT_NAME = {"python-docx": "docx", "PyYAML": "yaml"}


def _requirements_pins():
    """Distribution names pinned in requirements.txt (non-comment, non-blank)."""
    pins = []
    with open(os.path.join(BASE, "requirements.txt"), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name = re.split(r"[=<>!~ ]", line, 1)[0].strip()
            if name:
                pins.append(name)
    return pins


def test_requirements_has_cryptography():
    # The specific F-08 regression: the offline ECDSA verifier needs it.
    assert "cryptography" in _requirements_pins(), \
        "cryptography must stay pinned in requirements.txt for evidence verification"


def test_setup_deps_cover_requirements():
    pins = set(_requirements_pins())
    setup_src = open(os.path.join(BASE, "setup.py"), encoding="utf-8").read()
    # DEPS list (distribution names) must include every requirements pin.
    m = re.search(r"DEPS\s*=\s*\[([^\]]*)\]", setup_src)
    assert m, "could not find DEPS in setup.py"
    deps = set(re.findall(r"[\"']([^\"']+)[\"']", m.group(1)))
    missing = pins - deps
    assert not missing, f"setup.py DEPS is missing requirements pins: {sorted(missing)}"
    # The import-presence check must test every dependency's IMPORT name, so a
    # missing package triggers the install instead of a false 'all present'.
    for name in pins:
        mod = IMPORT_NAME.get(name, name)
        assert re.search(rf"[\"']{re.escape(mod)}[\"']", setup_src), \
            f"setup.py import-presence check omits '{mod}' (for {name})"


def test_make_install_uses_requirements_file():
    makefile = open(os.path.join(BASE, "Makefile"), encoding="utf-8").read()
    m = re.search(r"^install:.*?(?=^\w)", makefile, re.S | re.M)
    assert m, "could not find the install target in the Makefile"
    body = m.group(0)
    assert "-r requirements.txt" in body, \
        "make install must install from requirements.txt (single source of truth), " \
        "not a hardcoded package list that drifts"


def _run_all():
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for t in tests:
        t()
        print(f"PASS: {t.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
