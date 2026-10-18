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
    # F-08 as it stands after AUD-F87: setup.py keeps NO list of dependencies
    # of its own. It reads requirements.txt through requirement_pins(), so a
    # pin added there (cryptography was the original miss) is checked and
    # installed with no second edit. Assert the hand list is gone and the
    # reader returns exactly the requirements.txt pins.
    setup_src = open(os.path.join(BASE, "setup.py"), encoding="utf-8").read()
    assert not re.search(r"^DEPS\s*=", setup_src, re.M), \
        "setup.py must not keep its own DEPS list; requirements.txt is the source of truth"
    sys.path.insert(0, BASE)
    import setup as onboarding  # noqa: E402
    pins = onboarding.requirement_pins()
    assert set(pins) == set(_requirements_pins()), \
        f"requirement_pins() must return every requirements.txt pin: {sorted(pins)}"
    for name, version in pins.items():
        assert re.fullmatch(r"[0-9][0-9A-Za-z.]*", version), \
            f"{name} must be pinned to an exact version, got {version!r}"


def test_make_install_uses_requirements_file():
    makefile = open(os.path.join(BASE, "Makefile"), encoding="utf-8").read()
    m = re.search(r"^install:.*?(?=^\w)", makefile, re.S | re.M)
    assert m, "could not find the install target in the Makefile"
    body = m.group(0)
    assert "-r requirements.txt" in body, \
        "make install must install from requirements.txt (single source of truth), " \
        "not a hardcoded package list that drifts"


def _requirements_versions():
    """Distribution name -> exact pinned version from requirements.txt."""
    pins = {}
    with open(os.path.join(BASE, "requirements.txt"), encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, _, version = line.partition("==")
            if name and version:
                pins[name.strip()] = version.strip()
    return pins


def test_setup_checks_installed_versions_against_pins():
    # AUD-F87: an importable module is not the pinned module. setup.py used to
    # answer "all present" from __import__ alone, so an environment holding
    # jsonschema 4.17 (or any version) was accepted as the 4.26.0 the gate was
    # built against, and the install step never ran. It must read each
    # installed distribution's version and compare it to the requirements.txt
    # pin, reinstalling from the pinned file on any mismatch.
    sys.path.insert(0, BASE)
    import setup as onboarding  # noqa: E402
    pins = _requirements_versions()
    assert pins, "requirements.txt must carry exact == pins"
    # The checker exists and derives its expectations from requirements.txt,
    # never from a second hand-maintained list.
    assert hasattr(onboarding, "dependency_mismatches"), \
        "setup.py must expose dependency_mismatches() (installed vs pinned)"
    # Inject a fake 'installed version' oracle: one pin satisfied, one wrong,
    # one absent. The function must report exactly the wrong and absent ones.
    names = list(pins)
    fake = {names[0]: pins[names[0]], names[1]: "0.0.1"}

    def oracle(dist):
        if dist in fake:
            return fake[dist]
        raise onboarding.DistributionMissing(dist)

    mism = onboarding.dependency_mismatches(pins, installed_version=oracle)
    assert names[0] not in mism, "a distribution at its pinned version is not a mismatch"
    assert mism.get(names[1]) == ("0.0.1", pins[names[1]]), \
        "a wrong installed version must be reported as (installed, pinned)"
    for absent in names[2:]:
        assert mism.get(absent) == (None, pins[absent]), \
            f"an absent distribution must be reported as (None, pinned): {absent}"
    # And the real oracle reads importlib.metadata, so the check is about the
    # distribution on disk, not an import that any version would satisfy.
    src = open(os.path.join(BASE, "setup.py"), encoding="utf-8").read()
    assert "importlib.metadata" in src or "importlib_metadata" in src, \
        "setup.py must read installed versions through importlib.metadata"


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
