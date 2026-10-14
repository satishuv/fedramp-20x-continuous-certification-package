"""The ONE interpretation of a certification class (AUD-F65).

Before this module, "which classes does the package support" was answered by
string comparisons scattered across fifteen entry points: thirteen `if cls ==
"d"` guards with thirteen different messages, two `if cls not in ("a", "b",
"c")` guards, and generic resolvers (`sdr.submitted_ksi_ids`,
`sdr.submitted_rule_ids`) whose only special case was Class B, so for "d" and
for any typo they returned a plausible full set. The top-level builders refused
Class D correctly; the helpers underneath them did not know D existed, and an
unknown value like "e" fell through every `== "d"` guard into generic
processing (a missing class-e profile, a traceback, or a document labelled
"Class E").

Three states, one function:

    SUPPORTED   a, b, c   the package can be built, validated, preflighted,
                          reviewed and released for this class.
    FUTURE      d         FedRAMP pending (20x Phase 4 pilot; the full proposed
                          Class D requirements are being published through the
                          pilot). The pinned CR26 dataset already carries SOME
                          Class D values (for example FRC-CSX-VVK's four
                          automated methods per KSI), which is why generic
                          helpers could resolve "d" to something. Data existing
                          is not support: no Class D package is built, and the
                          Class D readiness register
                          (profiles/class-d-future/readiness-register.json) is
                          produced by its own explicit future-readiness path
                          (build_profiles.py), never by a certification resolver.
    INVALID     anything else, including the empty string. Never treated as
                          pending D.

Every entry point that resolves a class calls `unsupported_class_message` (for
scripts that print one line and return 1) or `require_supported_class` (for
library helpers that must not return a plausible answer for an unsupported
class). Callers that apply the template default for a MISSING value ("b") keep
doing so BEFORE calling here; this module interprets the value it is given.
"""

from enum import Enum

SUPPORTED_CLASSES = ("a", "b", "c")
FUTURE_CLASSES = ("d",)

CODE_FUTURE = "CLASS_D_NOT_SUPPORTED_YET"
CODE_INVALID = "INVALID_CERTIFICATION_CLASS"

READINESS_REGISTER = "profiles/class-d-future/readiness-register.json"


class ClassState(str, Enum):
    SUPPORTED = "supported"
    FUTURE = "future"
    INVALID = "invalid"


class UnsupportedCertificationClass(ValueError):
    """Raised by require_supported_class. `code` is CODE_FUTURE or CODE_INVALID
    and `cls` the normalized value, so a caller can report without parsing."""

    def __init__(self, code, cls, message):
        super().__init__(message)
        self.code = code
        self.cls = cls


def normalize_class(value):
    """Lower-cased, stripped class letter ("" for None)."""
    return str(value or "").strip().lower()


def certification_class_state(value):
    """Pure. The state of a certification class value."""
    cls = normalize_class(value)
    if cls in SUPPORTED_CLASSES:
        return ClassState.SUPPORTED
    if cls in FUTURE_CLASSES:
        return ClassState.FUTURE
    return ClassState.INVALID


def unsupported_class_message(value, operation):
    """None when the class is SUPPORTED; otherwise the one-line message an
    entry point prints before returning 1. `operation` names what was asked
    for ("SDR generation", "package-preflight", ...)."""
    cls = normalize_class(value)
    state = certification_class_state(cls)
    if state is ClassState.SUPPORTED:
        return None
    if state is ClassState.FUTURE:
        return (f"{CODE_FUTURE}: {operation} cannot resolve Class D. Class D is "
                "FedRAMP pending (20x Phase 4 pilot); the dataset carries some Class D "
                "values but no Class D package is built, validated or released until the "
                f"pilot requirements are adopted. See {READINESS_REGISTER} for the "
                "future-readiness register, which has its own explicit path.")
    return (f"{CODE_INVALID}: {value!r} is not a certification class ({operation}). "
            "Supported: A, B, C. Pending: D. Set certification_class in "
            "profiles/common/offering-profile.json (sdr.py init asks for it).")


def require_supported_class(value, operation):
    """Return the normalized class letter, or raise UnsupportedCertificationClass.
    For library helpers that would otherwise return a plausible answer for a
    class the package does not support."""
    msg = unsupported_class_message(value, operation)
    if msg is None:
        return normalize_class(value)
    code = CODE_FUTURE if certification_class_state(value) is ClassState.FUTURE else CODE_INVALID
    raise UnsupportedCertificationClass(code, normalize_class(value), msg)
