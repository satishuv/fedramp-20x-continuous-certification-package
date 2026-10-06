"""Unreviewed-proposal text: one definition, every consumer.

The framework writes three kinds of text into narrative fields that a human has
NOT confirmed as the provider's fact:

  "Example (reference architecture, ...): ..."   curated template examples
  "Example: ..."                                  short template example values
  "DRAFT (AI-assisted, unverified ...): ..."      proposals from draft_narratives.py

Until this module existed, none of them was a placeholder to the readiness
predicates: ``sdr.py`` preflight ``_answered``, ``validate_sdr.py``'s populated
checks and the scanner's ``state()`` all treated them as a real answer (AUD-F38).
A package whose 168 rule narratives were all machine drafts could therefore
read as fully populated without a human ever confirming one sentence.

The rule is simple: a value that STARTS WITH one of these labels is a proposal,
and a proposal is unanswered until a named human accepts it through
``sdr.py review``, which strips the label and records the acceptance.
Everything that decides "answered" imports this module; nothing re-implements
the list.
"""

UNREVIEWED_PREFIXES = (
    "DRAFT (",      # draft_narratives.py output
    "Example (",    # curated reference-architecture examples in the template
    "Example:",     # short template example values (owner, cadence, ...)
)


def is_unreviewed(value):
    """True when ``value`` (a string, or a list whose every string member is a
    proposal) is an unreviewed proposal. Non-strings are never proposals."""
    if isinstance(value, (list, tuple)):
        strings = [v for v in value if isinstance(v, str)]
        return bool(strings) and all(is_unreviewed(v) for v in strings)
    if not isinstance(value, str):
        return False
    return value.strip().startswith(UNREVIEWED_PREFIXES)


def strip_label(value):
    """Return the proposal text without its label, i.e. what a human ACCEPTS.

    ``"DRAFT (AI-assisted, unverified -- review before use): The inbox ..."``
    becomes ``"The inbox ..."``; ``"Example: Security Operations Manager"``
    becomes ``"Security Operations Manager"``. A value that carries no label is
    returned unchanged, so accepting hand-written text is a no-op.
    """
    if not isinstance(value, str):
        return value
    s = value.strip()
    if s.startswith("Example:"):
        return s[len("Example:"):].strip()
    for prefix in ("DRAFT (", "Example ("):
        if s.startswith(prefix):
            close = s.find("):", len(prefix))
            if close != -1:
                return s[close + 2:].strip()
            return s[len(prefix):].strip()
    return s
