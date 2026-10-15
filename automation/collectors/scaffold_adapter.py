#!/usr/bin/env python3
"""Adapter SDK: scaffold a new evidence adapter.

An adapter is how a third-party evidence source (a CSPM, a scanner, a config
service) feeds facts into the package. This prints a ready-to-fill adapter
subclass implementing the v2 contract (describe/health/collect), so a
contributor starts from a correct shape instead of a blank file. It writes
nothing by default; pass --write PATH to save the stub.

    python automation/collectors/scaffold_adapter.py Falcon crowdstrike
    python automation/collectors/scaffold_adapter.py Wiz wiz --write automation/collectors/wiz_adapter.py

Boundary reminder baked into the stub: an adapter GATHERS facts. It never
decides PASS/FAIL, never sets a status, never authors an approval.
"""

import argparse
import os
import sys

TEMPLATE = '''"""Evidence adapter for {display} ({source_type}).

Gathers facts from {display} and returns collector-shaped dicts. It does not
evaluate, score, or set any status. A validator evaluates; a human assesses.
"""

from evidence_wiring import EvidenceAdapter, register_adapter


class {cls}Adapter(EvidenceAdapter):
    name = "{name}"
    version = "1.0.0"
    service = "{source_type}"
    source_type = "{source_type}"
    supported_evidence_types = ["Report"]
    freshness_policy_days = 1
    # Declare the exact `check` values collect() can yield and the KSI ids they
    # are evidence toward (verify each against profiles/common/ksi-profile.json).
    # Every (service, check) pair is bound to every target in the source
    # registry the provenance gate reads; an undeclared check is refused.
    checks = ("example-check",)
    KSI_TARGETS = []  # e.g. ["KSI-MLA-OSM"]

    def ksi_targets(self):
        return list(self.KSI_TARGETS)

    def collect(self, raw):
        """Map the source payload `raw` to collector-shaped facts.

        Each yielded dict MUST have: service, check, status, detail, region,
        observed_at (the published fact contract, fact-contract.schema.json).
        `status` is the source's own observation string, not a compliance
        verdict. Do not invent an observed_at; carry the source's real
        timestamp so freshness is honest. `check` must be one of `checks`.
        """
        for item in raw.get("findings", []):
            yield {{
                "service": self.service,
                "check": item.get("id", "unknown"),
                "status": item.get("state", "unknown"),
                "detail": item.get("title", ""),
                "region": item.get("region", "global"),
                "observed_at": item.get("observed_at"),
            }}

    def health(self):
        """Override with the real last-collection outcome so a failed pull is
        never read as a clean posture."""
        return super().health()


register_adapter({cls}Adapter())
'''


def scaffold(display, source_type, name=None):
    cls = "".join(w.capitalize() for w in display.replace("-", " ").split())
    name = name or source_type
    return TEMPLATE.format(display=display, cls=cls, name=name, source_type=source_type)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("display", help="human name, e.g. Falcon")
    ap.add_argument("source_type", help="source slug, e.g. crowdstrike")
    ap.add_argument("--name", help="adapter registry name (defaults to source_type)")
    ap.add_argument("--write", help="path to write the stub to")
    args = ap.parse_args(argv)

    code = scaffold(args.display, args.source_type, args.name)
    if args.write:
        if os.path.exists(args.write):
            print(f"Refusing to overwrite existing file: {args.write}")
            return 1
        with open(args.write, "w", encoding="utf-8", newline="\n") as f:
            f.write(code)
        print(f"Wrote adapter stub: {args.write}")
    else:
        print(code)
    return 0


if __name__ == "__main__":
    sys.exit(main())
