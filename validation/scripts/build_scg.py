#!/usr/bin/env python3
"""Generate a Secure Configuration Guide (SCG) scaffold.

SCG-CSO-RSC requires providers to supply a Secure Configuration Guide covering
how to securely access, configure, operate and decommission top-level
administrative accounts (and the security implications of admin-only settings);
SCG-CSO-AUP requires USE INSTRUCTIONS explaining how to obtain and use that
guide (it is NOT an acceptable-use policy). FedRAMP does not define a JSON schema
for the
SCG (it is a human-readable guide, referenced from the CPO), so this generates
a Markdown scaffold with the required sections and honest TBD placeholders.

    python validation/scripts/build_scg.py

Output: package/scg/secure-configuration-guide.md
"""

import json
import os
import sys

import profile_contract as _pc  # noqa: E402  (offering_title: honest title while the name is TBD)

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PROFILE = os.path.join(BASE, "profiles", "common", "offering-profile.json")
OUT_MD = os.path.join(BASE, "package", "scg", "secure-configuration-guide.md")

TBD = "TBD: the provider supplies this."


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def val(v):
    return v if v not in (None, "") else TBD


def render(profile):
    L = []
    a = L.append
    a(f"# Secure Configuration Guide: {_pc.offering_title(profile)}")
    a("")
    a("This is a generated scaffold for the FedRAMP 20x Secure Configuration "
      "Guide required by SCG-CSO-RSC, with the use-instructions component "
      "required by SCG-CSO-AUP. Sections marked TBD are filled by the provider. "
      "This document is referenced from the Certification Package Overview and "
      "is not a compliance claim.")
    a("")
    a("## Purpose and scope")
    a("")
    name = profile.get("offering_name")
    name = "the offering" if _pc.is_hollow(name) else str(name)
    a(f"How to securely configure and operate {name}. Scope: {val(profile.get('business_purpose'))}")
    a("")
    a("## Recommendations for secure configuration (SCG-CSO-RSC)")
    a("")
    a("SCG-CSO-RSC requires guidance for securely accessing, configuring, "
      "operating, and decommissioning top-level administrative accounts, plus "
      "the security implications of top-level-admin-only settings.")
    a("")
    a("- How to securely ACCESS top-level administrative accounts: " + TBD)
    a("- How to securely CONFIGURE top-level administrative accounts: " + TBD)
    a("- How to securely OPERATE top-level administrative accounts: " + TBD)
    a("- How to securely DECOMMISSION top-level administrative accounts: " + TBD)
    a("- Security settings available ONLY to top-level administrators, and the "
      "security implications of each: " + TBD)
    a("- Other recommended secure settings customers must apply: " + TBD)
    a("- Default settings and which are secure out of the box: " + TBD)
    a(f"- Infrastructure-as-code baseline, if provided ({val(profile.get('iac_technology'))}): " + TBD)
    a("")
    a("## Customer responsibilities")
    a("")
    a("- Configuration the customer owns versus the provider: " + TBD)
    a("- Identity, access, and key management expectations: " + TBD)
    a("")
    a("## Use instructions (SCG-CSO-AUP)")
    a("")
    a("SCG-CSO-AUP requires instructions that explain how to OBTAIN and USE the "
      "Secure Configuration Guide (this is NOT an acceptable-use policy).")
    a("")
    a("- Where and how to obtain this Secure Configuration Guide: " + TBD)
    a("- Intended audience and how to apply the guidance: " + TBD)
    a("- Any authentication or access-request needed to reach it: " + TBD)
    a("")
    a("## Change and version history")
    a("")
    a("- Guide version and last-updated date: " + TBD)
    a("- How configuration guidance changes are communicated: " + TBD)
    a("")
    a("---")
    a("")
    a("Generated scaffold. Every TBD must be replaced with the provider's real "
      "guidance and reviewed by a qualified human before use. A generated "
      "document is not a compliance determination.")
    return "\n".join(L)


def main():
    profile = load(PROFILE)
    cls = (profile.get("certification_class") or "b").lower()
    if cls == "d":
        print("Class D is FedRAMP pending; no SCG is generated.")
        return 1
    os.makedirs(os.path.dirname(OUT_MD), exist_ok=True)
    with open(OUT_MD, "w", encoding="utf-8", newline="\n") as f:
        f.write(render(profile))
    print(f"SCG written: {os.path.relpath(OUT_MD, BASE)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
