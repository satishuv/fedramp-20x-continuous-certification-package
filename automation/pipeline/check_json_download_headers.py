"""Deployment-hardening ADVISORY check for public certification-JSON headers.

Two sources, kept distinct because they carry different weight:

1. The Consolidated Rules dataset. Since CR26 2026.10.05.01, FRC-CSO-JSN
   (FRR.FRC.data.all.CSO.FRC-CSO-JSN, force MUST) reads, verbatim:

       "... public JSON data MUST be supplied in a manner compatible with
       modern web frameworks, including:"

   with two following_information items, verbatim:

       "Cross-Origin Resource Sharing (CORS) should allow web applications
       running on a different domain to access the public JSON data directly."
       "Proper web application headers should be supplied for public JSON
       data, including at least setting Content-Type to application/json and
       X-Content-Type-Options: nosniff."

   The MUST is "compatible with modern web frameworks"; the two listed items
   are the rule's own "should" expectations of what that includes. They are
   reported here as rule-derived expectations. Whether an offering's public
   JSON endpoint meets FRC-CSO-JSN is a decision for the provider's record and
   the assessor, not this script: it reports header presence, nothing more.

2. FedRAMP Help Center guidance (September 15, 2026) additionally RECOMMENDS
   `Content-Disposition: attachment` for certification-JSON downloads, so the
   JSON is not interpreted as active content. That header is not named by any
   Consolidated Rule; it stays guidance.

Neither source makes a header a submission blocker in this framework: the
package preflight never gates on headers, and this script exits 0 unless the
caller passes --strict. The provider runs it against their OWN hosted public
certification-JSON endpoint (the CDS-CSO-PUB / FRC-CSO-JSN JSON documents).

Usage:
    # Evaluate a headers file (JSON object of header->value); advisory report:
    python automation/pipeline/check_json_download_headers.py --headers-file h.json
    # Or fetch a provider-hosted URL (advisory; requires network + urllib):
    python automation/pipeline/check_json_download_headers.py --url https://trust.example.gov/cert.json

Exit code is 0 unless --strict is passed AND an expected header is absent.
"""

import argparse
import json
import sys

# (header, expected-substring-in-value, human label, source). The value check is
# a case-insensitive substring so "application/json; charset=utf-8" still
# matches, and any non-empty Access-Control-Allow-Origin value counts as CORS
# being configured (the rule asks that other domains can read the public JSON;
# which origins a provider allows is their policy decision).
RULE = "FRC-CSO-JSN following_information (CR26 2026.10.05.01)"
GUIDANCE = "FedRAMP Help Center guidance, 2026-09-15 (not a Consolidated Rule)"
RECOMMENDED_HEADERS = [
    ("content-type", "application/json", "Content-Type: application/json", RULE),
    ("x-content-type-options", "nosniff", "X-Content-Type-Options: nosniff", RULE),
    ("access-control-allow-origin", "", "Access-Control-Allow-Origin: <origins allowed to read the public JSON>", RULE),
    ("content-disposition", "attachment", "Content-Disposition: attachment", GUIDANCE),
]


def evaluate_headers(headers):
    """Evaluate a response's headers against the expected set.

    headers: a mapping of header name -> value (any case). Returns a list of
    {header, label, source, present, value} dicts, one per expected header.
    Pure and offline so it is unit-testable without a network.
    """
    lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    results = []
    for name, want, label, source in RECOMMENDED_HEADERS:
        val = lower.get(name)
        if want:
            present = val is not None and want.lower() in val.lower()
        else:
            present = val is not None and val.strip() != ""
        results.append({"header": name, "label": label, "source": source,
                        "present": present, "value": val})
    return results


def _report(results, strict):
    missing = [r for r in results if not r["present"]]
    for r in results:
        mark = "PASS" if r["present"] else ("FAIL" if strict else "ADVISORY")
        got = f" (got: {r['value']})" if r["value"] is not None else " (header absent)"
        print(f"  {mark} {r['label']}{got}  [{r['source']}]")
    if missing:
        rule_missing = [r for r in missing if r["source"] == RULE]
        print(f"\n{len(missing)} expected header(s) not confirmed"
              + (f", {len(rule_missing)} of them named by FRC-CSO-JSN" if rule_missing else "")
              + ". This script reports presence only; it is advisory and never a "
              "submission blocker. Whether the public JSON endpoint meets FRC-CSO-JSN "
              "is recorded by the provider and assessed by the assessor.")
    else:
        print("\nAll expected public certification-JSON headers present.")
    return 1 if (strict and missing) else 0


def _fetch_headers(url):
    import urllib.parse
    import urllib.request
    # Bandit B310: restrict to http/https so a file:/ or custom scheme cannot be
    # opened (this tool fetches a provider's public certification-JSON URL only).
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(
            f"refusing to fetch a non-http(s) URL (scheme {scheme!r}); this check "
            "evaluates a public certification-JSON download URL only")
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310  # nosec B310 - scheme checked above
        return dict(resp.headers.items())


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--headers-file", help="JSON file: object of header->value")
    src.add_argument("--url", help="fetch this URL and evaluate its headers "
                                   "(advisory; needs network access)")
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero if an expected header is absent "
                         "(off by default: this script reports, it does not decide)")
    args = ap.parse_args(argv)

    print("Public certification-JSON header check (FRC-CSO-JSN following_information, "
          "CR26 2026.10.05.01, plus Help Center guidance 2026-09-15; advisory)")
    print("-" * 68)
    if args.headers_file:
        with open(args.headers_file, encoding="utf-8") as f:
            headers = json.load(f)
    else:
        try:
            headers = _fetch_headers(args.url)
        except Exception as exc:  # noqa: BLE001
            print(f"  Could not fetch {args.url}: {exc}")
            print("  (advisory check could not run; not a blocker)")
            return 0
    return _report(evaluate_headers(headers), args.strict)


if __name__ == "__main__":
    sys.exit(main())
