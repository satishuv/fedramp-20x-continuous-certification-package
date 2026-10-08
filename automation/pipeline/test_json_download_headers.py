# Offline tests for the public certification-JSON header advisory check.
#
# Three of the four expected headers are named by FRC-CSO-JSN's
# following_information since CR26 2026.10.05.01 (CORS; Content-Type
# application/json; X-Content-Type-Options nosniff); Content-Disposition is
# Help Center guidance only. The evaluator REPORTS presence; gating is the
# caller's --strict choice. These tests exercise the pure evaluator with no
# network.
#
# Run: python automation/pipeline/test_json_download_headers.py

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from check_json_download_headers import GUIDANCE, RULE, evaluate_headers, main  # noqa: E402

_fail = 0


def check(name, cond):
    global _fail
    if cond:
        print(f"  PASS {name}")
    else:
        _fail += 1
        print(f"  FAIL {name}")


def _by(results):
    return {r["header"]: r["present"] for r in results}


FULL = {"Content-Type": "application/json; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "Access-Control-Allow-Origin": "*",
        "Content-Disposition": "attachment; filename=cert.json"}


def main_test():
    # All four present (with a charset on content-type) -> all present.
    r = _by(evaluate_headers(FULL))
    check("all four expected headers detected", all(r.values()) and len(r) == 4)

    # Case-insensitive header names.
    r = _by(evaluate_headers({k.lower(): v for k, v in FULL.items()}))
    check("lowercase header names detected", all(r.values()))

    # Wrong content-type -> not present.
    r = _by(evaluate_headers(dict(FULL, **{"Content-Type": "text/html"})))
    check("text/html content-type is not a match", r["content-type"] is False)

    # nosniff missing -> not present.
    r = _by(evaluate_headers({"Content-Type": "application/json"}))
    check("absent nosniff reported not present", r["x-content-type-options"] is False)
    check("absent content-disposition reported not present", r["content-disposition"] is False)
    check("absent CORS header reported not present", r["access-control-allow-origin"] is False)

    # CORS: any non-empty allowed origin counts (which origins is the provider's
    # policy); an empty value does not.
    r = _by(evaluate_headers({"Access-Control-Allow-Origin": "https://agency.example.gov"}))
    check("specific allowed origin counts as CORS configured", r["access-control-allow-origin"] is True)
    r = _by(evaluate_headers({"Access-Control-Allow-Origin": "  "}))
    check("blank CORS value is not configured", r["access-control-allow-origin"] is False)

    # Each header names its source: the rule for the three FRC-CSO-JSN items,
    # guidance for Content-Disposition.
    src = {x["header"]: x["source"] for x in evaluate_headers(FULL)}
    check("CORS, content-type and nosniff cite FRC-CSO-JSN",
          all(src[h] == RULE for h in ("access-control-allow-origin", "content-type",
                                       "x-content-type-options")))
    check("content-disposition cites guidance, not a rule", src["content-disposition"] == GUIDANCE)
    check("the rule citation names the dataset release that introduced the text",
          "FRC-CSO-JSN" in RULE and "2026.10.05.01" in RULE)

    # Empty / None input is safe and reports all absent.
    r = _by(evaluate_headers({}))
    check("empty headers -> all absent", not any(r.values()))
    r = _by(evaluate_headers(None))
    check("None headers -> all absent", not any(r.values()))

    # main() with a headers file: default (non-strict) exits 0 even when absent;
    # --strict exits non-zero when a header is absent.
    import json
    import tempfile
    d = tempfile.mkdtemp(prefix="hdr-")
    p = os.path.join(d, "h.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"Content-Type": "text/plain"}, f)
    check("main() non-strict exits 0 on missing headers (advisory)",
          main(["--headers-file", p]) == 0)
    check("main() --strict exits non-zero on missing headers",
          main(["--headers-file", p, "--strict"]) != 0)
    # Full set: strict still exits 0.
    with open(p, "w", encoding="utf-8") as f:
        json.dump(FULL, f)
    check("main() --strict exits 0 when all present",
          main(["--headers-file", p, "--strict"]) == 0)
    # The three rule-named headers alone: strict still fails on the guidance one,
    # and the report says how many of the missing are named by the rule (none).
    with open(p, "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in FULL.items() if k != "Content-Disposition"}, f)
    check("main() --strict exits non-zero when only the guidance header is absent",
          main(["--headers-file", p, "--strict"]) != 0)

    print(f"\n{'PASS' if _fail == 0 else 'FAIL'}: json download headers ({_fail} failures)")
    return 1 if _fail else 0


if __name__ == "__main__":
    sys.exit(main_test())
