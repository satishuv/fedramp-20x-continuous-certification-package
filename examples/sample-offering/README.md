# Worked sample offering: Acme Cloud Widgets (fictional)

This is an illustrative, fully-fictional example so a reviewer can see a
populated Security Decision Record and a passing build gate instead of a
template full of `TBD` markers. Nothing here is a real offering, a real
attestation, or evidence of compliance.

## What this demonstrates

- A record store with every indicator's `implementation` and `validation`
  narrative filled with sample prose (clearly labelled `[SAMPLE - fictional]`).
- A completed offering profile (fictional Acme identity, Class B).
- A build that passes the gate: `Build gate BUILD PASS - structurally valid, hard failures: 0`.

## What it deliberately does NOT do

The sample fills narrative prose only. It does not fabricate an
`implementation_status`, an `assessment`, `tests`, or `evidence`, because those
are exactly the fields the framework's trust boundary reserves for a human
judgment, an accredited assessor, and deterministic telemetry. As a result the
readiness scanner honestly reports the sample as incomplete (findings remain), and
that is correct: a populated narrative is not a finished, assessed record.

## How to build it

`sdr.py` reads fixed input paths, so the builder swaps the sample inputs in,
runs the gate, and restores the real inputs afterward (even on failure):

```bash
python examples/sample-offering/build_sample.py
```

It writes `records-store.sample.json` and `offering-profile.sample.json` here,
runs `python sdr.py all`, prints the gate result, and restores
`sdr/records/records-store.json` and `profiles/common/offering-profile.json`.
Your real record store is never left modified.

To also write the rendered output package to `generated/` (so a reviewer can
read a populated SDR without running anything):

```bash
python examples/sample-offering/build_sample.py --emit
```

## Files

- `build_sample.py`: generates the sample inputs, runs the gate, restores originals.
- `records-store.sample.json`: the generated filled record store (fictional).
- `offering-profile.sample.json`: the generated filled profile (fictional).
- `generated/`: the rendered sample package (SDR JSON and text, CPO, OCR, SCG, event artifacts), committed so a reviewer can read a populated example directly.
