# Class C end-to-end sample on a platform other than AWS, and its assessor attack (fictional)

This directory drives a fully-worked, FICTIONAL Class C offering that does not
run on AWS ("Harborlight Civic Cloud", HCC: hosted on Google Cloud, with
on-premises operator hosts scanned against an XCCDF benchmark) to a
submission-preflight-ready package under `production-assurance`, then attacks
that package with the SAME probe list as the AWS Class C sample
(`examples/sample-offering-class-c`) plus this platform's own probes (MCE-12).

Everything here is fictional. No real organization, project, host, assessor or
evidence. A green preflight means the framework's readiness checks are
SATISFIABLE by complete input from a non-AWS platform, NOT that anything is
FedRAMP compliant. Compliance is the accredited assessor's and the program's
determination. Nothing here compares, ranks or evaluates any product; product
names identify the source whose export format a reference mapping reads (see
`THIRD_PARTY_NOTICE.md`).

## What is different from the AWS sample

- Every evidence entry behind every populated KSI comes through the ADAPTER
  PATH a real provider uses. The profile enables three mapping-driven sources
  (`evidence_sources`): the Google Cloud Security Command Center reference
  mapping, the OpenSCAP XCCDF reference mapping, and the provider's own
  collector declared the same way (`example-provider-collector`, one declared
  check per KSI the two posture sources do not bind). `apply_sources` reads
  their exports, attaches each entry to exactly the KSIs its declared
  `(service, check)` pair binds, and the sample hashes and signs every entry.
  Nothing is hand-written; the sample fails, naming the KSIs, if any populated
  KSI ends up without adapter-derived evidence.
- The profile declares NO `aws_partition`, `primary_region` or `dr_region`
  (MCE-16). The provenance gate therefore binds only the three enabled sources
  (AUD-F79): an entry claiming an AWS Config rule is unbound here.
- The signer is a managed key service pinned by its LABEL
  (`expected_evidence_signer.key_reference`, MCE-08), never an ARN, URL or
  GUID; the evidence store is declared as properties (MCE-09).
- The exports are produced in memory from the committed fixtures with today's
  observation times (the fixtures carry fixed dates and the mappings a short
  freshness policy) and written under `generated-exports/` for the length of
  the apply step only. Both commands fail if that folder is still present
  when they finish.

## Run it

```bash
# Build the production-assurance package through the adapter path and run
# package-preflight (expects READY):
python examples/sample-offering-class-c-non-aws/build_non_aws_class_c_sample.py

# Assessor attack: the shared probe list plus this platform's probes; every
# tamper must be BLOCKED by its own gate, the controls must stay READY:
python examples/sample-offering-class-c-non-aws/build_non_aws_class_c_sample.py --attack
```

Both always restore the real inputs (and regenerate all class outputs) in a
finally block, so the repository is never left holding sample content. The
attack is the `attack-non-aws` section of the one release gate
(`audit/release_gate.py`): CI runs it as the `attack-gate-non-aws` job in
parallel with the AWS harness, and the AWS `RELEASE_MODE` build and
`sdr.py release` run it too.

## The probe list

The harness is one function (`attack()` in the AWS sample) parametrized by a
`SamplePlatform`; this sample supplies `NonAwsPlatform`. The shared probes run
here with the same name and the same gate pinned per probe as on AWS
(`validation/scripts/test_attack_harness_probes.py` pins both lists against
`examples/sample-offering-class-c/attack-probes.golden.json`). The AWS
sample's four adapter probes (its Falcon and Wiz sources) do not run here;
this platform adds:

- an ADAPTER fact (the posture scanner's network check, bound to KSI-CNA-RNT)
  re-pointed at KSI-CED-RAT, digest recomputed and re-signed: the
  cryptographic gate stays silent and the provenance gate blocks (AC3)
- a VALID signed entry claiming an AWS Config rule, a source this offering
  does not operate, under the KSI the AWS rules manifest binds it to: blocked
  by the provenance gate (AUD-F79; it reached READY before that fix)
- a populated KSI whose adapter-derived evidence is removed: blocked by the
  validation gate (every populated KSI carries evidence at Class C)
- the same adapter entry under the SECOND KSI its check binds (the storage
  check binds KSI-CNA-MAT and KSI-MLA-EVC): stays READY (positive control)

## What building it found

- AUD-F79: the provenance gate bound every source the repository knows rather
  than the sources the offering operates (fixed before this sample landed).
- AUD-F80: the adapter apply path never supplied an evidence location base,
  so every adapter-derived pointer was a placeholder preflight refuses at
  Class C (fixed before this sample landed).
- AUD-F81: the AUD-F63 pointer check predated the AUD-F77 per-record pointer
  segment, so every entry from a source that reports one record per resource
  was pointer-unbound and production-assurance was unsatisfiable for it. The
  first dry run of this sample showed all 11 posture-scanner entries unbound.
  Fixed in this sample's change; the SOURCE family of
  `test_provenance_mutations.py` now carries a per-record pointer.
