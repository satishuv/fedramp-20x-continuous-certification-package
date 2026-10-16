# Quickstart: a provider on a platform other than AWS

Goal: take an export your tooling already produces, turn it into hashed, signed
evidence behind the right indicators, and reach Submission ready at Class C,
without an AWS account and without a credential anywhere in this repository.
Budget fifteen minutes. Every command below runs offline against committed
fixtures; the fictional non-AWS sample performs the whole sequence end to end.

What you get at each step is an EXPECTATION or a READINESS FINDING, never a
compliance determination: the framework states what the package expects and
whether the generated package meets its own gates. Whether an indicator is met
is the accredited assessor's and the program's determination.

Product names below identify the source whose export format a reference
mapping reads; nothing here compares, ranks or recommends any product (see
`THIRD_PARTY_NOTICE.md`).

## 0. The shape of the path

```text
export (JSON, JSON lines, CSV, XCCDF)  ->  mapping (one JSON file)  ->  facts (the one contract)
   ->  evidence (hashed, bound pointer)  ->  signature (your signer, pinned by label)
   ->  package-preflight READY (every populated KSI backed by bound, verified, fresh evidence)
```

Three sources are declared in the sample: a cloud posture findings export
(the Security Command Center reference mapping), an on-premises benchmark
scan (the OpenSCAP XCCDF reference mapping), and your own collector, declared
the same way (`example-provider-collector`). The provenance gate holds all
three to one rule: an entry's `service:check` is a source your profile
enables, bound to the KSI it sits under, or it is unbound.

## 1. Export: facts from a file your tooling already writes

A mapping names where in the export the check id, the state, the observation
time and the location live, how the source's state words normalize to `PASS`,
`FAIL` or `UNKNOWN`, and which KSIs each declared check is evidence toward.
Dry-run a mapping against its export; nothing is written:

```bash
python automation/collectors/mapping_adapter.py automation/collectors/fixtures/mapping/example-google-cloud-scc.mapping.json automation/collectors/fixtures/mapping/example-google-cloud-scc.export.json
python automation/collectors/mapping_adapter.py automation/collectors/fixtures/mapping/example-openscap-xccdf.mapping.json automation/collectors/fixtures/mapping/example-openscap-xccdf.results.xml
python automation/collectors/mapping_adapter.py automation/collectors/fixtures/mapping/example-provider-collector.mapping.json automation/collectors/fixtures/mapping/example-provider-collector.export.jsonl
```

Each prints the adapter's description (declared checks, their KSI bindings,
the undeclared-check policy), the collection outcome, and the facts in the
one contract (`automation/collectors/fact-contract.schema.json`): `service`,
`check`, `status`, `detail`, `region`, `observed_at`, and the raw platform
identifiers (a project, tenant, compartment or host) only as input fields
that become opaque scopes before export. A state the table does not name is
`UNKNOWN`, never `PASS`; an empty export is a collection that did not run.

To write your own mapping, copy the closest reference mapping and change the
paths, the state table and the `checks` with their `check_bindings`. Then
prove it against its own export the way the conformance suite does for every
mapping in the repository:

```bash
python automation/collectors/test_adapter_conformance.py
```

## 2. Mapping: declare the sources your offering operates

In `profiles/common/offering-profile.json`, enable each source with its
mapping and export path (the key must equal the mapping's `name`), declare
no AWS platform (leave `aws_partition`, `primary_region` and `dr_region`
out), select the platform whose how-to-comply notes your package should carry
(`"guidance_platform": "Google Cloud"`; `Microsoft Azure` and
`Oracle Cloud Infrastructure` also ship, see `guidance/platforms/README.md`),
and state the evidence store as properties:

```json
"evidence_sources": {
  "example-google-cloud-scc": {
    "enabled": true,
    "mapping_path": "automation/collectors/fixtures/mapping/example-google-cloud-scc.mapping.json",
    "export_path": "exports/scc-findings.json"
  },
  "example-openscap-xccdf": {
    "enabled": true,
    "mapping_path": "automation/collectors/fixtures/mapping/example-openscap-xccdf.mapping.json",
    "export_path": "exports/benchmark-results.xml"
  },
  "example-provider-collector": {
    "enabled": true,
    "mapping_path": "automation/collectors/fixtures/mapping/example-provider-collector.mapping.json",
    "export_path": "exports/provider-collector.jsonl"
  }
},
"evidence_store": {
  "versioned": true, "write_once": true, "separately_administered": true,
  "retention_days": 400, "access_logging": true,
  "implementation": "your write-once, versioned, separately administered store"
}
```

A source your profile does not enable binds nothing, and so does every AWS
source when no AWS platform is declared (AUD-F79): evidence claiming a tool
you say you do not use is unbound.

## 3. Facts to evidence: apply the sources

The apply driver reads each enabled source's export, runs its mapping, checks
every fact against the contract, converts each to an evidence entry with a
recomputable digest and a pointer under your evidence store, and attaches it
to exactly the KSIs its declared `(service, check)` pair binds. Set the store
base and, when an export carries raw scope identifiers, a deployment-private
scope key:

```text
SDR_EVIDENCE_LOCATION_BASE=https://evidence.example.invalid/store
SDR_EVIDENCE_SCOPE_KEY=<a secret private to your deployment, never in the repository>
python automation/collectors/apply_third_party_evidence.py
```

Without the base the pointers are `sdr://placeholder/` pseudo-URIs that
preflight refuses at Class C, and the driver says so (AUD-F80). Without the
scope key a fact carrying a raw project or host identifier is refused, never
exported raw. On a fresh clone, where no source is enabled yet, the driver
prints that there is nothing to do; the sample in step 5 runs it with all
three sources enabled.

## 4. Signature: your signer, pinned by label

Under `production-assurance` every entry's digest must be signed by a signer
the package pins independently. The signer is pluggable
(`automation/collectors/signers.py`): a managed key service reached through a
command that receives ONLY the content hash on stdin and prints the base64
DER ECDSA P-256 signature, or a software key for development only (a blocker
under `production-assurance`, because the pipeline that runs it holds the
key). Pin the public key and the key's LABEL in the profile; an ARN, URL,
GUID or account id is refused as a reference:

```json
"evidence_store_profile": "production-assurance",
"expected_evidence_signer": {
  "key_reference": "your-evidence-signer-2026",
  "public_key_pem": "-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----",
  "signer_kind": "managed-key-service"
}
```

Signing is a Python call your signing step makes, not something the
collectors can do (they must not hold the key):

```python
from signers import ExternalCommandSigner, sign_entry
signer = ExternalCommandSigner(["your-signing-command"], "your-evidence-signer-2026")
sign_entry(entry, signer)   # attaches xEvidenceSignature over xEvidenceContentHash
```

The verifier is one offline ECDSA path for every signer kind; it trusts only
the pinned key, never the key named inside the evidence.

## 5. Preflight: the whole path, end to end

The fictional non-AWS Class C sample does steps 2 to 4 against the committed
fixtures (exports produced in memory with today's observation times, a
throwaway key standing in for the managed key service), builds the package,
records a manifest-bound sign-off and runs `package-preflight`, then restores
every file it touched:

```bash
python examples/sample-offering-class-c-non-aws/build_non_aws_class_c_sample.py
```

Expect `package-preflight exit code: 0 (READY)` and 55 adapter-derived,
hashed, signed evidence entries behind 46 KSIs. On your own package the same
command is `python sdr.py package-preflight`; a finding there is a readiness
finding worded as an expectation, and a blocker names the gate that refused.

The same sample is also attacked with the assessor-attack probe list the AWS
sample uses, so the gates that protect your package are proven against a
package shaped like yours:

```text
python examples/sample-offering-class-c-non-aws/build_non_aws_class_c_sample.py --attack
```

(About twenty minutes; CI runs it as the `attack-gate-non-aws` job on every
change, so you do not have to.)

## What this does and does not say

Every output above is an expectation the package states or a readiness
finding against the package's own gates. None of it is a compliance
determination, an assessment result or a statement about any product. The
FedRAMP 20x rules dataset (`github.com/FedRAMP/rules`) is the controlling
source for every requirement; the accredited assessor and the program decide
whether an indicator is met.
