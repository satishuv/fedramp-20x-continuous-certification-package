# Third-party names notice

This repository names products and projects that belong to other organizations.
Every such name appears for one reason only: to identify an export format or
tool output that an optional, offline evidence adapter reads. The names are
trademarks or trade names of their respective owners. Their use here implies no
affiliation, sponsorship, endorsement, approval or association between this
repository, AWS Security Assurance Services or Amazon Web Services, Inc. and
any of those owners, and no statement about any of their products.

What this repository does not do with these names:

- It does not evaluate, rank, compare or recommend any product, including AWS
  products, and no sentence that names a third party may do so.
- It does not state or imply that any product meets, satisfies or fails any
  FedRAMP requirement. The repository emits expectations and readiness
  findings; compliance determinations belong to authorizing officials and
  independent assessors.
- It does not reproduce vendor documentation, logos, icons, screenshots or
  taglines. Export formats are described from each vendor's public
  documentation, cited by URL with a capture date in the adapter or fixture
  header, and never from memory.
- It does not call any vendor API or ship any vendor client. Adapters read a
  file the customer produced from their own tenant.
- It does not contain real customer, tenant, project, subscription,
  compartment, account or host identifiers. Every fixture is fictional.

## Registered names

A third-party name may be used in this repository only if it is listed here.
The guard `validation/scripts/test_third_party_names.py` runs in the validate
job: it fails on any name from its vendor watchlist that is not registered in
this table, on comparative or evaluative language in a sentence that contains
a registered name, and on any image file whose name carries a vendor token.
Adding a name means adding a row to this table in the same pull request.

| Name as used in this repository | Owner | Why it appears |
|---|---|---|
| CrowdStrike Falcon, CrowdStrike, Falcon | CrowdStrike, Inc. | An optional offline adapter reads a customer-produced Falcon export as evidence toward monitoring and incident-response indicators. |
| Wiz | Wiz, Inc. | An optional offline adapter reads a customer-produced Wiz export as evidence toward vulnerability and configuration indicators. |
| Google Cloud, Google Cloud Security Command Center, Security Command Center | Google LLC | A planned optional offline adapter (story MCE-04) reads a customer-produced findings export. |
| Microsoft Azure, Azure, Microsoft Defender for Cloud, Azure Policy | Microsoft Corporation | A planned optional offline adapter (story MCE-05) reads a customer-produced compliance export. |
| Oracle Cloud Infrastructure, OCI Cloud Guard, Cloud Guard | Oracle Corporation | A planned optional offline adapter (story MCE-06) reads a customer-produced problems export. |
| OpenSCAP | The OpenSCAP project (open source) | An optional offline adapter (story MCE-07) reads the XCCDF or ARF scan results file a customer's scan wrote; the results format itself is the NIST XCCDF standard. |

## Relationship to the LICENSE and README

The LICENSE governs this repository's own content and the conditions on AWS
names and marks. This notice adds nothing to and takes nothing from those
terms; it records how other organizations' names are used. Like the LICENSE
and README, its wording is subject to confirmation by AWS legal.
