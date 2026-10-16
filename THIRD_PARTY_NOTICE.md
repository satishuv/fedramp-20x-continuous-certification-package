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
| Google Cloud, Google Cloud Security Command Center, Security Command Center | Google LLC | An optional offline adapter (story MCE-04) reads a customer-produced findings export; the export shape is taken from Google's published API documentation, cited in the example mapping. |
| Microsoft Azure, Azure, Microsoft Defender for Cloud, Azure Policy | Microsoft Corporation | An optional offline adapter (story MCE-05) reads a customer-produced Azure Policy compliance-states export; the export shape is taken from Microsoft's published API documentation, cited in the example mapping. |
| Oracle Cloud Infrastructure, OCI Cloud Guard, Cloud Guard | Oracle Corporation | An optional offline adapter (story MCE-06) reads a customer-produced Cloud Guard problems export; the export shape is taken from Oracle's published API documentation, cited in the example mapping. |
| OpenSCAP | The OpenSCAP project (open source) | An optional offline adapter (story MCE-07) reads the XCCDF or ARF scan results file a customer's scan wrote; the results format itself is the NIST XCCDF standard. |
| Cloud Audit Logs, Cloud Logging, Cloud Monitoring, Cloud Key Management Service, Secret Manager, Certificate Manager, Certificate Authority Service, VPC Service Controls, Google Cloud Armor, Cloud Next Generation Firewall, Binary Authorization, Artifact Registry, Artifact Analysis, Cloud Build, Cloud Deploy, Cloud Asset Inventory, Organization Policy, Privileged Access Manager, Identity-Aware Proxy, Cloud Identity, Backup and DR, VM Manager, Infrastructure Manager, Config Connector, Policy Intelligence, Sensitive Data Protection, Google Security Operations, Assured Workloads, Cloud Service Mesh, Cloud Storage, Compute Engine, Google Kubernetes Engine | Google LLC | Named in the Google Cloud implementation guidance notes (`guidance/platforms/google-cloud.json`, story MCE-17) so a provider on that platform can locate the vendor's documentation for each service; names and URLs captured from Google's public documentation on the file's capture date. |
| Microsoft Entra, Microsoft Entra ID, Microsoft Entra Conditional Access, Microsoft Entra ID Governance, Microsoft Entra managed identities, Privileged Identity Management, Microsoft Sentinel, Azure Monitor, Log Analytics, Activity Log, Azure Key Vault, Azure Key Vault Managed HSM, Azure Firewall, Azure DDoS Protection, Azure Web Application Firewall, Azure Private Link, Azure Network Watcher, Azure Backup, Azure Site Recovery, Azure Update Manager, Azure Automation, Azure Pipelines, Bicep, Azure Container Registry, Azure Chaos Studio, Azure Blob Storage, Azure Attestation, Azure Resource Graph, Azure Machine Configuration, Azure management groups | Microsoft Corporation | Named in the Microsoft Azure implementation guidance notes (`guidance/platforms/azure.json`, story MCE-17) so a provider on that platform can locate the vendor's documentation for each service; names and URLs captured from Microsoft's public documentation on the file's capture date. |
| OCI Audit, OCI Logging, OCI Log Analytics, OCI Monitoring, OCI Notifications, OCI Events, OCI Security Zones, OCI Vault, OCI Certificates, OCI Vulnerability Scanning, OCI Bastion, OCI Resource Manager, OCI OS Management Hub, OCI Full Stack Disaster Recovery, OCI Object Storage, OCI IAM with Identity Domains, OCI Access Governance, OCI Web Application Firewall, OCI Network Firewall, OCI Zero Trust Packet Routing, OCI DevOps, OCI Container Registry, OCI Threat Intelligence, OCI Application Dependency Management, OCI Search | Oracle Corporation | Named in the Oracle Cloud Infrastructure implementation guidance notes (`guidance/platforms/oci.json`, story MCE-17) so a provider on that platform can locate the vendor's documentation for each service; the short service names are written with the OCI prefix in this repository; names and URLs captured from Oracle's public documentation on the file's capture date. |

## Removing a third party

Every third-party name is confined to files that exist only for it, plus the
registration row above and the guard's watchlist line, so withdrawing one is a
bounded edit that the gates then verify:

1. List what names it: `python validation/scripts/test_third_party_names.py --inventory`
   prints, for every registered name, the tracked files whose text contains it.
   The list is computed from the tree on each run, never maintained by hand.
2. Delete the files that exist only for that third party: its adapter or
   mapping, fixtures and golden under `automation/collectors/`, its platform
   guidance file under `guidance/platforms/`, and any sample or quickstart
   built on it. Then remove its mentions from the shared files the inventory
   lists (this notice's row, the guard's watchlist, README sections, the
   changelog is history and stays).
3. Run the validate suite. The naming guard fails on a name that is still used
   but no longer registered (a stale registration row is harmless; the
   inventory reports it with 0 files); the adapter conformance suite fails on
   a source whose fixtures are gone; the notes builder fails closed on a
   profile that still selects a withdrawn guidance platform.

The engine underneath (the fact contract, the mapping-driven adapter, the
binding gate, the signer contract, the evidence-store properties and the
platform-labelled notes) names no vendor and stays. Removing a platform's
guidance file leaves the built-in AWS notes exactly as they were.

## Relationship to the LICENSE and README

The LICENSE governs this repository's own content and the conditions on AWS
names and marks. This notice adds nothing to and takes nothing from those
terms; it records how other organizations' names are used. Like the LICENSE
and README, its wording is subject to confirmation by AWS legal.
