# -*- coding: utf-8 -*-
# Build the explainer notes layer: for every FRR rule and every KSI, a short
# note saying what the requirement looks for, how a provider typically complies
# on AWS, and what evidence is expected.
#
# Sources, in order of authority:
#   1. The official rule statement (resolved for the target class elsewhere).
#   2. Rule-specific "artifacts" lists in the canonical dataset (53 rules).
#   3. Rule-specific "notes"/"note" fields in the canonical dataset (79 rules).
#   4. The dataset's default artifact expectations (info.default_artifacts),
#      which apply when a rule defines no specific artifacts.
#   5. Hand-authored AWS compliance guidance, clearly labeled as guidance:
#      per-KSI (46 entries) and per-family for FRR rules. Guidance names
#      typical AWS services; it is advisory, not an official requirement.
#
# Outputs:
#   traceability/rule-notes.json   keyed by rule_id
#   traceability/ksi-notes.json    keyed by ksi_id
#
# Pipeline position: run after build_catalogs.py, before build_sdr.py.

import json
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CANONICAL = os.path.join(BASE, "references", "fedramp-consolidated-rules.json")
CATALOG = os.path.join(BASE, "traceability", "rule-catalog.json")
KSI_CATALOG = os.path.join(BASE, "traceability", "ksi-catalog.json")

# Advisory guidance per FRR family. Labeled as guidance in output.
FAMILY_GUIDANCE = {
    "AFC": "Stand up a dedicated, monitored FedRAMP security inbox as a distribution list reaching the security on-call rotation, separate from customer support. Test delivery and acknowledgement on a schedule (for example monthly synthetic emails) and keep membership current.",
    "AGU": "These rules apply to federal agencies, not providers. A provider only needs awareness of what agencies are told to expect.",
    "CCM": "Establish the quarterly Ongoing Certification Report and Quarterly Review cadence: a named owner, a calendar, a consistent format, a feedback mechanism, and public next-report and next-review dates in the certification data.",
    "CDS": "Publish certification data through a trust center with both public and agency-authenticated access, in human-readable and machine-readable form. Automate generation from the same pipeline that produces the SDR so the two never drift.",
    "CMU": "Use FIPS-validated cryptographic modules for federal data: AWS KMS (validated HSM-backed) for keys, FIPS endpoints for service APIs where required, and TLS 1.2 or higher. Record module certificates and validation numbers; document any exception formally.",
    "CPO": "Keep the Certification Package Overview concise and current. At Class C the package must be maintained at least every 2 weeks; put the maintenance run on a calendar with a named owner and generate as much as possible from the pipeline.",
    "FRC": "Certification mechanics: pick one Program Certification type, supply schema-valid JSON wherever a rule defines a schema, meet the per-class automated verification and validation minimums (FRC-CSX-VVK), and start accumulating the KSI metric history the Security Decision Record carries (SDR-CSX-KMT: daily data up to the past year at Class C) before applying.",
    "IEC": "Define incident evaluation and reporting procedures with the FedRAMP Reportable Incident test, the Potential Agency Impact N-rating scale, and the class-specific reporting timeframes. Wire detection (GuardDuty, Security Hub) to an on-call process that can meet the clock.",
    "IVV": "Engage a FedRAMP Recognized Assessor with documented independence (no advisory work on this offering in the past 2 years). Give the assessor access to the SDR and read access to live evidence; supply evidence of implementation (verification) and effectiveness (validation).",
    "MAS": "Define the Minimum Assessment Scope narrowly and defensibly: identify every information resource that handles federal data or whose compromise would affect it, justify each exclusion, and keep the inventory machine-generated (AWS Config, Resource Explorer) so it stays current.",
    "MKT": "Maintain an accurate FedRAMP Marketplace listing. If listing during Initial Implementation, schedule the assessment within 2 years (MKT-IIP-DLA). Keep listing data consistent with the certification data.",
    "REC": "These rules govern assessor recognition, not providers. A provider's obligation is to select an assessor that holds FedRAMP Recognition and to respect the 2-year advisory independence bar.",
    "SCG": "Write the Secure Configuration Guide for the agency customer, not the provider: the settings the customer controls, secure defaults, consequences of insecure choices, and machine-readable guidance where practical.",
    "SCN": "Classify changes (routine recurring, adaptive, transformative, impact categorization) and automate the notification workflow with the class timeframes. Keep 12 months of notification history in human-readable and JSON form; log every evaluation.",
    "SDR": "Maintain the Security Decision Record in both human-readable and JSON form, schema-valid, with an entry for every applicable rule and KSI, metadata (version, last updated, update source), and the per-class historical metrics.",
    "VDR": "Run continuous vulnerability detection across every in-scope resource (Amazon Inspector for EC2, ECR, Lambda; Security Hub aggregation), meet the class cadences for sample and drift detection, track mitigation and remediation against the timeframes, and honor CISA KEV due dates.",
    "VER": "Evaluate every detected vulnerability quickly, assign a Potential Agency Impact N-rating, treat qualifying exploitable vulnerabilities as FedRAMP Reportable Incidents per the class rules, and report through the required channels with machine-readable detail.",
}

# Advisory AWS compliance guidance per KSI. Labeled as guidance in output.
KSI_GUIDANCE = {
    "KSI-CED-RAT": "Review all training content and completion on a defined cycle; keep the review dated and owned. Evidence: review records with reviewer, date, and outcome, plus the updated training register.",
    "KSI-CMT-LMC": "Log and monitor every modification to the offering: CloudTrail organization trail (multi-region, log file validation), AWS Config recording all resource types, EventBridge alerting on out-of-pipeline writes. Evidence: trail status queries, Config recorder status, alert history.",
    "KSI-CMT-RMV": "Deploy changes by redeploying version-controlled resources (IaC through the pipeline) instead of modifying live resources. Evidence: pipeline deployment records diffed against CloudTrail write events; drift detection results.",
    "KSI-CMT-RVP": "Review change management procedure effectiveness on a cycle: measure failed changes, rollbacks, and out-of-band changes, and adjust the procedure. Evidence: dated reviews with metrics and resulting changes.",
    "KSI-CMT-VTD": "Automate testing and validation of changes through the CI/CD pipeline: pre-deployment tests, policy-as-code checks, post-deployment verification. Evidence: pipeline run records showing gates passed per change.",
    "KSI-CNA-DFP": "Strictly define functionality and privileges for infrastructure and services: least-privilege IAM roles, permission boundaries, service control policies. Evidence: IAM Access Analyzer findings, SCP inventory, unused-permission reports.",
    "KSI-CNA-EIS": "Class-varying (optional/MAY at Class B, required at Class C): automated services persistently assess the security of all machine-based information resources and automatically enforce their intended operational state. Evidence: Config rules with auto-remediation, Systems Manager State Manager/associations, drift-detection and enforcement records over time.",
    "KSI-CNA-IBP": "Persistently compare third-party machine-based resources against the original provider's best practices (for example CIS or vendor benchmarks via Security Hub standards and Config conformance packs). Evidence: benchmark compliance scores over time.",
    "KSI-CNA-MAT": "Minimize attack surface and lateral movement: private subnets by default, no unnecessary public endpoints, network segmentation, S3 Block Public Access. Evidence: Config rules for public exposure, VPC design records, Security Hub findings trend.",
    "KSI-CNA-OFA": "Review resources for high availability and rapid recovery: multi-AZ deployment, health checks, auto scaling, tested recovery. Evidence: architecture inventory with AZ coverage, recovery test records.",
    "KSI-CNA-RNT": "Limit inbound and outbound network traffic: security groups and NACLs deny by default, egress control, WAF on public entry points. Evidence: Config rules on open security groups, reachability analysis, WAF coverage.",
    "KSI-CNA-RVP": "Review protection against denial of service and unwanted activity: AWS Shield, WAF rate rules, GuardDuty findings review. Evidence: protection coverage inventory and periodic effectiveness reviews.",
    "KSI-CNA-ULN": "Use logical networking to enforce traffic flow controls: VPC segmentation, route tables, PrivateLink for service-to-service paths. Evidence: network architecture records, VPC flow log analysis, reachability tests.",
    "KSI-IAM-AAM": "Automate the lifecycle and privileges of all accounts, roles, and groups: IAM Identity Center with SCIM provisioning from the identity provider, automated deprovisioning on termination. Evidence: provisioning logs, access review records, orphan-account checks.",
    "KSI-IAM-APM": "Use passwordless authentication where feasible (FIDO2), otherwise strong passwords with phishing-resistant MFA. Block console login without MFA; eliminate long-lived access keys. Evidence: MFA enforcement queries, CloudTrail login analysis, IAM credential report.",
    "KSI-IAM-ELP": "Ensure each user and device can only access what it needs: periodic access reviews, least-privilege role design, Access Analyzer. Evidence: access review records, unused-access findings and their closure.",
    "KSI-IAM-JIT": "Use a least-privileged, role-based, just-in-time authorization model: temporary elevated access with approval and expiry rather than standing privileges. Evidence: elevation request logs with approvals and automatic expiry.",
    "KSI-IAM-SNU": "Use appropriately secure authentication for non-user accounts and services: IAM roles and short-lived STS credentials instead of static keys; rotate any unavoidable secrets. Evidence: credential inventory, key-age reports, Secrets Manager rotation status.",
    "KSI-IAM-SUS": "Disable or secure privileged accounts in response to suspicious activity: GuardDuty findings wired to automated response (disable keys, revoke sessions) with on-call escalation. Evidence: response runbooks plus executed-response records with timestamps.",
    "KSI-INR-AAR": "Generate after action reports for incidents and incorporate lessons persistently. Evidence: after action reports linked to incidents, with tracked improvement actions and closure.",
    "KSI-INR-RIR": "Review incident response procedure effectiveness on a cycle, including exercises. Evidence: dated reviews, exercise records, and procedure updates that resulted.",
    "KSI-INR-RPI": "Review past incidents for patterns and previously missed vulnerabilities. Evidence: periodic pattern-analysis reports referencing the incident register.",
    "KSI-MLA-ALA": "Class-varying (optional/MAY at Class B, required at Class C): a least-privileged, role/attribute-based, just-in-time authorization model governs access to log data by data sensitivity, and is persistently reviewed. Evidence: IAM/Access Analyzer for log-store access, JIT-access records, periodic access reviews of the log data store.",
    "KSI-MLA-EVC": "Persistently evaluate and test the configuration of machine-based resources, especially infrastructure as code: policy-as-code in the pipeline (cfn-guard, OPA, Checkov) plus AWS Config in runtime. Evidence: pipeline policy results per change and Config compliance over time.",
    "KSI-MLA-LET": "Maintain and review a list of resources and event types that will be logged, monitored, and audited, and confirm those activities occur. Evidence: the logging register plus coverage checks proving each listed source is actually emitting.",
    "KSI-MLA-OSM": "Operate a SIEM or similar for centralized, tamper-resistant logging: centralized log archive account, S3 object lock or equivalent integrity protection, restricted access. Evidence: log centralization architecture, integrity settings, access policies.",
    "KSI-MLA-RVL": "Persistently review and audit logs: automated detections (CloudWatch, Security Hub, GuardDuty) plus a documented human review cadence for what automation cannot judge. Evidence: detection inventory, alert dispositions, review records.",
    "KSI-PIY-GIV": "Generate real-time inventories automatically from authoritative sources: AWS Config aggregator and Resource Explorer as the inventory of record, queryable on demand. Evidence: on-demand inventory exports with timestamps proving real-time generation.",
    "KSI-PIY-RES": "Demonstrate and review executive support for security goals persistently: executive sponsorship in the charter, recurring leadership reviews of posture, funded remediation. Evidence: dated leadership review records and funding decisions tied to security goals.",
    "KSI-PIY-RIS": "Review the effectiveness of security investments persistently: track spend against measurable outcomes (findings closed, coverage gained) and adjust. Evidence: periodic investment-effectiveness reviews with metrics and resulting decisions.",
    "KSI-PIY-RSD": "Review the effectiveness of security and privacy in the SDLC against CISA Secure By Design principles: pipeline security gates, secure defaults, threat modeling. Evidence: SDLC review records mapped to Secure By Design principles with improvement actions.",
    "KSI-PIY-RVD": "Operate and persistently review a vulnerability disclosure program: a public intake channel, triage SLAs, and periodic effectiveness review. Evidence: the published policy, intake and triage records, dated program reviews.",
    "KSI-SCR-MIT": "Persistently identify, review, and mitigate supply chain risks: supplier vetting, dependency review, risk register entries with mitigations. Evidence: the supply chain risk register with review dates and mitigation status.",
    "KSI-SCR-MON": "Automatically monitor third-party software for upstream vulnerabilities: dependency scanning (Inspector, SCA tooling), SBOM tracking, advisory feeds. Evidence: scan results over time, advisory response records, SBOM currency.",
    "KSI-RPL-ABO": "Keep backups aligned with defined recovery objectives: AWS Backup plans matching the stated RPO, cross-region copies where the objectives require. Evidence: backup plan configuration, job success history, restore points against objectives.",
    "KSI-RPL-ARP": "Maintain a recovery plan aligned with objectives, covering roles, procedures, and dependencies. Evidence: the plan with review dates and alignment to the stated RTO and RPO.",
    "KSI-RPL-RRO": "Define recovery time and recovery point objectives and keep them current. Evidence: documented RTO and RPO with rationale and review history.",
    "KSI-RPL-TRC": "Test the capability to recover from incidents and contingencies: restore tests, failover exercises, game days, measured against objectives. Evidence: test records with measured times versus objectives and corrective actions.",
    "KSI-SVC-ACM": "Manage configuration with automation and review drift persistently: IaC as the source of truth, AWS Config drift detection, automated remediation where safe. Evidence: drift findings and their resolution over time.",
    "KSI-SVC-ASM": "Automate management, protection, and rotation of keys, certificates, and secrets: KMS key rotation, ACM certificate renewal, Secrets Manager rotation. Evidence: rotation status queries across all three, alerts on failures.",
    "KSI-SVC-EIS": "Persistently evaluate resources for security improvement opportunities and implement them: Security Hub findings triage, Trusted Advisor or Inspector recommendations with tracked adoption. Evidence: findings trend plus a record of improvements shipped.",
    "KSI-SVC-PRR": "Class-varying (optional/MAY at Class B, required at Class C): plans, procedures, and resource state are persistently reviewed after changes to limit and remove unwanted residual elements that could affect confidentiality, integrity, or availability of federal customer data. Evidence: post-change review records, drift/residual-resource cleanup logs.",
    "KSI-SVC-RUD": "Class-varying (optional/MAY at Class B, required at Class C): unwanted federal customer data is removed promptly when an agency requests it per customer agreements, including from backups where appropriate (e.g. data spill or usage change). Evidence: data-removal request handling records, backup-scoped deletion procedures and logs.",
    "KSI-SVC-SIN": "Encrypt or otherwise secure information from unwanted access or modification: KMS customer managed keys at rest, TLS 1.2+ in transit, S3 Block Public Access, deny-unencrypted policies. Evidence: Config encryption rules, account-level default encryption status.",
    "KSI-SVC-VCM": "Class-varying (optional/MAY at Class B, required at Class C): the authenticity and integrity of communications between machine-based information resources is persistently validated using automation. Evidence: mutual-TLS/service-mesh identity validation, signed inter-service requests, automated integrity-verification records.",
    "KSI-SVC-VRI": "Use cryptographic methods to validate the integrity of machine-based resources: signed artifacts, image digests pinned in deployment, CloudTrail log file validation. Evidence: signature or digest verification records in the pipeline.",
}


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def find_rule_extras(dataset, rule_id, family):
    node = dataset["FRR"].get(family, {}).get("data", {})

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == rule_id:
                    return v
                r = walk(v)
                if r is not None:
                    return r
        return None

    return walk(node) or {}


def main():
    dataset = load(CANONICAL)
    catalog = load(CATALOG)
    ksi_catalog = load(KSI_CATALOG)
    default_frr = dataset["info"]["default_artifacts"]["FRR"]
    default_ksi = dataset["info"]["default_artifacts"]["KSI"]

    rule_notes = {}
    for r in catalog["rules"]:
        extras = find_rule_extras(dataset, r["rule_id"], r["family"])
        artifacts = extras.get("artifacts")
        if isinstance(artifacts, dict):
            artifacts = artifacts.get("all") or [
                x for v in artifacts.values() if isinstance(v, list) for x in v
            ]
        notes = extras.get("notes") or ([extras["note"]] if extras.get("note") else [])
        rule_notes[r["rule_id"]] = {
            "what_it_looks_for": (
                "The rule text below is the requirement; the force keyword "
                "(MUST, SHOULD, MAY) sets how binding it is for this class."
            ),
            "official_notes": notes,
            "evidence_required": artifacts if artifacts else default_frr,
            "evidence_source": (
                "rule-specific artifacts list" if artifacts
                else "FedRAMP default artifact expectations for rules"
            ),
            "how_to_comply_guidance": FAMILY_GUIDANCE.get(
                r["family"],
                "See the rule statement; no family guidance authored."),
            "guidance_label": (
                "The compliance guidance is SAS advisory content naming typical "
                "AWS approaches. It is not an official FedRAMP requirement; the "
                "rule statement governs."
            ),
        }

    ksi_notes = {}
    for k in ksi_catalog["indicators"]:
        kid = k["ksi_id"]
        ksi_notes[kid] = {
            "what_it_looks_for": k["statement"] or (
                "FedRAMP pending: no statement published yet for this indicator."
            ),
            "evidence_required": default_ksi,
            "evidence_source": "FedRAMP default artifact expectations for KSIs",
            "nist_controls": k.get("controls", []),
            "how_to_comply_guidance": KSI_GUIDANCE.get(
                kid, "No guidance authored yet for this indicator."),
            "guidance_label": (
                "The compliance guidance is SAS advisory content naming typical "
                "AWS approaches. It is not an official FedRAMP requirement; the "
                "indicator statement governs."
            ),
        }

    # Family name map so every document can spell out the short forms
    # (for example VDR is Vulnerability Detection and Response, IAM is
    # Identity and Access Management). Read from the canonical dataset.
    family_names = {
        "frr": {
            fam: (famdata.get("info", {}) or {}).get("name", fam)
            for fam, famdata in dataset["FRR"].items()
        },
        "ksi": {
            fam: (famdata.get("name") or fam)
            for fam, famdata in dataset["KSI"].items()
        },
    }
    out3 = os.path.join(BASE, "traceability", "family-names.json")
    with open(out3, "w", encoding="utf-8", newline="\n") as f:
        json.dump(family_names, f, indent=1)

    out1 = os.path.join(BASE, "traceability", "rule-notes.json")
    out2 = os.path.join(BASE, "traceability", "ksi-notes.json")
    with open(out1, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"note": "Explainer layer for FRR rules.", "rules": rule_notes}, f, indent=1)
    with open(out2, "w", encoding="utf-8", newline="\n") as f:
        json.dump({"note": "Explainer layer for KSIs.", "indicators": ksi_notes}, f, indent=1)

    missing_guidance = [k for k in ksi_notes if "No guidance authored" in ksi_notes[k]["how_to_comply_guidance"]]
    print("rule notes:", len(rule_notes))
    print("ksi notes:", len(ksi_notes))
    print("ksis missing guidance:", missing_guidance)
    return 0


if __name__ == "__main__":
    sys.exit(main())
