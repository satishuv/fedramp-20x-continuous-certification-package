#!/usr/bin/env python3
"""Optional third-party evidence adapters: CrowdStrike Falcon and Wiz.

These are OPT-IN, per customer. One customer may run CrowdStrike, another Wiz,
another neither; nothing here is enabled by default. Each adapter turns a
security tool's EXPORT (a JSON file the customer produces in their own
environment) into SDR evidence entries via the shared EvidenceAdapter
interface, so the output lands as hashed, schema-valid ksiEvidence objects
under the exact same trust boundary as the AWS collectors:

  - Telemetry only. An adapter NEVER sets or changes an implementation,
    validation, or assessment status. A detection count or sensor-coverage
    figure is a metric, not a compliance verdict.
  - Offline and secret-free. Adapters read a file the customer already
    exported; this repository holds NO Falcon or Wiz API client and NO API
    credentials. Fetching from the live API (which needs a token) is the
    customer's own step in their own environment, kept out of this public
    template so the secret-scanners stay clean. See the reference note in each
    adapter for the expected export shape.

Each adapter maps to REAL CR26 KSI ids (verified against the pinned dataset),
returned by ksi_targets() so a caller knows which indicators the evidence
supports. The adapter attaches evidence; a human still decides the status.

Offline by construction: pure functions over the export dict. Run the tests:
    python automation/collectors/test_thirdparty_adapters.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evidence_wiring as ew  # noqa: E402


class FalconAdapter(ew.EvidenceAdapter):
    """CrowdStrike Falcon endpoint detection and response.

    Maps Falcon telemetry to centralized-monitoring, log-review, and
    incident-response indicators. Endpoint threat detection is evidence toward
    a SIEM-style monitoring capability and incident response, not proof of
    compliance.

    Expected export shape (a customer produces this from their Falcon tenant;
    all fields optional, missing ones are skipped):
        {
          "observed_at": "2026-09-08T00:00:00Z",
          "sensor_coverage": {"protected": 480, "total": 500},
          "detections_open": 3,
          "prevention_policy_enabled": true
        }
    """

    name = "crowdstrike-falcon"
    service = "crowdstrike"

    # Verified against the pinned KSI profile.
    KSI_TARGETS = ["KSI-MLA-OSM", "KSI-MLA-RVL", "KSI-MLA-LET", "KSI-INR-RIR"]
    # The exact checks collect() can yield; each is registered against every
    # target in the source registry (MCE-03). A fact outside this vocabulary is
    # refused by to_evidence, never exported unbound.
    checks = ("sensor_coverage", "open_detections", "prevention_policy")

    def ksi_targets(self):
        return list(self.KSI_TARGETS)

    def collect(self, raw):
        observed = raw.get("observed_at")
        cov = raw.get("sensor_coverage")
        if isinstance(cov, dict) and cov.get("total"):
            protected = cov.get("protected", 0)
            total = cov["total"]
            pct = round(100.0 * protected / total, 2)
            yield self._fact("sensor_coverage", f"{pct}%",
                             f"Falcon sensor on {protected} of {total} hosts", observed)
        if "detections_open" in raw:
            n = raw["detections_open"]
            yield self._fact("open_detections", str(n),
                             f"{n} open Falcon detection(s)", observed)
        if "prevention_policy_enabled" in raw:
            enabled = bool(raw["prevention_policy_enabled"])
            yield self._fact("prevention_policy",
                             "ENABLED" if enabled else "DISABLED",
                             "Falcon prevention policy applied", observed)

    def _fact(self, check, status, detail, observed):
        return {"service": self.service, "check": check, "status": status,
                "detail": detail, "region": "global", "observed_at": observed}


class WizAdapter(ew.EvidenceAdapter):
    """Wiz cloud-native application protection (CNAPP): configuration/posture
    and vulnerability findings.

    Maps Wiz telemetry to configuration-evaluation, monitoring, and
    supply-chain vulnerability indicators. Posture and vulnerability counts are
    evidence toward persistent configuration evaluation, not a verdict.

    Expected export shape (customer-produced from their Wiz tenant):
        {
          "observed_at": "2026-09-08T00:00:00Z",
          "issues_by_severity": {"critical": 0, "high": 2, "medium": 10},
          "config_findings_open": 4,
          "vulnerabilities_open": 7
        }
    """

    name = "wiz"
    service = "wiz"

    KSI_TARGETS = ["KSI-MLA-EVC", "KSI-MLA-OSM", "KSI-SCR-MON"]
    checks = ("issues_critical_high", "config_findings", "vulnerabilities")

    def ksi_targets(self):
        return list(self.KSI_TARGETS)

    def collect(self, raw):
        observed = raw.get("observed_at")
        sev = raw.get("issues_by_severity")
        if isinstance(sev, dict):
            crit = sev.get("critical", 0)
            high = sev.get("high", 0)
            yield self._fact("issues_critical_high", f"{crit} critical / {high} high",
                             "Wiz open issues by severity", observed)
        if "config_findings_open" in raw:
            n = raw["config_findings_open"]
            yield self._fact("config_findings", str(n),
                             f"{n} open Wiz configuration finding(s)", observed)
        if "vulnerabilities_open" in raw:
            n = raw["vulnerabilities_open"]
            yield self._fact("vulnerabilities", str(n),
                             f"{n} open Wiz vulnerability finding(s)", observed)

    def _fact(self, check, status, detail, observed):
        return {"service": self.service, "check": check, "status": status,
                "detail": detail, "region": "global", "observed_at": observed}


ew.register_adapter(FalconAdapter)
ew.register_adapter(WizAdapter)


# Names a caller checks against the offering profile's opt-in flags.
THIRD_PARTY_ADAPTERS = ["crowdstrike-falcon", "wiz"]
