"""
Validation Engine for VYASA.

Keeps VYASA's strict "no fabrication" guarantee while no longer discarding
genuinely-confirmed findings. Every active detector in VYASA emits a Finding
ONLY when a real HTTP response proved the issue, and tags it CONFIRMED with
concrete evidence (a missing header observed in the response, a reflected
unencoded payload, an exposed file, a reproduced SQLi differential, ...). The
previous validator re-filtered those against a small substring whitelist and
silently dropped valid results (e.g. missing HSTS/CSP), which made insecure
sites report as "secure". This version trusts the detector's confirmation and
drops only findings that are genuinely unproven (no status + no evidence
marker) or empty.
"""

import logging
from typing import List
from vyasa.core.models import Finding, ValidationStatus

logger = logging.getLogger("vyasa.validation")


class VulnerabilityValidator:
    """Verifies that identified findings are backed by real, reproducible evidence."""

    # Phrases that, on their own, establish a finding came from a real response.
    PROOF_MARKERS = (
        "http 200", "-> http 200", "returned http 200", "handshake",
        "connect_ex == 0", "matched signature", "signature:", "reflected",
        "schema definition", "introspection", "openapi",
        "access-control-allow-origin", "acao=",
        # Confirmation-gated injection proofs.
        "confirmed via", "unencoded", "time-based blind", "boolean-based blind",
        "error-based sqli",
        # Passive header / cookie / disclosure proofs (observed in the response).
        "header", "set-cookie", "server:", "x-powered-by", "nosniff",
        "directory indexing", "index of", "disclosed", "exposed", "downloadable",
        "robots.txt", "cors permits", "missing", "omitted", "without the",
    )

    # Evidence phrases that mean the detector ran but found nothing -> NOT a finding.
    NEGATIVE_MARKERS = (
        "no directory indexing", "no exposed", "no internal ip", "nothing to audit",
        "not confirmed", "no x-powered-by", "no version leaked", "failed to connect",
        "probe failed",
    )

    def validate_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        A finding is kept when it is backed by real evidence: either the detector
        already tagged it CONFIRMED (it only does so on a proven response), or its
        evidence carries a proof marker. Findings with empty evidence, a negative
        result, or neither a CONFIRMED status nor a proof marker are dropped, so
        the report never contains assumed or fabricated issues.
        """
        logger.info(f"Validating {len(findings)} findings against evidence...")
        confirmed: List[Finding] = []
        dropped = 0

        for finding in findings:
            evidence = (finding.evidence or "").strip()
            low = evidence.lower()

            if not evidence:
                dropped += 1
                continue

            # A detector that ran and found nothing must never surface as a finding.
            if any(neg in low for neg in self.NEGATIVE_MARKERS):
                dropped += 1
                logger.debug(f"Dropped negative-result finding '{finding.title}'.")
                continue

            already_confirmed = finding.validation_status == ValidationStatus.CONFIRMED
            has_marker = any(marker in low for marker in self.PROOF_MARKERS)

            if already_confirmed or has_marker:
                finding.validation_status = ValidationStatus.CONFIRMED
                confirmed.append(finding)
            else:
                dropped += 1
                logger.debug(f"Dropped unproven finding '{finding.title}' (evidence: {finding.evidence!r}).")

        logger.info(f"Validation completed: {len(confirmed)} confirmed, {dropped} unproven/negative finding(s) dropped.")
        return confirmed
