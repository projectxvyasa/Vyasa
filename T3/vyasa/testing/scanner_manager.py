"""
Scanner Manager for VYASA.
Coordinates targeted security testing passes using WebAuditor and protocol checks.
"""

import uuid
import logging
from typing import List
from vyasa.core.models import Asset, Finding, Severity, ValidationStatus
from vyasa.core.config import TestingConfig
from vyasa.testing.web_auditor import WebAuditor

logger = logging.getLogger("vyasa.testing.scanner_manager")


class ScannerManager:
    """Dispatches real security checks against discovered assets and normalizes findings."""

    def __init__(self, config: TestingConfig):
        self.config = config
        self.web_auditor = WebAuditor()

    def run_security_testing(self, assets: List[Asset]) -> List[Finding]:
        """
        Executes real vulnerability and misconfiguration audits against target assets.
        """
        logger.info(f"Executing security testing across {len(assets)} assets...")
        findings: List[Finding] = []

        for asset in assets:
            logger.info(f"Auditing asset: {asset.host} ({asset.ip or 'Unresolved'})...")
            # Run the real web & port security audit only. No mock/baseline
            # findings are ever synthesized (Strict PoC policy): a finding is
            # emitted solely when a live response proves it.
            real_findings = self.web_auditor.audit_asset(asset)
            findings.extend(real_findings)

        logger.info(f"Security testing completed: Identified {len(findings)} finding(s).")
        return findings
