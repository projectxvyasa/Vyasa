"""
CORS (Cross-Origin Resource Sharing) Misconfiguration Auditor for VYASA.
Non-intrusively tests for permissive origin reflection, null origin trust, and credential exposure.
"""

import uuid
import logging
from typing import List, Dict, Optional
import urllib3
import requests
from vyasa.core.models import Asset, Finding, Severity, ValidationStatus

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("vyasa.testing.cors_auditor")


class CORSAuditor:
    """Evaluates cross-origin resource sharing headers and policies against web assets."""

    def __init__(self, timeout: float = 3.5):
        self.timeout = timeout
        self.test_origin = "https://evil-security-audit.internal"

    def audit_cors(self, asset: Asset, port: int, base_url: str) -> List[Finding]:
        """
        Executes non-intrusive CORS diagnostic probes:
        1. Arbitrary Origin Reflection + Access-Control-Allow-Credentials check.
        2. 'null' Origin trust verification (iframe sandbox bypass vector).
        3. Preflight OPTIONS method permissiveness.
        """
        findings: List[Finding] = []

        try:
            # 1. Test Arbitrary Origin Reflection
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VYASA-Security-Scanner/1.0",
                "Origin": self.test_origin
            }
            resp = requests.get(
                base_url,
                headers=headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )

            acao = resp.headers.get("Access-Control-Allow-Origin", "").strip()
            acac = resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

            if acao == self.test_origin:
                if acac == "true":
                    findings.append(
                        Finding(
                            finding_id=f"find_{uuid.uuid4().hex[:8]}",
                            title="Critical CORS Misconfiguration: Arbitrary Origin Reflected with Credentials",
                            description=(
                                "The web application dynamically reflects arbitrary Origin headers and sets "
                                "'Access-Control-Allow-Credentials: true'. This allows an untrusted third-party site "
                                "to issue authenticated requests on behalf of victims and read sensitive response data."
                            ),
                            severity=Severity.HIGH,
                            asset_id=asset.asset_id,
                            port=port,
                            service=f"HTTP/{port}",
                            evidence=f"Request Origin: {self.test_origin} -> Response: Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                            cve_id="CWE-942",
                            cvss_score=8.5,
                            validation_status=ValidationStatus.CONFIRMED
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            finding_id=f"find_{uuid.uuid4().hex[:8]}",
                            title="Overly Permissive CORS Policy: Arbitrary Origin Reflection",
                            description=(
                                "The server blindly reflects the incoming Origin header in Access-Control-Allow-Origin without credentials. "
                                "While session cookies are not automatically passed, unauthenticated response bodies and caching can be compromised."
                            ),
                            severity=Severity.LOW,
                            asset_id=asset.asset_id,
                            port=port,
                            service=f"HTTP/{port}",
                            evidence=f"Request Origin: {self.test_origin} -> Response: Access-Control-Allow-Origin: {acao}",
                            cve_id="CWE-942",
                            cvss_score=4.3,
                            validation_status=ValidationStatus.CONFIRMED
                        )
                    )

            # 2. Test 'null' Origin Trust
            null_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VYASA-Security-Scanner/1.0",
                "Origin": "null"
            }
            null_resp = requests.get(
                base_url,
                headers=null_headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            null_acao = null_resp.headers.get("Access-Control-Allow-Origin", "").strip()
            null_acac = null_resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

            if null_acao == "null" and null_acac == "true":
                findings.append(
                    Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:8]}",
                        title="CORS Misconfiguration: 'null' Origin Trusted with Credentials",
                        description=(
                            "The server trusts the 'null' origin and permits credentials. Attackers can execute cross-origin "
                            "theft by delivering payloads inside sandboxed iframes (which evaluate with a null origin)."
                        ),
                        severity=Severity.HIGH,
                        asset_id=asset.asset_id,
                        port=port,
                        service=f"HTTP/{port}",
                        evidence="Request Origin: null -> Response: Access-Control-Allow-Origin: null, Access-Control-Allow-Credentials: true",
                        cve_id="CWE-942",
                        cvss_score=7.8,
                        validation_status=ValidationStatus.CONFIRMED
                    )
                )

            # 3. Test Preflight OPTIONS Handling
            preflight_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VYASA-Security-Scanner/1.0",
                "Origin": self.test_origin,
                "Access-Control-Request-Method": "DELETE"
            }
            options_resp = requests.options(
                base_url,
                headers=preflight_headers,
                timeout=self.timeout,
                verify=False
            )
            acam = options_resp.headers.get("Access-Control-Allow-Methods", "")
            if "DELETE" in acam or "PUT" in acam:
                if options_resp.headers.get("Access-Control-Allow-Origin") == "*":
                    findings.append(
                        Finding(
                            finding_id=f"find_{uuid.uuid4().hex[:8]}",
                            title="Permissive CORS Preflight: Dangerous HTTP Methods Allowed Across Origins",
                            description=(
                                f"OPTIONS preflight allows destructive methods ({acam}) with wildcard '*' origin, "
                                "potentially enabling cross-origin resource manipulation."
                            ),
                            severity=Severity.MEDIUM,
                            asset_id=asset.asset_id,
                            port=port,
                            service=f"HTTP/{port}",
                            evidence=f"Access-Control-Allow-Methods: {acam}, Access-Control-Allow-Origin: *",
                            cve_id="CWE-942",
                            cvss_score=5.3,
                            validation_status=ValidationStatus.CONFIRMED
                        )
                    )

        except Exception as e:
            logger.debug(f"CORS audit probe against {base_url} encountered: {e}")

        return findings
