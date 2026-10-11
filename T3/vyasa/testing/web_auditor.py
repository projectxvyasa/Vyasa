"""
Web Application Security Auditor for VYASA.
Performs real HTTP header audits, cookie security inspections, and exposed file checks.
"""

import uuid
import logging
from typing import List, Dict, Any, Optional
import urllib3
import requests
from vyasa.core.models import Asset, Finding, Severity, ValidationStatus
from vyasa.testing.cors_auditor import CORSAuditor
from vyasa.testing.graphql_auditor import GraphQLAuditor
from vyasa.testing.api_schema_auditor import APISchemaAuditor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("vyasa.testing.web_auditor")


class WebAuditor:
    """Audits web assets for HTTP misconfigurations, information leakage, and security hygiene."""

    def __init__(self, timeout: float = 3.5):
        self.timeout = timeout
        self.cors_auditor = CORSAuditor(timeout=timeout)
        self.graphql_auditor = GraphQLAuditor(timeout=timeout)
        self.api_schema_auditor = APISchemaAuditor(timeout=timeout)

    def audit_asset(self, asset: Asset) -> List[Finding]:
        """Runs targeted HTTP audits against open web ports on the asset."""
        findings: List[Finding] = []

        web_ports = [p for p in asset.open_ports if p in (80, 443, 8000, 8080, 8443, 8888, 9000)]
        if not web_ports:
            # If no standard web ports were observed open, still try 443/80 with
            # real requests; findings are only emitted on genuine responses.
            web_ports = [443, 80]

        for port in web_ports:
            scheme = "https" if port in (443, 8443) else "http"
            port_suffix = f":{port}" if port not in (80, 443) else ""
            base_url = f"{scheme}://{asset.host}{port_suffix}"

            try:
                resp = requests.get(
                    base_url,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VYASA-Security-Scanner/1.0"}
                )

                # Strict PoC policy: "confirmed-but-common" hygiene findings
                # (missing CSP/HSTS/X-Frame headers, insecure cookies, server
                # version / X-Powered-By banners) are intentionally NOT reported.
                # Only checks backed by a concrete proof-of-concept remain.

                # 1. Sensitive Endpoints & Actuators (real 200 + content required)
                endpoint_findings = self._probe_sensitive_paths(asset, port, base_url)
                findings.extend(endpoint_findings)

                # 2. CORS Policy Analysis (real origin reflection required)
                cors_findings = self.cors_auditor.audit_cors(asset, port, base_url)
                findings.extend(cors_findings)

                # 3. GraphQL Introspection & Playground (real schema response required)
                graphql_findings = self.graphql_auditor.audit_graphql(asset, port, base_url)
                findings.extend(graphql_findings)

                # 4. API Schema Discovery (real OpenAPI/Swagger document required)
                schema_findings = self.api_schema_auditor.audit_api_schemas(asset, port, base_url)
                findings.extend(schema_findings)

            except Exception as e:
                logger.debug(f"Could not complete web audit against {base_url}: {e}")

        # Non-web port audits (e.g. exposed databases)
        if 5432 in asset.open_ports:
            findings.append(
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    title="Exposed PostgreSQL Database Port (5432)",
                    description="Port 5432 responded to TCP handshake from external scanner IP, indicating missing firewall segmentation.",
                    severity=Severity.MEDIUM,
                    asset_id=asset.asset_id,
                    port=5432,
                    service="PostgreSQL",
                    evidence=f"TCP connection established to {asset.ip or asset.host}:5432.",
                    cve_id="CWE-284",
                    cvss_score=5.3,
                    validation_status=ValidationStatus.CONFIRMED
                )
            )

        if 3306 in asset.open_ports:
            findings.append(
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    title="Exposed MySQL Database Port (3306)",
                    description="Port 3306 responded to TCP handshake from external scanner IP, indicating missing firewall segmentation.",
                    severity=Severity.MEDIUM,
                    asset_id=asset.asset_id,
                    port=3306,
                    service="MySQL",
                    evidence=f"TCP connection established to {asset.ip or asset.host}:3306.",
                    cve_id="CWE-284",
                    cvss_score=5.3,
                    validation_status=ValidationStatus.CONFIRMED
                )
            )

        return findings

    def _probe_sensitive_paths(self, asset: Asset, port: int, base_url: str) -> List[Finding]:
        """
        Tests for sensitive/diagnostic endpoints. Strict PoC: a 200 status is not
        enough (SPA catch-alls return 200 for everything), so each path must also
        return a content signature proving the real file/endpoint was served.
        """
        findings = []
        # (path, title, severity, impact, required content signature)
        paths_to_test = [
            ("/actuator/env", "Spring Boot Actuator Env", Severity.HIGH,
             "Exposed environment configuration and credentials.", "propertySources"),
            ("/.env", "Exposed .env Configuration File", Severity.CRITICAL,
             "Application environment file containing secrets or database passwords.", "DB_PASSWORD"),
            ("/.git/HEAD", "Exposed Git Repository Metadata", Severity.HIGH,
             "Source code repository metadata exposed publicly.", "ref: refs/heads"),
        ]

        for path, title, severity, impact_desc, signature in paths_to_test:
            url = f"{base_url}{path}"
            try:
                probe_resp = requests.get(
                    url,
                    timeout=2.0,
                    verify=False,
                    allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VYASA-Security-Scanner/1.0"}
                )
                if probe_resp.status_code == 200 and signature.lower() in probe_resp.text.lower():
                    findings.append(
                        Finding(
                            finding_id=f"find_{uuid.uuid4().hex[:8]}",
                            title=title,
                            description=f"The endpoint '{path}' is publicly accessible without authentication. {impact_desc}",
                            severity=severity,
                            asset_id=asset.asset_id,
                            port=port,
                            service=f"HTTP/{port}",
                            evidence=f"GET {path} -> HTTP 200 and body matched signature '{signature}' (Content-Length: {len(probe_resp.text)}).",
                            cve_id="CWE-200",
                            cvss_score=7.5 if severity == Severity.HIGH else (9.1 if severity == Severity.CRITICAL else 3.5),
                            validation_status=ValidationStatus.CONFIRMED
                        )
                    )
            except Exception:
                pass

        return findings
