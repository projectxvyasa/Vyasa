"""
API Schema & Documentation Discovery Auditor for VYASA.
Non-intrusively discovers exposed OpenAPI/Swagger specifications,
ReDoc portals, SpringDoc routes, and API documentation catalogs.
"""

import uuid
import logging
from typing import List, Dict, Any, Optional
import urllib3
import requests
from vyasa.core.models import Asset, Finding, Severity, ValidationStatus

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("vyasa.testing.api_schema_auditor")


class APISchemaAuditor:
    """Discovers and evaluates exposure of unauthenticated API specifications and docs."""

    SCHEMA_PATHS = [
        # OpenAPI / Swagger JSON/YAML
        "/openapi.json",
        "/swagger.json",
        "/v3/api-docs",
        "/v2/api-docs",
        "/api/swagger.json",
        "/swagger/v1/swagger.json",
        "/api-docs",
        "/api/v1/api-docs",
        # Interactive UI Portals
        "/swagger-ui.html",
        "/swagger-ui/index.html",
        "/docs",
        "/redoc"
    ]

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def audit_api_schemas(self, asset: Asset, port: int, base_url: str) -> List[Finding]:
        """Probes for exposed API specifications and interactive documentation interfaces."""
        findings: List[Finding] = []
        found_schema_spec = False

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VYASA-Security-Scanner/1.0",
            "Accept": "application/json, text/html, */*"
        }

        for path in self.SCHEMA_PATHS:
            endpoint_url = f"{base_url}{path}"
            try:
                resp = requests.get(
                    endpoint_url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )

                if resp.status_code != 200 or len(resp.text) < 20:
                    continue

                content_type = resp.headers.get("Content-Type", "").lower()

                # 1. Check for JSON / YAML Schema Definitions
                if "application/json" in content_type or path.endswith(".json") or path.endswith("docs"):
                    try:
                        spec = resp.json()
                        is_openapi = "openapi" in spec or "swagger" in spec or "paths" in spec
                        if is_openapi:
                            found_schema_spec = True
                            api_title = spec.get("info", {}).get("title", "Unnamed API")
                            api_version = spec.get("info", {}).get("version", "1.0")
                            paths_dict = spec.get("paths", {})
                            path_count = len(paths_dict)
                            sample_paths = list(paths_dict.keys())[:6]

                            # Check for sensitive paths
                            sensitive_paths = [p for p in paths_dict.keys() if any(s in p.lower() for s in ("admin", "auth", "token", "user", "secret", "internal", "config", "debug"))]
                            severity = Severity.HIGH if sensitive_paths or path_count > 15 else Severity.MEDIUM

                            findings.append(
                                Finding(
                                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                                    title=f"Publicly Accessible API Specification: {api_title} ({path})",
                                    description=(
                                        f"The OpenAPI/Swagger schema at '{path}' is exposed without authentication. "
                                        f"It catalogs {path_count} API endpoints (e.g. {', '.join(sample_paths)}). "
                                        + (f"Sensitive routes identified: {', '.join(sensitive_paths[:5])}. " if sensitive_paths else "")
                                        + "Attackers can reverse-engineer internal parameters, expected payloads, and authentication mechanisms."
                                    ),
                                    severity=severity,
                                    asset_id=asset.asset_id,
                                    port=port,
                                    service=f"HTTP/{port}",
                                    evidence=f"GET {path} returned {path_count} endpoints in '{api_title}' v{api_version} schema definition.",
                                    cve_id="CWE-200",
                                    cvss_score=7.1 if severity == Severity.HIGH else 5.3,
                                    validation_status=ValidationStatus.CONFIRMED
                                )
                            )
                            # Once primary JSON schema is confirmed, limit duplicate JSON checks
                            continue
                    except Exception:
                        pass

                # 2. Check for Interactive UI (Swagger UI, ReDoc, SpringDoc)
                if "text/html" in content_type:
                    body = resp.text
                    doc_engine = None
                    if "swagger-ui" in body or "Swagger UI" in body:
                        doc_engine = "Swagger UI"
                    elif "redoc" in body or "<redoc" in body:
                        doc_engine = "ReDoc"
                    elif "springdoc" in body:
                        doc_engine = "SpringDoc OpenAPI Portal"

                    if doc_engine:
                        findings.append(
                            Finding(
                                finding_id=f"find_{uuid.uuid4().hex[:8]}",
                                title=f"Exposed {doc_engine} Documentation Interface ({path})",
                                description=(
                                    f"An interactive {doc_engine} portal is publicly accessible at '{path}'. "
                                    "Unauthenticated users can browse API parameter documentation and directly execute interactive HTTP requests against production endpoints."
                                ),
                                severity=Severity.MEDIUM,
                                asset_id=asset.asset_id,
                                port=port,
                                service=f"HTTP/{port}",
                                evidence=f"GET {path} returned interactive {doc_engine} HTML portal (HTTP 200).",
                                cve_id="CWE-200",
                                cvss_score=5.3,
                                validation_status=ValidationStatus.CONFIRMED
                            )
                        )

            except Exception as e:
                logger.debug(f"API schema probe against {endpoint_url} encountered: {e}")

        return findings
