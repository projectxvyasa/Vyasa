"""
GraphQL Security Auditor for VYASA.
Non-intrusively discovers GraphQL endpoints, tests for schema introspection,
exposed GraphiQL/Playground consoles, and field suggestions.
"""

import uuid
import logging
from typing import List, Dict, Any, Optional
import urllib3
import requests
from vyasa.core.models import Asset, Finding, Severity, ValidationStatus

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("vyasa.testing.graphql_auditor")


class GraphQLAuditor:
    """Audits GraphQL endpoints for introspection exposure, console access, and schema leakage."""

    COMMON_ENDPOINTS = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/query",
        "/graphiql",
        "/graphql/console",
        "/altair"
    ]

    INTROSPECTION_QUERY = {
        "query": "query IntrospectionQuery { __schema { queryType { name } types { name kind } } }"
    }

    SUGGESTION_PROBE_QUERY = {
        "query": "{ __vyasa_nonexistent_probe_field }"
    }

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def audit_graphql(self, asset: Asset, port: int, base_url: str) -> List[Finding]:
        """Runs non-intrusive GraphQL discovery and security checks."""
        findings: List[Finding] = []
        discovered_active_endpoint: Optional[str] = None

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VYASA-Security-Scanner/1.0",
            "Content-Type": "application/json",
            "Accept": "application/json, text/html"
        }

        for path in self.COMMON_ENDPOINTS:
            endpoint_url = f"{base_url}{path}"
            try:
                # 1. Test Introspection via POST
                post_resp = requests.post(
                    endpoint_url,
                    json=self.INTROSPECTION_QUERY,
                    headers=headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False
                )

                if post_resp.status_code == 200:
                    try:
                        data = post_resp.json()
                        schema = data.get("data", {}).get("__schema")
                        if schema:
                            discovered_active_endpoint = path
                            types_list = schema.get("types", [])
                            type_names = [t.get("name") for t in types_list if t.get("name") and not t.get("name", "").startswith("__")][:8]
                            sensitive_detected = any(any(k in name.lower() for k in ("user", "admin", "auth", "token", "order", "account", "secret")) for name in type_names)
                            severity = Severity.HIGH if sensitive_detected else Severity.MEDIUM

                            findings.append(
                                Finding(
                                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                                    title=f"GraphQL Schema Introspection Enabled ({path})",
                                    description=(
                                        f"The GraphQL service at '{path}' permits unauthenticated schema introspection. "
                                        f"Discovered {len(types_list)} schema types (including: {', '.join(type_names) if type_names else 'standard types'}). "
                                        "Attackers can reconstruct the complete data model, uncover hidden queries/mutations, and pinpoint backend logic."
                                    ),
                                    severity=severity,
                                    asset_id=asset.asset_id,
                                    port=port,
                                    service=f"HTTP/{port}",
                                    evidence=f"POST {path} with introspection payload returned HTTP 200 with schema definition ({len(types_list)} types).",
                                    cve_id="CWE-200",
                                    cvss_score=7.2 if severity == Severity.HIGH else 5.3,
                                    validation_status=ValidationStatus.CONFIRMED
                                )
                            )
                    except Exception:
                        pass

                # 2. Check for Exposed Interactive Playgrounds / Consoles via GET
                get_headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VYASA-Security-Scanner/1.0",
                    "Accept": "text/html"
                }
                get_resp = requests.get(
                    endpoint_url,
                    headers=get_headers,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=False
                )

                if get_resp.status_code == 200 and "text/html" in get_resp.headers.get("Content-Type", ""):
                    body = get_resp.text
                    console_type = None
                    if "GraphQL Playground" in body or "graphql-playground-html" in body:
                        console_type = "GraphQL Playground"
                    elif "<title>GraphiQL</title>" in body or "graphiql.min.js" in body:
                        console_type = "GraphiQL Console"
                    elif "altair-root" in body or "Altair GraphQL" in body:
                        console_type = "Altair GraphQL Client"

                    if console_type:
                        findings.append(
                            Finding(
                                finding_id=f"find_{uuid.uuid4().hex[:8]}",
                                title=f"Exposed {console_type} Interface ({path})",
                                description=(
                                    f"An interactive GraphQL developer tool ({console_type}) is publicly accessible at '{path}'. "
                                    "This simplifies query discovery and parameter enumeration for unauthenticated attackers."
                                ),
                                severity=Severity.MEDIUM,
                                asset_id=asset.asset_id,
                                port=port,
                                service=f"HTTP/{port}",
                                evidence=f"GET {path} returned interactive {console_type} HTML interface.",
                                cve_id="CWE-200",
                                cvss_score=5.0,
                                validation_status=ValidationStatus.CONFIRMED
                            )
                        )

                # 3. Test Field Suggestion Leakage if endpoint responded to GraphQL
                if discovered_active_endpoint == path:
                    sugg_resp = requests.post(
                        endpoint_url,
                        json=self.SUGGESTION_PROBE_QUERY,
                        headers=headers,
                        timeout=self.timeout,
                        verify=False
                    )
                    if "Did you mean" in sugg_resp.text:
                        findings.append(
                            Finding(
                                finding_id=f"find_{uuid.uuid4().hex[:8]}",
                                title=f"GraphQL Field Suggestion Enabled ({path})",
                                description=(
                                    f"The GraphQL server at '{path}' includes field suggestions ('Did you mean ...') in error responses. "
                                    "Even if introspection is disabled, attackers can brute-force internal field names using suggestion hints."
                                ),
                                severity=Severity.LOW,
                                asset_id=asset.asset_id,
                                port=port,
                                service=f"HTTP/{port}",
                                evidence=f"Invalid field query returned error with suggestion cues: {sugg_resp.text[:140]}...",
                                cve_id="CWE-200",
                                cvss_score=3.5,
                                validation_status=ValidationStatus.CONFIRMED
                            )
                        )
                    # Once verified on this endpoint, avoid duplicate checks on other alias routes
                    break

            except Exception as e:
                logger.debug(f"GraphQL probe against {endpoint_url} encountered: {e}")

        return findings
