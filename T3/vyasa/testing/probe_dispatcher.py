"""
Targeted Probe Dispatcher for VYASA.
Executes real network connections and HTTP probes based on AI reasoning decisions.
"""

import uuid
import socket
import logging
from typing import List, Tuple, Optional
import requests
from vyasa.core.models import Asset, Finding, Severity, ValidationStatus
from vyasa.core.state import EngagementState, InvestigationRecord
from vyasa.reasoning.decision_engine import InvestigationDecision
from vyasa.testing.cors_auditor import CORSAuditor
from vyasa.testing.graphql_auditor import GraphQLAuditor
from vyasa.testing.api_schema_auditor import APISchemaAuditor

logger = logging.getLogger("vyasa.testing.dispatcher")


class ProbeDispatcher:
    """Executes precision probes directed by the AI reasoning loop."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.cors_auditor = CORSAuditor(timeout=timeout)
        self.graphql_auditor = GraphQLAuditor(timeout=timeout)
        self.api_schema_auditor = APISchemaAuditor(timeout=timeout)

    def execute_decision(
        self,
        decision: InvestigationDecision,
        state: EngagementState
    ) -> Tuple[InvestigationRecord, List[Finding]]:
        """
        Executes real investigative probes and produces evidence-backed findings only.
        """
        target_asset = state.get_asset_by_id(decision.target_asset_id)
        asset_host = target_asset.host if target_asset else "Unknown"
        logger.info(f"Executing probe: {decision.action_type} -> {asset_host}{decision.target_resource}")

        new_findings: List[Finding] = []
        outcome = ""

        if decision.action_type == "PROBE_HTTP_ENDPOINT":
            outcome, new_findings = self._probe_http(target_asset, decision.target_resource)

        elif decision.action_type == "CHECK_PORT_BANNER":
            outcome, new_findings = self._probe_tcp_port(target_asset, decision.target_resource)

        elif decision.action_type == "TEST_UNAUTH_API":
            outcome, new_findings = self._probe_unauth_api(target_asset, decision.target_resource)

        elif decision.action_type == "AUDIT_CORS_POLICY":
            outcome, new_findings = self._probe_cors(target_asset, decision.target_resource)

        elif decision.action_type == "PROBE_GRAPHQL_INTROSPECTION":
            outcome, new_findings = self._probe_graphql(target_asset, decision.target_resource)

        elif decision.action_type == "DISCOVER_API_SCHEMAS":
            outcome, new_findings = self._probe_api_schemas(target_asset, decision.target_resource)

        else:
            outcome = f"Action {decision.action_type} evaluated."

        record = InvestigationRecord(
            iteration=state.iteration + 1,
            target_asset_id=decision.target_asset_id,
            action_type=decision.action_type,
            target_resource=decision.target_resource,
            hypothesis=decision.hypothesis,
            rationale=decision.rationale,
            outcome_summary=outcome,
            new_findings_count=len(new_findings)
        )

        return record, new_findings

    def _probe_http(self, asset: Optional[Asset], path: str) -> Tuple[str, List[Finding]]:
        """Executes HTTP probe against target endpoint."""
        findings: List[Finding] = []
        host = asset.host if asset else "localhost"
        port = 8080 if asset and 8080 in asset.open_ports else (443 if asset and 443 in asset.open_ports else 80)
        scheme = "https" if port in (443, 8443) else "http"
        port_suffix = f":{port}" if port not in (80, 443) else ""
        url = f"{scheme}://{host}{port_suffix}{path}"

        # Signatures that indicate the endpoint actually leaked sensitive data,
        # not merely that it returned HTTP 200.
        sensitive_signatures = {
            "/actuator/env": ("propertySources", "Spring Boot Actuator environment properties exposed"),
            "/actuator/health": ("status", "Spring Boot Actuator health endpoint exposed"),
            "/.env": ("DB_PASSWORD", "Environment secrets exposed via .env"),
            "/.git/head": ("ref: refs/heads", "Git repository metadata exposed"),
        }

        try:
            resp = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "VYASA-Security-Auditor/1.0"}
            )
            outcome = f"HTTP GET {path} returned status {resp.status_code} ({len(resp.text)} bytes)."

            # Strict PoC: only report when a real 200 response carries a signature
            # proving sensitive content, or a known-sensitive path is confirmed live.
            sig_key = next((k for k in sensitive_signatures if path.lower().startswith(k)), None)
            if resp.status_code == 200 and sig_key:
                signature, meaning = sensitive_signatures[sig_key]
                if signature.lower() in resp.text.lower():
                    findings.append(
                        Finding(
                            finding_id=f"find_{uuid.uuid4().hex[:8]}",
                            title=f"Confirmed Sensitive Endpoint Exposure: {path}",
                            description=f"{meaning}. Endpoint '{path}' is publicly accessible without authentication.",
                            severity=Severity.HIGH,
                            asset_id=asset.asset_id if asset else "asset_unknown",
                            port=port,
                            service="HTTP",
                            evidence=f"GET {path} -> HTTP 200, body matched signature '{signature}' (Content-Length: {len(resp.text)}).",
                            cve_id="CWE-200",
                            cvss_score=7.5,
                            validation_status=ValidationStatus.CONFIRMED
                        )
                    )
                    outcome = f"Confirmed exposure: {path} returned 200 and leaked '{signature}'."
            # No finding on non-200, missing signature, or connection error (no fabrication).
        except Exception as e:
            outcome = f"HTTP probe against {path} failed to connect ({e.__class__.__name__}); no finding emitted."

        return outcome, findings

    def _probe_tcp_port(self, asset: Optional[Asset], port_str: str) -> Tuple[str, List[Finding]]:
        """Tests live TCP connectivity to specified port."""
        findings: List[Finding] = []
        host = asset.ip or (asset.host if asset else "127.0.0.1")
        port = int(port_str) if port_str.isdigit() else 5432

        is_connected = False
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                if s.connect_ex((host, port)) == 0:
                    is_connected = True
        except Exception:
            pass

        # Strict PoC: only report when the TCP handshake actually succeeds.
        if not is_connected:
            outcome = f"TCP connection to {host}:{port} failed or was filtered; no finding emitted."
            return outcome, findings

        outcome = f"TCP handshake to {host}:{port} succeeded. Service is publicly accessible."
        findings.append(
            Finding(
                finding_id=f"find_{uuid.uuid4().hex[:8]}",
                title=f"Exposed Database Listener (Port {port})",
                description=f"Port {port} accepted a direct TCP connection from the scanner, indicating missing network segmentation.",
                severity=Severity.HIGH,
                asset_id=asset.asset_id if asset else "asset_unknown",
                port=port,
                service="PostgreSQL" if port == 5432 else (f"Port/{port}"),
                evidence=f"TCP handshake to {host}:{port} succeeded (connect_ex == 0).",
                cve_id="CWE-284",
                cvss_score=8.1,
                validation_status=ValidationStatus.CONFIRMED
            )
        )
        return outcome, findings

    def _probe_unauth_api(self, asset: Optional[Asset], route: str) -> Tuple[str, List[Finding]]:
        """Tests an internal debugging or admin API route with a real unauthenticated request."""
        findings: List[Finding] = []
        base_url, port = self._get_base_url_and_port(asset)
        route_path = route if route.startswith("/") else f"/{route}"
        url = f"{base_url}{route_path}"

        try:
            resp = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
                headers={"User-Agent": "VYASA-Security-Auditor/1.0"}
            )
        except Exception as e:
            return f"Unauth API probe {route_path} failed to connect ({e.__class__.__name__}); no finding emitted.", findings

        outcome = f"GET {route_path} (no credentials) returned HTTP {resp.status_code} ({len(resp.text)} bytes)."

        # Strict PoC: only a 200 with a real body proves the route is reachable
        # without authentication. 401/403/404/redirects are NOT findings.
        if resp.status_code == 200 and len(resp.text) > 10:
            findings.append(
                Finding(
                    finding_id=f"find_{uuid.uuid4().hex[:8]}",
                    title=f"Unauthenticated Route Reachable ({route_path})",
                    description=f"Route '{route_path}' returned HTTP 200 without any authentication, exposing its response to anonymous users.",
                    severity=Severity.MEDIUM,
                    asset_id=asset.asset_id if asset else "asset_unknown",
                    port=port,
                    service="HTTP-API",
                    evidence=f"GET {route_path} with no credentials -> HTTP 200 (Content-Length: {len(resp.text)}).",
                    cve_id="CWE-306",
                    cvss_score=6.5,
                    validation_status=ValidationStatus.CONFIRMED
                )
            )
        return outcome, findings

    def _get_base_url_and_port(self, asset: Optional[Asset]) -> Tuple[str, int]:
        """Resolves target base URL and representative port for an asset."""
        host = asset.host if asset else "localhost"
        port = 443 if asset and 443 in asset.open_ports else (8080 if asset and 8080 in asset.open_ports else (80 if asset and 80 in asset.open_ports else 8000))
        scheme = "https" if port in (443, 8443) else "http"
        port_suffix = f":{port}" if port not in (80, 443) else ""
        return f"{scheme}://{host}{port_suffix}", port

    def _probe_cors(self, asset: Optional[Asset], target_resource: str) -> Tuple[str, List[Finding]]:
        """Executes targeted CORS origin reflection audit."""
        base_url, port = self._get_base_url_and_port(asset)
        target_url = f"{base_url}{target_resource}" if target_resource.startswith("/") else base_url
        findings = self.cors_auditor.audit_cors(asset or Asset(asset_id="asset_unknown", host="localhost"), port, target_url)

        if findings:
            outcome = f"CORS policy probe against {target_url} flagged {len(findings)} policy violation(s)."
        else:
            outcome = f"CORS audit against {target_url} evaluated: No permissive origin reflection detected."

        return outcome, findings

    def _probe_graphql(self, asset: Optional[Asset], target_resource: str) -> Tuple[str, List[Finding]]:
        """Executes targeted GraphQL introspection and console audit."""
        base_url, port = self._get_base_url_and_port(asset)
        findings = self.graphql_auditor.audit_graphql(asset or Asset(asset_id="asset_unknown", host="localhost"), port, base_url)

        if findings:
            outcome = f"GraphQL probe against {base_url} discovered {len(findings)} schema and console exposure(s)."
        else:
            outcome = f"GraphQL audit against {base_url} completed: No active GraphQL endpoints discovered."

        return outcome, findings

    def _probe_api_schemas(self, asset: Optional[Asset], target_resource: str) -> Tuple[str, List[Finding]]:
        """Executes targeted OpenAPI and Swagger documentation discovery."""
        base_url, port = self._get_base_url_and_port(asset)
        findings = self.api_schema_auditor.audit_api_schemas(asset or Asset(asset_id="asset_unknown", host="localhost"), port, base_url)

        if findings:
            outcome = f"API schema discovery against {base_url} identified {len(findings)} exposed definition(s)."
        else:
            outcome = f"API schema probe against {base_url} completed: No public API schemas exposed."

        return outcome, findings

