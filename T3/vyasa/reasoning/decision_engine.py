"""
Decision Engine for VYASA.
Drives the autonomous reasoning loop: "What should be investigated next and why?"
"""

import json
import logging
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from vyasa.core.state import EngagementState, InvestigationRecord
from vyasa.core.llm_client import LLMClient
from vyasa.reasoning.prompts import REASONING_SYSTEM_PROMPT

logger = logging.getLogger("vyasa.reasoning.decision")


class InvestigationDecision(BaseModel):
    """The AI's next investigative move with reasoning."""
    action_type: str = Field(description="Type of test: 'PROBE_HTTP_ENDPOINT', 'CHECK_PORT_BANNER', 'TEST_UNAUTH_API', 'AUDIT_CORS_POLICY', 'PROBE_GRAPHQL_INTROSPECTION', 'DISCOVER_API_SCHEMAS', 'STOP'")
    target_asset_id: str
    target_resource: str = Field(description="e.g. '/actuator/env', '/graphql', 'cors', port number '5432', or API route")
    hypothesis: str = Field(description="What the AI suspects might be vulnerable")
    rationale: str = Field(description="Why this investigation is prioritized based on previous findings")
    stop_investigation: bool = Field(default=False, description="Set to true if no further meaningful investigation is needed")


DECISION_LOOP_PROMPT = """You are the Lead AI Security Engineer in an ongoing autonomous penetration test.
Review the current engagement state and decide the single most critical NEXT step to investigate.

TARGET SCOPE: {target_scope}
CURRENT ITERATION: {iteration} of {max_iterations}

DISCOVERED ASSETS:
{assets_json}

KNOWN FINDINGS SO FAR:
{findings_json}

PREVIOUS INVESTIGATION ACTIONS ALREADY CONDUCTED:
{history_json}

Your Task:
1. Review what is already known and what has already been probed.
2. Determine: "What should be investigated next and why?"
3. Formulate a testable hypothesis (e.g. "Because web API endpoints are detected, test for GraphQL introspection or permissive CORS origin reflection").
4. If sufficient evidence has been gathered to construct high-impact attack paths, or no further probes are relevant, set "stop_investigation": true.

Output strictly valid JSON conforming to this schema:
{{
  "action_type": "PROBE_HTTP_ENDPOINT" | "CHECK_PORT_BANNER" | "TEST_UNAUTH_API" | "AUDIT_CORS_POLICY" | "PROBE_GRAPHQL_INTROSPECTION" | "DISCOVER_API_SCHEMAS" | "STOP",
  "target_asset_id": "asset_id_to_probe",
  "target_resource": "path_or_port_to_test",
  "hypothesis": "Concrete vulnerability hypothesis",
  "rationale": "Logical explanation of why this step is critical right now",
  "stop_investigation": false
}}
"""


class DecisionEngine:
    """Evaluates engagement state to produce targeted next-action hypotheses."""

    def __init__(self, llm_client: Optional[LLMClient] = None):
        self.llm = llm_client

    def decide_next_step(self, state: EngagementState) -> InvestigationDecision:
        """Determines the next probe to execute based on current findings and history."""
        logger.info(f"[Reasoning Loop] Evaluating state for iteration {state.iteration + 1}...")

        if state.iteration >= state.max_iterations:
            return InvestigationDecision(
                action_type="STOP",
                target_asset_id="",
                target_resource="",
                hypothesis="Maximum iterations reached.",
                rationale="Reaching configured engagement depth boundary.",
                stop_investigation=True
            )

        if self.llm:
            try:
                assets_data = [
                    {
                        "asset_id": a.asset_id,
                        "host": a.host,
                        "ip": a.ip,
                        "open_ports": a.open_ports,
                        "technologies": a.technologies
                    }
                    for a in state.assets
                ]
                findings_data = [
                    {
                        "finding_id": f.finding_id,
                        "title": f.title,
                        "severity": f.severity.value,
                        "asset_id": f.asset_id,
                        "port": f.port,
                        "service": f.service,
                        "evidence": f.evidence[:200] if len(f.evidence) > 200 else f.evidence
                    }
                    for f in state.findings[-20:]  # Keep latest 20 findings to prevent token bloat
                ]
                history_data = [
                    {
                        "action_type": h.action_type,
                        "target_resource": h.target_resource,
                        "outcome": h.outcome_summary[:150] if len(h.outcome_summary) > 150 else h.outcome_summary
                    }
                    for h in state.investigation_history
                ]

                user_prompt = DECISION_LOOP_PROMPT.format(
                    target_scope=state.target_scope,
                    iteration=state.iteration + 1,
                    max_iterations=state.max_iterations,
                    assets_json=json.dumps(assets_data, indent=2, default=str),
                    findings_json=json.dumps(findings_data, indent=2, default=str),
                    history_json=json.dumps(history_data, indent=2, default=str)
                )

                result = self.llm.structured_json_completion(
                    system_prompt=REASONING_SYSTEM_PROMPT,
                    user_prompt=user_prompt
                )

                decision = InvestigationDecision(**result)
                logger.info(f"AI Decision formulated: {decision.action_type} on {decision.target_resource}")
                return decision
            except Exception as e:
                logger.warning(f"LLM decision reasoning failed ({e}). Employing autonomous heuristic reasoning.")

        # Fallback Dynamic Heuristic Loop
        return self._heuristic_decision(state)

    def _heuristic_decision(self, state: EngagementState) -> InvestigationDecision:
        """Rule-based decision tree when local LLM is offline or initializing."""
        tested_resources = {h.target_resource for h in state.investigation_history}

        # Step 1: Look for unprobed web actuator or admin endpoints
        for asset in state.assets:
            if 8080 in asset.open_ports and "/actuator/env" not in tested_resources:
                return InvestigationDecision(
                    action_type="PROBE_HTTP_ENDPOINT",
                    target_asset_id=asset.asset_id,
                    target_resource="/actuator/env",
                    hypothesis="Spring Boot actuator may be exposed without authentication, leaking credentials.",
                    rationale="Port 8080 is running Spring Boot. Actuator endpoints often leak sensitive connection strings.",
                    stop_investigation=False
                )

        # Step 2: Check for exposed API schemas (OpenAPI / Swagger)
        for asset in state.assets:
            has_web = any(p in asset.open_ports for p in (80, 443, 8000, 8080)) or "api" in asset.host
            if has_web and "/openapi.json" not in tested_resources:
                return InvestigationDecision(
                    action_type="DISCOVER_API_SCHEMAS",
                    target_asset_id=asset.asset_id,
                    target_resource="/openapi.json",
                    hypothesis="Target web services may publish unauthenticated OpenAPI / Swagger schemas revealing internal routes and data models.",
                    rationale="API schema discovery maps attack surface for unauthenticated parameter manipulation.",
                    stop_investigation=False
                )

        # Step 3: Check for GraphQL Introspection & Playgrounds
        for asset in state.assets:
            has_web = any(p in asset.open_ports for p in (80, 443, 8000, 8080))
            if has_web and "/graphql" not in tested_resources:
                return InvestigationDecision(
                    action_type="PROBE_GRAPHQL_INTROSPECTION",
                    target_asset_id=asset.asset_id,
                    target_resource="/graphql",
                    hypothesis="Web endpoint may host a GraphQL server with schema introspection enabled, leaking internal entity definitions.",
                    rationale="GraphQL introspection allows reverse-engineering database structures and administrative mutations.",
                    stop_investigation=False
                )

        # Step 4: Audit CORS origin reflection and credentials handling
        for asset in state.assets:
            has_web = any(p in asset.open_ports for p in (80, 443, 8000, 8080))
            if has_web and "cors_policy" not in tested_resources:
                return InvestigationDecision(
                    action_type="AUDIT_CORS_POLICY",
                    target_asset_id=asset.asset_id,
                    target_resource="cors_policy",
                    hypothesis="API endpoints may dynamically reflect untrusted origins with Access-Control-Allow-Credentials: true.",
                    rationale="Cross-Origin Resource Sharing vulnerabilities enable authenticated cross-origin data exfiltration.",
                    stop_investigation=False
                )

        # Step 5: Check exposed database ports for credential exposure correlation
        for asset in state.assets:
            if 5432 in asset.open_ports and "5432" not in tested_resources:
                return InvestigationDecision(
                    action_type="CHECK_PORT_BANNER",
                    target_asset_id=asset.asset_id,
                    target_resource="5432",
                    hypothesis="Database port 5432 is publicly exposed and vulnerable to direct connection.",
                    rationale="Correlating whether credentials obtained from previous web tiers allow direct database pivoting.",
                    stop_investigation=False
                )

        # Step 6: Check for internal API debug endpoints
        for asset in state.assets:
            if "api-internal" in asset.host and "/api/v1/debug" not in tested_resources:
                return InvestigationDecision(
                    action_type="TEST_UNAUTH_API",
                    target_asset_id=asset.asset_id,
                    target_resource="/api/v1/debug",
                    hypothesis="Internal API subdomain may lack authentication on administrative debugging routes.",
                    rationale="Subdomain reconnaissance identified internal service exposure.",
                    stop_investigation=False
                )

        # Conclude investigation if all high-priority hypotheses were explored
        return InvestigationDecision(
            action_type="STOP",
            target_asset_id="",
            target_resource="",
            hypothesis="All key attack hypotheses have been validated.",
            rationale="Sufficient evidence acquired to synthesize comprehensive multi-hop attack paths.",
            stop_investigation=True
        )
