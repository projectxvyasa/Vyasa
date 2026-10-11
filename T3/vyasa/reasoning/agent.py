"""
AI Reasoning Agent for VYASA.
Orchestrates LLM-powered attack path correlation and next-step hypothesis formulation.
"""

import uuid
import json
import logging
from typing import List, Dict, Any, Optional
from vyasa.core.models import Asset, Finding, AttackPath, AttackStep, Severity
from vyasa.core.config import ReasoningConfig
from vyasa.core.llm_client import LLMClient
from vyasa.reasoning.prompts import (
    REASONING_SYSTEM_PROMPT,
    ATTACK_PATH_CORRELATION_PROMPT,
    NEXT_ACTION_DECISION_PROMPT
)
from vyasa.reasoning.attack_graph import AttackGraphBuilder

logger = logging.getLogger("vyasa.reasoning.agent")


class ReasoningAgent:
    """The central AI reasoning brain of VYASA."""

    def __init__(self, config: ReasoningConfig, llm_client: Optional[LLMClient] = None):
        self.config = config
        self.llm = llm_client
        self.graph_builder = AttackGraphBuilder()

    def correlate_attack_paths(self, assets: List[Asset], findings: List[Finding]) -> List[AttackPath]:
        """
        Synthesizes individual findings into composite attack paths using the LLM.
        Falls back to rule-based graph correlation if the local LLM endpoint is unreachable.
        """
        logger.info("Executing AI reasoning: Correlating findings into attack paths...")

        assets_payload = [
            {
                "asset_id": a.asset_id,
                "host": a.host,
                "open_ports": a.open_ports,
                "technologies": a.technologies
            }
            for a in assets
        ]
        findings_payload = [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity.value,
                "asset_id": f.asset_id,
                "cve_id": f.cve_id,
                "description": f.description[:200] if len(f.description) > 200 else f.description,
                "evidence": f.evidence[:200] if len(f.evidence) > 200 else f.evidence
            }
            for f in findings
        ]

        if self.llm:
            try:
                user_prompt = ATTACK_PATH_CORRELATION_PROMPT.format(
                    assets_json=json.dumps(assets_payload, indent=2, default=str),
                    findings_json=json.dumps(findings_payload, indent=2, default=str)
                )

                result = self.llm.structured_json_completion(
                    system_prompt=REASONING_SYSTEM_PROMPT,
                    user_prompt=user_prompt
                )

                raw_paths = result.get("attack_paths", [])
                attack_paths: List[AttackPath] = []
                for p in raw_paths:
                    steps = [
                        AttackStep(
                            step_order=s.get("step_order", i + 1),
                            title=s.get("title", f"Step {i+1}"),
                            action_taken=s.get("action_taken", ""),
                            source_finding_id=s.get("source_finding_id"),
                            technique=s.get("technique", "Generic Technique"),
                            target_asset_id=s.get("target_asset_id", assets[0].asset_id if assets else "unknown"),
                            impact=s.get("impact", "")
                        )
                        for i, s in enumerate(p.get("steps", []))
                    ]
                    attack_paths.append(
                        AttackPath(
                            path_id=f"path_{uuid.uuid4().hex[:8]}",
                            title=p.get("title", "Correlated Attack Path"),
                            narrative=p.get("narrative", ""),
                            steps=steps,
                            composite_severity=Severity(p.get("composite_severity", "HIGH")),
                            likelihood=p.get("likelihood", "Medium"),
                            business_impact=p.get("business_impact", "")
                        )
                    )
                if attack_paths:
                    return attack_paths
            except Exception as e:
                logger.warning(f"LLM correlation failed or endpoint offline ({e}). Using deterministic graph correlation fallback.")

        # Fallback Deterministic Correlation
        return self._heuristic_correlation(assets, findings)

    def _heuristic_correlation(self, assets: List[Asset], findings: List[Finding]) -> List[AttackPath]:
        """Built-in correlation heuristic linking information disclosure to direct exposure."""
        paths: List[AttackPath] = []
        actuator_finding = next((f for f in findings if "Actuator" in f.title), None)
        db_finding = next((f for f in findings if "Database" in f.title or "PostgreSQL" in f.title), None)

        if actuator_finding and db_finding:
            steps = [
                AttackStep(
                    step_order=1,
                    title="Harvest Database Credentials via Exposed Actuator",
                    action_taken="Query unauthenticated /actuator/env endpoint to extract spring.datasource.password.",
                    source_finding_id=actuator_finding.finding_id,
                    technique="T1552 - Unsecured Credentials",
                    target_asset_id=actuator_finding.asset_id,
                    impact="Obtained plaintext or decipherable database credentials."
                ),
                AttackStep(
                    step_order=2,
                    title="Direct Authentication to Exposed PostgreSQL Service",
                    action_taken="Connect directly to public port 5432 using harvested database credentials.",
                    source_finding_id=db_finding.finding_id,
                    technique="T1078 - Valid Accounts",
                    target_asset_id=db_finding.asset_id,
                    impact="Full read/write access to production database records."
                )
            ]
            paths.append(
                AttackPath(
                    path_id=f"path_{uuid.uuid4().hex[:8]}",
                    title="Exposed Credentials to Remote Database Takeover",
                    narrative=(
                        "An attacker begins by requesting the unauthenticated /actuator/env endpoint, "
                        "which reveals internal database connection credentials. Because port 5432 is "
                        "open to the internet without IP restrictions, the attacker directly connects "
                        "and gains full access to database records."
                    ),
                    steps=steps,
                    composite_severity=Severity.CRITICAL,
                    likelihood="High",
                    business_impact="Critical breach of customer data confidentiality, integrity, and regulatory non-compliance."
                )
            )

        # Attack Path 2: Permissive CORS with Credentials -> Cross-Origin Data Exfiltration
        cors_finding = next((f for f in findings if "CORS" in f.title and "Credentials" in f.title), None)
        api_finding = next((f for f in findings if "API Specification" in f.title or "GraphQL" in f.title or "Swagger" in f.title), None)
        if cors_finding:
            target_desc = api_finding.title if api_finding else "target API endpoints"
            steps = [
                AttackStep(
                    step_order=1,
                    title="Map Internal API Routes and Parameters",
                    action_taken="Analyze exposed API schemas or GraphQL introspection queries to discover sensitive endpoints.",
                    source_finding_id=api_finding.finding_id if api_finding else cors_finding.finding_id,
                    technique="T1592 - Gather Victim Host Information",
                    target_asset_id=cors_finding.asset_id,
                    impact="Identified authenticated API routes exposing customer PII and token state."
                ),
                AttackStep(
                    step_order=2,
                    title="Exploit Permissive CORS to Exfiltrate Authenticated Data",
                    action_taken="Host a malicious webpage that issues authenticated cross-origin fetch requests using victim session cookies.",
                    source_finding_id=cors_finding.finding_id,
                    technique="T1189 - Drive-by Compromise",
                    target_asset_id=cors_finding.asset_id,
                    impact="Exfiltrated authenticated API responses across origins, bypassing Same-Origin Policy."
                )
            ]
            paths.append(
                AttackPath(
                    path_id=f"path_{uuid.uuid4().hex[:8]}",
                    title="Cross-Origin Data Exfiltration via Permissive CORS",
                    narrative=(
                        f"An attacker discovers endpoints through {target_desc} and leverages the server's "
                        "dynamic reflection of arbitrary Origin headers with 'Access-Control-Allow-Credentials: true'. "
                        "By luring an authenticated victim to a malicious site, the attacker issues cross-origin requests "
                        "and reads private account data directly."
                    ),
                    steps=steps,
                    composite_severity=Severity.HIGH,
                    likelihood="High",
                    business_impact="Unauthorized exfiltration of authenticated customer records and breach of data privacy boundaries."
                )
            )

        # Attack Path 3: GraphQL Introspection to Schema Enumeration
        graphql_finding = next((f for f in findings if "GraphQL Schema Introspection" in f.title), None)
        if graphql_finding and not any(p.title.startswith("Cross-Origin") for p in paths):
            steps = [
                AttackStep(
                    step_order=1,
                    title="Execute GraphQL Introspection Query",
                    action_taken="Submit introspection query to /graphql to dump full type system and mutation signatures.",
                    source_finding_id=graphql_finding.finding_id,
                    technique="T1082 - System Information Discovery",
                    target_asset_id=graphql_finding.asset_id,
                    impact="Full reverse engineering of backend schema and private object types."
                ),
                AttackStep(
                    step_order=2,
                    title="Target Discovered Entity Fields & Mutations",
                    action_taken="Craft targeted queries against unauthenticated or poorly restricted sensitive fields discovered in the schema.",
                    source_finding_id=graphql_finding.finding_id,
                    technique="T1212 - Exploitation for Credential Access",
                    target_asset_id=graphql_finding.asset_id,
                    impact="Discovered administrative queries and sensitive fields accessible to unauthorized users."
                )
            ]
            paths.append(
                AttackPath(
                    path_id=f"path_{uuid.uuid4().hex[:8]}",
                    title="Backend Data Model Compromise via GraphQL Introspection",
                    narrative=(
                        "Unauthenticated schema introspection at the GraphQL endpoint enables an attacker to dump "
                        "all queries, mutations, and database model types, significantly accelerating targeted business logic exploitation."
                    ),
                    steps=steps,
                    composite_severity=Severity.MEDIUM,
                    likelihood="High",
                    business_impact="Full disclosure of internal data models and accelerated discovery of unauthorized API operations."
                )
            )

        return paths
