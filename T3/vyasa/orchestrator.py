"""
VYASA Orchestrator Engine.
Coordinates the autonomous penetration testing workflow:
Reconnaissance -> Baseline Probing -> Autonomous AI Reasoning Loop -> Attack Path Correlation -> Report
"""

import logging
from typing import List, Optional
from vyasa.core.config import AppConfig
from vyasa.core.models import AuditReport, ReportPreferences, InvestigationTelemetry
from vyasa.core.state import EngagementState
from vyasa.core.llm_client import LLMClient
from vyasa.recon.engine import ReconEngine
from vyasa.testing.scanner_manager import ScannerManager
from vyasa.testing.deep_scanner import DeepScanner
from vyasa.testing.probe_dispatcher import ProbeDispatcher
from vyasa.reasoning.decision_engine import DecisionEngine
from vyasa.reasoning.agent import ReasoningAgent
from vyasa.validation.validator import VulnerabilityValidator
from vyasa.reporting.generator import ReportGenerator

logger = logging.getLogger("vyasa.orchestrator")


class VyasaOrchestrator:
    """The master orchestration engine connecting all platform phases."""

    def __init__(self, config: AppConfig, enable_dom_xss: bool = True, fast: bool = False, auth=None):
        self.config = config

        # Initialize LLM Client (OpenAI-compatible / local LM Studio / Bionic)
        try:
            self.llm_client = LLMClient(config.llm)
        except Exception as e:
            logger.warning(f"Could not connect to LLM: {e}. Running with heuristic reasoning engine.")
            self.llm_client = None

        # Initialize Subsystems
        self.recon_engine = ReconEngine(config.recon)
        self.scanner_manager = ScannerManager(config.testing)
        self.deep_scanner = DeepScanner(enable_dom_xss=enable_dom_xss, fast=fast, auth=auth)
        self.probe_dispatcher = ProbeDispatcher()
        self.decision_engine = DecisionEngine(self.llm_client)
        self.reasoning_agent = ReasoningAgent(config.reasoning, self.llm_client)
        self.validator = VulnerabilityValidator()
        self.report_generator = ReportGenerator(config.reporting)

    def run_engagement(
        self,
        target: str,
        progress_callback=None,
        deep_scan: bool = True,
        report_preferences: Optional[ReportPreferences] = None,
        selected_checks: Optional[List[str]] = None,
        selected_categories: Optional[List[str]] = None,
        target_endpoint: Optional[str] = None
    ) -> AuditReport:
        """
        Executes a full autonomous penetration testing engagement:
        1. Reconnaissance & Asset Discovery
        2. Baseline Security Testing
        3. Iterative AI Reasoning Loop ("What to investigate next and why")
        4. Attack Path Correlation
        5. Report Generation & Remediation Roadmap
        """
        from urllib.parse import urlparse
        if target.startswith("http://") or target.startswith("https://"):
            parsed_target = urlparse(target)
            target_host = parsed_target.hostname or target
            if parsed_target.path and parsed_target.path != "/" and not target_endpoint:
                target_endpoint = parsed_target.path
                if parsed_target.query:
                    target_endpoint += f"?{parsed_target.query}"
            target = target_host

        def notify(phase: str, message: str, data: dict = None):
            if progress_callback:
                try:
                    progress_callback(phase, message, data or {})
                except Exception as cb_err:
                    logger.debug(f"Progress callback error: {cb_err}")

        logger.info(f"=== Starting VYASA Security Engagement for: {target} ===")
        notify("START", f"Initiating security audit on scope: {target}")

        # Phase 1: Reconnaissance
        print(f"\n[+] Phase 1: Reconnaissance & Attack-Surface Discovery ({target})")
        notify("RECON_START", "Mapping attack surface, resolving DNS, and scanning open ports...")
        assets = self.recon_engine.discover_assets(target, notify=notify)
        print(f"    Discovered {len(assets)} active asset(s).")
        notify("RECON_COMPLETE", f"Discovered {len(assets)} active asset(s).", {"assets": [a.model_dump() for a in assets]})

        # Phase 2: Initial Baseline Probing & 100+ Check Deep Scan
        print(f"\n[+] Phase 2: Baseline Security Testing")
        notify("TESTING_START", "Auditing security headers, SSL/TLS, and exposed service ports...")
        initial_findings = self.scanner_manager.run_security_testing(assets)
        print(f"    Identified {len(initial_findings)} initial baseline finding(s).")
        notify("TESTING_COMPLETE", f"Identified {len(initial_findings)} initial security findings.", {"findings": [f.model_dump() for f in initial_findings]})

        investigation_telemetry: List[InvestigationTelemetry] = []

        if deep_scan and assets:
            sel_label = f"{len(selected_checks)} selected checks" if selected_checks else ("targeted category" if selected_categories else "100+ check catalog")
            ep_label = f" on endpoint '{target_endpoint}'" if target_endpoint else ""
            notify("DEEP_SCAN_START", f"Executing {sel_label}{ep_label} across target scope...")
            for asset in assets:
                deep_findings, telemetry_records = self.deep_scanner.run_deep_audit(
                    asset,
                    live_console=True,
                    selected_checks=selected_checks,
                    selected_categories=selected_categories,
                    target_endpoint=target_endpoint,
                    notify=notify
                )
                initial_findings.extend(deep_findings)
                investigation_telemetry.extend(telemetry_records)
            notify("DEEP_SCAN_COMPLETE", f"Deep scan finished. Captured {len(investigation_telemetry)} telemetry records.")

        # Initialize Engagement State
        state = EngagementState(
            target_scope=target,
            max_iterations=3,
            assets=assets,
            findings=initial_findings
        )

        # Phase 3: Autonomous AI Reasoning Loop
        print(f"\n[+] Phase 3: Autonomous AI Reasoning Loop (Investigative Decisions)")
        print("    The AI now evaluates findings to decide: 'What to investigate next and why?'")
        notify("REASONING_LOOP_START", "Autonomous AI Reasoning Loop activated. Evaluating findings for next investigative steps...")

        while not state.is_completed:
            iteration_num = state.iteration + 1
            print(f"\n    --- Iteration {iteration_num} of {state.max_iterations} ---")
            
            decision = self.decision_engine.decide_next_step(state)
            
            if decision.stop_investigation or decision.action_type == "STOP":
                print(f"    [*] AI Decision: Conclude targeted probing.")
                print(f"        Reason: {decision.rationale}")
                notify("REASONING_STOP", f"AI completed investigation: {decision.rationale}", {"decision": decision.model_dump()})
                break

            print(f"    [*] AI Decision: {decision.action_type} on '{decision.target_resource}'")
            print(f"        Hypothesis : {decision.hypothesis}")
            print(f"        Rationale  : {decision.rationale}")
            notify("REASONING_DECISION", f"AI Formulated Hypothesis: {decision.hypothesis}", {
                "iteration": iteration_num,
                "max_iterations": state.max_iterations,
                "decision": decision.model_dump()
            })

            # Dispatch probe and capture evidence
            record, new_findings = self.probe_dispatcher.execute_decision(decision, state)
            state.findings.extend(new_findings)
            state.record_investigation(record)

            investigation_telemetry.append(
                InvestigationTelemetry(
                    probe_id=f"REASON-{iteration_num}",
                    title=f"AI Investigation: {decision.action_type}",
                    category="AI Reasoning Loop",
                    endpoint=decision.target_resource,
                    method="PROBE",
                    request_summary=f"Hypothesis: {decision.hypothesis[:50]}",
                    response_summary=record.outcome_summary[:50],
                    verdict="VULNERABLE" if new_findings else "SECURE",
                    evidence_details=record.outcome_summary,
                    duration_ms=45.0
                )
            )

            print(f"        [+] Outcome: {record.outcome_summary}")
            print(f"        [+] New Findings Discovered: {len(new_findings)}")
            notify("PROBE_EXECUTED", f"Probe completed on {decision.target_resource}", {
                "record": record.model_dump(),
                "new_findings": [f.model_dump() for f in new_findings],
                "all_findings_count": len(state.findings)
            })

        # Phase 4: Validation & Attack Path Correlation
        print(f"\n[+] Phase 4: Attack Path Correlation & Risk Synthesis")
        notify("CORRELATION_START", "Correlating multi-hop kill chains and calculating business impact...")
        validated_findings = self.validator.validate_findings(state.findings)
        attack_paths = self.reasoning_agent.correlate_attack_paths(state.assets, validated_findings)
        print(f"    Synthesized {len(attack_paths)} composite attack path(s).")
        notify("CORRELATION_COMPLETE", f"Synthesized {len(attack_paths)} attack path(s).", {
            "attack_paths": [p.model_dump() for p in attack_paths]
        })

        for path in attack_paths:
            print(f"\n    --> Attack Path: {path.title} [{path.composite_severity.value}]")
            for step in path.steps:
                print(f"        Step {step.step_order}: {step.title} ({step.technique})")

        # Phase 5: Reporting
        print(f"\n[+] Phase 5: Actionable Security Report Generation")
        notify("REPORTING_START", "Synthesizing executive summary and prioritized remediation roadmap...")
        report = self.report_generator.generate_report(
            target=target,
            assets=state.assets,
            findings=validated_findings,
            attack_paths=attack_paths,
            investigation_telemetry=investigation_telemetry,
            preferences=report_preferences
        )
        print(f"    Report generated successfully: {report.report_id}")
        print(f"    Deliverables written to: {self.config.reporting.output_dir}/")
        notify("COMPLETED", f"Security Audit complete for {target}", {
            "report_id": report.report_id,
            "executive_summary": report.executive_summary,
            "report": report.model_dump()
        })

        print(f"\n=== Engagement Completed Successfully ===")
        return report
