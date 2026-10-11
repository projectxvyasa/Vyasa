"""
Report Preferences & Interactive Wizard for VYASA.
Enables users to customize the exact sections and telemetry included in generated reports.
"""

import sys
from vyasa.core.models import ReportPreferences


def prompt_report_preferences_cli(auto_default: bool = False) -> ReportPreferences:
    """
    Prompts the user in the terminal to configure their custom report preferences.
    If stdin is non-interactive or auto_default is set, returns default full report preferences.
    """
    if auto_default or not sys.stdin.isatty():
        return ReportPreferences()

    print("\n" + "="*70)
    print("📋 CUSTOMIZE YOUR SECURITY AUDIT REPORT DELIVERABLES")
    print("Choose which sections and telemetry you want to include:")
    print("="*70)

    def ask_yes_no(question: str, default: bool = True) -> bool:
        prompt_str = f"[?] {question} [{'Y/n' if default else 'y/N'}]: "
        try:
            choice = input(prompt_str).strip().lower()
            if not choice:
                return default
            return choice.startswith("y")
        except (EOFError, KeyboardInterrupt):
            print()
            return default

    exec_sum = ask_yes_no("1. Include Executive Summary?", default=True)
    telemetry = ask_yes_no("2. Include AI Model Investigation Telemetry ('What the model tried & what it got')?", default=True)
    attack_paths = ask_yes_no("3. Include Mermaid Attack Path Kill Chains?", default=True)
    vuln_catalog = ask_yes_no("4. Include Discovered Vulnerability Catalog?", default=True)
    test_matrix = ask_yes_no("5. Include Full 100+ Vulnerability Test Matrix & Evaluation Status?", default=True)
    raw_evidence = ask_yes_no("6. Include Technical Evidence (Raw HTTP Requests & Responses)?", default=True)
    roadmap = ask_yes_no("7. Include Prioritized Remediation Roadmap?", default=True)

    print("\n[+] Report preferences configured successfully!\n")

    return ReportPreferences(
        include_executive_summary=exec_sum,
        include_investigation_telemetry=telemetry,
        include_attack_paths=attack_paths,
        include_vulnerability_catalog=vuln_catalog,
        include_full_test_matrix=test_matrix,
        include_raw_evidence=raw_evidence,
        include_remediation_roadmap=roadmap
    )


def prompt_vulnerability_selection_cli():
    """
    Prompts the CLI user to select specific vulnerability categories or checks,
    and optionally an endpoint path.
    Returns: (selected_checks, selected_categories, target_endpoint)
    """
    if not sys.stdin.isatty():
        return None, None, None

    print("\n" + "="*70)
    print("🎯 SELECTIVE VULNERABILITY TARGETING & SCOPE")
    print("Reduce scan time and server load by focusing only on suspected flaws:")
    print("="*70)
    print("  [1] All 100+ Catalog Checks (Full Audit)")
    print("  [2] SQLi & Injection Canaries (INJ-01 to INJ-15)")
    print("  [3] Authentication & Sessions (AUTH-01 to AUTH-15)")
    print("  [4] Broken Object-Level Authorization - BOLA (AUTHZ-01 to AUTHZ-15)")
    print("  [5] Business Logic Flaws (LOGIC-01 to LOGIC-15)")
    print("  [6] API Security & GraphQL (API-01 to API-15)")
    print("  [7] Security Misconfigurations (CONF-01 to CONF-15)")
    print("  [8] Information Disclosure (INFO-01 to INFO-10)")
    print("  [9] Custom Check ID(s) (e.g., INJ-01, API-05)")

    selected_checks = None
    selected_categories = None
    target_endpoint = None

    try:
        choice = input("\n[?] Select vulnerability focus [1-9, default: 1]: ").strip()
        if choice == "2":
            selected_categories = ["Injection Canaries"]
        elif choice == "3":
            selected_categories = ["Authentication & Session"]
        elif choice == "4":
            selected_categories = ["Broken Access Control (BOLA)"]
        elif choice == "5":
            selected_categories = ["Business Logic"]
        elif choice == "6":
            selected_categories = ["API Security & GraphQL"]
        elif choice == "7":
            selected_categories = ["Security Misconfiguration"]
        elif choice == "8":
            selected_categories = ["Information Disclosure"]
        elif choice == "9":
            raw_ids = input("[?] Enter comma-separated Check IDs (e.g. INJ-01, CONF-03): ").strip()
            if raw_ids:
                selected_checks = [c.strip().upper() for c in raw_ids.split(",") if c.strip()]

        ep_input = input("[?] Target specific endpoint path (e.g., /api/search) [Press Enter for full host]: ").strip()
        if ep_input:
            target_endpoint = ep_input

    except (EOFError, KeyboardInterrupt):
        print()

    print("[+] Vulnerability targeting applied successfully.\n")
    return selected_checks, selected_categories, target_endpoint
