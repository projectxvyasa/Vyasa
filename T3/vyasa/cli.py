"""
Command Line Interface for VYASA.
"""

import argparse
import sys
import logging
from vyasa.core.config import load_config
from vyasa.orchestrator import VyasaOrchestrator
from vyasa.reporting.preferences import prompt_report_preferences_cli, prompt_vulnerability_selection_cli


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    parser = argparse.ArgumentParser(
        description="VYASA: Autonomous AI Penetration Testing & Attack Path Engine"
    )
    parser.add_argument(
        "-t", "--target",
        type=str,
        default=None,
        help="Target domain, IP, or network scope (e.g., example.com)"
    )
    parser.add_argument(
        "-e", "--endpoint",
        type=str,
        default=None,
        help="Specific endpoint path to target (e.g. /api/search or https://target/api/search)"
    )
    parser.add_argument(
        "--checks",
        type=str,
        default=None,
        help="Comma-separated check IDs to execute (e.g. INJ-01,CONF-03)"
    )
    parser.add_argument(
        "--category",
        type=str,
        default=None,
        help="Specific vulnerability category (e.g. injection, auth, bola, logic, api, conf, info)"
    )
    parser.add_argument(
        "-w", "--web",
        action="store_true",
        help="Launch the interactive VYASA Web Dashboard"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=8000,
        help="Port for the Web Dashboard server (default: 8000)"
    )
    parser.add_argument(
        "-c", "--config",
        type=str,
        default=None,
        help="Path to custom config.yaml file"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging"
    )
    parser.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Accept default report preferences without interactive prompt"
    )
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="Interactively customize which vulnerabilities and report sections to include"
    )
    parser.add_argument(
        "--no-deep",
        action="store_true",
        help="Skip the comprehensive vulnerability test catalog"
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Faster scan: skip the headless-browser pass, shorter time-based probes, fewer targets per check"
    )
    parser.add_argument(
        "--no-dom",
        action="store_true",
        help="Disable the headless-browser DOM/execution XSS pass (big speed-up on clean sites)"
    )
    parser.add_argument(
        "--cookie",
        type=str,
        default=None,
        help="Cookie header for authenticated scanning, e.g. \"session=abc; token=xyz\""
    )
    parser.add_argument(
        "-H", "--header",
        action="append",
        default=[],
        help="Extra request header for authenticated scanning (repeatable), e.g. -H \"Authorization: Bearer <jwt>\""
    )
    parser.add_argument(
        "--token",
        type=str,
        default=None,
        help="A JWT/bearer token to test (sent as Authorization: Bearer <token>) and analyze"
    )

    args = parser.parse_args()

    # Logging setup
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%H:%M:%S"
    )

    # 1. Web Dashboard Mode
    if args.web or not args.target:
        from vyasa.web.app import start_server
        start_server(host="127.0.0.1", port=args.port)
        return

    # 2. CLI Audit Mode
    config = load_config(args.config)

    # Build the authentication context for authenticated scanning.
    auth_headers = {}
    for h in (args.header or []):
        if ":" in h:
            k, v = h.split(":", 1)
            auth_headers[k.strip()] = v.strip()
    auth = {"headers": auth_headers, "cookie": args.cookie, "token": args.token}
    if auth_headers or args.cookie or args.token:
        logging.getLogger("vyasa.cli").info("Authenticated scan: applying provided credentials to all requests.")

    orchestrator = VyasaOrchestrator(config, enable_dom_xss=not args.no_dom, fast=args.fast, auth=auth)

    # Resolve selective checks & endpoint scoping
    selected_checks = [c.strip().upper() for c in args.checks.split(",") if c.strip()] if args.checks else None
    selected_categories = [args.category.strip()] if args.category else None
    target_endpoint = args.endpoint
    report_prefs = None

    if args.interactive:
        sel_c, sel_cats, ep = prompt_vulnerability_selection_cli()
        if sel_c:
            selected_checks = sel_c
        if sel_cats:
            selected_categories = sel_cats
        if ep:
            target_endpoint = ep
        report_prefs = prompt_report_preferences_cli(auto_default=False)
    elif not args.yes and sys.stdin.isatty():
        report_prefs = prompt_report_preferences_cli(auto_default=False)

    try:
        orchestrator.run_engagement(
            target=args.target,
            deep_scan=not args.no_deep,
            report_preferences=report_prefs,
            selected_checks=selected_checks,
            selected_categories=selected_categories,
            target_endpoint=target_endpoint
        )
    except KeyboardInterrupt:
        print("\n[!] Audit interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error during engagement: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
