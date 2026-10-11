"""
Reconnaissance Engine for VYASA.
Coordinates DNS resolution, multi-threaded port scanning, and technology fingerprinting.
"""

import logging
from typing import List, Dict, Any, Optional
from vyasa.core.models import Asset
from vyasa.core.config import ReconConfig
from vyasa.recon.dns_resolver import DNSResolver
from vyasa.recon.port_scanner import PortScanner
from vyasa.recon.tech_detector import TechDetector
from vyasa.recon.crawler import WebCrawler

logger = logging.getLogger("vyasa.recon.engine")


class ReconEngine:
    """Orchestrates asset discovery and initial attack-surface mapping."""

    def __init__(self, config: ReconConfig):
        self.config = config
        self.dns_resolver = DNSResolver()
        self.port_scanner = PortScanner()
        self.tech_detector = TechDetector()
        self.crawler = WebCrawler()

    def discover_assets(self, target: str, notify=None) -> List[Asset]:
        """
        Discovers active assets, resolves IPs, scans for open ports,
        and fingerprints technologies running on open interfaces.
        """
        logger.info(f"Initiating reconnaissance on target: {target}")
        assets: List[Asset] = []

        # 1. Resolve Primary Host IP
        ip = self.dns_resolver.resolve_ip(target)
        if not ip and (target == "localhost" or target == "127.0.0.1"):
            ip = "127.0.0.1"

        if not ip:
            # Strict PoC: never invent an asset with assumed ports/technologies.
            # If the host cannot be resolved there is nothing to probe.
            logger.warning(f"Could not resolve IP for {target}. No asset created (strict evidence-only mode).")
            return assets

        # 2. Port Scan Primary Host
        logger.info(f"Scanning ports on primary host: {target} ({ip})...")
        open_ports_dict = self.port_scanner.scan_target(ip)
        open_ports = list(open_ports_dict.keys())
        logger.info(f"Discovered {len(open_ports)} open port(s) on {target}: {open_ports}")

        # 3. Fingerprint Technologies
        techs, meta = self.tech_detector.detect_technologies(target, open_ports)
        meta["port_banners"] = open_ports_dict

        # 4. Crawl Target Endpoints & Parameters
        web_ports = [p for p in open_ports if p in (80, 443, 8000, 8080, 8443)]
        port = 443 if 443 in web_ports else (8080 if 8080 in web_ports else (80 if 80 in web_ports else 80))
        scheme = "https" if port in (443, 8443) else "http"
        port_suffix = f":{port}" if port not in (80, 443) else ""
        crawl_start_url = f"{scheme}://{target}{port_suffix}/"

        try:
            def _on_page(path, url):
                if notify:
                    notify("CRAWL", f"Discovered endpoint {path}", {"path": path, "url": url})
            endpoints, crawled_urls, forms = self.crawler.crawl(crawl_start_url, on_page=_on_page)
            meta["endpoints"] = endpoints
            meta["crawled_urls"] = crawled_urls
            meta["forms"] = forms
            logger.info(f"Crawled {len(crawled_urls)} pages, found {len(endpoints)} endpoints with parameters.")
        except Exception as crawl_err:
            logger.debug(f"Crawler execution error: {crawl_err}")
            meta["endpoints"] = []
            meta["crawled_urls"] = []
            meta["forms"] = []

        primary_asset = Asset(
            asset_id=f"asset_{target.replace('.', '_')}",
            host=target,
            ip=ip,
            open_ports=open_ports,          # only ports actually observed open
            technologies=techs,             # only technologies actually fingerprinted
            metadata=meta
        )
        assets.append(primary_asset)

        # 4. Subdomain Discovery (if enabled and applicable)
        if self.config.subdomain_enumeration and not target.replace(".", "").isdigit() and target not in ("localhost", "127.0.0.1"):
            logger.info(f"Probing subdomains for {target}...")
            subs = self.dns_resolver.probe_subdomains(target)
            for sub_host, sub_ip in subs:
                sub_ports_dict = self.port_scanner.scan_target(sub_ip, ports=[80, 443, 8080, 8443, 5432, 3306])
                sub_ports = list(sub_ports_dict.keys())
                sub_techs, sub_meta = self.tech_detector.detect_technologies(sub_host, sub_ports)
                sub_meta["port_banners"] = sub_ports_dict

                assets.append(
                    Asset(
                        asset_id=f"asset_{sub_host.replace('.', '_')}",
                        host=sub_host,
                        ip=sub_ip,
                        open_ports=sub_ports,
                        technologies=sub_techs,
                        metadata=sub_meta
                    )
                )

        logger.info(f"Reconnaissance completed: {len(assets)} asset(s) mapped.")
        return assets
