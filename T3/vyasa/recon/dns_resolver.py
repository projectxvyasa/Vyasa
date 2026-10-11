"""
DNS Resolution and Subdomain Discovery for VYASA.
"""

import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional

logger = logging.getLogger("vyasa.recon.dns")

DEFAULT_SUBDOMAIN_WORDLIST = [
    "api", "admin", "dev", "staging", "auth", "portal", "vpn",
    "mail", "corp", "internal", "test", "app", "dashboard", "gateway"
]


class DNSResolver:
    """Performs DNS lookups, reverse lookups, and subdomain enumeration."""

    def __init__(self, timeout: float = 1.0, max_threads: int = 20):
        self.timeout = timeout
        self.max_threads = max_threads

    def resolve_ip(self, host: str) -> Optional[str]:
        """Resolves hostname to its IPv4 address."""
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return None

    def reverse_dns(self, ip: str) -> Optional[str]:
        """Performs PTR reverse lookup for an IP."""
        try:
            host_info = socket.gethostbyaddr(ip)
            return host_info[0]
        except Exception:
            return None

    def probe_subdomains(self, domain: str, wordlist: Optional[List[str]] = None) -> List[Tuple[str, str]]:
        """
        Attempts DNS resolution across common subdomains.
        Returns list of (subdomain, ip) tuples for existing hosts.
        """
        words = wordlist or DEFAULT_SUBDOMAIN_WORDLIST
        found: List[Tuple[str, str]] = []

        # Avoid probing subdomains if the target is already an IP address
        if domain.replace(".", "").isdigit():
            return found

        def _check(sub: str) -> Optional[Tuple[str, str]]:
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                return fqdn, ip
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_sub = {executor.submit(_check, w): w for w in words}
            for future in as_completed(future_to_sub):
                res = future.result()
                if res:
                    found.append(res)
                    logger.info(f"Discovered active subdomain: {res[0]} -> {res[1]}")

        return found
