"""
Web Technology and SSL/TLS Fingerprinting for VYASA.
"""

import ssl
import socket
import logging
from typing import List, Dict, Any, Optional, Tuple
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("vyasa.recon.tech_detector")


class TechDetector:
    """Fingerprints web applications, frameworks, web servers, and TLS certificates."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def detect_technologies(self, host: str, open_ports: List[int]) -> Tuple[List[str], Dict[str, Any]]:
        """Probes standard web ports and identifies technology signatures."""
        technologies: set[str] = set()
        metadata: Dict[str, Any] = {}

        # Determine target schemes to test
        web_targets = []
        if 443 in open_ports or 8443 in open_ports:
            web_targets.append(("https", host, 443 if 443 in open_ports else 8443))
        if 80 in open_ports or 8080 in open_ports or not web_targets:
            web_targets.append(("http", host, 80 if 80 in open_ports else (8080 if 8080 in open_ports else 80)))

        for scheme, target_host, port in web_targets:
            port_suffix = f":{port}" if port not in (80, 443) else ""
            url = f"{scheme}://{target_host}{port_suffix}/"

            try:
                resp = requests.get(
                    url,
                    timeout=self.timeout,
                    verify=False,  # Allow self-signed during security assessment
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                )

                metadata[f"{scheme}_{port}_status"] = resp.status_code

                # 1. Server Header
                server_hdr = resp.headers.get("Server")
                if server_hdr:
                    technologies.add(server_hdr)
                    metadata[f"{port}_server"] = server_hdr

                # 2. X-Powered-By
                powered_by = resp.headers.get("X-Powered-By")
                if powered_by:
                    technologies.add(powered_by)
                    metadata[f"{port}_powered_by"] = powered_by

                # 3. Cookie Heuristics
                for cookie_name in resp.cookies.keys():
                    c_upper = cookie_name.upper()
                    if "JSESSIONID" in c_upper:
                        technologies.add("Java/Servlet")
                    elif "PHPSESSID" in c_upper:
                        technologies.add("PHP")
                    elif "CONNECT.SID" in c_upper:
                        technologies.add("Node.js/Express")
                    elif "DJANGO" in c_upper or "CSRFTOKEN" in c_upper:
                        technologies.add("Django/Python")
                    elif "ASP.NET" in c_upper or "ASPSESSIONID" in c_upper:
                        technologies.add("ASP.NET")

                # 4. Body Content Signatures
                body_sample = resp.text[:4000].lower()
                if "wp-content" in body_sample or "wp-includes" in body_sample:
                    technologies.add("WordPress")
                if "drupal" in body_sample:
                    technologies.add("Drupal")
                if "react" in body_sample or "_next" in body_sample:
                    technologies.add("React/Next.js")
                if "spring" in body_sample or "whitelabel error page" in body_sample:
                    technologies.add("Spring Boot")

            except Exception as e:
                logger.debug(f"Could not connect to {url}: {e}")

        # Check TLS certificate details if port 443 is open
        if 443 in open_ports or any(scheme == "https" for scheme, _, _ in web_targets):
            cert_info = self._get_tls_certificate_info(host, 443 if 443 in open_ports else 8443)
            if cert_info:
                metadata["tls_certificate"] = cert_info
                technologies.add(f"TLS ({cert_info.get('tls_version', 'Unknown')})")

        return list(sorted(technologies)), metadata

    def _get_tls_certificate_info(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Extracts peer certificate issuer, subject, and validity."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    cipher = ssock.cipher()
                    return {
                        "tls_version": tls_version,
                        "cipher": cipher[0] if cipher else None,
                        "subject": dict(x[0] for x in cert.get("subject", [])) if cert else "Self-Signed/Unverified",
                        "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert else "Self-Signed/Unverified",
                        "expires": cert.get("notAfter") if cert else None
                    }
        except Exception:
            return None
