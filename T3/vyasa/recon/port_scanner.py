"""
Multi-threaded TCP Port Scanner and Banner Grabber for VYASA.
"""

import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional

logger = logging.getLogger("vyasa.recon.port_scanner")

# Standard service ports frequently assessed in security audits
DEFAULT_COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9000, 27017
]


class PortScanner:
    """Performs multi-threaded TCP connect port scanning and banner identification."""

    def __init__(self, timeout: float = 0.8, max_threads: int = 50):
        self.timeout = timeout
        self.max_threads = max_threads

    def scan_port(self, target_ip: str, port: int) -> Tuple[int, bool, Optional[str]]:
        """Attempts a TCP handshake and captures service banner if available."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            result = s.connect_ex((target_ip, port))
            if result == 0:
                banner = self._grab_banner(s)
                return port, True, banner
            return port, False, None
        except Exception:
            return port, False, None
        finally:
            s.close()

    def _grab_banner(self, sock: socket.socket) -> Optional[str]:
        """Safely reads initial service banner if transmitted upon connection."""
        try:
            sock.settimeout(0.5)
            data = sock.recv(1024)
            if data:
                return data.decode("utf-8", errors="replace").strip()
        except Exception:
            pass
        return None

    def scan_target(self, target_ip: str, ports: Optional[List[int]] = None) -> Dict[int, Optional[str]]:
        """
        Scans specified ports concurrently against the target IP.
        Returns a dict of open ports mapping to their banner (or None).
        """
        scan_ports = ports or DEFAULT_COMMON_PORTS
        open_ports: Dict[int, Optional[str]] = {}

        logger.info(f"Scanning {len(scan_ports)} ports on {target_ip} with {self.max_threads} threads...")

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, target_ip, p): p for p in scan_ports
            }
            for future in as_completed(future_to_port):
                port, is_open, banner = future.result()
                if is_open:
                    open_ports[port] = banner
                    logger.debug(f"Port {port} is OPEN on {target_ip} (Banner: {banner})")

        return dict(sorted(open_ports.items()))
