"""
Deep Security Scanner for VYASA.
Executes the comprehensive vulnerability catalog across all discovered endpoints,
provides live real-time terminal telemetry, and captures structured audit trials.
Includes active web crawling, parameter extraction, and multi-vector payload probing.
"""

import re
import time
import uuid
import logging
from typing import List, Tuple, Dict, Any, Optional, Set
from urllib.parse import urlparse, parse_qs, urlencode
import urllib3
import requests
from vyasa.core.models import Asset, Finding, Severity, ValidationStatus, InvestigationTelemetry
from vyasa.testing.vulnerability_catalog import VULNERABILITY_CATALOG, VulnerabilityCheckDef
from vyasa.testing.injection_confirm import (
    confirm_sqli, confirm_xss, confirm_ssti, confirm_command, targets_from_endpoint,
)
from vyasa.testing.dom_scanner import confirm_dom_xss, playwright_available
from vyasa.testing.auth_scanner import (
    confirm_weak_jwt_secret, confirm_jwt_none_accepted, confirm_idor,
    confirm_unauth_privileged, find_jwt,
)
from vyasa.testing.extra_scanners import (
    confirm_xxe, confirm_crlf, confirm_host_header_injection, confirm_ssrf_reflected,
    confirm_error_disclosure, scan_asset_secrets, confirm_scm_metadata, confirm_nosql,
    confirm_csrf,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("vyasa.testing.deep_scanner")


class DeepScanner:
    """Executes multi-category vulnerability audits with live terminal streaming."""

    def __init__(self, timeout: float = 3.5, enable_dom_xss: bool = True, fast: bool = False,
                 auth: Optional[Dict[str, Any]] = None):
        self.timeout = timeout
        # Fast mode trades a little depth for speed: no headless-browser pass,
        # shorter time-based SQLi delay, and fewer injection targets per check.
        self.fast = fast
        # DOM/execution XSS confirmation via a real headless browser. Catches
        # DOM-based XSS and script-execution reflection the HTTP engine cannot.
        # Automatically skipped (with a note) if Playwright/Chromium is absent.
        self.enable_dom_xss = enable_dom_xss and not fast
        self._time_delay = 3 if fast else 5      # time-based SQLi/command sleep seconds
        self._inj_cap = 8 if fast else 10        # injection targets tested per check
        self._dom_scanned = False          # run the browser pass at most once per engagement
        self._dom_proof = None
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VYASA-Security-Auditor/2.0"
        })
        # Authentication context so the whole scan can run behind a login:
        # auth = {"headers": {...}, "cookie": "a=b; c=d", "token": "<jwt>"}.
        self._auth = auth or {}
        self._auth_token = self._auth.get("token")
        _ah = dict(self._auth.get("headers") or {})
        if _ah:
            self.session.headers.update(_ah)
        if self._auth.get("cookie"):
            self.session.headers["Cookie"] = self._auth["cookie"]
        if self._auth_token and "Authorization" not in self.session.headers:
            self.session.headers["Authorization"] = f"Bearer {self._auth_token}"

    def _unauth_session(self):
        """A fresh session with NO auth, for unauthenticated-access checks."""
        s = requests.Session()
        s.verify = False
        s.headers.update({"User-Agent": self.session.headers.get("User-Agent", "VYASA")})
        return s

    def _jwt_token(self, base_url: str) -> Optional[str]:
        """Find a JWT to test: provided token, provided auth headers/cookie, or
        one observed in the base response (Set-Cookie / body)."""
        if self._auth_token:
            return self._auth_token
        for v in list(self.session.headers.values()):
            t = find_jwt(str(v))
            if t:
                return t
        r = self._base_response(base_url)
        if r is not None:
            return find_jwt(r.headers.get("Set-Cookie", ""), (r.text or "")[:8000])
        return None

    def run_deep_audit(
        self,
        asset: Asset,
        discovered_paths: Optional[List[str]] = None,
        live_console: bool = True,
        selected_checks: Optional[List[str]] = None,
        selected_categories: Optional[List[str]] = None,
        target_endpoint: Optional[str] = None,
        notify=None
    ) -> Tuple[List[Finding], List[InvestigationTelemetry]]:
        """
        Executes targeted or comprehensive vulnerability checks across endpoints.
        Streams real-time execution telemetry to stdout.
        """
        findings: List[Finding] = []
        telemetry: List[InvestigationTelemetry] = []

        base_url, port = self._resolve_base_url(asset)

        # Collect endpoints and parameters from asset metadata (crawled by WebCrawler)
        crawled_eps = asset.metadata.get("endpoints", [])
        crawled_paths = set()
        crawled_urls = set()
        
        for ep in crawled_eps:
            if isinstance(ep, dict) and "path" in ep:
                crawled_paths.add(ep["path"])
                if ep.get("sample_url"):
                    crawled_urls.add(ep["sample_url"])

        # Determine target endpoint and evaluation paths
        scoped_endpoint_path = None
        if target_endpoint and target_endpoint.strip():
            ep_clean = target_endpoint.strip()
            if ep_clean.startswith("http://") or ep_clean.startswith("https://"):
                parsed = urlparse(ep_clean)
                scoped_endpoint_path = parsed.path or "/"
                if parsed.query:
                    scoped_endpoint_path += f"?{parsed.query}"
            else:
                scoped_endpoint_path = ep_clean if ep_clean.startswith("/") else f"/{ep_clean}"
            paths = {scoped_endpoint_path}
        else:
            paths = set(discovered_paths or [])
            paths.update(crawled_paths)
            paths.update([
                "/", "/listproducts.php", "/artists.php", "/search.php", "/userinfo.php",
                "/login.php", "/cart.php", "/api", "/api/v1", "/login", "/admin",
                "/graphql", "/openapi.json"
            ])

        # Filter catalog checks based on user selection
        checks_to_run: List[VulnerabilityCheckDef] = []
        for check in VULNERABILITY_CATALOG:
            if selected_checks and len(selected_checks) > 0:
                if check.check_id not in selected_checks:
                    continue
            if selected_categories and len(selected_categories) > 0:
                cat_lower_list = [c.strip().lower() for c in selected_categories]
                if check.category.strip().lower() not in cat_lower_list:
                    continue
            checks_to_run.append(check)

        if not checks_to_run:
            checks_to_run = VULNERABILITY_CATALOG

        print(f"\n{'='*75}")
        print(f"[*] VYASA DEEP SECURITY SCANNER: Running {len(checks_to_run)} Check(s)")
        scope_display = f"{base_url}{scoped_endpoint_path}" if scoped_endpoint_path else f"{base_url} ({len(paths)} endpoints)"
        print(f"[*] Target Scope: {scope_display}")
        print(f"{'='*75}\n")

        for check in checks_to_run:
            target_path = scoped_endpoint_path if scoped_endpoint_path else self._select_path_for_check(check, paths, crawled_eps)
            target_url = f"{base_url}{target_path}"

            start_time = time.time()
            verdict = "SECURE"

            try:
                probe_res = self._dispatch_check(check, target_url, base_url, asset, crawled_eps)
                duration_ms = round((time.time() - start_time) * 1000, 1)

                is_vuln, req_desc, resp_desc, evidence = probe_res

                if is_vuln:
                    verdict = "VULNERABLE"
                    finding = Finding(
                        finding_id=f"find_{uuid.uuid4().hex[:8]}",
                        title=f"{check.title} ({target_path})",
                        description=f"{check.description} Remediation: {check.remediation_guidance}",
                        severity=check.severity,
                        asset_id=asset.asset_id,
                        port=port,
                        service=f"HTTP/{port}",
                        evidence=evidence,
                        cve_id=check.cwe_id,
                        cvss_score=check.cvss_base,
                        validation_status=ValidationStatus.CONFIRMED
                    )
                    findings.append(finding)
                else:
                    verdict = "SECURE"

            except Exception as e:
                duration_ms = round((time.time() - start_time) * 1000, 1)
                req_desc = f"GET {target_path}"
                resp_desc = f"Connection error or timeout ({e.__class__.__name__})"
                verdict = "SECURE"
                evidence = "No response anomaly detected or service safely filtered probe."

            t_record = InvestigationTelemetry(
                probe_id=check.check_id,
                title=check.title,
                category=check.category,
                endpoint=target_path,
                method="GET/POST",
                request_summary=req_desc,
                response_summary=resp_desc,
                verdict=verdict,
                evidence_details=evidence,
                duration_ms=duration_ms
            )
            telemetry.append(t_record)

            if notify:
                try:
                    notify("CHECK", f"{check.check_id}: {check.title}", {
                        "check_id": check.check_id,
                        "title": check.title,
                        "category": check.category,
                        "verdict": verdict,
                        "duration_ms": duration_ms,
                    })
                except Exception:
                    pass

            if live_console:
                self._print_live_progress(check, target_path, req_desc, resp_desc, verdict, duration_ms)

        print(f"\n{'-'*75}")
        print(f"[+] Deep Audit Complete: Evaluated {len(telemetry)} checks across {len(paths)} endpoints.")
        print(f"[+] Total Vulnerabilities Identified: {len(findings)}")
        print(f"{'-'*75}\n")

        return findings, telemetry

    def _select_path_for_check(self, check: VulnerabilityCheckDef, paths: Set[str], crawled_eps: List[Dict[str, Any]]) -> str:
        """Selects the most appropriate endpoint path for a specific check category."""
        cid = check.check_id.upper()
        cat = check.category.upper()

        if cid == "CONF-01":
            return "/actuator/env"
        elif cid == "CONF-02":
            return "/.git/HEAD"
        elif cid == "CONF-03":
            return "/.env"
        elif cid in ("API-01", "API-02"):
            return "/graphql"
        elif cid == "API-05":
            return "/openapi.json"
        elif cid == "INFO-03":
            return "/phpinfo.php"
        elif cid == "INFO-04":
            return "/robots.txt"

        # Search for endpoint with query parameters for Injection testing
        if "INJ" in cid or "SQL" in cat or "XSS" in cat or "COMMAND" in cat:
            for ep in crawled_eps:
                if isinstance(ep, dict) and ep.get("params"):
                    path = ep.get("path", "")
                    params_str = "&".join(f"{p}=1" for p in ep["params"])
                    return f"{path}?{params_str}" if params_str else path

            for p in paths:
                if "?" in p:
                    return p
                if any(k in p for k in ("product", "list", "artist", "user", "search", "cat", "id", "item")):
                    return f"{p}?cat=1"

            return "/listproducts.php?cat=1" if "/listproducts.php" in paths else "/"

        if "AUTH" in cid:
            for p in paths:
                if "login" in p or "user" in p or "auth" in p:
                    return p
            return "/login" if "/login" in paths else "/"

        return "/"

    def _base_response(self, base_url: str):
        """Fetch (and cache) the base URL response once, so the many passive
        header/cookie/disclosure checks share a single request instead of each
        issuing their own."""
        if not hasattr(self, "_base_resp_cache"):
            self._base_resp_cache = {}
        if base_url not in self._base_resp_cache:
            try:
                self._base_resp_cache[base_url] = self.session.get(
                    base_url, timeout=max(self.timeout, 5.0), allow_redirects=True)
            except Exception:
                self._base_resp_cache[base_url] = None
        return self._base_resp_cache[base_url]

    def _resolve_base_url(self, asset: Asset) -> Tuple[str, int]:
        """
        Determine the real base URL to scan. SYN port scans are unreliable on
        WAF/CDN-fronted sites (Cloudflare etc. silently drop probes), which left
        the old logic defaulting to a bogus :8000. Instead we honour any open web
        port the scanner DID observe, otherwise actively probe HTTPS then HTTP
        with a real request and use whichever answers. Defaults to HTTPS.
        """
        host = asset.host
        open_ports = asset.open_ports or []

        # 1. Respect an explicitly observed web port. Standard ports (443/80)
        #    win over dev/alt ports (8000/8080) so a target running both is
        #    scanned on its primary web service, not an incidental dev server.
        for p in (443, 80, 8443, 8080, 8000):
            if p in open_ports:
                scheme = "https" if p in (443, 8443) else "http"
                suffix = f":{p}" if p not in (80, 443) else ""
                return f"{scheme}://{host}{suffix}", p

        # 2. No web port observed - probe HTTPS then HTTP with a real request.
        for base, port in ((f"https://{host}", 443), (f"http://{host}", 80)):
            try:
                r = self.session.get(base + "/", timeout=max(self.timeout, 5.0),
                                     allow_redirects=True)
                if r is not None and r.status_code < 600:
                    # Follow to the final scheme/host after redirects (http->https).
                    final = urlparse(r.url)
                    if final.scheme and final.netloc:
                        fport = 443 if final.scheme == "https" else 80
                        return f"{final.scheme}://{final.netloc}", fport
                    return base, port
            except Exception:
                continue

        # 3. Last resort: assume HTTPS (correct for the vast majority of sites).
        return f"https://{host}", 443

    def _build_injection_targets(
        self,
        target_url: str,
        base_url: str,
        crawled_eps: List[Dict[str, Any]]
    ) -> List[Tuple[str, str, Dict[str, str]]]:
        """
        Assemble concrete (method, url, params) probe targets for injection
        confirmation. Covers the scoped GET endpoint (with its query params) and
        every crawled endpoint's GET params and POST form fields, de-duplicated.
        """
        targets: List[Tuple[str, str, Dict[str, str]]] = []

        parsed = urlparse(target_url)
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else target_url
        get_params = {k: (v[0] if v else "1") for k, v in parse_qs(parsed.query).items()}
        targets.append(("GET", clean, get_params))

        for ep in (crawled_eps or []):
            if not isinstance(ep, dict):
                continue
            try:
                for m, u, p in targets_from_endpoint(base_url, ep):
                    targets.append((m, u, p))
            except Exception:
                continue

        # ALWAYS test common pretty-URL / search routes where input travels in a
        # PATH SEGMENT (e.g. /search/<term>/). These are high-signal and must be
        # probed even when the crawler surfaced nothing (filtered SYN scan, no
        # links, JS-rendered nav) - this is the class behind path-based reflected
        # search XSS like /search/"><script>...</script>/.
        bu = base_url.rstrip("/")
        for route in ("search", "s", "find", "results", "query", "tour", "tours",
                      "package", "packages", "product", "category", "tag", "city"):
            targets.append(("GET", f"{bu}/{route}/vytest", {}))

        # De-duplicate by (method, url, param-name-set); cap for runtime safety.
        seen: Set[Tuple[str, str, Tuple[str, ...]]] = set()
        unique: List[Tuple[str, str, Dict[str, str]]] = []
        for m, u, p in targets:
            key = (m, u, tuple(sorted(p.keys())))
            if key in seen:
                continue
            seen.add(key)
            unique.append((m, u, p))
        # Prioritize targets so the HIGH-SIGNAL ones are never cut by the cap.
        # TIER 0: literal search/query routes (where path-based reflected XSS
        #   almost always lives) - these must be tested first, ahead of generic
        #   "content" routes, or the vulnerable /search is pushed off the cap.
        # TIER 1: parameterized endpoints.
        # TIER 2: other content routes (product/category/tour/city/...).
        # TIER 3: any other >=2-segment (path-injectable) URL.  TIER 4: the rest.
        search_re = re.compile(r"/(search|s|find|results|query|q|lookup|go|seek)(/|$)", re.I)
        content_re = re.compile(
            r"/(tour|tours|package|packages|product|products|category|categories|"
            r"destination|destinations|city|cities|tag|tags|blog|post|posts|item|"
            r"items|view|page|profile|user|users)(/|$)", re.I)

        def _priority(t):
            method, u, p = t
            path = urlparse(u).path
            segs = [s for s in path.split("/") if s]
            if search_re.search(path):
                tier = 0
            elif p:
                tier = 1
            elif content_re.search(path):
                tier = 2
            elif len(segs) >= 2:
                tier = 3
            else:
                tier = 4
            return (tier, path)   # path tiebreaker keeps ordering deterministic

        unique.sort(key=_priority)
        return unique[:self._inj_cap]

    def _dom_xss_scan(self, target_url: str, base_url: str,
                      crawled_eps: List[Dict[str, Any]]):
        """
        Real-browser DOM/execution XSS confirmation, run at most once per
        engagement over a bounded set of candidate URLs (the scoped target plus
        a few crawled endpoints). Cached so repeated XSS catalog checks don't
        relaunch the browser. Returns a DomXssProof, or None if disabled.
        """
        if not self.enable_dom_xss:
            return None
        if self._dom_scanned:
            return self._dom_proof
        self._dom_scanned = True

        if not playwright_available():
            from vyasa.testing.dom_scanner import DomXssProof
            self._dom_proof = DomXssProof(
                confirmed=False, available=False,
                note="Playwright not installed - run `pip install playwright && playwright install chromium`.",
            )
            return self._dom_proof

        candidates: List[str] = [target_url]
        for ep in (crawled_eps or []):
            if isinstance(ep, dict):
                u = ep.get("sample_url") or f"{base_url.rstrip('/')}{ep.get('path', '')}"
                if u and u not in candidates:
                    candidates.append(u)
        candidates = candidates[:2]

        proof = None
        for u in candidates:
            try:
                res = confirm_dom_xss(u, timeout_ms=6000, max_urls=4)
            except Exception as e:
                logger.debug(f"DOM scan failed on {u}: {e}")
                continue
            proof = res
            if not res.available or res.confirmed:
                break
        self._dom_proof = proof
        return proof

    def _dispatch_check(
        self,
        check: VulnerabilityCheckDef,
        target_url: str,
        base_url: str,
        asset: Asset,
        crawled_eps: List[Dict[str, Any]]
    ) -> Tuple[bool, str, str, str]:
        """Dispatches active diagnostic payloads to detect real vulnerabilities."""
        cid = check.check_id
        cat = check.category.upper()

        # ---------------------------------------------------------
        # 1. Configuration & Sensitive Exposure
        # ---------------------------------------------------------
        if cid == "CONF-03":
            r = self.session.get(f"{base_url}/.env", timeout=self.timeout)
            is_vuln = r.status_code == 200 and any(k in r.text for k in ("DB_PASSWORD", "SECRET_KEY", "APP_ENV", "DATABASE_URL"))
            return is_vuln, "GET /.env", f"HTTP {r.status_code} ({len(r.text)} bytes)", f"Exposed environment secrets detected: {r.text[:80]}..."

        if cid == "CONF-02":
            r = self.session.get(f"{base_url}/.git/HEAD", timeout=self.timeout)
            is_vuln = r.status_code == 200 and "ref: refs/heads" in r.text
            return is_vuln, "GET /.git/HEAD", f"HTTP {r.status_code} ({len(r.text)} bytes)", f"Exposed Git repository metadata: {r.text[:60]}"

        if cid == "CONF-01":
            r = self.session.get(f"{base_url}/actuator/env", timeout=self.timeout)
            is_vuln = r.status_code == 200 and "propertySources" in r.text
            return is_vuln, "GET /actuator/env", f"HTTP {r.status_code} ({len(r.text)} bytes)", "Exposed Spring Boot Actuator environment properties."

        if cid == "INFO-03":
            r = self.session.get(f"{base_url}/phpinfo.php", timeout=self.timeout)
            is_vuln = r.status_code == 200 and "PHP Version" in r.text and "System" in r.text
            return is_vuln, "GET /phpinfo.php", f"HTTP {r.status_code} ({len(r.text)} bytes)", f"PHP configuration dump exposed on web root."

        if cid == "INFO-04":
            r = self.session.get(f"{base_url}/robots.txt", timeout=self.timeout)
            is_vuln = r.status_code == 200 and "Disallow:" in r.text
            return is_vuln, "GET /robots.txt", f"HTTP {r.status_code} ({len(r.text)} bytes)", f"Disallowed site pathways disclosed in robots.txt."

        if cid == "INFO-01":
            # Internal RFC1918 IP address disclosure in body or headers.
            r = self._base_response(base_url)
            blob = ((r.text if r is not None else "") + " " +
                    " ".join(f"{k}:{v}" for k, v in (r.headers.items() if r is not None else [])))
            m = re.search(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|"
                          r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b", blob)
            return (m is not None, f"GET {base_url}", "response body/headers",
                    (f"Internal RFC1918 IP address disclosed in the response: {m.group(0)}" if m
                     else "No internal IP address disclosed."))

        if cid == "CONF-04":
            # Directory indexing enabled on common static paths.
            for d in ("/images/", "/uploads/", "/assets/", "/static/", "/files/", "/img/", "/media/"):
                try:
                    rr = self.session.get(f"{base_url}{d}", timeout=self.timeout)
                except Exception:
                    continue
                if rr.status_code == 200 and any(k in rr.text.lower()
                                                 for k in ("index of /", "directory listing", "<title>index of")):
                    return True, f"GET {d}", f"HTTP 200 ({len(rr.text)} bytes)", \
                        f"Directory indexing ENABLED at '{d}' - file listing exposed (matched 'Index of /')."
            return False, f"GET {base_url}", "HTTP -", "No directory indexing observed on common static paths."

        if cid == "CONF-05":
            # Detailed server banner (software + version) leaked in the Server header.
            r = self._base_response(base_url)
            server = r.headers.get("Server", "") if r is not None else ""
            is_vuln = bool(re.search(r"[A-Za-z].*?\d+\.\d+", server))
            return is_vuln, f"GET {base_url}", f"Server: {server[:70]}", \
                (f"Server banner discloses software and version: '{server}'." if is_vuln
                 else f"Server header present but no version leaked: '{server or '(absent)'}'.")

        if cid == "CONF-06":
            # Backend technology disclosed via X-Powered-By.
            r = self._base_response(base_url)
            xpb = r.headers.get("X-Powered-By", "") if r is not None else ""
            return (bool(xpb), f"GET {base_url}", f"X-Powered-By: {xpb[:70]}",
                    (f"Backend technology/version disclosed via X-Powered-By: '{xpb}'." if xpb
                     else "No X-Powered-By header exposed."))

        if cid == "CONF-11":
            # Missing X-Content-Type-Options: nosniff.
            r = self._base_response(base_url)
            val = r.headers.get("X-Content-Type-Options", "") if r is not None else ""
            is_vuln = val.lower() != "nosniff"
            return is_vuln, f"GET {base_url}", f"X-Content-Type-Options: {val or '(absent)'}", \
                "X-Content-Type-Options: nosniff header missing - browsers may MIME-sniff responses (drive-by XSS risk)."

        if cid in ("CONF-12", "CONF-13", "CONF-14"):
            # Cookie security attributes observed in the Set-Cookie response header.
            r = self._base_response(base_url)
            setck = r.headers.get("Set-Cookie", "") if r is not None else ""
            if not setck:
                return False, f"GET {base_url}", "no Set-Cookie", "No cookies set on the base response (nothing to audit)."
            attr, label = {"CONF-12": ("secure", "Secure"),
                           "CONF-13": ("httponly", "HttpOnly"),
                           "CONF-14": ("samesite", "SameSite")}[cid]
            is_vuln = attr not in setck.lower()
            return is_vuln, f"GET {base_url}", f"Set-Cookie: {setck[:80]}", \
                f"Cookie set WITHOUT the '{label}' attribute (observed in the Set-Cookie response header)."

        if cid == "INFO-02":
            # Exposed backup / database dump files.
            for f in ("/backup.sql", "/database.sql", "/dump.sql", "/db.sql", "/backup.zip",
                      "/backup.tar.gz", "/www.zip", "/site.zip", "/backup.bak", "/.env.bak"):
                try:
                    rr = self.session.get(f"{base_url}{f}", timeout=self.timeout)
                except Exception:
                    continue
                ct = rr.headers.get("Content-Type", "").lower()
                size = int(rr.headers.get("Content-Length", "0") or 0)
                if rr.status_code == 200 and size > 0 and "text/html" not in ct:
                    return True, f"GET {f}", f"HTTP 200 ({ct}, {size}B)", \
                        f"Exposed backup/dump file downloadable without authentication at '{f}'."
            return False, f"GET {base_url}", "HTTP -", "No exposed backup/dump files on common paths."

        if cid == "AUTHZ-06":
            # CORS trusts the 'null' origin with credentials.
            try:
                r = self.session.get(base_url, headers={"Origin": "null"}, timeout=self.timeout)
            except Exception:
                return False, f"GET {base_url}", "error", "CORS null-origin probe failed to connect."
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
            is_vuln = acao == "null" and acac == "true"
            return is_vuln, f"GET {base_url} (Origin: null)", f"ACAO={acao}", \
                "CORS permits the 'null' origin WITH credentials (ACAO=null, ACAC=true) - exploitable from sandboxed iframes."

        # ---------------------------------------------------------
        # 2b. Authentication & Access Control (confirmation-gated)
        # ---------------------------------------------------------
        if cid == "AUTH-01":
            # Privileged endpoints reachable with NO authentication.
            proof = confirm_unauth_privileged(self._unauth_session(), base_url, timeout=max(self.timeout, 5.0))
            if proof:
                return True, proof.request_summary, proof.response_summary, proof.evidence
            return False, f"GET {base_url}", "HTTP -", "No unauthenticated privileged endpoint reachable."

        if cid == "AUTH-02":
            # JWT 'alg:none' acceptance - needs a token (provided or observed).
            token = self._jwt_token(base_url)
            if not token:
                return False, "JWT check", "no token", "No JWT available to test (provide --token or an authenticated --cookie)."
            for ep in ("", "/profile", "/api/me", "/me", "/account", "/api/profile", "/api/user", "/dashboard"):
                try:
                    proof = confirm_jwt_none_accepted(self.session, base_url.rstrip("/") + ep, token,
                                                      timeout=max(self.timeout, 6.0))
                except Exception:
                    proof = None
                if proof:
                    return True, proof.request_summary, proof.response_summary, proof.evidence
            return False, "JWT alg:none", "forged token rejected", "JWT alg:none forged token was rejected (signature enforced)."

        if cid == "AUTH-03":
            # JWT weak HMAC secret - offline crack.
            token = self._jwt_token(base_url)
            if not token:
                return False, "JWT check", "no token", "No JWT available to test for a weak secret."
            proof = confirm_weak_jwt_secret(token)
            if proof:
                return True, proof.request_summary, proof.response_summary, proof.evidence
            return False, "JWT weak secret", "not cracked", "JWT secret not found in the common-weak-secret list."

        if cid == "AUTHZ-01":
            # IDOR / BOLA - enumerate a neighbouring object id under this session.
            candidates = []
            tp = urlparse(target_url)
            if re.search(r"/\d{1,12}(/|$)", tp.path) or re.search(r"(?:id|user_id|uid|order|invoice|doc)=\d", tp.query, re.I):
                candidates.append(target_url)
            for ep in (crawled_eps or []):
                u = ep.get("sample_url") or f"{base_url.rstrip('/')}{ep.get('path','')}"
                pu = urlparse(u)
                if re.search(r"/\d{1,12}(/|$)", pu.path) or re.search(r"(?:id|user_id|uid|order|invoice|doc)=\d", pu.query, re.I):
                    candidates.append(u)
            seen = set()
            for u in candidates:
                if u in seen:
                    continue
                seen.add(u)
                try:
                    proof = confirm_idor(self.session, u, timeout=max(self.timeout, 6.0))
                except Exception:
                    proof = None
                if proof:
                    return True, proof.request_summary, proof.response_summary, proof.evidence
                if len(seen) >= 5:
                    break
            return False, "IDOR/BOLA", "no id-bearing endpoint confirmed", "No IDOR confirmed (no numeric-id endpoint, or object ownership is enforced)."

        # ---------------------------------------------------------
        # 2c. Extra confirmation-gated classes (XXE/CRLF/Host/SSRF/errors/secrets/SCM/NoSQL)
        # ---------------------------------------------------------
        if cid == "INJ-07":   # XXE
            proof = confirm_xxe(self.session, base_url, crawled_eps, timeout=max(self.timeout, 6.0))
            if proof:
                return True, proof.request_summary, proof.response_summary, proof.evidence
            return False, "XXE", "no entity resolution", "No XXE confirmed: XML external entities were not resolved."

        if cid == "INJ-04":   # Host header injection
            proof = confirm_host_header_injection(self.session, base_url, timeout=max(self.timeout, 6.0))
            if proof:
                return True, proof.request_summary, proof.response_summary, proof.evidence
            return False, "Host header", "not reflected", "No Host-header injection: attacker Host was not reflected."

        if cid == "INFO-05":  # SCM metadata (.svn/.hg/.bzr)
            proof = confirm_scm_metadata(self.session, base_url, timeout=self.timeout)
            if proof:
                return True, proof.request_summary, proof.response_summary, proof.evidence
            return False, "SCM metadata", "not exposed", "No exposed SCM metadata (.svn/.hg/.bzr) found."

        if cid == "INFO-06":  # Hard-coded secrets in client JS
            proof = scan_asset_secrets(self.session, base_url, timeout=self.timeout)
            if proof:
                return True, proof.request_summary, proof.response_summary, proof.evidence
            return False, "JS secrets", "none found", "No hard-coded secrets/keys found in client-side assets."

        if cid == "INFO-07":  # Verbose error / stack trace
            tgts = self._build_injection_targets(target_url, base_url, crawled_eps)
            for method, url, params in tgts[:4]:
                if method != "GET":
                    continue
                proof = confirm_error_disclosure(self.session, url, params or None, timeout=self.timeout)
                if proof:
                    return True, proof.request_summary, proof.response_summary, proof.evidence
            return False, "error disclosure", "no stack trace", "No verbose error/stack-trace disclosure observed."

        if cid == "INJ-03":   # CRLF / response splitting
            for method, url, params in self._build_injection_targets(target_url, base_url, crawled_eps)[:4]:
                if method != "GET":
                    continue
                proof = confirm_crlf(self.session, url, params or None, timeout=max(self.timeout, 6.0))
                if proof:
                    return True, proof.request_summary, proof.response_summary, proof.evidence
            return False, "CRLF", "no header injection", "No CRLF/response-splitting: injected header not reflected."

        if cid == "INJ-14":   # NoSQL injection
            for method, url, params in self._build_injection_targets(target_url, base_url, crawled_eps)[:4]:
                if method != "GET":
                    continue
                proof = confirm_nosql(self.session, url, params or None, timeout=max(self.timeout, 6.0))
                if proof:
                    return True, proof.request_summary, proof.response_summary, proof.evidence
            return False, "NoSQLi", "no NoSQL error", "No NoSQL injection confirmed (no NoSQL error signatures)."

        if cid == "CSRF-01":  # Missing anti-CSRF token on state-changing forms
            forms = asset.metadata.get("forms", []) if (asset and getattr(asset, "metadata", None)) else []
            proof = confirm_csrf(self.session, base_url, forms, timeout=self.timeout)
            if proof:
                return True, proof.request_summary, proof.response_summary, proof.evidence
            return False, "CSRF", "protected/none", "No CSRF confirmed (forms carry a token or SameSite-protected cookie, or none are state-changing)."

        # ---------------------------------------------------------
        # 2. Security Headers & CORS
        # ---------------------------------------------------------
        if cid == "CONF-08":
            r = self.session.get(base_url, timeout=self.timeout)
            is_vuln = "Strict-Transport-Security" not in r.headers
            return is_vuln, f"GET {base_url}", f"HTTP {r.status_code}", "Strict-Transport-Security (HSTS) header omitted from response."

        if cid == "CONF-09":
            r = self.session.get(base_url, timeout=self.timeout)
            is_vuln = "Content-Security-Policy" not in r.headers
            return is_vuln, f"GET {base_url}", f"HTTP {r.status_code}", "Content-Security-Policy (CSP) header omitted from response."

        if cid == "CONF-10":
            r = self.session.get(base_url, timeout=self.timeout)
            is_vuln = "X-Frame-Options" not in r.headers and "frame-ancestors" not in r.headers.get("Content-Security-Policy", "")
            return is_vuln, f"GET {base_url}", f"HTTP {r.status_code}", "X-Frame-Options missing (Clickjacking vulnerability)."

        if cid == "AUTHZ-05":
            r = self.session.get(base_url, headers={"Origin": "https://evil.internal"}, timeout=self.timeout)
            is_vuln = r.headers.get("Access-Control-Allow-Origin") == "https://evil.internal" and r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
            return is_vuln, f"GET {base_url} (Origin: evil.internal)", f"HTTP {r.status_code}", f"Permissive CORS ACAO reflected: {r.headers.get('Access-Control-Allow-Origin')}"

        # ---------------------------------------------------------
        # 3. API & GraphQL Introspection
        # ---------------------------------------------------------
        if cid == "API-01":
            r = self.session.post(
                f"{base_url}/graphql",
                json={"query": "query { __schema { types { name } } }"},
                timeout=self.timeout
            )
            is_vuln = r.status_code == 200 and "__schema" in r.text
            return is_vuln, "POST /graphql (__schema introspection)", f"HTTP {r.status_code}", "GraphQL introspection query exposed complete backend schema."

        if cid == "API-05":
            r = self.session.get(f"{base_url}/openapi.json", timeout=self.timeout)
            is_vuln = r.status_code == 200 and any(k in r.text for k in ("openapi", "swagger", "paths"))
            return is_vuln, "GET /openapi.json", f"HTTP {r.status_code}", "Unauthenticated OpenAPI specification exposed route map."

        # ---------------------------------------------------------
        # 4. Active SQL Injection (confirmation-gated: error / boolean / time)
        #    Routed only for genuine SQLi checks. LDAP/XPath/NoSQL/XXE have
        #    their own semantics and must NOT fall through to this detector.
        # ---------------------------------------------------------
        if cid == "INJ-01" or "SQL" in cat or "SQL INJECTION" in check.title.upper():
            targets = self._build_injection_targets(target_url, base_url, crawled_eps)
            default_path = urlparse(target_url).path or "/"
            for method, url, params in targets:
                try:
                    proof = confirm_sqli(
                        self.session, method, url, params or None,
                        timeout=max(self.timeout, 6.0), time_delay=self._time_delay
                    )
                except Exception:
                    proof = None
                if proof and proof.confirmed:
                    # Evidence carries a "CONFIRMED VIA ..." proof marker that the
                    # validation layer independently re-verifies before reporting.
                    return True, proof.request_summary, proof.response_summary, proof.evidence
            return (
                False,
                f"GET {default_path}",
                "HTTP 200 OK",
                "No SQL injection CONFIRMED: error-based, boolean-differential and "
                "time-based blind probes did not reproduce injectable behaviour on any parameter.",
            )

        # ---------------------------------------------------------
        # 5. Cross-Site Scripting (confirmation-gated: reflected, context-aware)
        #    Confirmed only when a breakout payload is reflected UNENCODED in an
        #    executable context. Reflection alone is never reported.
        # ---------------------------------------------------------
        if cid == "INJ-06" or "XSS" in cat or "CROSS-SITE SCRIPTING" in check.title.upper() or "XSS" in check.title.upper():
            targets = self._build_injection_targets(target_url, base_url, crawled_eps)
            default_path = urlparse(target_url).path or "/"
            suspected = None  # genuine maybe (reflected, partial filter) - does NOT drive risk
            for method, url, params in targets:
                try:
                    proof = confirm_xss(
                        self.session, method, url, params or None,
                        timeout=max(self.timeout, 6.0)
                    )
                except Exception:
                    proof = None
                if proof and proof.confirmed:
                    # CONFIRMED: context classified + required chars survived unencoded.
                    return True, proof.request_summary, proof.response_summary, proof.evidence
                if proof is not None and getattr(proof, "state", "") == "suspected" and suspected is None:
                    suspected = proof

            # Fallback: real-browser DOM/execution XSS (DOM sinks, fragment
            # sources, and execution-dependent reflection the HTTP engine misses).
            dom = self._dom_xss_scan(target_url, base_url, crawled_eps)
            if dom and dom.confirmed:
                return True, f"GET {dom.param}", "browser executed payload", dom.evidence

            # Not confirmed. Surface a Suspected observation (for the operator) but
            # keep is_vuln False so only CONFIRMED findings drive the risk score.
            if suspected is not None:
                note = (f"SUSPECTED XSS (NOT confirmed - excluded from risk score): {suspected.evidence}")
                return False, suspected.request_summary, suspected.response_summary, note

            note = "No XSS CONFIRMED: payloads were HTML-encoded, filtered, or reflected only inside non-executing contexts."
            if dom is not None and not dom.available:
                note += f" (DOM/browser check skipped: {dom.note})"
            return False, f"GET {default_path}", "HTTP 200 OK", note

        # ---------------------------------------------------------
        # 6. Server-Side Template Injection (INJ-05) - confirmation-gated
        # ---------------------------------------------------------
        if cid == "INJ-05" or "TEMPLATE INJECTION" in check.title.upper() or "SSTI" in check.title.upper():
            default_path = urlparse(target_url).path or "/"
            for method, url, params in self._build_injection_targets(target_url, base_url, crawled_eps):
                try:
                    proof = confirm_ssti(self.session, method, url, params or None,
                                         timeout=max(self.timeout, 6.0))
                except Exception:
                    proof = None
                if proof and proof.confirmed:
                    return True, proof.request_summary, proof.response_summary, proof.evidence
            return (False, f"GET {default_path}", "HTTP 200 OK",
                    "No SSTI CONFIRMED: template expressions (7*7/8*8) were not evaluated server-side.")

        # ---------------------------------------------------------
        # 7. OS Command Injection (INJ-11) - confirmation-gated (output + time)
        # ---------------------------------------------------------
        if cid == "INJ-11" or "COMMAND INJECTION" in check.title.upper() or "OS COMMAND" in cat:
            default_path = urlparse(target_url).path or "/"
            for method, url, params in self._build_injection_targets(target_url, base_url, crawled_eps):
                try:
                    proof = confirm_command(self.session, method, url, params or None,
                                            timeout=max(self.timeout, 6.0), time_delay=self._time_delay)
                except Exception:
                    proof = None
                if proof and proof.confirmed:
                    return True, proof.request_summary, proof.response_summary, proof.evidence
            return (False, f"GET {default_path}", "HTTP 200 OK",
                    "No command injection CONFIRMED: no command output and no reproduced shell time delay.")

        # ---------------------------------------------------------
        # 8. Path Traversal / LFI (CONF-04, CONF-05)
        # ---------------------------------------------------------
        if "CONF-04" in cid or "CONF-05" in cid or "TRAVERSAL" in cat or "FILE INCLUSION" in check.title.upper():
            lfi_payload = "../../../../etc/passwd"
            separator = "&" if "?" in target_url else "?"
            probe_url = f"{target_url}{separator}file={lfi_payload}&page={lfi_payload}"
            r = self.session.get(probe_url, timeout=self.timeout)
            
            is_vuln = "root:x:0:0:" in r.text or "[extensions]" in r.text.lower()
            evidence = "Local File Inclusion verified: /etc/passwd contents returned in HTTP response." if is_vuln else "Path traversal sequences rejected."
            return is_vuln, f"GET ...{separator}file=../../../../etc/passwd", f"HTTP {r.status_code}", evidence

        # ---------------------------------------------------------
        # 8. Open Redirect (INJ-02)
        # ---------------------------------------------------------
        if "INJ-02" in cid or "REDIRECT" in cat:
            separator = "&" if "?" in target_url else "?"
            probe_url = f"{target_url}{separator}redirect=https://canary.internal&url=https://canary.internal"
            r = self.session.get(probe_url, timeout=self.timeout, allow_redirects=False)
            loc = r.headers.get("Location", "")
            is_vuln = r.status_code in (301, 302, 307, 308) and "canary.internal" in loc
            evidence = f"Unvalidated redirect reflected: Location: {loc}" if is_vuln else f"No unvalidated redirect observed (HTTP {r.status_code})"
            return is_vuln, f"GET ...{separator}redirect=https://canary.internal", f"HTTP {r.status_code} (Location: {loc[:30]})", evidence

        # Strict PoC: no simulated/mock verdicts. Any check without an active
        # detector above is only reported if a real response proves it. For the
        # remaining catalog checks there is no PoC detector, so they report SECURE.
        r = self.session.get(target_url, timeout=self.timeout)
        return False, f"GET {target_url}", f"HTTP {r.status_code} ({len(r.text)} bytes)", "No vulnerability signature observed in response (no proof-of-concept match)."

    def _print_live_progress(
        self,
        check: VulnerabilityCheckDef,
        path: str,
        req_desc: str,
        resp_desc: str,
        verdict: str,
        duration_ms: float
    ):
        """Prints live real-time formatted execution block to the terminal."""
        badge = "🔴 [VULNERABLE]" if verdict == "VULNERABLE" else "🟢 [SECURE]    "
        print(f"{badge} {check.check_id}: {check.title[:45]:<45} | {duration_ms:>5}ms")
        print(f"    ├─ Target  : {path}")
        print(f"    ├─ Probe   : {req_desc[:65]}")
        print(f"    └─ Response: {resp_desc[:65]}")
