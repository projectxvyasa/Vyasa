"""
Web Crawler & Endpoint Discovery Engine for VYASA.
Crawls web assets to discover endpoints, URL parameters, HTML forms, and sensitive paths.
Everything is designed for educational and authorized security auditing.
"""

import re
import logging
from typing import List, Dict, Any, Set, Tuple, Optional
from urllib.parse import urlparse, urljoin, parse_qs
from html.parser import HTMLParser
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("vyasa.recon.crawler")


class SimpleHTMLParser(HTMLParser):
    """Parses HTML to extract links, form actions, and input names."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        
        # Extract href links
        if tag.lower() == "a" and "href" in attr_dict:
            href = attr_dict["href"].strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                full_url = urljoin(self.base_url, href)
                self.links.add(full_url)

        # Extract script src
        elif tag.lower() == "script" and "src" in attr_dict:
            src = attr_dict["src"].strip()
            if src:
                self.links.add(urljoin(self.base_url, src))

        # Extract form details
        elif tag.lower() == "form":
            action = attr_dict.get("action", "").strip()
            method = attr_dict.get("method", "GET").upper()
            form_url = urljoin(self.base_url, action) if action else self.base_url
            self._current_form = {
                "action": form_url,
                "method": method,
                "inputs": []
            }
            self.forms.append(self._current_form)

        # Extract form inputs
        elif tag.lower() in ("input", "textarea", "select") and self._current_form is not None:
            name = attr_dict.get("name")
            if name:
                self._current_form["inputs"].append({
                    "name": name,
                    "type": attr_dict.get("type", "text"),
                    "value": attr_dict.get("value", "")
                })

    def handle_endtag(self, tag: str):
        if tag.lower() == "form":
            self._current_form = None


class WebCrawler:
    """Crawls target web scope to discover endpoints, parameters, and forms."""

    def __init__(self, max_depth: int = 2, max_pages: int = 60, timeout: float = 3.0):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VYASA-Crawler/2.0"
        })

    def crawl(self, start_url: str, on_page=None) -> Tuple[List[Dict[str, Any]], List[str], List[Dict[str, Any]]]:
        """
        Crawls the target domain starting from start_url.
        Returns:
            - Discovered endpoints (dict with path, params, method, sample_url)
            - Crawled URLs
            - Form inventory
        """
        parsed_start = urlparse(start_url)
        target_domain = parsed_start.netloc or parsed_start.path
        scheme = parsed_start.scheme or "http"
        base_origin = f"{scheme}://{target_domain}"

        visited: Set[str] = set()
        to_visit: List[Tuple[str, int]] = [(start_url if start_url.startswith("http") else base_origin, 0)]

        # Common sensitive & admin paths to check
        sensitive_paths = [
            "/", "/login", "/login.php", "/admin", "/admin/login", "/userinfo.php",
            "/listproducts.php", "/artists.php", "/search.php", "/cart.php",
            "/phpinfo.php", "/.env", "/.git/HEAD", "/robots.txt", "/sitemap.xml",
            "/actuator/env", "/graphql", "/openapi.json", "/swagger.json",
            "/api", "/api/v1", "/config.json", "/backup.sql", "/server-status",
        ]

        # Path-style (RESTful / pretty-URL) endpoints where user input travels in
        # a PATH SEGMENT rather than a query string (e.g. /search/<term>/,
        # /product/<id>). Seeding these ensures path-based injection (reflected
        # XSS like /search/<script>.../, path SQLi) is probed even when the site
        # exposes no '?param=' endpoints and nothing links to them.
        VYPROBE = "vytest"
        path_style_seeds = [
            f"/search/{VYPROBE}", f"/search/{VYPROBE}/", f"/s/{VYPROBE}",
            f"/q/{VYPROBE}", f"/find/{VYPROBE}", f"/tour/{VYPROBE}",
            f"/tours/{VYPROBE}", f"/package/{VYPROBE}", f"/packages/{VYPROBE}",
            f"/product/{VYPROBE}", f"/products/{VYPROBE}", f"/category/{VYPROBE}",
            f"/tag/{VYPROBE}", f"/view/{VYPROBE}", f"/page/{VYPROBE}",
            f"/item/{VYPROBE}", f"/user/{VYPROBE}", f"/profile/{VYPROBE}",
            f"/blog/{VYPROBE}", f"/post/{VYPROBE}", f"/city/{VYPROBE}",
        ]
        for s_path in sensitive_paths + path_style_seeds:
            full_s_url = f"{base_origin}{s_path}"
            if full_s_url not in [u for u, _ in to_visit]:
                to_visit.append((full_s_url, 1))

        discovered_endpoints_map: Dict[str, Dict[str, Any]] = {}
        form_inventory: List[Dict[str, Any]] = []

        while to_visit and len(visited) < self.max_pages:
            url, depth = to_visit.pop(0)

            # Clean URL fragment
            clean_url = url.split("#")[0]
            if clean_url in visited:
                continue

            parsed_url = urlparse(clean_url)
            # Restrict crawling to target domain
            if parsed_url.netloc and parsed_url.netloc != target_domain and target_domain not in parsed_url.netloc:
                continue

            visited.add(clean_url)
            path = parsed_url.path or "/"

            # Extract URL query parameters
            query_params = list(parse_qs(parsed_url.query).keys())
            
            if path not in discovered_endpoints_map:
                discovered_endpoints_map[path] = {
                    "path": path,
                    "methods": ["GET"],
                    "params": set(query_params),
                    "forms": [],
                    "sample_url": clean_url
                }
                if on_page:
                    try:
                        on_page(path, clean_url)
                    except Exception:
                        pass
            else:
                discovered_endpoints_map[path]["params"].update(query_params)
                if not discovered_endpoints_map[path]["sample_url"]:
                    discovered_endpoints_map[path]["sample_url"] = clean_url

            if depth >= self.max_depth:
                continue

            try:
                resp = self.session.get(clean_url, timeout=self.timeout, allow_redirects=True)
                content_type = resp.headers.get("Content-Type", "").lower()

                if "text/html" in content_type:
                    parser = SimpleHTMLParser(clean_url)
                    parser.feed(resp.text)

                    # Store discovered forms
                    for form in parser.forms:
                        form_action_parsed = urlparse(form["action"])
                        form_path = form_action_parsed.path or "/"
                        form_inputs = [i["name"] for i in form.get("inputs", []) if i.get("name")]

                        if form_path not in discovered_endpoints_map:
                            discovered_endpoints_map[form_path] = {
                                "path": form_path,
                                "methods": [form["method"]],
                                "params": set(form_inputs),
                                "forms": [form],
                                "sample_url": form["action"]
                            }
                        else:
                            if form["method"] not in discovered_endpoints_map[form_path]["methods"]:
                                discovered_endpoints_map[form_path]["methods"].append(form["method"])
                            discovered_endpoints_map[form_path]["params"].update(form_inputs)
                            discovered_endpoints_map[form_path]["forms"].append(form)

                        form_inventory.append(form)

                    # Add new discovered links to queue
                    for link in parser.links:
                        parsed_link = urlparse(link)
                        if parsed_link.netloc == target_domain or not parsed_link.netloc:
                            clean_link = link.split("#")[0]
                            if clean_link not in visited:
                                to_visit.append((clean_link, depth + 1))

            except Exception as e:
                logger.debug(f"Crawler error on {clean_url}: {e}")

        # Format endpoints for returned list. Flag "dynamic" endpoints - those
        # that take user input (query/form params) or carry a variable path
        # segment (numeric id, slug, or our path-probe marker) - so the scanner
        # prioritizes them for injection testing.
        endpoints_list = []
        for path, ep_data in discovered_endpoints_map.items():
            segs = [s for s in path.split("/") if s]
            has_params = bool(ep_data["params"])
            path_dynamic = (
                len(segs) >= 2
                or any(s.isdigit() for s in segs)
                or any(VYPROBE in s for s in segs)
                or any(len(s) > 8 and "-" in s for s in segs)   # slug-like
            )
            endpoints_list.append({
                "path": path,
                "methods": ep_data["methods"],
                "params": sorted(list(ep_data["params"])),
                "form_count": len(ep_data["forms"]),
                "sample_url": ep_data["sample_url"],
                "dynamic": bool(has_params or path_dynamic),
                "path_injectable": bool(path_dynamic),
            })

        # Dynamic endpoints first - they are the ones worth injecting into.
        endpoints_list.sort(key=lambda e: (not e.get("dynamic", False), e["path"]))

        logger.info(f"Crawl finished for {start_url}: {len(visited)} pages visited, {len(endpoints_list)} endpoints identified.")
        return endpoints_list, sorted(list(visited)), form_inventory
