"""
Headless-Browser DOM / Execution XSS Confirmation for VYASA.

The HTTP engine (injection_confirm.confirm_xss) confirms XSS only when a
breakout payload is reflected UNENCODED in the raw HTML response. That misses
two very common real-world cases:

  * DOM-based XSS - the payload never appears in the server's HTML; client-side
    JavaScript reads it from location/hash/query and writes it into a dangerous
    sink (innerHTML, document.write, eval), where it executes.
  * Execution-only reflection - the payload is reflected but whether it actually
    runs depends on how the browser parses the surrounding markup.

This module loads candidate payload URLs in a REAL headless browser (Chromium
via Playwright) and confirms XSS ONLY when injected JavaScript actually EXECUTES
- observed by hooking alert/confirm/prompt and a unique marker function. That is
the strongest possible proof: the script ran.

Playwright is optional. If it is not installed, confirm_dom_xss returns a result
with available=False and a one-line install hint; the scanner continues with the
HTTP engine only. Install with:

    pip install playwright
    playwright install chromium

Intended for AUTHORIZED engagements only.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, quote

logger = logging.getLogger("vyasa.testing.dom_scanner")

# Marker the payloads call; the init script sets a flag when it runs.
_FIRE = "__vyasa_fire"

# Init script: run before any page script so our hooks are in place when the
# injected payload executes. We flag on the marker call AND on any native
# alert/confirm/prompt (covers alert(1)-style PoCs).
_INIT_JS = f"""
window.__vyasa_fired = false;
window.{_FIRE} = function() {{ window.__vyasa_fired = true; }};
try {{ window.alert   = function() {{ window.__vyasa_fired = true; }}; }} catch(e) {{}}
try {{ window.confirm = function() {{ window.__vyasa_fired = true; return true; }}; }} catch(e) {{}}
try {{ window.prompt  = function() {{ window.__vyasa_fired = true; return ''; }}; }} catch(e) {{}}
"""

# Execution payloads. Each triggers window.__vyasa_fire() when it runs in a
# live context. Mix of tag-injection, attribute/JS breakout, and script-close.
DOM_PAYLOADS = [
    f'"><img src=x onerror={_FIRE}()>',   # covers html + attribute breakout
    f"<img src=x onerror={_FIRE}()>",     # plain html-context
    f"';{_FIRE}();//",                    # JS string breakout
    f"</script><img src=x onerror={_FIRE}()>",  # script-block close
]


@dataclass
class DomXssProof:
    confirmed: bool
    url: str = ""
    payload: str = ""
    vector: str = "path"          # "path" | "query" | "fragment"
    param: str = ""
    evidence: str = ""
    available: bool = True
    note: str = ""


def playwright_available() -> bool:
    try:
        import playwright  # noqa: F401
        return True
    except Exception:
        return False


def build_candidate_urls(url: str,
                         param_names: Optional[List[str]] = None,
                         max_urls: int = 12) -> List[Tuple[str, str, str, str]]:
    """
    Build (candidate_url_template, vector, where, payload_placeholder) seeds for a
    target URL. The literal string '%PAYLOAD%' marks where a payload is inserted
    (URL-encoded) at call time.

    Vectors covered: URL path (append + replace last segment), each query param,
    and the URL fragment (#...), which is the classic DOM-XSS source.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc or parsed.path
    base = f"{scheme}://{netloc}"
    path = parsed.path if parsed.scheme else "/"
    segs = [s for s in (path or "/").split("/") if s]
    PH = "%PAYLOAD%"

    seeds: List[Tuple[str, str, str, str]] = []

    # Path: append new trailing segment.
    joined = "/".join(segs)
    base_path = f"/{joined}" if joined else ""
    seeds.append((f"{base}{base_path}/{PH}/", "path", f"path (appended to {path or '/'})", PH))
    # Path: replace last segment.
    if segs:
        rep = segs[:]
        rep[-1] = PH
        seeds.append((f"{base}/" + "/".join(rep), "path", f"path segment #{len(segs)}", PH))

    qbase = f"{base}{base_path or '/'}"

    # Fragment (classic DOM-XSS source) - tested early, before param fan-out.
    seeds.append((f"{qbase}#{PH}", "fragment", "URL fragment (#)", PH))

    # Query params.
    names = list(param_names or []) + ["q", "search", "s", "query", "name", "redirect"]
    seen = set()
    for n in names:
        if n in seen:
            continue
        seen.add(n)
        seeds.append((f"{qbase}?{n}={PH}", "query", f"parameter '{n}'", PH))

    return seeds[:max_urls]


def confirm_dom_xss(url: str,
                    param_names: Optional[List[str]] = None,
                    timeout_ms: int = 6000,
                    max_urls: int = 5,
                    payloads: Optional[List[str]] = None) -> DomXssProof:
    """
    Load candidate payload URLs in a headless browser and confirm XSS only when
    injected JavaScript actually executes. Returns DomXssProof.

    available=False (with an install hint) if Playwright/Chromium is missing.
    """
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return DomXssProof(confirmed=False, available=False,
                           note="Playwright not installed. `pip install playwright && playwright install chromium` "
                                "to enable DOM/execution XSS confirmation.")

    pls = payloads or DOM_PAYLOADS
    seeds = build_candidate_urls(url, param_names=param_names, max_urls=max_urls)

    try:
        with sync_playwright() as pw:
            try:
                browser = pw.chromium.launch(headless=True, args=["--no-sandbox", "--disable-gpu"])
            except Exception as e:
                return DomXssProof(confirmed=False, available=False,
                                   note=f"Chromium not available ({e.__class__.__name__}). Run `playwright install chromium`.")
            context = browser.new_context(ignore_https_errors=True)
            context.add_init_script(_INIT_JS)

            try:
                for tmpl, vector, where, ph in seeds:
                    for payload in pls:
                        probe_url = tmpl.replace(ph, quote(payload, safe="/"))
                        page = context.new_page()
                        fired = {"v": False}
                        page.on("dialog", lambda d: (fired.__setitem__("v", True), d.dismiss()))
                        try:
                            page.goto(probe_url, timeout=timeout_ms, wait_until="load")
                            page.wait_for_timeout(600)  # let async onerror/onload settle
                            try:
                                if page.evaluate("window.__vyasa_fired === true"):
                                    fired["v"] = True
                            except Exception:
                                pass
                        except Exception as nav_err:
                            logger.debug(f"DOM nav error {probe_url}: {nav_err}")
                        finally:
                            try:
                                page.close()
                            except Exception:
                                pass
                        if fired["v"]:
                            browser.close()
                            return DomXssProof(
                                confirmed=True, url=probe_url, payload=payload,
                                vector=vector, param=where,
                                evidence=(f"CONFIRMED VIA headless-browser DOM/execution XSS: payload "
                                          f"'{payload}' in {where} caused JavaScript to EXECUTE in a real "
                                          f"Chromium browser (alert/marker hook fired). This proves script "
                                          f"execution, whether via server reflection or a client-side DOM sink. "
                                          f"PoC URL: {probe_url}"),
                            )
            finally:
                try:
                    browser.close()
                except Exception:
                    pass
    except Exception as e:
        return DomXssProof(confirmed=False, available=True,
                           note=f"DOM scan error: {e.__class__.__name__}: {e}")

    return DomXssProof(confirmed=False, available=True,
                       note="No JavaScript execution observed across tested payload URLs.")
