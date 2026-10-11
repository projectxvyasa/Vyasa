#!/usr/bin/env python3
"""
VYASA live injection diagnostic.

Run this in YOUR normal terminal (not a restricted sandbox) against an
AUTHORIZED target to see exactly what the server does with an injected payload,
and whether VYASA's confirmation engine fires.

Usage:
    python diag_injection.py "https://www.mohittours.com/search/test123/"

It reports, for the URL path vector:
  * HTTP status, final URL, redirect chain
  * whether a benign canary is reflected, and in what context
  * whether '<', '>' survive unencoded (the XSS pre-condition)
Then it runs confirm_xss() and confirm_sqli() the same way the scanner does.
"""

import sys
import os
import importlib.util
from urllib.parse import urlparse, quote

import urllib3
import requests
urllib3.disable_warnings()

HERE = os.path.dirname(os.path.abspath(__file__))
MOD_PATH = os.path.join(HERE, "vyasa", "testing", "injection_confirm.py")


def load_engine():
    spec = importlib.util.spec_from_file_location("injection_confirm", MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def hr(t):
    print("\n" + "=" * 72 + f"\n{t}\n" + "=" * 72)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    url = sys.argv[1]
    engine = load_engine()

    s = requests.Session()
    s.verify = False
    s.headers.update({"User-Agent": "Mozilla/5.0 (VYASA-diag)"})

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    path = parsed.path or "/"
    segs = [x for x in path.split("/") if x]
    # Parent path with the last segment removed (so confirm appends a fresh one).
    parent = base + "/" + "/".join(segs[:-1]) if len(segs) > 1 else base + "/" + (segs[0] if segs else "")
    parent = parent.rstrip("/")

    hr("1. RAW REFLECTION PROBE (payload in the last path segment)")
    tok = "vyDiag7391"
    for desc, seg in [("benign canary", tok),
                      ("raw tag payload", f"<svg onload=/*{tok}*/>")]:
        probe_url = f"{parent}/{quote(seg, safe='/')}/"
        try:
            r = s.get(probe_url, timeout=20, allow_redirects=True)
            body = r.text or ""
            chain = [h.status_code for h in r.history]
            print(f"\n[{desc}] GET {probe_url}")
            print(f"  status={r.status_code}  final={r.url}  redirects={chain}  bytes={len(body)}")
            i = body.find(tok)
            if i == -1:
                print("  canary token NOT reflected in the response body")
                print(f"    encoded '&lt;svg' present? {'&lt;svg' in body}")
                print(f"    percent '%3Csvg' present? {'%3Csvg' in body}")
            else:
                snippet = body[max(0, i - 70):i + 70]
                print(f"  canary reflected at offset {i}")
                print(f"    context snippet: {snippet!r}")
                print(f"    raw '<svg onload=/*{tok}*/' present unencoded? "
                      f"{('<svg onload=/*' + tok + '*/') in body}")
                print(f"    encoded '&lt;svg' present instead?        {'&lt;svg' in body}")
        except Exception as e:
            print(f"\n[{desc}] ERROR {type(e).__name__}: {e}")

    hr("2. VYASA confirm_xss() — path vector")
    for label, u in [("parent (engine appends segment)", parent),
                     ("full url as given", url)]:
        try:
            p = engine.confirm_xss(s, "GET", u, {}, timeout=20)
            if p:
                print(f"\n[{label}] CONFIRMED  vector={p.vector} technique={p.technique}")
                print(f"    {p.evidence}")
            else:
                print(f"\n[{label}] not confirmed")
        except Exception as e:
            print(f"\n[{label}] ERROR {type(e).__name__}: {e}")

    hr("3. VYASA confirm_sqli() — path vector")
    try:
        p = engine.confirm_sqli(s, "GET", url, {}, timeout=20, time_delay=5)
        print("CONFIRMED: " + p.evidence if p else "not confirmed")
    except Exception as e:
        print(f"ERROR {type(e).__name__}: {e}")

    print("\nDone. If section 1 shows the canary reflected with raw '<svg...' present "
          "but section 2 says 'not confirmed', paste this whole output back.")


if __name__ == "__main__":
    main()
