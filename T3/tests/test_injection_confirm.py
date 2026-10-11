"""
Network-free regression tests for the confirmation-gated injection engine.

Uses a FakeSession that emulates vulnerable and safe backend behaviour, so the
suite runs fast and deterministically without a live target. Verifies both that
real vulnerabilities are CONFIRMED and that safe / non-executing cases produce
no finding (zero false positives).
"""

import re
import time
import html
import unittest
from urllib.parse import unquote

from vyasa.testing.injection_confirm import (
    confirm_sqli, confirm_xss, confirm_ssti, confirm_command,
)
from vyasa.testing.dom_scanner import build_candidate_urls


class FakeResponse:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code


PRODUCTS = "".join(f"<li>Product {i} gadget</li>" for i in range(1, 40))


def _bool_true(v: str) -> bool:
    s = v.lower()
    if any(f in s for f in ("1=2", "1'='2", "7=8", '7"="8', "1=3")):
        return False
    if any(t in s for t in ("1=1", "1'='1", "7=7", '7"="7')):
        return True
    return True


def _sleep_secs(v: str) -> float:
    m = (re.search(r"sleep\((\d+)\)", v, re.I) or re.search(r"delay '0:0:(\d+)'", v, re.I)
         or re.search(r"pg_sleep\((\d+)\)", v, re.I))
    return float(m.group(1)) if m else 0.0


class FakeSession:
    """Routes requests to emulated endpoints by URL suffix."""

    def _handle(self, url, values):
        v = ""
        for k in ("id", "q", "comment", "name", "host"):
            if k in values:
                v = str(values[k]); break
        if url.endswith("/ssti"):
            def _ev(mm): return str(int(mm.group(1)) * int(mm.group(2)))
            out = re.sub(r"\{\{\s*(\d+)\*(\d+)\s*\}\}", _ev, v)
            out = re.sub(r"\$\{\s*(\d+)\*(\d+)\s*\}", _ev, out)
            return FakeResponse(f"<html><body><h1>Hello {out}</h1></body></html>")
        if url.endswith("/safe_ssti"):
            return FakeResponse(f"<html><body><h1>Hello {html.escape(v)}</h1></body></html>")
        if url.endswith("/cmd"):
            if re.search(r"(;|\||&&|%0a)\s*id", v):
                return FakeResponse("uid=33(www-data) gid=33(www-data) groups=33")
            m = re.search(r"(;|\||&&)\s*sleep\s+(\d+)", v)
            if m:
                time.sleep(int(m.group(2)))
            return FakeResponse(f"<html><body>Pinging {html.escape(v)}</body></html>")
        if url.endswith("/safe_cmd"):
            return FakeResponse(f"<html><body>Pinging {html.escape(v)}</body></html>")
        if url.endswith("/sus_js"):
            # JS string where the quote survives but ';' is stripped -> SUSPECTED.
            vv = v.replace(";", "")
            return FakeResponse(f"<html><body><script>var t='{vv}';</script></body></html>")
        if url.endswith("/err"):
            if "'" in v or '"' in v:
                return FakeResponse("Database error: You have an error in your SQL syntax; near \"'\"", 500)
            return FakeResponse(f"<html><body>Item {html.escape(v)}<ul>{PRODUCTS}</ul></body></html>")
        if url.endswith("/booln"):
            if _bool_true(v):
                return FakeResponse(f"<html><body>FOUND<ul>{PRODUCTS}</ul></body></html>")
            return FakeResponse("<html><body>No results.</body></html>")
        if url.endswith("/timed"):
            s = _sleep_secs(v)
            if s > 0:
                time.sleep(s)
            return FakeResponse(f"<html><body>OK {html.escape(v)}</body></html>")
        if url.endswith("/safe_sql"):
            return FakeResponse(f"<html><body>Item {html.escape(v)}<ul>{PRODUCTS}</ul></body></html>")
        if url.endswith("/xss_html"):
            return FakeResponse(f"<html><body><h1>Results for {v}</h1></body></html>")
        if url.endswith("/xss_attr"):
            return FakeResponse(f'<html><body><input type="text" value="{v}"></body></html>')
        if url.endswith("/xss_js"):
            return FakeResponse(f'<html><body><script>var term="{v}";</script></body></html>')
        if url.endswith("/xss_inert"):
            return FakeResponse(f"<html><body><textarea>{v}</textarea></body></html>")
        if url.endswith("/safe_xss"):
            return FakeResponse(f"<html><body><h1>Results for {html.escape(v)}</h1></body></html>")
        if url.endswith("/comment"):
            return FakeResponse(f"<html><body><div class=comment>{v}</div></body></html>")
        return FakeResponse("<html><body>default</body></html>")

    def _handle_path(self, url):
        """Emulate path-segment reflection routes (/search/<p>/, /item/<id>)."""
        path = unquote(url.split("://", 1)[-1].split("/", 1)[-1])  # strip host
        if "asearch/" in path:
            # Reflects in a quoted attribute -> needs "> breakout (mohittours class).
            seg = path.split("asearch/", 1)[1].rstrip("/")
            return FakeResponse(f'<html><body><input type="text" value="{seg}"></body></html>')
        if "search/" in path and "safe_search/" not in path:
            seg = path.split("search/", 1)[1].rstrip("/")
            return FakeResponse(f"<html><body><h1>Search for {seg}</h1></body></html>")
        if "safe_search/" in path:
            seg = path.split("safe_search/", 1)[1].rstrip("/")
            return FakeResponse(f"<html><body><h1>Search for {html.escape(seg)}</h1></body></html>")
        if "item/" in path:
            seg = path.split("item/", 1)[1].rstrip("/")
            if "'" in seg or '"' in seg:
                return FakeResponse("Database error: SQL syntax error near \"'\"", 500)
            return FakeResponse(f"<html><body>Item {html.escape(seg)}<ul>{PRODUCTS}</ul></body></html>")
        return None

    def get(self, url, params=None, timeout=None, verify=None, allow_redirects=None):
        if params is None or not params:
            ph = self._handle_path(url)
            if ph is not None:
                return ph
        return self._handle(url, params or {})

    def post(self, url, data=None, timeout=None, verify=None, allow_redirects=None):
        return self._handle(url, data or {})


B = "http://fake.local"


class TestSQLiConfirmation(unittest.TestCase):
    def setUp(self):
        self.s = FakeSession()

    def test_error_based_confirmed(self):
        p = confirm_sqli(self.s, "GET", f"{B}/err", {"id": "1"}, time_delay=1)
        self.assertIsNotNone(p)
        self.assertTrue(p.confirmed)
        self.assertIn("error-based", p.technique)
        self.assertIn("CONFIRMED VIA", p.evidence)

    def test_boolean_based_confirmed(self):
        p = confirm_sqli(self.s, "GET", f"{B}/booln", {"id": "1"}, time_delay=1)
        self.assertIsNotNone(p)
        self.assertIn("boolean", p.technique)

    def test_time_based_confirmed(self):
        p = confirm_sqli(self.s, "GET", f"{B}/timed", {"id": "1"}, time_delay=1)
        self.assertIsNotNone(p)
        self.assertIn("time-based", p.technique)

    def test_safe_sql_not_confirmed(self):
        p = confirm_sqli(self.s, "GET", f"{B}/safe_sql", {"id": "1"}, time_delay=1)
        self.assertIsNone(p)


class TestXSSConfirmation(unittest.TestCase):
    def setUp(self):
        self.s = FakeSession()

    def test_html_context_confirmed(self):
        p = confirm_xss(self.s, "GET", f"{B}/xss_html", {"q": "x"})
        self.assertIsNotNone(p)
        self.assertIn("html", p.technique)
        self.assertIn("UNENCODED", p.evidence)

    def test_attribute_context_confirmed(self):
        p = confirm_xss(self.s, "GET", f"{B}/xss_attr", {"q": "x"})
        self.assertIsNotNone(p)
        self.assertIn("attribute", p.technique)

    def test_js_context_confirmed(self):
        p = confirm_xss(self.s, "GET", f"{B}/xss_js", {"q": "x"})
        self.assertIsNotNone(p)
        self.assertIn("js", p.technique)

    def test_inert_container_not_confirmed(self):
        # Reflected verbatim but inside <textarea> -> not executable -> no finding.
        p = confirm_xss(self.s, "GET", f"{B}/xss_inert", {"q": "x"})
        self.assertIsNone(p)

    def test_safe_encoded_not_confirmed(self):
        p = confirm_xss(self.s, "GET", f"{B}/safe_xss", {"q": "x"})
        self.assertIsNone(p)

    def test_suspected_tier(self):
        # Reflected in JS string, quote survives but ';' stripped -> Suspected,
        # NOT confirmed (must not drive the risk score).
        p = confirm_xss(self.s, "GET", f"{B}/sus_js", {"q": "x"})
        self.assertIsNotNone(p)
        self.assertFalse(p.confirmed)
        self.assertEqual(p.state, "suspected")
        self.assertNotIn("CONFIRMED VIA", p.evidence)

    def test_post_form_confirmed(self):
        p = confirm_xss(self.s, "POST", f"{B}/comment", {"comment": "x"})
        self.assertIsNotNone(p)
        self.assertEqual(p.method, "POST")

    def test_path_segment_confirmed(self):
        # The /search/<payload>/ class: payload lives in the URL path, not a param.
        p = confirm_xss(self.s, "GET", f"{B}/search", {})
        self.assertIsNotNone(p)
        self.assertEqual(p.vector, "path")

    def test_path_segment_safe_not_confirmed(self):
        p = confirm_xss(self.s, "GET", f"{B}/safe_search", {})
        self.assertIsNone(p)

    def test_path_attribute_breakout_confirmed(self):
        # /asearch/<term> reflects inside value="..." -> confirmed via "> breakout.
        # This is the exact shape of the mohittours /search/"><script>...</script>/ bug.
        p = confirm_xss(self.s, "GET", f"{B}/asearch", {})
        self.assertIsNotNone(p)
        self.assertEqual(p.vector, "path")
        self.assertIn("attribute-breakout", p.technique)


class TestPathSQLi(unittest.TestCase):
    def setUp(self):
        self.s = FakeSession()

    def test_path_sqli_confirmed(self):
        # /item/<id> error-based SQLi via path substitution.
        p = confirm_sqli(self.s, "GET", f"{B}/item/1", {}, time_delay=1)
        self.assertIsNotNone(p)
        self.assertEqual(p.vector, "path")
        self.assertIn("error-based", p.technique)


class TestSSTIandCommand(unittest.TestCase):
    def setUp(self):
        self.s = FakeSession()

    def test_ssti_confirmed(self):
        p = confirm_ssti(self.s, "GET", f"{B}/ssti", {"name": "x"})
        self.assertIsNotNone(p)
        self.assertIn("template-eval", p.technique)

    def test_ssti_safe_not_confirmed(self):
        self.assertIsNone(confirm_ssti(self.s, "GET", f"{B}/safe_ssti", {"name": "x"}))

    def test_command_output_confirmed(self):
        p = confirm_command(self.s, "GET", f"{B}/cmd", {"host": "1"}, time_delay=1)
        self.assertIsNotNone(p)
        self.assertIn("output", p.technique)

    def test_command_safe_not_confirmed(self):
        self.assertIsNone(confirm_command(self.s, "GET", f"{B}/safe_cmd", {"host": "1"}, time_delay=1))


class TestDomCandidateUrls(unittest.TestCase):
    def test_fragment_vector_present_early(self):
        # The DOM fragment source must be probed (it caused an early miss when
        # ordered past the cap); confirm it's in the first few candidates.
        seeds = build_candidate_urls("http://x/search/test", max_urls=6)
        vectors = [v for (_, v, _, _) in seeds]
        self.assertIn("fragment", vectors)
        self.assertIn("path", vectors)


if __name__ == "__main__":
    unittest.main(verbosity=2)
