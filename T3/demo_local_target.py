#!/usr/bin/env python3
"""
Local Demo Target Application for VYASA Penetration Testing Platform.

Provides intentional, safe test endpoints on localhost to verify:
1. Reflected XSS (HTML body context, attribute context, path segment)
2. SQL Injection (Error-based and Boolean-based blind)
3. Safe sanitized endpoints for control/comparison

Usage:
    python demo_local_target.py [port]
    Default port: 8080 (http://127.0.0.1:8080)
"""

import sys
import html
import re
from urllib.parse import urlparse, parse_qs, unquote
from http.server import HTTPServer, BaseHTTPRequestHandler

MOCK_PRODUCTS = "".join(f"<li>Product #{i}: High-Performance Security Token</li>\n" for i in range(1, 15))


class LocalDemoHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Keep console output clean
        sys.stdout.write(f"[Local Target 8080] {args[0]} - {args[1]} {args[2]}\n")

    def _send_html(self, content: str, status_code: int = 200):
        body = content.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        # 1. Landing Page
        if path == "/" or path == "":
            html_doc = f"""<!DOCTYPE html>
<html>
<head><title>Localhost Security Testing Playground</title></head>
<body style="font-family:sans-serif; margin:40px;">
  <h1>Localhost Security Testing Playground</h1>
  <p>Authorized local test targets for VYASA:</p>
  <ul>
    <li><a href="/search?q=test">/search?q=test</a> (Reflected XSS - HTML body)</li>
    <li><a href="/profile?name=guest">/profile?name=guest</a> (Reflected XSS - Attribute context)</li>
    <li><a href="/products?id=1">/products?id=1</a> (SQL Injection - Error & Boolean-based)</li>
    <li><a href="/safe_search?q=test">/safe_search?q=test</a> (Safe control - HTML escaped)</li>
  </ul>
</body>
</html>"""
            self._send_html(html_doc)
            return

        # 2. Reflected XSS in HTML body (?q=...)
        if path == "/search":
            q_val = params.get("q", [""])[0]
            html_doc = f"""<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body>
  <h1>Search Results for: {q_val}</h1>
  <p>Found 0 matching records.</p>
</body>
</html>"""
            self._send_html(html_doc)
            return

        # 3. Reflected XSS in Attribute context (?name=...)
        if path == "/profile":
            name_val = params.get("name", ["guest"])[0]
            html_doc = f"""<!DOCTYPE html>
<html>
<head><title>User Profile</title></head>
<body>
  <h2>Edit Profile</h2>
  <form method="GET" action="/profile">
    <label>Username:</label>
    <input type="text" name="name" value="{name_val}">
    <input type="submit" value="Save">
  </form>
</body>
</html>"""
            self._send_html(html_doc)
            return

        # 4. Reflected XSS in URL Path Segment (/search/<segment>/)
        if path.startswith("/search/"):
            raw_seg = path[len("/search/"):].rstrip("/")
            decoded_seg = unquote(raw_seg)
            html_doc = f"""<!DOCTYPE html>
<html>
<head><title>Search Directory</title></head>
<body>
  <h1>Search directory for: {decoded_seg}</h1>
</body>
</html>"""
            self._send_html(html_doc)
            return

        # 5. SQL Injection (?id=...)
        if path == "/products" or path == "/item":
            id_val = params.get("id", ["1"])[0]
            low_id = id_val.lower()

            # Error-based trigger: quotes trigger a simulated DBMS error
            if "'" in id_val or '"' in id_val:
                err_doc = """<!DOCTYPE html>
<html>
<head><title>500 Internal Server Error</title></head>
<body>
  <h1>Database Error</h1>
  <p>Database error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax near '\' LIMIT 1' at line 1</p>
</body>
</html>"""
                self._send_html(err_doc, status_code=500)
                return

            # Boolean-based differential trigger:
            if any(f in low_id for f in ("1=2", "1'='2", "7=8", '7"="8', "1=3")):
                # False condition -> No results
                false_doc = """<!DOCTYPE html>
<html>
<head><title>Product Catalog</title></head>
<body>
  <h1>Product Catalog</h1>
  <p>No products found matching query.</p>
</body>
</html>"""
                self._send_html(false_doc)
                return

            # Normal or True condition -> Return catalog
            true_doc = f"""<!DOCTYPE html>
<html>
<head><title>Product Catalog</title></head>
<body>
  <h1>Product Catalog</h1>
  <ul>
    {MOCK_PRODUCTS}
  </ul>
</body>
</html>"""
            self._send_html(true_doc)
            return

        # 6. Safe Search (Control)
        if path == "/safe_search":
            q_val = params.get("q", [""])[0]
            safe_q = html.escape(q_val)
            html_doc = f"""<!DOCTYPE html>
<html>
<head><title>Safe Search</title></head>
<body>
  <h1>Search results for: {safe_q}</h1>
  <p>Query sanitized safely.</p>
</body>
</html>"""
            self._send_html(html_doc)
            return

        # 404 fallback
        self._send_html("<html><body><h1>404 Not Found</h1></body></html>", status_code=404)

    def do_POST(self):
        # Support POST form vectors
        content_len = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else ""
        params = parse_qs(post_data)

        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/feedback" or path == "/comment":
            comment = params.get("comment", [""])[0]
            html_doc = f"""<!DOCTYPE html>
<html>
<head><title>Feedback Received</title></head>
<body>
  <h2>Thank you for your feedback!</h2>
  <div class="user-comment">{comment}</div>
</body>
</html>"""
            self._send_html(html_doc)
            return

        self._send_html("<html><body><h1>404 Not Found</h1></body></html>", status_code=404)


def run(port: int = 8080):
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, LocalDemoHandler)
    print(f"===========================================================")
    print(f"[*] Local Security Playground running at: http://127.0.0.1:{port}")
    print(f"[*] Endpoints ready for testing:")
    print(f"    - http://127.0.0.1:{port}/search?q=test         (Reflected XSS)")
    print(f"    - http://127.0.0.1:{port}/profile?name=guest    (Attribute XSS)")
    print(f"    - http://127.0.0.1:{port}/products?id=1         (SQL Injection)")
    print(f"    - http://127.0.0.1:{port}/safe_search?q=test    (Safe Control)")
    print(f"===========================================================")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")


if __name__ == "__main__":
    port_arg = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    run(port_arg)
