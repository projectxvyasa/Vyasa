"""
Tests verifying Web Dashboard endpoints, Web Terminal, and Report Options.
"""

import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
from vyasa.web.app import app


class TestWebDashboardAndTerminal(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_dashboard_html_contains_terminal_and_options(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("web-terminal-logs", res.text)
        self.assertIn("config-modal", res.text)
        self.assertIn("Report Options", res.text)
        self.assertIn("endpoint-input", res.text)
        self.assertIn("vuln-modal", res.text)
        self.assertIn("selected-vulns-badge", res.text)
        self.assertIn("audit-launch-modal", res.text)
        self.assertIn("Automatic Testing", res.text)
        self.assertIn("Manual Testing", res.text)
        self.assertIn("theme-toggle-btn", res.text)
        self.assertIn("toggleTheme", res.text)

    def test_get_catalog_endpoint(self):
        res = self.client.get("/api/catalog")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(len(data), 100)
        check_ids = {c["check_id"] for c in data}
        self.assertIn("INJ-01", check_ids)
        self.assertIn("AUTH-01", check_ids)

    def test_delete_reports_endpoint(self):
        res = self.client.delete("/api/reports")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "success")

    @patch("vyasa.web.app.run_background_scan")
    def test_scan_api_accepts_preferences(self, mock_bg_scan):
        res = self.client.post("/api/scan", json={
            "target": "localhost",
            "endpoint": "/api/v1/search",
            "deep_scan": True,
            "selected_checks": ["INJ-01"],
            "preferences": {
                "include_executive_summary": True,
                "include_attack_paths": True,
                "include_investigation_telemetry": True
            },
            "clear_old_reports": True
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("scan_id", data)

        # Check status endpoint
        scan_id = data["scan_id"]
        res_status = self.client.get(f"/api/scan/{scan_id}")
        self.assertEqual(res_status.status_code, 200)
        status_data = res_status.json()
        self.assertIn("terminal_logs", status_data)
        self.assertEqual(status_data["endpoint"], "/api/v1/search")
        self.assertTrue(len(status_data["terminal_logs"]) >= 1)
        mock_bg_scan.assert_called_once()


if __name__ == "__main__":
    unittest.main()

