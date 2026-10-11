"""
Tests verifying the 100+ Vulnerability Catalog, DeepScanner, and Customized Reporting.
"""

import unittest
from unittest.mock import patch, MagicMock
from vyasa.core.models import Asset, ReportPreferences, Finding, Severity
from vyasa.core.config import ReportingConfig
from vyasa.testing.vulnerability_catalog import VULNERABILITY_CATALOG
from vyasa.testing.deep_scanner import DeepScanner
from vyasa.reporting.generator import ReportGenerator


class TestDeepScannerAndReporting(unittest.TestCase):

    def setUp(self):
        self.asset = Asset(asset_id="asset_test", host="testcorp.internal", open_ports=[80, 443])

    def test_vulnerability_catalog_count(self):
        """Verify the catalog contains exactly 100 standard vulnerability checks."""
        self.assertEqual(len(VULNERABILITY_CATALOG), 100)
        categories = {c.category for c in VULNERABILITY_CATALOG}
        self.assertIn("Authentication & Session", categories)
        self.assertIn("Broken Access Control (BOLA)", categories)
        self.assertIn("Business Logic", categories)
        self.assertIn("API Security & GraphQL", categories)
        self.assertIn("Injection Canaries", categories)
        self.assertIn("Security Misconfiguration", categories)
        self.assertIn("Information Disclosure", categories)

    def test_deep_scanner_execution(self):
        """Test DeepScanner running checks against an asset and collecting telemetry."""
        scanner = DeepScanner(timeout=1.0)
        with patch.object(scanner.session, "get") as mock_get, patch.object(scanner.session, "post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "OK"
            mock_resp.headers = {"Strict-Transport-Security": "max-age=31536000"}
            mock_get.return_value = mock_resp
            mock_post.return_value = mock_resp

            findings, telemetry = scanner.run_deep_audit(self.asset, live_console=False)
            self.assertEqual(len(telemetry), 100)
            self.assertTrue(all(t.verdict in ("VULNERABLE", "SECURE", "INCONCLUSIVE") for t in telemetry))

    def test_customized_report_generation(self):
        """Test report generator respecting user section preferences."""
        generator = ReportGenerator(ReportingConfig(output_dir="reports", output_format=["markdown", "json"]))
        
        # Test preference with telemetry included
        prefs = ReportPreferences(
            include_executive_summary=True,
            include_investigation_telemetry=True,
            include_attack_paths=False,
            include_vulnerability_catalog=True,
            include_full_test_matrix=True,
            include_raw_evidence=False,
            include_remediation_roadmap=True
        )

        dummy_finding = Finding(
            finding_id="find_test",
            title="Test Finding Title",
            description="Test Description",
            severity=Severity.HIGH,
            asset_id="asset_test",
            evidence="GET / evidence test",
            cvss_score=7.5
        )

        report = generator.generate_report(
            target="testcorp.internal",
            assets=[self.asset],
            findings=[dummy_finding],
            attack_paths=[],
            investigation_telemetry=[],
            preferences=prefs
        )

        self.assertIsNotNone(report)
        md_file = generator.output_dir / f"{report.report_id}.md"
        self.assertTrue(md_file.exists())
        with open(md_file, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("Executive Summary", content)
            self.assertIn("Comprehensive Vulnerability Test Matrix (100+ Check Catalog)", content)
            # Attack paths were excluded by preference
            self.assertNotIn("Correlated Attack Paths", content)

    def test_selective_checks_execution(self):
        """Test DeepScanner executing only user-selected checks (e.g., SQLi Only)."""
        scanner = DeepScanner(timeout=1.0)
        with patch.object(scanner.session, "get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "Normal response"
            mock_get.return_value = mock_resp

            # Request only INJ-01 (SQLi Diagnostic Reflection)
            findings, telemetry = scanner.run_deep_audit(
                self.asset,
                selected_checks=["INJ-01"],
                live_console=False
            )
            self.assertEqual(len(telemetry), 1)
            self.assertEqual(telemetry[0].probe_id, "INJ-01")
            self.assertEqual(telemetry[0].category, "Injection Canaries")

    def test_target_endpoint_scoping(self):
        """Test DeepScanner evaluating a specific user-defined endpoint path."""
        scanner = DeepScanner(timeout=1.0)
        with patch.object(scanner.session, "get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "syntax error in query"
            mock_get.return_value = mock_resp

            findings, telemetry = scanner.run_deep_audit(
                self.asset,
                selected_checks=["INJ-01"],
                target_endpoint="/api/v1/search",
                live_console=False
            )
            self.assertEqual(len(telemetry), 1)
            self.assertEqual(telemetry[0].endpoint, "/api/v1/search")
            self.assertEqual(telemetry[0].verdict, "VULNERABLE")
            self.assertEqual(len(findings), 1)
            self.assertIn("/api/v1/search", findings[0].title)

    def test_xss_probe_reflection(self):
        """Test DeepScanner detecting reflected XSS canary payloads on endpoints/parameters."""
        scanner = DeepScanner(timeout=1.0)
        with patch.object(scanner.session, "get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
            mock_resp.text = '<html><body><h1>Search Results for: <script>vyasa_xss_canary_882()</script></h1></body></html>'
            mock_get.return_value = mock_resp

            findings, telemetry = scanner.run_deep_audit(
                self.asset,
                selected_checks=["INJ-06"],
                target_endpoint="/search?q=test",
                live_console=False
            )
            self.assertEqual(len(telemetry), 1)
            self.assertEqual(telemetry[0].verdict, "VULNERABLE")
            self.assertEqual(len(findings), 1)
            self.assertIn("Cross-Site Scripting", findings[0].title)


if __name__ == "__main__":
    unittest.main()
