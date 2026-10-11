"""Unit tests verifying specialized web security assessment probes."""

import unittest
from unittest.mock import patch, MagicMock
from vyasa.core.models import Asset, Severity
from vyasa.testing.cors_auditor import CORSAuditor
from vyasa.testing.graphql_auditor import GraphQLAuditor
from vyasa.testing.api_schema_auditor import APISchemaAuditor


class TestSpecializedProbes(unittest.TestCase):

    def setUp(self):
        self.asset = Asset(asset_id="asset_test1", host="app.example.internal", open_ports=[443])

    def test_cors_origin_reflection_with_credentials(self):
        auditor = CORSAuditor()
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.headers = {
                "Access-Control-Allow-Origin": "https://evil-security-audit.internal",
                "Access-Control-Allow-Credentials": "true"
            }
            mock_get.return_value = mock_resp
            findings = auditor.audit_cors(self.asset, 443, "https://app.example.internal")

            self.assertTrue(any("Arbitrary Origin Reflected with Credentials" in f.title for f in findings))
            finding = findings[0]
            self.assertEqual(finding.severity, Severity.HIGH)
            self.assertEqual(finding.cve_id, "CWE-942")

    def test_cors_null_origin_trusted(self):
        auditor = CORSAuditor()
        with patch("requests.get") as mock_get:
            # First call: normal origin, second call: null origin
            resp_normal = MagicMock()
            resp_normal.headers = {}
            resp_null = MagicMock()
            resp_null.headers = {
                "Access-Control-Allow-Origin": "null",
                "Access-Control-Allow-Credentials": "true"
            }
            mock_get.side_effect = [resp_normal, resp_null]
            findings = auditor.audit_cors(self.asset, 443, "https://app.example.internal")

            self.assertTrue(any("'null' Origin Trusted with Credentials" in f.title for f in findings))

    def test_graphql_introspection_enabled(self):
        auditor = GraphQLAuditor()
        with patch("requests.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "data": {
                    "__schema": {
                        "types": [
                            {"name": "User", "kind": "OBJECT"},
                            {"name": "AdminRole", "kind": "OBJECT"},
                            {"name": "Query", "kind": "OBJECT"}
                        ]
                    }
                }
            }
            mock_post.return_value = mock_resp
            findings = auditor.audit_graphql(self.asset, 443, "https://app.example.internal")

            self.assertTrue(any("GraphQL Schema Introspection Enabled" in f.title for f in findings))
            matching = next(f for f in findings if "Introspection" in f.title)
            self.assertIn("User", matching.description)
            self.assertEqual(matching.cve_id, "CWE-200")

    def test_graphql_playground_detected(self):
        auditor = GraphQLAuditor()
        with patch("requests.post") as mock_post, patch("requests.get") as mock_get:
            mock_post.return_value = MagicMock(status_code=400)
            mock_get_resp = MagicMock()
            mock_get_resp.status_code = 200
            mock_get_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
            mock_get_resp.text = "<html><head><title>GraphQL Playground</title></head><body></body></html>"
            mock_get.return_value = mock_get_resp

            findings = auditor.audit_graphql(self.asset, 443, "https://app.example.internal")
            self.assertTrue(any("GraphQL Playground" in f.title for f in findings))

    def test_openapi_schema_discovery(self):
        auditor = APISchemaAuditor()
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = '{"openapi": "3.0.0", "info": {"title": "Payments Gateway API"}}'
            mock_resp.headers = {"Content-Type": "application/json"}
            mock_resp.json.return_value = {
                "openapi": "3.0.0",
                "info": {"title": "Payments Gateway API", "version": "2.1"},
                "paths": {
                    "/api/v1/checkout": {},
                    "/api/v1/refund": {},
                    "/admin/system-status": {}
                }
            }
            mock_get.return_value = mock_resp
            findings = auditor.audit_api_schemas(self.asset, 443, "https://app.example.internal")

            self.assertTrue(any("Payments Gateway API" in f.title for f in findings))
            matching = next(f for f in findings if "Payments Gateway API" in f.title)
            self.assertEqual(matching.severity, Severity.HIGH)
            self.assertIn("/admin/system-status", matching.description)

    def test_swagger_ui_interface_detected(self):
        auditor = APISchemaAuditor()
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "<html><head><title>Swagger UI</title><link rel='stylesheet' href='swagger-ui.css'></head><body></body></html>"
            mock_resp.headers = {"Content-Type": "text/html"}
            mock_get.return_value = mock_resp

            findings = auditor.audit_api_schemas(self.asset, 443, "https://app.example.internal")
            self.assertTrue(any("Swagger UI" in f.title for f in findings))


if __name__ == "__main__":
    unittest.main()
