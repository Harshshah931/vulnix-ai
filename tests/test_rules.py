from __future__ import annotations

import unittest
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from vulnix.rules import analyze_response, _cookie_details
from vulnix.url_safety import URLSafetyError, normalize_url, same_site_host, validate_public_url
from vulnix.demo import sample_report
from vulnix.reporting import to_csv_bytes, to_html_bytes, to_json_bytes
from vulnix.scanner import scan_website


class URLSafetyTests(unittest.TestCase):
    def test_adds_https_when_scheme_is_missing(self):
        self.assertEqual(normalize_url("example.com"), "https://example.com/")

    def test_rejects_non_http_scheme(self):
        with self.assertRaises(URLSafetyError):
            normalize_url("file:///etc/passwd")

    def test_rejects_embedded_credentials(self):
        with self.assertRaises(URLSafetyError):
            normalize_url("https://user:pass@example.com")

    def test_rejects_nonstandard_port(self):
        with self.assertRaises(URLSafetyError):
            normalize_url("https://example.com:8443")

    def test_rejects_localhost(self):
        with self.assertRaises(URLSafetyError):
            normalize_url("http://localhost:80")

    def test_rejects_control_characters(self):
        with self.assertRaises(URLSafetyError):
            normalize_url("https://example.com/path\r\nHost: internal")

    def test_unicode_hostname_is_converted_to_idna(self):
        self.assertEqual(normalize_url("https://bücher.example"), "https://xn--bcher-kva.example/")

    def test_fragments_are_removed(self):
        self.assertEqual(normalize_url("https://example.com/path#fragment"), "https://example.com/path")

    def test_www_redirect_scope(self):
        self.assertTrue(same_site_host("www.example.com", "example.com"))
        self.assertFalse(same_site_host("example.com", "example.net"))

    def test_blocks_private_ip_destinations(self):
        with self.assertRaises(URLSafetyError):
            validate_public_url("http://127.0.0.1")
        with self.assertRaises(URLSafetyError):
            validate_public_url("http://10.0.0.8")

    def test_authorisation_is_required_before_any_scan(self):
        with self.assertRaises(URLSafetyError):
            scan_website("https://example.com", authorization_confirmed=False)


class RuleEngineTests(unittest.TestCase):
    def test_missing_headers_create_expected_findings(self):
        findings = analyze_response(
            requested_url="https://example.com/",
            final_url="https://example.com/",
            headers={"Content-Type": "text/html"},
            html="<html><head><title>Test</title></head><body>Hello</body></html>",
            set_cookie_headers=[],
            tls_info={"verified": True},
        )
        ids = {item["id"] for item in findings}
        self.assertIn("VX-HDR-001", ids)
        self.assertIn("VX-HDR-002", ids)
        self.assertIn("VX-HDR-003", ids)
        self.assertIn("VX-HDR-004", ids)

    def test_secure_headers_reduce_header_findings(self):
        findings = analyze_response(
            requested_url="https://example.com/",
            final_url="https://example.com/",
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=(), microphone=()",
                "X-Frame-Options": "DENY",
            },
            html="<html><body>OK</body></html>",
            set_cookie_headers=[],
            tls_info={"verified": True},
        )
        ids = {item["id"] for item in findings}
        self.assertNotIn("VX-HDR-001", ids)
        self.assertNotIn("VX-HDR-002", ids)
        self.assertNotIn("VX-HDR-003", ids)
        self.assertNotIn("VX-HDR-004", ids)
        self.assertNotIn("VX-HDR-005", ids)
        self.assertNotIn("VX-HDR-006", ids)
        self.assertNotIn("VX-HDR-007", ids)
        self.assertNotIn("VX-HDR-008", ids)

    def test_hsts_zero_max_age_is_flagged(self):
        findings = analyze_response(
            requested_url="https://example.com/", final_url="https://example.com/",
            headers={"Strict-Transport-Security": "max-age=0", "Content-Security-Policy": "default-src 'self'; script-src 'self'", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"},
            html="", set_cookie_headers=[], tls_info={"verified": True},
        )
        self.assertIn("VX-HDR-007", {item["id"] for item in findings})

    def test_permissive_csp_is_flagged(self):
        findings = analyze_response(
            requested_url="https://example.com/", final_url="https://example.com/",
            headers={"Content-Security-Policy": "default-src 'self'; script-src * 'unsafe-eval' 'unsafe-inline'"},
            html="", set_cookie_headers=[], tls_info={"verified": True},
        )
        result = next(item for item in findings if item["id"] == "VX-HDR-008")
        self.assertEqual(result["status"], "Policy hardening recommendation")
        self.assertIn("unsafe-eval", result["evidence"])

    def test_invalid_x_frame_options_does_not_count_as_protection(self):
        findings = analyze_response(
            requested_url="https://example.com/", final_url="https://example.com/",
            headers={"X-Frame-Options": "ALLOW-FROM https://trusted.example"},
            html="", set_cookie_headers=[], tls_info={"verified": True},
        )
        result = next(item for item in findings if item["id"] == "VX-HDR-003")
        self.assertIn("ALLOW-FROM", result["evidence"])

    def test_cookie_values_are_never_in_evidence(self):
        raw = ["session_id=very-secret-value; Path=/; SameSite=Lax"]
        parsed = _cookie_details(raw)
        self.assertEqual(parsed[0]["name"], "session_id")
        self.assertNotIn("very-secret-value", repr(parsed))
        findings = analyze_response(
            requested_url="https://example.com/", final_url="https://example.com/",
            headers={"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"},
            html="", set_cookie_headers=raw, tls_info={"verified": True},
        )
        self.assertNotIn("very-secret-value", repr(findings))
        self.assertTrue(any(item["id"] == "VX-COOKIE-001" for item in findings))

    def test_http_and_password_form_are_detected(self):
        findings = analyze_response(
            requested_url="http://example.com/", final_url="http://example.com/",
            headers={}, html='<form><input type="password" name="password"></form>',
            set_cookie_headers=[], tls_info={},
        )
        ids = {item["id"] for item in findings}
        self.assertIn("VX-HTTP-001", ids)
        self.assertIn("VX-FORM-002", ids)

    def test_mixed_content_is_detected_on_https(self):
        findings = analyze_response(
            requested_url="https://example.com/", final_url="https://example.com/",
            headers={"Content-Security-Policy": "default-src 'self'", "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"},
            html='<script src="http://cdn.example.net/app.js"></script>', set_cookie_headers=[], tls_info={"verified": True},
        )
        self.assertIn("VX-HTML-001", {item["id"] for item in findings})

    def test_mixed_content_evidence_redacts_query_strings(self):
        findings = analyze_response(
            requested_url="https://example.com/", final_url="https://example.com/",
            headers={}, html='<script src="http://cdn.example.net/app.js?token=supersecret#frag"></script>',
            set_cookie_headers=[], tls_info={"verified": True},
        )
        item = next(item for item in findings if item["id"] == "VX-HTML-001")
        self.assertNotIn("supersecret", item["evidence"])
        self.assertNotIn("token=", item["evidence"])


class ScannerIntegrationTests(unittest.TestCase):
    def test_scanner_parses_mocked_http_response_without_external_network(self):
        body = b'<html><head><title>Scanner Integration</title></head><body><form><input type="password" name="pw"></form></body></html>'

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Set-Cookie", "session_id=never-export-this-value; Path=/")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        server_port = server.server_address[1]
        real_create_connection = socket.create_connection

        def pinned_test_connection(_address, timeout=None, source_address=None):
            # Route the scanner's pinned-public-IP socket to the local fixture server.
            # DNS resolution is mocked in this test only; production code still blocks
            # non-public IP destinations before any request is sent.
            return real_create_connection(("127.0.0.1", server_port), timeout=timeout, source_address=source_address)

        try:
            with patch("vulnix.url_safety.resolve_public_host", return_value=["93.184.216.34"]), \
                 patch("vulnix.scanner.resolve_public_host", return_value=["93.184.216.34"]), \
                 patch("vulnix.scanner.socket.create_connection", side_effect=pinned_test_connection):
                result = scan_website("http://scanner-test.example", authorization_confirmed=True)
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.page_title, "Scanner Integration")
            finding_ids = {finding["id"] for finding in result.findings}
            self.assertIn("VX-HTTP-001", finding_ids)
            self.assertIn("VX-FORM-002", finding_ids)
            self.assertNotIn("never-export-this-value", repr(result.to_dict()))
            self.assertEqual(result.errors, [])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)


class ReportTests(unittest.TestCase):
    def test_sample_report_exports(self):
        report = sample_report()
        self.assertTrue(report["warnings"])
        self.assertIn(b"synthetic", to_json_bytes(report).lower())
        self.assertIn(b"id,title,severity", to_csv_bytes(report))
        html = to_html_bytes(report, "Example summary <script>alert(1)</script>")
        self.assertIn(b"Vulnix AI Report", html)
        self.assertNotIn(b"<script>alert(1)</script>", html)
        self.assertIn(b"&lt;script&gt;", html)

    def test_csv_export_neutralises_spreadsheet_formulas(self):
        report = {"findings": [{
            "id": "VX-TEST", "title": "=HYPERLINK(\"https://evil.example\")", "severity": "Low",
            "category": "Test", "confidence": "High", "status": "Test",
            "evidence": "  +cmd", "impact": "@SUM(1,1)", "remediation": "-1+1", "reference": "https://example.com",
        }]}
        csv_bytes = to_csv_bytes(report)
        self.assertIn(b"'=HYPERLINK", csv_bytes)
        self.assertIn(b"'  +cmd", csv_bytes)
        self.assertIn(b"'@SUM", csv_bytes)
        self.assertIn(b"'-1+1", csv_bytes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
