from __future__ import annotations

import threading
import unittest
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import requests

from agent.tools.analysis_tools import analyze_headers
from agent.tools.results import parse_tool_result
from agent.tools.verification_tools import verify_injection


class _TargetHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        return

    def _write(self, text: str) -> None:
        encoded = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        value = parse_qs(parsed.query).get("value", [""])[0]
        if parsed.path == "/sqli":
            self._write("SQL syntax error near quote" if "'" in value else "product list")
        elif parsed.path == "/xss":
            self._write(f"search result: {value}")
        elif parsed.path == "/lfi":
            if value == "convert.base64-encode":
                self._write("cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA==")
            else:
                self._write("root:x:0:0:root:/root:/bin/bash" if "etc/passwd" in value else "home page")
        elif parsed.path == "/weak":
            self._write(f"request received: {value}")
        else:
            self._write("ok")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        value = parse_qs(self.rfile.read(length).decode("utf-8")).get("value", [""])[0]
        self._write(f"posted: {value}")


class ActiveVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _TargetHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"
        cls.rate_limit = patch("agent.tools.http_client.DEFAULT_MIN_INTERVAL", 0)
        cls.rate_limit.start()

    @classmethod
    def tearDownClass(cls):
        cls.rate_limit.stop()
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def invoke_verify(self, path: str, vuln_type: str, **extra):
        output = verify_injection.invoke({
            "url": f"{self.base_url}{path}?value=home",
            "param": "value",
            "vuln_type": vuln_type,
            **extra,
        })
        return parse_tool_result(output)

    def test_sqli_confirmation_has_control_and_differential_evidence(self):
        _text, result = self.invoke_verify("/sqli", "sqli")

        self.assertEqual(result["findings"][0]["confidence"], "confirmed")
        self.assertEqual(result["data"]["baseline"]["status_code"], 200)
        self.assertEqual(result["data"]["invalid"]["status_code"], 200)
        self.assertIn("database error marker", result["findings"][0]["evidence"][0]["description"])

    def test_xss_and_lfi_have_fixed_confirmed_regressions(self):
        for path, vuln_type in (("/xss", "xss"), ("/lfi", "lfi")):
            with self.subTest(vuln_type=vuln_type):
                _text, result = self.invoke_verify(path, vuln_type)
                self.assertEqual(result["findings"][0]["confidence"], "confirmed")
                self.assertTrue(result["data"]["attempts"])

    def test_weak_signal_is_not_promoted_to_confirmed(self):
        _text, result = self.invoke_verify("/weak", "sqli")

        self.assertEqual(result["findings"][0]["confidence"], "weak")

    def test_post_form_verification_uses_the_supplied_body(self):
        output = verify_injection.invoke({
            "url": f"{self.base_url}/post",
            "param": "value",
            "vuln_type": "xss",
            "method": "POST",
            "form_data": "value=home&other=1",
        })
        _text, result = parse_tool_result(output)

        self.assertEqual(result["findings"][0]["confidence"], "confirmed")
        self.assertEqual(result["request"]["method"], "POST")

    def test_control_timeout_is_classified(self):
        with patch("agent.tools.verification_tools.request", side_effect=requests.exceptions.Timeout("slow")):
            output = verify_injection.invoke({
                "url": f"{self.base_url}/sqli?value=home",
                "param": "value",
                "vuln_type": "sqli",
            })
        _text, result = parse_tool_result(output)

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["errors"][0]["kind"], "timeout")

    def test_payload_parse_failure_is_classified(self):
        parse_error = json.JSONDecodeError("bad payload file", "{", 1)
        with patch("agent.tools.verification_tools._payloads", side_effect=parse_error):
            output = verify_injection.invoke({
                "url": f"{self.base_url}/sqli?value=home",
                "param": "value",
                "vuln_type": "sqli",
            })
        _text, result = parse_tool_result(output)

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["errors"][0]["kind"], "parse_error")

    def test_core_tool_is_native_not_a_legacy_adapter(self):
        output = analyze_headers.invoke({"url": f"{self.base_url}/headers"})
        _text, result = parse_tool_result(output)

        self.assertNotIn("migration", result["data"])
        self.assertEqual(result["request"]["method"], "GET")
        self.assertEqual(result["response"]["status_code"], 200)
