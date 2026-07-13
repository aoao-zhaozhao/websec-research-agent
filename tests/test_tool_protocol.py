from __future__ import annotations

import unittest
from unittest.mock import patch

import requests

from agent.tools import BASE_TOOLS
from agent.tools.results import parse_tool_result, tool_result_protocol_error


class FakeResponse:
    def __init__(
        self,
        text: str = "<html><body>ok</body></html>",
        status_code: int = 200,
        headers: dict[str, str] | None = None,
        reason: str = "OK",
    ):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "text/html"}
        self.reason = reason


def invoke(name: str, arguments: dict) -> tuple[str, dict | None]:
    tool = next(item for item in BASE_TOOLS if item.name == name)
    return parse_tool_result(tool.invoke(arguments))


class ToolProtocolTests(unittest.TestCase):
    def test_missing_result_envelope_is_a_protocol_failure(self):
        self.assertEqual(tool_result_protocol_error("unstructured text"), "missing_result_envelope")

    def test_headers_returns_findings_in_a_uniform_envelope(self):
        with patch("agent.tools.analysis_tools.get", return_value=FakeResponse()):
            text, result = invoke("analyze_headers", {"url": "http://scanner.test"})

        self.assertIn("安全头分析", text)
        self.assertEqual(result["tool"], "analyze_headers")
        self.assertEqual(result["status"], "ok")
        self.assertGreaterEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["confidence"], "confirmed")

    def test_headers_only_create_findings_for_missing_headers(self):
        headers = {
            "Content-Type": "text/html",
            "Content-Security-Policy": "default-src 'self'",
        }
        with patch("agent.tools.analysis_tools.get", return_value=FakeResponse(headers=headers)):
            _text, result = invoke("analyze_headers", {"url": "http://scanner.test"})

        titles = [finding["title"] for finding in result["findings"]]
        self.assertNotIn("缺少安全响应头：Content-Security-Policy", titles)
        self.assertIn("缺少安全响应头：X-Frame-Options", titles)

    def test_forms_empty_result_is_still_a_valid_envelope(self):
        with patch("agent.tools.analysis_tools.get", return_value=FakeResponse("<html></html>")):
            text, result = invoke("extract_forms", {"url": "http://scanner.test/form"})

        self.assertIn("未发现任何表单", text)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["errors"], [])

    def test_links_uses_shared_http_client_and_returns_structured_result(self):
        html = '<a href="/account">Account</a><a href="https://outside.test">Outside</a>'
        with patch("agent.tools.analysis_tools.get", return_value=FakeResponse(html)) as get:
            text, result = invoke("extract_links", {"url": "http://scanner.test"})

        get.assert_called_once()
        self.assertIn("内部链接 (1)", text)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["target"], "http://scanner.test")

    def test_generic_request_supports_put_and_uses_shared_client(self):
        with patch("agent.tools.http_tools.request", return_value=FakeResponse("wctf{example}")) as request:
            text, result = invoke(
                "http_request",
                {"method": "put", "url": "http://scanner.test/secret"},
            )

        request.assert_called_once_with("PUT", "http://scanner.test/secret", data=None, headers=None)
        self.assertIn("[PUT]", text)
        self.assertIn("wctf{example}", text)
        self.assertEqual(result["status"], "ok")

    def test_generic_request_rejects_disallowed_methods(self):
        text, result = invoke(
            "http_request",
            {"method": "DELETE", "url": "http://scanner.test/secret"},
        )

        self.assertIn("method not allowed", text)
        self.assertEqual(result["status"], "error")

    def test_timeout_is_classified_without_losing_the_text_summary(self):
        with patch(
            "agent.tools.analysis_tools.get",
            side_effect=requests.exceptions.Timeout("request timeout"),
        ):
            text, result = invoke("analyze_headers", {"url": "http://scanner.test"})

        self.assertIn("Error", text)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["errors"][0]["kind"], "timeout")

    def test_crawl_success_uses_the_same_envelope(self):
        response = FakeResponse('<a href="/next">Next</a>')
        with patch("agent.tools.crawl_tools.get", return_value=response):
            text, result = invoke("crawl", {"root_url": "http://scanner.test", "max_depth": 0, "max_pages": 1})

        self.assertIn("发现页面: 1", text)
        self.assertEqual(result["tool"], "crawl")
        self.assertEqual(result["status"], "ok")

    def test_lfi_baseline_failure_is_classified(self):
        with patch(
            "agent.tools.lfi_tools.get",
            side_effect=requests.exceptions.Timeout("request timeout"),
        ):
            text, result = invoke(
                "test_lfi_param",
                {"url": "http://scanner.test/index.php?file=home", "param": "file"},
            )

        self.assertIn("Baseline request failed", text)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["errors"][0]["kind"], "timeout")
