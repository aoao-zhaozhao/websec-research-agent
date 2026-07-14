from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import requests

from agent.tools import BASE_TOOLS
from agent.tools.auth_session_tools import _denied_response, reset_auth_session_mode, set_auth_session_mode
from agent.tools.results import parse_tool_result


def _b64(data: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode()).rstrip(b"=").decode()


def _token(admin: bool) -> str:
    header = _b64({"alg": "HS256", "typ": "JWT"})
    payload = _b64({"sub": {"admin": admin, "data": {"username": "zombo", "password": "zombo"}}})
    signing_input = f"{header}.{payload}"
    signature = base64.urlsafe_b64encode(hmac.new(b"123", signing_input.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{signing_input}.{signature}"


class _AuthHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        return

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        values = parse_qs(body)
        if self.path == "/login" and values.get("username") == ["zombo"] and values.get("password") == ["zombo"]:
            self.send_response(302)
            self.send_header("Location", "/home")
            self.send_header("Set-Cookie", f"token={_token(False)}; HttpOnly; Path=/")
            self.end_headers()
            return
        self.send_response(401)
        self.end_headers()

    def do_GET(self):  # noqa: N802
        if self.path not in {"/home", "/soft-home"}:
            self.send_response(404)
            self.end_headers()
            return
        if self.path == "/soft-home":
            body = b"Login to access to home page"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        token = next((part[6:] for part in self.headers.get("Cookie", "").split("; ") if part.startswith("token=")), "")
        payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "==")) if token.count(".") == 2 else {}
        if payload.get("sub", {}).get("admin") is True:
            body = b"admin evidence shellmates{test_flag}"
            self.send_response(200)
        else:
            body = b"not admin"
            self.send_response(403)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _invoke(name: str, arguments: dict):
    tool = next(item for item in BASE_TOOLS if item.name == name)
    return parse_tool_result(tool.invoke(arguments))


class AuthSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _AuthHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_auth_session_jwt_flow_keeps_token_and_secret_out_of_results(self):
        text, login = _invoke("auth_login", {"url": f"{self.base_url}/login", "username": "zombo", "password": "zombo"})
        session_ref = login["data"]["session_ref"]
        self.assertEqual(login["data"]["redirect"], "/home")
        self.assertTrue(login["data"]["jwt"]["present"])
        self.assertNotIn("eyJ", text)
        self.assertNotIn("zombo", text)

        text, review = _invoke("session_jwt_review", {"session_ref": session_ref})
        self.assertEqual(review["data"]["claims"]["sub"]["admin"], False)
        self.assertEqual(review["data"]["claims"]["sub"]["data"]["password"], "[REDACTED]")
        self.assertNotIn("eyJ", text)

        text, checked = _invoke("session_jwt_hmac_check", {"session_ref": session_ref})
        self.assertTrue(checked["data"]["weak_key_confirmed"])
        self.assertNotIn("123", text)
        safe_data = {key: value for key, value in checked["data"].items() if key != "session_ref"}
        self.assertNotIn("123", json.dumps(safe_data))

        _text, denied = _invoke("session_jwt_privilege_check", {"session_ref": session_ref, "path": "/home"})
        self.assertEqual(denied["status"], "error")

        context = set_auth_session_mode("benchmark")
        try:
            text, validated = _invoke("session_jwt_privilege_check", {"session_ref": session_ref, "path": "/home"})
            self.assertTrue(validated["data"]["validated"])
            self.assertTrue(validated["data"]["baseline_denied"])
            self.assertTrue(validated["data"]["content_changed"])
            self.assertNotIn("eyJ", text)
            self.assertNotIn("123", text)

            text, search = _invoke(
                "session_response_search",
                {"session_ref": session_ref, "path": "/home", "keyword_or_regex": r"regex:shellmates\{[^}]+\}"},
            )
        finally:
            reset_auth_session_mode(context)
        self.assertEqual(search["data"]["match_count"], 1)
        self.assertIn("shellmates{test_flag}", text)

    def test_privilege_check_rejects_an_unchanged_http_200_login_page(self):
        _text, login = _invoke("auth_login", {"url": f"{self.base_url}/login", "username": "zombo", "password": "zombo"})
        context = set_auth_session_mode("benchmark")
        try:
            _text, result = _invoke("session_jwt_privilege_check", {"session_ref": login["data"]["session_ref"], "path": "/soft-home"})
        finally:
            reset_auth_session_mode(context)

        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["data"]["baseline_denied"])
        self.assertFalse(result["data"]["content_changed"])
        self.assertFalse(result["data"]["validated"])

    def test_legacy_jwt_tools_are_not_available_to_the_agent(self):
        names = {tool.name for tool in BASE_TOOLS}
        self.assertNotIn("jwt_hmac_brute", names)
        self.assertNotIn("jwt_alg_none_attack", names)
        self.assertNotIn("jwt_key_confusion", names)

    def test_denied_response_recognizes_the_challenge_guest_message(self):
        response = requests.Response()
        response.status_code = 200
        response._content = b"Sorry, you are not an admin"
        self.assertTrue(_denied_response(response))


if __name__ == "__main__":
    unittest.main()
