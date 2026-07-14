"""
Agent 工具集 —— 统一导出所有扫描工具。

v1.8: 新增流量取证工具和 MCP 桥接适配器。
"""

from .http_tools import http_get, http_post, http_request, set_traffic_capture_for_tools
from .targeted_search_tools import search_http_body, search_rendered_dom
from .auth_session_tools import auth_login, session_jwt_review, session_jwt_hmac_check, session_jwt_privilege_check, session_response_search
from .analysis_tools import analyze_headers, extract_forms, extract_links
from .crawl_tools import crawl, sitemap, batch_scan
from .static_tools import analyze_js, decode_jwt, discover_api, render_page
from .lfi_tools import test_lfi_param
from .verification_tools import verify_injection
from .exploit_tools import css_exfil_payload, webhook_reconstruct
from .skill_tools import (
    skill_archive,
    skill_create,
    skill_list,
    skill_load,
    skill_patch,
    skill_pin,
    skill_restore,
    skill_view,
    scan_reflect,
)
from .case_tools import case_create
from .ssrf_tools import test_ssrf, probe_internal_port
from .command_injection_tools import test_command_injection, test_ssti
from .jwt_attack_tools import jwt_alg_none_attack, jwt_hmac_brute, jwt_key_confusion
from .authz_tools import test_idor, test_privilege_escalation, test_role_manipulation
from .oob_tools import generate_oob_payload, check_oob_callbacks
from .traffic_tools import traffic_list, traffic_view, traffic_repeat, traffic_sitemap, set_traffic_store
from .structured import structured_tool, mcp_tool_adapter

# 基础工具列表（不包含 search_knowledge，由 rag.py 动态注入）
BASE_TOOLS = [
    structured_tool(tool)
    for tool in (
        # ── HTTP 基础 ──
        http_get,
        http_post,
        http_request,
        search_http_body,
        search_rendered_dom,
        auth_login,
        session_jwt_review,
        session_jwt_hmac_check,
        session_jwt_privilege_check,
        session_response_search,
        # ── 攻击面测绘 ──
        analyze_headers,
        extract_forms,
        extract_links,
        crawl,
        sitemap,
        batch_scan,
        analyze_js,
        discover_api,
        render_page,
        # ── 被动分析 ──
        decode_jwt,
        # ── 注入验证 ──
        test_lfi_param,
        verify_injection,
        test_command_injection,
        test_ssti,
        # ── SSRF 检测 ──
        test_ssrf,
        probe_internal_port,
        # ── 授权攻击 ──
        test_idor,
        test_privilege_escalation,
        test_role_manipulation,
        # ── OOB 外带确认 ──
        generate_oob_payload,
        check_oob_callbacks,
        # ── 高级利用 (CTF) ──
        css_exfil_payload,
        webhook_reconstruct,
        # ── 自进化技能 ──
        skill_list,
        skill_view,
        skill_load,
        skill_create,
        skill_patch,
        skill_pin,
        skill_archive,
        skill_restore,
        case_create,
        scan_reflect,
        # ── 流量取证 (v1.8) ──
        traffic_list,
        traffic_view,
        traffic_repeat,
        traffic_sitemap,
    )
]

__all__ = [
    "http_get",
    "http_post",
    "http_request",
    "search_http_body",
    "search_rendered_dom",
    "auth_login",
    "session_jwt_review",
    "session_jwt_hmac_check",
    "session_jwt_privilege_check",
    "session_response_search",
    "analyze_headers",
    "extract_forms",
    "extract_links",
    "analyze_js",
    "decode_jwt",
    "discover_api",
    "render_page",
    "test_lfi_param",
    "verify_injection",
    "test_command_injection",
    "test_ssti",
    "test_ssrf",
    "probe_internal_port",
    "test_idor",
    "test_privilege_escalation",
    "test_role_manipulation",
    "generate_oob_payload",
    "check_oob_callbacks",
    "crawl",
    "sitemap",
    "batch_scan",
    "css_exfil_payload",
    "webhook_reconstruct",
    "skill_list",
    "skill_view",
    "skill_load",
    "skill_create",
    "skill_patch",
    "skill_pin",
    "skill_archive",
    "skill_restore",
    "case_create",
    "scan_reflect",
    "traffic_list",
    "traffic_view",
    "traffic_repeat",
    "traffic_sitemap",
    "set_traffic_store",
    "set_traffic_capture_for_tools",
    "structured_tool",
    "mcp_tool_adapter",
    "BASE_TOOLS",
]
