"""
Agent 工具集 —— 统一导出所有扫描工具。
"""

from .http_tools import http_get, http_post, http_request
from .analysis_tools import analyze_headers, extract_forms, extract_links
from .crawl_tools import crawl, sitemap, batch_scan
from .static_tools import analyze_js, decode_jwt, discover_api, render_page
from .lfi_tools import test_lfi_param
from .verification_tools import verify_injection
from .exploit_tools import css_exfil_payload, webhook_reconstruct
from .skill_tools import skill_list, skill_load, skill_create, skill_patch, scan_reflect
from .ssrf_tools import test_ssrf, probe_internal_port
from .command_injection_tools import test_command_injection, test_ssti
from .jwt_attack_tools import jwt_alg_none_attack, jwt_hmac_brute, jwt_key_confusion
from .authz_tools import test_idor, test_privilege_escalation, test_role_manipulation
from .oob_tools import generate_oob_payload, check_oob_callbacks
from .structured import structured_tool

# 基础工具列表（不包含 search_knowledge，由 rag.py 动态注入）
BASE_TOOLS = [
    structured_tool(tool)
    for tool in (
        # ── HTTP 基础 ──
        http_get,
        http_post,
        http_request,
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
        # ── JWT 主动攻击 ──
        jwt_alg_none_attack,
        jwt_hmac_brute,
        jwt_key_confusion,
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
        skill_load,
        skill_create,
        skill_patch,
        scan_reflect,
    )
]

__all__ = [
    "http_get",
    "http_post",
    "http_request",
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
    "jwt_alg_none_attack",
    "jwt_hmac_brute",
    "jwt_key_confusion",
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
    "skill_load",
    "skill_create",
    "skill_patch",
    "scan_reflect",
    "BASE_TOOLS",
]
