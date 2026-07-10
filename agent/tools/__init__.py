"""
Agent 工具集 —— 统一导出所有扫描工具。
"""

from .http_tools import http_get, http_post, http_request
from .analysis_tools import analyze_headers, extract_forms, extract_links
from .crawl_tools import crawl, sitemap, batch_scan
from .static_tools import analyze_js, decode_jwt, discover_api, render_page
from .lfi_tools import test_lfi_param
from .verification_tools import verify_injection
from .structured import structured_tool

# 基础工具列表（不包含 search_knowledge，由 rag.py 动态注入）
BASE_TOOLS = [
    structured_tool(tool)
    for tool in (
        http_get,
        http_post,
        http_request,
        analyze_headers,
        extract_forms,
        extract_links,
        analyze_js,
        decode_jwt,
        discover_api,
        render_page,
        test_lfi_param,
        verify_injection,
        crawl,
        sitemap,
        batch_scan,
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
    "crawl",
    "sitemap",
    "batch_scan",
    "BASE_TOOLS",
]
