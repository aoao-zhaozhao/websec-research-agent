"""
Agent 工具集 —— 统一导出所有扫描工具。
"""

from .http_tools import http_get, http_post
from .analysis_tools import analyze_headers, extract_forms, extract_links
from .crawl_tools import crawl, sitemap, batch_scan

# 基础工具列表（不包含 search_knowledge，由 rag.py 动态注入）
BASE_TOOLS = [
    http_get,
    http_post,
    analyze_headers,
    extract_forms,
    extract_links,
    crawl,
    sitemap,
    batch_scan,
]

__all__ = [
    "http_get",
    "http_post",
    "analyze_headers",
    "extract_forms",
    "extract_links",
    "crawl",
    "sitemap",
    "batch_scan",
    "BASE_TOOLS",
]
