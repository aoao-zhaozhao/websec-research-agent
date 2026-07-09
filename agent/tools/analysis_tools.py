"""
页面分析工具: 安全头分析 / 表单提取 / 链接提取。

v0.5: 从 agent/core.py 拆分，无功能变更。
"""

import requests
import urllib3
from bs4 import BeautifulSoup
from langchain_core.tools import tool
from urllib.parse import urljoin, urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@tool
def analyze_headers(url: str) -> str:
    """
    分析目标 URL 的 HTTP 安全响应头。

    检查项:
        - Content-Security-Policy (CSP)
        - Strict-Transport-Security (HSTS)
        - X-Frame-Options
        - X-Content-Type-Options
        - Referrer-Policy
        - Permissions-Policy
        - Set-Cookie (HttpOnly / Secure / SameSite)

    参数:
        url: 目标 URL
    """
    try:
        r = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        headers = r.headers

        checks = {
            "Content-Security-Policy": "防止XSS和数据注入攻击",
            "Strict-Transport-Security": "强制HTTPS连接",
            "X-Frame-Options": "防止点击劫持",
            "X-Content-Type-Options": "防止MIME类型嗅探",
            "Referrer-Policy": "控制Referer信息泄露",
            "Permissions-Policy": "限制浏览器API使用",
        }

        result = [f"安全头分析 - {url}", f"HTTP Status: {r.status_code}", ""]
        issues = 0

        for header, desc in checks.items():
            if header in headers:
                result.append(f"  ✅ {header}: {headers[header]}")
            else:
                result.append(f"  ❌ {header} — 缺失 ({desc})")
                issues += 1

        # Cookie 安全
        cookies = headers.get("Set-Cookie", "")
        if cookies:
            cookie_flags = []
            if "HttpOnly" not in cookies:
                cookie_flags.append("HttpOnly 未设置")
            if "Secure" not in cookies:
                cookie_flags.append("Secure 未设置")
            if "SameSite" not in cookies:
                cookie_flags.append("SameSite 未设置")
            if cookie_flags:
                result.append(f"  ⚠️ Cookie 安全问题: {', '.join(cookie_flags)}")
                issues += len(cookie_flags)
        else:
            result.append("  ℹ️ 未设置 Cookie")

        result.append(f"\n共发现 {issues} 个安全问题")
        return "\n".join(result)
    except Exception as e:
        return f"analyze_headers Error: {str(e)}"


@tool
def extract_forms(url: str) -> str:
    """
    从页面 HTML 中提取所有 <form> 标签及其输入参数。

    返回: 每个表单的 action、method、以及所有 input/textarea/select 的 name/type。

    用途: 发现可测试的注入点。

    参数:
        url: 目标页面 URL
    """
    try:
        r = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        forms = soup.find_all("form")

        if not forms:
            return f"[extract_forms] {url}\n未发现任何表单。"

        result = [f"[extract_forms] {url} — 发现 {len(forms)} 个表单", ""]
        for i, form in enumerate(forms, 1):
            action = form.get("action", "(当前页面)")
            method = form.get("method", "GET").upper()
            result.append(f"表单 #{i}: {method} {action}")

            inputs = form.find_all(["input", "textarea", "select"])
            for inp in inputs:
                tag = inp.name
                name = inp.get("name", "(无名称)")
                itype = inp.get("type", "text") if tag == "input" else tag
                result.append(f"  [{itype}] {name}")
            result.append("")

        return "\n".join(result)
    except Exception as e:
        return f"extract_forms Error: {str(e)}"


@tool
def extract_links(url: str) -> str:
    """
    从页面 HTML 中提取所有 <a href> 链接。

    用途: 发现更多攻击面（API 端点、隐藏页面、管理后台等）。

    参数:
        url: 目标页面 URL
    """
    try:
        r = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        links = soup.find_all("a", href=True)

        base_domain = urlparse(url).netloc
        internal, external = [], []

        for link in links:
            href = urljoin(url, link["href"])
            parsed = urlparse(href)
            label = link.get_text(strip=True) or "(无文本)"
            entry = f"  {href}  — {label}"
            if parsed.netloc == base_domain or parsed.netloc == "":
                internal.append(entry)
            else:
                external.append(entry)

        result = [
            f"[extract_links] {url}",
            f"内部链接 ({len(internal)}):",
        ]
        result.extend(internal[:30])  # 最多 30 条
        result.append(f"\n外部链接 ({len(external)}) — 不扫描:")
        result.extend(external[:10])
        result.append(f"\n总计: {len(internal) + len(external)} 个链接")
        return "\n".join(result)
    except Exception as e:
        return f"extract_links Error: {str(e)}"
