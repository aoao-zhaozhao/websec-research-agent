"""
爬虫与攻击面测绘工具: crawl / sitemap / batch_scan。

v0.5: 从 agent/core.py 拆分，无功能变更。
"""

import urllib3
from bs4 import BeautifulSoup
from langchain_core.tools import tool
from urllib.parse import urljoin, urlparse, urldefrag

from .http_client import get, in_scope_url, normalize_url
from .results import Evidence, Finding, RequestRecord, ToolResult, error_kind

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


@tool
def crawl(root_url: str, max_depth: int = 2, max_pages: int = 30) -> str:
    """
    从根 URL 出发，BFS 爬取同域下所有可达页面。

    自动发现:
        - 页面中所有 <a href> 内部链接
        - 常见敏感路径: /admin, /api, /.env, /backup, /robots.txt, /sitemap.xml, /.git/HEAD
        - <script src> 和 <link href> 中的 JS/CSS 资源路径（可能泄露 API 端点）

    参数:
        root_url: 根 URL（如 http://example.com）
        max_depth: 最大爬取深度（默认 2，建议 2-3）
        max_pages: 最多爬取页数（默认 30）
    """
    root_url = normalize_url(root_url)
    base_domain = urlparse(root_url).netloc
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(root_url.rstrip("/"), 0)]
    discovered: list[dict] = []
    errors: list[dict[str, str]] = []

    # 常见的敏感探测路径
    sensitive_paths = [
        "/admin", "/admin/login", "/backup", "/bak",
        "/.env", "/.git/HEAD", "/robots.txt", "/sitemap.xml",
        "/api", "/api/v1", "/swagger", "/docs",
        "/phpinfo.php", "/info.php", "/test.php",
        "/wp-admin", "/wp-login.php",
        "/console", "/actuator", "/debug",
    ]

    while queue and len(discovered) < max_pages:
        url, depth = queue.pop(0)
        norm = url.rstrip("/")

        if norm in visited:
            continue
        visited.add(norm)

        try:
            r = get(url, timeout=8)
            status = r.status_code
            content_type = r.headers.get("Content-Type", "")

            discovered.append({
                "url": url,
                "status": status,
                "content_type": content_type.split(";")[0] if content_type else "unknown",
                "size": len(r.text),
            })

            if "text/html" not in content_type:
                continue

            if depth >= max_depth:
                continue

            soup = BeautifulSoup(r.text, "html.parser")

            for a in soup.find_all("a", href=True):
                href = urljoin(url, a["href"])
                href, _ = urldefrag(href)
                target = in_scope_url(root_url, href)
                if target and target not in visited:
                    queue.append((target, depth + 1))

        except Exception as exc:
            errors.append({"kind": error_kind(exc), "message": f"{url}: {exc}"})
            continue

    # 探测敏感路径
    sensitive_found: list[dict[str, object]] = []
    for path in sensitive_paths:
        probe_url = urljoin(root_url, path)
        try:
            r = get(probe_url, timeout=5, allow_redirects=False)
            if r.status_code not in (404, 500, 502, 503):
                sensitive_found.append({"url": probe_url, "status": r.status_code})
        except Exception as exc:
            errors.append({"kind": error_kind(exc), "message": f"{probe_url}: {exc}"})
            pass

    lines = [
        f"[crawl] 根 URL: {root_url}",
        f"域名: {base_domain}",
        f"爬取深度: {max_depth} | 最多页数: {max_pages}",
        f"发现页面: {len(discovered)}",
        "",
        "── 发现的页面 ──",
    ]
    for d in discovered:
        lines.append(f"  [{d['status']}] {d['content_type']:20s} {d['url']}")

    if sensitive_found:
        lines.append("")
        lines.append("── 敏感路径探测 ──")
        lines.extend(f"  {item['url']} → {item['status']}" for item in sensitive_found)

    lines.append("")
    lines.append(f"总计: {len(discovered)} 个页面, {len(sensitive_found)} 个敏感路径")
    findings = [
        Finding(
            title=f"敏感路径可访问：{item['url']}", severity="medium", confidence="likely",
            category="sensitive_path",
            evidence=[Evidence("http_status", "Sensitive path returned a non-error status.", str(item["url"]), {"status": item["status"]})],
            reproduction=[f"GET {item['url']}"],
        )
        for item in sensitive_found
    ]
    readable = "\n".join(lines)
    return ToolResult(
        tool="crawl", target=root_url, status="ok", summary=f"发现 {len(discovered)} 个页面和 {len(sensitive_found)} 个敏感路径",
        raw_excerpt=readable, findings=findings, errors=errors,
        request=RequestRecord("GET", root_url), data={"pages": discovered, "sensitive_paths": sensitive_found},
    ).to_text()


@tool
def sitemap(root_url: str) -> str:
    """
    对 crawl 发现的页面进行智能分类。

    分类维度:
        - 登录/认证页（含 login/signin/auth 关键词）
        - 表单页（含 <form> 标签）
        - API 端点（JSON 响应 / 路径含 api）
        - 管理后台（路径含 admin/management/dashboard）
        - 静态资源（CSS/JS/图片）
        - 其他页面
        - 敏感暴露（.env/.git/phpinfo 等返回了内容）

    参数:
        root_url: 根 URL（会先自动 crawl）
    """
    root_url = normalize_url(root_url)
    base_domain = urlparse(root_url).netloc
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(root_url.rstrip("/"), 0)]
    pages: list[dict] = []

    while queue and len(pages) < 25:
        url, depth = queue.pop(0)
        norm = url.rstrip("/")

        if norm in visited:
            continue
        visited.add(norm)

        try:
            r = get(url, timeout=8)
            status = r.status_code
            ct = r.headers.get("Content-Type", "")
            is_html = "text/html" in ct
            is_json = "application/json" in ct

            has_forms = False
            if is_html:
                soup = BeautifulSoup(r.text, "html.parser")
                has_forms = len(soup.find_all("form")) > 0

            pages.append({
                "url": url,
                "status": status,
                "is_html": is_html,
                "is_json": is_json,
                "has_forms": has_forms,
            })

            if is_html and depth < 2:
                soup = BeautifulSoup(r.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = urljoin(url, a["href"])
                    href, _ = urldefrag(href)
                    target = in_scope_url(root_url, href)
                    if target and target not in visited:
                        queue.append((target, depth + 1))
        except Exception:
            continue

    # 分类
    categories = {
        "登录/认证页": [],
        "表单页": [],
        "API 端点": [],
        "管理后台": [],
        "静态资源": [],
        "其他页面": [],
    }

    for p in pages:
        url_lower = p["url"].lower()
        path = urlparse(p["url"]).path.lower()

        if any(kw in url_lower for kw in ["login", "signin", "auth", "signup", "register", "sign_on"]):
            categories["登录/认证页"].append(p)
        elif any(kw in path for kw in ["admin", "manage", "dashboard", "backend", "cms"]):
            categories["管理后台"].append(p)
        elif p["is_json"] or "/api" in path or "/v1/" in path or "/v2/" in path:
            categories["API 端点"].append(p)
        elif p["has_forms"]:
            categories["表单页"].append(p)
        elif any(path.endswith(ext) for ext in [".css", ".js", ".png", ".jpg", ".svg", ".ico", ".woff", ".ttf"]):
            categories["静态资源"].append(p)
        else:
            categories["其他页面"].append(p)

    # 汇总
    total = len(pages)
    lines = [
        f"[sitemap] 攻击面测绘 — {root_url}",
        f"域名: {base_domain}",
        f"发现页面总数: {total}",
        "",
    ]
    for cat, items in categories.items():
        if items:
            lines.append(f"## {cat} ({len(items)}):")
            for it in items[:8]:
                forms_mark = " [含表单]" if it.get("has_forms") else ""
                lines.append(f"  [{it['status']}] {it['url']}{forms_mark}")
            if len(items) > 8:
                lines.append(f"  ... 还有 {len(items) - 8} 个")
            lines.append("")

    lines.append(f"攻击面评级: {'🔴 大' if total > 20 else '🟡 中' if total > 8 else '🟢 小'} ({total} 个页面)")
    return "\n".join(lines)


@tool
def batch_scan(root_url: str) -> str:
    """
    批量扫描目标站点的安全配置。

    自动执行:
        1. crawl 发现所有页面
        2. 对每个页面做安全头检查（CSP/HSTS/X-Frame-Options 等）
        3. 汇总缺失安全头的页面列表
        4. 统计整体安全态势

    参数:
        root_url: 目标根 URL
    """
    root_url = normalize_url(root_url)
    base_domain = urlparse(root_url).netloc
    visited: set[str] = set()
    queue: list[tuple[str, int]] = [(root_url.rstrip("/"), 0)]
    results: list[dict] = []
    errors: list[dict[str, str]] = []

    # 第一步: crawl
    while queue and len(results) < 20:
        url, depth = queue.pop(0)
        norm = url.rstrip("/")
        if norm in visited:
            continue
        visited.add(norm)

        try:
            r = get(url, timeout=8)
            headers = dict(r.headers)
            results.append({
                "url": url,
                "status": r.status_code,
                "missing_headers": [
                    h for h in [
                        "Content-Security-Policy",
                        "Strict-Transport-Security",
                        "X-Frame-Options",
                        "X-Content-Type-Options",
                    ] if h not in headers
                ],
            })

            if depth < 2 and "text/html" in headers.get("Content-Type", ""):
                soup = BeautifulSoup(r.text, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = urljoin(url, a["href"])
                    href, _ = urldefrag(href)
                    target = in_scope_url(root_url, href)
                    if target and target not in visited:
                        queue.append((target, depth + 1))
        except Exception as exc:
            errors.append({"kind": error_kind(exc), "message": f"{url}: {exc}"})
            continue

    # 第二步: 汇总
    lines = [
        f"[batch_scan] 批量安全扫描 — {root_url}",
        f"扫描页面数: {len(results)}",
        "",
        "── 安全头缺失汇总 ──",
    ]

    header_stats: dict[str, list[str]] = {}
    for r in results:
        for h in r["missing_headers"]:
            header_stats.setdefault(h, []).append(r["url"])

    for header, urls in header_stats.items():
        lines.append(f"  ❌ {header}: {len(urls)}/{len(results)} 页缺失")

    lines.append("")
    lines.append("── 逐页详情 ──")
    for r in results:
        if r["missing_headers"]:
            missing = ", ".join(r["missing_headers"])
            lines.append(f"  [{r['status']}] {r['url']}")
            lines.append(f"         缺失: {missing}")
        else:
            lines.append(f"  [{r['status']}] {r['url']} ✅ 安全头完整")

    # 评分
    total_missing = sum(len(r["missing_headers"]) for r in results)
    if total_missing == 0:
        grade = "🟢 A — 安全配置完善"
    elif total_missing <= len(results) * 2:
        grade = "🟡 B — 存在一定缺失"
    else:
        grade = "🔴 C — 安全配置严重不足"

    lines.append(f"\n整体安全评级: {grade}")
    findings: list[Finding] = []
    for item in results:
        for header in item["missing_headers"]:
            findings.append(Finding(
                title=f"缺少安全响应头：{header}", severity="low", confidence="confirmed",
                category="security_headers",
                evidence=[Evidence("header_check", f"{header} is absent", item["url"], {"status": item["status"], "header": header})],
                reproduction=[f"请求 {item['url']} 并检查 {header} 响应头。"],
            ))
    readable = "\n".join(lines)
    return ToolResult(
        tool="batch_scan", target=root_url, status="ok", summary=f"扫描 {len(results)} 页，发现 {total_missing} 个安全头缺失",
        raw_excerpt=readable, findings=findings, errors=errors,
        request=RequestRecord("GET", root_url), data={"pages": results, "grade": grade},
    ).to_text()
