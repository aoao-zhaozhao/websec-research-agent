"""
Agent 核心模块 —— Web 漏洞审查引擎。

v0.3: 基于 LangGraph 重构
  - 用 LangGraph create_react_agent 替代手写 ReAct 循环
  - ChatOpenAI 指向 DeepSeek（OpenAI 兼容）
  - 5 个 Web 扫描工具: http_get / http_post / analyze_headers / extract_forms / extract_links
  - 工具定义用 LangChain @tool 装饰器

后续扩展:
  v0.4 → RAG 知识库（CVE/OWASP）→ create_retrieval_chain
  v0.5 → 工具权限管控 → tool_call_permissions
"""

import os
from dataclasses import dataclass, field
from typing import AsyncIterator

# ── LangChain imports ──────────────────────────────
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage
from langchain_core.tools import tool

# ── HTTP 工具所需 ──────────────────────────────────
import requests
from bs4 import BeautifulSoup


# ═══════════════════════════════════════════════════════
# 配置
# ═══════════════════════════════════════════════════════

@dataclass
class AgentConfig:
    api_key: str = field(default_factory=lambda: os.getenv("DEEPSEEK_API_KEY", ""))
    base_url: str = field(
        default_factory=lambda: os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    )
    model: str = field(default_factory=lambda: os.getenv("DEEPSEEK_MODEL", "deepseek-chat"))
    max_turns: int = 20


# ═══════════════════════════════════════════════════════
# System Prompt — Web 安全专家
# ═══════════════════════════════════════════════════════

SYSTEM_PROMPT = """\
你是一个Web应用安全审计专家。你的任务是扫描目标Web应用并发现漏洞。

## 工作流程
1. 先用 http_get 访问目标 URL 获取页面内容
2. 用 extract_forms 提取页面中所有可注入的输入点
3. 用 extract_links 提取页面内链，扩展攻击面
4. 对每个输入点用 http_post 发送测试 payload（XSS、SQLi）
5. 用 analyze_headers 检查安全响应头是否缺失

## 输出格式
每个发现按以下格式报告:
- **漏洞类型**: (XSS / SQL注入 / CSRF / 安全头缺失 / 信息泄露 / ...)
- **风险等级**: 🔴高危 / 🟡中危 / 🟢低危
- **位置**: URL + 参数名/Header名
- **证据**: 响应中观察到的具体内容
- **复现步骤**: 如何重现
- **修复建议**: 具体的代码/配置修改方案

## 扫描原则
- 仅分析 target URL 对应的主机，不要扫描外部链接
- XSS payload: <script>alert(1)</script> 及其变体
- SQLi payload: ' OR '1'='1 及 sleep 型
- 注意响应中是否反射了 payload（XSS）或出现了数据库错误（SQLi）
- 响应体可能很长，重点关注前 3000 字符中的关键信息

请用中文回复。"""


# ═══════════════════════════════════════════════════════
# 工具定义
# ═══════════════════════════════════════════════════════

@tool
def http_get(url: str) -> str:
    """
    发送 HTTP GET 请求到目标 URL，返回状态码、响应头、页面内容（前 3000 字符）。

    用途: 获取页面内容、探测端点是否存在、触发反射型漏洞。

    参数:
        url: 目标 URL（如 http://example.com/page?id=1）
    """
    try:
        r = requests.get(url, timeout=10, allow_redirects=True, verify=False)
        headers_str = "\n".join(f"  {k}: {v}" for k, v in r.headers.items())
        return (
            f"[GET] {url}\n"
            f"Status: {r.status_code} {r.reason}\n"
            f"Response Headers:\n{headers_str}\n\n"
            f"Body (first 3000 chars):\n{r.text[:3000]}"
        )
    except requests.exceptions.Timeout:
        return f"[GET] {url}\nError: 请求超时"
    except requests.exceptions.ConnectionError:
        return f"[GET] {url}\nError: 无法连接到目标服务器"
    except Exception as e:
        return f"[GET] {url}\nError: {str(e)}"


@tool
def http_post(url: str, data: str = "", content_type: str = "application/x-www-form-urlencoded") -> str:
    """
    发送 HTTP POST 请求，用于向表单/API 提交测试 payload。

    用途: 测试 XSS 反射、SQL 注入、命令注入、XXE 等。

    参数:
        url: 目标 URL
        data: POST body 数据（如 username=admin&password=' OR '1'='1）
        content_type: Content-Type（默认 application/x-www-form-urlencoded）
    """
    try:
        headers = {"Content-Type": content_type}
        r = requests.post(url, data=data, headers=headers, timeout=10, allow_redirects=True, verify=False)
        return (
            f"[POST] {url}\n"
            f"Payload: {data[:500]}\n"
            f"Status: {r.status_code}\n"
            f"Body (first 3000 chars):\n{r.text[:3000]}"
        )
    except Exception as e:
        return f"[POST] {url}\nError: {str(e)}"


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
        from urllib.parse import urljoin, urlparse

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


# ═══════════════════════════════════════════════════════
# Agent 类 — 基于 LangGraph
# ═══════════════════════════════════════════════════════

TOOLS = [http_get, http_post, analyze_headers, extract_forms, extract_links]


class Agent:
    """
    Web 漏洞审查 Agent (v0.3 — LangGraph 引擎)。

    与 v0.2 的区别:
        - 引擎从手写 ReAct 循环 → LangGraph create_react_agent
        - 工具从手写 JSON → LangChain @tool 装饰器
        - messages 仍跨 run() 累积（多轮记忆），但 agent 内部管理 tool-call 循环

    用法:
        agent = Agent(AgentConfig())
        async for token in agent.run("扫描 http://testphp.vulnweb.com"):
            print(token, end="")
    """

    def __init__(self, config: AgentConfig | None = None):
        self.config = config or AgentConfig()
        self.llm = ChatOpenAI(
            api_key=self.config.api_key,
            base_url=self.config.base_url,
            model=self.config.model,
            temperature=0.3,  # 低温度，安全分析需要精确
        )
        self.agent = create_react_agent(self.llm, TOOLS)
        self.messages = [SystemMessage(content=SYSTEM_PROMPT)]

    def clear(self) -> None:
        """清空对话历史，只保留 system prompt"""
        self.messages = [SystemMessage(content=SYSTEM_PROMPT)]

    async def run(self, user_input: str) -> AsyncIterator[str]:
        """
        执行扫描，逐 token yield 模型输出。

        LangGraph 的 astream_events(version="v2") 在 on_chat_model_stream
        事件中产出每个 token。工具调用过程由 agent 内部处理，不会
        yield 给调用者（避免了工具参数碎片出现在输出中）。
        """
        self.messages.append(HumanMessage(content=user_input))

        # 收集完整回复（用于写入历史）
        full_response: list[str] = []

        async for event in self.agent.astream_events(
            {"messages": list(self.messages)},  # copy to avoid mutation during iteration
            version="v2",
        ):
            kind = event["event"]

            # 只有 LLM 产出的文本 token 才 yield（工具调用内部细节不暴露）
            if kind == "on_chat_model_stream":
                chunk = event["data"]["chunk"]
                if chunk.content:
                    full_response.append(chunk.content)
                    yield chunk.content

        # 将本轮回复写入历史
        response_text = "".join(full_response).strip()
        if response_text:
            self.messages.append(AIMessage(content=response_text))

        # 如果本轮没有文本输出（全是工具调用且最终无总结），兜底
        if not response_text:
            self.messages.append(AIMessage(content="扫描完成，请查看上方工具调用结果。"))
