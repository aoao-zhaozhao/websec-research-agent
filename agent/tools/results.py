"""Structured scanner tool-result protocol for v0.9.

The model still receives a concise readable summary.  The JSON envelope is
delimited so the event stream and future report storage can consume the same
facts without parsing presentation text.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any


RESULT_OPEN = "<scanner-result>"
RESULT_CLOSE = "</scanner-result>"
_RESULT_RE = re.compile(
    re.escape(RESULT_OPEN) + r"\s*(\{.*?\})\s*" + re.escape(RESULT_CLOSE),
    re.DOTALL,
)


@dataclass
class Evidence:
    kind: str
    description: str
    url: str | None = None
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class RequestRecord:
    method: str
    url: str
    parameters: dict[str, Any] = field(default_factory=dict)
    payload: str | None = None
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class ResponseRecord:
    status_code: int | None = None
    content_type: str | None = None
    body_length: int | None = None
    excerpt: str = ""


@dataclass
class Finding:
    title: str
    severity: str = "info"
    confidence: str = "info"
    category: str = "observation"
    evidence: list[Evidence] = field(default_factory=list)
    reproduction: list[str] = field(default_factory=list)


@dataclass
class ToolResult:
    tool: str
    target: str
    status: str
    summary: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    raw_excerpt: str = ""
    request: RequestRecord | None = None
    response: ResponseRecord | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_text(self) -> str:
        """Keep the original readable result while adding a machine envelope."""
        readable = self.raw_excerpt or self.summary
        return (
            f"{readable}\n\n{RESULT_OPEN}\n"
            f"{json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)}\n"
            f"{RESULT_CLOSE}"
        )


def error_kind(message: str | Exception) -> str:
    exception_name = message.__class__.__name__.lower() if isinstance(message, Exception) else ""
    text = str(message)
    lower = text.lower()
    if "timeout" in exception_name:
        return "timeout"
    if "connection" in exception_name:
        return "connection_error"
    if "jsondecode" in exception_name:
        return "parse_error"
    if "timeout" in lower or "超时" in text:
        return "timeout"
    if "connection" in lower or "无法连接" in text:
        return "connection_error"
    if "parse" in lower or "解析" in text:
        return "parse_error"
    if "scope" in lower or "同域" in text:
        return "out_of_scope"
    return "tool_bug"


def response_record(response: Any, excerpt_limit: int = 800) -> ResponseRecord:
    """Capture the bounded response facts required to reproduce a finding."""
    text = str(getattr(response, "text", ""))
    headers = getattr(response, "headers", {}) or {}
    return ResponseRecord(
        status_code=getattr(response, "status_code", None),
        content_type=str(headers.get("Content-Type", "")).split(";", 1)[0] or None,
        body_length=len(text),
        excerpt=text[:excerpt_limit],
    )


def error_result(tool: str, target: str, message: str | Exception) -> ToolResult:
    """Build a native, classified error result without parsing presentation text."""
    return ToolResult(
        tool=tool,
        target=target,
        status="error",
        summary=f"{tool} failed: {message}",
        errors=[{"kind": error_kind(message), "message": str(message)[:500]}],
        raw_excerpt=f"[{tool}] {target}\nError: {message}",
    )


def _target_from_input(arguments: dict[str, Any]) -> str:
    for key in ("url", "root_url", "query", "token"):
        value = arguments.get(key)
        if value:
            return str(value)
    return ""


def _summary(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line[:240]
    return "工具执行完成。"


def _header_findings(text: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for header in (
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ):
        if re.search(rf"❌\s*{re.escape(header)}\s*.*缺失", text):
            findings.append(
                Finding(
                    title=f"缺少安全响应头：{header}",
                    severity="low",
                    confidence="confirmed",
                    category="security_headers",
                    evidence=[Evidence("header_check", f"{header} is absent", target)],
                    reproduction=[f"请求 {target} 并检查响应头。"],
                )
            )
    return findings


def legacy_result(tool: str, arguments: dict[str, Any], output: Any) -> ToolResult:
    """Adapt existing text tools during the staged v0.9 migration."""
    text = str(getattr(output, "content", output)).strip()
    target = _target_from_input(arguments)
    is_error = bool(re.search(r"(?:\bError:|failed:|失败:)", text, re.IGNORECASE))
    errors: list[dict[str, str]] = []
    if is_error:
        errors.append({"kind": error_kind(text), "message": text[:500]})

    findings = _header_findings(text, target)
    if tool == "test_lfi_param" and "Result: likely LFI" in text:
        findings.append(
            Finding(
                title="疑似本地文件包含（LFI）",
                severity="high",
                confidence="likely",
                category="lfi",
                evidence=[Evidence("response_diff", "Bounded LFI payload produced a scored response difference.", target)],
                reproduction=["使用工具输出中的 payload 和 URL 重放请求。"],
            )
        )

    return ToolResult(
        tool=tool,
        target=target,
        status="error" if is_error else "ok",
        summary=_summary(text),
        findings=findings,
        errors=errors,
        raw_excerpt=text[:6000],
        data={"migration": "legacy_text_adapter"},
    )


def parse_tool_result(output: Any) -> tuple[str, dict[str, Any] | None]:
    """Return display text and an optional validated JSON-compatible envelope."""
    text = str(getattr(output, "content", output)).strip()
    match = _RESULT_RE.search(text)
    if not match:
        return text, None
    try:
        result = json.loads(match.group(1))
    except json.JSONDecodeError:
        return text, None
    readable = (text[:match.start()] + text[match.end():]).strip()
    return readable, result if isinstance(result, dict) else None
