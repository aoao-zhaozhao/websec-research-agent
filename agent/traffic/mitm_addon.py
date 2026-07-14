"""mitmproxy addon: 将所有代理流量路由到统一捕获层。

这是免费的 HTTP 代理捕获后端（对标 VulnClaw 的 Tier-A 方案）。
Burp MCP 保留为可选的交互式叠加层。

mitmproxy 是可选依赖 —— `mitmproxy_available()` 在运行时检测可用性；
addon 逻辑本身不含 mitmproxy import，可脱离真实代理进行单元测试。
"""

from __future__ import annotations

from typing import Any

from agent.traffic.capture import TrafficCapture
from agent.traffic.models import (
    SOURCE_PROXY,
    CapturedExchange,
    CapturedRequest,
    CapturedResponse,
    coerce_headers,
)


def mitmproxy_available() -> bool:
    """检测 mitmproxy 运行时是否可导入。"""
    try:
        import mitmproxy  # noqa: F401
        return True
    except ImportError:
        return False


def exchange_from_flow(flow: Any) -> CapturedExchange:
    """从 mitmproxy HTTPFlow 构建 CapturedExchange。

    不依赖 mitmproxy import —— 接受 duck-type 的 flow 对象。
    """
    req = flow.request
    request = CapturedRequest(
        method=str(getattr(req, "method", "GET")),
        url=str(getattr(req, "pretty_url", getattr(req, "url", ""))),
        headers=coerce_headers(getattr(req, "headers", {})),
        body=bytes(getattr(req, "raw_content", b"") or getattr(req, "content", b"") or b""),
        http_version=str(getattr(req, "http_version", "HTTP/1.1")),
    )
    response = None
    resp = getattr(flow, "response", None)
    if resp is not None:
        response = CapturedResponse(
            status=int(getattr(resp, "status_code", 0) or 0),
            headers=coerce_headers(getattr(resp, "headers", {})),
            body=bytes(getattr(resp, "raw_content", b"") or getattr(resp, "content", b"") or b""),
            reason=str(getattr(resp, "reason", "")),
            http_version=str(getattr(resp, "http_version", "HTTP/1.1")),
        )
    return CapturedExchange(request=request, response=response)


class TrafficCaptureAddon:
    """mitmproxy addon —— 每个完成的 HTTP flow 写入 TrafficStore。"""

    def __init__(self, capture: TrafficCapture) -> None:
        self.capture = capture
        self.flow_count: int = 0

    def capture_flow(self, flow: Any) -> str | None:
        """归一化并捕获一个 flow。返回 request_id 或 None（超域丢弃）。"""
        exchange = exchange_from_flow(flow)
        request_id = self.capture.capture(exchange, source=SOURCE_PROXY, tags=["proxy"])
        if request_id:
            self.flow_count += 1
        return request_id

    # mitmproxy 事件钩子（response 到达后触发）
    def response(self, flow: Any) -> None:  # pragma: no cover - requires mitmproxy runtime
        self.capture_flow(flow)

    # 也捕获仅有请求没有响应的情况（如连接失败）
    def error(self, flow: Any) -> None:  # pragma: no cover
        if getattr(flow, "response", None) is None:
            self.capture_flow(flow)
