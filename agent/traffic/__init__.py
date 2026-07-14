"""
流量证据存储 (v1.8) —— 统一的 HTTP 流量捕获、存储与归一化。

所有 HTTP 流量（Agent 直接发出的、mitmproxy 代理的、Playwright 浏览器的、
Burp 代理的）归一化为统一的 CapturedExchange 模型，以追加式 JSONL 索引 +
原始报文文件落盘。

免费方案: mitmproxy（Tier-A 代理） + Playwright 浏览器
可选叠加: Burp MCP / Chrome DevTools MCP

目录结构:
    evidence/traffic/
      requests.jsonl              ← 追加式索引
      <request_id>/request        ← 原始请求报文
      <request_id>/response       ← 原始响应报文
"""

from .models import (
    SOURCE_PROXY,
    SOURCE_BROWSER,
    SOURCE_AGENT,
    SOURCE_MANUAL_REPLAY,
    CapturedRequest,
    CapturedResponse,
    CapturedExchange,
    TrafficRecord,
    coerce_headers,
)
from .store import TrafficStore, compute_request_id
from .capture import TrafficCapture
from .scope import ScopeChecker, ScopeMode, Target
from .serialization import raw_request_bytes, raw_response_bytes, parse_raw_request
from .mitm_addon import TrafficCaptureAddon, exchange_from_flow, mitmproxy_available
from .proxy import ProxyManager

__all__ = [
    "SOURCE_PROXY",
    "SOURCE_BROWSER",
    "SOURCE_AGENT",
    "SOURCE_MANUAL_REPLAY",
    "CapturedRequest",
    "CapturedResponse",
    "CapturedExchange",
    "TrafficRecord",
    "coerce_headers",
    "TrafficStore",
    "compute_request_id",
    "TrafficCapture",
    "ScopeChecker",
    "ScopeMode",
    "Target",
    "raw_request_bytes",
    "raw_response_bytes",
    "parse_raw_request",
    "TrafficCaptureAddon",
    "exchange_from_flow",
    "mitmproxy_available",
    "ProxyManager",
]
