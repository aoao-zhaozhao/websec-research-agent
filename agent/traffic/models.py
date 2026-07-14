"""流量证据数据模型 —— 来源无关的统一 HTTP 交换表示。

所有捕获后端（Agent 直接请求、Burp、Chrome DevTools）归一化到同一组 dataclass。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# 捕获来源常量
SOURCE_PROXY = "proxy"
SOURCE_BROWSER = "browser"
SOURCE_AGENT = "agent"
SOURCE_MANUAL_REPLAY = "manual-replay"
VALID_SOURCES = frozenset({SOURCE_PROXY, SOURCE_BROWSER, SOURCE_AGENT, SOURCE_MANUAL_REPLAY})


def coerce_headers(value: Any) -> dict[str, str]:
    """将后端传来的 header 归一化为 ``{str: str}`` dict。

    支持:
    - dict / mapping（mitmproxy、Burp）
    - list of {name, value}（Chrome DevTools / HAR）
    - 其他（返回空 dict）
    """
    if isinstance(value, list):
        headers: dict[str, str] = {}
        for item in value:
            if isinstance(item, dict) and "name" in item:
                headers[str(item["name"])] = str(item.get("value", ""))
        return headers
    if hasattr(value, "items"):
        try:
            return {str(k): str(v) for k, v in value.items()}
        except Exception:
            return {}
    return {}


@dataclass
class CapturedRequest:
    """一次 HTTP 请求的完整记录"""
    method: str = "GET"
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    http_version: str = "HTTP/1.1"


@dataclass
class CapturedResponse:
    """一次 HTTP 响应的完整记录"""
    status: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    reason: str = ""
    http_version: str = "HTTP/1.1"


@dataclass
class CapturedExchange:
    """一对请求和响应（响应可选）"""
    request: CapturedRequest
    response: CapturedResponse | None = None


@dataclass
class TrafficRecord:
    """索引条目 —— 存储在 requests.jsonl 中的一行"""
    request_id: str
    seq: int
    timestamp: str
    method: str
    url: str
    host: str
    path: str
    status: int
    content_length: int
    source: str
    tags: list[str] = field(default_factory=list)

    def to_index(self) -> dict:
        return {
            "request_id": self.request_id,
            "seq": self.seq,
            "timestamp": self.timestamp,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "status": self.status,
            "content_length": self.content_length,
            "source": self.source,
            "tags": list(self.tags),
        }
