"""外部流量归一化 —— 将 Burp / Chrome DevTools 的异构格式归一化为 CapturedExchange。

Burp (`get_proxy_http_history`) 和 chrome-devtools MCP 服务作为可选的外部叠加层，
当它们接入时，捕获的流量归一化为相同的 CapturedExchange 格式进入统一的 TrafficStore。
"""

from __future__ import annotations

from typing import Any

from agent.traffic.capture import TrafficCapture
from agent.traffic.models import (
    SOURCE_BROWSER,
    SOURCE_PROXY,
    CapturedExchange,
    CapturedRequest,
    CapturedResponse,
    coerce_headers,
)


def _as_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8", "replace")


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def normalize_burp_entry(entry: dict[str, Any]) -> CapturedExchange:
    """将一条 Burp Proxy History 条目映射为 CapturedExchange。"""
    req = entry.get("request", entry) if isinstance(entry.get("request"), dict) else entry
    resp = entry.get("response") if isinstance(entry.get("response"), dict) else None

    request = CapturedRequest(
        method=str(req.get("method", entry.get("method", "GET")) or "GET"),
        url=str(req.get("url", entry.get("url", "")) or ""),
        headers=coerce_headers(req.get("headers", entry.get("headers"))),
        body=_as_bytes(req.get("body", req.get("data"))),
    )
    response = None
    if resp is not None or "status" in entry or "status_code" in entry:
        source = resp or entry
        response = CapturedResponse(
            status=_int(source.get("status", source.get("status_code", 0))),
            headers=coerce_headers(source.get("headers")),
            body=_as_bytes(source.get("body", source.get("data"))),
            reason=str(source.get("reason", "")),
        )
    return CapturedExchange(request=request, response=response)


def normalize_chrome_devtools_entry(entry: dict[str, Any]) -> CapturedExchange:
    """将一条 Chrome DevTools network 条目映射为 CapturedExchange。"""
    req = entry.get("request", {}) if isinstance(entry.get("request"), dict) else entry
    resp = entry.get("response") if isinstance(entry.get("response"), dict) else None

    request = CapturedRequest(
        method=str(req.get("method", "GET") or "GET"),
        url=str(req.get("url", entry.get("url", "")) or ""),
        headers=coerce_headers(req.get("headers")),
        body=_as_bytes(req.get("postData", req.get("body"))),
    )
    response = None
    if resp is not None:
        response = CapturedResponse(
            status=_int(resp.get("status", resp.get("statusCode", 0))),
            headers=coerce_headers(resp.get("headers")),
            body=_as_bytes(resp.get("body", entry.get("body"))),
            reason=str(resp.get("statusText", resp.get("reason", ""))),
        )
    return CapturedExchange(request=request, response=response)


def ingest_burp_history(
    capture: TrafficCapture, entries: list[dict[str, Any]]
) -> list[str]:
    """批量归一化并捕获 Burp 历史条目。返回写入的 request_id 列表。"""
    kept: list[str] = []
    for entry in entries:
        exchange = normalize_burp_entry(entry)
        request_id = capture.capture(exchange, source=SOURCE_PROXY, tags=["burp", "overlay"])
        if request_id:
            kept.append(request_id)
    return kept


def ingest_chrome_devtools(
    capture: TrafficCapture, entries: list[dict[str, Any]]
) -> list[str]:
    """批量归一化并捕获 Chrome DevTools 网络条目。返回写入的 request_id 列表。"""
    kept: list[str] = []
    for entry in entries:
        exchange = normalize_chrome_devtools_entry(entry)
        request_id = capture.capture(exchange, source=SOURCE_BROWSER, tags=["chrome-devtools", "overlay"])
        if request_id:
            kept.append(request_id)
    return kept
