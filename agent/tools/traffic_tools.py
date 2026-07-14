"""Agent 流量的 LangChain 工具 —— traffic_list / traffic_view / traffic_repeat / traffic_sitemap。

所有工具读取统一的 TrafficStore，Agent 通过它们查看、分析和重放已捕获的 HTTP 流量。
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from agent.tools.results import ToolResult, Finding, Evidence, error_result


# 模块级 TrafficStore 引用（由 Agent.__init__ 注入）
_traffic_store: Any = None
_lock = threading.Lock()


def set_traffic_store(store: Any) -> None:
    """注入当前扫描的 TrafficStore 实例。"""
    global _traffic_store
    with _lock:
        _traffic_store = store


def _get_store() -> Any:
    with _lock:
        return _traffic_store


def _format_view(view: dict, limit: int = 4000) -> str:
    """格式化一条流量的完整视图。"""
    method = view.get("method", "GET")
    url = view.get("url", "")
    status = view.get("status", 0)
    source = view.get("source", "unknown")
    request_id = view.get("request_id", "")

    lines = [
        f"=== Request: {method} {url} ===",
        f"Request ID: {request_id}",
        f"Status: {status}  Source: {source}",
        "",
    ]
    req_text = view.get("request_text", "")
    if req_text:
        lines.append("--- Request ---")
        if len(req_text) > limit:
            lines.append(req_text[:limit] + f"\n...[truncated {len(req_text) - limit} chars]")
        else:
            lines.append(req_text)

    resp_text = view.get("response_text", "")
    if resp_text:
        lines.append("\n--- Response ---")
        if len(resp_text) > limit:
            lines.append(resp_text[:limit] + f"\n...[truncated {len(resp_text) - limit} chars]")
        else:
            lines.append(resp_text)

    return "\n".join(lines)


@tool
def traffic_list(
    method: str = "",
    host: str = "",
    status: int = 0,
    source: str = "",
    limit: int = 20,
) -> str:
    """列出已捕获的 HTTP 流量（支持 method/host/status/source 过滤）。

    Args:
        method: HTTP 方法过滤（GET/POST/PUT...），空字符串表示不过滤
        host: 按 host 过滤，空字符串表示不过滤
        status: HTTP 状态码过滤（200/404/500...），0 表示不过滤
        source: 来源过滤（agent/proxy/browser/manual-replay），空字符串表示不过滤
        limit: 最多返回条数（默认 20）
    """
    store = _get_store()
    if store is None:
        return error_result("traffic_list", "", "流量存储未初始化，请先开始扫描。").to_text()

    try:
        entries = store.entries()
    except Exception as exc:
        return error_result("traffic_list", "", str(exc)).to_text()

    # 过滤
    filtered = []
    for entry in entries:
        if method and entry.get("method", "").upper() != method.upper():
            continue
        if host and host.lower() not in (entry.get("host", "") or "").lower():
            continue
        if status and entry.get("status", 0) != status:
            continue
        if source and entry.get("source", "") != source:
            continue
        filtered.append(entry)

    # 取最近 limit 条
    filtered = filtered[-limit:]

    if not filtered:
        return ToolResult(
            tool="traffic_list", target="", status="ok",
            summary="traffic_list: 无匹配的流量记录。",
            raw_excerpt="没有找到符合条件的 HTTP 流量。",
        ).to_text()

    lines = [f"{'request_id':<18} {'method':<7} {'status':<6} {'source':<12} url"]
    lines.append("-" * 90)
    for entry in filtered:
        rid = entry.get("request_id", "")[:16]
        m = entry.get("method", "GET")
        s = entry.get("status", 0)
        src = entry.get("source", "unknown")
        url = entry.get("url", "")
        if len(url) > 50:
            url = url[:47] + "..."
        lines.append(f"{rid:<18} {m:<7} {s:<6} {src:<12} {url}")

    result_text = "\n".join(lines)
    return ToolResult(
        tool="traffic_list", target=f"total={len(filtered)}", status="ok",
        summary=f"traffic_list: {len(filtered)} 条匹配",
        raw_excerpt=result_text,
        data={"count": len(filtered), "entries": filtered},
    ).to_text()


@tool
def traffic_view(request_id: str) -> str:
    """查看某个已捕获请求的完整请求与响应报文。

    Args:
        request_id: 流量记录的唯一 ID（来自 traffic_list 的输出）
    """
    store = _get_store()
    if store is None:
        return error_result("traffic_view", request_id, "流量存储未初始化。").to_text()

    try:
        view = store.view(request_id)
    except Exception as exc:
        return error_result("traffic_view", request_id, str(exc)).to_text()

    if view is None:
        return error_result("traffic_view", request_id, f"未找到: {request_id}").to_text()

    result_text = _format_view(view)
    return ToolResult(
        tool="traffic_view", target=request_id, status="ok",
        summary=f"traffic_view {request_id}: {view.get('method')} {view.get('url')}",
        raw_excerpt=result_text,
        data={"request_id": request_id, "method": view.get("method"), "url": view.get("url")},
    ).to_text()


@tool
def traffic_repeat(
    request_id: str,
    method: str = "",
    url: str = "",
    headers: str = "",
    body: str = "",
) -> str:
    """重放一个已捕获的请求（可选择性覆盖 method/url/headers/body）。

    重放的结果本身也会作为新流量被捕获，返回新的 request_id。

    Args:
        request_id: 要重放的流量记录的 ID
        method:  覆盖 HTTP 方法（可选）
        url:     覆盖目标 URL（可选）
        headers: 覆盖请求头，JSON 格式字符串（可选），如 '{"Authorization":"Bearer x"}'
        body:    覆盖请求体（可选）
    """
    store = _get_store()
    if store is None:
        return error_result("traffic_repeat", request_id, "流量存储未初始化。").to_text()

    try:
        original = store.load_request(request_id)
    except Exception as exc:
        return error_result("traffic_repeat", request_id, str(exc)).to_text()

    if original is None:
        return error_result("traffic_repeat", request_id, f"未找到: {request_id}").to_text()

    # 应用覆盖
    new_method = method or original.method
    new_url = url or original.url
    new_headers = dict(original.headers)
    new_body = body.encode("utf-8", "replace") if body else original.body

    if headers:
        try:
            override_headers = json.loads(headers)
            for k, v in override_headers.items():
                if v is None:
                    new_headers.pop(k, None)
                else:
                    new_headers[k] = str(v)
        except json.JSONDecodeError:
            return error_result("traffic_repeat", request_id, f"headers 不是合法 JSON: {headers}").to_text()

    # 发送请求
    try:
        import httpx
        with httpx.Client(verify=False, timeout=30.0, follow_redirects=True) as client:
            response = client.request(
                method=new_method, url=new_url, headers=new_headers, content=new_body,
            )
    except ImportError:
        return error_result("traffic_repeat", request_id, "httpx 未安装，无法重放请求。").to_text()
    except Exception as exc:
        return error_result("traffic_repeat", request_id, f"请求失败: {exc}").to_text()

    # 将重放结果写入 TrafficStore
    from agent.traffic.models import CapturedRequest, CapturedResponse, CapturedExchange, SOURCE_MANUAL_REPLAY

    captured_req = CapturedRequest(method=new_method, url=new_url, headers=new_headers, body=new_body)
    captured_resp = CapturedResponse(
        status=response.status_code,
        headers=dict(response.headers),
        body=response.content,
        reason=response.reason_phrase if hasattr(response, "reason_phrase") else "",
    )
    exchange = CapturedExchange(request=captured_req, response=captured_resp)

    # 如果 TrafficCapture 可用，通过它写入（含 scope 检查）；否则直接写入 store
    from agent.traffic.capture import TrafficCapture
    from agent.traffic.store import TrafficStore

    if isinstance(store, TrafficStore):
        record = store.record(exchange, source=SOURCE_MANUAL_REPLAY, tags=["replay", f"from:{request_id}"])
        new_id = record.request_id
    else:
        new_id = "unknown"

    return ToolResult(
        tool="traffic_repeat", target=new_url, status="ok",
        summary=f"重放成功: {new_method} {new_url} → {response.status_code}，新 request_id: {new_id}",
        raw_excerpt=f"Replay: {new_method} {new_url}\nStatus: {response.status_code}\nNew request_id: {new_id}",
        data={"request_id": new_id, "method": new_method, "url": new_url, "status": response.status_code},
    ).to_text()


@tool
def traffic_sitemap() -> str:
    """按 host 聚合显示所有已捕获流量的路径与命中次数（站点地图）。"""
    store = _get_store()
    if store is None:
        return error_result("traffic_sitemap", "", "流量存储未初始化。").to_text()

    try:
        sitemap = store.sitemap()
    except Exception as exc:
        return error_result("traffic_sitemap", "", str(exc)).to_text()

    if not sitemap:
        return ToolResult(
            tool="traffic_sitemap", target="", status="ok",
            summary="traffic_sitemap: 无数据。",
            raw_excerpt="没有已捕获的流量。",
        ).to_text()

    lines: list[str] = []
    for host, paths in sitemap.items():
        lines.append(f"\n=== {host} ===")
        for entry in paths:
            methods = ",".join(entry["methods"])
            lines.append(f"  {entry['path']:<50} [{methods}] x{entry['hits']}")

    result_text = "\n".join(lines).strip()
    return ToolResult(
        tool="traffic_sitemap", target="", status="ok",
        summary=f"traffic_sitemap: {len(sitemap)} 个 host",
        raw_excerpt=result_text,
        data={"hosts": len(sitemap), "sitemap": sitemap},
    ).to_text()


# 工具列表
TRAFFIC_TOOLS = [traffic_list, traffic_view, traffic_repeat, traffic_sitemap]
