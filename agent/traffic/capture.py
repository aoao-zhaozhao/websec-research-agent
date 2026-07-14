"""统一捕获入口 —— 所有后端共用的流量记录 seam。

Scope 检查 → TrafficStore.record()
"""

from __future__ import annotations

from agent.traffic.models import CapturedExchange
from agent.traffic.scope import ScopeChecker
from agent.traffic.store import TrafficStore


class TrafficCapture:
    """流量捕获统一入口。

    所有捕获后端（Agent 直接请求、Burp、Chrome DevTools）通过此类写入 TrafficStore。
    Scope 在写入前检查 —— 超域流量会被静默丢弃。
    """

    def __init__(self, store: TrafficStore, scope: ScopeChecker | None = None) -> None:
        self.store = store
        self.scope = scope or ScopeChecker()

    def capture(
        self,
        exchange: CapturedExchange,
        *,
        source: str,
        tags: list[str] | None = None,
        timestamp: str | None = None,
    ) -> str | None:
        """记录一次 HTTP 交换。返回 request_id，超域则返回 None。"""
        if not self.scope.in_scope(exchange.request.url):
            return None
        record = self.store.record(
            exchange, source=source, tags=tags, timestamp=timestamp
        )
        return record.request_id
