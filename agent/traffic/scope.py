"""Scope 过滤器 —— 复用 my-agent 的 same_origin 逻辑，增加 open 模式。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse


class ScopeMode(str, Enum):
    STRICT = "strict"
    SUBDOMAIN = "subdomain"
    OPEN = "open"


@dataclass
class Target:
    """单个在域目标，用于捕获时过滤。"""
    host: str
    port: int | None = None
    path_prefix: str | None = None

    def __post_init__(self) -> None:
        self.host = (self.host or "").strip().lower()
        if self.path_prefix and not self.path_prefix.startswith("/"):
            self.path_prefix = "/" + self.path_prefix


def _host_port(url: str) -> tuple[str, int | None, str]:
    """解析 URL 返回 (host, port, path)。"""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.port:
        port = parsed.port
    elif parsed.scheme == "https":
        port = 443
    elif parsed.scheme == "http":
        port = 80
    else:
        port = None
    path = parsed.path or "/"
    return host, port, path


def _host_matches(candidate: str, target: Target, mode: ScopeMode) -> bool:
    """检查候选 host 是否匹配目标。"""
    if mode == ScopeMode.OPEN:
        return True
    if candidate == target.host:
        return True
    if mode == ScopeMode.SUBDOMAIN and candidate.endswith("." + target.host):
        return True
    return False


class ScopeChecker:
    """HTTP 流量 Scope 过滤器。

    复用 my-agent http_client 的 same_origin 思路，扩展 subdomain/open 模式。
    """

    def __init__(
        self,
        targets: list[Target] | None = None,
        mode: ScopeMode | str = ScopeMode.STRICT,
    ) -> None:
        self.targets = targets or []
        self.mode = ScopeMode(mode) if isinstance(mode, str) else mode

    def in_scope(self, url: str) -> bool:
        """判断 URL 是否在捕获范围内。"""
        if not url:
            return False
        if self.mode == ScopeMode.OPEN:
            return True
        if not self.targets:
            return False

        host, port, path = _host_port(url)

        for target in self.targets:
            if not _host_matches(host, target, self.mode):
                continue
            if target.port is not None and port != target.port:
                continue
            if target.path_prefix is not None and not path.startswith(target.path_prefix):
                continue
            return True

        return False
