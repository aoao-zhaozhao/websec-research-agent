"""
Shared HTTP helpers for scanner tools.

v0.6 centralizes URL normalization, same-origin checks, timeouts, a light
per-host rate limit, retries, and response truncation.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from urllib.parse import urldefrag, urljoin, urlparse

import requests


DEFAULT_TIMEOUT = float(os.getenv("SCAN_TIMEOUT", "10"))
DEFAULT_MAX_CHARS = int(os.getenv("SCAN_MAX_RESPONSE_CHARS", "3000"))
DEFAULT_MIN_INTERVAL = float(os.getenv("SCAN_MIN_INTERVAL", "0.2"))
DEFAULT_RETRIES = int(os.getenv("SCAN_RETRIES", "1"))
DEFAULT_USER_AGENT = os.getenv(
    "SCAN_USER_AGENT",
    "MyAgent-WebSecurityScanner/0.6 (+authorized security testing)",
)
DEFAULT_PROXY = os.getenv("SCAN_PROXY", "")

_session = requests.Session()
_session.headers.update({"User-Agent": DEFAULT_USER_AGENT})
if DEFAULT_PROXY:
    _session.proxies = {"http": DEFAULT_PROXY, "https": DEFAULT_PROXY}
_last_request_at: dict[str, float] = {}
_rate_lock = threading.Lock()
_proxy_lock = threading.Lock()


@dataclass
class RequestOptions:
    timeout: float = DEFAULT_TIMEOUT
    min_interval: float = DEFAULT_MIN_INTERVAL
    retries: int = DEFAULT_RETRIES
    max_chars: int = DEFAULT_MAX_CHARS


def normalize_url(url: str, base_url: str | None = None) -> str:
    """Normalize a URL for scanning and drop fragments."""
    raw = (url or "").strip()
    if base_url:
        raw = urljoin(base_url, raw)
    if raw and "://" not in raw and not raw.startswith("//"):
        raw = "http://" + raw
    normalized, _ = urldefrag(raw)
    return normalized.rstrip("/") if normalized not in ("http://", "https://") else normalized


def is_http_url(url: str) -> bool:
    return urlparse(url).scheme in ("http", "https")


def same_origin(root_url: str, target_url: str) -> bool:
    root = urlparse(normalize_url(root_url))
    target = urlparse(normalize_url(target_url, root_url))
    return bool(root.netloc) and root.netloc == target.netloc


def in_scope_url(root_url: str, target_url: str) -> str | None:
    """Return a normalized URL when it is an HTTP(S) same-origin URL."""
    normalized = normalize_url(target_url, root_url)
    if is_http_url(normalized) and same_origin(root_url, normalized):
        return normalized
    return None


def truncate_text(text: str, max_chars: int = DEFAULT_MAX_CHARS) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + f"\n...[truncated {len(text) - max_chars} chars]"


def _wait_for_host(url: str, min_interval: float) -> None:
    if min_interval <= 0:
        return
    host = urlparse(url).netloc
    if not host:
        return
    with _rate_lock:
        now = time.monotonic()
        wait = min_interval - (now - _last_request_at.get(host, 0.0))
        if wait > 0:
            time.sleep(wait)
        _last_request_at[host] = time.monotonic()


def request(method: str, url: str, **kwargs) -> requests.Response:
    """Send an HTTP request with scanner defaults and one retry by default."""
    options = RequestOptions(
        timeout=float(kwargs.pop("timeout", DEFAULT_TIMEOUT)),
        min_interval=float(kwargs.pop("min_interval", DEFAULT_MIN_INTERVAL)),
        retries=int(kwargs.pop("retries", DEFAULT_RETRIES)),
    )
    normalized = normalize_url(url)
    if not is_http_url(normalized):
        raise ValueError(f"unsupported URL scheme: {url}")

    kwargs.setdefault("verify", False)
    kwargs.setdefault("allow_redirects", True)
    kwargs.setdefault("timeout", options.timeout)

    last_exc: Exception | None = None
    for attempt in range(options.retries + 1):
        try:
            _wait_for_host(normalized, options.min_interval)
            return _session.request(method.upper(), normalized, **kwargs)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as exc:
            last_exc = exc
            if attempt >= options.retries:
                raise
            time.sleep(0.25 * (attempt + 1))
    if last_exc:
        raise last_exc
    raise RuntimeError("request failed without an exception")


def set_proxy(proxy_url: str | None) -> None:
    """动态设置/取消 HTTP 代理（v1.8 mitmproxy 集成）。

    传空字符串或 None 取消代理。
    线程安全。
    """
    with _proxy_lock:
        if proxy_url:
            _session.proxies = {"http": proxy_url, "https": proxy_url}
        else:
            _session.proxies = {}


def get_proxy() -> str | None:
    """获取当前代理 URL，无代理时返回 None。"""
    proxies = _session.proxies
    return proxies.get("http") or proxies.get("https") or None


def get(url: str, **kwargs) -> requests.Response:
    return request("GET", url, **kwargs)


def post(url: str, **kwargs) -> requests.Response:
    return request("POST", url, **kwargs)
