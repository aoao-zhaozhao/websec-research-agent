"""流量存储 —— 追加式 JSONL 索引 + 原始报文 blob 文件。

磁盘布局:
    <base_dir>/
      requests.jsonl              ← 追加式索引
      <request_id>/request        ← 原始请求报文
      <request_id>/response       ← 原始响应报文
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from agent.traffic.models import (
    VALID_SOURCES,
    CapturedExchange,
    TrafficRecord,
)
from agent.traffic.serialization import raw_request_bytes, raw_response_bytes, parse_raw_request

INDEX_FILENAME = "requests.jsonl"
REQUEST_BLOB = "request"
RESPONSE_BLOB = "response"


def compute_request_id(seq: int, request: Any) -> str:
    """根据序号和请求内容生成确定性的 request_id（SHA-256 前 16 位 hex）。"""
    url = getattr(request, "url", "") or ""
    method = getattr(request, "method", "GET") or "GET"
    body = getattr(request, "body", b"") or b""
    if isinstance(body, str):
        body = body.encode("utf-8", "replace")
    fingerprint = f"{seq:08d}\n{method} {url}\n".encode("utf-8") + body
    return hashlib.sha256(fingerprint).hexdigest()[:16]


class TrafficStore:
    """追加式 HTTP 流量证据存储。"""

    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)
        self.index_path = self.base_dir / INDEX_FILENAME

    def _next_seq(self) -> int:
        """从现有 JSONL 行数推断下一个序号。"""
        if not self.index_path.exists():
            return 0
        count = 0
        with open(self.index_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    count += 1
        return count

    def record(
        self,
        exchange: CapturedExchange,
        *,
        source: str,
        tags: list[str] | None = None,
        timestamp: str | None = None,
    ) -> TrafficRecord:
        """将一次 HTTP 交换写入存储。"""
        if source not in VALID_SOURCES:
            raise ValueError(f"无效的 source: {source}，有效值: {VALID_SOURCES}")

        seq = self._next_seq()
        request_id = compute_request_id(seq, exchange.request)

        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()

        # 解析 URL 组件
        parsed = urlparse(exchange.request.url or "")
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        status = exchange.response.status if exchange.response else 0
        content_length = len(exchange.response.body) if exchange.response else 0

        record = TrafficRecord(
            request_id=request_id,
            seq=seq,
            timestamp=timestamp,
            method=exchange.request.method,
            url=exchange.request.url,
            host=host,
            path=path,
            status=status,
            content_length=content_length,
            source=source,
            tags=list(tags or []),
        )

        # 确保目录存在
        self.base_dir.mkdir(parents=True, exist_ok=True)

        # 写入原始报文
        blob_dir = self.base_dir / request_id
        blob_dir.mkdir(parents=True, exist_ok=True)

        req_blob = raw_request_bytes(exchange.request)
        (blob_dir / REQUEST_BLOB).write_bytes(req_blob)

        if exchange.response:
            resp_blob = raw_response_bytes(exchange.response)
            (blob_dir / RESPONSE_BLOB).write_bytes(resp_blob)

        # 追加 JSONL 行
        with open(self.index_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record.to_index(), ensure_ascii=False) + "\n")

        return record

    def entries(self) -> list[dict]:
        """读取全部索引条目。"""
        if not self.index_path.exists():
            return []
        entries: list[dict] = []
        with open(self.index_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return entries

    def find(self, request_id: str) -> dict | None:
        """线性扫描查找指定 request_id 的索引条目。"""
        for entry in self.entries():
            if entry.get("request_id") == request_id:
                return entry
        return None

    def request_blob(self, request_id: str) -> bytes | None:
        """读取原始请求报文。"""
        blob_path = self.base_dir / request_id / REQUEST_BLOB
        if blob_path.exists():
            return blob_path.read_bytes()
        return None

    def response_blob(self, request_id: str) -> bytes | None:
        """读取原始响应报文。"""
        blob_path = self.base_dir / request_id / RESPONSE_BLOB
        if blob_path.exists():
            return blob_path.read_bytes()
        return None

    def view(self, request_id: str) -> dict | None:
        """获取一次交换的完整视图（索引条目 + 解码后的请求/响应文本）。"""
        entry = self.find(request_id)
        if entry is None:
            return None

        result = dict(entry)
        req_blob = self.request_blob(request_id)
        resp_blob = self.response_blob(request_id)

        if req_blob:
            try:
                result["request_text"] = req_blob.decode("utf-8", errors="replace")
            except Exception:
                result["request_text"] = repr(req_blob)

        if resp_blob:
            try:
                result["response_text"] = resp_blob.decode("utf-8", errors="replace")
            except Exception:
                result["response_text"] = repr(resp_blob)

        return result

    def load_request(self, request_id: str) -> Any | None:
        """从 blob 重建 CapturedRequest。"""
        entry = self.find(request_id)
        if entry is None:
            return None
        blob = self.request_blob(request_id)
        if blob is None:
            return None
        return parse_raw_request(blob, url=entry.get("url", ""))

    def sitemap(self) -> dict[str, list[dict]]:
        """按 host → path 聚合并统计命中次数。"""
        hosts: dict[str, dict[str, dict]] = {}
        for entry in self.entries():
            host = entry.get("host", "") or "unknown"
            path = entry.get("path", "/")
            method = entry.get("method", "GET")
            if host not in hosts:
                hosts[host] = {}
            if path not in hosts[host]:
                hosts[host][path] = {"methods": set(), "hits": 0}
            hosts[host][path]["methods"].add(method)
            hosts[host][path]["hits"] += 1

        result: dict[str, list[dict]] = {}
        for host in sorted(hosts):
            paths = []
            for path in sorted(hosts[host]):
                info = hosts[host][path]
                paths.append({
                    "path": path,
                    "methods": sorted(info["methods"]),
                    "hits": info["hits"],
                })
            result[host] = paths
        return result
