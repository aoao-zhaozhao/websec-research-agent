"""原始 HTTP 报文序列化 —— 在 CapturedRequest/Response 和原始字节之间转换。"""

from __future__ import annotations

from urllib.parse import urlparse

from agent.traffic.models import CapturedRequest, CapturedResponse


def raw_request_bytes(request: CapturedRequest) -> bytes:
    """将 CapturedRequest 序列化为原始 HTTP 请求报文。

    格式:
        METHOD /path?query HTTP/1.1\r\n
        Name: Value\r\n
        \r\n
        <body>
    """
    parsed = urlparse(request.url or "")
    target = parsed.path or "/"
    if parsed.query:
        target = f"{target}?{parsed.query}"

    lines = [f"{request.method} {target} {request.http_version}"]
    for key, value in request.headers.items():
        lines.append(f"{key}: {value}")
    lines.append("")
    header_block = "\r\n".join(lines).encode("utf-8")
    return header_block + b"\r\n" + (request.body or b"")


def raw_response_bytes(response: CapturedResponse) -> bytes:
    """将 CapturedResponse 序列化为原始 HTTP 响应报文。

    格式:
        HTTP/1.1 200 OK\r\n
        Name: Value\r\n
        \r\n
        <body>
    """
    reason = response.reason or ""
    status_line = f"{response.http_version} {response.status} {reason}".strip()
    lines = [status_line]
    for key, value in response.headers.items():
        lines.append(f"{key}: {value}")
    lines.append("")
    header_block = "\r\n".join(lines).encode("utf-8")
    return header_block + b"\r\n" + (response.body or b"")


def parse_raw_request(blob: bytes, *, url: str = "") -> CapturedRequest:
    """从原始 HTTP 请求 blob 重建 CapturedRequest。"""
    text = blob.decode("utf-8", errors="replace")
    separator = "\r\n\r\n"
    if separator not in text:
        separator = "\n\n"

    header_part, _, body_part = text.partition(separator)
    header_lines = header_part.split("\r\n") if "\r\n" in header_part else header_part.split("\n")

    method, target, version = "GET", "/", "HTTP/1.1"
    if header_lines:
        parts = header_lines[0].strip().split()
        if len(parts) >= 1:
            method = parts[0]
        if len(parts) >= 2:
            target = parts[1]
        if len(parts) >= 3:
            version = parts[2]

    headers: dict[str, str] = {}
    for line in header_lines[1:]:
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip()] = value.strip()

    # 构建完整 URL
    full_url = url
    if not full_url:
        host = headers.get("Host", "")
        scheme = "https" if headers.get(":scheme") == "https" else "http"
        if host:
            full_url = f"{scheme}://{host}{target}"
        else:
            full_url = target

    return CapturedRequest(
        method=method,
        url=full_url,
        headers=headers,
        body=body_part.encode("utf-8", errors="replace") if body_part else b"",
        http_version=version,
    )
