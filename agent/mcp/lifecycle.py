"""MCP 生命周期管理器 —— 启停 MCP 服务、健康检查、工具调度。

移植自 VulnClaw，适配 my-agent 的配置体系。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import time
from contextlib import suppress
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from agent.config import MCPServerConfig, MCPTransportConfig
from agent.mcp.registry import HealthStatus, MCPRegistry

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:  # pragma: no cover
    ClientSession = None          # type: ignore
    StdioServerParameters = None  # type: ignore
    stdio_client = None           # type: ignore

try:
    from mcp.client.streamable_http import streamablehttp_client
except ImportError:  # pragma: no cover
    streamablehttp_client = None  # type: ignore

try:
    from mcp.client.sse import sse_client
except ImportError:  # pragma: no cover
    sse_client = None  # type: ignore

HTTP_TRANSPORT_TYPES = frozenset({"streamable-http", "streamable_http", "streamablehttp", "http"})
SSE_TRANSPORT_TYPES = frozenset({"sse", "sse-client", "sse_client", "sseclient"})

_BENIGN_SHUTDOWN_KEYWORDS = ("cancel scope", "generator didn't stop")
_MEMORY_STORE: dict[str, str] = {}
_MEMORY_PATH: str | None = None


def _is_benign_shutdown_exception(exc: BaseException) -> bool:
    """判断是否为无害的关闭期异常（CancelScope、GeneratorExit 等）。"""
    if hasattr(exc, "exceptions"):
        subs = list(getattr(exc, "exceptions", []))
        return bool(subs) and all(_is_benign_shutdown_exception(sub) for sub in subs)
    if isinstance(exc, RuntimeError):
        msg = str(exc).lower()
        if any(kw in msg for kw in _BENIGN_SHUTDOWN_KEYWORDS):
            return True
    return isinstance(exc, (GeneratorExit, asyncio.CancelledError))


def _infer_port_from_url(url: str) -> int | None:
    """从 URL 推断端口号。"""
    parsed = urlparse(url)
    if parsed.port is not None:
        return parsed.port
    if parsed.scheme == "https":
        return 443
    if parsed.scheme == "http":
        return 80
    return None


class MCPLifecycleManager:
    """管理 MCP 服务的生命周期：启动、停止、健康检查、工具调用。

    支持 4 种传输:
    - local:  进程内实现（fetch / memory）
    - stdio:  通过子进程 stdin/stdout 通信
    - sse:    通过 HTTP SSE 连接外部服务
    - streamable-http: 通过 Streamable HTTP 协议

    外部服务不可用时自动降级为 placeholder 模式。
    """

    MAX_RESTART_ATTEMPTS = 3
    RESTART_BACKOFF_BASE = 1.0
    TERMINATE_GRACE_SECONDS = 5.0
    HEALTHY_RATE = 0.9
    DEGRADED_RATE = 0.5

    def __init__(self, servers: dict[str, MCPServerConfig]) -> None:
        self._servers_config = servers
        self.registry = MCPRegistry()
        self._processes: dict[str, subprocess.Popen] = {}
        self._mcp_clients: dict[str, Any] = {}
        self._fetch_cookies: Any = None

    # ═══════════════════════════════════════════════════════════
    # 生命周期
    # ═══════════════════════════════════════════════════════════

    async def __aenter__(self) -> MCPLifecycleManager:
        self.start_enabled_servers()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.astop_all()

    def start_enabled_servers(self) -> int:
        """启动所有启用的 MCP 服务。返回成功启动的数量。"""
        started = 0
        for name, server_config in self._servers_config.items():
            if server_config.enabled:
                self.registry.register_server(name)
                try:
                    if self._start_server(name, server_config):
                        started += 1
                except Exception as e:
                    self.registry.set_server_error(name, str(e), error_type="startup_error")
        return started

    def _start_server(self, name: str, config: MCPServerConfig) -> bool:
        """启动单个 MCP 服务。"""
        transport = config.transport

        # 本地实现
        if name in {"fetch", "memory"}:
            self.registry.set_server_running(name, running=False)
            self.registry.set_server_execution_mode(name, "local")
            self.registry.set_server_health(name, "healthy")
            self.registry.set_server_attach_result(name, attempted=False, succeeded=True)
            self._register_known_tools(name)
            return True

        # stdio
        if transport.type == "stdio":
            self.registry.set_server_health(name, HealthStatus.STARTING.value)
            attached = self._try_attach_stdio_client(name, config)
            self.registry.set_server_attach_result(name, attempted=True, succeeded=attached)
            self.registry.set_server_running(name, running=attached)
            self.registry.set_server_execution_mode(name, "sdk" if attached else "placeholder")
            self.registry.set_server_health(
                name, HealthStatus.HEALTHY.value if attached else HealthStatus.DEGRADED.value
            )
            if not attached:
                self._register_known_tools(name)
            return True

        # SSE
        if transport.type in SSE_TRANSPORT_TYPES:
            self.registry.set_server_health(name, HealthStatus.STARTING.value)
            attached = self._try_attach_sse_client(name, config)
            self.registry.set_server_attach_result(name, attempted=True, succeeded=attached)
            self.registry.set_server_running(name, running=attached)
            self.registry.set_server_execution_mode(name, "sse" if attached else "placeholder")
            self.registry.set_server_health(
                name, HealthStatus.HEALTHY.value if attached else HealthStatus.DEGRADED.value
            )
            if not attached:
                self._register_known_tools(name)
            return True

        # Streamable HTTP
        if transport.type in HTTP_TRANSPORT_TYPES:
            self.registry.set_server_health(name, HealthStatus.STARTING.value)
            attached = self._try_attach_http_client(name, config)
            self.registry.set_server_attach_result(name, attempted=True, succeeded=attached)
            self.registry.set_server_running(name, running=attached)
            self.registry.set_server_execution_mode(name, "http" if attached else "placeholder")
            self.registry.set_server_health(
                name, HealthStatus.HEALTHY.value if attached else HealthStatus.DEGRADED.value
            )
            if not attached:
                self._register_known_tools(name)
            return True

        self.registry.set_server_health(name, "unavailable")
        return False

    def stop_server(self, name: str) -> None:
        """同步停止单个 MCP 服务。"""
        self.registry.set_server_health(name, HealthStatus.STOPPING.value)
        client_meta = self._mcp_clients.pop(name, None)
        if isinstance(client_meta, dict) and client_meta.get("kind") in (
            "persistent-stdio", "persistent-http", "persistent-sse"
        ):
            loop = client_meta.get("loop")
            if loop is not None and not loop.is_closed():
                try:
                    future = asyncio.run_coroutine_threadsafe(
                        self._aclose_session_meta(client_meta), loop
                    )
                    future.result(timeout=5)
                except Exception:
                    pass

        proc = self._processes.pop(name, None)
        if proc is not None:
            self._graceful_terminate(proc)

        self.registry.set_server_running(name, running=False)
        self.registry.set_server_health(name, HealthStatus.UNKNOWN.value)

    def stop_all(self) -> None:
        """同步停止全部 MCP 服务。"""
        for name in list(self._servers_config.keys()):
            self.stop_server(name)

    async def astop_server(self, name: str) -> None:
        """异步停止单个 MCP 服务。"""
        self.registry.set_server_health(name, HealthStatus.STOPPING.value)
        client_meta = self._mcp_clients.pop(name, None)
        await self._aclose_session_meta(client_meta)
        proc = self._processes.pop(name, None)
        if proc is not None:
            await self._terminate_process(proc)
        self.registry.set_server_running(name, running=False)
        self.registry.set_server_health(name, HealthStatus.UNKNOWN.value)

    async def astop_all(self) -> None:
        """异步停止全部 MCP 服务。"""
        for name in list(self._servers_config.keys()):
            try:
                await self.astop_server(name)
            except BaseException as exc:
                if not _is_benign_shutdown_exception(exc):
                    raise

    # ═══════════════════════════════════════════════════════════
    # 工具调用调度
    # ═══════════════════════════════════════════════════════════

    def get_tool_schemas(self) -> list[dict[str, Any]]:
        """获取全部已注册工具的 OpenAI function-calling 格式 schema。"""
        return self.registry.get_all_tool_schemas()

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """调用一个 MCP 工具。返回统一的 _tool_result dict。"""
        server_name = self.registry.get_server_for_tool(tool_name)
        if not server_name:
            return self._tool_result(
                ok=False, server="unknown", tool=tool_name, execution_mode="unknown",
                error_type="unknown_tool",
                message=f"未知工具: {tool_name}",
                suggestion="检查工具名是否正确。",
            )

        # 进程存活检测 + 自动重启
        if server_name in self._processes and not self._is_process_alive(server_name):
            await self._restart_server(server_name)

        server_state = self.registry.get_all_servers().get(server_name)
        mode = server_state.execution_mode if server_state else "unknown"

        call_started = time.monotonic()
        try:
            return await self._dispatch_call_tool(server_name, tool_name, arguments, mode)
        finally:
            latency_ms = (time.monotonic() - call_started) * 1000.0
            self.registry.set_last_call_latency(server_name, latency_ms)

    async def _dispatch_call_tool(
        self, server_name: str, tool_name: str, arguments: dict[str, Any], mode: str
    ) -> dict[str, Any]:
        """按服务类型分发工具调用。"""
        try:
            # ── fetch (本地) ──
            if server_name == "fetch" and tool_name == "fetch":
                content = await self._call_fetch(arguments)
                self.registry.record_tool_call(server_name, success=True)
                return self._tool_result(
                    ok=True, server=server_name, tool=tool_name, execution_mode=mode,
                    content=content,
                )

            # ── memory (本地) ──
            if server_name == "memory":
                content = self._call_memory(tool_name, arguments)
                self.registry.record_tool_call(server_name, success=True)
                return self._tool_result(
                    ok=True, server=server_name, tool=tool_name, execution_mode=mode,
                    content=content,
                )

            # ── chrome-devtools ──
            if server_name == "chrome-devtools":
                try:
                    content, structured = await self._call_chrome(tool_name, arguments)
                    self.registry.record_tool_call(server_name, success=True)
                    return self._tool_result(
                        ok=True, server=server_name, tool=tool_name, execution_mode=mode,
                        content=content, structured_content=structured,
                    )
                except Exception as exc:
                    self.registry.record_tool_call(server_name, success=False)
                    self.registry.set_server_error(server_name, str(exc), error_type="service_unavailable")
                    return self._tool_result(
                        ok=False, server=server_name, tool=tool_name, execution_mode=mode,
                        error_type="service_unavailable", message=str(exc),
                        suggestion="启动 chrome-devtools MCP 服务或换用本地浏览器方案。",
                    )

            # ── burp ──
            if server_name == "burp":
                try:
                    content, structured = await self._call_burp(tool_name, arguments)
                    self.registry.record_tool_call(server_name, success=True)
                    return self._tool_result(
                        ok=True, server=server_name, tool=tool_name, execution_mode=mode,
                        content=content, structured_content=structured,
                    )
                except Exception as exc:
                    self.registry.record_tool_call(server_name, success=False)
                    self.registry.set_server_error(server_name, str(exc), error_type="service_unavailable")
                    return self._tool_result(
                        ok=False, server=server_name, tool=tool_name, execution_mode=mode,
                        error_type="service_unavailable", message=str(exc),
                        suggestion="启动 Burp MCP 扩展并确认代理集成就绪。",
                    )

            # ── 通用 SDK 附加路径 ──
            if self._is_sdk_attachable(server_name):
                try:
                    content, structured = await self._call_attached_server(server_name, tool_name, arguments)
                    self.registry.record_tool_call(server_name, success=True)
                    return self._tool_result(
                        ok=True, server=server_name, tool=tool_name, execution_mode=mode,
                        content=content, structured_content=structured,
                    )
                except Exception as exc:
                    self.registry.record_tool_call(server_name, success=False)
                    self.registry.set_server_error(server_name, str(exc), error_type="service_unavailable")
                    return self._tool_result(
                        ok=False, server=server_name, tool=tool_name, execution_mode=mode,
                        error_type="service_unavailable", message=str(exc),
                        suggestion="确认 MCP 服务可达、工具名与参数正确。",
                    )

            # ── 无法执行 ──
            msg = f"MCP 工具 '{tool_name}' 在 {mode} 模式下注册但不可执行。"
            self.registry.record_tool_call(server_name, success=False)
            self.registry.set_server_error(server_name, msg, error_type="unsupported_mode")
            return self._tool_result(
                ok=False, server=server_name, tool=tool_name, execution_mode=mode,
                error_type="unsupported_mode", message=msg,
                suggestion="换用本地替代方案，或为此服务启用可运行的后端。",
            )

        except Exception as exc:
            self.registry.record_tool_call(server_name, success=False)
            self.registry.set_server_error(server_name, str(exc), error_type="execution_failed")
            return self._tool_result(
                ok=False, server=server_name, tool=tool_name, execution_mode=mode,
                error_type="execution_failed", message=str(exc),
                suggestion="检查 MCP 服务状态与工具参数后重试。",
            )

    # ═══════════════════════════════════════════════════════════
    # 本地实现: fetch
    # ═══════════════════════════════════════════════════════════

    async def _call_fetch(self, args: dict) -> str:
        """使用 httpx 发送 HTTP 请求。与 my-agent 的 requests Session 共享 cookie jar。"""
        try:
            import httpx

            url = args.get("url", "")
            method = args.get("method", "GET").upper()
            headers = args.get("headers", {}) or {}
            body = args.get("body")

            if self._fetch_cookies is None:
                self._fetch_cookies = httpx.Cookies()

            async with httpx.AsyncClient(
                verify=False, timeout=30.0, cookies=self._fetch_cookies, follow_redirects=True,
            ) as client:
                response = await client.request(
                    method=method, url=url, headers=headers, content=body,
                )
                self._fetch_cookies.extract_cookies(response)

            result = f"Status: {response.status_code}\n"
            result += f"Headers: {dict(response.headers)}\n"
            result += f"Body (first 2000 chars): {response.text[:2000]}"
            return result

        except ImportError:
            return "[!] httpx 未安装，无法执行 fetch 请求"
        except Exception as e:
            return f"[!] fetch 请求失败: {e}"

    # ═══════════════════════════════════════════════════════════
    # 本地实现: memory
    # ═══════════════════════════════════════════════════════════

    def _call_memory(self, tool_name: str, args: dict) -> str:
        """本地键值存储（内存 dict + 可选 JSON 文件）。"""
        global _MEMORY_STORE, _MEMORY_PATH

        if tool_name == "save":
            key = str(args.get("key", ""))
            value = str(args.get("value", ""))
            _MEMORY_STORE[key] = value
            self._persist_memory()
            return f"[+] 已保存: {key}"

        if tool_name == "retrieve":
            key = str(args.get("key", ""))
            value = _MEMORY_STORE.get(key)
            if value is not None:
                return str(value)
            return f"[-] 未找到: {key}"

        return f"[!] 未知 memory 工具: {tool_name}"

    def _persist_memory(self) -> None:
        """将内存字典写入 JSON 文件（如已配置路径）。"""
        global _MEMORY_PATH
        if _MEMORY_PATH:
            try:
                os.makedirs(os.path.dirname(_MEMORY_PATH), exist_ok=True)
                with open(_MEMORY_PATH, "w", encoding="utf-8") as f:
                    json.dump(_MEMORY_STORE, f, ensure_ascii=False, indent=2)
            except Exception:
                pass

    @staticmethod
    def set_memory_path(path: str) -> None:
        """设置 memory 持久化文件路径，并加载已有数据。"""
        global _MEMORY_PATH, _MEMORY_STORE
        _MEMORY_PATH = path
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    _MEMORY_STORE = json.load(f)
        except Exception:
            _MEMORY_STORE = {}

    # ═══════════════════════════════════════════════════════════
    # 外部 MCP 调用
    # ═══════════════════════════════════════════════════════════

    async def _call_chrome(self, tool_name: str, args: dict) -> tuple[str, dict | None]:
        """调用 chrome-devtools MCP 工具。"""
        return await self._call_attached_server("chrome-devtools", tool_name, args)

    async def _call_burp(self, tool_name: str, args: dict) -> tuple[str, dict | None]:
        """调用 Burp Suite MCP 工具。"""
        return await self._call_attached_server("burp", tool_name, args)

    async def _call_attached_server(
        self, server_name: str, tool_name: str, args: dict
    ) -> tuple[str, dict | None]:
        """通过持久化 SDK 会话调用外部 MCP 服务。"""
        session = await self._get_or_create_session(server_name)
        config = self._servers_config.get(server_name)
        timeout_s = (
            (config.tool_timeout_ms / 1000.0)
            if config and config.tool_timeout_ms
            else 300.0
        )
        result = await asyncio.wait_for(
            session.call_tool(tool_name, arguments=args), timeout=timeout_s
        )
        rendered, structured, is_error = self._render_mcp_call_result(result)
        if is_error:
            raise RuntimeError(rendered or f"{server_name} 调用返回错误")
        return rendered, structured

    # ═══════════════════════════════════════════════════════════
    # MCP SDK 会话管理
    # ═══════════════════════════════════════════════════════════

    async def _get_or_create_session(self, server_name: str) -> Any:
        """根据传输类型获取或创建持久化 MCP 会话。"""
        config = self._servers_config.get(server_name)
        transport_type = (config.transport.type if config else "").lower()
        if transport_type in SSE_TRANSPORT_TYPES:
            return await self._get_or_create_persistent_sse_session(server_name)
        if transport_type in HTTP_TRANSPORT_TYPES:
            return await self._get_or_create_persistent_http_session(server_name)
        return await self._get_or_create_persistent_stdio_session(server_name)

    def _is_sdk_attachable(self, server_name: str) -> bool:
        """判断服务是否可通过 MCP SDK 驱动。"""
        config = self._servers_config.get(server_name)
        if config is None or config.transport is None:
            return False
        ttype = (config.transport.type or "").lower()
        if ttype in HTTP_TRANSPORT_TYPES:
            return streamablehttp_client is not None and ClientSession is not None
        if ttype in SSE_TRANSPORT_TYPES:
            return sse_client is not None and ClientSession is not None
        if ttype == "stdio":
            return stdio_client is not None and ClientSession is not None
        return False

    async def _get_or_create_persistent_stdio_session(self, server_name: str) -> Any:
        """创建并缓存 stdio MCP 会话。"""
        if stdio_client is None or ClientSession is None:
            raise RuntimeError("MCP Python SDK 未安装")

        current_loop = asyncio.get_running_loop()
        client_meta = self._mcp_clients.get(server_name)

        if isinstance(client_meta, dict) and client_meta.get("kind") == "persistent-stdio":
            if client_meta.get("loop") is current_loop and client_meta.get("session") is not None:
                return client_meta["session"]

        config = self._servers_config.get(server_name)
        if config is None:
            raise RuntimeError(f"缺少 MCP 配置: {server_name}")

        transport = config.transport
        server = StdioServerParameters(
            command=transport.command or "",
            args=transport.args or [],
            env=transport.env,
        )
        timeout_s = (config.tool_timeout_ms / 1000.0) if config.tool_timeout_ms else 300.0

        cm = stdio_client(server)
        read_stream, write_stream = await cm.__aenter__()
        session = ClientSession(
            read_stream, write_stream,
            read_timeout_seconds=timedelta(seconds=timeout_s),
        )
        try:
            await session.__aenter__()
            await session.initialize()
        except BaseException:
            with suppress(Exception):
                await session.__aexit__(None, None, None)
            with suppress(Exception):
                await cm.__aexit__(None, None, None)
            raise

        # 发现真实工具
        try:
            result = await asyncio.wait_for(session.list_tools(), timeout=10)
            tool_defs = self._normalize_mcp_tools(getattr(result, "tools", []) or [])
            if tool_defs:
                self._register_runtime_tools(server_name, tool_defs)
        except BaseException:
            pass

        # 关闭旧上下文管理器
        old_cm = client_meta.get("context_manager") if isinstance(client_meta, dict) else None
        if old_cm is not None and old_cm is not cm:
            with suppress(Exception):
                await old_cm.__aexit__(None, None, None)

        self._mcp_clients[server_name] = {
            "kind": "persistent-stdio", "config": config,
            "loop": current_loop, "session": session, "context_manager": cm,
        }
        return session

    async def _get_or_create_persistent_sse_session(self, server_name: str) -> Any:
        """创建并缓存 SSE MCP 会话。"""
        if sse_client is None or ClientSession is None:
            raise RuntimeError("MCP Python SDK 未安装")

        current_loop = asyncio.get_running_loop()
        client_meta = self._mcp_clients.get(server_name)

        if isinstance(client_meta, dict) and client_meta.get("kind") == "persistent-sse":
            if client_meta.get("loop") is current_loop and client_meta.get("session") is not None:
                return client_meta["session"]

        config = self._servers_config.get(server_name)
        if config is None:
            raise RuntimeError(f"缺少 MCP 配置: {server_name}")

        url = config.transport.url or ""
        if not url:
            raise RuntimeError(f"SSE 传输缺少 URL: {server_name}")
        timeout_s = (config.tool_timeout_ms / 1000.0) if config.tool_timeout_ms else 300.0

        cm = None
        session = None
        try:
            cm = sse_client(url)
            read_stream, write_stream = await cm.__aenter__()
            session = ClientSession(
                read_stream, write_stream,
                read_timeout_seconds=timedelta(seconds=timeout_s),
            )
            await session.__aenter__()
            await session.initialize()
        except BaseException as exc:
            if session is not None:
                with suppress(Exception):
                    await session.__aexit__(None, None, None)
            if cm is not None:
                with suppress(Exception):
                    await cm.__aexit__(None, None, None)
            detail = str(exc)
            if hasattr(exc, "exceptions"):
                subs = list(getattr(exc, "exceptions", []))
                if subs:
                    detail = "; ".join(str(s) for s in subs)
            raise RuntimeError(f"SSE 会话失败 [{server_name}]: {detail}") from None

        try:
            tools = await session.list_tools()
            tool_defs = self._normalize_mcp_tools(getattr(tools, "tools", []) or [])
            if tool_defs:
                self._register_runtime_tools(server_name, tool_defs)
        except Exception:
            pass

        self._mcp_clients[server_name] = {
            "kind": "persistent-sse", "config": config,
            "loop": current_loop, "session": session, "context_manager": cm,
        }
        self.registry.set_server_running(server_name, running=True)
        self.registry.set_server_health(server_name, HealthStatus.HEALTHY.value)
        return session

    async def _get_or_create_persistent_http_session(self, server_name: str) -> Any:
        """创建并缓存 Streamable HTTP MCP 会话。"""
        if streamablehttp_client is None or ClientSession is None:
            raise RuntimeError("MCP Python SDK 未安装")

        current_loop = asyncio.get_running_loop()
        client_meta = self._mcp_clients.get(server_name)

        if isinstance(client_meta, dict) and client_meta.get("kind") == "persistent-http":
            if client_meta.get("loop") is current_loop and client_meta.get("session") is not None:
                return client_meta["session"]

        config = self._servers_config.get(server_name)
        if config is None:
            raise RuntimeError(f"缺少 MCP 配置: {server_name}")

        url = config.transport.url or ""
        if not url:
            raise RuntimeError(f"Streamable HTTP 传输缺少 URL: {server_name}")
        headers = config.transport.env or None
        startup_timeout_s = (config.startup_timeout_ms / 1000.0) if config.startup_timeout_ms else 30.0
        read_timeout_s = (config.tool_timeout_ms / 1000.0) if config.tool_timeout_ms else 300.0

        cm = None
        session = None
        try:
            cm = streamablehttp_client(
                url, headers=headers, timeout=startup_timeout_s, sse_read_timeout=read_timeout_s,
            )
            read_stream, write_stream, _get_session_id = await cm.__aenter__()
            session = ClientSession(
                read_stream, write_stream,
                read_timeout_seconds=timedelta(seconds=read_timeout_s),
            )
            await session.__aenter__()
            await session.initialize()
        except BaseException as exc:
            if session is not None:
                with suppress(Exception):
                    await session.__aexit__(None, None, None)
            if cm is not None:
                with suppress(Exception):
                    await cm.__aexit__(None, None, None)
            detail = str(exc)
            if hasattr(exc, "exceptions"):
                subs = list(getattr(exc, "exceptions", []))
                if subs:
                    detail = "; ".join(str(s) for s in subs)
            raise RuntimeError(f"HTTP 会话失败 [{server_name}]: {detail}") from None

        try:
            tools = await session.list_tools()
            tool_defs = self._normalize_mcp_tools(getattr(tools, "tools", []) or [])
            if tool_defs:
                self._register_runtime_tools(server_name, tool_defs)
        except Exception:
            pass

        self._mcp_clients[server_name] = {
            "kind": "persistent-http", "config": config,
            "loop": current_loop, "session": session, "context_manager": cm,
        }
        self.registry.set_server_running(server_name, running=True)
        self.registry.set_server_health(server_name, HealthStatus.HEALTHY.value)
        return session

    # ═══════════════════════════════════════════════════════════
    # 传输探测
    # ═══════════════════════════════════════════════════════════

    _DEFERRED_PACKAGE_COMMANDS = frozenset({
        "npx", "pnpx", "bunx", "npm", "pnpm", "yarn", "bun",
    })

    def _is_deferred_package_command(self, command: str) -> bool:
        """判断命令是否会触发包管理器下载（健康探测应跳过）。"""
        if not command:
            return False
        base = os.path.basename(command.rstrip("/\\")).lower()
        return base in self._DEFERRED_PACKAGE_COMMANDS

    @staticmethod
    def _check_http_reachable(url: str) -> bool:
        """快速 HTTP 连通性检查。"""
        try:
            import httpx
            with httpx.stream("GET", url, timeout=10.0) as resp:
                return resp.status_code < 500
        except Exception:
            return False

    def _try_attach_stdio_client(self, name: str, config: MCPServerConfig) -> bool:
        """探测 stdio MCP 服务是否可达并列出工具。"""
        if stdio_client is None or ClientSession is None:
            return False
        transport = config.transport
        if not transport.command:
            return False
        if self._is_deferred_package_command(transport.command):
            return False
        ok, _detail, tool_defs = self._run_probe(
            self._async_probe_stdio_server(config)
        )
        if ok and tool_defs:
            self._register_runtime_tools(name, tool_defs)
        return ok

    def _try_attach_sse_client(self, name: str, config: MCPServerConfig) -> bool:
        """探测 SSE MCP 服务是否可达并列出工具。"""
        if sse_client is None or ClientSession is None:
            return False
        url = config.transport.url or ""
        if not url:
            return False
        if not self._check_http_reachable(url):
            return False
        ok, _detail, tool_defs = self._run_probe(
            self._async_probe_sse_server(config)
        )
        if ok and tool_defs:
            self._register_runtime_tools(name, tool_defs)
        return ok

    def _try_attach_http_client(self, name: str, config: MCPServerConfig) -> bool:
        """探测 Streamable HTTP MCP 服务是否可达。"""
        if streamablehttp_client is None or ClientSession is None:
            return False
        url = config.transport.url or ""
        if not url:
            return False
        if not self._check_http_reachable(url):
            return False
        return True

    async def _async_probe_stdio_server(
        self, config: MCPServerConfig
    ) -> tuple[bool, str, list[dict] | None]:
        """启动 stdio 子进程，初始化 MCP 会话，列出工具后立即关闭。"""
        transport = config.transport
        server = StdioServerParameters(
            command=transport.command or "",
            args=transport.args or [],
            env=transport.env,
        )
        timeout_s = (config.startup_timeout_ms / 1000.0) if config.startup_timeout_ms else 30.0
        try:
            async with stdio_client(server) as (read_stream, write_stream):
                async with ClientSession(
                    read_stream, write_stream,
                    read_timeout_seconds=timedelta(seconds=timeout_s),
                ) as session:
                    await asyncio.wait_for(session.initialize(), timeout=timeout_s)
                    result = await asyncio.wait_for(session.list_tools(), timeout=timeout_s)
                    tool_defs = self._normalize_mcp_tools(getattr(result, "tools", []) or [])
                    return True, "stdio probe ok", tool_defs
        except Exception as e:
            return False, str(e), None

    async def _async_probe_sse_server(
        self, config: MCPServerConfig
    ) -> tuple[bool, str, list[dict] | None]:
        """通过 SSE 探测 MCP 服务并列出工具。"""
        url = config.transport.url or ""
        timeout_s = (config.startup_timeout_ms / 1000.0) if config.startup_timeout_ms else 30.0
        try:
            async with sse_client(url) as (read_stream, write_stream):
                async with ClientSession(
                    read_stream, write_stream,
                    read_timeout_seconds=timedelta(seconds=timeout_s),
                ) as session:
                    await asyncio.wait_for(session.initialize(), timeout=timeout_s)
                    result = await asyncio.wait_for(session.list_tools(), timeout=timeout_s)
                    tool_defs = self._normalize_mcp_tools(getattr(result, "tools", []) or [])
                    return True, "sse probe ok", tool_defs
        except Exception as e:
            return False, str(e), None

    async def _async_probe_http_server(
        self, config: MCPServerConfig
    ) -> tuple[bool, str, list[dict] | None]:
        """通过 Streamable HTTP 探测 MCP 服务并列出工具。"""
        url = config.transport.url or ""
        headers = config.transport.env or None
        timeout_s = (config.startup_timeout_ms / 1000.0) if config.startup_timeout_ms else 30.0
        try:
            async with streamablehttp_client(
                url, headers=headers, timeout=timeout_s, sse_read_timeout=timeout_s,
            ) as (read_stream, write_stream, _get_session_id):
                async with ClientSession(
                    read_stream, write_stream,
                    read_timeout_seconds=timedelta(seconds=timeout_s),
                ) as session:
                    await asyncio.wait_for(session.initialize(), timeout=timeout_s)
                    result = await asyncio.wait_for(session.list_tools(), timeout=timeout_s)
                    tool_defs = self._normalize_mcp_tools(getattr(result, "tools", []) or [])
                    return True, "http probe ok", tool_defs
        except Exception as e:
            return False, str(e), None

    def _run_probe(self, coro: Any) -> tuple[bool, str, list[dict] | None]:
        """在同步或异步上下文中安全运行异步探测协程。"""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            try:
                return asyncio.run(coro)
            except Exception as e:
                return False, str(e), None

        import concurrent.futures
        future = concurrent.futures.Future()

        def _runner() -> None:
            try:
                result = asyncio.run(coro)
                future.set_result(result)
            except Exception as exc:
                future.set_exception(exc)

        thread = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        thread.submit(_runner)
        try:
            return future.result(timeout=35)
        except Exception as e:
            return False, str(e), None

    # ═══════════════════════════════════════════════════════════
    # 健康检查 + 自动重启
    # ═══════════════════════════════════════════════════════════

    def _is_process_alive(self, server_name: str) -> bool:
        """检查服务的子进程是否仍存活。"""
        proc = self._processes.get(server_name)
        if proc is None:
            return True
        return proc.poll() is None

    async def _restart_server(self, server_name: str) -> bool:
        """指数退避重启崩溃的服务（最多 3 次）。"""
        config = self._servers_config.get(server_name)
        if config is None:
            self.registry.set_server_error(server_name, "缺少配置", error_type="config_error")
            self.registry.set_server_health(server_name, HealthStatus.UNAVAILABLE.value)
            return False

        await self._teardown_server(server_name)

        for attempt in range(1, self.MAX_RESTART_ATTEMPTS + 1):
            if attempt > 1:
                backoff = self.RESTART_BACKOFF_BASE * (2 ** (attempt - 2))
                await asyncio.sleep(backoff)
            self.registry.record_restart(server_name)
            self.registry.set_server_health(server_name, HealthStatus.STARTING.value)
            try:
                started = self._start_server(server_name, config)
            except Exception as exc:
                self.registry.set_server_error(server_name, str(exc), error_type="restart_error")
                continue
            if started and self._is_server_back_up(server_name):
                return True

        self.registry.set_server_health(server_name, HealthStatus.UNAVAILABLE.value)
        return False

    def _is_server_back_up(self, server_name: str) -> bool:
        """判断服务是否已恢复。"""
        state = self.registry.get_all_servers().get(server_name)
        if state is None:
            return False
        if state.running:
            return True
        return (
            state.execution_mode == "local"
            and state.health_status == HealthStatus.HEALTHY.value
        )

    async def _teardown_server(self, server_name: str) -> None:
        """关闭会话并终止进程。"""
        client_meta = self._mcp_clients.pop(server_name, None)
        await self._aclose_session_meta(client_meta)
        proc = self._processes.pop(server_name, None)
        if proc is not None:
            await self._terminate_process(proc)

    async def _aclose_session_meta(self, client_meta: Any) -> None:
        """关闭持久化会话及其传输上下文。"""
        if not isinstance(client_meta, dict):
            return
        if client_meta.get("kind") not in ("persistent-stdio", "persistent-http", "persistent-sse"):
            return
        session = client_meta.get("session")
        if session is not None:
            try:
                await session.__aexit__(None, None, None)
            except BaseException as exc:
                if not _is_benign_shutdown_exception(exc):
                    raise
        cm = client_meta.get("context_manager")
        if cm is not None:
            try:
                await cm.__aexit__(None, None, None)
            except BaseException as exc:
                if not _is_benign_shutdown_exception(exc):
                    raise

    # ═══════════════════════════════════════════════════════════
    # 进程管理
    # ═══════════════════════════════════════════════════════════

    def _graceful_terminate(self, proc: subprocess.Popen) -> None:
        """优雅终止进程：terminate → 等待 → kill。"""
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=self.TERMINATE_GRACE_SECONDS)
            return
        except Exception:
            pass
        try:
            proc.kill()
            proc.wait(timeout=self.TERMINATE_GRACE_SECONDS)
        except Exception:
            pass

    async def _terminate_process(self, proc: subprocess.Popen) -> None:
        """异步终止进程。"""
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
        except Exception:
            pass
        deadline = time.monotonic() + self.TERMINATE_GRACE_SECONDS
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return
            await asyncio.sleep(0.05)
        with suppress(Exception):
            proc.kill()

    # ═══════════════════════════════════════════════════════════
    # 工具 schema 归一化
    # ═══════════════════════════════════════════════════════════

    def _normalize_mcp_tools(self, tools: list[Any]) -> list[dict[str, Any]]:
        """将 MCP SDK 返回的工具列表归一化为 dict 列表。"""
        normalized: list[dict[str, Any]] = []
        for tool in tools:
            name = getattr(tool, "name", None)
            if not name:
                continue
            normalized.append({
                "name": name,
                "description": getattr(tool, "description", "") or "",
                "inputSchema": (
                    getattr(tool, "inputSchema", None)
                    or getattr(tool, "input_schema", None)
                    or {"type": "object", "properties": {}}
                ),
            })
        return normalized

    def _render_mcp_call_result(self, result: Any) -> tuple[str, dict | None, bool]:
        """将 MCP 的 CallToolResult 归一化为可读文本 + 结构化数据。"""
        if result is None:
            return "", None, False

        structured = getattr(result, "structuredContent", None)
        is_error = bool(getattr(result, "isError", False))
        content_items = getattr(result, "content", None)

        if not content_items:
            return (
                str(structured or result),
                structured if isinstance(structured, dict) else None,
                is_error,
            )

        parts: list[str] = []
        for item in content_items:
            item_type = getattr(item, "type", "")
            if item_type == "text":
                text = getattr(item, "text", "")
                if text:
                    parts.append(str(text))
            elif item_type == "image":
                mime = getattr(item, "mimeType", "") or getattr(item, "mime_type", "")
                parts.append(f"[image:{mime or 'unknown'}]")
            elif item_type == "resource_link":
                uri = getattr(item, "uri", "")
                name = getattr(item, "name", "") or uri
                parts.append(f"[resource:{name}]")
            else:
                parts.append(str(item))

        rendered = "\n".join(part for part in parts if part).strip()
        if not rendered and structured is not None:
            rendered = str(structured)
        return rendered, structured if isinstance(structured, dict) else None, is_error

    def _register_runtime_tools(self, server_name: str, tools: list[dict[str, Any]]) -> None:
        """用运行时发现的真实工具替换静态占位工具。"""
        self.registry.clear_server_tools(server_name)
        for tool in tools:
            self.registry.register_tool(server_name, tool)

    # ═══════════════════════════════════════════════════════════
    # 已知工具注册（fallback）
    # ═══════════════════════════════════════════════════════════

    def _register_known_tools(self, server_name: str) -> None:
        """为某个服务注册静态已知工具（外部 MCP 不可用时的占位）。"""
        KNOWN_TOOLS: dict[str, list[dict]] = {
            "fetch": [{
                "name": "fetch",
                "description": "Fetch a URL and return the content",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "URL to fetch"},
                        "method": {
                            "type": "string", "description": "HTTP method", "default": "GET",
                        },
                        "headers": {"type": "object", "description": "HTTP headers"},
                        "body": {"type": "string", "description": "Request body"},
                    },
                    "required": ["url"],
                },
            }],
            "memory": [
                {
                    "name": "save",
                    "description": "Save information to persistent memory",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "key": {"type": "string", "description": "Memory key"},
                            "value": {"type": "string", "description": "Memory value"},
                        },
                        "required": ["key", "value"],
                    },
                },
                {
                    "name": "retrieve",
                    "description": "Retrieve information from persistent memory",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "key": {"type": "string", "description": "Memory key to retrieve"},
                        },
                        "required": ["key"],
                    },
                },
            ],
            "chrome-devtools": [
                {
                    "name": "chrome_navigate",
                    "description": "Navigate Chrome to a URL",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL to navigate to"},
                        },
                        "required": ["url"],
                    },
                },
                {
                    "name": "chrome_read_page",
                    "description": "Read the current page content (HTML, text, links, forms)",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "format": {
                                "type": "string", "description": "Output format: text, html, links, forms",
                                "default": "text",
                            },
                        },
                    },
                },
                {
                    "name": "chrome_screenshot",
                    "description": "Take a screenshot of the current page",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "chrome_javascript",
                    "description": "Execute JavaScript in the browser and return the result",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "code": {"type": "string", "description": "JavaScript code to execute"},
                        },
                        "required": ["code"],
                    },
                },
                {
                    "name": "chrome_get_web_content",
                    "description": "Get structured web content from the current page",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL (optional, uses current page)"},
                        },
                    },
                },
                {
                    "name": "chrome_console",
                    "description": "Get browser console messages (errors, warnings, logs)",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "chrome_network_request",
                    "description": "Send an HTTP request through the browser context",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL"},
                            "method": {"type": "string", "description": "HTTP method"},
                            "headers": {"type": "object", "description": "Headers"},
                            "body": {"type": "string", "description": "Request body"},
                        },
                        "required": ["url"],
                    },
                },
                {
                    "name": "chrome_click_element",
                    "description": "Click an element on the page by CSS selector or text",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "selector": {"type": "string", "description": "CSS selector or text to click"},
                        },
                        "required": ["selector"],
                    },
                },
                {
                    "name": "chrome_fill_or_select",
                    "description": "Fill in a form field or select an option",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "selector": {"type": "string", "description": "CSS selector of the input"},
                            "value": {"type": "string", "description": "Value to fill"},
                        },
                        "required": ["selector", "value"],
                    },
                },
                {
                    "name": "chrome_pentest_http",
                    "description": "Analyze HTTP security: CORS, CSP, HSTS, cookie flags",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL to analyze"},
                        },
                    },
                },
                {
                    "name": "chrome_pentest_js_analyze",
                    "description": "Analyze JavaScript for security issues",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "chrome_pentest_cookies",
                    "description": "Analyze cookies for security flags",
                    "inputSchema": {"type": "object", "properties": {}},
                },
                {
                    "name": "chrome_pentest_headers",
                    "description": "Check HTTP response security headers",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL to check"},
                        },
                    },
                },
            ],
            "burp": [
                {
                    "name": "send_http1_request",
                    "description": "Send an HTTP/1 request through Burp proxy",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "method": {"type": "string", "description": "HTTP method"},
                            "url": {"type": "string", "description": "Target URL"},
                            "headers": {"type": "object", "description": "Request headers"},
                            "body": {"type": "string", "description": "Request body"},
                        },
                        "required": ["method", "url"],
                    },
                },
                {
                    "name": "get_proxy_http_history",
                    "description": "Get items within the proxy HTTP history",
                    "inputSchema": {"type": "object", "properties": {}},
                },
            ],
        }

        tools = KNOWN_TOOLS.get(server_name, [])
        for tool in tools:
            self.registry.register_tool(server_name, tool)

    # ═══════════════════════════════════════════════════════════
    # ToolResult 输出格式
    # ═══════════════════════════════════════════════════════════

    def _tool_result(
        self,
        *,
        ok: bool,
        server: str,
        tool: str,
        execution_mode: str,
        content: Any = None,
        structured_content: dict[str, Any] | None = None,
        error_type: str | None = None,
        message: str = "",
        suggestion: str = "",
    ) -> dict[str, Any]:
        """构建统一的工具调用结果 dict。"""
        return {
            "ok": ok,
            "server": server,
            "tool": tool,
            "execution_mode": execution_mode,
            "content": content,
            "structured_content": structured_content,
            "error_type": error_type,
            "message": message,
            "suggestion": suggestion,
        }
