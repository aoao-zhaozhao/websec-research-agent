"""
MCP 可插拔工具链 (v1.8) —— 服务注册、生命周期管理、健康诊断。

提供 4 个 MCP 服务的标准接入:
- fetch:  本地 HTTP 请求（httpx）
- memory: 本地键值存储
- chrome-devtools: Chrome 浏览器自动化（stdio MCP）
- burp:    Burp Suite 代理集成（SSE MCP）
"""

from .registry import MCPRegistry, MCPServerState, MCPToolSchema, HealthStatus
from .lifecycle import MCPLifecycleManager
from .schemas import MCPServiceView, MCPDiagnosticsView

__all__ = [
    "MCPRegistry",
    "MCPServerState",
    "MCPToolSchema",
    "HealthStatus",
    "MCPLifecycleManager",
    "MCPServiceView",
    "MCPDiagnosticsView",
]
