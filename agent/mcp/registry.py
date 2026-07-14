"""MCP 服务注册中心 —— 管理服务元数据、工具 schema 和运行时状态。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class HealthStatus(str, Enum):
    """MCP 服务健康状态"""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"
    STARTING = "starting"
    STOPPING = "stopping"
    UNKNOWN = "unknown"


@dataclass
class MCPToolSchema:
    """单个 MCP 工具的 schema"""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(
        default_factory=lambda: {"type": "object", "properties": {}}
    )
    server_name: str = ""


@dataclass
class MCPServerState:
    """MCP 服务运行时状态"""

    name: str
    running: bool = False
    pid: int | None = None
    tools: list[str] = field(default_factory=list)
    error: str | None = None
    last_error_type: str | None = None
    started_at: str | None = None
    execution_mode: str = "placeholder"  # local / sdk / subprocess / sse / placeholder
    health_status: str = "unknown"
    attach_attempted: bool = False
    attach_succeeded: bool = False
    call_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    total_latency_ms: float = 0.0
    avg_latency_ms: float = 0.0
    restart_count: int = 0
    last_restart_time: str | None = None
    recent_outcomes: list[bool] = field(default_factory=list)


class MCPRegistry:
    """MCP 服务与工具中央注册表。

    维护:
    - 服务配置与元数据
    - 每个服务的工具 schema
    - 运行时状态（运行/停止、健康评分）
    """

    HEALTH_WINDOW_SIZE = 20

    def __init__(self) -> None:
        self._servers: dict[str, MCPServerState] = {}
        self._tools: dict[str, MCPToolSchema] = {}        # tool_name → schema
        self._server_tools: dict[str, list[str]] = {}     # server_name → [tool_names]

    # ── 服务管理 ──────────────────────────────────────────────

    def register_server(self, name: str) -> None:
        """注册一个新的 MCP 服务"""
        if name not in self._servers:
            self._servers[name] = MCPServerState(name=name)
            self._server_tools[name] = []

    def unregister_server(self, name: str) -> None:
        """移除一个服务及其所有工具"""
        if name in self._server_tools:
            for tool_name in self._server_tools[name]:
                self._tools.pop(tool_name, None)
            del self._server_tools[name]
        self._servers.pop(name, None)

    def set_server_running(self, name: str, running: bool, pid: int | None = None) -> None:
        """更新服务运行状态"""
        if name not in self._servers:
            return
        self._servers[name].running = running
        self._servers[name].pid = pid
        if running:
            from datetime import datetime
            self._servers[name].started_at = datetime.now().isoformat()

    def set_server_execution_mode(self, name: str, mode: str) -> None:
        """更新服务执行模式"""
        if name in self._servers:
            self._servers[name].execution_mode = mode

    def set_server_health(self, name: str, health_status: str) -> None:
        """更新服务健康状态"""
        if name in self._servers:
            self._servers[name].health_status = health_status

    def set_server_attach_result(self, name: str, attempted: bool, succeeded: bool) -> None:
        """记录 attach/连接 尝试的结果"""
        if name in self._servers:
            self._servers[name].attach_attempted = attempted
            self._servers[name].attach_succeeded = succeeded

    def set_server_error(self, name: str, error: str, error_type: str | None = None) -> None:
        """记录服务错误"""
        if name in self._servers:
            self._servers[name].error = error
            self._servers[name].last_error_type = error_type
            self._servers[name].health_status = "degraded"

    def record_restart(self, name: str) -> None:
        """记录服务重启"""
        if name not in self._servers:
            return
        from datetime import datetime
        self._servers[name].restart_count += 1
        self._servers[name].last_restart_time = datetime.now().isoformat()

    # ── 工具管理 ──────────────────────────────────────────────

    def register_tool(self, server_name: str, tool_schema: dict[str, Any]) -> None:
        """注册一个来自 MCP 服务的工具"""
        tool_name = tool_schema.get("name", "")
        if not tool_name:
            return

        schema = MCPToolSchema(
            name=tool_name,
            description=tool_schema.get("description", ""),
            input_schema=tool_schema.get("inputSchema", {"type": "object", "properties": {}}),
            server_name=server_name,
        )

        self._tools[tool_name] = schema
        if server_name not in self._server_tools:
            self._server_tools[server_name] = []
        if tool_name not in self._server_tools[server_name]:
            self._server_tools[server_name].append(tool_name)

        if server_name in self._servers:
            self._servers[server_name].tools = self._server_tools[server_name]

    def clear_server_tools(self, server_name: str) -> None:
        """清除某个服务当前注册的全部工具"""
        if server_name not in self._server_tools:
            self._server_tools[server_name] = []
            return
        for tool_name in list(self._server_tools[server_name]):
            self._tools.pop(tool_name, None)
        self._server_tools[server_name] = []
        if server_name in self._servers:
            self._servers[server_name].tools = []

    def get_tool_schema(self, tool_name: str) -> MCPToolSchema | None:
        """获取指定工具的 schema"""
        return self._tools.get(tool_name)

    def get_all_tool_schemas(self) -> list[dict[str, Any]]:
        """获取所有工具 schema（OpenAI function-calling 格式）"""
        return [
            {
                "name": schema.name,
                "description": schema.description,
                "inputSchema": schema.input_schema,
            }
            for schema in self._tools.values()
        ]

    def get_server_for_tool(self, tool_name: str) -> str | None:
        """查找工具所属的服务"""
        schema = self._tools.get(tool_name)
        return schema.server_name if schema else None

    def get_server_tools(self, server_name: str) -> list[str]:
        """获取某个服务的所有工具名"""
        return self._server_tools.get(server_name, [])

    # ── 查询 ──────────────────────────────────────────────────

    def get_running_servers(self) -> list[str]:
        """获取正在运行的服务名称列表"""
        return [name for name, state in self._servers.items() if state.running]

    def get_all_servers(self) -> dict[str, MCPServerState]:
        """获取所有服务状态"""
        return self._servers.copy()

    @property
    def tool_count(self) -> int:
        return len(self._tools)

    @property
    def server_count(self) -> int:
        return len(self._servers)

    # ── 统计 ──────────────────────────────────────────────────

    def record_tool_call(
        self, name: str, success: bool, latency_ms: float | None = None
    ) -> None:
        """记录单次工具调用统计，更新健康评分滑动窗口"""
        if name not in self._servers:
            return
        state = self._servers[name]
        state.call_count += 1
        if success:
            state.success_count += 1
            if state.health_status == "unknown":
                state.health_status = "healthy"
        else:
            state.failure_count += 1
            if state.health_status == "unknown":
                state.health_status = "degraded"

        if latency_ms is not None and latency_ms >= 0:
            state.total_latency_ms += latency_ms
        if state.call_count > 0:
            state.avg_latency_ms = state.total_latency_ms / state.call_count

        state.recent_outcomes.append(bool(success))
        if len(state.recent_outcomes) > self.HEALTH_WINDOW_SIZE:
            state.recent_outcomes = state.recent_outcomes[-self.HEALTH_WINDOW_SIZE:]

    def set_last_call_latency(self, name: str, latency_ms: float) -> None:
        """将延迟归属到最近一次调用并刷新平均值"""
        state = self._servers.get(name)
        if state is None or latency_ms < 0:
            return
        state.total_latency_ms += latency_ms
        if state.call_count > 0:
            state.avg_latency_ms = state.total_latency_ms / state.call_count

    def recent_success_rate(self, name: str) -> float | None:
        """最近 20 次调用的成功率；无调用记录返回 None"""
        state = self._servers.get(name)
        if state is None or not state.recent_outcomes:
            return None
        return sum(1 for ok in state.recent_outcomes if ok) / len(state.recent_outcomes)

    def get_server_stats(self, name: str) -> dict[str, Any]:
        """获取某个服务的运行时统计快照"""
        state = self._servers.get(name)
        if state is None:
            return {}

        uptime_seconds: float | None = None
        if state.running and state.started_at:
            from datetime import datetime
            try:
                started = datetime.fromisoformat(state.started_at)
                uptime_seconds = max(0.0, (datetime.now() - started).total_seconds())
            except ValueError:
                uptime_seconds = None

        return {
            "name": state.name,
            "running": state.running,
            "health_status": state.health_status,
            "execution_mode": state.execution_mode,
            "call_count": state.call_count,
            "success_count": state.success_count,
            "failure_count": state.failure_count,
            "avg_latency_ms": round(state.avg_latency_ms, 2),
            "recent_success_rate": self.recent_success_rate(name),
            "restart_count": state.restart_count,
            "last_restart_time": state.last_restart_time,
            "started_at": state.started_at,
            "uptime_seconds": uptime_seconds,
            "error": state.error,
            "last_error_type": state.last_error_type,
        }
