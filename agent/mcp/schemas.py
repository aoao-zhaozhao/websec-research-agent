"""MCP 诊断视图模型 —— 供 Web API 和 CLI 共同使用。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MCPServiceView:
    """单个 MCP 服务的诊断视图"""

    name: str
    enabled: bool
    priority: int
    transport_type: str
    execution_mode: str
    health_status: str
    attach_attempted: bool = False
    attach_succeeded: bool = False
    running: bool = False
    can_execute: bool = False
    tool_count: int = 0
    tools: list[str] = field(default_factory=list)
    error: str | None = None
    last_error_type: str | None = None
    started_at: str | None = None
    description: str = ""
    call_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    recent_success_rate: float | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "priority": self.priority,
            "transport_type": self.transport_type,
            "execution_mode": self.execution_mode,
            "health_status": self.health_status,
            "attach_attempted": self.attach_attempted,
            "attach_succeeded": self.attach_succeeded,
            "running": self.running,
            "can_execute": self.can_execute,
            "tool_count": self.tool_count,
            "tools": self.tools,
            "error": self.error,
            "last_error_type": self.last_error_type,
            "started_at": self.started_at,
            "description": self.description,
            "call_count": self.call_count,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "recent_success_rate": (
                round(self.recent_success_rate, 4)
                if self.recent_success_rate is not None
                else None
            ),
        }


@dataclass
class MCPDiagnosticsView:
    """聚合的 MCP 诊断视图"""

    total_services: int = 0
    running_services: int = 0
    local_services: int = 0
    placeholder_services: int = 0
    tool_count: int = 0
    services: list[MCPServiceView] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_services": self.total_services,
            "running_services": self.running_services,
            "local_services": self.local_services,
            "placeholder_services": self.placeholder_services,
            "tool_count": self.tool_count,
            "services": [svc.to_dict() for svc in self.services],
        }
