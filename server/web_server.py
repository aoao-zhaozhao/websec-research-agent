"""FastAPI server for WebSec Research Agent v1.7.4."""

from __future__ import annotations

import json
import os
import sys
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from agent import Agent, AgentConfig
from agent.telemetry import TelemetryStore

load_dotenv(PROJECT_ROOT / ".env")

APP_VERSION = "1.7.5"

@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Start durable workers for evolution, MCP lifecycle, and review jobs."""
    from agent.evolution import get_evolution_worker
    from agent.mcp.lifecycle import MCPLifecycleManager

    worker = get_evolution_worker()

    async def worker_loop() -> None:
        while True:
            await asyncio.to_thread(worker.run_until_idle)
            await asyncio.sleep(max(0.25, worker.config.worker_poll_seconds))

    await asyncio.to_thread(worker.run_until_idle)
    worker_task = asyncio.create_task(worker_loop())

    # v1.8: 初始化 MCP 生命周期管理器
    mcp_manager = MCPLifecycleManager(agent_config.mcp.servers)
    mcp_manager.start_enabled_servers()
    _app.state.mcp_manager = mcp_manager

    try:
        yield
    finally:
        worker_task.cancel()
        try:
            await worker_task
        except asyncio.CancelledError:
            pass
        await mcp_manager.astop_all()


app = FastAPI(title="Web Security Scanner", version=APP_VERSION, lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_methods=["*"],
    allow_headers=["*"],
)

agent_config = AgentConfig()
telemetry_store = TelemetryStore(Path(agent_config.telemetry_db_path))
active_sessions: int = 0


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value, ensure_ascii=False)
        return value
    except TypeError:
        return str(value)


def _config_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    raise HTTPException(status_code=422, detail=f"{field_name} must be a boolean")


@app.get("/api/config")
async def get_config():
    return {
        "model": agent_config.model,
        "base_url": agent_config.base_url,
        "max_turns": agent_config.max_turns,
        "history_message_limit": agent_config.history_message_limit,
        "thinking_enabled": agent_config.thinking_enabled,
        "reasoning_effort": agent_config.reasoning_effort,
        "show_reasoning": agent_config.show_reasoning,
        "has_api_key": bool(agent_config.api_key),
        "version": APP_VERSION,
    }


@app.put("/api/config")
async def update_config(data: dict):
    if "model" in data:
        model = str(data["model"]).strip()
        if model not in {"deepseek-v4-flash", "deepseek-v4-pro"}:
            raise HTTPException(status_code=422, detail="model must be deepseek-v4-flash or deepseek-v4-pro")
        agent_config.model = model
    if "base_url" in data:
        agent_config.base_url = str(data["base_url"]).strip()
    if "api_key" in data:
        agent_config.api_key = str(data["api_key"])
    if "thinking_enabled" in data:
        agent_config.thinking_enabled = _config_bool(data["thinking_enabled"], "thinking_enabled")
    if "show_reasoning" in data:
        agent_config.show_reasoning = _config_bool(data["show_reasoning"], "show_reasoning")
    if "reasoning_effort" in data:
        effort = str(data["reasoning_effort"]).lower()
        if effort not in {"high", "max"}:
            raise HTTPException(status_code=422, detail="reasoning_effort must be high or max")
        agent_config.reasoning_effort = effort
    for key, minimum, maximum in (("max_turns", 10, 240), ("history_message_limit", 2, 100)):
        if key in data:
            try:
                value = int(data[key])
            except (TypeError, ValueError) as exc:
                raise HTTPException(status_code=422, detail=f"{key} must be an integer") from exc
            if not minimum <= value <= maximum:
                raise HTTPException(status_code=422, detail=f"{key} must be between {minimum} and {maximum}")
            setattr(agent_config, key, value)
    return {"status": "ok", "model": agent_config.model, "thinking_enabled": agent_config.thinking_enabled}


@app.get("/api/sessions")
async def get_sessions():
    return {"active_sessions": active_sessions}


@app.get("/api/conversations")
async def list_conversations():
    return {"conversations": telemetry_store.list_conversations()}


@app.post("/api/conversations")
async def create_conversation(data: dict | None = None):
    title = str((data or {}).get("title", "新扫描"))
    return telemetry_store.create_conversation(title=title)


@app.post("/api/conversations/import")
async def import_conversations(data: dict):
    sessions = data.get("sessions", [])
    if not isinstance(sessions, list):
        raise HTTPException(status_code=422, detail="sessions must be a list")
    return {"imported": telemetry_store.import_conversations(sessions)}


@app.get("/api/conversations/{conversation_id}")
async def get_conversation(conversation_id: str):
    conversation = telemetry_store.get_conversation(conversation_id)
    if conversation is None:
        raise HTTPException(status_code=404, detail="conversation not found")
    return conversation


@app.put("/api/conversations/{conversation_id}")
async def rename_conversation(conversation_id: str, data: dict):
    title = str(data.get("title", "")).strip()
    if not title:
        raise HTTPException(status_code=422, detail="title must not be empty")
    conversation = telemetry_store.rename_conversation(conversation_id, title)
    if conversation is None:
        raise HTTPException(status_code=404, detail="conversation not found")
    return conversation


@app.delete("/api/conversations")
async def delete_all_conversations():
    return {
        "status": "ok",
        "deleted": telemetry_store.delete_all_conversations(),
        "run_retention": "anonymized",
    }


@app.delete("/api/conversations/{conversation_id}")
async def delete_conversation(conversation_id: str):
    if not telemetry_store.delete_conversation(conversation_id):
        raise HTTPException(status_code=404, detail="conversation not found")
    return {"status": "ok", "run_retention": "anonymized"}


@app.get("/api/metrics")
async def get_metrics(category: str | None = None, mode: str | None = None):
    """Return durable v1.7 runtime metrics for production and benchmark runs."""
    return telemetry_store.metrics(category=category, mode=mode)


@app.get("/api/usage-stats")
async def get_usage_stats(range: str = "all"):
    """Return model-usage aggregates for the frontend Stats view."""
    try:
        return telemetry_store.usage_stats(date_range=range)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/runs")
async def get_runs(limit: int = 50):
    return {"runs": telemetry_store.list_runs(limit=limit)}


@app.get("/api/runs/{run_id}")
async def get_run(run_id: str):
    run = telemetry_store.get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    return run


@app.post("/api/runs/{run_id}/evaluation")
async def record_evaluation(run_id: str, data: dict):
    if telemetry_store.get_run(run_id) is None:
        raise HTTPException(status_code=404, detail="run not found")
    try:
        evaluation = telemetry_store.record_evaluation(
            run_id,
            judge=str(data.get("judge", "manual")),
            outcome=str(data.get("outcome", "inconclusive")),
            verified=bool(data.get("verified", False)),
            candidate_fingerprint=str(data.get("candidate_fingerprint", "")),
            reason=str(data.get("reason", "")),
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"status": "ok", "evaluation": evaluation}


@app.get("/api/tools")
async def get_tools():
    """Return all registered tools grouped by category for the frontend inventory."""
    from agent.tools import BASE_TOOLS

    categories: dict[str, list[dict]] = {}
    for t in BASE_TOOLS:
        name = t.name
        desc = (t.description or "").strip()
        # Parse the first paragraph as the short description
        short_desc = desc.split("\n")[0].split("。")[0].split(".")[0][:160]

        # Extract parameters from the tool's schema
        params: list[dict] = []
        if t.args_schema:
            schema = t.args_schema.model_json_schema()
            props = schema.get("properties", {})
            required = schema.get("required", [])
            for pname, pinfo in props.items():
                params.append({
                    "name": pname,
                    "type": pinfo.get("type", "string"),
                    "required": pname in required,
                    "description": (pinfo.get("description", "") or "")[:200],
                })

        # Categorize tools
        category = _categorize_tool(name, desc)
        categories.setdefault(category, []).append({
            "name": name,
            "description": short_desc,
            "params": params,
        })

    # Sort categories and tools within each category
    category_order = [
        "HTTP 基础", "攻击面测绘", "注入验证", "SSRF 检测",
        "JWT 攻击", "授权攻击", "OOB 外带确认", "高级利用",
        "自进化技能", "流量取证", "MCP 外部工具",
    ]
    result = []
    for cat in category_order:
        if cat in categories:
            result.append({"category": cat, "tools": sorted(categories.pop(cat), key=lambda t: t["name"])})
    # Any remaining categories
    for cat in sorted(categories):
        result.append({"category": cat, "tools": sorted(categories[cat], key=lambda t: t["name"])})

    return {"version": APP_VERSION, "total": len(BASE_TOOLS), "categories": result}


@app.get("/api/skills")
async def get_skills():
    """Return learned skills for the workspace inventory."""
    from agent.skill_manager import get_skill_manager

    skills = get_skill_manager().list_all()
    return {"total": len(skills), "skills": skills}


def _categorize_tool(name: str, desc: str) -> str:
    """Assign a tool to a UI category."""
    lower = (name + " " + desc).lower()
    if any(kw in name for kw in ("http_get", "http_post", "http_request", "search_http_body", "auth_login")):
        return "HTTP 基础"
    if any(kw in name for kw in ("crawl", "sitemap", "batch_scan", "extract_forms", "extract_links",
                                   "analyze_js", "discover_api", "render_page", "search_rendered_dom", "analyze_headers")):
        return "攻击面测绘"
    if any(kw in name for kw in ("verify_injection", "test_lfi_param", "test_command_injection",
                                  "test_ssti", "decode_jwt")):
        return "注入验证"
    if any(kw in name for kw in ("test_ssrf", "probe_internal_port")):
        return "SSRF 检测"
    if any(kw in name for kw in ("jwt_alg", "jwt_hmac", "jwt_key", "session_jwt", "session_response_search")):
        return "JWT 攻击"
    if any(kw in name for kw in ("test_idor", "test_privilege", "test_role_manipulation")):
        return "授权攻击"
    if any(kw in name for kw in ("generate_oob", "check_oob")):
        return "OOB 外带确认"
    if any(kw in name for kw in ("css_exfil", "webhook_reconstruct")):
        return "高级利用"
    if any(kw in name for kw in ("skill_", "case_create", "scan_reflect")):
        return "自进化技能"
    if any(kw in name for kw in ("traffic_list", "traffic_view", "traffic_repeat", "traffic_sitemap")):
        return "流量取证"
    return "其他"


# ═══════════════════════════════════════════════════════════════
# MCP 诊断 API (v1.8)
# ═══════════════════════════════════════════════════════════════

def _get_mcp_diagnostics() -> dict:
    """获取 MCP 诊断信息的内部函数，供各端点复用。"""
    from agent.mcp.schemas import MCPDiagnosticsView, MCPServiceView

    services: list[MCPServiceView] = []
    local_count = 0
    placeholder_count = 0
    running_count = 0
    total_tool_count = 0

    for name, server_config in agent_config.mcp.servers.items():
        transport = server_config.transport
        transport_type = transport.type or "unknown"
        can_execute = transport_type in ("local", "sdk", "subprocess", "sse")

        # 对齐计划: 本地服务算 running
        is_running = transport_type == "local" or transport_type == "sdk"

        if transport_type == "local":
            local_count += 1
        elif transport_type == "placeholder":
            placeholder_count += 1

        if is_running:
            running_count += 1

        tools: list[str] = []
        if name == "fetch":
            tools = ["fetch"]
        elif name == "memory":
            tools = ["save", "retrieve"]
        elif name == "chrome-devtools":
            tools = [
                "chrome_navigate", "chrome_read_page", "chrome_screenshot",
                "chrome_javascript", "chrome_get_web_content", "chrome_console",
                "chrome_network_request", "chrome_click_element", "chrome_fill_or_select",
                "chrome_pentest_http", "chrome_pentest_js_analyze",
                "chrome_pentest_cookies", "chrome_pentest_headers",
            ]
        elif name == "burp":
            tools = ["send_http1_request", "get_proxy_http_history"]

        tool_count = len(tools)
        total_tool_count += tool_count

        services.append(MCPServiceView(
            name=name,
            enabled=server_config.enabled,
            priority=server_config.priority,
            transport_type=transport_type,
            execution_mode=transport_type if transport_type == "local" else "placeholder",
            health_status="healthy" if server_config.enabled else "unknown",
            attach_attempted=server_config.enabled,
            attach_succeeded=transport_type == "local",
            running=is_running,
            can_execute=can_execute,
            tool_count=tool_count,
            tools=tools,
            error=None,
            description=server_config.description or "",
        ))

    diag = MCPDiagnosticsView(
        total_services=len(services),
        running_services=running_count,
        local_services=local_count,
        placeholder_services=placeholder_count,
        tool_count=total_tool_count,
        services=services,
    )
    return diag.to_dict()


@app.get("/api/mcp/diagnostics")
async def get_mcp_diagnostics():
    """MCP 服务状态诊断。"""
    return _get_mcp_diagnostics()


@app.get("/api/mcp/tools")
async def get_mcp_tools():
    """所有 MCP 工具列表（含服务归属）。"""
    from agent.config import MCPConfig
    tools: list[dict] = []
    for name, server_config in agent_config.mcp.servers.items():
        if not server_config.enabled:
            continue
        # 静态已知工具表
        known = {
            "fetch": [{"name": "fetch", "description": "Fetch a URL and return the content"}],
            "memory": [
                {"name": "save", "description": "Save information to persistent memory"},
                {"name": "retrieve", "description": "Retrieve information from persistent memory"},
            ],
        }
        for tool in known.get(name, []):
            tools.append({**tool, "server": name})
    return {"servers": list(agent_config.mcp.servers.keys()), "tools": tools}


# ═══════════════════════════════════════════════════════════════
# 流量证据 API (v1.8)
# ═══════════════════════════════════════════════════════════════

def _get_traffic_store():
    """获取流量存储实例（如已初始化）。"""
    try:
        from agent.tools.traffic_tools import _get_store
        return _get_store()
    except Exception:
        return None


@app.get("/api/traffic")
async def get_traffic_list(
    method: str = "",
    host: str = "",
    status: int = 0,
    source: str = "",
    limit: int = 50,
):
    """流量列表查询。"""
    store = _get_traffic_store()
    if store is None:
        return {"entries": [], "note": "流量存储未初始化，请先开始扫描。"}

    try:
        entries = store.entries()
    except Exception:
        return {"entries": []}

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

    filtered = filtered[-limit:]
    return {"total": len(entries), "filtered": len(filtered), "entries": filtered}


@app.get("/api/traffic/{request_id}")
async def get_traffic_detail(request_id: str):
    """查看单个流量详情（请求+响应）。"""
    store = _get_traffic_store()
    if store is None:
        raise HTTPException(status_code=503, detail="流量存储未初始化")

    view = store.view(request_id)
    if view is None:
        raise HTTPException(status_code=404, detail=f"未找到: {request_id}")

    return {
        "request_id": request_id,
        "method": view.get("method"),
        "url": view.get("url"),
        "host": view.get("host"),
        "status": view.get("status"),
        "source": view.get("source"),
        "timestamp": view.get("timestamp"),
        "request_text": view.get("request_text", ""),
        "response_text": view.get("response_text", ""),
    }


@app.websocket("/api/chat")
async def chat(ws: WebSocket):
    global active_sessions

    await ws.accept()
    agent: Agent | None = None
    conversation_id: str | None = None
    scan_task: asyncio.Task | None = None
    send_lock = asyncio.Lock()
    active_sessions += 1
    print(f"[WS] session opened (active: {active_sessions})")

    async def send_json(payload: dict[str, Any]) -> None:
        async with send_lock:
            await ws.send_json(payload)

    async def run_scan(user_input: str, mode: str, category: str, scan_conversation_id: str) -> None:
        assert agent is not None
        try:
            async for event in agent.run_events(
                user_input, mode=mode, category=category, conversation_id=scan_conversation_id
            ):
                if event.get("type") in {"tool_started", "tool_finished"}:
                    event["input"] = _json_safe(event.get("input"))
                    event["output"] = _json_safe(event.get("output"))
                    event["result"] = _json_safe(event.get("result"))
                await send_json(event)
            await send_json({"type": "done"})
        except asyncio.CancelledError:
            for event in agent.finish_scan("stopped"):
                await send_json(event)
            await send_json({"type": "stopped", "content": "扫描已停止"})
            raise
        except Exception as exc:
            import traceback

            print(f"[ERROR] Agent exception:\n{traceback.format_exc()}")
            for event in agent.finish_scan("failed"):
                await send_json(event)
            await send_json({"type": "error", "content": f"扫描出错: {exc}"})

    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                msg = {"content": raw}

            if msg.get("command") == "stop":
                if scan_task and not scan_task.done():
                    scan_task.cancel()
                    await send_json({"type": "info", "content": "正在停止当前扫描..."})
                else:
                    await send_json({"type": "info", "content": "当前没有正在运行的扫描"})
                continue

            if msg.get("command") == "clear":
                if scan_task and not scan_task.done():
                    scan_task.cancel()
                if agent is not None:
                    agent.clear()
                await send_json({"type": "info", "content": "对话记忆已清空"})
                continue

            user_input = str(msg.get("content", "")).strip()
            if not user_input:
                continue
            mode = str(msg.get("mode", "production")).strip().lower()
            if mode not in {"production", "benchmark"}:
                await send_json({"type": "error", "content": "mode must be production or benchmark"})
                continue
            category = str(msg.get("category", "web")).strip().lower()[:80] or "web"
            requested_conversation_id = str(msg.get("conversation_id", "")).strip()[:120]
            conversation = telemetry_store.get_conversation(requested_conversation_id)
            if not requested_conversation_id or conversation is None:
                await send_json({"type": "error", "content": "会话不存在，请刷新后重试"})
                continue

            if scan_task and not scan_task.done():
                await send_json({"type": "error", "content": "已有扫描正在运行，请先停止当前扫描"})
                continue

            if conversation_id != requested_conversation_id:
                agent = Agent(agent_config, telemetry=telemetry_store)
                agent.restore_history(conversation["messages"])
                conversation_id = requested_conversation_id
                # v1.8: 注入 MCP 工具链
                _mcp = getattr(app.state, "mcp_manager", None)
                if _mcp is not None:
                    agent.set_mcp_lifecycle(_mcp)
            scan_task = asyncio.create_task(run_scan(user_input, mode, category, requested_conversation_id))

    except WebSocketDisconnect:
        print(f"[WS] session closed (active: {active_sessions - 1})")
    finally:
        if scan_task and not scan_task.done():
            scan_task.cancel()
        active_sessions -= 1


@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = PROJECT_ROOT / "web" / "index.html"
    return html_path.read_text(encoding="utf-8")


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "model": agent_config.model,
        "engine": "LangGraph",
        "version": APP_VERSION,
        "active_sessions": active_sessions,
    }


@app.get("/api/evolution")
async def evolution_status():
    """Expose bounded evolution state for operations and debugging."""
    from agent.evolution import get_evolution_store

    store = get_evolution_store()
    jobs = store.list_jobs()
    return {
        "tool_calls_since_review": store.tool_counter(),
        "pending_directive": store.pending_review(),
        "jobs": jobs[-20:],
        "reviews": store.list_reviews(limit=20),
    }


if __name__ == "__main__":
    import io

    import uvicorn

    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "9120"))

    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

    print(f"[*] Web Security Scanner v{APP_VERSION}: http://{host}:{port}")
    print("    API: /api/health | /api/config | /api/sessions")

    uvicorn.run(app, host=host, port=port, log_level="info")
