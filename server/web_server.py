"""
FastAPI server for My Agent Web Security Scanner v1.1.

v1.1 adds observable scan lifecycle events while preserving v1.0 evidence.
"""

from __future__ import annotations

import json
import os
import sys
import asyncio
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from agent import Agent, AgentConfig

load_dotenv(PROJECT_ROOT / ".env")

APP_VERSION = "1.1.0"

app = FastAPI(title="Web Security Scanner", version=APP_VERSION)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_methods=["*"],
    allow_headers=["*"],
)

agent_config = AgentConfig()
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
        "JWT 攻击", "授权攻击", "OOB 外带确认", "高级利用", "自进化技能",
    ]
    result = []
    for cat in category_order:
        if cat in categories:
            result.append({"category": cat, "tools": sorted(categories.pop(cat), key=lambda t: t["name"])})
    # Any remaining categories
    for cat in sorted(categories):
        result.append({"category": cat, "tools": sorted(categories[cat], key=lambda t: t["name"])})

    return {"version": APP_VERSION, "total": len(BASE_TOOLS), "categories": result}


def _categorize_tool(name: str, desc: str) -> str:
    """Assign a tool to a UI category."""
    lower = (name + " " + desc).lower()
    if any(kw in name for kw in ("http_get", "http_post", "http_request")):
        return "HTTP 基础"
    if any(kw in name for kw in ("crawl", "sitemap", "batch_scan", "extract_forms", "extract_links",
                                  "analyze_js", "discover_api", "render_page", "analyze_headers")):
        return "攻击面测绘"
    if any(kw in name for kw in ("verify_injection", "test_lfi_param", "test_command_injection",
                                  "test_ssti", "decode_jwt")):
        return "注入验证"
    if any(kw in name for kw in ("test_ssrf", "probe_internal_port")):
        return "SSRF 检测"
    if any(kw in name for kw in ("jwt_alg", "jwt_hmac", "jwt_key")):
        return "JWT 攻击"
    if any(kw in name for kw in ("test_idor", "test_privilege", "test_role_manipulation")):
        return "授权攻击"
    if any(kw in name for kw in ("generate_oob", "check_oob")):
        return "OOB 外带确认"
    if any(kw in name for kw in ("css_exfil", "webhook_reconstruct")):
        return "高级利用"
    if any(kw in name for kw in ("skill_", "scan_reflect")):
        return "自进化技能"
    return "其他"


@app.websocket("/api/chat")
async def chat(ws: WebSocket):
    global active_sessions

    await ws.accept()
    agent = Agent(agent_config)
    scan_task: asyncio.Task | None = None
    send_lock = asyncio.Lock()
    active_sessions += 1
    print(f"[WS] session opened (active: {active_sessions})")

    async def send_json(payload: dict[str, Any]) -> None:
        async with send_lock:
            await ws.send_json(payload)

    async def run_scan(user_input: str) -> None:
        try:
            async for event in agent.run_events(user_input):
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
                agent.clear()
                await send_json({"type": "info", "content": "对话记忆已清空"})
                continue

            user_input = str(msg.get("content", "")).strip()
            if not user_input:
                continue

            if scan_task and not scan_task.done():
                await send_json({"type": "error", "content": "已有扫描正在运行，请先停止当前扫描"})
                continue

            scan_task = asyncio.create_task(run_scan(user_input))

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
