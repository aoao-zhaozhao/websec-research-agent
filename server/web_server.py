"""
FastAPI 服务器 —— 提供 WebSocket 对话和 REST 管理 API。

v0.2 改动:
    - WS 连接内复用同一个 Agent 实例 → 多轮对话记忆
    - 新增 /api/chat/clear WebSocket 指令 → 清空记忆
    - 新增 /api/sessions 查看活跃会话数

用法:
    python server/web_server.py
"""

import json
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv

load_dotenv(PROJECT_ROOT / ".env")

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from agent import Agent, AgentConfig

# ─── FastAPI 应用 ──────────────────────────────────────

app = FastAPI(title="My Agent", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── 全局状态 ────────────────────────────────────────

agent_config = AgentConfig()
active_sessions: int = 0  # 当前活跃 WS 连接数


# ─── REST: 配置读写 ────────────────────────────────────

@app.get("/api/config")
async def get_config():
    return {
        "model": agent_config.model,
        "base_url": agent_config.base_url,
        "system_prompt": agent_config.system_prompt,
        "has_api_key": bool(agent_config.api_key),
    }


@app.put("/api/config")
async def update_config(data: dict):
    allowed = ["model", "base_url", "system_prompt", "api_key", "max_turns"]
    for k in allowed:
        if k in data:
            setattr(agent_config, k, data[k])
    return {"status": "ok"}


@app.get("/api/sessions")
async def get_sessions():
    """查看当前活跃的 WebSocket 连接数"""
    return {"active_sessions": active_sessions}


# ─── WebSocket: 核心对话 ──────────────────────────────

@app.websocket("/api/chat")
async def chat(ws: WebSocket):
    global active_sessions

    await ws.accept()

    # ── v0.2: Agent 实例在连接建立时创建一次，整个会话复用 ──
    agent = Agent(agent_config)
    active_sessions += 1
    print(f"[WS] 新会话建立 (活跃: {active_sessions})")

    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                msg = {"content": raw}

            # ── v0.2: 特殊指令 /clear 清空记忆 ──
            if msg.get("command") == "clear":
                agent.clear()
                await ws.send_json({"type": "info", "content": "对话记忆已清空"})
                continue

            user_input = msg.get("content", "")
            if not user_input.strip():
                continue

            # 流式输出（同一个 agent 自动累积历史）
            async for token in agent.run(user_input):
                await ws.send_json({"type": "token", "content": token})

            # 发送本轮结束信号
            await ws.send_json({"type": "done"})

    except WebSocketDisconnect:
        print(f"[WS] 客户端断开连接 (活跃: {active_sessions - 1})")
    finally:
        active_sessions -= 1


# ─── 健康检查 ─────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "model": agent_config.model, "active_sessions": active_sessions}


# ─── 启动入口 ─────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "9120"))

    print(f"🚀 Agent 服务启动 (v0.2): http://{host}:{port}")
    print(f"   WebSocket 对话: ws://{host}:{port}/api/chat")
    print(f"   配置接口:       http://{host}:{port}/api/config")
    print(f"   健康检查:       http://{host}:{port}/api/health")
    print(f"   会话数:         http://{host}:{port}/api/sessions")
    print()
    print("   v0.2 新特性: 多轮对话记忆 / 同一 WS 连接内 Agent 自动记住上文")

    uvicorn.run(app, host=host, port=port, log_level="info")
