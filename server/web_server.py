"""
FastAPI 服务器 —— Web 漏洞审查 Agent (v0.3)。

v0.3: 底层切换到 LangGraph，FastAPI 层保持不变。
  - WS 连接内复用同一個 Agent 实例
  - 流式输出通过 LangGraph astream_events 逐 token 推送
  - REST: /api/config /api/sessions /api/health

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

app = FastAPI(title="Web Security Scanner", version="0.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── 全局状态 ────────────────────────────────────────

agent_config = AgentConfig()
active_sessions: int = 0


# ─── REST: 配置读写 ────────────────────────────────────

@app.get("/api/config")
async def get_config():
    return {
        "model": agent_config.model,
        "base_url": agent_config.base_url,
        "has_api_key": bool(agent_config.api_key),
    }


@app.put("/api/config")
async def update_config(data: dict):
    allowed = ["model", "base_url", "api_key", "max_turns"]
    for k in allowed:
        if k in data:
            setattr(agent_config, k, data[k])
    return {"status": "ok"}


@app.get("/api/sessions")
async def get_sessions():
    return {"active_sessions": active_sessions}


# ─── WebSocket: 核心对话 ──────────────────────────────

@app.websocket("/api/chat")
async def chat(ws: WebSocket):
    global active_sessions

    await ws.accept()

    # Agent 实例绑定到 WS 连接生命周期
    agent = Agent(agent_config)
    active_sessions += 1
    print(f"[WS] 新扫描会话建立 (活跃: {active_sessions})")

    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                msg = {"content": raw}

            # /clear 指令
            if msg.get("command") == "clear":
                agent.clear()
                await ws.send_json({"type": "info", "content": "对话记忆已清空"})
                continue

            user_input = msg.get("content", "")
            if not user_input.strip():
                continue

            # 通过 LangGraph agent 流式扫描
            async for token in agent.run(user_input):
                await ws.send_json({"type": "token", "content": token})

            await ws.send_json({"type": "done"})

    except WebSocketDisconnect:
        print(f"[WS] 客户端断开连接 (活跃: {active_sessions - 1})")
    finally:
        active_sessions -= 1


# ─── 健康检查 ─────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "model": agent_config.model,
        "engine": "LangGraph",
        "active_sessions": active_sessions,
    }


# ─── 启动入口 ─────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "9120"))

    print(f"🔍 Web 漏洞审查 Agent v0.3 (LangGraph): http://{host}:{port}")
    print(f"   WebSocket: ws://{host}:{port}/api/chat")
    print(f"   配置:      http://{host}:{port}/api/config")
    print(f"   健康检查:   http://{host}:{port}/api/health")
    print()
    print("   输入网站 URL 开始扫描, 例如:")
    print('   {"content": "扫描 http://testphp.vulnweb.com 的安全漏洞"}')

    uvicorn.run(app, host=host, port=port, log_level="info")
