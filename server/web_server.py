"""
FastAPI 服务器 —— 提供 WebSocket 对话和 REST 管理 API。

用法:
    python server/web_server.py

模块分工:
    - /api/chat (WebSocket) → 实时对话，流式输出
    - /api/config (GET/PUT)  → 管理配置
    -  SPA 静态文件          → 前端页面
"""

import json
import os
import sys
from pathlib import Path

# 确保项目根目录在 path 中，方便 import agent 模块
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dotenv import load_dotenv

load_dotenv(PROJECT_ROOT / ".env")

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from agent import Agent, AgentConfig

# ─── FastAPI 应用 ──────────────────────────────────────

app = FastAPI(title="My Agent", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── 全局状态（简单阶段，用内存字典存配置）────────────

agent_config = AgentConfig()


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


# ─── WebSocket: 核心对话 ──────────────────────────────

@app.websocket("/api/chat")
async def chat(ws: WebSocket):
    await ws.accept()

    try:
        while True:
            # 收用户消息
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
                user_input = msg.get("content", "")
            except json.JSONDecodeError:
                user_input = raw

            if not user_input.strip():
                continue

            # 创建 Agent 实例（每次对话独立，不共享 history）
            agent = Agent(agent_config)

            # 流式输出
            async for token in agent.run(user_input):
                await ws.send_json({"type": "token", "content": token})

            # 发送完成信号
            await ws.send_json({"type": "done"})

    except WebSocketDisconnect:
        print("[WS] 客户端断开连接")


# ─── 健康检查 ─────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "model": agent_config.model}


# ─── 启动入口 ─────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "9120"))

    print(f"🚀 Agent 服务启动: http://{host}:{port}")
    print(f"   WebSocket 对话: ws://{host}:{port}/api/chat")
    print(f"   配置接口:       http://{host}:{port}/api/config")
    print(f"   健康检查:       http://{host}:{port}/api/health")

    uvicorn.run(app, host=host, port=port, log_level="info")
