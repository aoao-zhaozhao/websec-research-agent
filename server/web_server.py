"""
FastAPI 服务器 —— Web 漏洞审查 Agent (v0.5)。

v0.5: RAG 知识库
  - 集成 Chroma 向量库 + search_knowledge 工具
  - OWASP Top 10 / CVE 案例 / 修复方案知识库
  - 模块化拆分: config.py / prompts.py / agent.py / tools/ / rag.py

v0.4: 前端页面
  - / 直接返回聊天页面，无需额外终端
  - WS 连接内复用同一个 Agent 实例
  - 流式输出通过 LangGraph astream_events 逐 token 推送

用法:
    python server/web_server.py
    浏览器打开 http://127.0.0.1:9120
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
from fastapi.responses import JSONResponse, HTMLResponse

from agent import Agent, AgentConfig

# ─── FastAPI 应用 ──────────────────────────────────────

app = FastAPI(title="Web Security Scanner", version="0.5.0")

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
            try:
                async for token in agent.run(user_input):
                    await ws.send_json({"type": "token", "content": token})
                await ws.send_json({"type": "done"})
            except Exception as exc:
                import traceback
                tb = traceback.format_exc()
                print(f"[ERROR] Agent 异常:\n{tb}")
                await ws.send_json({"type": "error", "content": f"扫描出错: {str(exc)}"})

    except WebSocketDisconnect:
        print(f"[WS] 客户端断开连接 (活跃: {active_sessions - 1})")
    finally:
        active_sessions -= 1


# ─── 前端页面 ─────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = PROJECT_ROOT / "web" / "index.html"
    return html_path.read_text(encoding="utf-8")


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

    # Windows 兼容: 避免 emoji 导致的 GBK 编码错误
    import io, sys
    if sys.stdout.encoding != 'utf-8':
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

    print(f"[*] Web Security Scanner v0.5: http://{host}:{port}")
    print(f"    Open the above URL in your browser")
    print(f"    API: /api/health | /api/config | /api/sessions")

    uvicorn.run(app, host=host, port=port, log_level="info")
