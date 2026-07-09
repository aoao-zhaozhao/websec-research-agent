"""
测试客户端 —— 多轮对话模式。

v0.2 改动:
    - 支持连续输入多轮对话，不再是发一条就退出
    - 输入 "exit" 或 "quit" 退出
    - 输入 "/clear" 清空 Agent 记忆
"""

import asyncio
import json

import websockets


async def main():
    uri = "ws://127.0.0.1:9120/api/chat"

    print("🔌 连接到 Agent...")
    async with websockets.connect(uri) as ws:
        print("✅ 已连接（输入 'exit' 退出，输入 '/clear' 清空记忆）\n")

        while True:
            # ── 用户输入 ──
            try:
                user_input = input("👤 你: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n👋 退出")
                break

            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit"):
                print("👋 退出")
                break

            # ── /clear 指令 ──
            if user_input == "/clear":
                await ws.send(json.dumps({"command": "clear"}))
                raw = await ws.recv()
                msg = json.loads(raw)
                print(f"🧹 {msg.get('content', '记忆已清空')}\n")
                continue

            # ── 发送消息 ──
            await ws.send(json.dumps({"content": user_input}))

            # ── 流式接收回复 ──
            print("🤖 Agent: ", end="", flush=True)
            while True:
                raw = await ws.recv()
                msg = json.loads(raw)
                if msg["type"] == "token":
                    print(msg["content"], end="", flush=True)
                elif msg["type"] == "done":
                    print("\n")
                    break


if __name__ == "__main__":
    asyncio.run(main())
