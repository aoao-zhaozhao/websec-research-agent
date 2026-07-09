"""
测试客户端 —— Web 漏洞扫描交互模式。

用法:
    python test_client.py

支持:
    - 输入 URL 开始扫描
    - /clear 清空会话
    - exit 退出
"""

import asyncio
import json

import websockets


async def main():
    uri = "ws://127.0.0.1:9120/api/chat"

    print("🔍 连接到 Web 漏洞审查 Agent...")
    async with websockets.connect(uri) as ws:
        print("✅ 已连接（输入 URL 开始扫描，/clear 清空记忆，exit 退出）\n")
        print("示例: 扫描 http://testphp.vulnweb.com 的安全漏洞\n")

        while True:
            try:
                user_input = input("🔍 你: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n👋 退出")
                break

            if not user_input:
                continue
            if user_input.lower() in ("exit", "quit"):
                print("👋 退出")
                break

            if user_input == "/clear":
                await ws.send(json.dumps({"command": "clear"}))
                raw = await ws.recv()
                msg = json.loads(raw)
                print(f"🧹 {msg.get('content', '记忆已清空')}\n")
                continue

            await ws.send(json.dumps({"content": user_input}))

            print("🤖 Agent: ", end="", flush=True)
            while True:
                raw = await ws.recv()
                msg = json.loads(raw)
                if msg["type"] == "token":
                    print(msg["content"], end="", flush=True)
                elif msg["type"] == "done":
                    print("\n" + "─" * 60 + "\n")
                    break


if __name__ == "__main__":
    asyncio.run(main())
