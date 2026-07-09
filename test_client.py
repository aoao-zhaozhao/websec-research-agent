# 测试脚本 —— 模拟 WebSocket 客户端对话

import asyncio
import json

import websockets


async def main():
    uri = "ws://127.0.0.1:9120/api/chat"

    print("连接到 Agent...")
    async with websockets.connect(uri) as ws:
        # 发一条消息
        test_msg = "帮我算一下 (123 + 456) * 789，然后告诉我现在的精确时间"
        print(f"\n👤 User: {test_msg}\n")
        print("🤖 Agent: ", end="", flush=True)

        await ws.send(json.dumps({"content": test_msg}))

        # 收回复（流式）
        while True:
            raw = await ws.recv()
            msg = json.loads(raw)
            if msg["type"] == "token":
                print(msg["content"], end="", flush=True)
            elif msg["type"] == "done":
                print("\n\n✅ 对话完成")
                break

    print("测试结束。")


if __name__ == "__main__":
    asyncio.run(main())
