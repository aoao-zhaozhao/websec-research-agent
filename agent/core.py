"""
Agent 核心模块 —— 与 DeepSeek 交互的推理循环。

不依赖 FastAPI，可以脱离 Web 服务器独立运行。
"""

import json
import os
from dataclasses import dataclass, field
from typing import Any, AsyncIterator

from openai import AsyncOpenAI


@dataclass
class AgentConfig:
    """Agent 配置"""

    api_key: str = field(default_factory=lambda: os.getenv("DEEPSEEK_API_KEY", ""))
    base_url: str = field(
        default_factory=lambda: os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    )
    model: str = field(default_factory=lambda: os.getenv("DEEPSEEK_MODEL", "deepseek-chat"))
    system_prompt: str = "你是一个有用的AI助手，请用中文回答用户的问题。"
    max_turns: int = 20  # 最大推理轮数（防止无限循环）


# ─── 工具定义（后面可扩展为插件体系） ──────────────────────────

TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "get_current_time",
            "description": "获取当前日期和时间",
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "calculate",
            "description": "执行数学计算，支持 + - * / 及括号",
            "parameters": {
                "type": "object",
                "properties": {
                    "expression": {"type": "string", "description": "数学表达式，如 '(3+5)*2'"}
                },
                "required": ["expression"],
            },
        },
    },
]


def _execute_tool(name: str, args: dict) -> str:
    """执行工具调用，返回结果字符串"""
    if name == "get_current_time":
        from datetime import datetime

        return f"当前时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    elif name == "calculate":
        expr = args.get("expression", "")
        try:
            # 安全的 eval，仅限数学表达式
            result = eval(expr, {"__builtins__": {}}, {})
            return f"{expr} = {result}"
        except Exception as e:
            return f"计算错误: {e}"
    else:
        return f"未知工具: {name}"


class Agent:
    """
    AI Agent 核心。

    用法（独立运行，不用 FastAPI）:
        agent = Agent(AgentConfig())
        async for token in agent.run("帮我算一下 123 * 456"):
            print(token, end="", flush=True)
    """

    def __init__(self, config: AgentConfig | None = None):
        self.config = config or AgentConfig()
        self.client = AsyncOpenAI(
            api_key=self.config.api_key,
            base_url=self.config.base_url,
        )
        self.messages: list[dict] = []

    def _reset(self, user_input: str) -> None:
        """每轮对话重置消息列表"""
        self.messages = [
            {"role": "system", "content": self.config.system_prompt},
            {"role": "user", "content": user_input},
        ]

    async def run(self, user_input: str) -> AsyncIterator[str]:
        """
        执行 Agent 推理循环，逐 token yield 最终回复。

        内部有 tool-call 循环：模型调工具 → 执行 → 把结果喂回去 → 继续
        但只有最终的文本回复才对调用者 yield。
        """
        self._reset(user_input)

        for _ in range(self.config.max_turns):
            stream = await self.client.chat.completions.create(
                model=self.config.model,
                messages=self.messages,
                tools=TOOLS,
                stream=True,
                temperature=0.7,
            )

            # ── 收集本轮 delta ─────────────────────────
            content_parts: list[str] = []
            tool_calls_map: dict[int, dict] = {}  # idx → {id, name, args_str}

            async for chunk in stream:
                delta = chunk.choices[0].delta

                # 文本 token
                if delta.content:
                    content_parts.append(delta.content)
                    yield delta.content

                # 工具调用 token
                if delta.tool_calls:
                    for tc in delta.tool_calls:
                        idx = tc.index
                        if idx not in tool_calls_map:
                            tool_calls_map[idx] = {
                                "id": tc.id or "",
                                "name": "",
                                "args_str": "",
                            }
                        entry = tool_calls_map[idx]
                        if tc.id:
                            entry["id"] = tc.id
                        if tc.function:
                            if tc.function.name:
                                entry["name"] += tc.function.name
                            if tc.function.arguments:
                                entry["args_str"] += tc.function.arguments

            # ── 如果纯文本回复，结束 ──────────────────
            if not tool_calls_map:
                return  # 已经 yield 完了

            # ── 否则执行工具，把结果加入历史继续循环 ──
            # 先把 assistant 消息写入 history
            assistant_msg: dict = {
                "role": "assistant",
                "content": "".join(content_parts) or None,
                "tool_calls": [],
            }
            for idx in sorted(tool_calls_map.keys()):
                tc = tool_calls_map[idx]
                assistant_msg["tool_calls"].append(
                    {
                        "id": tc["id"],
                        "type": "function",
                        "function": {
                            "name": tc["name"],
                            "arguments": tc["args_str"],
                        },
                    }
                )
            self.messages.append(assistant_msg)

            # 执行每个工具，并写入 tool result
            for idx in sorted(tool_calls_map.keys()):
                tc = tool_calls_map[idx]
                result = _execute_tool(tc["name"], json.loads(tc["args_str"]))
                self.messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "content": result,
                    }
                )

            # 循环回到顶部，让模型看到工具结果后决定下一步

        yield "\n[已达到最大推理轮数]"
