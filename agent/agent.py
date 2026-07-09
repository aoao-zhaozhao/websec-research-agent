"""
Agent 核心引擎 — 基于 LangGraph 的 Web 漏洞审查 Agent (v0.5)。

v0.5 变更:
  - 从 core.py 拆分，Module-based 架构
  - 集成 RAG 知识库 (search_knowledge 工具)
  - System Prompt 要求先查知识库再下结论
  - 配置项独立到 config.py

用法:
    from agent import Agent, AgentConfig
    agent = Agent(AgentConfig())
    async for token in agent.run("扫描 http://testphp.vulnweb.com"):
        print(token, end="")
"""

from typing import AsyncIterator

# ── LangChain / LangGraph ─────────────────────────────
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

# ── Agent 子模块 ──────────────────────────────────────
from .config import AgentConfig
from .prompts import SYSTEM_PROMPT
from .tools import BASE_TOOLS
from .rag import create_search_knowledge_tool


class Agent:
    """
    Web 漏洞审查 Agent (v0.5 — RAG 知识库)。

    v0.5 新增:
        - search_knowledge: 语义检索知识库，匹配 CVE/CVSS/修复方案
        - System Prompt 要求先查知识库再下结论
        - 模块化架构: config.py / prompts.py / tools/ / rag.py

    v0.4 能力:
        - crawl: BFS 爬虫，自动发现所有同域页面 + 敏感路径探测
        - sitemap: 攻击面分类（登录页/表单页/API/管理后台）
        - batch_scan: 批量安全头检查所有发现页面
        - 两步工作流: 先爬取测绘攻击面 → 再深度扫描漏洞

    用法:
        agent = Agent(AgentConfig())
        async for token in agent.run("扫描 http://testphp.vulnweb.com"):
            print(token, end="")
    """

    def __init__(self, config: AgentConfig | None = None):
        self.config = config or AgentConfig()

        # ── LLM ───────────────────────────────────
        self.llm = ChatOpenAI(
            api_key=self.config.api_key,
            base_url=self.config.base_url,
            model=self.config.model,
            temperature=self.config.temperature,
        )

        # ── RAG 知识库 ───────────────────────────
        self._search_knowledge_tool = None
        self._rag_manager = None
        self._init_rag()

        # ── LangGraph agent ───────────────────────
        tools = BASE_TOOLS + [self._search_knowledge_tool]
        self.agent = create_react_agent(self.llm, tools)
        self.messages = [SystemMessage(content=SYSTEM_PROMPT)]

    def _init_rag(self):
        """初始化 RAG 知识库，失败时降级为无 RAG 模式。"""
        try:
            search_tool, rag_mgr = create_search_knowledge_tool(self.config)
            self._search_knowledge_tool = search_tool
            self._rag_manager = rag_mgr
        except Exception as e:
            print(f"[Agent] ⚠️ RAG 初始化失败 ({e})，降级为无知识库模式")
            self._search_knowledge_tool = None
            self._rag_manager = None

    @property
    def has_rag(self) -> bool:
        """是否成功加载 RAG 知识库。"""
        return self._rag_manager is not None and self._search_knowledge_tool is not None

    def clear(self) -> None:
        """清空对话历史，只保留 system prompt。"""
        self.messages = [SystemMessage(content=SYSTEM_PROMPT)]

    async def run(self, user_input: str) -> AsyncIterator[str]:
        """
        执行扫描，逐 token yield 模型输出。

        LangGraph 的 astream_events(version="v2") 在 on_chat_model_stream
        事件中产出每个 token。工具调用过程由 agent 内部处理，不会
        yield 给调用者（避免了工具参数碎片出现在输出中）。
        """
        self.messages.append(HumanMessage(content=user_input))

        # 动态重建 agent（确保 search_knowledge 工具最新）
        tools = list(BASE_TOOLS)
        if self._search_knowledge_tool:
            tools.append(self._search_knowledge_tool)
        self.agent = create_react_agent(self.llm, tools)

        full_response: list[str] = []

        async for event in self.agent.astream_events(
            {"messages": list(self.messages)},
            version="v2",
        ):
            kind = event["event"]

            if kind == "on_chat_model_stream":
                chunk = event["data"]["chunk"]
                if chunk.content:
                    full_response.append(chunk.content)
                    yield chunk.content

        # 将本轮回复写入历史
        response_text = "".join(full_response).strip()
        if response_text:
            self.messages.append(AIMessage(content=response_text))
        else:
            self.messages.append(AIMessage(content="扫描完成，请查看上方工具调用结果。"))
