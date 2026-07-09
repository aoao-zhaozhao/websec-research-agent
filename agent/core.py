"""
Agent 核心模块 — 向后兼容重导出 (v0.5)。

v0.5: 模块已拆分到 agent/ 子模块中。
      本文件保留以兼容旧引用，实际逻辑请见:
        config.py  prompts.py  agent.py  rag.py  tools/
"""

# 向后兼容: 从新模块重导出所有符号
from .config import AgentConfig
from .agent import Agent
from .prompts import SYSTEM_PROMPT
from .tools import BASE_TOOLS

# 保持旧的 TOOLS 变量名兼容
TOOLS = list(BASE_TOOLS)

__all__ = ["Agent", "AgentConfig", "SYSTEM_PROMPT", "TOOLS", "BASE_TOOLS"]
