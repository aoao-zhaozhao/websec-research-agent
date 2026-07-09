"""
Agent 模块 — Web 漏洞审查引擎 (v0.5)。

v0.5: 模块化拆分
  agent/
    config.py     — 配置 (AgentConfig)
    prompts.py    — System Prompt
    agent.py      — Agent 核心引擎
    rag.py        — RAG 知识库 (Chroma)
    tools/        — 扫描工具集
      http_tools.py     — http_get, http_post
      analysis_tools.py — analyze_headers, extract_forms, extract_links
      crawl_tools.py    — crawl, sitemap, batch_scan
    knowledge/    — 知识库 Markdown 源文件
      owasp_top10.md
      common_cves.md
      remediation.md
"""

from .config import AgentConfig
from .agent import Agent
from .rag import RAGManager, create_search_knowledge_tool

__all__ = ["Agent", "AgentConfig", "RAGManager", "create_search_knowledge_tool"]
