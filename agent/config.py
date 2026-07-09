"""
Agent 配置模块 —— 集中管理所有可配置项。

来源优先级: 代码默认值 → .env 环境变量 → API 运行时覆盖
"""

import os
from dataclasses import dataclass, field


@dataclass
class AgentConfig:
    """Web 漏洞审查 Agent 配置"""

    # ── LLM 连接 ──
    api_key: str = field(
        default_factory=lambda: os.getenv("DEEPSEEK_API_KEY", "")
    )
    base_url: str = field(
        default_factory=lambda: os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    )
    model: str = field(
        default_factory=lambda: os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
    )

    # ── Agent 行为 ──
    max_turns: int = 25           # 单次扫描最大推理轮数
    temperature: float = 0.3      # LLM 温度（安全分析需精确）

    # ── RAG 知识库 ──
    knowledge_dir: str = field(
        default_factory=lambda: os.path.join(os.path.dirname(__file__), "knowledge")
    )
    chroma_persist_dir: str = field(
        default_factory=lambda: os.path.join(os.path.dirname(__file__), "chroma_db")
    )

    # ── RAG 模型 (项目内 models/ 目录) ──
    embedding_model_dir: str = field(
        default_factory=lambda: os.path.join(
            os.path.dirname(__file__), "models", "qwen3-embedding-0.6b"
        )
    )
    reranker_model_dir: str = field(
        default_factory=lambda: os.path.join(
            os.path.dirname(__file__), "models", "qwen3-reranker-0.6b"
        )
    )

    # ── RAG 检索参数 ──
    rag_top_k: int = 4                # 最终返回条数
    rag_candidate_multiplier: int = 3 # 初检 top_k × N → reranker 精排
