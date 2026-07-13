"""
Agent 配置模块 —— 集中管理所有可配置项。

来源优先级: 代码默认值 → .env 环境变量 → API 运行时覆盖
"""

import os
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_optional_float(name: str) -> float | None:
    value = os.getenv(name)
    if value is None or not value.strip():
        return None
    return float(value)


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
        default_factory=lambda: os.getenv("DEEPSEEK_MODEL", "deepseek-v4-flash")
    )

    # ── Agent 行为 ──
    max_turns: int = field(default_factory=lambda: int(os.getenv("AGENT_MAX_TURNS", "120")))
    history_message_limit: int = field(default_factory=lambda: int(os.getenv("AGENT_HISTORY_MESSAGES", "24")))
    temperature: float = 0.3      # LLM 温度（安全分析需精确）
    thinking_enabled: bool = field(default_factory=lambda: _env_bool("DEEPSEEK_THINKING_ENABLED", True))
    reasoning_effort: str = field(default_factory=lambda: os.getenv("DEEPSEEK_REASONING_EFFORT", "high"))
    show_reasoning: bool = field(default_factory=lambda: _env_bool("DEEPSEEK_SHOW_REASONING", True))

    # Skill evolution runtime
    skill_nudge_interval: int = field(
        default_factory=lambda: int(os.getenv("SKILL_NUDGE_INTERVAL", "10"))
    )
    skill_stale_after_days: int = field(
        default_factory=lambda: int(os.getenv("SKILL_STALE_AFTER_DAYS", "30"))
    )
    skill_archive_after_days: int = field(
        default_factory=lambda: int(os.getenv("SKILL_ARCHIVE_AFTER_DAYS", "90"))
    )
    skills_dir: str = field(
        default_factory=lambda: os.getenv(
            "AGENT_SKILLS_DIR", os.path.join(os.path.dirname(__file__), "skills")
        )
    )
    evolution_db_path: str = field(
        default_factory=lambda: os.getenv(
            "EVOLUTION_DB_PATH",
            os.path.join(os.path.dirname(__file__), "..", "data", "evolution.db"),
        )
    )

    # Runtime telemetry (v1.7)
    telemetry_db_path: str = field(
        default_factory=lambda: os.getenv(
            "TELEMETRY_DB_PATH",
            os.path.join(os.path.dirname(__file__), "..", "data", "telemetry.db"),
        )
    )
    input_cost_per_million_tokens: float | None = field(
        default_factory=lambda: _env_optional_float("MODEL_INPUT_COST_PER_MILLION")
    )
    output_cost_per_million_tokens: float | None = field(
        default_factory=lambda: _env_optional_float("MODEL_OUTPUT_COST_PER_MILLION")
    )

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
