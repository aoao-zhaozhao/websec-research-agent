"""Configuration for deterministic skill maintenance."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class EvolutionConfig:
    skills_root: Path = field(
        default_factory=lambda: Path(
            os.getenv("AGENT_SKILLS_DIR", str(Path(__file__).parent.parent / "skills"))
        )
    )
    db_path: Path = field(
        default_factory=lambda: Path(
            os.getenv(
                "EVOLUTION_DB_PATH",
                str(Path(__file__).parent.parent.parent / "data" / "evolution.db"),
            )
        )
    )
    nudge_interval: int = field(
        default_factory=lambda: int(os.getenv("SKILL_NUDGE_INTERVAL", "10"))
    )
    stale_after_days: int = field(
        default_factory=lambda: int(os.getenv("SKILL_STALE_AFTER_DAYS", "30"))
    )
    archive_after_days: int = field(
        default_factory=lambda: int(os.getenv("SKILL_ARCHIVE_AFTER_DAYS", "90"))
    )
    worker_lease_seconds: int = field(
        default_factory=lambda: int(os.getenv("EVOLUTION_WORKER_LEASE_SECONDS", "60"))
    )
    worker_max_attempts: int = field(
        default_factory=lambda: int(os.getenv("EVOLUTION_WORKER_MAX_ATTEMPTS", "3"))
    )
    worker_retry_delay_seconds: int = field(
        default_factory=lambda: int(os.getenv("EVOLUTION_WORKER_RETRY_DELAY_SECONDS", "5"))
    )
    worker_poll_seconds: float = field(
        default_factory=lambda: float(os.getenv("EVOLUTION_WORKER_POLL_SECONDS", "2"))
    )
    llm_curation_enabled: bool = field(
        default_factory=lambda: _env_bool("SKILL_LLM_CURATION_ENABLED", True)
    )
    llm_curation_min_skills: int = field(
        default_factory=lambda: int(os.getenv("SKILL_LLM_CURATION_MIN_SKILLS", "2"))
    )
    llm_curation_min_confidence: float = field(
        default_factory=lambda: float(os.getenv("SKILL_LLM_CURATION_MIN_CONFIDENCE", "0.92"))
    )
    llm_curation_max_skills: int = field(
        default_factory=lambda: int(os.getenv("SKILL_LLM_CURATION_MAX_SKILLS", "12"))
    )
