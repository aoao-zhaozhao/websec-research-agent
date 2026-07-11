"""In-process durable worker for deterministic evolution jobs."""

from __future__ import annotations

import os
import socket
import threading
import uuid
from dataclasses import dataclass
from typing import Any

from .config import EvolutionConfig
from .curator import LLMSkillCurator
from .reviewer import DeterministicSkillReviewer
from .store import EvolutionStore, get_evolution_store


@dataclass(frozen=True)
class WorkerResult:
    job: dict[str, Any]
    review: dict[str, Any] | None
    error: str = ""


class EvolutionWorker:
    def __init__(
        self,
        store: EvolutionStore,
        config: EvolutionConfig | None = None,
        reviewer: DeterministicSkillReviewer | None = None,
        curator: LLMSkillCurator | None = None,
        worker_id: str | None = None,
    ):
        self.store = store
        self.config = config or EvolutionConfig()
        self.reviewer = reviewer or DeterministicSkillReviewer(store)
        self.curator = curator or LLMSkillCurator(store, self.config)
        self.worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"

    def run_once(self) -> WorkerResult | None:
        job = self.store.claim_next_job(
            self.worker_id,
            lease_seconds=self.config.worker_lease_seconds,
            max_attempts=self.config.worker_max_attempts,
        )
        if job is None:
            return None
        try:
            if job["kind"] != "skill_review":
                raise ValueError(f"unsupported evolution job kind: {job['kind']}")
            decision = self.reviewer.review(job)
            decision = self.curator.curate(job, decision)
            review = self.store.save_review(
                str(job["id"]),
                status=decision.status,
                report=decision.report,
                evidence=decision.evidence,
            )
            self.store.finish_job(str(job["id"]), success=True)
            return WorkerResult(self.store.get_job(str(job["id"])) or job, review)
        except Exception as exc:
            self.store.retry_job(
                str(job["id"]),
                error=str(exc),
                retry_delay_seconds=self.config.worker_retry_delay_seconds,
                max_attempts=self.config.worker_max_attempts,
            )
            return WorkerResult(self.store.get_job(str(job["id"])) or job, None, str(exc))

    def run_until_idle(self, max_jobs: int = 10) -> list[WorkerResult]:
        results: list[WorkerResult] = []
        for _ in range(max(1, max_jobs)):
            result = self.run_once()
            if result is None:
                break
            results.append(result)
            if result.error:
                break
        return results


_worker: EvolutionWorker | None = None
_worker_lock = threading.Lock()


def get_evolution_worker() -> EvolutionWorker:
    global _worker
    if _worker is None:
        with _worker_lock:
            if _worker is None:
                _worker = EvolutionWorker(get_evolution_store())
    return _worker
