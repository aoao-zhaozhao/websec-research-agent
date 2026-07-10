"""Connect agent tool events to deterministic evolution maintenance."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .config import EvolutionConfig
from .lifecycle import LifecyclePolicy
from .store import EvolutionStore, get_evolution_store
from .worker import EvolutionWorker


EVOLUTION_TOOLS = {
    "skill_list",
    "skill_view",
    "skill_load",
    "skill_create",
    "skill_patch",
    "skill_pin",
    "skill_archive",
    "skill_restore",
    "scan_reflect",
}


@dataclass
class MaintenanceResult:
    tool_calls_since_review: int
    review_job: dict[str, Any] | None
    transitions: list[dict[str, str]]
    reviews: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EvolutionCoordinator:
    def __init__(
        self,
        config: EvolutionConfig | None = None,
        store: EvolutionStore | None = None,
        manager: Any | None = None,
        worker: EvolutionWorker | None = None,
    ):
        self.config = config or EvolutionConfig()
        self.store = store or get_evolution_store()
        self.manager = manager
        self.worker = worker or EvolutionWorker(self.store, self.config)

    def record_tool_completed(
        self,
        tool_name: str,
        result: dict[str, Any] | None = None,
        *,
        scan_id: str | None = None,
    ) -> int:
        self.store.record_observation(tool_name, result, scan_id=scan_id)
        if self._resolves_pending_review(tool_name, result):
            self.store.acknowledge_pending_review()
        if tool_name in EVOLUTION_TOOLS or tool_name.startswith("skill_"):
            return self.store.tool_counter()
        return self.store.increment_tool_counter()

    @staticmethod
    def _resolves_pending_review(tool_name: str, result: dict[str, Any] | None) -> bool:
        result = result or {}
        if result.get("status") != "ok":
            return False
        if tool_name in {"skill_create", "skill_patch"}:
            return True
        if tool_name != "scan_reflect":
            return False
        suggestions = (result.get("data") or {}).get("suggestions") or []
        return not any(
            isinstance(item, dict) and item.get("action") == "consider_skill_create"
            for item in suggestions
        )

    def pending_directive(self) -> str | None:
        review = self.store.pending_review()
        if review is None:
            return None
        return (
            "CODE-ENFORCED SKILL REVIEW (persistent until resolved):\n"
            + str(review["report"])
        )

    def finalize_turn(self) -> MaintenanceResult:
        # Imported lazily to keep the repository independent from orchestration.
        from ..skill_manager import get_skill_manager

        manager = self.manager or get_skill_manager()
        policy = LifecyclePolicy(
            stale_after_days=self.config.stale_after_days,
            archive_after_days=self.config.archive_after_days,
        )
        transitions = manager.apply_automatic_transitions(policy=policy)
        job = self.store.schedule_review_if_due(self.config.nudge_interval)
        worker_results = self.worker.run_until_idle()
        if job is not None:
            job = self.store.get_job(str(job["id"])) or job
        return MaintenanceResult(
            tool_calls_since_review=self.store.tool_counter(),
            review_job=job,
            transitions=transitions,
            reviews=[item.review for item in worker_results if item.review is not None],
        )
