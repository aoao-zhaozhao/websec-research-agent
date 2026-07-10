from __future__ import annotations

import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent.evolution import EvolutionConfig, EvolutionCoordinator, EvolutionStore, EvolutionWorker
from agent.evolution.lifecycle import LifecyclePolicy
from agent.skill_manager import SkillAlreadyExistsError, SkillManager


class _ManagerFixture:
    def __init__(self):
        self.transitions: list[dict[str, str]] = []

    def apply_automatic_transitions(self, policy):
        return list(self.transitions)


class SkillEvolutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = EvolutionStore(self.root / "evolution.db")
        self.manager = SkillManager(self.root / "skills", store=self.store)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def create_skill(self, name: str = "test-technique"):
        return self.manager.create(
            title=name,
            description="Reusable test technique",
            body="## Steps\n\nRun the bounded test.",
            category="general",
            tags=["test"],
        )

    def test_create_records_agent_source_and_rejects_overwrite(self):
        self.create_skill()
        record = self.store.get_skill("test-technique")

        self.assertEqual(record["source"], "agent")
        document = self.root / "skills" / "general" / "test-technique" / "SKILL.md"
        self.assertIn("source: agent", document.read_text(encoding="utf-8"))
        with self.assertRaises(SkillAlreadyExistsError):
            self.create_skill()

    def test_view_use_and_patch_have_independent_telemetry(self):
        self.create_skill()
        self.manager.view("test-technique")
        self.manager.load("test-technique")
        self.assertTrue(self.manager.patch("test-technique", "Run the bounded test.", "Run and verify the bounded test."))

        record = self.store.get_skill("test-technique")
        self.assertEqual(record["view_count"], 1)
        self.assertEqual(record["use_count"], 1)
        self.assertEqual(record["patch_count"], 1)
        document = self.manager.view("test-technique")
        self.assertNotIn("use_count:", document)

    def test_view_does_not_revive_stale_skill_but_use_does(self):
        self.create_skill()
        self.manager.set_state("test-technique", "stale")

        self.manager.view("test-technique")
        self.assertEqual(self.store.get_skill("test-technique")["state"], "stale")
        self.manager.load("test-technique")
        self.assertEqual(self.store.get_skill("test-technique")["state"], "active")

    def test_concurrent_usage_bumps_do_not_lose_updates(self):
        self.create_skill()

        def bump_many(_worker: int) -> None:
            for _ in range(25):
                self.store.bump("test-technique", "use")

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(bump_many, range(8)))

        self.assertEqual(self.store.get_skill("test-technique")["use_count"], 200)

    def test_lifecycle_is_deterministic_and_pin_protects_skill(self):
        created = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self._write_legacy_skill("old-technique", created, source="agent")
        self.manager = SkillManager(self.root / "skills", store=self.store)
        policy = LifecyclePolicy(stale_after_days=30, archive_after_days=90)

        self.manager.pin("old-technique", True)
        self.assertEqual(
            self.manager.apply_automatic_transitions(policy, now=created + timedelta(days=31)),
            [],
        )
        self.manager.pin("old-technique", False)
        self.assertEqual(
            self.manager.apply_automatic_transitions(policy, now=created + timedelta(days=31)),
            [{"name": "old-technique", "from": "active", "to": "stale"}],
        )
        self.assertEqual(
            self.manager.apply_automatic_transitions(policy, now=created + timedelta(days=91)),
            [{"name": "old-technique", "from": "stale", "to": "archived"}],
        )
        self.assertFalse((self.root / "skills" / "general" / "old-technique").exists())
        self.assertTrue(self.manager.restore("old-technique"))
        self.assertEqual(self.store.get_skill("old-technique")["state"], "active")

    def test_bundled_skill_is_never_automatically_archived(self):
        created = datetime(2025, 1, 1, tzinfo=timezone.utc)
        self._write_legacy_skill("seed-skill", created, source="bundled")
        self.manager = SkillManager(self.root / "skills", store=self.store)

        first = self.manager.apply_automatic_transitions(
            LifecyclePolicy(stale_after_days=30, archive_after_days=90),
            now=created + timedelta(days=31),
        )
        transitions = self.manager.apply_automatic_transitions(
            LifecyclePolicy(stale_after_days=30, archive_after_days=90),
            now=created + timedelta(days=100),
        )

        self.assertEqual(first, [])
        self.assertEqual(transitions, [])
        self.assertEqual(self.store.get_skill("seed-skill")["state"], "active")
        self.assertFalse(self.manager.patch("seed-skill", "# seed-skill", "# changed"))
        self.assertTrue((self.root / "skills" / "general" / "seed-skill" / "SKILL.md").exists())

    def test_protected_reference_blocks_archive(self):
        self.create_skill()
        self.assertTrue(self.store.set_reference("cron", "daily-scan", "test-technique"))
        self.assertFalse(self.manager.archive("test-technique"))
        self.assertTrue(self.store.remove_reference("cron", "daily-scan", "test-technique"))
        self.assertTrue(self.manager.archive("test-technique"))

    def _write_legacy_skill(self, name: str, created: datetime, source: str) -> None:
        path = self.root / "skills" / "general" / name / "SKILL.md"
        path.parent.mkdir(parents=True, exist_ok=True)
        timestamp = created.strftime("%Y-%m-%dT%H:%M:%SZ")
        path.write_text(
            "\n".join(
                [
                    "---",
                    f"name: {name}",
                    "description: test",
                    "category: general",
                    "author: agent",
                    f"source: {source}",
                    f"created_at: {timestamp}",
                    f"updated_at: {timestamp}",
                    "state: active",
                    "---",
                    "",
                    f"# {name}",
                    "",
                ]
            ),
            encoding="utf-8",
        )


class EvolutionNudgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = EvolutionStore(self.root / "evolution.db")
        self.manager = _ManagerFixture()
        self.coordinator = EvolutionCoordinator(
            config=EvolutionConfig(
                skills_root=self.root / "skills",
                db_path=self.root / "evolution.db",
                nudge_interval=10,
                stale_after_days=30,
                archive_after_days=90,
            ),
            store=self.store,
            manager=self.manager,
        )

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_nudge_creates_one_durable_job_and_resets_only_on_success(self):
        for _ in range(9):
            self.coordinator.record_tool_completed("crawl", {"status": "ok", "findings": []})
        self.coordinator.record_tool_completed("skill_load", {"status": "ok"})
        self.assertIsNone(self.coordinator.finalize_turn().review_job)

        self.coordinator.record_tool_completed(
            "http_get",
            {
                "status": "ok",
                "findings": [
                    {
                        "title": "Confirmed SSRF",
                        "category": "ssrf",
                        "confidence": "confirmed",
                    }
                ],
            },
        )
        first = self.coordinator.finalize_turn()
        self.assertIsNotNone(first.review_job)
        self.assertEqual(first.review_job["trigger_count"], 10)
        self.assertEqual(first.review_job["status"], "completed")
        self.assertEqual(first.reviews[0]["status"], "action_required")
        self.assertIn("ssrf", self.coordinator.pending_directive())
        self.assertIsNone(self.coordinator.finalize_turn().review_job)
        self.assertEqual(len(self.store.list_jobs()), 1)
        self.assertEqual(self.store.tool_counter(), 0)

        self.coordinator.record_tool_completed("skill_create", {"status": "ok"})
        self.assertIsNone(self.coordinator.pending_directive())

    def test_no_action_review_completes_without_directive(self):
        for _ in range(10):
            self.coordinator.record_tool_completed("crawl", {"status": "ok", "findings": []})

        result = self.coordinator.finalize_turn()

        self.assertEqual(result.review_job["status"], "completed")
        self.assertEqual(result.reviews[0]["status"], "no_action")
        self.assertIsNone(self.coordinator.pending_directive())

    def test_expired_lease_is_reclaimed_and_attempt_count_is_preserved(self):
        now = datetime.now(timezone.utc)
        for _ in range(10):
            self.store.increment_tool_counter()
        job = self.store.schedule_review_if_due(10)
        first = self.store.claim_next_job("worker-1", lease_seconds=10, now=now)
        self.assertEqual(first["attempts"], 1)

        second = self.store.claim_next_job(
            "worker-2",
            lease_seconds=10,
            now=now + timedelta(seconds=11),
        )

        self.assertEqual(second["id"], job["id"])
        self.assertEqual(second["attempts"], 2)
        self.assertEqual(second["lease_owner"], "worker-2")

    def test_worker_retries_failure_then_marks_job_failed(self):
        class BrokenReviewer:
            def review(self, _job):
                raise RuntimeError("review failed")

        for _ in range(10):
            self.store.increment_tool_counter()
        job = self.store.schedule_review_if_due(10)
        config = EvolutionConfig(
            skills_root=self.root / "skills",
            db_path=self.root / "evolution.db",
            nudge_interval=10,
            worker_max_attempts=2,
            worker_retry_delay_seconds=0,
        )
        worker = EvolutionWorker(
            self.store,
            config=config,
            reviewer=BrokenReviewer(),
            worker_id="broken-worker",
        )

        worker.run_once()
        self.assertEqual(self.store.get_job(job["id"])["status"], "pending")
        worker.run_once()
        failed = self.store.get_job(job["id"])
        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["attempts"], 2)
        self.assertEqual(self.store.tool_counter(), 0)
        self.assertIsNone(self.store.schedule_review_if_due(10))
        for _ in range(10):
            self.store.increment_tool_counter()
        self.assertIsNotNone(self.store.schedule_review_if_due(10))

    def test_expired_final_attempt_moves_batch_to_dead_letter(self):
        now = datetime.now(timezone.utc)
        for _ in range(10):
            self.store.increment_tool_counter()
        job = self.store.schedule_review_if_due(10)
        self.store.claim_next_job("worker-1", lease_seconds=10, max_attempts=1, now=now)

        self.assertIsNone(
            self.store.claim_next_job(
                "worker-2",
                lease_seconds=10,
                max_attempts=1,
                now=now + timedelta(seconds=11),
            )
        )
        self.assertEqual(self.store.get_job(job["id"])["status"], "failed")
        self.assertEqual(self.store.tool_counter(), 0)


if __name__ == "__main__":
    unittest.main()
