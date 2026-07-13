from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.telemetry import TelemetryStore


class TelemetryStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "telemetry.db"
        self.store = TelemetryStore(self.db_path)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def _create_run(self, run_id: str, category: str = "web") -> None:
        self.store.create_run(
            run_id,
            input_text="scan the authorized target",
            target="http://scanner.test",
            mode="benchmark",
            category=category,
            model="test-model",
        )

    def test_action_terminal_record_is_deduplicated_by_tool_run_id(self):
        self._create_run("run-1")
        self.store.start_action(
            "run-1", tool_run_id="tool-1", tool_name="http_get", input_data={"url": "http://scanner.test"}
        )
        self.store.start_action(
            "run-1", tool_run_id="tool-1", tool_name="http_get", input_data={"url": "http://scanner.test"}
        )
        self.store.finish_action(
            "run-1",
            tool_run_id="tool-1",
            tool_name="http_get",
            status="ok",
            output_excerpt="ok",
            result_data={"status": "ok", "data": {"status_code": 200}},
            duration_ms=12,
            effective=True,
        )

        run = self.store.get_run("run-1")
        self.assertEqual(len(run["actions"]), 1)
        self.assertEqual(run["actions"][0]["duration_ms"], 12)

    def test_metrics_separate_tool_and_protocol_failures(self):
        self._create_run("run-web", "web")
        self.store.start_action("run-web", tool_run_id="first", tool_name="crawl", input_data={})
        self.store.finish_action(
            "run-web", tool_run_id="first", tool_name="crawl", status="ok", output_excerpt="found",
            result_data={"status": "ok", "findings": [{"title": "x"}]}, duration_ms=10, effective=True,
        )
        self.store.start_action("run-web", tool_run_id="second", tool_name="search", input_data={})
        self.store.finish_action(
            "run-web", tool_run_id="second", tool_name="search", status="protocol_error", output_excerpt="plain text",
            result_data=None, duration_ms=5, protocol_error="missing_result_envelope", effective=None,
        )
        self.store.finish_run("run-web", "completed")
        self.store.record_evaluation("run-web", judge="local", outcome="solved", verified=True)

        self._create_run("run-crypto", "crypto")
        self.store.start_action("run-crypto", tool_run_id="first", tool_name="decode", input_data={})
        self.store.finish_action(
            "run-crypto", tool_run_id="first", tool_name="decode", status="error", output_excerpt="bad input",
            result_data={"status": "error"}, duration_ms=7, effective=False,
        )
        self.store.finish_run("run-crypto", "failed")

        metrics = self.store.metrics()
        self.assertEqual(metrics["runs"]["total"], 2)
        self.assertEqual(metrics["actions"]["tool_errors"], 1)
        self.assertEqual(metrics["actions"]["protocol_failures"], 1)
        self.assertEqual(metrics["first_effective_action"]["rate"], 0.5)
        self.assertEqual(metrics["solve_rate"]["rate"], 1.0)
        self.assertEqual(metrics["by_category"]["web"]["solve_rate"]["rate"], 1.0)

    def test_model_usage_keeps_cost_unknown_without_price_configuration(self):
        self._create_run("run-usage")
        self.store.record_model_usage(
            "run-usage", model="test-model", input_tokens=120, output_tokens=30,
            cached_tokens=20, cost_usd=None, raw_usage={"input_tokens": 120, "output_tokens": 30},
        )

        usage = self.store.metrics()["model_usage"]
        self.assertEqual(usage["input_tokens"], 120)
        self.assertEqual(usage["output_tokens"], 30)
        self.assertEqual(usage["cost_usd"], None)

    def test_conversation_survives_store_reopen_and_links_runs(self):
        conversation = self.store.create_conversation("Authorized review")
        self.store.create_run(
            "run-conversation",
            input_text="Authorization: Bearer top-secret",
            target="http://scanner.test",
            mode="production",
            category="web",
            model="test-model",
            conversation_id=conversation["id"],
        )
        self.store.finish_run("run-conversation", "completed", "password=unsafe should not persist")
        self.store.close()
        self.store = TelemetryStore(self.db_path)
        recovered = self.store.get_conversation(conversation["id"])

        self.assertEqual(recovered["runs"][0]["conversation_id"], conversation["id"])
        self.assertEqual(recovered["messages"][0]["content"], "Authorization: Bearer [REDACTED]")
        self.assertEqual(recovered["messages"][1]["content"], "password=[REDACTED] should not persist")

    def test_delete_conversation_retains_anonymized_run(self):
        conversation = self.store.create_conversation()
        self.store.create_run(
            "run-retained", input_text="scan", target="http://scanner.test", mode="production",
            category="web", model="test-model", conversation_id=conversation["id"],
        )

        self.assertTrue(self.store.delete_conversation(conversation["id"]))
        self.assertIsNone(self.store.get_conversation(conversation["id"]))
        self.assertIsNone(self.store.get_run("run-retained")["conversation_id"])

    def test_legacy_import_is_idempotent_and_redacts_credentials(self):
        sessions = [{
            "id": "legacy-1", "title": "old", "createdAt": 1_700_000_000_000,
            "messages": [{"role": "user", "content": "api_key=old-secret", "at": 1_700_000_000_001}],
        }]
        self.assertEqual(self.store.import_conversations(sessions), 1)
        self.assertEqual(self.store.import_conversations(sessions), 0)
        self.assertEqual(self.store.get_conversation("legacy-1")["messages"][0]["content"], "api_key=[REDACTED]")


if __name__ == "__main__":
    unittest.main()
