from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from agent.agent import Agent
from agent.scan_state import ScanState, stage_for_tool, target_from_input
from agent.telemetry import TelemetryStore
from agent.tools.results import Evidence, Finding, ToolResult
from langchain_core.messages import HumanMessage, SystemMessage


class ScanStateTests(unittest.TestCase):
    def test_tool_stages_advance_monotonically_and_keep_progress(self):
        scan = ScanState(target="http://scanner.test")

        events = scan.start_tool("crawl", "crawl-1")
        self.assertEqual(events[0]["type"], "stage_started")
        self.assertEqual(events[0]["stage"], "crawl")
        progress = scan.finish_tool("crawl", "crawl-1", {"status": "ok"})

        self.assertEqual(progress["type"], "stage_progress")
        self.assertEqual(progress["scan"]["tool_count"], 1)
        self.assertEqual(progress["scan"]["stages"]["scope"], "completed")
        self.assertEqual(progress["scan"]["stages"]["crawl"], "active")

        scan.start_tool("verify_injection", "verify-1")
        self.assertEqual(scan.current_stage, "verify")
        scan.start_tool("extract_links", "late-crawl")
        self.assertEqual(scan.current_stage, "verify")

    def test_findings_and_stop_keep_the_existing_evidence_counts(self):
        scan = ScanState(target="http://scanner.test")
        events = scan.finding_events(
            "verify_injection",
            {"findings": [{"title": "LFI", "confidence": "confirmed"}]},
        )
        finished = scan.finish("stopped")

        self.assertEqual(events[0]["type"], "finding_created")
        self.assertEqual(events[0]["finding"]["confidence"], "confirmed")
        self.assertEqual(finished[-1]["type"], "scan_finished")
        self.assertEqual(finished[-1]["scan"]["status"], "stopped")
        self.assertEqual(finished[-1]["scan"]["finding_count"], 1)

    def test_target_and_tool_classification(self):
        self.assertEqual(target_from_input("scan https://example.test/path."), "https://example.test/path")
        self.assertEqual(stage_for_tool("search_knowledge"), "knowledge")
        self.assertEqual(stage_for_tool("unknown"), "scope")


class _FakeGraph:
    async def astream_events(self, _input, **_kwargs):
        self.last_input = _input
        yield {
            "event": "on_chat_model_stream",
            "data": {"chunk": SimpleNamespace(content="", additional_kwargs={"reasoning_content": "Inspect the target."})},
        }
        yield {
            "event": "on_tool_start",
            "run_id": "crawl-1",
            "name": "crawl",
            "data": {"input": {"root_url": "http://scanner.test"}},
        }
        result = ToolResult(
            tool="crawl",
            target="http://scanner.test",
            status="ok",
            summary="found one page",
            findings=[
                Finding(
                    title="Sensitive path",
                    confidence="likely",
                    evidence=[Evidence("http_status", "status 200")],
                )
            ],
        ).to_text()
        yield {
            "event": "on_tool_end",
            "run_id": "crawl-1",
            "name": "crawl",
            "data": {"output": result},
        }


class AgentLifecycleEventTests(unittest.IsolatedAsyncioTestCase):
    async def test_agent_emits_stage_progress_finding_and_finished_events(self):
        agent = Agent.__new__(Agent)
        agent.config = SimpleNamespace(max_turns=4, history_message_limit=24, show_reasoning=True, model="test-model")
        agent.llm = object()
        agent.messages = [SystemMessage(content="system")]
        agent._active_scan = None
        agent.last_scan = None
        agent._tools = lambda: []
        agent._build_llm = lambda: object()
        agent.telemetry = TelemetryStore(":memory:")
        self.addCleanup(agent.telemetry.close)
        agent.evolution = Mock()
        agent.evolution.finalize_turn.return_value.to_dict.return_value = {
            "tool_calls_since_review": 1,
            "review_job": None,
            "transitions": [],
            "reviews": [],
        }
        agent.evolution.pending_directive.return_value = "review directive"

        graph = _FakeGraph()
        with patch("agent.agent.create_react_agent", return_value=graph):
            events = [event async for event in agent.run_events("scan http://scanner.test")]

        telemetry_run = agent.telemetry.get_run(events[0]["scan_id"])
        self.assertEqual(telemetry_run["status"], "completed")
        self.assertEqual(len(telemetry_run["actions"]), 1)
        self.assertEqual(telemetry_run["actions"][0]["tool_name"], "crawl")

        event_types = [event["type"] for event in events]
        self.assertEqual(event_types[0], "scan_started")
        self.assertIn("stage_started", event_types)
        self.assertIn("reasoning", event_types)
        self.assertIn("tool_started", event_types)
        self.assertIn("tool_finished", event_types)
        self.assertIn("stage_progress", event_types)
        self.assertIn("finding_created", event_types)
        self.assertEqual(event_types[-1], "scan_finished")
        finding = next(event for event in events if event["type"] == "finding_created")
        finished = events[-1]
        self.assertEqual(finding["finding"]["confidence"], "likely")
        self.assertEqual(finished["scan"]["status"], "completed")
        call = agent.evolution.record_tool_completed.call_args
        self.assertEqual(call.args[0], "crawl")
        self.assertEqual(call.args[1]["status"], "ok")
        self.assertEqual(call.kwargs["scan_id"], finished["scan"]["id"])
        agent.evolution.finalize_turn.assert_called_once_with()
        self.assertEqual(graph.last_input["messages"][1].content, "review directive")


class AgentModelConfigurationTests(unittest.TestCase):
    def make_agent(self, **config):
        agent = Agent.__new__(Agent)
        defaults = {
            "api_key": "key",
            "base_url": "https://api.deepseek.com",
            "model": "deepseek-v4-flash",
            "temperature": 0.3,
            "reasoning_effort": "high",
            "thinking_enabled": True,
            "history_message_limit": 2,
        }
        defaults.update(config)
        agent.config = SimpleNamespace(**defaults)
        return agent

    def test_thinking_request_uses_provider_fields_without_temperature(self):
        agent = self.make_agent()
        with patch("agent.agent.ChatOpenAI") as chat_openai:
            agent._build_llm()

        kwargs = chat_openai.call_args.kwargs
        self.assertEqual(kwargs["reasoning_effort"], "high")
        self.assertEqual(kwargs["extra_body"], {"thinking": {"type": "enabled"}})
        self.assertNotIn("temperature", kwargs)

    def test_non_thinking_request_disables_thinking_and_keeps_temperature(self):
        agent = self.make_agent(thinking_enabled=False)
        with patch("agent.agent.ChatOpenAI") as chat_openai:
            agent._build_llm()

        kwargs = chat_openai.call_args.kwargs
        self.assertEqual(kwargs["temperature"], 0.3)
        self.assertEqual(kwargs["extra_body"], {"thinking": {"type": "disabled"}})

    def test_history_trim_preserves_system_prompt_and_recent_messages(self):
        agent = self.make_agent()
        agent.messages = [SystemMessage(content="system")] + [
            HumanMessage(content=f"message-{index}") for index in range(4)
        ]
        agent._trim_history()

        self.assertEqual(len(agent.messages), 3)
        self.assertEqual(agent.messages[0].content, "system")
        self.assertEqual(agent.messages[-1].content, "message-3")
