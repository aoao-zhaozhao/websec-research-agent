"""LangGraph scanner orchestration with structured lifecycle events."""

from __future__ import annotations

from pathlib import Path
from typing import Any, AsyncIterator

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from .config import AgentConfig
from .evolution import EvolutionConfig, EvolutionCoordinator
from .prompts import SYSTEM_PROMPT
from .rag import create_search_knowledge_tool
from .scan_state import ScanState, target_from_input
from .tools import BASE_TOOLS
from .tools.results import parse_tool_result


class Agent:
    """Web application security scanning agent."""

    def __init__(self, config: AgentConfig | None = None):
        self.config = config or AgentConfig()
        self.llm = self._build_llm()

        self._search_knowledge_tool = None
        self._rag_manager = None
        self._init_rag()

        self.evolution = EvolutionCoordinator(
            EvolutionConfig(
                skills_root=Path(self.config.skills_dir),
                db_path=Path(self.config.evolution_db_path),
                nudge_interval=self.config.skill_nudge_interval,
                stale_after_days=self.config.skill_stale_after_days,
                archive_after_days=self.config.skill_archive_after_days,
            )
        )

        self.agent = create_react_agent(self.llm, self._tools())
        self.messages = [SystemMessage(content=SYSTEM_PROMPT)]
        self._active_scan: ScanState | None = None
        self.last_scan: ScanState | None = None

    def _tools(self):
        tools = list(BASE_TOOLS)
        if self._search_knowledge_tool:
            tools.append(self._search_knowledge_tool)
        return tools

    def _build_llm(self) -> ChatOpenAI:
        """Build a fresh client so runtime model settings apply to the next scan."""
        options: dict[str, Any] = {
            "api_key": self.config.api_key,
            "base_url": self.config.base_url,
            "model": self.config.model,
        }
        if self.config.thinking_enabled:
            # DeepSeek's OpenAI-compatible API requires provider fields in
            # extra_body and ignores temperature in thinking mode.
            options["reasoning_effort"] = self.config.reasoning_effort
            options["extra_body"] = {"thinking": {"type": "enabled"}}
        else:
            options["temperature"] = self.config.temperature
            options["extra_body"] = {"thinking": {"type": "disabled"}}
        return ChatOpenAI(**options)

    def _trim_history(self) -> None:
        """Keep the system prompt and recent completed turns within a stable budget."""
        limit = max(2, int(self.config.history_message_limit))
        system = self.messages[:1]
        recent = self.messages[1:]
        if len(recent) > limit:
            self.messages = system + recent[-limit:]

    @staticmethod
    def _reasoning_content(chunk: Any) -> str:
        additional = getattr(chunk, "additional_kwargs", {}) or {}
        value = additional.get("reasoning_content")
        if value is None:
            value = getattr(chunk, "reasoning_content", None)
        if isinstance(value, str):
            return value
        return ""

    def _init_rag(self) -> None:
        """Initialize the RAG tool; continue without it if local models fail."""
        try:
            search_tool, rag_mgr = create_search_knowledge_tool(self.config)
            self._search_knowledge_tool = search_tool
            self._rag_manager = rag_mgr
        except Exception as exc:
            print(f"[Agent] RAG init failed ({exc}); continuing without knowledge search")
            self._search_knowledge_tool = None
            self._rag_manager = None

    @property
    def has_rag(self) -> bool:
        return self._rag_manager is not None and self._search_knowledge_tool is not None

    def clear(self) -> None:
        self.messages = [SystemMessage(content=SYSTEM_PROMPT)]

    def finish_scan(self, status: str) -> list[dict[str, Any]]:
        """Return terminal lifecycle events for the current or latest scan."""
        scan = self._active_scan or self.last_scan
        return scan.finish(status) if scan else []

    def _summarize_tool_output(self, output: Any, limit: int = 900) -> str:
        if hasattr(output, "content"):
            text = str(output.content)
        else:
            text = str(output)
        text = text.strip()
        if len(text) > limit:
            return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"
        return text

    def _finalize_evolution(self) -> dict[str, Any] | None:
        coordinator = getattr(self, "evolution", None)
        if coordinator is None:
            return None
        try:
            return coordinator.finalize_turn().to_dict()
        except Exception as exc:
            # Skill maintenance must not change the scan's terminal status.
            print(f"[Agent] evolution finalizer failed: {exc}")
            return {"error": str(exc)}

    async def run_events(self, user_input: str) -> AsyncIterator[dict[str, Any]]:
        """
        Execute one turn and yield structured events.

        The model remains responsible for tool selection. ScanState emits a
        stable projection of that work for the UI: scan_started, stage_started,
        stage_progress, finding_created, and scan_finished.
        """
        scan = ScanState(target=target_from_input(user_input))
        self._active_scan = scan
        self.last_scan = scan
        self.messages.append(HumanMessage(content=user_input))
        self._trim_history()
        invocation_messages = list(self.messages)
        directive = self.evolution.pending_directive()
        if directive and invocation_messages:
            invocation_messages = [
                invocation_messages[0],
                SystemMessage(content=directive),
                *invocation_messages[1:],
            ]
        self.llm = self._build_llm()
        self.agent = create_react_agent(self.llm, self._tools())

        full_response: list[str] = []
        evolution_finalized = False
        yield scan.started_event()
        try:
            async for event in self.agent.astream_events(
                {"messages": invocation_messages},
                config={"recursion_limit": self.config.max_turns},
                version="v2",
            ):
                kind = event["event"]

                if kind == "on_chat_model_stream":
                    chunk = event["data"]["chunk"]
                    reasoning = self._reasoning_content(chunk)
                    if reasoning and self.config.show_reasoning:
                        yield {"type": "reasoning", "scan_id": scan.scan_id, "content": reasoning}
                    if chunk.content:
                        full_response.append(chunk.content)
                        yield {"type": "token", "scan_id": scan.scan_id, "content": chunk.content}
                elif kind == "on_tool_start":
                    tool_name = event.get("name", "tool")
                    run_id = str(event.get("run_id", ""))
                    for lifecycle_event in scan.start_tool(tool_name, run_id):
                        yield lifecycle_event
                    yield {
                        "type": "tool_started",
                        "scan_id": scan.scan_id,
                        "stage": scan.current_stage,
                        "id": run_id,
                        "name": tool_name,
                        "input": event.get("data", {}).get("input"),
                    }
                elif kind == "on_tool_end":
                    tool_name = event.get("name", "tool")
                    run_id = str(event.get("run_id", ""))
                    output, result = parse_tool_result(event.get("data", {}).get("output"))
                    yield {
                        "type": "tool_finished",
                        "scan_id": scan.scan_id,
                        "stage": scan.current_stage,
                        "id": run_id,
                        "name": tool_name,
                        "output": self._summarize_tool_output(output),
                        "result": result,
                    }
                    yield scan.finish_tool(tool_name, run_id, result)
                    for finding_event in scan.finding_events(tool_name, result):
                        yield finding_event
                    coordinator = getattr(self, "evolution", None)
                    if coordinator is not None:
                        coordinator.record_tool_completed(
                            tool_name,
                            result,
                            scan_id=scan.scan_id,
                        )

            response_text = "".join(full_response).strip()
            if response_text:
                self.messages.append(AIMessage(content=response_text))
            else:
                self.messages.append(AIMessage(content="扫描完成，请查看工具调用结果。"))
            self._trim_history()
            maintenance = self._finalize_evolution()
            evolution_finalized = True
            if maintenance and (maintenance.get("review_job") or maintenance.get("transitions") or maintenance.get("reviews") or maintenance.get("error")):
                yield {
                    "type": "evolution_maintenance",
                    "scan_id": scan.scan_id,
                    **maintenance,
                }
            for lifecycle_event in scan.finish("completed"):
                yield lifecycle_event
        except Exception:
            response_text = "".join(full_response).strip()
            if response_text:
                self.messages.append(AIMessage(content=response_text))
                self._trim_history()
            maintenance = self._finalize_evolution()
            evolution_finalized = True
            if maintenance and (maintenance.get("review_job") or maintenance.get("transitions") or maintenance.get("reviews") or maintenance.get("error")):
                yield {
                    "type": "evolution_maintenance",
                    "scan_id": scan.scan_id,
                    **maintenance,
                }
            for lifecycle_event in scan.finish("failed"):
                yield lifecycle_event
            raise
        finally:
            if not evolution_finalized:
                self._finalize_evolution()
            self._active_scan = None

    async def run(self, user_input: str) -> AsyncIterator[str]:
        """Backward-compatible token-only stream."""
        async for event in self.run_events(user_input):
            if event.get("type") == "token":
                yield str(event.get("content", ""))
