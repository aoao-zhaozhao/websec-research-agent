"""LangGraph scanner orchestration with structured lifecycle events."""

from __future__ import annotations

import time
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
from .telemetry import TelemetryStore
from .tools import BASE_TOOLS
from .tools.results import parse_tool_result, tool_result_protocol_error
from .tools.auth_session_tools import reset_auth_session_mode, set_auth_session_mode
from .case_evidence import begin_case_evidence_gate, end_case_evidence_gate, record_verified_evidence


class Agent:
    """Web application security scanning agent."""

    def __init__(self, config: AgentConfig | None = None, telemetry: TelemetryStore | None = None):
        self.config = config or AgentConfig()
        self.llm = self._build_llm()
        self.telemetry = telemetry or TelemetryStore(Path(self.config.telemetry_db_path))

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

        # v1.8: MCP 生命周期管理器（可选，由 web_server 注入）
        self._mcp_lifecycle: Any = None

        # v1.8: 流量捕获（按扫描会话创建）
        self._traffic_capture: Any = None

        self.agent = create_react_agent(self.llm, self._tools())
        self.messages = [SystemMessage(content=SYSTEM_PROMPT)]
        self._active_scan: ScanState | None = None
        self.last_scan: ScanState | None = None

    def set_mcp_lifecycle(self, lifecycle: Any) -> None:
        """注入 MCP 生命周期管理器（由 web_server 在创建 Agent 后调用）。"""
        self._mcp_lifecycle = lifecycle

    def _init_traffic(self, target_url: str) -> None:
        """为当前扫描初始化流量证据存储、捕获器和 mitmproxy 代理。"""
        try:
            from pathlib import Path
            from urllib.parse import urlparse
            from agent.traffic.store import TrafficStore
            from agent.traffic.capture import TrafficCapture
            from agent.traffic.scope import ScopeChecker, ScopeMode, Target
            from agent.traffic.proxy import ProxyManager
            from agent.tools.traffic_tools import set_traffic_store
            from agent.tools.http_tools import set_traffic_capture_for_tools

            evidence_dir = Path(self.config.evidence_dir)
            traffic_dir = evidence_dir / "traffic"
            store = TrafficStore(traffic_dir)

            parsed = urlparse(target_url)
            target_host = (parsed.hostname or "").lower()
            if target_host:
                scope = ScopeChecker(
                    targets=[Target(host=target_host)],
                    mode=ScopeMode.SUBDOMAIN,
                )
            else:
                scope = ScopeChecker(mode=ScopeMode.OPEN)

            capture = TrafficCapture(store, scope)
            self._traffic_capture = capture
            set_traffic_store(store)
            set_traffic_capture_for_tools(capture)

            # v1.8: 启动 mitmproxy 代理（免费 Tier-A 后端）
            self._proxy_manager: Any = ProxyManager(capture, port=8080)
            proxy_ok = self._proxy_manager.start()
            if proxy_ok:
                print(f"[Agent] mitmproxy 代理已启动 → {self._proxy_manager.proxy_url}")
                # 将 http_client 路由到代理
                from agent.tools.http_client import set_proxy
                set_proxy(self._proxy_manager.proxy_url)
            else:
                print(f"[Agent] mitmproxy 代理启动失败: {self._proxy_manager._error}，使用直连模式")
                self._proxy_manager = None
        except Exception as exc:
            print(f"[Agent] 流量存储初始化失败: {exc}")
            self._proxy_manager = None

    def _teardown_traffic(self) -> None:
        """扫描结束后停止代理并清理流量捕获引用。"""
        proxy = getattr(self, "_proxy_manager", None)
        if proxy is not None:
            proxy.stop()
            print(f"[Agent] mitmproxy 代理已停止（共捕获 {proxy.flow_count} 条流量）")
            self._proxy_manager = None
        from agent.tools.http_client import set_proxy
        set_proxy(None)
        self._traffic_capture = None

    def _tools(self):
        tools = list(BASE_TOOLS)
        if self._search_knowledge_tool:
            tools.append(self._search_knowledge_tool)
        # v1.8: 动态注入 MCP 工具
        if self._mcp_lifecycle is not None:
            try:
                from .tools.structured import mcp_tool_adapter
                for schema in self._mcp_lifecycle.get_tool_schemas():
                    tool_name = schema.get("name", "")
                    server_name = schema.get("server_name", "")
                    # 跳过已有同名工具（避免覆盖本地实现）
                    existing_names = {t.name for t in tools}
                    if tool_name in existing_names:
                        continue
                    adapted = mcp_tool_adapter(
                        tool_name=tool_name,
                        server_name=server_name or "",
                        input_schema=schema.get("inputSchema", {}),
                        description=schema.get("description", ""),
                        lifecycle_manager=self._mcp_lifecycle,
                    )
                    tools.append(adapted)
            except Exception as exc:
                print(f"[Agent] MCP 工具注入失败: {exc}")
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

    def restore_history(self, messages: list[dict[str, Any]]) -> None:
        """Rebuild the bounded model context from a durable conversation."""
        restored: list[Any] = [SystemMessage(content=SYSTEM_PROMPT)]
        for message in messages:
            content = str(message.get("content", "")).strip()
            if not content:
                continue
            if message.get("role") == "user":
                restored.append(HumanMessage(content=content))
            elif message.get("role") == "assistant":
                restored.append(AIMessage(content=content))
        self.messages = restored
        self._trim_history()

    def finish_scan(self, status: str) -> list[dict[str, Any]]:
        """Return terminal lifecycle events for the current or latest scan."""
        scan = self._active_scan or self.last_scan
        if scan is None:
            return []
        events = scan.finish(status)
        if events and getattr(self, "telemetry", None) is not None:
            self.telemetry.finish_run(scan.scan_id, status)
        return events

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

    @staticmethod
    def _effective_result(result: dict[str, Any] | None) -> bool | None:
        """A v1.7 proxy until task-specific success predicates are introduced."""
        if result is None:
            return None
        if result.get("status") != "ok":
            return False
        return bool(
            result.get("findings")
            or result.get("data")
            or result.get("request")
            or result.get("response")
        )

    def _record_model_usage(self, scan_id: str, output: Any) -> dict[str, int | str] | None:
        """Persist provider usage and return normalized values for the live UI."""
        telemetry = getattr(self, "telemetry", None)
        usage = getattr(output, "usage_metadata", None)
        response_metadata = getattr(output, "response_metadata", {}) or {}
        if not isinstance(usage, dict):
            usage = response_metadata.get("token_usage") or response_metadata.get("usage")
        if not isinstance(usage, dict):
            return None
        input_tokens = int(usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0)
        output_tokens = int(usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0)
        details = usage.get("input_token_details") or usage.get("prompt_tokens_details") or {}
        cached_tokens = int(
            usage.get(
                "cached_tokens",
                usage.get(
                    "prompt_cache_hit_tokens",
                    details.get("cached_tokens", details.get("cache_read", 0)),
                ),
            )
            or 0
        )
        # DeepSeek reports cache hits separately from prompt_tokens. Use its
        # hit/miss fields as a fallback when an OpenAI-compatible wrapper
        # omits the combined prompt token count.
        if not input_tokens:
            input_tokens = cached_tokens + int(usage.get("prompt_cache_miss_tokens", 0) or 0)
        input_rate = self.config.input_cost_per_million_tokens
        output_rate = self.config.output_cost_per_million_tokens
        cost_usd = None
        if input_rate is not None and output_rate is not None:
            cost_usd = (input_tokens * input_rate + output_tokens * output_rate) / 1_000_000
        if telemetry is not None:
            telemetry.record_model_usage(
                scan_id,
                model=self.config.model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cached_tokens=cached_tokens,
                cost_usd=cost_usd,
                raw_usage=usage,
            )
        return {
            "model": self.config.model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cached_tokens": cached_tokens,
        }

    async def run_events(
        self,
        user_input: str,
        *,
        mode: str = "production",
        category: str = "web",
        conversation_id: str | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """
        Execute one turn and yield structured events.

        The model remains responsible for tool selection. ScanState emits a
        stable projection of that work for the UI: scan_started, stage_started,
        stage_progress, finding_created, and scan_finished.
        """
        scan = ScanState(target=target_from_input(user_input))
        self._active_scan = scan
        self.last_scan = scan

        # v1.8: 初始化流量证据存储
        if scan.target:
            self._init_traffic(scan.target)

        telemetry = getattr(self, "telemetry", None)
        if telemetry is not None:
            telemetry.create_run(
                scan.scan_id,
                input_text=user_input,
                target=scan.target,
                mode=mode,
                category=category,
                model=self.config.model,
                conversation_id=conversation_id,
            )
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
        model_call_started: dict[str, float] = {}
        evolution_finalized = False
        auth_session_token = set_auth_session_mode(mode)
        case_evidence_token = begin_case_evidence_gate(scan.scan_id, scan.target)
        yield scan.started_event()
        try:
            async for event in self.agent.astream_events(
                {"messages": invocation_messages},
                config={"recursion_limit": self.config.max_turns},
                version="v2",
            ):
                kind = event["event"]

                if kind == "on_chat_model_start":
                    model_call_started[str(event.get("run_id", ""))] = time.perf_counter()
                elif kind == "on_chat_model_stream":
                    chunk = event["data"]["chunk"]
                    reasoning = self._reasoning_content(chunk)
                    if reasoning and self.config.show_reasoning:
                        yield {"type": "reasoning", "scan_id": scan.scan_id, "content": reasoning}
                    if chunk.content:
                        full_response.append(chunk.content)
                        if telemetry is not None:
                            telemetry.update_run_summary(scan.scan_id, "".join(full_response))
                        yield {"type": "token", "scan_id": scan.scan_id, "content": chunk.content}
                elif kind == "on_chat_model_end":
                    call_id = str(event.get("run_id", ""))
                    started_at = model_call_started.pop(call_id, None)
                    live_usage = self._record_model_usage(scan.scan_id, event.get("data", {}).get("output"))
                    if live_usage is not None:
                        yield {
                            "type": "model_usage",
                            "scan_id": scan.scan_id,
                            "duration_ms": round((time.perf_counter() - started_at) * 1000) if started_at else None,
                            **live_usage,
                        }
                elif kind == "on_tool_start":
                    tool_name = event.get("name", "tool")
                    run_id = str(event.get("run_id", ""))
                    for lifecycle_event in scan.start_tool(tool_name, run_id):
                        yield lifecycle_event
                    if telemetry is not None:
                        telemetry.start_action(
                            scan.scan_id,
                            tool_run_id=run_id,
                            tool_name=tool_name,
                            input_data=event.get("data", {}).get("input"),
                        )
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
                    raw_output = event.get("data", {}).get("output")
                    output, result = parse_tool_result(raw_output)
                    protocol_error = tool_result_protocol_error(raw_output)
                    action_status = "protocol_error" if protocol_error else str(result.get("status", "ok"))
                    result_for_scan = result or {"status": "protocol_error"}
                    progress_event = scan.finish_tool(tool_name, run_id, result_for_scan)
                    record_verified_evidence(tool_name, result)
                    if telemetry is not None:
                        telemetry.finish_action(
                            scan.scan_id,
                            tool_run_id=run_id,
                            tool_name=tool_name,
                            status=action_status,
                            output_excerpt=self._summarize_tool_output(output, limit=6000),
                            result_data=result,
                            duration_ms=progress_event.get("duration_ms"),
                            protocol_error=protocol_error,
                            effective=self._effective_result(result),
                        )
                    yield {
                        "type": "tool_finished",
                        "scan_id": scan.scan_id,
                        "stage": scan.current_stage,
                        "id": run_id,
                        "name": tool_name,
                        "output": self._summarize_tool_output(output),
                        "result": result,
                        "protocol_error": protocol_error,
                    }
                    if tool_name == "case_create" and result and result.get("status") == "ok":
                        case_data = result.get("data", {})
                        case_id = str(case_data.get("id", "案例"))
                        notice = f"\n\n案例已保存并已加入知识库：{case_id}。"
                        full_response.append(notice)
                        if telemetry is not None:
                            telemetry.update_run_summary(scan.scan_id, "".join(full_response))
                        yield {"type": "token", "scan_id": scan.scan_id, "content": notice}
                        yield {
                            "type": "case_saved",
                            "scan_id": scan.scan_id,
                            "case": {
                                "id": case_id,
                                "path": str(case_data.get("path", "")),
                                "tags": case_data.get("tags", []),
                            },
                        }
                    yield progress_event
                    for finding_event in scan.finding_events(tool_name, result):
                        yield finding_event
                    coordinator = getattr(self, "evolution", None)
                    if coordinator is not None and result is not None:
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
            if telemetry is not None:
                telemetry.finish_run(scan.scan_id, "completed", response_text)
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
            if telemetry is not None:
                telemetry.finish_run(scan.scan_id, "failed", response_text)
            raise
        finally:
            reset_auth_session_mode(auth_session_token)
            end_case_evidence_gate(case_evidence_token)
            if not evolution_finalized:
                self._finalize_evolution()
            self._teardown_traffic()
            self._active_scan = None

    async def run(self, user_input: str) -> AsyncIterator[str]:
        """Backward-compatible token-only stream."""
        async for event in self.run_events(user_input):
            if event.get("type") == "token":
                yield str(event.get("content", ""))
