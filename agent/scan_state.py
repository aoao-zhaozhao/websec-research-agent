"""Structured lifecycle state for one security scan.

LangGraph remains responsible for choosing tools.  This module records the
observable scanner lifecycle independently, so clients can render progress and
retain the evidence already produced when a scan is stopped.
"""

from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


SCAN_STAGES = ("scope", "crawl", "enumerate", "verify", "knowledge", "report")
_STAGE_INDEX = {stage: index for index, stage in enumerate(SCAN_STAGES)}
_URL_RE = re.compile(r"https?://[^\s<>'\"]+", re.IGNORECASE)

TOOL_STAGES = {
    "crawl": "crawl",
    "sitemap": "crawl",
    "extract_forms": "crawl",
    "extract_links": "crawl",
    "analyze_js": "enumerate",
    "discover_api": "enumerate",
    "render_page": "enumerate",
    "analyze_headers": "enumerate",
    "batch_scan": "enumerate",
    "decode_jwt": "verify",
    "http_post": "verify",
    "http_request": "verify",
    "test_lfi_param": "verify",
    "verify_injection": "verify",
    # New tools (v1.4 migration from Shannon)
    "test_command_injection": "verify",
    "test_ssti": "verify",
    "test_ssrf": "verify",
    "probe_internal_port": "verify",
    "test_idor": "verify",
    "test_privilege_escalation": "verify",
    "test_role_manipulation": "verify",
    "jwt_alg_none_attack": "verify",
    "jwt_hmac_brute": "verify",
    "jwt_key_confusion": "verify",
    "generate_oob_payload": "verify",
    "check_oob_callbacks": "verify",
    "search_knowledge": "knowledge",
}


def target_from_input(value: str) -> str:
    """Extract a display-safe target URL without changing the user's prompt."""
    match = _URL_RE.search(value or "")
    return match.group(0).rstrip(".,;)") if match else ""


def stage_for_tool(tool_name: str) -> str:
    return TOOL_STAGES.get(tool_name, "scope")


@dataclass
class ScanState:
    """A serializable, monotonic view of a single scan."""

    target: str = ""
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: float = field(default_factory=time.time)
    status: str = "running"
    current_stage: str = "scope"
    stages: dict[str, str] = field(
        default_factory=lambda: {stage: "pending" for stage in SCAN_STAGES}
    )
    tool_count: int = 0
    finding_count: int = 0
    error_count: int = 0
    _tool_started_at: dict[str, float] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        self.stages["scope"] = "active"

    def snapshot(self) -> dict[str, Any]:
        return {
            "id": self.scan_id,
            "target": self.target,
            "status": self.status,
            "current_stage": self.current_stage,
            "stages": dict(self.stages),
            "started_at": int(self.started_at * 1000),
            "elapsed_ms": int((time.time() - self.started_at) * 1000),
            "tool_count": self.tool_count,
            "finding_count": self.finding_count,
            "error_count": self.error_count,
        }

    def event(self, event_type: str, **data: Any) -> dict[str, Any]:
        return {"type": event_type, "scan_id": self.scan_id, "scan": self.snapshot(), **data}

    def started_event(self) -> dict[str, Any]:
        return self.event("scan_started")

    def _advance(self, stage: str) -> list[dict[str, Any]]:
        """Advance only forward; a late tool must not rewind the UI."""
        if _STAGE_INDEX[stage] <= _STAGE_INDEX[self.current_stage]:
            return []
        self.stages[self.current_stage] = "completed"
        self.current_stage = stage
        self.stages[stage] = "active"
        return [self.event("stage_started", stage=stage)]

    def start_tool(self, tool_name: str, run_id: str | None) -> list[dict[str, Any]]:
        events = self._advance(stage_for_tool(tool_name))
        self.tool_count += 1
        if run_id:
            self._tool_started_at[run_id] = time.monotonic()
        return events

    def finish_tool(
        self,
        tool_name: str,
        run_id: str | None,
        result: dict[str, Any] | None,
    ) -> dict[str, Any]:
        started = self._tool_started_at.pop(run_id, None) if run_id else None
        duration_ms = int((time.monotonic() - started) * 1000) if started else None
        status = str((result or {}).get("status", "ok"))
        if status == "error":
            self.error_count += 1
        return self.event(
            "stage_progress",
            stage=self.current_stage,
            tool=tool_name,
            run_id=run_id,
            tool_status=status,
            duration_ms=duration_ms,
        )

    def finding_events(
        self, tool_name: str, result: dict[str, Any] | None
    ) -> list[dict[str, Any]]:
        findings = (result or {}).get("findings", [])
        if not isinstance(findings, list):
            return []
        events: list[dict[str, Any]] = []
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                continue
            self.finding_count += 1
            events.append(
                self.event(
                    "finding_created",
                    finding_id=f"{self.scan_id}:{self.finding_count}:{index}",
                    tool=tool_name,
                    finding=finding,
                )
            )
        return events

    def finish(self, status: str) -> list[dict[str, Any]]:
        if self.status != "running":
            return []
        events: list[dict[str, Any]] = []
        if status == "completed":
            events.extend(self._advance("report"))
            self.stages["report"] = "completed"
        else:
            self.stages[self.current_stage] = status
        self.status = status
        events.append(self.event("scan_finished"))
        return events
