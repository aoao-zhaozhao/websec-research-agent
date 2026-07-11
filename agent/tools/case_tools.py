"""Tools for storing solved-task memory as RAG-searchable case records."""

from __future__ import annotations

from langchain_core.tools import tool

from ..case_manager import get_case_manager
from ..skill_manager import CATEGORIES
from .results import Evidence, Finding, ToolResult, error_result


@tool
def case_create(
    target: str,
    title: str,
    summary: str,
    evidence: str,
    solution: str,
    failed_attempts: str = "",
    category: str = "general",
    tags: str = "",
) -> str:
    """Save a solved task as a searchable case for future RAG retrieval.

    Use after a successful or instructive scan. Capture the observed facts,
    preconditions, solution chain, and failed paths. Do not store flags,
    credentials, tokens, or other secrets. A case is not a skill: it records
    one episode and is only promoted after repeated independent evidence.
    """
    normalized_category = category.strip().lower()
    if normalized_category not in CATEGORIES:
        return error_result("case_create", target, f"Unknown category '{normalized_category}'").to_text()
    if not all(value.strip() for value in (title, summary, evidence, solution)):
        return error_result("case_create", target, "title, summary, evidence, and solution are required").to_text()

    record = get_case_manager().create(
        title=title,
        target=target,
        summary=summary,
        evidence=evidence,
        solution=solution,
        failed_attempts=failed_attempts,
        category=normalized_category,
        tags=[tag.strip() for tag in tags.split(",") if tag.strip()],
    )
    return ToolResult(
        tool="case_create",
        target=target,
        status="ok",
        summary=f"Saved case '{record['id']}'",
        raw_excerpt=f"[case_create] Saved RAG case: {record['id']}\nPath: {record['path']}",
        findings=[
            Finding(
                title=f"Case memory saved: {record['id']}",
                severity="info",
                confidence="confirmed",
                category="case_memory",
                evidence=[Evidence("case_saved", summary[:500], str(record["path"]))],
            )
        ],
        data=record,
    ).to_text()
