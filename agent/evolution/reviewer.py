"""Deterministic skill review based on structured tool observations."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .store import EvolutionStore


CATEGORY_ALIASES = {
    "sql_injection": "sqli",
    "sqli": "sqli",
    "xss": "xss",
    "cross_site_scripting": "xss",
    "lfi": "lfi",
    "local_file_inclusion": "lfi",
    "ssrf": "ssrf",
    "jwt": "auth",
    "idor": "auth",
    "auth": "auth",
    "authentication": "auth",
    "authorization": "auth",
    "css_injection": "css_injection",
    "csp_bypass": "csp_bypass",
    "recon": "recon",
}


@dataclass(frozen=True)
class ReviewDecision:
    status: str
    report: str
    evidence: dict[str, Any]


class DeterministicSkillReviewer:
    def __init__(self, store: EvolutionStore):
        self.store = store

    def review(self, job: dict[str, Any]) -> ReviewDecision:
        try:
            payload = json.loads(str(job.get("payload") or "{}"))
        except json.JSONDecodeError:
            payload = {}
        after_id = int(payload.get("after_observation_id", 0))
        through_id = int(payload.get("through_observation_id", 0))
        observations = self.store.list_observations(after_id, through_id)

        strong_findings: list[dict[str, str]] = []
        tool_counts: dict[str, int] = {}
        errors = 0
        skill_mutation = False
        reflection_requested_skill = False

        for observation in observations:
            tool_name = str(observation["tool_name"])
            result = observation.get("result") or {}
            tool_counts[tool_name] = tool_counts.get(tool_name, 0) + 1
            if str(result.get("status", observation.get("status"))) == "error":
                errors += 1
            if tool_name in {"skill_create", "skill_patch"} and result.get("status") == "ok":
                skill_mutation = True
            if tool_name == "scan_reflect":
                suggestions = (result.get("data") or {}).get("suggestions") or []
                reflection_requested_skill = reflection_requested_skill or any(
                    item.get("action") == "consider_skill_create"
                    for item in suggestions
                    if isinstance(item, dict)
                )
            for finding in result.get("findings") or []:
                if not isinstance(finding, dict):
                    continue
                confidence = str(finding.get("confidence", ""))
                if confidence not in {"confirmed", "likely"}:
                    continue
                category = self._normalize_category(str(finding.get("category", "general")))
                strong_findings.append(
                    {
                        "title": str(finding.get("title", "Untitled finding"))[:300],
                        "category": category,
                        "confidence": confidence,
                        "tool": tool_name,
                    }
                )

        covered = self._covered_agent_categories()
        uncovered = sorted({item["category"] for item in strong_findings} - covered)
        action_required = bool(uncovered) and not skill_mutation
        if reflection_requested_skill and not covered and not skill_mutation:
            action_required = True
            uncovered = uncovered or ["general"]

        evidence = {
            "observation_range": [after_id, through_id],
            "observation_count": len(observations),
            "tool_counts": tool_counts,
            "error_count": errors,
            "strong_findings": strong_findings[:50],
            "covered_agent_categories": sorted(covered),
            "uncovered_categories": uncovered,
            "skill_mutation_observed": skill_mutation,
        }
        if action_required:
            titles = "; ".join(item["title"] for item in strong_findings[:8]) or "reusable scan technique"
            report = (
                "A deterministic skill review found reusable evidence without an "
                f"agent-created skill in these categories: {', '.join(uncovered)}. "
                f"Evidence: {titles}. Before finishing the next scan, call skill_list, "
                "inspect related skills with skill_view, then call skill_create or "
                "skill_patch when the technique is reusable. If no reusable lesson "
                "exists, call scan_reflect with no successful techniques and record "
                "the reason in failed_attempts."
            )
            return ReviewDecision("action_required", report, evidence)

        reason = "a skill mutation was already recorded" if skill_mutation else "no uncovered reusable finding was found"
        report = (
            f"Deterministic review completed: {reason}. "
            f"Reviewed {len(observations)} observations with {errors} tool errors."
        )
        return ReviewDecision("no_action", report, evidence)

    def _covered_agent_categories(self) -> set[str]:
        covered: set[str] = set()
        for skill in self.store.list_skills(include_archived=False):
            if str(skill.get("source")) != "agent":
                continue
            path = Path(str(skill.get("path", "")))
            if path.parts:
                covered.add(path.parts[0])
        return covered

    @staticmethod
    def _normalize_category(category: str) -> str:
        normalized = category.strip().lower().replace("-", "_").replace(" ", "_")
        return CATEGORY_ALIASES.get(normalized, "general")

