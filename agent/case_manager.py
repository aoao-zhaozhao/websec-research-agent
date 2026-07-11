"""Filesystem-backed case memory for solved scans and CTFs."""

from __future__ import annotations

import os
import re
import uuid
from pathlib import Path

import yaml

from .evolution.store import now_iso


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    return slug[:56] or "case"


class CaseManager:
    """Store structured, searchable lessons without promoting them to skills."""

    def __init__(self, root: Path | None = None):
        self.root = root or Path(
            os.getenv("AGENT_CASES_DIR", str(Path(__file__).parent / "knowledge" / "cases"))
        )
        self.root.mkdir(parents=True, exist_ok=True)

    def create(
        self,
        *,
        title: str,
        target: str,
        summary: str,
        evidence: str,
        solution: str,
        failed_attempts: str = "",
        category: str = "general",
        tags: list[str] | None = None,
        source: str = "agent",
    ) -> dict[str, str | list[str]]:
        case_id = f"{_slugify(title)}-{uuid.uuid4().hex[:8]}"
        path = self.root / f"{case_id}.md"
        metadata = {
            "id": case_id,
            "title": title.strip()[:200],
            "target": target.strip()[:500],
            "category": category.strip().lower()[:64] or "general",
            "tags": sorted({tag.strip()[:64] for tag in (tags or []) if tag.strip()}),
            "source": source,
            "created_at": now_iso(),
        }
        sections = [
            f"# {metadata['title']}",
            "## Summary",
            summary.strip(),
            "## Evidence",
            evidence.strip(),
            "## Resolution",
            solution.strip(),
        ]
        if failed_attempts.strip():
            sections.extend(["## Failed Attempts", failed_attempts.strip()])
        content = f"---\n{yaml.safe_dump(metadata, allow_unicode=True, sort_keys=False).strip()}\n---\n\n" + "\n\n".join(sections) + "\n"
        path.write_text(content, encoding="utf-8")
        return {"id": case_id, "path": str(path), "tags": metadata["tags"]}

    def count_similar(self, category: str, tags: list[str]) -> int:
        """Count independent case records that can justify a skill promotion."""
        wanted_tags = {tag.strip().lower() for tag in tags if tag.strip()}
        count = 0
        for path in self.root.glob("*.md"):
            text = path.read_text(encoding="utf-8")
            if not text.startswith("---\n"):
                continue
            closing = text.find("\n---\n", 4)
            if closing < 0:
                continue
            try:
                metadata = yaml.safe_load(text[4:closing]) or {}
            except yaml.YAMLError:
                continue
            if str(metadata.get("category", "")).lower() != category.lower():
                continue
            case_tags = {str(tag).lower() for tag in metadata.get("tags", [])}
            if wanted_tags and not wanted_tags.intersection(case_tags):
                continue
            count += 1
        return count


_manager: CaseManager | None = None


def get_case_manager() -> CaseManager:
    global _manager
    if _manager is None:
        _manager = CaseManager()
    return _manager
