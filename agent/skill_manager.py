"""
Skill Manager — agent self-evolution engine (v1.3).

Inspired by Hermes Agent's skill system, this module provides:
  - Create / load / list / patch / delete skills (SKILL.md format)
  - Auto-categorization by vulnerability type
  - YAML frontmatter + Markdown body (agentskills.io compatible)
  - Lifecycle tracking (active → stale → archived)

Skills live in agent/skills/<category>/<name>/SKILL.md and are loaded
into the agent's context to improve future scans.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

SKILLS_ROOT = Path(__file__).parent.parent / "skills"

CATEGORIES = {
    "sqli": "SQL 注入",
    "xss": "跨站脚本",
    "lfi": "本地文件包含",
    "ssrf": "服务端请求伪造",
    "css_injection": "CSS 注入 / Scriptless XSS",
    "auth": "认证与授权",
    "recon": "侦察与信息收集",
    "csp_bypass": "CSP 绕过",
    "general": "通用技巧",
}

FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
SKILL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
VALID_STATES = {"active", "stale", "archived"}


@dataclass
class SkillMeta:
    """Parsed SKILL.md frontmatter."""

    name: str
    description: str = ""
    version: str = "1.0.0"
    category: str = "general"
    author: str = "agent"
    tags: list[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    use_count: int = 0
    state: str = "active"

    def to_frontmatter(self) -> str:
        return yaml.dump(
            {
                "name": self.name,
                "description": self.description,
                "version": self.version,
                "category": self.category,
                "author": self.author,
                "tags": self.tags,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "use_count": self.use_count,
                "state": self.state,
            },
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
        ).strip()


def _slugify(text: str) -> str:
    """Convert a title to a kebab-case skill name."""
    slug = re.sub(r"[^a-z0-9]+", "-", text.strip().lower())
    slug = slug.strip("-")
    return slug[:64] or "untitled"


def _resolve_category(name: str, hint: str | None = None) -> str:
    """Resolve category from hint or skill name."""
    if hint and hint in CATEGORIES:
        return hint
    for key in CATEGORIES:
        if key.replace("_", "") in name.lower().replace("-", "").replace("_", ""):
            return key
    return "general"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SkillManager:
    """Manage the agent's skill library."""

    def __init__(self, skills_root: Path | None = None):
        self.root = Path(skills_root) if skills_root else SKILLS_ROOT
        self.root.mkdir(parents=True, exist_ok=True)

    # ── CRUD ──────────────────────────────────────────────────

    def create(
        self,
        title: str,
        description: str,
        body: str,
        category: str | None = None,
        tags: list[str] | None = None,
    ) -> SkillMeta:
        """Create a new skill from a title, description, and body."""
        name = _slugify(title)
        category = _resolve_category(name, category)
        now = _now_iso()

        meta = SkillMeta(
            name=name,
            description=description[:1024],
            category=category,
            author="agent",
            tags=tags or [],
            created_at=now,
            updated_at=now,
        )

        skill_dir = self.root / category / name
        skill_dir.mkdir(parents=True, exist_ok=True)

        fm = meta.to_frontmatter()
        content = f"---\n{fm}\n---\n\n# {title}\n\n{body.strip()}\n"
        (skill_dir / "SKILL.md").write_text(content, encoding="utf-8")

        return meta

    def load(self, name: str) -> str | None:
        """Load a skill's full SKILL.md content by name. Returns None if not found."""
        path = self._find_skill(name)
        if path is None:
            return None
        self._bump_use_count(path)
        return path.read_text(encoding="utf-8")

    def load_metadata(self, name: str) -> SkillMeta | None:
        """Load only the metadata of a skill."""
        path = self._find_skill(name)
        if path is None:
            return None
        return self._parse_frontmatter(path)

    def list_all(self, category: str | None = None) -> list[dict[str, Any]]:
        """List all skills, optionally filtered by category."""
        results: list[dict[str, Any]] = []
        search_dir = self.root / category if category else self.root
        if not search_dir.exists():
            return results

        for md_file in sorted(search_dir.rglob("SKILL.md")):
            meta = self._parse_frontmatter(md_file)
            results.append(
                {
                    "name": meta.name,
                    "description": meta.description,
                    "category": meta.category,
                    "tags": meta.tags,
                    "version": meta.version,
                    "state": meta.state,
                    "use_count": meta.use_count,
                    "path": str(md_file.relative_to(self.root)),
                }
            )
        return results

    def patch(self, name: str, old_text: str, new_text: str) -> bool:
        """Replace old_text with new_text in a skill's SKILL.md. Returns True on success."""
        path = self._find_skill(name)
        if path is None:
            return False
        content = path.read_text(encoding="utf-8")
        if old_text not in content:
            return False
        new_content = content.replace(old_text, new_text, 1)
        # Update the updated_at timestamp
        new_content = re.sub(
            r"updated_at: .*",
            f"updated_at: {_now_iso()}",
            new_content,
        )
        path.write_text(new_content, encoding="utf-8")
        return True

    def delete(self, name: str) -> bool:
        """Delete a skill by name. Returns True if found and deleted."""
        path = self._find_skill(name)
        if path is None:
            return False
        skill_dir = path.parent
        import shutil
        shutil.rmtree(skill_dir)
        # Also clean up empty category dirs
        cat_dir = skill_dir.parent
        if cat_dir != self.root and not any(cat_dir.iterdir()):
            cat_dir.rmdir()
        return True

    def set_state(self, name: str, state: str) -> bool:
        """Transition a skill to a new lifecycle state."""
        if state not in VALID_STATES:
            return False
        path = self._find_skill(name)
        if path is None:
            return False
        content = path.read_text(encoding="utf-8")
        new_content = re.sub(r"^state: .*$", f"state: {state}", content, flags=re.MULTILINE)
        if new_content == content:
            return False
        path.write_text(new_content, encoding="utf-8")
        return True

    # ── Helpers ───────────────────────────────────────────────

    def _find_skill(self, name: str) -> Path | None:
        """Find a SKILL.md file by name across all categories."""
        for md_file in self.root.rglob("SKILL.md"):
            meta = self._parse_frontmatter(md_file)
            if meta.name == name:
                return md_file
        # Try exact directory name match as fallback
        for child in self.root.rglob(name):
            if child.is_dir():
                candidate = child / "SKILL.md"
                if candidate.exists():
                    return candidate
        return None

    def _parse_frontmatter(self, path: Path) -> SkillMeta:
        """Parse YAML frontmatter from a SKILL.md file."""
        text = path.read_text(encoding="utf-8")
        match = FRONTMATTER_RE.match(text)
        if not match:
            return SkillMeta(
                name=path.parent.name,
                description="(no frontmatter)",
                category=path.parent.parent.name if path.parent.parent != self.root else "general",
            )
        try:
            data = yaml.safe_load(match.group(1)) or {}
        except yaml.YAMLError:
            return SkillMeta(name=path.parent.name, description="(invalid YAML)")

        if not isinstance(data, dict):
            return SkillMeta(name=path.parent.name, description="(invalid frontmatter)")

        return SkillMeta(
            name=str(data.get("name", path.parent.name)),
            description=str(data.get("description", ""))[:1024],
            version=str(data.get("version", "1.0.0")),
            category=str(data.get("category", "general")),
            author=str(data.get("author", "agent")),
            tags=list(data.get("tags") or []),
            created_at=str(data.get("created_at", "")),
            updated_at=str(data.get("updated_at", "")),
            use_count=int(data.get("use_count", 0)),
            state=str(data.get("state", "active")),
        )

    def _bump_use_count(self, path: Path) -> None:
        """Increment the use_count in a skill's frontmatter."""
        content = path.read_text(encoding="utf-8")
        match = FRONTMATTER_RE.match(content)
        if not match:
            return
        fm_text = match.group(1)
        try:
            data = yaml.safe_load(fm_text) or {}
        except yaml.YAMLError:
            return
        if not isinstance(data, dict):
            return
        current = int(data.get("use_count", 0))
        data["use_count"] = current + 1
        new_fm = yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False).strip()
        new_content = content[: match.start(1)] + new_fm + content[match.end(1) :]
        path.write_text(new_content, encoding="utf-8")


# ── Singleton ──────────────────────────────────────────────────
_manager: SkillManager | None = None


def get_skill_manager() -> SkillManager:
    global _manager
    if _manager is None:
        _manager = SkillManager()
    return _manager
