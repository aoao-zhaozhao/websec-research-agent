"""Compatibility facade for the durable skill evolution runtime."""

from __future__ import annotations

import os
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .evolution.config import EvolutionConfig
from .evolution.lifecycle import LifecyclePolicy, decide_transition
from .evolution.store import EvolutionStore, get_evolution_store, now_iso


SKILLS_ROOT = EvolutionConfig().skills_root

CATEGORIES = {
    "sqli": "SQL injection",
    "xss": "Cross-site scripting",
    "lfi": "Local file inclusion",
    "ssrf": "Server-side request forgery",
    "css_injection": "CSS injection / scriptless XSS",
    "auth": "Authentication and authorization",
    "recon": "Reconnaissance",
    "csp_bypass": "CSP bypass",
    "general": "General techniques",
}

FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)
SKILL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
VALID_STATES = {"active", "stale", "archived"}


class SkillAlreadyExistsError(ValueError):
    pass


@dataclass
class SkillMeta:
    name: str
    description: str = ""
    version: str = "1.0.0"
    category: str = "general"
    author: str = "agent"
    source: str = "bundled"
    tags: list[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""
    use_count: int = 0
    view_count: int = 0
    patch_count: int = 0
    state: str = "active"
    pinned: bool = False

    def to_frontmatter(self) -> str:
        return yaml.dump(
            {
                "name": self.name,
                "description": self.description,
                "version": self.version,
                "category": self.category,
                "author": self.author,
                "source": self.source,
                "tags": self.tags,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "state": self.state,
            },
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=False,
        ).strip()


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.strip().lower()).strip("-")
    return slug[:64] or "untitled"


def _resolve_category(name: str, hint: str | None = None) -> str:
    if hint and hint in CATEGORIES:
        return hint
    normalized = name.lower().replace("-", "").replace("_", "")
    for key in CATEGORIES:
        if key.replace("_", "") in normalized:
            return key
    return "general"


class SkillManager:
    """Own skill documents while delegating mutable state to SQLite."""

    def __init__(
        self,
        skills_root: Path | None = None,
        store: EvolutionStore | None = None,
    ):
        self.root = Path(skills_root) if skills_root else SKILLS_ROOT
        self.root.mkdir(parents=True, exist_ok=True)
        self.store = store or get_evolution_store()
        self._lock = threading.RLock()
        self._sync_library()

    def create(
        self,
        title: str,
        description: str,
        body: str,
        category: str | None = None,
        tags: list[str] | None = None,
    ) -> SkillMeta:
        name = _slugify(title)
        category = _resolve_category(name, category)
        if self._find_skill(name) is not None or self.store.get_skill(name) is not None:
            raise SkillAlreadyExistsError(f"skill '{name}' already exists")

        timestamp = now_iso()
        meta = SkillMeta(
            name=name,
            description=description[:1024],
            category=category,
            author="agent",
            source="agent",
            tags=tags or [],
            created_at=timestamp,
            updated_at=timestamp,
        )
        skill_path = self.root / category / name / "SKILL.md"
        content = f"---\n{meta.to_frontmatter()}\n---\n\n# {title}\n\n{body.strip()}\n"
        with self._lock:
            skill_path.parent.mkdir(parents=True, exist_ok=False)
            try:
                self._atomic_write(skill_path, content)
                self._register(skill_path, meta)
            except Exception:
                if skill_path.exists():
                    skill_path.unlink()
                if skill_path.parent.exists() and not any(skill_path.parent.iterdir()):
                    skill_path.parent.rmdir()
                raise
        return self.load_metadata(name) or meta

    def load(self, name: str, scan_id: str | None = None) -> str | None:
        """Load a skill for execution and record a use event."""
        path = self._find_skill(name)
        if path is None:
            return None
        meta = self._parse_frontmatter(path)
        self._register(path, meta)
        record = self.store.bump(meta.name, "use", scan_id=scan_id)
        if meta.state != record["state"]:
            self._write_state(path, str(record["state"]))
        return path.read_text(encoding="utf-8")

    def view(self, name: str, scan_id: str | None = None) -> str | None:
        """Inspect a skill without marking it as used."""
        path = self._find_skill(name)
        if path is None:
            return None
        meta = self._parse_frontmatter(path)
        self._register(path, meta)
        self.store.bump(meta.name, "view", scan_id=scan_id)
        return path.read_text(encoding="utf-8")

    def load_metadata(self, name: str) -> SkillMeta | None:
        path = self._find_skill(name)
        if path is None:
            record = self.store.get_skill(name)
            if not record:
                return None
            return SkillMeta(
                name=name,
                state=str(record["state"]),
                use_count=int(record["use_count"]),
                view_count=int(record["view_count"]),
                patch_count=int(record["patch_count"]),
                pinned=bool(record["pinned"]),
            )
        meta = self._parse_frontmatter(path)
        record = self._register(path, meta)
        return self._merge_runtime(meta, record)

    def list_all(
        self,
        category: str | None = None,
        *,
        include_archived: bool = False,
    ) -> list[dict[str, Any]]:
        self._sync_library()
        results: list[dict[str, Any]] = []
        for record in self.store.list_skills(include_archived=include_archived):
            if category:
                path_parts = Path(str(record["path"])).parts
                if category not in path_parts:
                    continue
            path = self.root / str(record["path"])
            meta = self._parse_frontmatter(path) if path.exists() else SkillMeta(name=str(record["name"]))
            meta = self._merge_runtime(meta, record)
            results.append(
                {
                    "name": meta.name,
                    "description": meta.description,
                    "category": meta.category,
                    "tags": meta.tags,
                    "version": meta.version,
                    "state": meta.state,
                    "source": str(record["source"]),
                    "pinned": meta.pinned,
                    "use_count": meta.use_count,
                    "view_count": meta.view_count,
                    "patch_count": meta.patch_count,
                    "path": str(record["path"]),
                }
            )
        return sorted(results, key=lambda item: item["name"])

    def patch(self, name: str, old_text: str, new_text: str) -> bool:
        path = self._find_skill(name)
        if path is None:
            return False
        with self._lock:
            meta = self._parse_frontmatter(path)
            record = self._register(path, meta)
            if str(record["source"]) != "agent":
                return False
            content = path.read_text(encoding="utf-8")
            if old_text not in content:
                return False
            timestamp = now_iso()
            updated = content.replace(old_text, new_text, 1)
            updated = re.sub(r"^updated_at: .*$", f"updated_at: {timestamp}", updated, flags=re.MULTILINE)
            self._atomic_write(path, updated)
            meta = self._parse_frontmatter(path)
            self._register(path, meta)
            record = self.store.bump(meta.name, "patch")
            if meta.state != record["state"]:
                self._write_state(path, str(record["state"]))
        return True

    def delete(self, name: str) -> bool:
        """Backward-compatible soft delete."""
        return self.archive(name)

    def archive(self, name: str, absorbed_into: str | None = None) -> bool:
        path = self._find_skill(name)
        if path is None:
            return False
        meta = self._parse_frontmatter(path)
        record = self._register(path, meta)
        if bool(record["pinned"]) or bool(record["protected_reference"]):
            return False
        if str(record["source"]) != "agent":
            return False

        archive_dir = self.root / ".archive" / str(record["id"]) / name
        archive_path = archive_dir / "SKILL.md"
        with self._lock:
            archive_dir.parent.mkdir(parents=True, exist_ok=True)
            if archive_dir.exists():
                return False
            path.parent.replace(archive_dir)
            self._write_state(archive_path, "archived")
            self.store.set_state(
                name,
                "archived",
                path=str(archive_path.relative_to(self.root)),
                absorbed_into=absorbed_into,
            )
            category_dir = path.parent.parent
            if category_dir != self.root and category_dir.exists() and not any(category_dir.iterdir()):
                category_dir.rmdir()
        return True

    def restore(self, name: str) -> bool:
        record = self.store.get_skill(name)
        if not record or record["state"] != "archived":
            return False
        archive_path = self.root / str(record["path"])
        if not archive_path.exists():
            return False
        meta = self._parse_frontmatter(archive_path)
        category = _resolve_category(name, meta.category)
        destination = self.root / category / name
        with self._lock:
            if destination.exists():
                return False
            destination.parent.mkdir(parents=True, exist_ok=True)
            archive_path.parent.replace(destination)
            restored_path = destination / "SKILL.md"
            self._write_state(restored_path, "active")
            self.store.set_state(
                name,
                "active",
                path=str(restored_path.relative_to(self.root)),
            )
            archive_id_dir = archive_path.parent.parent
            if archive_id_dir.exists() and not any(archive_id_dir.iterdir()):
                archive_id_dir.rmdir()
        return True

    def pin(self, name: str, pinned: bool = True) -> bool:
        path = self._find_skill(name)
        if path is not None:
            self._register(path, self._parse_frontmatter(path))
        return self.store.set_pinned(name, pinned)

    def set_state(self, name: str, state: str) -> bool:
        if state not in VALID_STATES:
            return False
        if state == "archived":
            return self.archive(name)
        record = self.store.get_skill(name)
        if record and record["state"] == "archived":
            return self.restore(name) if state == "active" else False
        path = self._find_skill(name)
        if path is None:
            return False
        with self._lock:
            self._write_state(path, state)
            return self.store.set_state(name, state)

    def apply_automatic_transitions(
        self,
        policy: LifecyclePolicy | None = None,
        now: datetime | None = None,
    ) -> list[dict[str, str]]:
        policy = policy or LifecyclePolicy()
        current = now or datetime.now(timezone.utc)
        self._sync_library()
        transitions: list[dict[str, str]] = []
        for record in self.store.list_skills(include_archived=False):
            target = decide_transition(record, current, policy)
            if target is None:
                continue
            previous = str(record["state"])
            changed = self.archive(str(record["name"])) if target == "archived" else self.set_state(str(record["name"]), target)
            if changed:
                transitions.append({"name": str(record["name"]), "from": previous, "to": target})
        return transitions

    def _find_skill(self, name: str) -> Path | None:
        for path in self.root.rglob("SKILL.md"):
            if ".archive" in path.parts:
                continue
            meta = self._parse_frontmatter(path)
            if meta.name == name or path.parent.name == name:
                return path
        return None

    def _sync_library(self) -> None:
        for path in self.root.rglob("SKILL.md"):
            if ".archive" in path.parts:
                continue
            self._register(path, self._parse_frontmatter(path))

    def _register(self, path: Path, meta: SkillMeta) -> dict[str, Any]:
        return self.store.register_skill(
            name=meta.name,
            path=str(path.relative_to(self.root)),
            source=meta.source,
            state=meta.state if meta.state in VALID_STATES else "active",
            created_at=meta.created_at or None,
            use_count=meta.use_count,
        )

    def _parse_frontmatter(self, path: Path) -> SkillMeta:
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
            source=str(data.get("source", "bundled")),
            tags=list(data.get("tags") or []),
            created_at=str(data.get("created_at", "")),
            updated_at=str(data.get("updated_at", "")),
            use_count=int(data.get("use_count", 0)),
            state=str(data.get("state", "active")),
        )

    @staticmethod
    def _merge_runtime(meta: SkillMeta, record: dict[str, Any]) -> SkillMeta:
        meta.state = str(record["state"])
        meta.use_count = int(record["use_count"])
        meta.view_count = int(record["view_count"])
        meta.patch_count = int(record["patch_count"])
        meta.pinned = bool(record["pinned"])
        return meta

    def _write_state(self, path: Path, state: str) -> None:
        content = path.read_text(encoding="utf-8")
        updated = re.sub(r"^state: .*$", f"state: {state}", content, flags=re.MULTILINE)
        if updated == content:
            match = FRONTMATTER_RE.match(content)
            if not match:
                return
            updated = content[: match.end(1)] + f"\nstate: {state}" + content[match.end(1) :]
        self._atomic_write(path, updated)

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        temporary.write_text(content, encoding="utf-8")
        os.replace(temporary, path)


_manager: SkillManager | None = None
_manager_lock = threading.Lock()


def get_skill_manager() -> SkillManager:
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = SkillManager()
    return _manager
