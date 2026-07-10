"""
Session persistence layer (v1.3).

SQLite-backed store for scan sessions, findings, and evidence.
Supports cross-session search via FTS5 and history APIs for the web frontend.

Uses only stdlib sqlite3 — no SQLAlchemy dependency required.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_DIR = Path(os.getenv("SESSION_DB_DIR", str(Path(__file__).parent.parent / "data")))
DB_PATH = DB_DIR / "sessions.db"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SessionDB:
    """Thread-safe SQLite store for scan sessions."""

    def __init__(self, db_path: Path | None = None):
        self._path = db_path or DB_PATH
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_schema()

    # ── Connection management ───────────────────────────────

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(str(self._path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return self._local.conn

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    # ── Schema ──────────────────────────────────────────────

    def _init_schema(self) -> None:
        conn = self._conn
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id          TEXT PRIMARY KEY,
                target      TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'running',
                started_at  TEXT NOT NULL,
                finished_at TEXT,
                summary     TEXT DEFAULT '',
                total_findings INTEGER DEFAULT 0,
                stages_completed TEXT DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                title       TEXT NOT NULL,
                severity    TEXT NOT NULL DEFAULT 'info',
                confidence  TEXT NOT NULL DEFAULT 'info',
                category    TEXT NOT NULL DEFAULT 'observation',
                url         TEXT DEFAULT '',
                evidence    TEXT DEFAULT '{}',
                reproduction TEXT DEFAULT '[]',
                created_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                event_type  TEXT NOT NULL,
                stage       TEXT DEFAULT '',
                tool_name   TEXT DEFAULT '',
                data        TEXT DEFAULT '{}',
                created_at  TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_events_scan ON scan_events(scan_id);
            CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
            CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);

            -- FTS5 for full-text search across findings
            CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
                title, category, evidence_text, content='findings',
                content_rowid='id'
            );

            -- Triggers to keep FTS in sync
            CREATE TRIGGER IF NOT EXISTS findings_ai AFTER INSERT ON findings BEGIN
                INSERT INTO findings_fts(rowid, title, category, evidence_text)
                VALUES (new.id, new.title, new.category, new.evidence);
            END;

            CREATE TRIGGER IF NOT EXISTS findings_ad AFTER DELETE ON findings BEGIN
                INSERT INTO findings_fts(findings_fts, rowid, title, category, evidence_text)
                VALUES ('delete', old.id, old.title, old.category, old.evidence);
            END;

            CREATE TRIGGER IF NOT EXISTS findings_au AFTER UPDATE ON findings BEGIN
                INSERT INTO findings_fts(findings_fts, rowid, title, category, evidence_text)
                VALUES ('delete', old.id, old.title, old.category, old.evidence);
                INSERT INTO findings_fts(rowid, title, category, evidence_text)
                VALUES (new.id, new.title, new.category, new.evidence);
            END;
            """
        )
        conn.commit()

    # ── CRUD: Scans ─────────────────────────────────────────

    def create_scan(self, scan_id: str, target: str) -> dict[str, Any]:
        now = _now_iso()
        self._conn.execute(
            "INSERT INTO scans (id, target, status, started_at) VALUES (?, ?, 'running', ?)",
            (scan_id, target, now),
        )
        self._conn.commit()
        return self.get_scan(scan_id) or {}

    def update_scan(self, scan_id: str, **kwargs) -> None:
        allowed = {"status", "finished_at", "summary", "total_findings", "stages_completed"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return
        set_clause = ", ".join(f"{k}=?" for k in updates)
        values = list(updates.values()) + [scan_id]
        self._conn.execute(f"UPDATE scans SET {set_clause} WHERE id=?", values)
        self._conn.commit()

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        return dict(row) if row else None

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ── CRUD: Findings ──────────────────────────────────────

    def add_finding(self, scan_id: str, finding: dict[str, Any]) -> int:
        now = _now_iso()
        evidence_text = json.dumps(finding.get("evidence", []), ensure_ascii=False)
        with self._conn:
            cursor = self._conn.execute(
                """INSERT INTO findings (scan_id, title, severity, confidence, category, url, evidence, reproduction, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    finding.get("title", ""),
                    finding.get("severity", "info"),
                    finding.get("confidence", "info"),
                    finding.get("category", "observation"),
                    finding.get("url", ""),
                    evidence_text,
                    json.dumps(finding.get("reproduction", []), ensure_ascii=False),
                    now,
                ),
            )
        return cursor.lastrowid or 0

    def get_findings(self, scan_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY severity DESC, created_at ASC",
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def search_findings(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        """FTS5 full-text search across findings."""
        rows = self._conn.execute(
            """SELECT f.* FROM findings f
               JOIN findings_fts ft ON f.id = ft.rowid
               WHERE findings_fts MATCH ?
               ORDER BY rank LIMIT ?""",
            (query, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── CRUD: Events ────────────────────────────────────────

    def add_event(self, scan_id: str, event_type: str, stage: str = "", tool_name: str = "", data: dict[str, Any] | None = None) -> None:
        now = _now_iso()
        self._conn.execute(
            "INSERT INTO scan_events (scan_id, event_type, stage, tool_name, data, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, event_type, stage, tool_name, json.dumps(data or {}, ensure_ascii=False), now),
        )
        self._conn.commit()

    def get_events(self, scan_id: str, event_type: str = "") -> list[dict[str, Any]]:
        if event_type:
            rows = self._conn.execute(
                "SELECT * FROM scan_events WHERE scan_id=? AND event_type=? ORDER BY id ASC",
                (scan_id, event_type),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM scan_events WHERE scan_id=? ORDER BY id ASC",
                (scan_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Stats ───────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        scans = self._conn.execute("SELECT COUNT(*) as c FROM scans").fetchone()
        findings = self._conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()
        by_severity = self._conn.execute(
            "SELECT severity, COUNT(*) as c FROM findings GROUP BY severity"
        ).fetchall()
        return {
            "total_scans": scans["c"] if scans else 0,
            "total_findings": findings["c"] if findings else 0,
            "by_severity": {r["severity"]: r["c"] for r in by_severity},
        }


# ── Singleton ──────────────────────────────────────────────────
_db: SessionDB | None = None


def get_session_db() -> SessionDB:
    global _db
    if _db is None:
        _db = SessionDB()
    return _db
