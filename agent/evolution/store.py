"""SQLite-backed telemetry and durable evolution jobs."""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def now_iso(now: datetime | None = None) -> str:
    value = now or datetime.now(timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class EvolutionStore:
    """Concurrent-safe authoritative store for mutable skill state."""

    def __init__(self, db_path: Path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._connections: set[sqlite3.Connection] = set()
        self._connections_lock = threading.Lock()
        self._init_schema()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(str(self.path), timeout=30, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=30000")
            self._local.conn = conn
            with self._connections_lock:
                self._connections.add(conn)
        return self._local.conn

    def close(self) -> None:
        with self._connections_lock:
            connections = list(self._connections)
            self._connections.clear()
        for conn in connections:
            conn.close()
        self._local.conn = None

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS skills (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                path TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'agent',
                state TEXT NOT NULL DEFAULT 'active'
                    CHECK(state IN ('active', 'stale', 'archived')),
                pinned INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_used_at TEXT,
                last_viewed_at TEXT,
                last_patched_at TEXT,
                archived_at TEXT,
                absorbed_into TEXT,
                use_count INTEGER NOT NULL DEFAULT 0,
                view_count INTEGER NOT NULL DEFAULT 0,
                patch_count INTEGER NOT NULL DEFAULT 0,
                revision INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS skill_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                skill_id TEXT NOT NULL REFERENCES skills(id),
                event_type TEXT NOT NULL,
                scan_id TEXT,
                metadata TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS skill_references (
                owner_type TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                skill_id TEXT NOT NULL REFERENCES skills(id),
                protected INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY(owner_type, owner_id, skill_id)
            );

            CREATE TABLE IF NOT EXISTS runtime_counters (
                name TEXT PRIMARY KEY,
                value INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evolution_jobs (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                trigger TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                trigger_count INTEGER NOT NULL DEFAULT 0,
                attempts INTEGER NOT NULL DEFAULT 0,
                payload TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                error TEXT,
                available_at TEXT,
                lease_owner TEXT,
                lease_expires_at TEXT
            );

            CREATE TABLE IF NOT EXISTS evolution_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                tool_name TEXT NOT NULL,
                status TEXT NOT NULL,
                result TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evolution_reviews (
                id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL UNIQUE REFERENCES evolution_jobs(id),
                status TEXT NOT NULL,
                report TEXT NOT NULL,
                evidence TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                acknowledged_at TEXT
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_one_open_job_per_kind
            ON evolution_jobs(kind)
            WHERE status IN ('pending', 'running');
            """
        )
        self._ensure_column("evolution_jobs", "available_at", "TEXT")
        self._ensure_column("evolution_jobs", "lease_owner", "TEXT")
        self._ensure_column("evolution_jobs", "lease_expires_at", "TEXT")
        self._conn.commit()

    def _ensure_column(self, table: str, column: str, definition: str) -> None:
        columns = {
            str(row["name"])
            for row in self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if column not in columns:
            self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def register_skill(
        self,
        *,
        name: str,
        path: str,
        source: str,
        state: str,
        created_at: str | None,
        use_count: int = 0,
    ) -> dict[str, Any]:
        timestamp = now_iso()
        anchor = created_at or timestamp
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO skills (
                    id, name, path, source, state, created_at, updated_at, use_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    path=excluded.path,
                    source=excluded.source,
                    use_count=MAX(skills.use_count, excluded.use_count)
                """,
                (str(uuid.uuid4()), name, path, source, state, anchor, timestamp, max(0, use_count)),
            )
        record = self.get_skill(name)
        if record is None:
            raise RuntimeError(f"failed to register skill {name}")
        return record

    def get_skill(self, name: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            """
            SELECT s.*,
                   EXISTS(
                       SELECT 1 FROM skill_references r
                       WHERE r.skill_id=s.id AND r.protected=1
                   ) AS protected_reference
            FROM skills s WHERE s.name=?
            """,
            (name,),
        ).fetchone()
        return dict(row) if row else None

    def list_skills(self, include_archived: bool = True) -> list[dict[str, Any]]:
        where = "" if include_archived else "WHERE s.state != 'archived'"
        rows = self._conn.execute(
            f"""
            SELECT s.*,
                   EXISTS(
                       SELECT 1 FROM skill_references r
                       WHERE r.skill_id=s.id AND r.protected=1
                   ) AS protected_reference
            FROM skills s {where} ORDER BY s.name
            """
        ).fetchall()
        return [dict(row) for row in rows]

    def bump(
        self,
        name: str,
        event_type: str,
        *,
        scan_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        columns = {
            "use": ("use_count", "last_used_at"),
            "view": ("view_count", "last_viewed_at"),
            "patch": ("patch_count", "last_patched_at"),
        }
        if event_type not in columns:
            raise ValueError(f"unsupported skill event: {event_type}")
        count_column, time_column = columns[event_type]
        timestamp = now_iso(now)
        with self._conn:
            cursor = self._conn.execute(
                f"""
                UPDATE skills SET
                    {count_column}={count_column}+1,
                    {time_column}=?,
                    updated_at=?,
                    revision=revision+1,
                    state=CASE WHEN ? IN ('use', 'patch') AND state='stale'
                               THEN 'active' ELSE state END
                WHERE name=? AND state != 'archived'
                """,
                (timestamp, timestamp, event_type, name),
            )
            if cursor.rowcount != 1:
                raise KeyError(name)
            self._conn.execute(
                """
                INSERT INTO skill_events(skill_id, event_type, scan_id, metadata, created_at)
                SELECT id, ?, ?, ?, ? FROM skills WHERE name=?
                """,
                (event_type, scan_id, json.dumps(metadata or {}, ensure_ascii=False), timestamp, name),
            )
        record = self.get_skill(name)
        if record is None:
            raise KeyError(name)
        return record

    def set_state(
        self,
        name: str,
        state: str,
        *,
        path: str | None = None,
        absorbed_into: str | None = None,
        now: datetime | None = None,
    ) -> bool:
        if state not in {"active", "stale", "archived"}:
            raise ValueError(state)
        timestamp = now_iso(now)
        assignments = ["state=?", "updated_at=?", "revision=revision+1"]
        values: list[Any] = [state, timestamp]
        if path is not None:
            assignments.append("path=?")
            values.append(path)
        if state == "archived":
            assignments.extend(["archived_at=?", "absorbed_into=?"])
            values.extend([timestamp, absorbed_into])
        else:
            assignments.extend(["archived_at=NULL", "absorbed_into=NULL"])
        values.append(name)
        with self._conn:
            cursor = self._conn.execute(
                f"UPDATE skills SET {', '.join(assignments)} WHERE name=?",
                values,
            )
        return cursor.rowcount == 1

    def set_pinned(self, name: str, pinned: bool) -> bool:
        with self._conn:
            cursor = self._conn.execute(
                "UPDATE skills SET pinned=?, updated_at=?, revision=revision+1 WHERE name=?",
                (int(pinned), now_iso(), name),
            )
        return cursor.rowcount == 1

    def set_reference(
        self,
        owner_type: str,
        owner_id: str,
        skill_name: str,
        *,
        protected: bool = True,
    ) -> bool:
        """Register an external reference, ready for cron/workflow adapters."""
        with self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO skill_references(owner_type, owner_id, skill_id, protected)
                SELECT ?, ?, id, ? FROM skills WHERE name=?
                ON CONFLICT(owner_type, owner_id, skill_id)
                DO UPDATE SET protected=excluded.protected
                """,
                (owner_type, owner_id, int(protected), skill_name),
            )
        return cursor.rowcount == 1

    def remove_reference(self, owner_type: str, owner_id: str, skill_name: str) -> bool:
        with self._conn:
            cursor = self._conn.execute(
                """
                DELETE FROM skill_references
                WHERE owner_type=? AND owner_id=?
                  AND skill_id=(SELECT id FROM skills WHERE name=?)
                """,
                (owner_type, owner_id, skill_name),
            )
        return cursor.rowcount == 1

    def record_observation(
        self,
        tool_name: str,
        result: dict[str, Any] | None,
        *,
        scan_id: str | None = None,
        now: datetime | None = None,
    ) -> int:
        timestamp = now_iso(now)
        bounded = result or {}
        serialized = json.dumps(bounded, ensure_ascii=False, sort_keys=True)
        if len(serialized) > 50_000:
            serialized = json.dumps(
                {
                    "tool": bounded.get("tool", tool_name),
                    "status": bounded.get("status", "unknown"),
                    "summary": str(bounded.get("summary", ""))[:1000],
                    "findings": list(bounded.get("findings") or [])[:20],
                    "data": bounded.get("data", {}),
                    "truncated": True,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        with self._conn:
            cursor = self._conn.execute(
                """
                INSERT INTO evolution_observations(
                    scan_id, tool_name, status, result, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    tool_name,
                    str(bounded.get("status", "unknown")),
                    serialized,
                    timestamp,
                ),
            )
        return int(cursor.lastrowid or 0)

    def list_observations(self, after_id: int, through_id: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT * FROM evolution_observations
            WHERE id > ? AND id <= ? ORDER BY id
            """,
            (after_id, through_id),
        ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                item["result"] = json.loads(str(item["result"]))
            except json.JSONDecodeError:
                item["result"] = {}
            results.append(item)
        return results

    def last_reviewed_observation_id(self) -> int:
        row = self._conn.execute(
            "SELECT value FROM runtime_counters WHERE name='last_reviewed_observation_id'"
        ).fetchone()
        return int(row["value"]) if row else 0

    def increment_tool_counter(self) -> int:
        timestamp = now_iso()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO runtime_counters(name, value, updated_at)
                VALUES ('tool_calls_since_review', 1, ?)
                ON CONFLICT(name) DO UPDATE SET
                    value=value+1, updated_at=excluded.updated_at
                """,
                (timestamp,),
            )
        return self.tool_counter()

    def tool_counter(self) -> int:
        row = self._conn.execute(
            "SELECT value FROM runtime_counters WHERE name='tool_calls_since_review'"
        ).fetchone()
        return int(row["value"]) if row else 0

    def schedule_review_if_due(self, interval: int) -> dict[str, Any] | None:
        if interval <= 0:
            return None
        count = self.tool_counter()
        if count < interval:
            return None
        job_id = str(uuid.uuid4())
        timestamp = now_iso()
        observation = self._conn.execute(
            "SELECT COALESCE(MAX(id), 0) AS value FROM evolution_observations"
        ).fetchone()
        through_id = int(observation["value"]) if observation else 0
        payload = json.dumps(
            {
                "after_observation_id": self.last_reviewed_observation_id(),
                "through_observation_id": through_id,
            },
            sort_keys=True,
        )
        try:
            with self._conn:
                self._conn.execute(
                    """
                    INSERT INTO evolution_jobs(
                        id, kind, trigger, status, trigger_count, payload,
                        created_at, available_at
                    ) VALUES (?, 'skill_review', 'tool_interval', 'pending', ?, ?, ?, ?)
                    """,
                    (job_id, count, payload, timestamp, timestamp),
                )
        except sqlite3.IntegrityError:
            return None
        return self.get_job(job_id)

    def claim_next_job(
        self,
        worker_id: str,
        *,
        lease_seconds: int = 60,
        max_attempts: int = 3,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        current = now or datetime.now(timezone.utc)
        timestamp = now_iso(current)
        lease_expires = now_iso(current + timedelta(seconds=max(1, lease_seconds)))
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            expired = conn.execute(
                """
                SELECT * FROM evolution_jobs
                WHERE status='running' AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= ?
                """,
                (timestamp,),
            ).fetchall()
            conn.execute(
                """
                UPDATE evolution_jobs SET
                    status=CASE WHEN attempts >= ? THEN 'failed' ELSE 'pending' END,
                    available_at=?, lease_owner=NULL, lease_expires_at=NULL,
                    error=CASE WHEN attempts >= ? THEN 'worker lease expired' ELSE error END,
                    finished_at=CASE WHEN attempts >= ? THEN ? ELSE finished_at END
                WHERE status='running' AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= ?
                """,
                (max_attempts, timestamp, max_attempts, max_attempts, timestamp, timestamp),
            )
            for expired_job in expired:
                if int(expired_job["attempts"]) >= max_attempts:
                    self._advance_review_window(dict(expired_job), timestamp)
            row = conn.execute(
                """
                SELECT id FROM evolution_jobs
                WHERE status='pending' AND attempts < ?
                  AND COALESCE(available_at, created_at) <= ?
                ORDER BY created_at LIMIT 1
                """,
                (max_attempts, timestamp),
            ).fetchone()
            if row is None:
                conn.commit()
                return None
            job_id = str(row["id"])
            cursor = conn.execute(
                """
                UPDATE evolution_jobs SET
                    status='running', attempts=attempts+1, started_at=?,
                    lease_owner=?, lease_expires_at=?, error=NULL
                WHERE id=? AND status='pending'
                """,
                (timestamp, worker_id, lease_expires, job_id),
            )
            if cursor.rowcount != 1:
                conn.rollback()
                return None
            conn.commit()
            return self.get_job(job_id)
        except Exception:
            conn.rollback()
            raise

    def retry_job(
        self,
        job_id: str,
        *,
        error: str,
        retry_delay_seconds: int,
        max_attempts: int,
        now: datetime | None = None,
    ) -> bool:
        current = now or datetime.now(timezone.utc)
        record = self.get_job(job_id)
        if not record or record["status"] != "running":
            return False
        exhausted = int(record["attempts"]) >= max_attempts
        available_at = now_iso(current + timedelta(seconds=max(0, retry_delay_seconds)))
        with self._conn:
            cursor = self._conn.execute(
                """
                UPDATE evolution_jobs SET status=?, available_at=?, error=?,
                    lease_owner=NULL, lease_expires_at=NULL,
                    finished_at=CASE WHEN ? THEN ? ELSE NULL END
                WHERE id=? AND status='running'
                """,
                (
                    "failed" if exhausted else "pending",
                    available_at,
                    error[:1000],
                    exhausted,
                    now_iso(current),
                    job_id,
                ),
            )
            if cursor.rowcount == 1 and exhausted:
                self._advance_review_window(record, now_iso(current))
        return cursor.rowcount == 1

    def _advance_review_window(self, job: dict[str, Any], timestamp: str) -> None:
        trigger_count = int(job.get("trigger_count", 0))
        self._conn.execute(
            """
            INSERT INTO runtime_counters(name, value, updated_at)
            VALUES ('tool_calls_since_review', 0, ?)
            ON CONFLICT(name) DO UPDATE SET
                value=MAX(0, value-?), updated_at=excluded.updated_at
            """,
            (timestamp, trigger_count),
        )
        try:
            payload = json.loads(str(job.get("payload") or "{}"))
        except json.JSONDecodeError:
            payload = {}
        through_id = int(payload.get("through_observation_id", 0))
        self._conn.execute(
            """
            INSERT INTO runtime_counters(name, value, updated_at)
            VALUES ('last_reviewed_observation_id', ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                value=MAX(value, excluded.value), updated_at=excluded.updated_at
            """,
            (through_id, timestamp),
        )

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM evolution_jobs WHERE id=?", (job_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_jobs(self, status: str | None = None) -> list[dict[str, Any]]:
        if status:
            rows = self._conn.execute(
                "SELECT * FROM evolution_jobs WHERE status=? ORDER BY created_at", (status,)
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM evolution_jobs ORDER BY created_at"
            ).fetchall()
        return [dict(row) for row in rows]

    def save_review(
        self,
        job_id: str,
        *,
        status: str,
        report: str,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        if status not in {"action_required", "no_action", "acknowledged"}:
            raise ValueError(status)
        review_id = str(uuid.uuid4())
        timestamp = now_iso()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO evolution_reviews(
                    id, job_id, status, report, evidence, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_id) DO UPDATE SET
                    status=excluded.status,
                    report=excluded.report,
                    evidence=excluded.evidence
                """,
                (
                    review_id,
                    job_id,
                    status,
                    report,
                    json.dumps(evidence, ensure_ascii=False, sort_keys=True),
                    timestamp,
                ),
            )
        row = self._conn.execute(
            "SELECT * FROM evolution_reviews WHERE job_id=?", (job_id,)
        ).fetchone()
        if row is None:
            raise RuntimeError(f"failed to save review for job {job_id}")
        return self._decode_review(row)

    @staticmethod
    def _decode_review(row: sqlite3.Row) -> dict[str, Any]:
        review = dict(row)
        try:
            review["evidence"] = json.loads(str(review["evidence"]))
        except json.JSONDecodeError:
            review["evidence"] = {}
        return review

    def list_reviews(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM evolution_reviews ORDER BY created_at DESC LIMIT ?",
            (max(1, min(limit, 200)),),
        ).fetchall()
        return [self._decode_review(row) for row in rows]

    def pending_review(self) -> dict[str, Any] | None:
        row = self._conn.execute(
            """
            SELECT * FROM evolution_reviews
            WHERE status='action_required' AND acknowledged_at IS NULL
            ORDER BY created_at LIMIT 1
            """
        ).fetchone()
        return self._decode_review(row) if row else None

    def acknowledge_pending_review(self) -> bool:
        pending = self.pending_review()
        if pending is None:
            return False
        timestamp = now_iso()
        with self._conn:
            cursor = self._conn.execute(
                """
                UPDATE evolution_reviews
                SET status='acknowledged', acknowledged_at=?
                WHERE id=? AND acknowledged_at IS NULL
                """,
                (timestamp, pending["id"]),
            )
        return cursor.rowcount == 1

    def finish_job(self, job_id: str, *, success: bool, error: str = "") -> bool:
        timestamp = now_iso()
        with self._conn:
            cursor = self._conn.execute(
                """
                UPDATE evolution_jobs
                SET status=?, finished_at=?, error=?
                WHERE id=? AND status IN ('pending', 'running')
                """,
                ("completed" if success else "failed", timestamp, error[:1000], job_id),
            )
            if cursor.rowcount == 1 and success:
                job = self.get_job(job_id)
                if job:
                    self._advance_review_window(job, timestamp)
        return cursor.rowcount == 1


_store: EvolutionStore | None = None
_store_lock = threading.Lock()


def get_evolution_store(db_path: Path | None = None) -> EvolutionStore:
    global _store
    if db_path is not None:
        return EvolutionStore(db_path)
    if _store is None:
        from .config import EvolutionConfig

        with _store_lock:
            if _store is None:
                _store = EvolutionStore(EvolutionConfig().db_path)
    return _store
