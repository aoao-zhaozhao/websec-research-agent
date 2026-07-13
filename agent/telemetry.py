"""Durable v1.7 runtime telemetry for agent runs and evaluations."""

from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


DEFAULT_DB_PATH = Path(
    os.getenv("TELEMETRY_DB_PATH", str(Path(__file__).parent.parent / "data" / "telemetry.db"))
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json(value: Any) -> str:
    return json.dumps(_redact(value), ensure_ascii=False, sort_keys=True, default=str)


def _redact(value: Any) -> Any:
    """Remove common credentials before durable storage."""
    secret_keys = {"authorization", "cookie", "password", "passwd", "secret", "api_key", "apikey", "token"}
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if str(key).lower().replace("-", "_") in secret_keys else _redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if not isinstance(value, str):
        return value
    text = value
    for pattern in (
        r"(?i)\b(?:[a-z0-9_-]*(?:ctf|flag)|flag)\{[^}\r\n]{1,512}\}",
        r"(?i)(bearer\s+)[^\s,;]+",
        r"(?i)((?:api[_-]?key|token|password|passwd|secret)\s*[=:]\s*)[^\s&;,]+",
        r"(?i)(cookie\s*[:=]\s*)[^\r\n]+",
    ):
        text = re.sub(pattern, lambda match: f"{match.group(1)}[REDACTED]" if match.lastindex else "[REDACTED]", text)
    return text


class TelemetryStore:
    """SQLite store for durable conversations, runs, actions, and evaluations."""

    def __init__(self, db_path: Path | str | None = None):
        self.path = Path(db_path or DEFAULT_DB_PATH)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_schema()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(str(self.path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return self._local.conn

    def close(self) -> None:
        if hasattr(self._local, "conn") and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS telemetry_runs (
                id TEXT PRIMARY KEY,
                input_text TEXT NOT NULL DEFAULT '',
                target TEXT NOT NULL DEFAULT '',
                mode TEXT NOT NULL DEFAULT 'production',
                category TEXT NOT NULL DEFAULT 'web',
                model TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'running',
                started_at TEXT NOT NULL,
                finished_at TEXT,
                summary TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS conversations (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL DEFAULT '新扫描',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active'
            );

            CREATE TABLE IF NOT EXISTS conversation_messages (
                id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
                role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
                content TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS telemetry_actions (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES telemetry_runs(id) ON DELETE CASCADE,
                tool_run_id TEXT NOT NULL,
                sequence_number INTEGER NOT NULL,
                tool_name TEXT NOT NULL,
                input_data TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'running',
                protocol_error TEXT,
                output_excerpt TEXT NOT NULL DEFAULT '',
                result_data TEXT NOT NULL DEFAULT '{}',
                effective INTEGER,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                duration_ms INTEGER,
                UNIQUE(run_id, tool_run_id)
            );

            CREATE TABLE IF NOT EXISTS telemetry_model_usage (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES telemetry_runs(id) ON DELETE CASCADE,
                model TEXT NOT NULL DEFAULT '',
                input_tokens INTEGER NOT NULL DEFAULT 0,
                output_tokens INTEGER NOT NULL DEFAULT 0,
                cached_tokens INTEGER NOT NULL DEFAULT 0,
                cost_usd REAL,
                raw_usage TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS telemetry_evaluations (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL UNIQUE REFERENCES telemetry_runs(id) ON DELETE CASCADE,
                judge TEXT NOT NULL DEFAULT 'manual',
                outcome TEXT NOT NULL,
                verified INTEGER NOT NULL DEFAULT 0,
                candidate_fingerprint TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_telemetry_runs_started
                ON telemetry_runs(started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_telemetry_runs_category
                ON telemetry_runs(category, mode);
            CREATE INDEX IF NOT EXISTS idx_telemetry_actions_run
                ON telemetry_actions(run_id, sequence_number);
            CREATE INDEX IF NOT EXISTS idx_telemetry_usage_run
                ON telemetry_model_usage(run_id);
            CREATE INDEX IF NOT EXISTS idx_conversations_updated
                ON conversations(updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_conversation_messages_conversation
                ON conversation_messages(conversation_id, created_at);
            """
        )
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(telemetry_runs)")}
        if "conversation_id" not in columns:
            self._conn.execute(
                "ALTER TABLE telemetry_runs ADD COLUMN conversation_id TEXT REFERENCES conversations(id) ON DELETE SET NULL"
            )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_telemetry_runs_conversation ON telemetry_runs(conversation_id, started_at DESC)"
        )
        self._redact_existing_records()
        self._backfill_cached_tokens()
        self._conn.commit()

    def _redact_existing_records(self) -> None:
        """Upgrade previously persisted telemetry when redaction rules expand."""
        for table, fields in {
            "telemetry_runs": ("input_text", "target", "summary"),
            "telemetry_actions": ("input_data", "output_excerpt", "result_data", "protocol_error"),
            "telemetry_model_usage": ("raw_usage",),
            "conversation_messages": ("content",),
        }.items():
            rows = self._conn.execute(f"SELECT rowid, {', '.join(fields)} FROM {table}").fetchall()
            for row in rows:
                updates = {field: _redact(row[field]) for field in fields if isinstance(row[field], str)}
                changed = {field: value for field, value in updates.items() if value != row[field]}
                if changed:
                    assignments = ", ".join(f"{field}=?" for field in changed)
                    self._conn.execute(
                        f"UPDATE {table} SET {assignments} WHERE rowid=?",
                        (*changed.values(), row["rowid"]),
                    )

    def _backfill_cached_tokens(self) -> None:
        """Recover cache reads recorded before the provider field was mapped."""
        rows = self._conn.execute(
            "SELECT id, raw_usage FROM telemetry_model_usage WHERE cached_tokens=0"
        ).fetchall()
        for row in rows:
            try:
                usage = json.loads(row["raw_usage"])
            except (TypeError, json.JSONDecodeError):
                continue
            if not isinstance(usage, dict):
                continue
            details = usage.get("input_token_details") or usage.get("prompt_tokens_details") or {}
            if not isinstance(details, dict):
                details = {}
            cached_tokens = usage.get(
                "cached_tokens",
                usage.get(
                    "prompt_cache_hit_tokens",
                    details.get("cached_tokens", details.get("cache_read", 0)),
                ),
            )
            try:
                cached_tokens = max(0, int(cached_tokens or 0))
            except (TypeError, ValueError):
                continue
            if cached_tokens:
                self._conn.execute(
                    "UPDATE telemetry_model_usage SET cached_tokens=? WHERE id=?",
                    (cached_tokens, row["id"]),
                )

    def create_conversation(self, title: str = "新扫描", conversation_id: str | None = None) -> dict[str, Any]:
        conversation_id = conversation_id or str(uuid.uuid4())
        now = _now_iso()
        self._conn.execute(
            """
            INSERT OR IGNORE INTO conversations (id, title, created_at, updated_at, status)
            VALUES (?, ?, ?, ?, 'active')
            """,
            (conversation_id, _redact(title)[:80] or "新扫描", now, now),
        )
        self._conn.commit()
        return self.get_conversation(conversation_id) or {}

    def list_conversations(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT c.*, COUNT(r.id) AS run_count, MAX(r.started_at) AS last_run_at
            FROM conversations c LEFT JOIN telemetry_runs r ON r.conversation_id=c.id
            GROUP BY c.id ORDER BY c.updated_at DESC LIMIT ?
            """,
            (max(1, min(limit, 200)),),
        ).fetchall()
        return [dict(row) for row in rows]

    def get_conversation(self, conversation_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM conversations WHERE id=?", (conversation_id,)).fetchone()
        if row is None:
            return None
        conversation = dict(row)
        runs = self._conn.execute(
            "SELECT * FROM telemetry_runs WHERE conversation_id=? ORDER BY started_at",
            (conversation_id,),
        ).fetchall()
        messages = [dict(item) for item in self._conn.execute(
            "SELECT role, content, created_at FROM conversation_messages WHERE conversation_id=? ORDER BY created_at, id",
            (conversation_id,),
        ).fetchall()]
        for run in runs:
            messages.append({"role": "user", "content": run["input_text"], "created_at": run["started_at"]})
            if run["summary"]:
                messages.append({"role": "assistant", "content": run["summary"], "created_at": run["finished_at"] or run["started_at"]})
        messages.sort(key=lambda item: str(item["created_at"]))
        conversation["messages"] = messages
        conversation["runs"] = [self.get_run(str(item["id"])) for item in runs]
        return conversation

    def rename_conversation(self, conversation_id: str, title: str) -> dict[str, Any] | None:
        self._conn.execute(
            "UPDATE conversations SET title=?, updated_at=? WHERE id=?",
            (_redact(title)[:80] or "新扫描", _now_iso(), conversation_id),
        )
        self._conn.commit()
        return self.get_conversation(conversation_id)

    def delete_conversation(self, conversation_id: str) -> bool:
        # Retain de-identified run telemetry for aggregate metrics and audits.
        cursor = self._conn.execute("DELETE FROM conversations WHERE id=?", (conversation_id,))
        self._conn.commit()
        return cursor.rowcount > 0

    def delete_all_conversations(self) -> int:
        cursor = self._conn.execute("DELETE FROM conversations")
        self._conn.commit()
        return cursor.rowcount

    def import_conversations(self, sessions: list[dict[str, Any]]) -> int:
        imported = 0
        for session in sessions[:100]:
            conversation_id = str(session.get("id", "")).strip()[:120]
            if not conversation_id or self.get_conversation(conversation_id) is not None:
                continue
            title = str(session.get("title", "新扫描"))
            created_at = self._legacy_time(session.get("createdAt"))
            self._conn.execute(
                "INSERT INTO conversations (id, title, created_at, updated_at, status) VALUES (?, ?, ?, ?, 'active')",
                (conversation_id, _redact(title)[:80] or "新扫描", created_at, created_at),
            )
            for message in session.get("messages", [])[:500]:
                role = str(message.get("role", ""))
                if role not in {"user", "assistant"}:
                    continue
                self._conn.execute(
                    "INSERT INTO conversation_messages (id, conversation_id, role, content, created_at) VALUES (?, ?, ?, ?, ?)",
                    (str(uuid.uuid4()), conversation_id, role, _redact(str(message.get("content", "")))[:12000], self._legacy_time(message.get("at"))),
                )
            imported += 1
        self._conn.commit()
        return imported

    @staticmethod
    def _legacy_time(value: Any) -> str:
        try:
            return datetime.fromtimestamp(float(value) / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (TypeError, ValueError, OSError):
            return _now_iso()

    def create_run(
        self,
        run_id: str,
        *,
        input_text: str,
        target: str,
        mode: str,
        category: str,
        model: str,
        conversation_id: str | None = None,
    ) -> dict[str, Any]:
        self._conn.execute(
            """
            INSERT OR IGNORE INTO telemetry_runs
                (id, input_text, target, mode, category, model, conversation_id, status, started_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'running', ?)
            """,
            (run_id, _redact(input_text), _redact(target), mode, category, model, conversation_id, _now_iso()),
        )
        if conversation_id:
            self._conn.execute("UPDATE conversations SET updated_at=? WHERE id=?", (_now_iso(), conversation_id))
        self._conn.commit()
        return self.get_run(run_id) or {}

    def finish_run(self, run_id: str, status: str, summary: str = "") -> None:
        self._conn.execute(
            """
            UPDATE telemetry_runs
            SET status=?, finished_at=COALESCE(finished_at, ?), summary=?
            WHERE id=?
            """,
            (status, _now_iso(), _redact(summary)[:4000], run_id),
        )
        self._conn.execute(
            """
            UPDATE conversations SET updated_at=?
            WHERE id=(SELECT conversation_id FROM telemetry_runs WHERE id=?)
            """,
            (_now_iso(), run_id),
        )
        self._conn.commit()

    def update_run_summary(self, run_id: str, summary: str) -> None:
        self._conn.execute(
            "UPDATE telemetry_runs SET summary=? WHERE id=?",
            (_redact(summary)[:4000], run_id),
        )
        self._conn.commit()

    def start_action(
        self,
        run_id: str,
        *,
        tool_run_id: str,
        tool_name: str,
        input_data: Any,
    ) -> str:
        tool_run_id = tool_run_id or str(uuid.uuid4())
        existing = self._conn.execute(
            "SELECT id FROM telemetry_actions WHERE run_id=? AND tool_run_id=?",
            (run_id, tool_run_id),
        ).fetchone()
        if existing:
            return str(existing["id"])
        row = self._conn.execute(
            "SELECT COALESCE(MAX(sequence_number), 0) + 1 AS n FROM telemetry_actions WHERE run_id=?",
            (run_id,),
        ).fetchone()
        action_id = str(uuid.uuid4())
        self._conn.execute(
            """
            INSERT INTO telemetry_actions
                (id, run_id, tool_run_id, sequence_number, tool_name, input_data, started_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (action_id, run_id, tool_run_id, int(row["n"]), tool_name, _json(input_data), _now_iso()),
        )
        self._conn.commit()
        return action_id

    def finish_action(
        self,
        run_id: str,
        *,
        tool_run_id: str,
        tool_name: str,
        status: str,
        output_excerpt: str,
        result_data: dict[str, Any] | None,
        duration_ms: int | None,
        protocol_error: str | None = None,
        effective: bool | None = None,
    ) -> None:
        tool_run_id = tool_run_id or f"orphan:{uuid.uuid4()}"
        existing = self._conn.execute(
            "SELECT id FROM telemetry_actions WHERE run_id=? AND tool_run_id=?",
            (run_id, tool_run_id),
        ).fetchone()
        if existing is None:
            self.start_action(
                run_id,
                tool_run_id=tool_run_id,
                tool_name=tool_name,
                input_data={},
            )
        self._conn.execute(
            """
            UPDATE telemetry_actions
            SET status=?, protocol_error=?, output_excerpt=?, result_data=?, effective=?,
                finished_at=?, duration_ms=?
            WHERE run_id=? AND tool_run_id=?
            """,
            (
                status,
                protocol_error,
                output_excerpt[:6000],
                _json(result_data or {}),
                None if effective is None else int(effective),
                _now_iso(),
                duration_ms,
                run_id,
                tool_run_id,
            ),
        )
        self._conn.commit()

    def record_model_usage(
        self,
        run_id: str,
        *,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cached_tokens: int,
        cost_usd: float | None,
        raw_usage: dict[str, Any],
    ) -> None:
        self._conn.execute(
            """
            INSERT INTO telemetry_model_usage
                (id, run_id, model, input_tokens, output_tokens, cached_tokens, cost_usd, raw_usage, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid4()),
                run_id,
                model,
                max(0, int(input_tokens)),
                max(0, int(output_tokens)),
                max(0, int(cached_tokens)),
                cost_usd,
                _json(raw_usage),
                _now_iso(),
            ),
        )
        self._conn.commit()

    def record_evaluation(
        self,
        run_id: str,
        *,
        judge: str,
        outcome: str,
        verified: bool,
        candidate_fingerprint: str = "",
        reason: str = "",
    ) -> dict[str, Any]:
        if outcome not in {"solved", "failed", "inconclusive"}:
            raise ValueError("outcome must be solved, failed, or inconclusive")
        self._conn.execute(
            """
            INSERT INTO telemetry_evaluations
                (id, run_id, judge, outcome, verified, candidate_fingerprint, reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET
                judge=excluded.judge, outcome=excluded.outcome, verified=excluded.verified,
                candidate_fingerprint=excluded.candidate_fingerprint, reason=excluded.reason,
                created_at=excluded.created_at
            """,
            (
                str(uuid.uuid4()),
                run_id,
                judge[:120],
                outcome,
                int(verified),
                candidate_fingerprint[:256],
                reason[:2000],
                _now_iso(),
            ),
        )
        self._conn.commit()
        row = self._conn.execute(
            "SELECT * FROM telemetry_evaluations WHERE run_id=?", (run_id,)
        ).fetchone()
        return dict(row) if row else {}

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM telemetry_runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            return None
        run = dict(row)
        actions = self._conn.execute(
            "SELECT * FROM telemetry_actions WHERE run_id=? ORDER BY sequence_number", (run_id,)
        ).fetchall()
        run["actions"] = [self._decode_action(item) for item in actions]
        usage = self._conn.execute(
            "SELECT * FROM telemetry_model_usage WHERE run_id=? ORDER BY created_at", (run_id,)
        ).fetchall()
        run["model_usage"] = [self._decode_usage(item) for item in usage]
        evaluation = self._conn.execute(
            "SELECT * FROM telemetry_evaluations WHERE run_id=?", (run_id,)
        ).fetchone()
        run["evaluation"] = dict(evaluation) if evaluation else None
        return run

    def list_runs(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM telemetry_runs ORDER BY started_at DESC LIMIT ?",
            (max(1, min(limit, 200)),),
        ).fetchall()
        return [dict(row) for row in rows]

    def metrics(self, category: str | None = None, mode: str | None = None) -> dict[str, Any]:
        clauses: list[str] = []
        values: list[Any] = []
        if category:
            clauses.append("category=?")
            values.append(category)
        if mode:
            clauses.append("mode=?")
            values.append(mode)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        run_count = int(self._conn.execute(f"SELECT COUNT(*) AS c FROM telemetry_runs{where}", values).fetchone()["c"])
        completed = int(self._conn.execute(f"SELECT COUNT(*) AS c FROM telemetry_runs{where} AND status='completed'" if where else "SELECT COUNT(*) AS c FROM telemetry_runs WHERE status='completed'", values).fetchone()["c"])
        action_where = f" WHERE r.{' AND r.'.join(clauses)}" if clauses else ""
        action_rows = self._conn.execute(
            f"""
            SELECT a.status, a.protocol_error
            FROM telemetry_actions a JOIN telemetry_runs r ON r.id=a.run_id
            {action_where}
            """,
            values,
        ).fetchall()
        total_actions = len(action_rows)
        tool_errors = sum(row["status"] == "error" for row in action_rows)
        protocol_failures = sum(row["status"] == "protocol_error" for row in action_rows)
        first_rows = self._conn.execute(
            f"""
            SELECT a.status, a.effective
            FROM telemetry_actions a
            JOIN telemetry_runs r ON r.id=a.run_id
            JOIN (
                SELECT run_id, MIN(sequence_number) AS first_sequence
                FROM telemetry_actions GROUP BY run_id
            ) first_action ON first_action.run_id=a.run_id
                AND first_action.first_sequence=a.sequence_number
            {action_where}
            """,
            values,
        ).fetchall()
        first_attempts = len(first_rows)
        first_effective = sum(row["effective"] == 1 for row in first_rows)
        eval_where = f" WHERE r.{' AND r.'.join(clauses)}" if clauses else ""
        evaluation = self._conn.execute(
            f"""
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN e.outcome='solved' AND e.verified=1 THEN 1 ELSE 0 END) AS solved
            FROM telemetry_evaluations e JOIN telemetry_runs r ON r.id=e.run_id
            {eval_where}
            """,
            values,
        ).fetchone()
        usage = self._conn.execute(
            f"""
            SELECT COALESCE(SUM(u.input_tokens), 0) AS input_tokens,
                   COALESCE(SUM(u.output_tokens), 0) AS output_tokens,
                   COALESCE(SUM(u.cached_tokens), 0) AS cached_tokens,
                   COUNT(u.id) AS records,
                   COUNT(u.cost_usd) AS priced_records,
                   SUM(u.cost_usd) AS cost_usd
            FROM telemetry_model_usage u JOIN telemetry_runs r ON r.id=u.run_id
            {action_where}
            """,
            values,
        ).fetchone()
        result = {
            "runs": {"total": run_count, "completed": completed},
            "actions": {
                "total": total_actions,
                "tool_errors": tool_errors,
                "tool_failure_rate": tool_errors / total_actions if total_actions else None,
                "protocol_failures": protocol_failures,
                "protocol_failure_rate": protocol_failures / total_actions if total_actions else None,
            },
            "first_effective_action": {
                "attempts": first_attempts,
                "effective": first_effective,
                "rate": first_effective / first_attempts if first_attempts else None,
            },
            "solve_rate": {
                "evaluated": int(evaluation["total"] or 0),
                "solved": int(evaluation["solved"] or 0),
                "rate": (int(evaluation["solved"] or 0) / int(evaluation["total"] or 0))
                if evaluation["total"]
                else None,
            },
            "model_usage": {
                "records": int(usage["records"]),
                "input_tokens": int(usage["input_tokens"]),
                "output_tokens": int(usage["output_tokens"]),
                "cached_tokens": int(usage["cached_tokens"]),
                "cache_hit_rate": (
                    int(usage["cached_tokens"]) / int(usage["input_tokens"])
                    if int(usage["input_tokens"]) > 0
                    else None
                ),
                "cost_usd": float(usage["cost_usd"]) if usage["priced_records"] else None,
                "priced_records": int(usage["priced_records"]),
            },
        }
        if category is None:
            category_rows = self._conn.execute("SELECT DISTINCT category FROM telemetry_runs ORDER BY category").fetchall()
            result["by_category"] = {
                str(row["category"]): self.metrics(category=str(row["category"]), mode=mode)
                for row in category_rows
            }
        return result

    def usage_stats(self, date_range: str = "all") -> dict[str, Any]:
        """Aggregate durable model usage for the browser statistics view."""
        if date_range not in {"all", "7d", "30d"}:
            raise ValueError("date_range must be all, 7d, or 30d")

        clauses: list[str] = []
        values: list[Any] = []
        if date_range != "all":
            days = int(date_range[:-1])
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days - 1)).strftime("%Y-%m-%dT00:00:00Z")
            clauses.append("r.started_at >= ?")
            values.append(cutoff)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        usage_rows = self._conn.execute(
            f"""
            SELECT substr(r.started_at, 1, 10) AS day,
                   COALESCE(NULLIF(u.model, ''), NULLIF(r.model, ''), 'unknown') AS model,
                   COALESCE(SUM(u.input_tokens), 0) AS input_tokens,
                   COALESCE(SUM(u.output_tokens), 0) AS output_tokens,
                   COALESCE(SUM(u.cached_tokens), 0) AS cached_tokens
            FROM telemetry_runs r
            LEFT JOIN telemetry_model_usage u ON u.run_id=r.id
            {where}
            GROUP BY substr(r.started_at, 1, 10), COALESCE(NULLIF(u.model, ''), NULLIF(r.model, ''), 'unknown')
            ORDER BY substr(r.started_at, 1, 10), COALESCE(NULLIF(u.model, ''), NULLIF(r.model, ''), 'unknown')
            """,
            values,
        ).fetchall()
        run_rows = self._conn.execute(
            f"""
            SELECT substr(r.started_at, 1, 10) AS day,
                   COUNT(*) AS sessions,
                   MAX(CASE WHEN r.finished_at IS NOT NULL
                       THEN CAST((julianday(r.finished_at) - julianday(r.started_at)) * 86400000 AS INTEGER)
                       ELSE 0 END) AS longest_session_ms
            FROM telemetry_runs r
            {where}
            GROUP BY day
            ORDER BY day
            """,
            values,
        ).fetchall()

        daily: dict[str, dict[str, Any]] = {
            str(row["day"]): {
                "date": str(row["day"]),
                "tokens": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "cached_tokens": 0,
                "sessions": 0,
                "longest_session_ms": 0,
            }
            for row in run_rows
        }
        models: dict[str, dict[str, Any]] = {}
        for row in usage_rows:
            day = str(row["day"])
            item = daily.setdefault(day, {
                "date": day, "tokens": 0, "input_tokens": 0, "output_tokens": 0,
                "cached_tokens": 0, "sessions": 0, "longest_session_ms": 0,
            })
            model = str(row["model"])
            input_tokens = int(row["input_tokens"] or 0)
            output_tokens = int(row["output_tokens"] or 0)
            cached_tokens = int(row["cached_tokens"] or 0)
            item["input_tokens"] += input_tokens
            item["output_tokens"] += output_tokens
            item["cached_tokens"] += cached_tokens
            item["tokens"] += input_tokens + output_tokens
            aggregate = models.setdefault(model, {
                "model": model, "input_tokens": 0, "output_tokens": 0,
                "cached_tokens": 0, "tokens": 0,
            })
            aggregate["input_tokens"] += input_tokens
            aggregate["output_tokens"] += output_tokens
            aggregate["cached_tokens"] += cached_tokens
            aggregate["tokens"] += input_tokens + output_tokens

        for row in run_rows:
            item = daily[str(row["day"])]
            item["sessions"] = int(row["sessions"] or 0)
            item["longest_session_ms"] = int(row["longest_session_ms"] or 0)

        day_items = sorted(daily.values(), key=lambda item: item["date"])
        active_dates = [datetime.strptime(item["date"], "%Y-%m-%d").date() for item in day_items if item["sessions"]]
        active_set = set(active_dates)
        current_streak = 0
        cursor = datetime.now(timezone.utc).date()
        while cursor in active_set:
            current_streak += 1
            cursor -= timedelta(days=1)
        longest_streak = 0
        streak = 0
        previous = None
        for day in active_dates:
            streak = streak + 1 if previous and day - previous == timedelta(days=1) else 1
            longest_streak = max(longest_streak, streak)
            previous = day
        total_tokens = sum(item["tokens"] for item in day_items)
        total_sessions = sum(item["sessions"] for item in day_items)
        most_active = max(day_items, key=lambda item: (item["tokens"], item["sessions"]), default=None)
        longest_session = max((item["longest_session_ms"] for item in day_items), default=0)
        model_items = sorted(models.values(), key=lambda item: item["tokens"], reverse=True)

        return {
            "range": date_range,
            "overview": {
                "total_tokens": total_tokens,
                "total_sessions": total_sessions,
                "active_days": len(active_dates),
                "longest_session_ms": longest_session,
                "longest_streak": longest_streak,
                "current_streak": current_streak,
                "most_active_day": most_active["date"] if most_active else None,
                "favorite_model": model_items[0]["model"] if model_items else None,
            },
            "daily": day_items,
            "models": model_items,
        }

    @staticmethod
    def _decode_action(row: sqlite3.Row) -> dict[str, Any]:
        action = dict(row)
        for key in ("input_data", "result_data"):
            try:
                action[key] = json.loads(action[key])
            except json.JSONDecodeError:
                action[key] = {}
        return action

    @staticmethod
    def _decode_usage(row: sqlite3.Row) -> dict[str, Any]:
        usage = dict(row)
        try:
            usage["raw_usage"] = json.loads(usage["raw_usage"])
        except json.JSONDecodeError:
            usage["raw_usage"] = {}
        return usage
