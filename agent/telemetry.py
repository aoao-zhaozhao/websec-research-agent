"""Durable v1.7 runtime telemetry for agent runs and evaluations."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_DB_PATH = Path(
    os.getenv("TELEMETRY_DB_PATH", str(Path(__file__).parent.parent / "data" / "telemetry.db"))
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


class TelemetryStore:
    """SQLite store for runs, actions, model usage, and judge outcomes."""

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
            """
        )
        self._conn.commit()

    def create_run(
        self,
        run_id: str,
        *,
        input_text: str,
        target: str,
        mode: str,
        category: str,
        model: str,
    ) -> dict[str, Any]:
        self._conn.execute(
            """
            INSERT OR IGNORE INTO telemetry_runs
                (id, input_text, target, mode, category, model, status, started_at)
            VALUES (?, ?, ?, ?, ?, ?, 'running', ?)
            """,
            (run_id, input_text, target, mode, category, model, _now_iso()),
        )
        self._conn.commit()
        return self.get_run(run_id) or {}

    def finish_run(self, run_id: str, status: str, summary: str = "") -> None:
        self._conn.execute(
            """
            UPDATE telemetry_runs
            SET status=?, finished_at=COALESCE(finished_at, ?), summary=?
            WHERE id=?
            """,
            (status, _now_iso(), summary[:4000], run_id),
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
