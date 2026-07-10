"""Pure lifecycle decisions with no model or filesystem access."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any


@dataclass(frozen=True)
class LifecyclePolicy:
    stale_after_days: int = 30
    archive_after_days: int = 90

    def __post_init__(self) -> None:
        if self.stale_after_days < 0:
            raise ValueError("stale_after_days must be non-negative")
        if self.archive_after_days < self.stale_after_days:
            raise ValueError("archive_after_days must be >= stale_after_days")


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def last_activity(record: dict[str, Any], fallback: datetime | None = None) -> datetime:
    timestamps = [
        parse_timestamp(record.get("created_at")),
        parse_timestamp(record.get("last_used_at")),
        parse_timestamp(record.get("last_patched_at")),
    ]
    return max(
        (item for item in timestamps if item is not None),
        default=fallback or datetime.now(timezone.utc),
    )


def decide_transition(
    record: dict[str, Any],
    now: datetime,
    policy: LifecyclePolicy,
) -> str | None:
    """Return the next state only; callers own all side effects."""
    now = now.astimezone(timezone.utc)
    state = str(record.get("state", "active"))
    if str(record.get("source", "bundled")) != "agent":
        return None
    if state == "archived" or bool(record.get("pinned")):
        return None
    if bool(record.get("protected_reference")):
        return None

    activity = last_activity(record, fallback=now)
    if state == "active" and activity <= now - timedelta(days=policy.stale_after_days):
        return "stale"
    if state == "stale" and activity <= now - timedelta(days=policy.archive_after_days):
        return "archived"
    return None
