"""UTC timestamp helpers. Stored timestamps are fixed-width so they sort lexicographically."""

from __future__ import annotations

from datetime import datetime, timezone

TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_ts(value: datetime) -> str:
    """Format as UTC with microsecond precision, e.g. 2025-01-02T03:04:05.123456Z."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime(TS_FORMAT)


def now_ts() -> str:
    return format_ts(utc_now())


def parse_ts(text: str) -> str:
    """Parse a user supplied ISO-8601 timestamp; naive values are UTC. Returns stored format."""
    value = text.strip()
    if value.endswith(("Z", "z")):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as err:
        raise ValueError(
            f"invalid timestamp {text!r}: use ISO-8601, e.g. 2025-01-31T12:00:00Z"
        ) from err
    return format_ts(parsed)
