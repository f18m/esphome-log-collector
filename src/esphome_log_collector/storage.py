"""SQLite storage: the structured source of truth for collected events and metadata.

* WAL journal, synchronous=NORMAL (durable across process crashes; a power loss can only
  lose the last few transactions, never corrupt the database), foreign keys on.
* Every write is its own short transaction, so lines are persisted promptly.
* auto_vacuum=INCREMENTAL lets retention return space to the filesystem.
* Timestamps are UTC, ISO-8601 with microseconds ("...Z"), assigned by the collector
  when a line is received. The device's own clock (if present in the line) is kept
  separately as `device_time`.
"""

from __future__ import annotations

import sqlite3
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .parsing import parse_line
from .timeutil import now_ts

SCHEMA_VERSION = 1

# event types
LOG = "log"
SESSION_START = "session_start"
SESSION_END = "session_end"
CONNECTED = "connected"
DISCONNECTED = "disconnected"
RETRY = "retry_scheduled"
GAP = "gap"
COLLECTOR_ERROR = "collector_error"
COLLECTOR_EVENTS = (SESSION_START, SESSION_END, CONNECTED, DISCONNECTED, RETRY, GAP, COLLECTOR_ERROR)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    device      TEXT NOT NULL,
    address     TEXT,
    session_id  TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    level       TEXT,
    component   TEXT,
    device_time TEXT,
    message     TEXT,
    raw         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_device_ts ON events(device, ts);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    device     TEXT NOT NULL,
    address    TEXT,
    started_at TEXT NOT NULL,
    ended_at   TEXT,
    end_reason TEXT,
    line_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_device ON sessions(device, started_at);
CREATE TABLE IF NOT EXISTS device_status (
    device       TEXT PRIMARY KEY,
    address      TEXT,
    backend      TEXT,
    source       TEXT,
    state        TEXT NOT NULL,
    session_id   TEXT,
    updated_at   TEXT NOT NULL,
    last_line_at TEXT,
    last_error   TEXT,
    last_error_at TEXT,
    attempts     INTEGER NOT NULL DEFAULT 0,
    next_retry_at TEXT
);
CREATE TABLE IF NOT EXISTS config_snapshots (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device       TEXT NOT NULL,
    captured_at  TEXT NOT NULL,
    source_hash  TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    content      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_device ON config_snapshots(device, captured_at);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def new_session_id() -> str:
    return uuid.uuid4().hex


def connect(path: Path, readonly: bool = False) -> sqlite3.Connection:
    target, uri = (f"file:{path}?mode=ro", True) if readonly else (str(path), False)
    conn = sqlite3.connect(target, uri=uri, timeout=30, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


class Storage:
    """Read/write access used by the collector. Thread-safe through a single lock."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        fresh = not path.exists()
        self._lock = threading.RLock()
        self._conn = connect(path)
        if fresh:
            self._conn.execute("PRAGMA auto_vacuum=INCREMENTAL")  # only effective before tables exist
        mode = self._conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        if mode.lower() != "wal":
            raise RuntimeError(f"could not enable WAL journal mode on {path} (got {mode!r}); is it on a network filesystem?")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA journal_size_limit=67108864")
        self._conn.executescript(_SCHEMA)
        self._conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),)
        )
        self._conn.execute(
            "UPDATE sessions SET ended_at=COALESCE(ended_at, ?), end_reason=COALESCE(end_reason, 'collector_crashed_or_killed') "
            "WHERE ended_at IS NULL", (now_ts(),),
        )

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def checkpoint(self) -> None:
        """Fold the WAL back into the database file (best effort; readers may defer it)."""
        with self._lock:
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def close(self) -> None:
        with self._lock:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            finally:
                self._conn.close()

    # --- sessions -------------------------------------------------------------------
    def start_session(self, device: str, address: str | None) -> tuple[str, str | None]:
        """Create a session; returns (session_id, timestamp of the device's last stored event)."""
        session_id = new_session_id()
        ts = now_ts()
        with self.transaction() as conn:
            prev = conn.execute(
                "SELECT MAX(ts) FROM events WHERE device=?", (device,)
            ).fetchone()[0]
            conn.execute(
                "INSERT INTO sessions(session_id, device, address, started_at) VALUES (?,?,?,?)",
                (session_id, device, address, ts),
            )
        return session_id, prev

    def end_session(self, session_id: str, reason: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "UPDATE sessions SET ended_at=?, end_reason=? WHERE session_id=?", (now_ts(), reason, session_id)
            )

    # --- events ---------------------------------------------------------------------
    def add_event(
        self, device: str, address: str | None, session_id: str, event_type: str, raw: str,
        ts: str | None = None, parse: bool = False,
    ) -> str:
        """Persist one event. `raw` is the redacted input; parsed fields are best-effort extras."""
        ts = ts or now_ts()
        parsed = parse_line(raw) if parse else None
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO events(ts, device, address, session_id, event_type, level, component, device_time, message, raw) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    ts, device, address, session_id, event_type,
                    parsed.level if parsed else None, parsed.component if parsed else None,
                    parsed.device_time if parsed else None, parsed.message if parsed else raw, raw,
                ),
            )
            if event_type == LOG:
                conn.execute("UPDATE sessions SET line_count=line_count+1 WHERE session_id=?", (session_id,))
        return ts

    def add_log(self, device: str, address: str | None, session_id: str, raw: str) -> str:
        return self.add_event(device, address, session_id, LOG, raw, parse=True)

    # --- status ---------------------------------------------------------------------
    def set_status(
        self, device: str, *, state: str, address: str | None = None, backend: str | None = None,
        source: str | None = None, session_id: str | None = None, error: str | None = None,
        attempts: int | None = None, next_retry_at: str | None = None, last_line_at: str | None = None,
    ) -> None:
        ts = now_ts()
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO device_status(device, address, backend, source, state, session_id, updated_at, attempts) "
                "VALUES (?,?,?,?,?,?,?,0) ON CONFLICT(device) DO NOTHING",
                (device, address, backend, source, state, session_id, ts),
            )
            fields: dict[str, Any] = {"state": state, "updated_at": ts, "session_id": session_id,
                                      "next_retry_at": next_retry_at}
            if address is not None:
                fields["address"] = address
            if backend is not None:
                fields["backend"] = backend
            if source is not None:
                fields["source"] = source
            if error is not None:
                fields.update(last_error=error, last_error_at=ts)
            if attempts is not None:
                fields["attempts"] = attempts
            if last_line_at is not None:
                fields["last_line_at"] = last_line_at
            assignments = ", ".join(f"{k}=?" for k in fields)
            conn.execute(f"UPDATE device_status SET {assignments} WHERE device=?", (*fields.values(), device))

    def mark_all_stopped(self) -> None:
        with self.transaction() as conn:
            conn.execute("UPDATE device_status SET state='stopped', session_id=NULL, next_retry_at=NULL, updated_at=?",
                         (now_ts(),))

    # --- config snapshots -----------------------------------------------------------
    def latest_snapshot(self, device: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM config_snapshots WHERE device=? ORDER BY id DESC LIMIT 1", (device,)
            ).fetchone()

    def first_event_id(self, device: str, offset: int) -> int | None:
        """id of the event `offset` positions from the newest one of a device (None if fewer exist)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM events WHERE device=? ORDER BY id DESC LIMIT 1 OFFSET ?", (device, offset)
            ).fetchone()
        return row[0] if row else None

    def add_snapshot(self, device: str, source_hash: str, content_hash: str, content: str) -> None:
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO config_snapshots(device, captured_at, source_hash, content_hash, content) VALUES (?,?,?,?,?)",
                (device, now_ts(), source_hash, content_hash, content),
            )

    # --- misc -----------------------------------------------------------------------
    def used_bytes(self) -> int:
        """Bytes in use by live pages: (page_count - freelist_count) * page_size."""
        with self._lock:
            page_size = self._conn.execute("PRAGMA page_size").fetchone()[0]
            pages = self._conn.execute("PRAGMA page_count").fetchone()[0]
            free = self._conn.execute("PRAGMA freelist_count").fetchone()[0]
        return (pages - free) * page_size

    def integrity_check(self) -> str:
        with self._lock:
            return self._conn.execute("PRAGMA integrity_check").fetchone()[0]
