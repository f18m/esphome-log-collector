"""Consistent, sanitized export tarballs.

Consistency: every query runs inside one read transaction on a WAL snapshot, so a
running collector cannot produce a half-written view. Only data that was read from the
database is archived (never SQLite files, source secret files or unredacted
configuration) and every archive member is written under a fixed, collector-chosen path,
so user input can never influence archive paths.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import sqlite3
import tarfile
import tempfile
import time
from pathlib import Path
from typing import IO, Iterator, Sequence

from . import SUPPORTED_ESPHOME_VERSION, __version__
from .config import DEVICE_NAME_RE
from .parsing import strip_ansi
from .redact import Redactor
from .storage import connect
from .timeutil import now_ts, parse_ts, utc_now

EXPORT_PREFIX = "esphome-log-export-"
EXPORT_SUFFIX = ".tar.gz"
TMP_PREFIX = ".export-tmp-"
EXPORT_NAME_RE = re.compile(r"^esphome-log-export-\d{8}T\d{6}Z-[0-9a-f]{8}\.tar\.gz$")
FORMAT_VERSION = 1

_LOG_FIELDS = ("id", "ts", "device", "address", "session_id", "event_type", "level", "component",
               "device_time", "message", "raw")


class ExportError(Exception):
    pass


def _stage(export_dir: Path) -> IO[bytes]:
    return tempfile.TemporaryFile(dir=export_dir, prefix=TMP_PREFIX)


def _jsonl(fh: IO[bytes], rows: Iterator[dict]) -> int:
    count = 0
    for row in rows:
        fh.write(json.dumps(row, ensure_ascii=False, sort_keys=False).encode("utf-8") + b"\n")
        count += 1
    return count


def _event_rows(conn: sqlite3.Connection, device: str, start: str | None, end: str | None) -> Iterator[dict]:
    sql = "SELECT " + ", ".join(_LOG_FIELDS) + " FROM events WHERE device=?"
    params: list = [device]
    if start:
        sql += " AND ts >= ?"
        params.append(start)
    if end:
        sql += " AND ts < ?"
        params.append(end)
    sql += " ORDER BY ts, id"
    cur = conn.execute(sql, params)
    while True:
        rows = cur.fetchmany(1000)
        if not rows:
            return
        for r in rows:
            rec = {("timestamp" if k == "ts" else k): r[k] for k in _LOG_FIELDS}
            rec["clean"] = strip_ansi(r["raw"])
            yield rec


def create_export(
    db_path: Path,
    export_dir: Path,
    devices: Sequence[str] | None = None,
    start: str | None = None,
    end: str | None = None,
    include_configs: bool = True,
    redactor: Redactor | None = None,
) -> Path:
    """Create an export tarball and return its path. start is inclusive, end exclusive (UTC)."""
    for name in devices or ():
        if not DEVICE_NAME_RE.match(name):
            raise ExportError(f"invalid device name {name!r}")
    try:
        start_ts = parse_ts(start) if start else None
        end_ts = parse_ts(end) if end else None
    except ValueError as err:
        raise ExportError(str(err)) from err
    if start_ts and end_ts and start_ts >= end_ts:
        raise ExportError("start must be earlier than end")
    redactor = redactor or Redactor()
    export_dir.mkdir(parents=True, exist_ok=True)

    members: list[tuple[str, IO[bytes], int, str, int | None]] = []  # arcname, file, size, sha, records
    staged: list[IO[bytes]] = []
    tmp_path: Path | None = None
    conn = connect(db_path, readonly=True)
    try:
        conn.execute("BEGIN")  # one consistent snapshot for everything below
        known = [r[0] for r in conn.execute("SELECT DISTINCT device FROM events ORDER BY device")]
        known += [r[0] for r in conn.execute("SELECT device FROM device_status") if r[0] not in known]
        selected = list(devices) if devices else known
        selected = sorted(dict.fromkeys(d for d in selected if DEVICE_NAME_RE.match(d)))
        counts: dict[str, int] = {}

        def add(arcname: str, fh: IO[bytes], records: int | None) -> None:
            fh.flush()
            fh.seek(0)
            digest = hashlib.sha256()
            size = 0
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
                size += len(chunk)
            fh.seek(0)
            members.append((arcname, fh, size, digest.hexdigest(), records))

        for device in selected:
            fh = _stage(export_dir)
            staged.append(fh)
            counts[device] = _jsonl(fh, _event_rows(conn, device, start_ts, end_ts))
            add(f"logs/{device}.jsonl", fh, counts[device])

        placeholders = ",".join("?" * len(selected))
        sess_sql = ("SELECT session_id, device, address, started_at, ended_at, end_reason, line_count FROM sessions "
                    f"WHERE device IN ({placeholders})")
        sess_params: list = list(selected)
        if start_ts:
            sess_sql += " AND (ended_at IS NULL OR ended_at >= ?)"
            sess_params.append(start_ts)
        if end_ts:
            sess_sql += " AND started_at < ?"
            sess_params.append(end_ts)
        fh = _stage(export_dir)
        staged.append(fh)
        n = _jsonl(fh, (dict(r) for r in conn.execute(sess_sql + " ORDER BY started_at", sess_params)))
        add("metadata/sessions.jsonl", fh, n)

        status = [dict(r) for r in conn.execute(
            f"SELECT * FROM device_status WHERE device IN ({placeholders}) ORDER BY device", selected)]
        fh = _stage(export_dir)
        staged.append(fh)
        fh.write(json.dumps(status, indent=2).encode("utf-8"))
        add("metadata/device_status.json", fh, len(status))

        config_files = 0
        if include_configs:
            for device in selected:
                rows = conn.execute(
                    "SELECT id, captured_at, source_hash, content FROM config_snapshots WHERE device=? ORDER BY id",
                    (device,)).fetchall()
                keep = [r for r in rows if (not start_ts or r["captured_at"] >= start_ts)
                        and (not end_ts or r["captured_at"] < end_ts)]
                before = [r for r in rows if start_ts and r["captured_at"] < start_ts]
                if before:
                    keep.insert(0, before[-1])  # the configuration in effect when the window opened
                for r in keep:
                    fh = _stage(export_dir)
                    staged.append(fh)
                    # defence in depth: snapshots are redacted when stored and again here
                    fh.write(redactor.redact_text(r["content"]).encode("utf-8"))
                    stamp = re.sub(r"[^0-9TZ]", "", r["captured_at"][:19] + "Z")
                    add(f"configs/{device}/{stamp}-{r['id']}.yaml", fh, None)
                    config_files += 1
        conn.execute("COMMIT")

        created = now_ts()
        manifest = {
            "format_version": FORMAT_VERSION,
            "created_at": created,
            "generator": {"name": "esphome-log-collector", "version": __version__,
                          "esphome_version": SUPPORTED_ESPHOME_VERSION},
            "filters": {"devices": list(devices) if devices else None, "start": start_ts, "end": end_ts,
                        "range": "start inclusive, end exclusive, UTC", "include_configs": include_configs},
            "timestamps": "UTC ISO-8601 with microseconds, assigned by the collector when a line is received; "
                          "'device_time' is the device clock text (if any) parsed from the line",
            "log_format": "JSON Lines; one event per line; fields: " + ", ".join(
                ["timestamp" if f == "ts" else f for f in _LOG_FIELDS] + ["clean (raw with ANSI sequences removed)"]),
            "redaction": "configuration snapshots are redacted; credentials, source secret files and "
                         "SQLite files are never included",
            "devices": {d: {"events": counts[d]} for d in selected},
            "files": [{"path": a, "size": s, "sha256": h, **({"records": r} if r is not None else {})}
                      for a, _, s, h, r in members],
        }
        manifest_bytes = json.dumps(manifest, indent=2).encode("utf-8")

        final = export_dir / f"{EXPORT_PREFIX}{utc_now():%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}{EXPORT_SUFFIX}"
        fd, tmp_name = tempfile.mkstemp(prefix=TMP_PREFIX, suffix=EXPORT_SUFFIX, dir=export_dir)
        tmp_path = Path(tmp_name)
        mtime = time.time()
        with os.fdopen(fd, "wb") as raw_out, tarfile.open(fileobj=raw_out, mode="w:gz") as tar:
            info = tarfile.TarInfo("manifest.json")
            info.size, info.mtime, info.mode = len(manifest_bytes), mtime, 0o644
            tar.addfile(info, io.BytesIO(manifest_bytes))
            for arcname, fh, size, _, _ in members:
                info = tarfile.TarInfo(arcname)
                info.size, info.mtime, info.mode = size, mtime, 0o644
                tar.addfile(info, fh)
            raw_out.flush()
            os.fsync(raw_out.fileno())
        os.replace(tmp_path, final)
        tmp_path = None
        return final
    except sqlite3.Error as err:
        raise ExportError(f"database error while exporting: {err}") from err
    finally:
        conn.close()
        for fh in staged:
            fh.close()
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()
