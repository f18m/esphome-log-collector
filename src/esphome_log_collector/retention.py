"""Bounded retention cleanup, safe to run while collection is active.

Deletion happens in small committed batches through the collector's own connection, so
writers are only ever blocked for the duration of one batch. At most
`max_batches_per_run` batches are deleted per run; remaining work is picked up by the
next run (and reported in the log).
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from datetime import timedelta
from pathlib import Path

from . import storage as st
from .config import RetentionConfig
from .export import EXPORT_PREFIX, EXPORT_SUFFIX, TMP_PREFIX
from .timeutil import format_ts, utc_now

log = logging.getLogger("retention")

STALE_TMP_SECONDS = 24 * 3600


class Retention:
    def __init__(self, storage: st.Storage, retention: RetentionConfig, export_dir: Path) -> None:
        self.storage = storage
        self.cfg = retention
        self.export_dir = export_dir
        self._budget = 0

    async def run_once(self) -> dict[str, int]:
        """Apply every policy once; returns counts of deleted items."""
        stats = {"events_age": 0, "events_device": 0, "events_size": 0, "sessions": 0,
                 "config_snapshots": 0, "exports": 0, "tmp": 0}
        self._budget = self.cfg.max_batches_per_run
        cfg = self.cfg
        if cfg.max_age_days:
            cutoff = format_ts(utc_now() - timedelta(days=cfg.max_age_days))
            stats["events_age"] += await self._delete_batches("ts < ?", (cutoff,), "ts")
        for device, limits in cfg.per_device.items():
            if limits.max_age_days:
                cutoff = format_ts(utc_now() - timedelta(days=limits.max_age_days))
                stats["events_device"] += await self._delete_batches("device = ? AND ts < ?", (device, cutoff), "ts")
            if limits.max_events:
                stats["events_device"] += await self._enforce_device_count(device, limits.max_events)
        if cfg.max_total_size_mb:
            stats["events_size"] += await self._enforce_size(int(cfg.max_total_size_mb * 1024 * 1024))
        stats["sessions"] = self._prune_sessions()
        stats["config_snapshots"] = self._prune_snapshots()
        stats["exports"], stats["tmp"] = self._prune_exports()
        self._finish()
        if any(stats.values()):
            log.info("retention run deleted: %s", ", ".join(f"{k}={v}" for k, v in stats.items() if v))
        if self._budget <= 0:
            log.warning("retention batch budget (%d) exhausted; the remainder is deferred to the next run",
                        cfg.max_batches_per_run)
        return stats

    async def _delete_batches(self, where: str, params: tuple, order: str) -> int:
        total = 0
        while self._budget > 0:
            with self.storage.transaction() as conn:
                cur = conn.execute(
                    f"DELETE FROM events WHERE id IN (SELECT id FROM events WHERE {where} ORDER BY {order} LIMIT ?)",
                    (*params, self.cfg.batch_size),
                )
                deleted = cur.rowcount
                if deleted:
                    conn.execute("PRAGMA incremental_vacuum(2000)")
            self._budget -= 1
            total += deleted
            if deleted < self.cfg.batch_size:
                break
            await asyncio.sleep(0)
        return total

    async def _enforce_device_count(self, device: str, max_events: int) -> int:
        with self.storage.transaction() as conn:
            row = conn.execute(
                "SELECT id FROM events WHERE device=? ORDER BY id DESC LIMIT 1 OFFSET ?", (device, max_events)
            ).fetchone()
        if row is None:
            return 0
        return await self._delete_batches("device = ? AND id <= ?", (device, row[0]), "id")

    async def _enforce_size(self, limit: int) -> int:
        total = 0
        while self.storage.used_bytes() > limit and self._budget > 0:
            deleted = await self._delete_oldest_batch()
            total += deleted
            if deleted == 0:
                log.warning(
                    "storage is %d bytes, above max_total_size_mb (%d bytes), but no events are left to delete; "
                    "remaining data is config snapshots/metadata", self.storage.used_bytes(), limit,
                )
                break
            await asyncio.sleep(0)
        return total

    async def _delete_oldest_batch(self) -> int:
        with self.storage.transaction() as conn:
            cur = conn.execute(
                "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY id LIMIT ?)", (self.cfg.batch_size,)
            )
            if cur.rowcount:
                conn.execute("PRAGMA incremental_vacuum(2000)")
        self._budget -= 1
        return cur.rowcount

    def _prune_sessions(self) -> int:
        with self.storage.transaction() as conn:
            return conn.execute(
                "DELETE FROM sessions WHERE ended_at IS NOT NULL "
                "AND NOT EXISTS (SELECT 1 FROM events WHERE events.session_id = sessions.session_id)"
            ).rowcount

    def _prune_snapshots(self) -> int:
        cfg = self.cfg
        deleted = 0
        with self.storage.transaction() as conn:
            if cfg.configs_max_age_days:
                cutoff = format_ts(utc_now() - timedelta(days=cfg.configs_max_age_days))
                deleted += conn.execute("DELETE FROM config_snapshots WHERE captured_at < ?", (cutoff,)).rowcount
            if cfg.configs_keep_last:
                deleted += conn.execute(
                    "DELETE FROM config_snapshots WHERE id IN (SELECT id FROM ("
                    " SELECT id, ROW_NUMBER() OVER (PARTITION BY device ORDER BY id DESC) AS n FROM config_snapshots"
                    ") WHERE n > ?)", (cfg.configs_keep_last,),
                ).rowcount
        return deleted

    def _prune_exports(self) -> tuple[int, int]:
        """Only files created by the exporter (known name pattern) are ever removed."""
        if not self.export_dir.is_dir():
            return 0, 0
        cfg, now = self.cfg, time.time()
        removed = tmp_removed = 0
        archives = []
        for entry in self.export_dir.iterdir():
            if not entry.is_file() or entry.is_symlink():
                continue
            if entry.name.startswith(TMP_PREFIX):
                if now - entry.stat().st_mtime > STALE_TMP_SECONDS:
                    entry.unlink()
                    tmp_removed += 1
            elif entry.name.startswith(EXPORT_PREFIX) and entry.name.endswith(EXPORT_SUFFIX):
                archives.append(entry)
        archives.sort(key=lambda p: p.stat().st_mtime)
        if cfg.exports_max_age_days:
            for path in list(archives):
                if now - path.stat().st_mtime > cfg.exports_max_age_days * 86400:
                    path.unlink()
                    archives.remove(path)
                    removed += 1
        if cfg.exports_max_total_size_mb:
            limit = cfg.exports_max_total_size_mb * 1024 * 1024
            while archives and sum(p.stat().st_size for p in archives) > limit:
                archives.pop(0).unlink()
                removed += 1
        return removed, tmp_removed

    def _finish(self) -> None:
        self.storage.checkpoint()

    async def loop(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await self.run_once()
            except (OSError, sqlite3.Error) as err:
                log.error("retention run failed: %s", err)
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.cfg.cleanup_interval_seconds)
            except asyncio.TimeoutError:
                pass
