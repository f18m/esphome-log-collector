"""Device configuration capture: run `esphome config`, redact, store sanitized snapshots."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from pathlib import Path
from typing import Callable

from . import storage as st
from .collector import _signal_group, subprocess_env
from .config import Config, DeviceConfig
from .logs_args import build_config_command
from .parsing import strip_ansi
from .redact import Redactor

log = logging.getLogger("capture")
CAPTURE_SESSION = "config-capture"
POLL_SECONDS = 30.0
MAX_OUTPUT = 4 * 1024 * 1024


def source_hash(device: DeviceConfig) -> str:
    """Hash of the device YAML plus the files listed in capture.watch_files."""
    digest = hashlib.sha256()
    for path in [device.config_file, *device.capture.watch_files]:
        digest.update(str(path).encode())
        try:
            digest.update(Path(path).read_bytes())
        except OSError:
            digest.update(b"<unreadable>")
    return digest.hexdigest()


class ConfigCapture:
    def __init__(self, config: Config, storage: st.Storage, redactor: Redactor) -> None:
        self.config = config
        self.storage = storage
        self.redactor = redactor
        self._sem = asyncio.Semaphore(2)

    async def capture_device(self, device: DeviceConfig, reason: str) -> bool:
        """Capture one device; returns True when a new snapshot was stored."""
        if not device.config_file:
            return False
        argv = build_config_command(self.config.esphome_command, device)
        src = source_hash(device)
        async with self._sem:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *argv, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE, env=subprocess_env(self.config.data_dir, device.name),
                    start_new_session=True,
                )
            except OSError as err:
                self._fail(device, f"cannot run esphome config: {err}")
                return False
            try:
                out, err_out = await asyncio.wait_for(proc.communicate(), timeout=self.config.capture.timeout)
            except asyncio.TimeoutError:
                _signal_group(proc, 9)
                await proc.wait()
                self._fail(device, f"esphome config timed out after {self.config.capture.timeout:.0f}s")
                return False
            except asyncio.CancelledError:
                _signal_group(proc, 9)
                await proc.wait()
                raise
        if proc.returncode != 0:
            detail = self.redactor.redact_text(strip_ansi(err_out.decode("utf-8", "replace")))[-500:].strip()
            self._fail(device, f"esphome config exited with code {proc.returncode}: {detail}")
            return False
        content = self.redactor.redact_text(strip_ansi(out[:MAX_OUTPUT].decode("utf-8", "replace")))
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        latest = self.storage.latest_snapshot(device.name)
        if latest is not None and latest["content_hash"] == content_hash:
            log.debug("device %s: configuration unchanged (%s)", device.name, reason)
            return False
        self.storage.add_snapshot(device.name, src, content_hash, content)
        log.info("device %s: stored sanitized configuration snapshot (%s)", device.name, reason)
        return True

    def _fail(self, device: DeviceConfig, message: str) -> None:
        log.error("device %s: configuration capture failed: %s", device.name, message)
        self.storage.add_event(device.name, device.address, CAPTURE_SESSION, st.COLLECTOR_ERROR,
                               f"configuration capture failed: {message}")

    async def loop(self, stop: asyncio.Event, devices: Callable[[], list[DeviceConfig]]) -> None:
        cfg = self.config.capture
        state: dict[str, tuple[str, float]] = {}  # device -> (source hash at last capture/baseline, monotonic time)
        while not stop.is_set():
            for device in devices():
                if not device.config_file or not device.capture.enabled or stop.is_set():
                    continue
                name, now, current = device.name, time.monotonic(), source_hash(device)
                reason = None
                if name not in state:
                    if cfg.on_startup:
                        reason = "startup"
                    else:
                        latest = self.storage.latest_snapshot(name)
                        state[name] = (latest["source_hash"] if latest else current, now)
                else:
                    last_hash, last_time = state[name]
                    if cfg.on_change and last_hash != current:
                        reason = "source changed"
                    elif cfg.interval_seconds and now - last_time >= cfg.interval_seconds:
                        reason = "scheduled"
                if reason:
                    state[name] = (current, now)
                    await self.capture_device(device, reason)
            try:
                await asyncio.wait_for(stop.wait(), timeout=POLL_SECONDS)
            except asyncio.TimeoutError:
                pass
