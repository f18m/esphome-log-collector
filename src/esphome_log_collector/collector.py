"""Per-device supervised log collection (CLI subprocess or native API) and the supervisor."""

from __future__ import annotations

import asyncio
from collections import deque
import json
import logging
import os
import random
import signal
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Callable

from . import storage as st
from .config import Config, DeviceConfig, RetryConfig
from .parsing import parse_line
from .redact import Redactor, load_esphome_secret_values
from .logs_args import build_logs_command, redact_argv
from .timeutil import format_ts, now_ts, utc_now

log = logging.getLogger("collector")

MAX_LINE_BYTES = 1024 * 1024  # longer lines are split into several events
READ_CHUNK = 64 * 1024
HEARTBEAT_SECONDS = 10.0
_ENV_PASSTHROUGH = ("PATH", "HOME", "LANG", "LC_ALL", "TZ", "VIRTUAL_ENV", "SSL_CERT_FILE", "PYTHONPATH")


class Backoff:
    """Exponential backoff with +/- jitter; reset after a sufficiently long healthy session."""

    def __init__(self, retry: RetryConfig, rng: Callable[[], float] = random.random) -> None:
        self.retry = retry
        self.attempt = 0
        self._rng = rng

    def next_delay(self, session_seconds: float = 0.0) -> float:
        r = self.retry
        if r.reset_after and session_seconds >= r.reset_after:
            self.attempt = 0
        base = min(r.max_delay, r.initial_delay * (r.multiplier ** self.attempt))
        self.attempt += 1
        jittered = base * (1 + r.jitter * (2 * self._rng() - 1))
        return max(0.05, jittered)


class RawLogFile:
    """Optional per-device append-only file; a convenience copy, SQLite stays the source of truth."""

    def __init__(self, path: Path, max_bytes: int) -> None:
        self.path = path
        self.max_bytes = max_bytes
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8", errors="replace", buffering=1)

    def write(self, ts: str, text: str) -> None:
        if self._fh.tell() >= self.max_bytes:
            self._fh.close()
            os.replace(self.path, self.path.with_name(self.path.name + ".1"))
            self._fh = open(self.path, "a", encoding="utf-8", errors="replace", buffering=1)
        self._fh.write(f"{ts} {text}\n")

    def close(self) -> None:
        self._fh.close()


@dataclass
class SessionResult:
    reason: str
    error: str | None = None


def _looks_connected(text: str) -> bool:
    """True once ESPHome reports a connection or the first firmware log line arrives."""
    parsed = parse_line(text)
    return parsed.device_time is not None or (parsed.message or "").startswith("Successfully connected")


def subprocess_env(data_dir: Path, device: str) -> dict[str, str]:
    env = {k: os.environ[k] for k in _ENV_PASSTHROUGH if k in os.environ}
    env["PYTHONUNBUFFERED"] = "1"
    esphome_data = data_dir / "esphome-data" / device
    esphome_data.mkdir(parents=True, exist_ok=True)
    env["ESPHOME_DATA_DIR"] = str(esphome_data)  # keeps the read-only config mount untouched
    return env


class DeviceCollector:
    """Collects logs from one device forever; errors here never affect other devices."""

    def __init__(self, device: DeviceConfig, storage: st.Storage, config: Config, stop: asyncio.Event) -> None:
        self.device = device
        self.storage = storage
        self.config = config
        self.stop = stop
        self.backoff = Backoff(device.retry)
        self.raw_file: RawLogFile | None = None
        self.session_id = ""
        self.lines = 0
        self.connected = False
        self.recent_output: deque[str] = deque(maxlen=12)
        self.redactor = Redactor(
            config.capture.extra_key_patterns,
            config.capture.extra_value_patterns,
            (*config.secrets, *load_esphome_secret_values(device.config_file)),
        )
        if config.raw_files.enabled:
            self.raw_file = RawLogFile(
                config.data_dir / "raw" / f"{device.name}.log", int(config.raw_files.max_file_mb * 1024 * 1024)
            )

    @property
    def address(self) -> str | None:
        return self.device.address or self.device.target

    # ---- helpers ----------------------------------------------------------------
    def _event(self, event_type: str, message: str) -> None:
        ts = self.storage.add_event(self.device.name, self.address, self.session_id, event_type, message)
        if self.raw_file:
            self.raw_file.write(ts, f"# collector {event_type}: {message}")

    def _line(self, text: str) -> None:
        text = self.redactor.redact_line(text)
        self.recent_output.append(text[:400])
        ts = self.storage.add_log(self.device.name, self.address, self.session_id, text)
        self.lines += 1
        if self.raw_file:
            self.raw_file.write(ts, text)
        if not self.connected and _looks_connected(text):
            self._mark_connected(ts)
        elif self.connected and self.lines % 50 == 0:
            self.storage.set_status(self.device.name, state="connected", session_id=self.session_id, last_line_at=ts)

    def _mark_connected(self, ts: str | None = None) -> None:
        self.connected = True
        self._event(st.CONNECTED, "device connection established (log output flowing)")
        self.storage.set_status(self.device.name, state="connected", session_id=self.session_id,
                                last_line_at=ts or now_ts())

    async def _sleep(self, seconds: float) -> None:
        try:
            await asyncio.wait_for(self.stop.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass

    # ---- main loop --------------------------------------------------------------
    async def run(self) -> None:
        name = self.device.name
        self.storage.set_status(
            name, state="starting", address=self.address, backend=self.device.backend, source=self.device.source
        )
        try:
            while not self.stop.is_set():
                started = time.monotonic()
                self.session_id, previous = self.storage.start_session(name, self.address)
                self.lines = 0
                self.connected = False
                self._event(st.SESSION_START, f"collection session started (backend={self.device.backend})")
                if previous:
                    self._event(st.GAP, f"no events stored between {previous} and {now_ts()}")
                self.storage.set_status(name, state="connecting", session_id=self.session_id)
                try:
                    if self.device.backend == "cli":
                        result = await self._session_cli()
                    else:
                        result = await self._session_api()
                except Exception as err:  # noqa: BLE001 - one device must never take the others down
                    log.exception("device %s: unexpected collector error", name)
                    result = SessionResult("collector_error", f"{type(err).__name__}: {err}")
                if result.error:
                    self._event(st.COLLECTOR_ERROR, result.error)
                    log.error("device %s: %s", name, result.error)
                self._event(st.DISCONNECTED, f"{result.reason} ({self.lines} lines this session)")
                self.storage.end_session(self.session_id, result.reason)
                if self.stop.is_set():
                    break
                delay = self.backoff.next_delay(time.monotonic() - started)
                retry_at = format_ts(utc_now() + timedelta(seconds=delay))
                self.storage.set_status(
                    name, state="backoff", error=result.error or result.reason,
                    attempts=self.backoff.attempt, next_retry_at=retry_at,
                )
                log.warning("device %s: disconnected (%s); retrying in %.1fs", name, result.reason, delay)
                self._retry_event(delay, retry_at)
                await self._sleep(delay)
        finally:
            if self.raw_file:
                self.raw_file.close()
            self.storage.set_status(name, state="stopped")

    def _retry_event(self, delay: float, retry_at: str) -> None:
        """Retry notices belong to the session that just ended, so record them against it."""
        ts = self.storage.add_event(
            self.device.name, self.address, self.session_id, st.RETRY,
            f"retry in {delay:.1f}s (attempt {self.backoff.attempt}) at {retry_at}",
        )
        if self.raw_file:
            self.raw_file.write(ts, f"# collector {st.RETRY}: retry in {delay:.1f}s")

    # ---- backends ---------------------------------------------------------------
    async def _session_cli(self) -> SessionResult:
        argv = build_logs_command(self.config.esphome_command, self.device)
        self.recent_output.clear()
        self.redactor.reset()
        secrets = [self.device.logs.mqtt_password.reveal()] if self.device.logs.mqtt_password else []
        log.info("device %s: starting %s", self.device.name, " ".join(redact_argv(argv, secrets)))
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, env=subprocess_env(self.config.data_dir, self.device.name),
                start_new_session=True,
            )
        except FileNotFoundError as err:
            return SessionResult("failed to start", f"cannot execute {argv[0]!r}: {err.strerror}; is ESPHome installed?")
        except OSError as err:
            return SessionResult("failed to start", f"cannot start esphome: {err}")
        assert proc.stdout is not None
        stop_wait = asyncio.ensure_future(self.stop.wait())
        buffer = b""
        idle = self.device.idle_timeout or None
        reason: str | None = None
        try:
            while reason is None:
                read = asyncio.ensure_future(proc.stdout.read(READ_CHUNK))
                done, _ = await asyncio.wait({read, stop_wait}, timeout=idle, return_when=asyncio.FIRST_COMPLETED)
                if not done:
                    read.cancel()
                    reason = f"no output for {idle:.0f}s (idle_timeout); restarting"
                    break
                if read not in done:
                    read.cancel()
                    reason = "collector shutting down"
                    break
                chunk = read.result()
                if not chunk:
                    break
                buffer += chunk
                buffer = self._emit_lines(buffer)
            if buffer:
                self._emit_lines(buffer, final=True)
        finally:
            stop_wait.cancel()
            code = await self._terminate(proc)
        if reason:
            return SessionResult(reason)
        if code == 0:
            return SessionResult(f"esphome exited with code {code}")
        tail = "\n".join(line for line in self.recent_output if line)
        detail = f"; recent output:\n{tail}" if tail else ""
        return SessionResult(f"esphome exited with code {code}",
                             f"esphome logs exited with code {code}{detail}")

    def _emit_lines(self, buffer: bytes, final: bool = False) -> bytes:
        while True:
            idx = buffer.find(b"\n")
            if idx < 0:
                if len(buffer) >= MAX_LINE_BYTES or (final and buffer):
                    self._line(buffer.decode("utf-8", "replace").rstrip("\r"))
                    return b""
                return buffer
            line, buffer = buffer[:idx], buffer[idx + 1:]
            self._line(line.decode("utf-8", "replace").rstrip("\r"))

    async def _terminate(self, proc: asyncio.subprocess.Process) -> int | None:
        if proc.returncode is None:
            _signal_group(proc, signal.SIGTERM)
            try:
                await asyncio.wait_for(proc.wait(), timeout=self.config.stop_grace_seconds)
            except asyncio.TimeoutError:
                log.warning("device %s: esphome did not exit after SIGTERM; killing", self.device.name)
                _signal_group(proc, signal.SIGKILL)
                await proc.wait()
        return proc.returncode

    async def _session_api(self) -> SessionResult:
        from aioesphomeapi import APIClient, LogLevel
        from aioesphomeapi.core import APIConnectionError

        dev, api = self.device, self.device.api
        host = dev.target
        assert host is not None
        client = APIClient(
            host, api.port, api.password.reveal() if api.password else None,
            client_info="esphome-log-collector",
            noise_psk=api.noise_psk.reveal() if api.noise_psk else None,
        )
        disconnected = asyncio.Event()

        async def on_stop(expected: bool) -> None:
            disconnected.set()

        def on_log(msg) -> None:
            text = msg.message.decode("utf-8", "backslashreplace")
            ts = utc_now()
            for part in text.split("\n"):
                self._line(f"[{ts:%H:%M:%S}]{part.rstrip(chr(13))}")

        try:
            await asyncio.wait_for(client.connect(on_stop=on_stop, login=True), timeout=api.connect_timeout)
            self._mark_connected()
            client.subscribe_logs(on_log, log_level=LogLevel.LOG_LEVEL_VERY_VERBOSE, dump_config=True)
            stop_wait = asyncio.ensure_future(self.stop.wait())
            gone = asyncio.ensure_future(disconnected.wait())
            try:
                done, _ = await asyncio.wait({stop_wait, gone}, timeout=dev.idle_timeout or None,
                                             return_when=asyncio.FIRST_COMPLETED)
            finally:
                stop_wait.cancel()
                gone.cancel()
            if not done:
                return SessionResult(f"no events for {dev.idle_timeout:.0f}s (idle_timeout); reconnecting")
            if gone in done and not self.stop.is_set():
                return SessionResult("device disconnected")
            return SessionResult("collector shutting down")
        except (APIConnectionError, asyncio.TimeoutError, OSError) as err:
            return SessionResult("connection failed", f"API connection to {host}:{api.port} failed: {type(err).__name__}: {err}")
        finally:
            await client.disconnect()


def _signal_group(proc: asyncio.subprocess.Process, sig: int) -> None:
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        pass


def _log_task_failure(task: asyncio.Task) -> None:
    if not task.cancelled() and task.exception() is not None:
        log.error("background task %s failed", task.get_name(), exc_info=task.exception())


class Collector:
    """Owns the storage, the per-device tasks and the housekeeping tasks."""

    def __init__(self, config: Config, storage: st.Storage) -> None:
        self.config = config
        self.storage = storage
        self.stop = asyncio.Event()
        self.devices: dict[str, asyncio.Task] = {}
        self.known: dict[str, DeviceConfig] = {}
        self._aux: list[asyncio.Task] = []

    def add_device(self, device: DeviceConfig) -> bool:
        if device.name.lower() in {n.lower() for n in self.devices}:
            return False
        if not device.enabled:
            log.info("device %s is disabled; not collecting", device.name)
            return False
        self.known[device.name] = device
        collector = DeviceCollector(device, self.storage, self.config, self.stop)
        self.devices[device.name] = asyncio.create_task(collector.run(), name=f"device-{device.name}")
        log.info("collecting from %s (%s backend, source=%s)", device.name, device.backend, device.source)
        return True

    def add_background(self, coro, name: str) -> None:
        task = asyncio.create_task(coro, name=name)
        task.add_done_callback(_log_task_failure)
        self._aux.append(task)

    def request_stop(self) -> None:
        self.stop.set()

    async def _heartbeat(self) -> None:
        path = self.config.health_file
        path.parent.mkdir(parents=True, exist_ok=True)
        while not self.stop.is_set():
            payload = {"pid": os.getpid(), "ts": now_ts(), "devices": len(self.devices)}
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            os.replace(tmp, path)
            try:
                await asyncio.wait_for(self.stop.wait(), timeout=HEARTBEAT_SECONDS)
            except asyncio.TimeoutError:
                pass

    async def run(self, devices: list[DeviceConfig]) -> None:
        self.add_background(self._heartbeat(), "heartbeat")
        for device in devices:
            self.add_device(device)
        await self.stop.wait()
        log.info("shutting down: stopping %d device collectors", len(self.devices))
        results = await asyncio.gather(*self.devices.values(), return_exceptions=True)
        for res in results:
            if isinstance(res, BaseException):
                log.error("device task ended with an error: %r", res)
        for task in self._aux:
            task.cancel()
        await asyncio.gather(*self._aux, return_exceptions=True)
        self.storage.mark_all_stopped()
