"""Command line interface: run, check-config, export, healthcheck."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import SUPPORTED_ESPHOME_VERSION, __version__
from .capture import ConfigCapture
from .collector import Collector
from .config import Config, ConfigError, load_config
from .discovery import discovery_loop
from .export import ExportError, create_export
from .redact import Redactor
from .retention import Retention
from .storage import Storage
from .web import WebServer

log = logging.getLogger("main")
DEFAULT_CONFIG = "/config/config.yaml"
HEALTH_MAX_AGE_SECONDS = 60


class SecretFilter(logging.Filter):
    """Masks configured credentials in every log record emitted by the collector."""

    def __init__(self, secrets: tuple[str, ...]) -> None:
        super().__init__()
        self._secrets = sorted((s for s in secrets if len(s) >= 4), key=len, reverse=True)

    def filter(self, record: logging.LogRecord) -> bool:
        if self._secrets:
            message = record.getMessage()
            for secret in self._secrets:
                message = message.replace(secret, "***")
            record.msg, record.args = message, None
        return True


def setup_logging(config: Config) -> None:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s", "%Y-%m-%dT%H:%M:%SZ"))
    handler.formatter.converter = lambda *a: datetime.now(timezone.utc).timetuple()  # type: ignore[union-attr]
    handler.addFilter(SecretFilter(config.secrets))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(config.log_level)


def make_redactor(config: Config) -> Redactor:
    return Redactor(config.capture.extra_key_patterns, config.capture.extra_value_patterns, config.secrets)


async def run_collector(config: Config) -> None:
    storage = Storage(config.db_path)
    redactor = make_redactor(config)
    collector = Collector(config, storage)
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, collector.request_stop)
    web: WebServer | None = None
    try:
        collector.add_background(Retention(storage, config.retention, config.export_dir).loop(collector.stop), "retention")
        if config.capture.enabled:
            capture = ConfigCapture(config, storage, redactor)
            collector.add_background(capture.loop(collector.stop, lambda: list(collector.known.values())), "capture")
        if config.discovery.enabled:
            collector.add_background(
                discovery_loop(config, collector.stop, lambda: list(collector.known.values()), collector.add_device),
                "discovery",
            )
        if config.web.enabled:
            web = WebServer(config, redactor)
            web.start()
        log.info("esphome-log-collector %s started (ESPHome %s, %d configured device(s))",
                 __version__, SUPPORTED_ESPHOME_VERSION, len(config.devices))
        await collector.run(list(config.devices))
    finally:
        if web:
            await asyncio.to_thread(web.stop)
        storage.close()
        log.info("shutdown complete")


def _load(args: argparse.Namespace) -> Config:
    try:
        return load_config(args.config)
    except ConfigError as err:
        print(f"error: {err}", file=sys.stderr)
        raise SystemExit(2) from err


def cmd_run(args: argparse.Namespace) -> int:
    config = _load(args)
    setup_logging(config)
    for warning in config.warnings:
        log.warning("config: %s", warning)
    asyncio.run(run_collector(config))
    return 0


def cmd_check_config(args: argparse.Namespace) -> int:
    config = _load(args)
    for warning in config.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    print(f"configuration OK: {len(config.devices)} device(s), discovery "
          f"{'enabled' if config.discovery.enabled else 'disabled'}, web UI "
          f"{'enabled' if config.web.enabled else 'disabled'}")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    config = _load(args)
    setup_logging(config)
    out_dir = Path(args.output_dir) if args.output_dir else config.export_dir
    try:
        path = create_export(
            config.db_path, out_dir, devices=args.device or None, start=args.start, end=args.end,
            include_configs=not args.no_configs, redactor=make_redactor(config),
        )
    except ExportError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    print(path)
    return 0


def cmd_healthcheck(args: argparse.Namespace) -> int:
    """Healthy when the collector process is alive and its event loop is making progress.

    Offline ESPHome devices do not affect the result.
    """
    path = Path(args.data_dir) / "health" / "heartbeat"
    try:
        age = datetime.now().timestamp() - path.stat().st_mtime
        pid = json.loads(path.read_text(encoding="utf-8"))["pid"]
    except (OSError, ValueError, KeyError) as err:
        print(f"unhealthy: heartbeat unreadable: {err}", file=sys.stderr)
        return 1
    if age > HEALTH_MAX_AGE_SECONDS:
        print(f"unhealthy: heartbeat is {age:.0f}s old", file=sys.stderr)
        return 1
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        print(f"unhealthy: collector process {pid} is gone", file=sys.stderr)
        return 1
    except PermissionError:
        pass
    print("healthy")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="esphome-log-collector", description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__} (ESPHome {SUPPORTED_ESPHOME_VERSION})")
    sub = parser.add_subparsers(dest="command", required=True)

    def with_config(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
        p.add_argument("-c", "--config", default=os.environ.get("ESPHOME_LOG_COLLECTOR_CONFIG", DEFAULT_CONFIG),
                       help="collector YAML file (env ESPHOME_LOG_COLLECTOR_CONFIG, default %(default)s)")
        return p

    with_config(sub.add_parser("run", help="collect logs until stopped")).set_defaults(func=cmd_run)
    with_config(sub.add_parser("check-config", help="validate the configuration and exit")).set_defaults(func=cmd_check_config)
    exp = with_config(sub.add_parser("export", help="create an export tarball"))
    exp.add_argument("--device", action="append", help="device name (repeatable; default all)")
    exp.add_argument("--start", help="UTC start, inclusive (ISO-8601, e.g. 2025-01-31T00:00:00Z)")
    exp.add_argument("--end", help="UTC end, exclusive")
    exp.add_argument("--no-configs", action="store_true", help="omit sanitized configuration snapshots")
    exp.add_argument("--output-dir", help="directory for the tarball (default: storage.export_dir)")
    exp.set_defaults(func=cmd_export)
    hc = sub.add_parser("healthcheck", help="exit 0 when the collector process is healthy")
    hc.add_argument("--data-dir", default=os.environ.get("ESPHOME_LOG_COLLECTOR_DATA_DIR", "/data"))
    hc.set_defaults(func=cmd_healthcheck)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
