"""YAML configuration loading, defaults, per-device overrides and strict validation.

Every problem found is collected and reported together in a single ConfigError so that
the operator can fix the file in one pass. Unknown keys are errors (typos must not be
silently ignored) and nothing is silently substituted for missing credentials.
"""

from __future__ import annotations

import copy
import ipaddress
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .logs_args import validate_extra_args

DEVICE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")
BACKENDS = ("auto", "cli", "api")
LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")


class ConfigError(Exception):
    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("invalid configuration:\n" + "\n".join(f"  - {e}" for e in errors))


class Secret:
    """A credential value that never appears in repr/str output."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret('***')"

    __str__ = __repr__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and other._value == self._value

    def __hash__(self) -> int:
        return hash(self._value)


@dataclass(frozen=True)
class RetryConfig:
    initial_delay: float = 2.0
    max_delay: float = 300.0
    multiplier: float = 2.0
    jitter: float = 0.2  # fraction of the delay, applied +/-
    reset_after: float = 60.0  # a session this long resets the backoff


@dataclass(frozen=True)
class LogsOptions:
    """Options of `esphome logs` (pinned version), see logs_args.py."""

    device: str | None = None
    mqtt_topic: str | None = None
    mqtt_username: str | None = None
    mqtt_password: Secret | None = None
    client_id: str | None = None
    reset: bool = False
    states: bool | None = None
    extra_args: tuple[str, ...] = ()


@dataclass(frozen=True)
class ApiOptions:
    port: int = 6053
    noise_psk: Secret | None = None
    password: Secret | None = None
    connect_timeout: float = 30.0


@dataclass(frozen=True)
class DeviceCapture:
    enabled: bool = True
    watch_files: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeviceConfig:
    name: str
    backend: str  # resolved: "cli" or "api"
    address: str | None = None
    esphome_name: str | None = None
    config_file: str | None = None
    enabled: bool = True
    logs: LogsOptions = field(default_factory=LogsOptions)
    api: ApiOptions = field(default_factory=ApiOptions)
    retry: RetryConfig = field(default_factory=RetryConfig)
    idle_timeout: float = 0.0  # restart the connection after this many silent seconds (0 = off)
    substitutions: tuple[tuple[str, str], ...] = ()
    capture: DeviceCapture = field(default_factory=DeviceCapture)
    source: str = "explicit"

    @property
    def target(self) -> str | None:
        """Host used by the API backend."""
        return self.address or (f"{self.esphome_name}.local" if self.esphome_name else None)


@dataclass(frozen=True)
class DiscoveryConfig:
    enabled: bool = False
    interval_seconds: float = 0.0  # 0 = scan once at startup
    scan_timeout: float = 10.0
    names: tuple[str, ...] = ()
    name_prefixes: tuple[str, ...] = ()
    exclude_names: tuple[str, ...] = ()
    allow_all: bool = False
    config_dir: str | None = None


@dataclass(frozen=True)
class RawFilesConfig:
    enabled: bool = False
    max_file_mb: float = 50.0  # rotated to <name>.log.1 (one generation kept)


@dataclass(frozen=True)
class DeviceRetention:
    max_age_days: float | None = None
    max_events: int | None = None


@dataclass(frozen=True)
class RetentionConfig:
    max_age_days: float | None = None
    max_total_size_mb: float | None = None
    cleanup_interval_seconds: float = 3600.0
    batch_size: int = 5000
    max_batches_per_run: int = 200
    per_device: dict[str, DeviceRetention] = field(default_factory=dict)
    exports_max_age_days: float | None = 14.0
    exports_max_total_size_mb: float | None = None
    configs_max_age_days: float | None = None
    configs_keep_last: int | None = 20  # snapshots kept per device


@dataclass(frozen=True)
class CaptureConfig:
    enabled: bool = False
    on_startup: bool = True
    interval_seconds: float = 0.0
    on_change: bool = False
    timeout: float = 120.0
    extra_key_patterns: tuple[str, ...] = ()
    extra_value_patterns: tuple[str, ...] = ()


@dataclass(frozen=True)
class WebConfig:
    enabled: bool = False
    bind: str = "127.0.0.1"
    port: int = 8080
    page_size: int = 100
    allowed_hosts: tuple[str, ...] = ()


@dataclass(frozen=True)
class Config:
    data_dir: Path
    export_dir: Path
    log_level: str
    esphome_command: tuple[str, ...]
    stop_grace_seconds: float
    devices: tuple[DeviceConfig, ...]
    discovery: DiscoveryConfig
    raw_files: RawFilesConfig
    retention: RetentionConfig
    capture: CaptureConfig
    web: WebConfig
    defaults: dict[str, Any] = field(default_factory=dict, repr=False)
    secrets: tuple[str, ...] = field(default=(), repr=False)
    warnings: tuple[str, ...] = ()

    @property
    def db_path(self) -> Path:
        return self.data_dir / "collector.sqlite3"

    @property
    def health_file(self) -> Path:
        return self.data_dir / "health" / "heartbeat"


class _Ctx:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.secrets: list[str] = []

    def err(self, path: str, msg: str) -> None:
        self.errors.append(f"{path}: {msg}")

    def mapping(self, path: str, raw: Any, allowed: set[str]) -> dict[str, Any]:
        if raw is None:
            return {}
        if not isinstance(raw, dict):
            self.err(path, f"expected a mapping, got {type(raw).__name__}")
            return {}
        for key in raw:
            if key not in allowed:
                self.err(f"{path}.{key}", f"unknown option (allowed: {', '.join(sorted(allowed))})")
        return {k: v for k, v in raw.items() if k in allowed}

    def boolean(self, path: str, raw: dict, key: str, default: bool | None) -> bool | None:
        if key not in raw or raw[key] is None:
            return default
        if not isinstance(raw[key], bool):
            self.err(f"{path}.{key}", "expected true or false")
            return default
        return raw[key]

    def number(
        self, path: str, raw: dict, key: str, default: Any, minimum: float | None = None,
        maximum: float | None = None, integer: bool = False, exclusive_min: bool = False,
    ) -> Any:
        if key not in raw or raw[key] is None:
            return default
        value = raw[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or (integer and not isinstance(value, int)):
            self.err(f"{path}.{key}", f"expected {'an integer' if integer else 'a number'}")
            return default
        if minimum is not None and (value < minimum or (exclusive_min and value == minimum)):
            self.err(f"{path}.{key}", f"must be {'>' if exclusive_min else '>='} {minimum}")
            return default
        if maximum is not None and value > maximum:
            self.err(f"{path}.{key}", f"must be <= {maximum}")
            return default
        return value

    def string(self, path: str, raw: dict, key: str, default: str | None = None) -> str | None:
        if key not in raw or raw[key] is None:
            return default
        if not isinstance(raw[key], str) or not raw[key].strip():
            self.err(f"{path}.{key}", "expected a non-empty string")
            return default
        return raw[key]

    def string_list(self, path: str, raw: dict, key: str) -> tuple[str, ...]:
        value = raw.get(key)
        if value is None:
            return ()
        if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
            self.err(f"{path}.{key}", "expected a list of non-empty strings")
            return ()
        return tuple(value)

    def secret(self, path: str, raw: dict, key: str) -> Secret | None:
        """Resolve a credential: {env: NAME}, {file: /run/secrets/x} or a plain string."""
        if key not in raw or raw[key] is None:
            return None
        value = raw[key]
        resolved: str | None = None
        if isinstance(value, dict):
            if set(value) == {"env"} and isinstance(value["env"], str):
                resolved = os.environ.get(value["env"])
                if resolved is None:
                    self.err(f"{path}.{key}", f"environment variable {value['env']!r} is not set")
            elif set(value) == {"file"} and isinstance(value["file"], str):
                try:
                    resolved = Path(value["file"]).read_text(encoding="utf-8").rstrip("\r\n")
                except OSError as err:
                    self.err(f"{path}.{key}", f"cannot read secret file {value['file']!r}: {err.strerror}")
            else:
                self.err(f"{path}.{key}", "expected a string, {env: NAME} or {file: PATH}")
        elif isinstance(value, str):
            resolved = value
            self.warnings.append(
                f"{path}.{key}: plaintext credential in YAML; prefer {{env: NAME}} or {{file: PATH}}"
            )
        else:
            self.err(f"{path}.{key}", "expected a string, {env: NAME} or {file: PATH}")
        if resolved is None:
            return None
        if resolved == "":
            self.err(f"{path}.{key}", "credential resolved to an empty value")
            return None
        self.secrets.append(resolved)
        return Secret(resolved)


_RETRY_KEYS = {"initial_delay", "max_delay", "multiplier", "jitter", "reset_after"}
_LOGS_KEYS = {
    "device", "mqtt_topic", "mqtt_username", "mqtt_password", "client_id",
    "reset", "states", "extra_args",
}
_API_KEYS = {"port", "noise_psk", "password", "connect_timeout"}
_DEVICE_KEYS = {
    "name", "address", "esphome_name", "config_file", "enabled", "backend", "logs", "api",
    "retry", "idle_timeout", "substitutions", "capture",
}
_DEFAULT_KEYS = {"backend", "logs", "api", "retry", "idle_timeout", "substitutions", "capture"}
_DEFAULT_LOGS_KEYS = _LOGS_KEYS - {"device", "reset"}


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in override.items():
        is_secret_ref = isinstance(value, dict) and value and set(value) <= {"env", "file"}
        if isinstance(value, dict) and isinstance(out.get(key), dict) and not is_secret_ref:
            out[key] = _merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def _check_address(ctx: _Ctx, path: str, value: str | None) -> None:
    if value is None:
        return
    try:
        ipaddress.ip_address(value.strip("[]"))
        return
    except ValueError:
        pass
    if not HOSTNAME_RE.match(value):
        ctx.err(path, f"{value!r} is not a valid hostname or IP address")


def _build_retry(ctx: _Ctx, path: str, raw: Any) -> RetryConfig:
    r = ctx.mapping(path, raw, _RETRY_KEYS)
    d = RetryConfig()
    retry = RetryConfig(
        initial_delay=ctx.number(path, r, "initial_delay", d.initial_delay, 0.1),
        max_delay=ctx.number(path, r, "max_delay", d.max_delay, 0.1),
        multiplier=ctx.number(path, r, "multiplier", d.multiplier, 1.0),
        jitter=ctx.number(path, r, "jitter", d.jitter, 0.0, 1.0),
        reset_after=ctx.number(path, r, "reset_after", d.reset_after, 0.0),
    )
    if retry.max_delay < retry.initial_delay:
        ctx.err(f"{path}.max_delay", "must be >= initial_delay")
    return retry


def _build_device(ctx: _Ctx, path: str, raw: dict, cfg_defaults: dict, source: str) -> DeviceConfig | None:
    merged = _merge(cfg_defaults, {k: v for k, v in raw.items() if k != "name"})
    name = raw.get("name")
    if not isinstance(name, str) or not DEVICE_NAME_RE.match(name):
        ctx.err(f"{path}.name", "required; letters, digits, '.', '_' or '-' (max 64, must start alphanumeric)")
        name = None
    d = ctx.mapping(path, merged, _DEVICE_KEYS)
    address = ctx.string(path, d, "address")
    esphome_name = ctx.string(path, d, "esphome_name")
    config_file = ctx.string(path, d, "config_file")
    _check_address(ctx, f"{path}.address", address)
    if esphome_name is not None and not DEVICE_NAME_RE.match(esphome_name):
        ctx.err(f"{path}.esphome_name", "invalid ESPHome device name")
    if config_file is not None:
        p = Path(config_file)
        if not p.is_absolute():
            ctx.err(f"{path}.config_file", "must be an absolute path (a path inside the container)")
        elif not p.is_file():
            ctx.err(f"{path}.config_file", f"file not found or not a regular file: {config_file}")
        elif not os.access(p, os.R_OK):
            ctx.err(f"{path}.config_file", f"file is not readable: {config_file}")
    backend = ctx.string(path, d, "backend", "auto")
    if backend not in BACKENDS:
        ctx.err(f"{path}.backend", f"must be one of {', '.join(BACKENDS)}")
        backend = "auto"
    if backend == "auto":
        backend = "cli" if config_file else "api"
    if backend == "cli" and not config_file:
        ctx.err(f"{path}.config_file", "required by the 'cli' backend (`esphome logs` needs a YAML file); "
                "use backend: api for devices without a configuration file")
    if address is None and esphome_name is None:
        ctx.err(path, "one of 'address' or 'esphome_name' is required")

    lraw = ctx.mapping(f"{path}.logs", d.get("logs"), _LOGS_KEYS)
    if backend == "api":
        own = raw.get("logs")
        used = [k for k, v in (own.items() if isinstance(own, dict) else ()) if v not in (None, False, [])]
        if used:
            ctx.err(f"{path}.logs", f"options {used} only apply to the 'cli' backend (`esphome logs`)")
        lraw = {}  # inherited defaults are irrelevant for the api backend
    reset = ctx.boolean(f"{path}.logs", lraw, "reset", False)
    states = ctx.boolean(f"{path}.logs", lraw, "states", None)
    extra_args = ctx.string_list(f"{path}.logs", lraw, "extra_args")
    logs = LogsOptions(
        device=ctx.string(f"{path}.logs", lraw, "device"),
        mqtt_topic=ctx.string(f"{path}.logs", lraw, "mqtt_topic"),
        mqtt_username=ctx.string(f"{path}.logs", lraw, "mqtt_username"),
        mqtt_password=ctx.secret(f"{path}.logs", lraw, "mqtt_password"),
        client_id=ctx.string(f"{path}.logs", lraw, "client_id"),
        reset=bool(reset),
        states=states,
        extra_args=extra_args,
    )
    for problem in validate_extra_args(extra_args):
        ctx.err(f"{path}.logs", problem)

    araw = ctx.mapping(f"{path}.api", d.get("api"), _API_KEYS)
    api = ApiOptions(
        port=ctx.number(f"{path}.api", araw, "port", 6053, 1, 65535, integer=True),
        noise_psk=ctx.secret(f"{path}.api", araw, "noise_psk"),
        password=ctx.secret(f"{path}.api", araw, "password"),
        connect_timeout=ctx.number(f"{path}.api", araw, "connect_timeout", 30.0, 0.0, exclusive_min=True),
    )
    subs_raw = d.get("substitutions")
    subs: tuple[tuple[str, str], ...] = ()
    if subs_raw is not None:
        if not isinstance(subs_raw, dict) or not all(isinstance(k, str) and isinstance(v, (str, int, float)) and not isinstance(v, bool)
                                                     for k, v in subs_raw.items()):
            ctx.err(f"{path}.substitutions", "expected a mapping of names to scalar values")
        else:
            subs = tuple((k, str(v)) for k, v in subs_raw.items())
    craw = ctx.mapping(f"{path}.capture", d.get("capture"), {"enabled", "watch_files"})
    capture = DeviceCapture(
        enabled=bool(ctx.boolean(f"{path}.capture", craw, "enabled", True)),
        watch_files=ctx.string_list(f"{path}.capture", craw, "watch_files"),
    )
    for wf in capture.watch_files:
        if not Path(wf).is_absolute():
            ctx.err(f"{path}.capture.watch_files", f"{wf!r} must be an absolute path")
    device = DeviceConfig(
        name=name or "?", backend=backend, address=address, esphome_name=esphome_name,
        config_file=config_file, enabled=bool(ctx.boolean(path, d, "enabled", True)),
        logs=logs, api=api, retry=_build_retry(ctx, f"{path}.retry", d.get("retry")),
        idle_timeout=ctx.number(path, d, "idle_timeout", 0.0, 0.0),
        substitutions=subs, capture=capture, source=source,
    )
    return device if name else None


def make_discovered_device(config: Config, name: str, address: str, config_file: str | None) -> DeviceConfig:
    """Build a device for an mDNS-discovered target using the global defaults."""
    ctx = _Ctx()
    raw: dict[str, Any] = {"name": name, "esphome_name": name, "address": address}
    if config_file:
        raw["config_file"] = config_file
    device = _build_device(ctx, f"discovered[{name}]", raw, config.defaults, "discovered")
    if ctx.errors or device is None:
        raise ConfigError(ctx.errors)
    return device


def load_config(path: str | os.PathLike[str]) -> Config:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as err:
        raise ConfigError([f"cannot read configuration file {path}: {err.strerror}"]) from err
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as err:
        raise ConfigError([f"{path} is not valid YAML: {err}"]) from err
    return parse_config(raw)


def parse_config(raw: Any) -> Config:
    ctx = _Ctx()
    top = ctx.mapping(
        "config", raw,
        {"collector", "storage", "defaults", "devices", "discovery", "retention", "capture", "web"},
    )

    col = ctx.mapping("collector", top.get("collector"), {"log_level", "esphome_command", "stop_grace_seconds"})
    log_level = str(ctx.string("collector", col, "log_level", "INFO")).upper()
    if log_level not in LOG_LEVELS:
        ctx.err("collector.log_level", f"must be one of {', '.join(LOG_LEVELS)}")
    command = ctx.string_list("collector", col, "esphome_command") or (sys.executable, "-m", "esphome")
    grace = ctx.number("collector", col, "stop_grace_seconds", 10.0, 0.0)

    st = ctx.mapping("storage", top.get("storage"), {"path", "export_dir", "raw_files"})
    data_dir = Path(ctx.string("storage", st, "path", "/data"))
    if not data_dir.is_absolute():
        ctx.err("storage.path", "must be an absolute path")
    export_dir = Path(ctx.string("storage", st, "export_dir", str(data_dir / "exports")))
    if not export_dir.is_absolute():
        ctx.err("storage.export_dir", "must be an absolute path")
    rf = ctx.mapping("storage.raw_files", st.get("raw_files"), {"enabled", "max_file_mb"})
    raw_files = RawFilesConfig(
        enabled=bool(ctx.boolean("storage.raw_files", rf, "enabled", False)),
        max_file_mb=ctx.number("storage.raw_files", rf, "max_file_mb", 50.0, 1.0),
    )

    defaults_raw = top.get("defaults") or {}
    ctx.mapping("defaults", defaults_raw, _DEFAULT_KEYS)
    if isinstance(defaults_raw, dict):
        dl = defaults_raw.get("logs")
        if isinstance(dl, dict):
            for key in dl:
                if key in {"device", "reset"}:
                    ctx.err(f"defaults.logs.{key}", "cannot be set globally; configure it per device"
                            + (" (reset is disruptive and needs an explicit per-device opt-in)" if key == "reset" else ""))
            ctx.mapping("defaults.logs", dl, _DEFAULT_LOGS_KEYS)
    defaults = {k: v for k, v in defaults_raw.items() if k in _DEFAULT_KEYS} if isinstance(defaults_raw, dict) else {}

    devices: list[DeviceConfig] = []
    raw_devices = top.get("devices") or []
    if not isinstance(raw_devices, list):
        ctx.err("devices", "expected a list")
        raw_devices = []
    seen: dict[str, int] = {}
    for i, item in enumerate(raw_devices):
        label = item.get("name") if isinstance(item, dict) and isinstance(item.get("name"), str) else i
        path = f"devices[{label}]"
        if not isinstance(item, dict):
            ctx.err(path, "expected a mapping")
            continue
        device = _build_device(ctx, path, item, defaults, "explicit")
        if device is None:
            continue
        if device.name.lower() in seen:
            ctx.err(f"{path}.name", f"duplicate device name {device.name!r}")
            continue
        seen[device.name.lower()] = i
        devices.append(device)

    dc = ctx.mapping("discovery", top.get("discovery"), {
        "enabled", "interval_seconds", "scan_timeout", "names", "name_prefixes", "exclude_names",
        "allow_all", "config_dir"})
    discovery = DiscoveryConfig(
        enabled=bool(ctx.boolean("discovery", dc, "enabled", False)),
        interval_seconds=ctx.number("discovery", dc, "interval_seconds", 0.0, 0.0),
        scan_timeout=ctx.number("discovery", dc, "scan_timeout", 10.0, 1.0),
        names=ctx.string_list("discovery", dc, "names"),
        name_prefixes=ctx.string_list("discovery", dc, "name_prefixes"),
        exclude_names=ctx.string_list("discovery", dc, "exclude_names"),
        allow_all=bool(ctx.boolean("discovery", dc, "allow_all", False)),
        config_dir=ctx.string("discovery", dc, "config_dir"),
    )
    if discovery.enabled and not (discovery.names or discovery.name_prefixes or discovery.allow_all):
        ctx.err("discovery", "enabled without a filter: set 'names' and/or 'name_prefixes', "
                "or explicitly set allow_all: true to collect from every ESPHome device found")
    if discovery.config_dir and not Path(discovery.config_dir).is_dir():
        ctx.err("discovery.config_dir", f"directory not found: {discovery.config_dir}")
    if discovery.enabled and not discovery.config_dir:
        ctx.warnings.append("discovery.config_dir not set: discovered devices use the 'api' backend")

    rt = ctx.mapping("retention", top.get("retention"), {
        "max_age_days", "max_total_size_mb", "cleanup_interval_seconds", "batch_size", "max_batches_per_run",
        "per_device", "exports", "config_snapshots"})
    per_device: dict[str, DeviceRetention] = {}
    pd = rt.get("per_device") or {}
    if not isinstance(pd, dict):
        ctx.err("retention.per_device", "expected a mapping of device name to limits")
        pd = {}
    for dev, limits in pd.items():
        p = f"retention.per_device.{dev}"
        lim = ctx.mapping(p, limits, {"max_age_days", "max_events"})
        per_device[str(dev)] = DeviceRetention(
            max_age_days=ctx.number(p, lim, "max_age_days", None, 0.0, exclusive_min=True),
            max_events=ctx.number(p, lim, "max_events", None, 1, integer=True),
        )
    ex = ctx.mapping("retention.exports", rt.get("exports"), {"max_age_days", "max_total_size_mb"})
    cs = ctx.mapping("retention.config_snapshots", rt.get("config_snapshots"), {"max_age_days", "keep_last"})
    retention = RetentionConfig(
        max_age_days=ctx.number("retention", rt, "max_age_days", None, 0.0, exclusive_min=True),
        max_total_size_mb=ctx.number("retention", rt, "max_total_size_mb", None, 1.0),
        cleanup_interval_seconds=ctx.number("retention", rt, "cleanup_interval_seconds", 3600.0, 1.0),
        batch_size=ctx.number("retention", rt, "batch_size", 5000, 1, integer=True),
        max_batches_per_run=ctx.number("retention", rt, "max_batches_per_run", 200, 1, integer=True),
        per_device=per_device,
        exports_max_age_days=ctx.number("retention.exports", ex, "max_age_days", 14.0, 0.0, exclusive_min=True),
        exports_max_total_size_mb=ctx.number("retention.exports", ex, "max_total_size_mb", None, 1.0),
        configs_max_age_days=ctx.number("retention.config_snapshots", cs, "max_age_days", None, 0.0, exclusive_min=True),
        configs_keep_last=ctx.number("retention.config_snapshots", cs, "keep_last", 20, 1, integer=True),
    )
    for dev in per_device:
        if dev.lower() not in seen and not discovery.enabled:
            ctx.err(f"retention.per_device.{dev}", "does not match any configured device")

    cp = ctx.mapping("capture", top.get("capture"), {
        "enabled", "on_startup", "interval_seconds", "on_change", "timeout",
        "extra_key_patterns", "extra_value_patterns"})
    capture = CaptureConfig(
        enabled=bool(ctx.boolean("capture", cp, "enabled", False)),
        on_startup=bool(ctx.boolean("capture", cp, "on_startup", True)),
        interval_seconds=ctx.number("capture", cp, "interval_seconds", 0.0, 0.0),
        on_change=bool(ctx.boolean("capture", cp, "on_change", False)),
        timeout=ctx.number("capture", cp, "timeout", 120.0, 1.0),
        extra_key_patterns=ctx.string_list("capture", cp, "extra_key_patterns"),
        extra_value_patterns=ctx.string_list("capture", cp, "extra_value_patterns"),
    )
    for key in ("extra_key_patterns", "extra_value_patterns"):
        for pattern in getattr(capture, key):
            try:
                re.compile(pattern)
            except re.error as err:
                ctx.err(f"capture.{key}", f"invalid regular expression {pattern!r}: {err}")

    wb = ctx.mapping("web", top.get("web"), {"enabled", "bind", "port", "page_size", "allowed_hosts"})
    web = WebConfig(
        enabled=bool(ctx.boolean("web", wb, "enabled", True)),
        bind=ctx.string("web", wb, "bind", "127.0.0.1"),
        port=ctx.number("web", wb, "port", 8080, 1, 65535, integer=True),
        page_size=ctx.number("web", wb, "page_size", 100, 1, 500, integer=True),
        allowed_hosts=ctx.string_list("web", wb, "allowed_hosts"),
    )
    try:
        ipaddress.ip_address(web.bind)
    except ValueError:
        ctx.err("web.bind", f"{web.bind!r} must be an IP address (use 127.0.0.1 or 0.0.0.0)")
    else:
        if web.enabled and not ipaddress.ip_address(web.bind).is_loopback:
            ctx.warnings.append(
                f"web.bind {web.bind}: the web UI has no authentication; "
                "put it behind an authenticated reverse proxy or restrict access with firewalling"
            )

    if not devices and not discovery.enabled:
        ctx.err("devices", "no devices configured and discovery is disabled; nothing to collect")

    if ctx.errors:
        raise ConfigError(ctx.errors)
    return Config(
        data_dir=data_dir, export_dir=export_dir, log_level=log_level, esphome_command=tuple(command),
        stop_grace_seconds=grace, devices=tuple(devices), discovery=discovery, raw_files=raw_files,
        retention=retention, capture=capture, web=web, defaults=defaults,
        secrets=tuple(dict.fromkeys(ctx.secrets)), warnings=tuple(ctx.warnings),
    )


__all__ = ["Config", "ConfigError", "DeviceConfig", "Secret", "load_config", "parse_config",
           "make_discovered_device"]
