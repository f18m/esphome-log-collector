"""Mapping of YAML options to `esphome logs` command line arguments.

Verified against the pinned ESPHome version (see SUPPORTED_ESPHOME_VERSION), whose
`esphome logs --help` offers exactly these options::

    esphome logs [-h] [--topic TOPIC] [--username USERNAME] [--password PASSWORD]
                 [--client-id CLIENT_ID] [--device DEVICE] [--reset] configuration

`--states/--no-states` is NOT offered by that version. The `states` option exists in the
YAML schema so that it can be enabled when ESPHome is upgraded, but setting it is a
validation error while it is absent from SUPPORTED_FLAGS.

Commands are always built as argument lists; no shell is ever involved.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Sequence

if TYPE_CHECKING:
    from .config import DeviceConfig, LogsOptions

# option -> flags offered by the pinned `esphome logs`
SUPPORTED_FLAGS = {
    "mqtt_topic": "--topic",
    "mqtt_username": "--username",
    "mqtt_password": "--password",
    "client_id": "--client-id",
    "device": "--device",
    "reset": "--reset",
}
UNSUPPORTED_OPTIONS = {
    "states": "`--states/--no-states` is not offered by `esphome logs` in the pinned ESPHome version",
}

# Flags the collector controls itself (or which would break supervision) and may not be
# passed through `extra_args`, including their abbreviations.
_MANAGED = {
    "-h", "--help", "--topic", "--username", "--password", "--client-id", "--device", "--reset", "-r",
    "--states", "--no-states", "-c", "--config", "--configuration", "-o", "--output", "--output-file",
    "--log-file", "--logfile", "--file", "-s", "--substitution", "--substitutions", "-l", "--log-level",
    "-q", "--quiet", "-v", "--verbose",
}
_MANAGED_LONG = tuple(m for m in _MANAGED if m.startswith("--"))
_ARG_RE = re.compile(r"^--?[A-Za-z][A-Za-z0-9-]*(=[^\x00\n]*)?$")


def validate_logs_support(options: "LogsOptions") -> list[str]:
    problems = []
    if options.states is not None:
        problems.append(UNSUPPORTED_OPTIONS["states"] + "; remove the 'states' option")
    return problems


def validate_extra_args(args: Sequence[str]) -> list[str]:
    """Pass-through arguments must be flags (`--flag` or `--flag=value`) and not managed ones."""
    problems = []
    for arg in args:
        if not _ARG_RE.match(arg):
            problems.append(
                f"extra_args entry {arg!r} must be a flag like '--flag' or '--flag=value' "
                "(positional values are not allowed)"
            )
            continue
        flag = arg.split("=", 1)[0]
        # argparse accepts unambiguous abbreviations, so `--dev` must be blocked as well as `--device`
        if flag in _MANAGED or (flag.startswith("--") and any(m.startswith(flag) for m in _MANAGED_LONG)):
            problems.append(f"extra_args entry {arg!r} is managed by the collector and cannot be overridden")
    return problems


def global_args(device: "DeviceConfig") -> list[str]:
    """Top-level `esphome` options placed before the sub-command (substitutions)."""
    args: list[str] = []
    for key, value in device.substitutions:
        args += ["-s", key, value]
    return args


def build_logs_command(base: Sequence[str], device: "DeviceConfig") -> list[str]:
    """Full argv for `esphome logs` for a device (backend 'cli')."""
    if not device.config_file:
        raise ValueError(f"device {device.name}: the cli backend requires config_file")
    opts = device.logs
    target = opts.device or device.address
    args = [*base, *global_args(device), "logs"]
    if opts.mqtt_topic:
        args += [SUPPORTED_FLAGS["mqtt_topic"], opts.mqtt_topic]
    if opts.mqtt_username:
        args += [SUPPORTED_FLAGS["mqtt_username"], opts.mqtt_username]
    if opts.mqtt_password:
        args += [SUPPORTED_FLAGS["mqtt_password"], opts.mqtt_password.reveal()]
    if opts.client_id:
        args += [SUPPORTED_FLAGS["client_id"], opts.client_id]
    if target:
        args += [SUPPORTED_FLAGS["device"], target]
    if opts.reset:
        args.append(SUPPORTED_FLAGS["reset"])
    args += list(opts.extra_args)
    # `--` ends option parsing so the path can never be mistaken for a flag
    args += ["--", device.config_file]
    return args


def build_config_command(base: Sequence[str], device: "DeviceConfig") -> list[str]:
    """Argv for `esphome config`, used for configuration capture."""
    if not device.config_file:
        raise ValueError(f"device {device.name}: no config_file")
    return [*base, *global_args(device), "config", "--", device.config_file]


def redact_argv(args: Sequence[str], secrets: Sequence[str]) -> list[str]:
    """Copy of argv that is safe to log (known secrets are masked wherever they appear)."""
    out = list(args)
    for i, arg in enumerate(out):
        if arg == "--password" and i + 1 < len(out):
            out[i + 1] = "***"
    masked = []
    for arg in out:
        for secret in secrets:
            if secret:
                arg = arg.replace(secret, "***")
        masked.append(arg)
    return masked
