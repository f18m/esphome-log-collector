"""Best-effort parsing of ESPHome log lines. The raw line is never modified."""

from __future__ import annotations

import re
from dataclasses import dataclass

ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")

LEVELS = {
    "V": "VERY_VERBOSE",
    "D": "DEBUG",
    "C": "CONFIG",
    "I": "INFO",
    "W": "WARNING",
    "E": "ERROR",
}

# [12:34:56.789][I][wifi:123]: message   (ESPHome firmware format)
_DEVICE_LINE = re.compile(
    r"^\[(?P<time>\d{1,2}:\d{2}:\d{2}(?:\.\d+)?)\]"
    r"\[(?P<level>[VDCIWE])\]"
    r"\[(?P<component>[^\]:]*)(?::(?P<line>\d+))?\]:? ?(?P<message>.*)$",
    re.DOTALL,
)
# INFO message   (ESPHome CLI format)
_CLI_LINE = re.compile(r"^(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL) (?P<message>.*)$", re.DOTALL)


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


@dataclass(frozen=True)
class ParsedLine:
    level: str | None = None
    component: str | None = None
    device_time: str | None = None
    message: str | None = None


def parse_line(raw: str) -> ParsedLine:
    """Parse level/component/message when the format is recognised, else only a clean message."""
    clean = strip_ansi(raw)
    match = _DEVICE_LINE.match(clean)
    if match:
        return ParsedLine(
            level=LEVELS[match.group("level")],
            component=match.group("component") or None,
            device_time=match.group("time"),
            message=match.group("message"),
        )
    match = _CLI_LINE.match(clean)
    if match:
        return ParsedLine(level=match.group("level"), message=match.group("message"))
    return ParsedLine(message=clean)
