"""Redaction of secrets and credential-like values from `esphome config` output."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Iterable

import yaml

REDACTED = "[REDACTED]"
log = logging.getLogger("collector.redact")

# Any YAML key containing one of these (case-insensitive) is treated as sensitive.
DEFAULT_KEY_PATTERN = (
    r"pass(word|wd|phrase)|psk|secret|token|key|credential|auth|bearer|"
    r"private|cert|signature|pairing"
)

_KEY_LINE = re.compile(
    r"^(?P<indent>\s*)(?P<dash>(?:-\s+)*)(?P<key>\"[^\"]*\"|'[^']*'|[^\s:#'\"][^:#]*?)\s*:(?:\s+|$)(?P<value>.*)$"
)
_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----")
_PEM_END = re.compile(r"-----END [A-Z ]*(PRIVATE KEY|CERTIFICATE)-----")
_URL_CREDS = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]*@")
_BLOCK_INDICATOR = re.compile(r"^[|>][+-]?\d*\s*$")


class Redactor:
    """Redacts sensitive content line by line.

    * values of keys matching the key pattern (plus configured extra key patterns),
      including nested mappings/lists and block scalars below such keys
    * PEM private key / certificate blocks
    * credentials embedded in URL userinfo
    * configured extra value patterns, and exact secret values known to the collector
    """

    def __init__(
        self,
        extra_key_patterns: Iterable[str] = (),
        extra_value_patterns: Iterable[str] = (),
        known_secrets: Iterable[str] = (),
    ) -> None:
        keys = [DEFAULT_KEY_PATTERN, *extra_key_patterns]
        self._key_re = re.compile("|".join(f"(?:{p})" for p in keys), re.IGNORECASE)
        self._value_res = [re.compile(p) for p in extra_value_patterns]
        self._known = sorted({s for s in known_secrets if s and len(s) >= 4}, key=len, reverse=True)
        self._in_pem = False
        self._skip_below: int | None = None

    def reset(self) -> None:
        self._in_pem = False
        self._skip_below = None

    def redact_text(self, text: str) -> str:
        out: list[str] = []
        self.reset()
        for line in text.splitlines():
            out.append(self.redact_line(line))
        return "\n".join(out) + ("\n" if text.endswith("\n") else "")

    def redact_line(self, line: str) -> str:
        """Redact one streamed line while preserving multi-line secret-block state."""
        if self._in_pem:
            if _PEM_END.search(line):
                self._in_pem = False
            return ""
        begin = _PEM_BEGIN.search(line)
        if begin:
            self._in_pem = not _PEM_END.search(line, begin.end())
            return line[: begin.start()] + REDACTED
        indent = len(line) - len(line.lstrip(" "))
        if self._skip_below is not None:
            if not line.strip() or indent > self._skip_below:
                return ""
            self._skip_below = None
        match = _KEY_LINE.match(line)
        if match and self._key_re.search(match.group("key").strip("'\"")):
            key_col = len(match.group("indent")) + len(match.group("dash"))
            if match.group("value").strip() == "" or _BLOCK_INDICATOR.match(match.group("value").strip()):
                self._skip_below = key_col
            return f"{match.group('indent')}{match.group('dash')}{match.group('key')}: {REDACTED}"
        return self._scrub_inline(line)

    def _scrub_inline(self, line: str) -> str:
        line = _URL_CREDS.sub(lambda m: f"{m.group('scheme')}{REDACTED}@", line)
        for pattern in self._value_res:
            line = pattern.sub(REDACTED, line)
        for secret in self._known:
            line = line.replace(secret, REDACTED)
        return line


def load_esphome_secret_values(config_file: str | None) -> tuple[str, ...]:
    """Read scalar values from the standard adjacent ESPHome secrets.yaml for scrubbing."""
    if not config_file:
        return ()
    path = Path(config_file).parent / "secrets.yaml"
    try:
        values = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return ()
    except OSError as err:
        log.warning("cannot read %s for log redaction (%s)", path, err.strerror)
        return ()
    except yaml.YAMLError:
        log.warning("cannot parse %s for log redaction; key-based redaction remains active", path)
        return ()

    secrets: set[str] = set()

    def collect(value: object) -> None:
        if isinstance(value, dict):
            for nested in value.values():
                collect(nested)
        elif isinstance(value, list):
            for nested in value:
                collect(nested)
        elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
            secrets.add(str(value))

    collect(values)
    return tuple(secrets)
