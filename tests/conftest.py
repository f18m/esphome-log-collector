import json
import sys
from pathlib import Path

import pytest

from esphome_log_collector.config import parse_config

FAKE = str(Path(__file__).with_name("fake_esphome.py"))


def device_file(directory: Path, name: str, **spec) -> str:
    path = directory / f"{name}.json"
    path.write_text(json.dumps(spec))
    return str(path)


def build_config(tmp_path: Path, devices: list[dict], **sections) -> "Config":  # noqa: F821
    raw = {
        "collector": {"esphome_command": [sys.executable, FAKE], "stop_grace_seconds": 3},
        "storage": {"path": str(tmp_path / "data")},
        "devices": devices,
        "defaults": {"retry": {"initial_delay": 0.1, "max_delay": 0.2, "jitter": 0.0}},
    }
    for key, value in sections.items():
        raw[key] = {**raw.get(key, {}), **value} if isinstance(value, dict) else value
    return parse_config(raw)


@pytest.fixture
def make_config(tmp_path):
    return lambda devices, **sections: build_config(tmp_path, devices, **sections)
