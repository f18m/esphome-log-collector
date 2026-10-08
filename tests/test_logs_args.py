import re
import shutil
import subprocess
import sys

import pytest

from esphome_log_collector import SUPPORTED_ESPHOME_VERSION
from esphome_log_collector.config import ApiOptions, DeviceConfig, LogsOptions, Secret
from esphome_log_collector.logs_args import (
    SUPPORTED_FLAGS, build_config_command, build_logs_command, redact_argv,
)

BASE = ["esphome"]


def device(**logs):
    return DeviceConfig(name="d", backend="cli", address="10.0.0.5", config_file="/cfg/d.yaml",
                        logs=LogsOptions(**logs), substitutions=(("room", "kitchen; rm -rf /"),))


def test_every_supported_option_maps_to_its_flag():
    argv = build_logs_command(BASE, device(
        device="/dev/ttyUSB0", mqtt_topic="t/1", mqtt_username="u", mqtt_password=Secret("pw"),
        client_id="cid", reset=True, extra_args=("--future=1",)))
    assert argv == [
        "esphome", "-s", "room", "kitchen; rm -rf /", "logs",
        "--topic", "t/1", "--username", "u", "--password", "pw", "--client-id", "cid",
        "--device", "/dev/ttyUSB0", "--reset", "--future=1", "--", "/cfg/d.yaml",
    ]


def test_defaults_use_address_and_never_reset():
    argv = build_logs_command(BASE, device())
    assert argv[argv.index("--device") + 1] == "10.0.0.5"
    assert "--reset" not in argv


def test_arguments_are_a_list_without_shell_interpolation():
    argv = build_logs_command(BASE, device(client_id="$(touch /tmp/pwned); `x`"))
    assert isinstance(argv, list) and "$(touch /tmp/pwned); `x`" in argv  # one literal element
    assert "kitchen; rm -rf /" in argv


def test_config_command_and_redacted_argv():
    assert build_config_command(BASE, device())[-3:] == ["config", "--", "/cfg/d.yaml"]
    argv = build_logs_command(BASE, device(mqtt_password=Secret("hunter22")))
    assert "hunter22" not in " ".join(redact_argv(argv, ["hunter22"]))


@pytest.mark.skipif(shutil.which("esphome") is None and not __import__("importlib").util.find_spec("esphome"),
                    reason="esphome not installed")
def test_flags_match_pinned_esphome_help():
    """The option mapping must stay aligned with the pinned ESPHome version's `logs --help`."""
    version = subprocess.run([sys.executable, "-m", "esphome", "version"], capture_output=True, text=True).stdout
    assert SUPPORTED_ESPHOME_VERSION in version
    out = subprocess.run([sys.executable, "-m", "esphome", "logs", "--help"], capture_output=True, text=True).stdout
    offered = set(re.findall(r"--[a-z][a-z-]*", out)) - {"--help"}
    assert offered == set(SUPPORTED_FLAGS.values()) - {"--states"}
    assert "--states" not in out
