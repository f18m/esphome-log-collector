import importlib.util
import shutil
import subprocess
import sys

import pytest


@pytest.mark.skipif(
    shutil.which("esphome") is None and importlib.util.find_spec("esphome") is None,
    reason="esphome not installed",
)
def test_esphome_resolves_substitution_in_dynamic_include_path(tmp_path):
    (tmp_path / "config.yaml").write_text(
        "substitutions:\n"
        "  target_platform: esp32\n"
        "esphome:\n"
        "  name: dynamic-include-smoke-test\n"
        "esp32:\n"
        "  board: esp32dev\n"
        "packages:\n"
        "  hardware: !include\n"
        "    file: include_${target_platform}.yaml\n"
        "    vars: {}\n"
    )
    (tmp_path / "include_esp32.yaml").write_text("logger: {}\n")

    result = subprocess.run(
        [sys.executable, "-m", "esphome", "config", str(tmp_path / "config.yaml")],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
