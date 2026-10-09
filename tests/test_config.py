import os
from pathlib import Path

import pytest
import yaml

from esphome_log_collector.config import ConfigError, parse_config, load_config, make_discovered_device

BASE = {"storage": {"path": "/data"}}


def cfg(**kw):
    return parse_config({**BASE, **kw})


def errors_of(**kw) -> str:
    with pytest.raises(ConfigError) as exc:
        cfg(**kw)
    return str(exc.value)


def test_defaults_and_overrides(tmp_path):
    f = tmp_path / "a.yaml"
    f.write_text("esphome: {}\n")
    c = cfg(
        defaults={"retry": {"initial_delay": 5, "max_delay": 50}, "idle_timeout": 30,
                  "logs": {"client_id": "shared"}},
        devices=[
            {"name": "a", "address": "10.0.0.1", "config_file": str(f)},
            {"name": "b", "address": "10.0.0.2", "backend": "api", "retry": {"initial_delay": 1},
             "idle_timeout": 0},
        ],
    )
    a, b = c.devices
    assert a.backend == "cli" and b.backend == "api"  # auto resolution
    assert a.retry.initial_delay == 5 and a.retry.max_delay == 50
    assert b.retry.initial_delay == 1 and b.retry.max_delay == 50  # per-device override merges
    assert a.idle_timeout == 30 and b.idle_timeout == 0
    assert a.logs.client_id == "shared"
    assert a.logs.reset is False  # never enabled by default
    assert c.web.enabled is False and c.web.bind == "127.0.0.1"
    assert c.discovery.enabled is False


def test_all_errors_reported_together():
    msg = errors_of(devices=[{"name": "bad name!", "address": "x"}, {"name": "ok", "bogus": 1}])
    assert "devices[bad name!].name" in msg and "devices[ok].bogus" in msg and "address" in msg


def test_cli_backend_requires_existing_config_file(tmp_path):
    msg = errors_of(devices=[{"name": "a", "address": "1.2.3.4", "backend": "cli",
                              "config_file": str(tmp_path / "missing.yaml")}])
    assert "file not found" in msg
    msg = errors_of(devices=[{"name": "a", "address": "1.2.3.4", "backend": "cli"}])
    assert "required by the 'cli' backend" in msg


def test_reset_needs_per_device_opt_in(tmp_path):
    f = tmp_path / "a.yaml"
    f.write_text("x: 1\n")
    assert "cannot be set globally" in errors_of(
        defaults={"logs": {"reset": True}}, devices=[{"name": "a", "address": "1.1.1.1", "config_file": str(f)}])
    c = cfg(devices=[{"name": "a", "address": "1.1.1.1", "config_file": str(f), "logs": {"reset": True}}])
    assert c.devices[0].logs.reset is True


def test_states_option_is_supported_for_pinned_version(tmp_path):
    f = tmp_path / "a.yaml"
    f.write_text("x: 1\n")
    c = cfg(devices=[{"name": "a", "address": "1.1.1.1", "config_file": str(f), "logs": {"states": False}}])
    assert c.devices[0].logs.states is False


@pytest.mark.parametrize("arg", ["--device=x", "--config=y", "-o=1", "positional", "--res", "--output-file"])
def test_unsafe_extra_args_rejected(tmp_path, arg):
    f = tmp_path / "a.yaml"
    f.write_text("x: 1\n")
    with pytest.raises(ConfigError):
        cfg(devices=[{"name": "a", "address": "1.1.1.1", "config_file": str(f), "logs": {"extra_args": [arg]}}])


def test_secret_references(tmp_path, monkeypatch):
    secret_file = tmp_path / "pw"
    secret_file.write_text("from-file\n")
    monkeypatch.setenv("MQTT_PW", "from-env")
    c = cfg(devices=[
        {"name": "a", "address": "1.1.1.1", "backend": "api",
         "api": {"password": {"env": "MQTT_PW"}, "noise_psk": {"file": str(secret_file)}}}])
    api = c.devices[0].api
    assert api.password.reveal() == "from-env" and api.noise_psk.reveal() == "from-file"
    assert "from-env" not in repr(c) and "from-file" not in repr(c)
    assert set(c.secrets) == {"from-env", "from-file"}


def test_missing_secret_is_an_error_not_a_default(monkeypatch):
    monkeypatch.delenv("NOPE", raising=False)
    msg = errors_of(devices=[{"name": "a", "address": "1.1.1.1", "backend": "api", "api": {"password": {"env": "NOPE"}}}])
    assert "'NOPE' is not set" in msg
    msg = errors_of(devices=[{"name": "a", "address": "1.1.1.1", "backend": "api",
                              "api": {"noise_psk": {"file": "/nonexistent/secret"}}}])
    assert "cannot read secret file" in msg


def test_api_backend_rejects_cli_only_options():
    assert "only apply to the 'cli' backend" in errors_of(
        devices=[{"name": "a", "address": "1.1.1.1", "backend": "api", "logs": {"mqtt_topic": "t"}}])


def test_discovery_requires_filter():
    assert "enabled without a filter" in errors_of(discovery={"enabled": True})
    c = cfg(discovery={"enabled": True, "name_prefixes": ["s-"]})
    assert c.discovery.enabled


def test_nothing_to_collect_is_an_error():
    assert "nothing to collect" in errors_of()


def test_duplicate_device_names():
    msg = errors_of(devices=[{"name": "a", "address": "1.1.1.1"}, {"name": "A", "address": "1.1.1.2"}])
    assert "duplicate" in msg


def test_web_defaults_to_localhost_and_warns_on_public_bind():
    assert cfg(devices=[{"name": "a", "address": "1.1.1.1"}], web={"enabled": True}).web.bind == "127.0.0.1"
    c = cfg(devices=[{"name": "a", "address": "1.1.1.1"}], web={"enabled": True, "bind": "0.0.0.0"})
    assert any("no authentication" in w for w in c.warnings)


def test_invalid_yaml_and_missing_file(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("a: [unclosed\n")
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(bad)
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "nope.yaml")


def test_retention_per_device_must_match_a_device():
    assert "does not match" in errors_of(devices=[{"name": "a", "address": "1.1.1.1"}],
                                         retention={"per_device": {"zzz": {"max_events": 5}}})


def test_make_discovered_device_uses_defaults():
    c = cfg(defaults={"retry": {"initial_delay": 7, "max_delay": 70}}, discovery={"enabled": True, "names": ["k"]})
    d = make_discovered_device(c, "k", "10.1.1.1", None)
    assert d.backend == "api" and d.source == "discovered" and d.retry.initial_delay == 7


def test_example_configuration_is_valid(tmp_path, monkeypatch):
    example = Path(__file__).parent.parent / "examples" / "config.example.yaml"
    text = example.read_text()
    conf_dir = tmp_path / "config"
    (conf_dir / "devices").mkdir(parents=True)
    for n in ("living-room", "garage", "bench", "secrets"):
        (conf_dir / "devices" / f"{n}.yaml").write_text("esphome: {}\n")
    secrets = tmp_path / "run"
    secrets.mkdir()
    (secrets / "mqtt_password").write_text("pw\n")
    text = text.replace("/config/", f"{conf_dir}/").replace("/run/secrets/", f"{secrets}/")
    text = text.replace("path: /data", f"path: {tmp_path}/data").replace("export_dir: /data/exports", f"export_dir: {tmp_path}/data/exports")
    monkeypatch.setenv("ESPHOME_MQTT_PASSWORD", "x")
    monkeypatch.setenv("PORCH_API_KEY", "y")
    conf = tmp_path / "c.yaml"
    conf.write_text(text)
    c = load_config(conf)
    names = [d.name for d in c.devices]
    assert names == ["living-room", "garage", "porch", "bench-serial"]
    porch = c.devices[2]
    assert porch.backend == "api" and porch.logs.mqtt_password is None  # defaults for cli don't leak into api
    assert c.devices[3].logs.reset is True and c.devices[0].logs.reset is False
    assert yaml.safe_load(text)["web"]["enabled"] is False
