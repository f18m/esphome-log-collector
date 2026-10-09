import asyncio

from esphome_log_collector.config import make_discovered_device, parse_config
from esphome_log_collector.discovery import Discovered, discovery_loop, matches_filter, new_targets
from esphome_log_collector.redact import REDACTED, Redactor, load_esphome_secret_values

SAMPLE = """\
esphome:
  name: kitchen
wifi:
  ssid: HomeNet
  password: SuperSecretWifi
  networks:
    - ssid: Other
      password: "another secret"
api:
  encryption:
    key: dGhpcyBpcyBhIGtleQ==
ota:
  - platform: esphome
    password: otapass1234
mqtt:
  broker: mqtt://user:brokerpass@10.0.0.2:1883
  username: bob
  password: mqttpass
  discovery_cert: |
    line1
    line2
  keep: visible
my_custom_secret: custom-value
note: contains legacy-token-ABCD1234 inline
cert: |
  -----BEGIN PRIVATE KEY-----
  MIIEvQIBADANBgkqhkiG9w0BAQEFAASC
  -----END PRIVATE KEY-----
after: ok
"""


def test_redaction_removes_credentials_and_keeps_structure():
    r = Redactor(extra_key_patterns=["^my_custom_secret$"], extra_value_patterns=[r"legacy-token-\w+"])
    out = r.redact_text(SAMPLE)
    for leaked in ("SuperSecretWifi", "another secret", "dGhpcyBpcyBhIGtleQ", "otapass1234", "brokerpass",
                   "mqttpass", "line1", "custom-value", "legacy-token-ABCD1234", "MIIEvQ", "BEGIN PRIVATE"):
        assert leaked not in out, leaked
    assert "ssid: HomeNet" in out and "keep: visible" in out and "after: ok" in out
    assert out.count(REDACTED) >= 8


def test_known_secrets_are_scrubbed_anywhere():
    out = Redactor(known_secrets=["s3cr3t-value"]).redact_text("name: dev-s3cr3t-value-x\n")
    assert "s3cr3t-value" not in out


def test_streaming_redaction_hides_sensitive_blocks_across_lines():
    r = Redactor()
    lines = [
        r.redact_line("api:"),
        r.redact_line("  encryption:"),
        r.redact_line("    key: |"),
        r.redact_line("      private-material"),
        r.redact_line("  password: cleartext-password"),
    ]
    assert "private-material" not in "\n".join(lines)
    assert "cleartext-password" not in "\n".join(lines)
    assert lines[-1] == f"  password: {REDACTED}"


def test_esphome_secret_values_are_loaded_for_log_redaction(tmp_path):
    config = tmp_path / "device.yaml"
    config.write_text("esphome: {}\n")
    (tmp_path / "secrets.yaml").write_text("wifi_password: hidden-value\nnested:\n  key: hidden-key\n")
    assert set(load_esphome_secret_values(str(config))) == {"hidden-value", "hidden-key"}


def test_discovery_filters_and_dedup():
    cfg = parse_config({"devices": [
        {"name": "explicit", "esphome_name": "kitchen-sensor", "address": "10.0.0.9"}],
        "discovery": {"enabled": True, "names": ["porch"], "name_prefixes": ["sensor-"], "exclude_names": ["sensor-bad"]}})
    found = [Discovered("kitchen-sensor", "10.0.0.20"), Discovered("porch", "10.0.0.21"),
             Discovered("sensor-1", "10.0.0.22"), Discovered("sensor-bad", "10.0.0.23"),
             Discovered("other", "10.0.0.24"), Discovered("renamed", "10.0.0.9"),
             Discovered("Porch", "10.0.0.25")]
    cfg.discovery  # noqa: B018
    names = [d.name for d in new_targets(found, cfg.discovery, cfg.devices)]
    assert names == ["porch", "sensor-1"]  # dup of explicit name/address, excluded and unlisted are dropped
    assert matches_filter("anything", parse_config({"devices": [{"name": "a", "address": "1.1.1.1"}],
                                                    "discovery": {"enabled": True, "allow_all": True}}).discovery)


def test_discovery_loop_adds_only_new_devices():
    cfg = parse_config({"devices": [{"name": "explicit", "address": "10.0.0.9"}],
                        "discovery": {"enabled": True, "name_prefixes": ["s-"]}})
    added = []

    async def scanner(_):
        return [Discovered("s-1", "10.0.0.31"), Discovered("explicit", "10.0.0.9")]

    asyncio.run(discovery_loop(cfg, asyncio.Event(), lambda: list(added), lambda d: added.append(d) or True, scanner))
    assert [d.name for d in added] == ["s-1"] and added[0].source == "discovered"
    assert make_discovered_device(cfg, "s-2", "10.0.0.32", None).address == "10.0.0.32"
