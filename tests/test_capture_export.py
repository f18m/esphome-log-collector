import asyncio
import hashlib
import json
import sqlite3
import tarfile
from datetime import timedelta

import pytest

from conftest import device_file
from esphome_log_collector import storage as st
from esphome_log_collector.capture import ConfigCapture
from esphome_log_collector.export import ExportError, create_export
from esphome_log_collector.redact import Redactor
from esphome_log_collector.timeutil import format_ts, utc_now
from helpers import seed

CONFIG_OUT = """\
esphome:
  name: kitchen
wifi:
  ssid: HomeNet
  password: WifiPassw0rd
api:
  encryption:
    key: QVBJS0VZMTIzNDU2Nzg5MA==
ota:
  - platform: esphome
    password: OtaSecret99
mqtt:
  password: MqttSecret77
"""
LEAKS = ["WifiPassw0rd", "QVBJS0VZ", "OtaSecret99", "MqttSecret77"]


def test_capture_redacts_and_dedupes(tmp_path, make_config):
    f = device_file(tmp_path, "k", config_output=CONFIG_OUT)
    cfg = make_config([{"name": "k", "address": "1.1.1.1", "config_file": f}], capture={"enabled": True})
    s = st.Storage(cfg.data_dir / "db.sqlite3")
    cap = ConfigCapture(cfg, s, Redactor())
    assert asyncio.run(cap.capture_device(cfg.devices[0], "startup")) is True
    assert asyncio.run(cap.capture_device(cfg.devices[0], "scheduled")) is False  # unchanged
    content = s.latest_snapshot("k")["content"]
    assert "HomeNet" in content and not any(x in content for x in LEAKS)
    dump = "\n".join(s._conn.iterdump())
    assert not any(x in dump for x in LEAKS)
    argv = [json.loads(line) for line in open(f + ".argv")]
    assert argv[0] == ["config", "--", f]


def test_capture_failure_is_reported_not_raised(tmp_path, make_config):
    f = device_file(tmp_path, "k", config_output="", config_exit=2)
    cfg = make_config([{"name": "k", "address": "1.1.1.1", "config_file": f}], capture={"enabled": True})
    s = st.Storage(cfg.data_dir / "db.sqlite3")
    assert asyncio.run(ConfigCapture(cfg, s, Redactor()).capture_device(cfg.devices[0], "startup")) is False
    assert s.latest_snapshot("k") is None
    err = s._conn.execute("SELECT raw FROM events WHERE event_type='collector_error'").fetchone()[0]
    assert "exited with code 2" in err


def test_capture_on_change_detection(tmp_path, make_config, monkeypatch):
    from esphome_log_collector import capture as capmod

    f = device_file(tmp_path, "k", config_output=CONFIG_OUT)
    cfg = make_config([{"name": "k", "address": "1.1.1.1", "config_file": f}],
                      capture={"enabled": True, "on_startup": False, "on_change": True})
    s = st.Storage(cfg.data_dir / "db.sqlite3")
    monkeypatch.setattr(capmod, "POLL_SECONDS", 0.1)

    async def main():
        stop = asyncio.Event()
        task = asyncio.create_task(ConfigCapture(cfg, s, Redactor()).loop(stop, lambda: list(cfg.devices)))
        await asyncio.sleep(0.4)
        assert s.latest_snapshot("k") is None  # no startup capture, no change yet
        device_file(tmp_path, "k", config_output=CONFIG_OUT + "extra: 1\n")
        for _ in range(50):
            await asyncio.sleep(0.1)
            if s.latest_snapshot("k"):
                break
        stop.set()
        await task

    asyncio.run(main())
    assert "extra: 1" in s.latest_snapshot("k")["content"]


@pytest.fixture
def populated(tmp_path):
    db = tmp_path / "db.sqlite3"
    s = st.Storage(db)
    seed(s, "a", 10, age_days=2, prefix="old")
    seed(s, "a", 10, age_days=0, prefix="new")
    seed(s, "b", 5, age_days=0, prefix="bee")
    s.add_snapshot("a", "h", "c", "wifi:\n  password: leaked-secret-1\n  ssid: x\n")  # simulate legacy unredacted row
    s.set_status("a", state="connected", address="10.0.0.1")
    s.checkpoint()
    return s, db


def read_tar(path):
    with tarfile.open(path) as tar:
        return {m.name: tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()}, tar.getnames()


def test_export_contents_manifest_and_checksums(tmp_path, populated):
    s, db = populated
    out = create_export(db, tmp_path / "exports", redactor=Redactor())
    files, names = read_tar(out)
    manifest = json.loads(files["manifest.json"])
    assert manifest["format_version"] == 1 and set(manifest["devices"]) == {"a", "b"}
    for entry in manifest["files"]:
        assert hashlib.sha256(files[entry["path"]]).hexdigest() == entry["sha256"]
    assert {"logs/a.jsonl", "logs/b.jsonl", "metadata/sessions.jsonl", "metadata/device_status.json"} <= set(names)
    rows = [json.loads(line) for line in files["logs/a.jsonl"].splitlines()]
    assert len(rows) == 20 and {"timestamp", "device", "session_id", "event_type", "raw", "clean", "level"} <= set(rows[0])
    assert rows == sorted(rows, key=lambda r: (r["timestamp"], r["id"]))
    assert not any(n.endswith(("-wal", "-shm", ".sqlite3")) or ".export-tmp" in n for n in names)
    assert not any(n.startswith("/") or ".." in n for n in names)
    assert not list((tmp_path / "exports").glob(".export-tmp-*"))  # no temp leftovers


def test_export_device_and_time_filters(tmp_path, populated):
    s, db = populated
    cut = format_ts(utc_now() - timedelta(days=1))
    out = create_export(db, tmp_path / "exports", devices=["a"], start=cut, include_configs=False)
    files, names = read_tar(out)
    assert "logs/b.jsonl" not in names and not any(n.startswith("configs/") for n in names)
    raws = [json.loads(line)["raw"] for line in files["logs/a.jsonl"].splitlines()]
    assert raws and all("old-" not in r for r in raws) and any("new-" in r for r in raws)
    out = create_export(db, tmp_path / "exports", devices=["a"], end=cut)
    raws = [json.loads(line)["raw"] for line in read_tar(out)[0]["logs/a.jsonl"].splitlines()]
    assert raws and all("new-" not in r for r in raws)
    assert json.loads(read_tar(out)[0]["manifest.json"])["filters"]["end"] == cut


def test_export_excludes_secrets_even_from_legacy_rows(tmp_path, populated):
    _, db = populated
    out = create_export(db, tmp_path / "exports", redactor=Redactor())
    files, names = read_tar(out)
    cfgs = [n for n in names if n.startswith("configs/a/")]
    assert cfgs and all(b"leaked-secret-1" not in files[n] for n in cfgs)
    assert b"ssid: x" in files[cfgs[0]]


def test_export_rejects_bad_input(tmp_path, populated):
    _, db = populated
    for kwargs in ({"devices": ["../etc/passwd"]}, {"start": "yesterday"}, {"start": "2025-02-01", "end": "2025-01-01"}):
        with pytest.raises(ExportError):
            create_export(db, tmp_path / "exports", **kwargs)


def test_export_is_consistent_while_collection_is_active(tmp_path, populated):
    s, db = populated
    sid, _ = s.start_session("a", None)
    import threading

    stop = threading.Event()

    def writer():
        i = 0
        while not stop.is_set():
            s.add_log("a", None, sid, f"live-{i}")
            i += 1

    t = threading.Thread(target=writer)
    t.start()
    try:
        out = create_export(db, tmp_path / "exports", devices=["a"])
    finally:
        stop.set()
        t.join()
    files, _ = read_tar(out)
    manifest = json.loads(files["manifest.json"])
    ids = [json.loads(line)["id"] for line in files["logs/a.jsonl"].splitlines()]
    assert len(ids) == manifest["devices"]["a"]["events"] == len(set(ids))
    assert sqlite3.connect(db).execute("PRAGMA integrity_check").fetchone()[0] == "ok"
