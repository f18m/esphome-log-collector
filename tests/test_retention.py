import asyncio
import os
import time

from esphome_log_collector import storage as st
from esphome_log_collector.config import RetentionConfig, DeviceRetention
from esphome_log_collector.retention import Retention
from helpers import seed


def retention(tmp_path, **kw):
    s = st.Storage(tmp_path / "db.sqlite3")
    return s, lambda **extra: Retention(s, RetentionConfig(**{**kw, **extra}), tmp_path / "exports")


def n_events(s, device=None):
    sql, a = "SELECT COUNT(*) FROM events", ()
    if device:
        sql, a = sql + " WHERE device=?", (device,)
    return s._conn.execute(sql, a).fetchone()[0]


def test_max_age_deletes_only_old_events_in_batches(tmp_path):
    s, mk = retention(tmp_path)
    seed(s, "a", 30, age_days=10)
    seed(s, "a", 5, age_days=0)
    stats = asyncio.run(mk(max_age_days=5, batch_size=7).run_once())
    assert stats["events_age"] == 30 and n_events(s) == 5
    assert s._conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1  # empty session pruned
    assert s.integrity_check() == "ok"


def test_batch_budget_bounds_work_per_run(tmp_path):
    s, mk = retention(tmp_path)
    seed(s, "a", 50, age_days=10)
    r = mk(max_age_days=5, batch_size=10, max_batches_per_run=2)
    assert asyncio.run(r.run_once())["events_age"] == 20 and n_events(s) == 30
    asyncio.run(r.run_once())
    assert n_events(s) == 10


def test_per_device_limits(tmp_path):
    s, mk = retention(tmp_path)
    seed(s, "a", 20)
    seed(s, "b", 20)
    seed(s, "c", 10, age_days=3)
    r = mk(per_device={"a": DeviceRetention(max_events=8), "c": DeviceRetention(max_age_days=1)})
    asyncio.run(r.run_once())
    assert n_events(s, "a") == 8 and n_events(s, "b") == 20 and n_events(s, "c") == 0
    assert s._conn.execute("SELECT MIN(raw) FROM events WHERE device='a'").fetchone()[0].find("-12 ") > 0  # newest kept


def test_max_total_size_removes_oldest_first(tmp_path):
    s, mk = retention(tmp_path)
    seed(s, "a", 2000, age_days=2, pad=200)
    seed(s, "b", 2000, age_days=0, pad=200)
    before = s.used_bytes()
    limit_mb = 1.0
    assert before > limit_mb * 1024 * 1024
    asyncio.run(mk(max_total_size_mb=limit_mb, batch_size=200).run_once())
    assert s.used_bytes() <= limit_mb * 1024 * 1024
    assert n_events(s, "b") > n_events(s, "a")  # older device data went first
    assert os.path.getsize(tmp_path / "db.sqlite3") < before  # incremental vacuum returned space


def test_collection_continues_during_cleanup(tmp_path):
    s, mk = retention(tmp_path)
    sid = seed(s, "a", 500, age_days=10)
    live, _ = s.start_session("a", None)

    async def main():
        r = mk(max_age_days=1, batch_size=50)
        task = asyncio.create_task(r.run_once())
        for i in range(20):
            s.add_log("a", None, live, f"live {i}")
            await asyncio.sleep(0)
        await task

    asyncio.run(main())
    assert n_events(s) == 20 and s.integrity_check() == "ok"


def test_config_snapshot_retention(tmp_path):
    s, mk = retention(tmp_path)
    for i in range(5):
        s.add_snapshot("a", f"s{i}", f"c{i}", "x: 1\n")
    s.add_snapshot("b", "s", "c", "y: 1\n")
    stats = asyncio.run(mk(configs_keep_last=2).run_once())
    assert stats["config_snapshots"] == 3
    assert s._conn.execute("SELECT COUNT(*) FROM config_snapshots WHERE device='a'").fetchone()[0] == 2


def test_export_retention_only_touches_exporter_files(tmp_path):
    s, mk = retention(tmp_path)
    d = tmp_path / "exports"
    d.mkdir()
    old = d / "esphome-log-export-20200101T000000Z-aabbccdd.tar.gz"
    new = d / "esphome-log-export-20990101T000000Z-aabbccdd.tar.gz"
    other = d / "notes.txt"
    stale_tmp = d / ".export-tmp-xyz"
    for f in (old, new, other, stale_tmp):
        f.write_text("x")
    longago = time.time() - 40 * 86400
    for f in (old, stale_tmp):
        os.utime(f, (longago, longago))
    stats = asyncio.run(mk(exports_max_age_days=14).run_once())
    assert not old.exists() and not stale_tmp.exists() and new.exists() and other.exists()
    assert stats["exports"] == 1 and stats["tmp"] == 1
