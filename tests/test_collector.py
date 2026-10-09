import asyncio
import json
import os
import sqlite3
import sys
import time

from conftest import device_file
from esphome_log_collector import storage as st
from esphome_log_collector.collector import Backoff, Collector
from esphome_log_collector.config import RetryConfig


def run_collector(config, duration=None, until=None, timeout=20):
    """Run the collector until `until(storage)` is true (or duration elapsed), then stop it gracefully."""

    async def main():
        storage = st.Storage(config.db_path)
        collector = Collector(config, storage)
        task = asyncio.create_task(collector.run(list(config.devices)))
        start = time.monotonic()
        while time.monotonic() - start < (duration or timeout):
            await asyncio.sleep(0.05)
            if until and until(storage):
                break
        collector.request_stop()
        await asyncio.wait_for(task, 15)
        storage.close()

    asyncio.run(main())
    return sqlite3.connect(config.db_path)


def count(storage, device, event_type=None):
    sql, args = "SELECT COUNT(*) FROM events WHERE device=?", [device]
    if event_type:
        sql += " AND event_type=?"
        args.append(event_type)
    return storage._conn.execute(sql, args).fetchone()[0]


def test_logs_persisted_with_raw_and_session_events(tmp_path, make_config):
    f = device_file(tmp_path, "a", lines=["[00:00:01]\x1b[0;32m[I][app:1]: hello\x1b[0m", "free text"], hang=True)
    cfg = make_config([{"name": "a", "address": "10.0.0.1", "config_file": f}])
    db = run_collector(cfg, until=lambda s: count(s, "a", st.LOG) >= 2)
    rows = db.execute("SELECT event_type, raw, level, session_id, address FROM events WHERE device='a' ORDER BY id").fetchall()
    types = [r[0] for r in rows]
    assert types[0] == "session_start" and "connected" in types and types.count("log") == 2
    assert [r[1] for r in rows if r[0] == "log"] == ["[00:00:01]\x1b[0;32m[I][app:1]: hello\x1b[0m", "free text"]
    assert len({r[3] for r in rows}) == 1 and rows[0][4] == "10.0.0.1"
    assert types[-1] == "disconnected"  # graceful shutdown recorded
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert db.execute("SELECT end_reason FROM sessions").fetchone()[0] == "collector shutting down"
    argv = json.loads(open(f + ".argv").read().splitlines()[0])
    assert argv == ["logs", "--device", "10.0.0.1", "--", f]


def test_reconnects_with_new_session_and_records_gap(tmp_path, make_config):
    f = device_file(tmp_path, "a", lines=["one"], **{"exit": 1})
    cfg = make_config([{"name": "a", "address": "10.0.0.1", "config_file": f}])
    db = run_collector(cfg, until=lambda s: count(s, "a", st.GAP) >= 2)
    types = [r[0] for r in db.execute("SELECT event_type FROM events ORDER BY id")]
    assert types.count("session_start") >= 3 and types.count("retry_scheduled") >= 2
    assert "connected" not in types  # a banner line is not proof of a device connection
    assert types.count("gap") >= 2 and types.count("collector_error") >= 2  # exit code 1 is an error
    assert db.execute("SELECT COUNT(DISTINCT session_id) FROM sessions").fetchone()[0] >= 3
    status = db.execute("SELECT state, last_error FROM device_status").fetchone()
    assert status[0] == "stopped" and "exited with code 1" in status[1]


def test_cli_failure_includes_sanitized_diagnostic_output(tmp_path, make_config):
    f = device_file(tmp_path, "a", lines=[
        "INFO Reading configuration",
        "Failed config",
        "  wifi_password: configured-secret-value",
        *(f"  rendered_config_line_{index}: value" for index in range(30)),
        "  Error reading include: missing-file.yaml",
        *(f"  trailing_config_line_{index}: value" for index in range(20)),
    ], **{"exit": 2})
    (tmp_path / "secrets.yaml").write_text("api_key: configured-secret-value\n")
    cfg = make_config([{"name": "a", "address": "10.0.0.1", "config_file": f}])
    db = run_collector(
        cfg,
        until=lambda s: count(s, "a", st.COLLECTOR_ERROR) >= 1
        and s._conn.execute("SELECT state FROM device_status WHERE device='a'").fetchone()[0] == "backoff",
    )
    rows = db.execute("SELECT raw FROM events WHERE device='a' AND event_type='log'").fetchall()
    logs = "\n".join(row[0] for row in rows)
    status = db.execute("SELECT last_error FROM device_status WHERE device='a'").fetchone()[0]
    assert "configured-secret-value" not in logs + status
    assert "Failed config" in status and "missing-file.yaml" in status
    assert "trailing_config_line_19" in status
    assert "[REDACTED]" in logs and "exited with code 2" in status


def test_one_failing_device_does_not_affect_others(tmp_path, make_config):
    good = device_file(tmp_path, "good", lines=["ok-line"], hang=True)
    bad = device_file(tmp_path, "bad", lines=["x"], **{"exit": 3})
    cfg = make_config([
        {"name": "bad", "address": "10.0.0.2", "config_file": bad},
        {"name": "good", "address": "10.0.0.1", "config_file": good},
    ])
    db = run_collector(cfg, until=lambda s: count(s, "good", st.LOG) >= 1 and count(s, "bad", st.RETRY) >= 2)
    assert db.execute("SELECT COUNT(*) FROM events WHERE device='good' AND event_type='log'").fetchone()[0] >= 1
    assert db.execute("SELECT COUNT(*) FROM events WHERE device='bad' AND event_type='retry_scheduled'").fetchone()[0] >= 2


def test_missing_esphome_binary_is_reported_and_retried(tmp_path, make_config):
    f = device_file(tmp_path, "a", lines=[])
    cfg = make_config([{"name": "a", "address": "10.0.0.1", "config_file": f}],
                      collector={"esphome_command": ["/nonexistent/esphome"]})
    db = run_collector(cfg, until=lambda s: count(s, "a", st.COLLECTOR_ERROR) >= 2)
    msg = db.execute("SELECT raw FROM events WHERE event_type='collector_error'").fetchone()[0]
    assert "cannot execute" in msg and "/nonexistent/esphome" in msg


def test_idle_timeout_restarts_hung_process(tmp_path, make_config):
    f = device_file(tmp_path, "a", lines=[], hang=True)
    cfg = make_config([{"name": "a", "address": "10.0.0.1", "config_file": f, "idle_timeout": 0.3}])
    db = run_collector(cfg, until=lambda s: count(s, "a", st.SESSION_START) >= 2)
    reasons = [r[0] for r in db.execute("SELECT end_reason FROM sessions WHERE end_reason IS NOT NULL")]
    assert any("idle_timeout" in r for r in reasons)


def test_shutdown_terminates_child_and_keeps_database_consistent(tmp_path, make_config):
    f = device_file(tmp_path, "a", lines=["l"] * 50, hang=True)
    cfg = make_config([{"name": "a", "address": "10.0.0.1", "config_file": f}])
    db = run_collector(cfg, until=lambda s: count(s, "a", st.LOG) >= 50)
    assert db.execute("SELECT COUNT(*) FROM events WHERE event_type='log'").fetchone()[0] == 50
    assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert db.execute("SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL").fetchone()[0] == 0
    # heartbeat file written for the container health check
    assert cfg.health_file.exists() and json.loads(cfg.health_file.read_text())["pid"] == os.getpid()


def test_raw_files_optional_copy(tmp_path, make_config):
    f = device_file(tmp_path, "a", lines=["raw \x1b[31mred\x1b[0m"], hang=True)
    cfg = make_config([{"name": "a", "address": "10.0.0.1", "config_file": f}], storage={"raw_files": {"enabled": True}})
    run_collector(cfg, until=lambda s: count(s, "a", st.LOG) >= 1)
    text = (cfg.data_dir / "raw" / "a.log").read_text()
    assert "raw \x1b[31mred\x1b[0m" in text


def test_backoff_growth_jitter_and_reset():
    b = Backoff(RetryConfig(initial_delay=1, max_delay=8, multiplier=2, jitter=0.5, reset_after=30), rng=lambda: 0.5)
    assert [b.next_delay(0) for _ in range(5)] == [1, 2, 4, 8, 8]
    assert b.next_delay(31) == 1  # healthy long session resets
    hi = Backoff(RetryConfig(initial_delay=10, max_delay=100, jitter=0.2), rng=lambda: 1.0)
    lo = Backoff(RetryConfig(initial_delay=10, max_delay=100, jitter=0.2), rng=lambda: 0.0)
    assert round(hi.next_delay(), 6) == 12 and round(lo.next_delay(), 6) == 8


def test_api_backend_reports_unreachable_device_and_retries(make_config):
    cfg = make_config([{"name": "api-dev", "address": "127.0.0.1", "backend": "api",
                        "api": {"port": 1, "connect_timeout": 2}}])
    db = run_collector(cfg, until=lambda s: count(s, "api-dev", st.RETRY) >= 2)
    msgs = [r[0] for r in db.execute("SELECT raw FROM events WHERE event_type='collector_error'")]
    assert msgs and all("API connection to 127.0.0.1:1 failed" in m for m in msgs)
