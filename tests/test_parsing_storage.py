import re
import sqlite3

from esphome_log_collector import storage as st
from esphome_log_collector.parsing import parse_line, strip_ansi

TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")


def test_parse_esphome_line_with_ansi():
    raw = "[12:34:56]\x1b[0;32m[I][wifi:123]: Connected\x1b[0m"
    p = parse_line(raw)
    assert (p.level, p.component, p.device_time, p.message) == ("INFO", "wifi", "12:34:56", "Connected")
    assert strip_ansi(raw) == "[12:34:56][I][wifi:123]: Connected"


def test_parse_variants_and_unparseable():
    assert parse_line("[12:34:56.789][E][sensor.x:5]: boom").level == "ERROR"
    assert parse_line("WARNING Could not resolve").level == "WARNING"
    p = parse_line("garbage \x1b[31mred\x1b[0m")
    assert p.level is None and p.message == "garbage red"


def test_raw_preserved_and_timestamps_utc(tmp_path):
    s = st.Storage(tmp_path / "db.sqlite3")
    sid, prev = s.start_session("dev", "1.2.3.4")
    assert prev is None
    raw = "[01:02:03]\x1b[0;31m[E][app:1]: weird  spacing\t\x1b[0m"
    s.add_log("dev", "1.2.3.4", sid, raw)
    s.add_log("dev", "1.2.3.4", sid, "not a log format \u00e9\u00e8")
    s.add_event("dev", "1.2.3.4", sid, st.DISCONNECTED, "gone")
    s.end_session(sid, "done")
    rows = s._conn.execute("SELECT * FROM events ORDER BY id").fetchall()
    assert rows[0]["raw"] == raw and rows[0]["level"] == "ERROR" and rows[0]["component"] == "app"
    assert rows[1]["raw"] == "not a log format \u00e9\u00e8" and rows[1]["level"] is None
    assert rows[2]["event_type"] == st.DISCONNECTED
    assert all(TS_RE.match(r["ts"]) for r in rows)
    assert s._conn.execute("SELECT line_count FROM sessions").fetchone()[0] == 2
    s.close()


def test_pragmas_indexes_and_integrity(tmp_path):
    s = st.Storage(tmp_path / "db.sqlite3")
    assert s._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert s._conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2
    idx = {r[1] for r in s._conn.execute("PRAGMA index_list(events)")}
    assert {"idx_events_device_ts", "idx_events_ts"} <= idx
    assert s.integrity_check() == "ok"
    s.close()


def test_failed_transaction_rolls_back(tmp_path):
    s = st.Storage(tmp_path / "db.sqlite3")
    try:
        with s.transaction() as conn:
            conn.execute("INSERT INTO meta VALUES ('k','v')")
            raise ValueError
    except ValueError:
        pass
    assert s._conn.execute("SELECT COUNT(*) FROM meta WHERE key='k'").fetchone()[0] == 0
    s.close()


def test_reopen_closes_dangling_sessions_and_tracks_gap(tmp_path):
    p = tmp_path / "db.sqlite3"
    s = st.Storage(p)
    sid, _ = s.start_session("dev", None)
    s.add_log("dev", None, sid, "line")
    s._conn.close()  # simulated crash: session never ended
    s2 = st.Storage(p)
    row = s2._conn.execute("SELECT ended_at, end_reason FROM sessions").fetchone()
    assert row["ended_at"] and row["end_reason"] == "collector_crashed_or_killed"
    _, prev = s2.start_session("dev", None)
    assert prev is not None
    s2.close()
    assert sqlite3.connect(p).execute("PRAGMA integrity_check").fetchone()[0] == "ok"
