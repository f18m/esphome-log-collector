from datetime import timedelta

from esphome_log_collector import storage as st
from esphome_log_collector.timeutil import format_ts, utc_now


def seed(storage: st.Storage, device: str, n: int, age_days: float = 0, prefix: str = "line", pad: int = 0) -> str:
    sid, _ = storage.start_session(device, "10.0.0.1")
    for i in range(n):
        ts = format_ts(utc_now() - timedelta(days=age_days, seconds=n - i))
        storage.add_event(device, "10.0.0.1", sid, st.LOG, f"[00:00:00][I][t:1]: {prefix}-{i} " + "x" * pad,
                          ts=ts, parse=True)
    storage.end_session(sid, "test")
    return sid
