from argparse import Namespace
import asyncio
import dataclasses
from datetime import datetime, timezone
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request

import pytest

from esphome_log_collector import __version__, cli
from esphome_log_collector import storage as st
from esphome_log_collector.cli import main
from esphome_log_collector.openapi_cli import main as openapi_main, render_openapi
from esphome_log_collector.web import WebServer, _format_log_duration, _format_time_ago
from helpers import seed


class RunningServer:
    """Runs a WebServer on its own event loop in a thread (as it runs next to the collector)."""

    def __init__(self, cfg):
        self.server = WebServer(cfg)
        self._ready = threading.Event()
        self._error = None
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        async def main():
            self._stop = asyncio.Event()
            self._loop = asyncio.get_running_loop()
            try:
                await self.server.start()
            except BaseException as err:  # noqa: BLE001
                self._error = err
                self._ready.set()
                return
            self._ready.set()
            await self._stop.wait()
            await self.server.stop()

        asyncio.run(main())

    def __enter__(self):
        self._thread.start()
        assert self._ready.wait(10)
        if self._error:
            raise self._error
        return self.server

    def __exit__(self, *exc):
        self._loop.call_soon_threadsafe(self._stop.set)
        self._thread.join(15)
        assert not self._thread.is_alive()


@pytest.fixture
def web(tmp_path, make_config):
    cfg = make_config([{"name": "a", "address": "1.1.1.1"}], web={"enabled": True})
    cfg = dataclasses.replace(cfg, web=dataclasses.replace(cfg.web, port=0))
    s = st.Storage(cfg.db_path)
    seed(s, "a", 30, prefix="alpha")
    seed(s, "b", 5, prefix="beta")
    s.add_log("a", None, s.start_session("a", None)[0], "[00:00:00]\x1b[0;31m[E][x:1]: failure 100%_done\x1b[0m")
    s.set_status("a", state="connected", address="1.1.1.1", error="previous connection error")
    s.checkpoint()
    with RunningServer(cfg) as server:
        yield f"http://127.0.0.1:{server.port}", server, cfg
    s.close()


def get(url, **kw):
    req = urllib.request.Request(url, **kw)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace"), r.headers
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", "replace"), err.headers


def test_web_enabled_and_localhost_by_default(make_config):
    cfg = make_config([{"name": "a", "address": "1.1.1.1"}])
    assert cfg.web.enabled is True and cfg.web.bind == "127.0.0.1"
    disabled = make_config([{"name": "a", "address": "1.1.1.1"}], web={"enabled": False})
    assert disabled.web.enabled is False


def test_run_logs_package_version(monkeypatch, capsys, make_config):
    cfg = make_config([{"name": "a", "address": "1.1.1.1"}])

    async def run(_config):
        return None

    monkeypatch.setattr(cli, "_load", lambda _args: cfg)
    monkeypatch.setattr(cli, "run_collector", run)

    assert cli.cmd_run(Namespace()) == 0
    assert f"esphome-log-collector v{__version__} starting" in capsys.readouterr().err


def test_status_page_and_api(web):
    base, _, cfg = web
    storage = st.Storage(cfg.db_path)
    storage.set_status("a", state="connected", last_line_at="2025-01-02T03:04:05.678901Z")
    storage.close()
    status, body, headers = get(base + "/")
    assert status == 200 and "connected" in body and headers["Content-Security-Policy"].startswith("default-src 'none'")
    assert "/static/app.css" in body and 'name="viewport"' in body
    assert body.count('<script src="/static/ui.js" defer></script>') == 1
    assert '<a href="/" class="active" aria-current="page">Status</a>' in body
    assert "<h1>" not in body
    assert '<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">' in body
    assert "img-src 'self'" in headers["Content-Security-Policy"]
    assert "img-src https:" not in headers["Content-Security-Policy"]
    assert 'class="project-icon" href="https://github.com/f18m/esphome-log-collector/"' in body
    assert '<img src="/static/favicon.svg" alt="" width="40" height="40">' in body
    assert f'<span class="site-title">ESPHome Log Collector v{__version__}</span>' in body
    assert '<footer class="site-footer">' in body
    assert '<a href="https://github.com/f18m/esphome-log-collector/">Project homepage</a>' in body
    assert '<span class="state-indicator state-connected" title="connected" aria-label="connected">●</span>' in body
    assert '<td class="address">1.1.1.1</td>' in body
    assert "<td>2025-01-02 03:04:05</td>" in body
    assert "2025-01-02 03:04:05.678901" not in body
    assert "<th>Last Line (UTC)</th><th>Last Line</th><th>Log lines</th><th>Log span</th>" in body
    assert (
        '<time class="last-line-ago" data-timestamp="2025-01-02T03:04:05.678901Z">'
        in body
    )
    assert " days ago</time>" in body
    assert "<td>31</td><td>&lt;1 min</td><td>0</td><td>-</td><td>none</td>" in body
    assert "previous connection error" not in body
    assert "<td>-</td><td>none</td>" in body
    css = get(base + "/static/app.css")[1]
    assert "td.address" in css and "font-family: ui-monospace" in css
    assert json.loads(get(base + "/api/status")[1])[0]["device"] == "a"


@pytest.mark.parametrize(
    ("first", "last", "expected"),
    [
        ("2025-01-01T00:00:00.000000Z", "2025-01-01T00:12:00.000000Z", "12 min"),
        ("2025-01-01T00:00:00.000000Z", "2025-01-01T03:20:00.000000Z", "3h 20m"),
        ("2025-01-01T00:00:00.000000Z", "2025-01-03T05:00:00.000000Z", "2d 5h"),
        (None, None, "-"),
    ],
)
def test_format_log_duration(first, last, expected):
    assert _format_log_duration(first, last) == expected


def test_format_time_ago():
    now = datetime(2025, 1, 1, 0, 5, tzinfo=timezone.utc)
    assert _format_time_ago("2025-01-01T00:00:00.000000Z", now) == "5 min ago"
    assert _format_time_ago(None, now) == "-"


def test_static_assets(web):
    base, _, _ = web
    status, css, headers = get(base + "/static/app.css")
    assert status == 200 and headers["Content-Type"].startswith("text/css")
    assert "radial-gradient" in css
    assert ".site-footer" in css and "text-align: center" in css
    status, favicon, headers = get(base + "/static/favicon.svg")
    assert status == 200 and headers["Content-Type"].startswith("image/svg+xml")
    assert "<svg" in favicon and "viewBox=" in favicon
    status, script, headers = get(base + "/static/tail.js")
    assert status == 200 and headers["Content-Type"].startswith("text/javascript")
    assert "new EventSource" in script
    status, script, headers = get(base + "/static/ui.js")
    assert status == 200 and headers["Content-Type"].startswith("text/javascript")
    assert "sessionStorage" in script and "data-font-target" in script
    assert "last-line-ago" in script and "setInterval(updateLastLineTimes, 15_000)" in script
    assert get(base + "/static/missing.js")[0] == 404


def test_log_search_filters_and_pagination(web):
    base, _, _ = web
    page = get(base + "/logs")[1]
    assert '<a href="/logs" class="active" aria-current="page">Logs</a>' in page
    assert '<div id="logs-rows" class="terminal logs-terminal">' in page
    assert '<table' not in page
    assert page.index("</form>") < page.index('class="control-toolbar"') < page.index('data-font-target="logs"')
    assert '<div class="control-toolbar">\n    <p>page 1 ' in page
    assert 'data-font-target="logs"' in page and "Increase log font size" in page
    assert '<option value="">any</option>' in page
    assert '<option value="DEBUG">DEBUG or higher</option>' in page
    assert 'Log Level <select name="level">' in page
    assert '<label class="text-filter">Text <input name="q" value=""></label>' in page
    css = get(base + "/static/app.css")[1]
    assert ".logs-terminal { font-size: var(--log-font-size" in css
    assert ".control-toolbar {" in css and "justify-content: space-between" in css
    assert "min-width: 2rem;" in css and "min-height: 1.8rem;" in css
    assert ".text-filter {" in css and "white-space: nowrap" in css
    assert ".terminal {" in css and "overflow: auto" in css
    range_page = get(base + "/logs?start=2025-01-31T12%3A34%3A56Z&end=2025-02-01T01%3A02%3A03Z")[1]
    assert '<input type="datetime-local" name="start" step="1" value="2025-01-31T12:34:56">' in range_page
    assert '<input type="datetime-local" name="end" step="1" value="2025-02-01T01:02:03">' in range_page
    assert range_page.index('name="start"') < range_page.index('name="end"') < range_page.index('name="q"')
    data = json.loads(get(base + "/api/logs?device=a&q=alpha&page_size=10")[1])
    assert len(data["events"]) == 10 and data["has_next"] is True
    page3 = json.loads(get(base + "/api/logs?device=a&q=alpha&page_size=10&page=3")[1])
    assert len(page3["events"]) == 10 and page3["has_next"] is False
    only_b = json.loads(get(base + "/api/logs?device=b")[1])["events"]
    assert only_b and all(e["device"] == "b" for e in only_b)
    errs = json.loads(get(base + "/api/logs?level=ERROR")[1])["events"]
    assert len(errs) == 1 and "\x1b" not in errs[0]["clean"] and "\x1b" in errs[0]["raw"]
    levels = (
        "[00:00:00][V][test:1]: very verbose",
        "[00:00:00][D][test:1]: debug",
        "[00:00:00][C][test:1]: config",
        "[00:00:00][I][test:1]: info",
        "[00:00:00][W][test:1]: warning",
        "[00:00:00][E][test:1]: error",
        "CRITICAL critical",
    )
    storage = st.Storage(web[2].db_path)
    sid, _ = storage.start_session("a", None)
    for line in levels:
        storage.add_log("a", None, sid, line)
    storage.close()
    threshold_events = json.loads(get(base + "/api/logs?level=INFO")[1])["events"]
    assert {event["level"] for event in threshold_events} == {"INFO", "WARNING", "ERROR", "CRITICAL"}
    assert len(json.loads(get(base + "/api/logs?q=100%25_done")[1])["events"]) == 1  # LIKE wildcards are literal
    assert json.loads(get(base + "/api/logs?q=alpha&start=2999-01-01T00:00:00Z")[1])["events"] == []
    assert get(base + "/api/logs?start=garbage")[0] == 400
    assert get(base + "/api/logs?level=NOPE")[0] == 400


def test_tail_page_and_live_stream(web):
    base, _, cfg = web
    status, body, headers = get(base + "/tail?device=a")
    assert status == 200 and "<title>Live Tail</title>" in body and "/static/tail.js" in body
    assert '<a href="/tail" class="active" aria-current="page">Live Tail</a>' in body
    assert body.index("</form>") < body.index('class="control-toolbar"') < body.index('data-font-target="tail"')
    assert '<p>Stream: <strong id="tail-state" aria-live="polite">Connecting…</strong></p>' in body
    assert 'data-font-target="tail"' in body and "Increase Live Tail font size" in body
    assert 'Log Level <select name="level">' in body
    assert '<option value="INFO">INFO or higher</option>' in body
    assert 'class="terminal"' in body and "<table" not in body
    assert "[E][x:1]: failure 100%_done" in body
    assert "script-src 'self'" in headers["Content-Security-Policy"]
    assert "connect-src 'self'" in headers["Content-Security-Policy"]
    assert get(base + "/api/tail?after=invalid")[0] == 400


def test_storage_page(web):
    base, _, cfg = web
    cache = cfg.data_dir / "esphome-data" / "device-a"
    cache.mkdir(parents=True)
    (cache / "cache.bin").write_bytes(b"x" * 2048)
    storage = st.Storage(cfg.db_path)
    storage._conn.execute(
        "INSERT INTO meta(key, value) VALUES ('retention_deleted_log_lines', '123')"
    )
    storage.close()

    status, body, _ = get(base + "/storage")
    assert status == 200
    assert '<a href="/storage" class="active" aria-current="page">Storage</a>' in body
    assert "<th>SQLite database (including WAL)</th>" in body
    assert "<td>123</td>" in body
    assert "<th>ESPHome cache (esphome-data)</th><td>2.0 KiB</td>" in body

    with st.connect(cfg.db_path, readonly=True) as conn:
        after = conn.execute("SELECT MAX(id) FROM events").fetchone()[0]
    response = urllib.request.urlopen(base + f"/api/tail?device=a&after={after}", timeout=5)
    try:
        assert response.headers["Content-Type"].startswith("text/event-stream")
        assert "img-src" not in response.headers["Content-Security-Policy"]
        assert response.readline() == b": connected\n"
        response.readline()

        storage = st.Storage(cfg.db_path)
        session_id, _ = storage.start_session("a", "1.1.1.1")
        storage.add_log("a", "1.1.1.1", session_id, "[00:00:00]\x1b[0;31m[E][live:1]: new line\x1b[0m")
        storage.close()

        while True:
            line = response.readline()
            if line.startswith(b"data: "):
                event = json.loads(line.removeprefix(b"data: "))
                break
        assert event["device"] == "a" and event["clean"].endswith("[E][live:1]: new line")
    finally:
        response.close()


def test_html_is_escaped(web):
    base, _, cfg = web
    s = st.Storage(cfg.db_path)
    sid, _ = s.start_session("a", None)
    s.add_log("a", None, sid, "<script>alert(1)</script>")
    s.close()
    body = get(base + "/logs?q=script")[1]
    assert "<script>" not in body and "&lt;script&gt;" in body


def test_read_only_methods_and_csrf(web):
    base, server, _ = web
    assert get(base + "/", method="PUT")[0] == 405 and get(base + "/", method="DELETE")[0] == 405
    assert get(base + "/export", data=b"device=a", method="POST")[0] == 403  # no CSRF token
    assert get(base + "/nope")[0] == 404


def test_export_create_and_download(web):
    base, server, cfg = web
    page = get(base + "/exports")[1]
    assert '<table class="device-select-table">' in page
    assert '<input id="export-device-a" type="checkbox" name="device" value="a">' in page
    assert '<input type="datetime-local" name="start" step="1">' in page
    assert '<input type="datetime-local" name="end" step="1">' in page
    token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(base + "/export", data=f"csrf={token}&device=a".encode(), method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc:
        opener.open(req)
    assert exc.value.code == 303
    listing = get(base + "/exports")[1]
    name = re.search(r'/exports/(esphome-log-export-[^"]+\.tar\.gz)', listing).group(1)
    status, _, headers = get(base + "/exports/" + name)
    assert status == 200 and headers["Content-Type"] == "application/gzip"
    for bad in ("../collector.sqlite3", "..%2fcollector.sqlite3", "notes.txt", "%2e%2e/x"):
        assert get(base + "/exports/" + bad)[0] == 404


def test_allowed_hosts(tmp_path, make_config):
    cfg = make_config([{"name": "a", "address": "1.1.1.1"}], web={"enabled": True, "allowed_hosts": ["logs.example"]})
    cfg = dataclasses.replace(cfg, web=dataclasses.replace(cfg.web, port=0))
    st.Storage(cfg.db_path).close()
    with RunningServer(cfg) as server:
        base = f"http://127.0.0.1:{server.port}"
        status, body, headers = get(base + "/api/status")
        assert status == 403 and body == "host not allowed" and headers["X-Frame-Options"] == "DENY"
        assert get(base + "/api/status", headers={"Host": "logs.example"})[0] == 200
        assert get(base + "/api/status", headers={"Host": "logs.example:8080"})[0] == 200
        assert get(base + "/", headers={"Host": "evil.example"})[0] == 403


# ---- FastAPI migration: contract, errors, streaming, shutdown ----
def test_api_models_errors_and_security_headers(web):
    base, _, _ = web
    status, body, headers = get(base + "/api/status")
    assert status == 200 and headers["Content-Type"] == "application/json"
    row = json.loads(body)[0]
    assert set(row) == {"device", "address", "backend", "source", "state", "session_id", "updated_at", "last_line_at",
                        "last_error", "last_error_at", "attempts", "next_retry_at"}
    for header, value in (("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
                          ("Referrer-Policy", "no-referrer"), ("Cache-Control", "no-store")):
        assert headers[header] == value
    event = json.loads(get(base + "/api/logs?page_size=1")[1])["events"][0]
    assert set(event) == {"id", "ts", "device", "session_id", "event_type", "level", "component", "message", "raw", "clean"}
    for bad in ("/api/logs?page=x", "/api/logs?page_size=x", "/api/logs?start=garbage", "/api/logs?type=nope",
                "/api/tail?after=-1", "/api/tail?level=NOPE"):
        status, body, headers = get(base + bad)
        assert status == 400 and headers["Content-Type"] == "application/json", bad
        assert isinstance(json.loads(body)["error"], str)
    status, body, headers = get(base + "/api/tail?after=1", headers={"Last-Event-ID": "oops"})
    assert status == 400 and "error" in json.loads(body)
    status, body, _ = get(base + "/api/nope")
    assert status == 404 and "error" in json.loads(body)
    # HTML pages keep HTML errors
    status, body, headers = get(base + "/logs?start=garbage")
    assert status == 400 and headers["Content-Type"].startswith("text/html") and "<html" in body
    assert get(base + "/logs?page_size=1000")[0] == 200
    status, body, headers = get(base + "/nope")
    assert status == 404 and headers["Content-Type"].startswith("text/html")
    assert get(base + "/export", data=b"", method="PUT")[0] == 405
    assert get(base + "/nope", data=b"x", method="POST")[0] == 404


def test_openapi_served_and_docs_disabled(web):
    base, _, _ = web
    status, body, headers = get(base + "/openapi.json")
    assert status == 200 and headers["Content-Type"].startswith("application/json")
    assert json.loads(body) == json.loads(render_openapi())
    assert get(base + "/docs")[0] == 404 and get(base + "/redoc")[0] == 404


def test_openapi_contract():
    spec = json.loads(render_openapi())
    assert set(spec["paths"]) == {"/api/status", "/api/logs", "/api/tail"}  # UI-only routes are not public API
    tail = spec["paths"]["/api/tail"]["get"]["responses"]
    assert list(tail["200"]["content"]) == ["text/event-stream"] and "application/json" not in tail["200"]["content"]
    assert "422" not in json.dumps(spec) and "HTTPValidationError" not in json.dumps(spec)
    params = {p["name"] for p in spec["paths"]["/api/tail"]["get"]["parameters"]}
    assert {"after", "last-event-id", "device", "level", "type", "q", "start", "end"} <= params
    logs = spec["paths"]["/api/logs"]["get"]
    assert logs["responses"]["400"]["content"]["application/json"]["schema"] == {"$ref": "#/components/schemas/ErrorResponse"}
    assert set(spec["components"]["schemas"]) == {"DeviceStatus", "ErrorResponse", "LogEvent", "LogPage"}


def test_committed_openapi_json_is_in_sync():
    from pathlib import Path
    committed = Path(__file__).resolve().parent.parent / "openapi.json"
    assert openapi_main(["--check", "-o", str(committed)]) == 0, (
        "openapi.json is out of date; run: python -m esphome_log_collector.openapi_cli"
    )
    assert committed.read_text(encoding="utf-8") == render_openapi()


def _read_until(response, prefix):
    while True:
        line = response.readline()
        assert line, "stream ended"
        if line.startswith(prefix):
            return line


def test_tail_resume_ids_and_disconnect(web):
    base, server, cfg = web
    with st.connect(cfg.db_path, readonly=True) as conn:
        after = conn.execute("SELECT MAX(id) FROM events").fetchone()[0]
    writer = st.Storage(cfg.db_path)
    sid, _ = writer.start_session("a", None)
    for i in range(3):
        writer.add_log("a", None, sid, f"[00:00:00][I][t:1]: line {i}")
    # Last-Event-ID wins over ?after= (EventSource reconnect)
    request = urllib.request.Request(base + "/api/tail?device=a&after=0", headers={"Last-Event-ID": str(after)})
    response = urllib.request.urlopen(request, timeout=10)
    try:
        assert response.headers["Content-Type"].startswith("text/event-stream")
        assert response.headers["X-Accel-Buffering"] == "no" and response.headers["Cache-Control"] == "no-cache"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.readline() == b": connected\n"
        ids = []
        for _ in range(3):
            id_line = _read_until(response, b"id: ")
            data = json.loads(_read_until(response, b"data: ").removeprefix(b"data: "))
            assert int(id_line.removeprefix(b"id: ")) == data["id"]
            ids.append(data["id"])
        assert ids == sorted(ids) and ids[0] > after and len(set(ids)) == 3
        assert server.state.active_streams == 1
    finally:
        response.close()
        writer.close()
    deadline = time.time() + 10
    while server.state.active_streams and time.time() < deadline:
        time.sleep(0.05)
    assert server.state.active_streams == 0  # generator exited after the client went away


def test_concurrent_streams_do_not_block_server(web):
    base, server, cfg = web
    with st.connect(cfg.db_path, readonly=True) as conn:
        after = conn.execute("SELECT MAX(id) FROM events").fetchone()[0]
    streams = [urllib.request.urlopen(base + f"/api/tail?after={after}", timeout=10) for _ in range(8)]
    try:
        for stream in streams:
            assert stream.readline() == b": connected\n"
        assert server.state.active_streams == 8
        started = time.monotonic()
        assert get(base + "/api/status")[0] == 200 and get(base + "/api/logs?page_size=5")[0] == 200
        assert time.monotonic() - started < 3
        writer = st.Storage(cfg.db_path)
        sid, _ = writer.start_session("a", None)
        writer.add_log("a", None, sid, "[00:00:00][I][t:1]: broadcast")
        writer.close()
        for stream in streams:  # every client receives the new event
            assert b"broadcast" in _read_until(stream, b"data: ")
    finally:
        for stream in streams:
            stream.close()


def test_shutdown_ends_streams_and_releases_port(tmp_path, make_config):
    cfg = make_config([{"name": "a", "address": "1.1.1.1"}], web={"enabled": True})
    cfg = dataclasses.replace(cfg, web=dataclasses.replace(cfg.web, port=0))
    st.Storage(cfg.db_path).close()
    running = RunningServer(cfg)
    server = running.__enter__()
    stream = urllib.request.urlopen(f"http://127.0.0.1:{server.port}/api/tail", timeout=10)
    assert stream.readline() == b": connected\n"
    started = time.monotonic()
    running.__exit__(None, None, None)  # returns only after stop() completed
    assert time.monotonic() - started < 10
    assert server.state.active_streams == 0
    stream.close()


def test_bind_failure_is_reported(tmp_path, make_config):
    cfg = make_config([{"name": "a", "address": "1.1.1.1"}], web={"enabled": True})
    cfg = dataclasses.replace(cfg, web=dataclasses.replace(cfg.web, port=0))
    st.Storage(cfg.db_path).close()
    with RunningServer(cfg) as first:
        busy = dataclasses.replace(cfg, web=dataclasses.replace(cfg.web, port=first.port))
        with pytest.raises(OSError):
            RunningServer(busy).__enter__()


# ---- CLI ----
def write_conf(tmp_path, extra=""):
    conf = tmp_path / "c.yaml"
    conf.write_text(f"storage: {{path: {tmp_path}/data}}\ndevices:\n  - {{name: a, address: 1.1.1.1, backend: api}}\n{extra}")
    return str(conf)


def test_cli_check_config_reports_actionable_errors(tmp_path, capsys):
    assert main(["check-config", "-c", write_conf(tmp_path)]) == 0
    bad = tmp_path / "bad.yaml"
    bad.write_text("devices:\n  - {name: a}\n")
    with pytest.raises(SystemExit) as exc:
        main(["check-config", "-c", str(bad)])
    assert exc.value.code == 2
    assert "one of 'address' or 'esphome_name' is required" in capsys.readouterr().err


def test_cli_export_command(tmp_path, capsys):
    conf = write_conf(tmp_path)
    s = st.Storage(tmp_path / "data" / "collector.sqlite3")
    seed(s, "a", 3)
    s.close()
    assert main(["export", "-c", conf, "--device", "a", "--start", "2000-01-01"]) == 0
    out = capsys.readouterr().out.strip()
    assert out.endswith(".tar.gz") and os.path.exists(out)
    assert main(["export", "-c", conf, "--start", "nonsense"]) == 1


def test_cli_healthcheck(tmp_path, capsys):
    data = tmp_path / "d"
    assert main(["healthcheck", "--data-dir", str(data)]) == 1  # no heartbeat yet
    (data / "health").mkdir(parents=True)
    hb = data / "health" / "heartbeat"
    hb.write_text(json.dumps({"pid": os.getpid()}))
    assert main(["healthcheck", "--data-dir", str(data)]) == 0
    hb.write_text(json.dumps({"pid": 2 ** 22 + 12345}))
    assert main(["healthcheck", "--data-dir", str(data)]) == 1  # process gone
    hb.write_text(json.dumps({"pid": os.getpid()}))
    old = time.time() - 300
    os.utime(hb, (old, old))
    assert main(["healthcheck", "--data-dir", str(data)]) == 1  # stale
