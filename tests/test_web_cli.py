import dataclasses
import json
import os
import re
import time
import urllib.error
import urllib.request

import pytest

from esphome_log_collector import storage as st
from esphome_log_collector.cli import main
from esphome_log_collector.web import WebServer
from helpers import seed


@pytest.fixture
def web(tmp_path, make_config):
    cfg = make_config([{"name": "a", "address": "1.1.1.1"}], web={"enabled": True})
    cfg = dataclasses.replace(cfg, web=dataclasses.replace(cfg.web, port=0))
    s = st.Storage(cfg.db_path)
    seed(s, "a", 30, prefix="alpha")
    seed(s, "b", 5, prefix="beta")
    s.add_log("a", None, s.start_session("a", None)[0], "[00:00:00]\x1b[0;31m[E][x:1]: failure 100%_done\x1b[0m")
    s.set_status("a", state="connected", address="1.1.1.1")
    s.checkpoint()
    server = WebServer(cfg)
    server.start()
    yield f"http://127.0.0.1:{server.port}", server, cfg
    server.stop()
    s.close()


def get(url, **kw):
    req = urllib.request.Request(url, **kw)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode("utf-8", "replace"), r.headers
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode("utf-8", "replace"), err.headers


def test_disabled_and_localhost_by_default(make_config):
    cfg = make_config([{"name": "a", "address": "1.1.1.1"}])
    assert cfg.web.enabled is False and cfg.web.bind == "127.0.0.1"


def test_status_page_and_api(web):
    base, _, _ = web
    status, body, headers = get(base + "/")
    assert status == 200 and "connected" in body and headers["Content-Security-Policy"].startswith("default-src 'none'")
    assert "radial-gradient" in body and "name='viewport'" in body
    assert json.loads(get(base + "/api/status")[1])[0]["device"] == "a"


def test_log_search_filters_and_pagination(web):
    base, _, _ = web
    data = json.loads(get(base + "/api/logs?device=a&q=alpha&page_size=10")[1])
    assert len(data["events"]) == 10 and data["has_next"] is True
    page3 = json.loads(get(base + "/api/logs?device=a&q=alpha&page_size=10&page=3")[1])
    assert len(page3["events"]) == 10 and page3["has_next"] is False
    only_b = json.loads(get(base + "/api/logs?device=b")[1])["events"]
    assert only_b and all(e["device"] == "b" for e in only_b)
    errs = json.loads(get(base + "/api/logs?level=ERROR")[1])["events"]
    assert len(errs) == 1 and "\x1b" not in errs[0]["clean"] and "\x1b" in errs[0]["raw"]
    assert len(json.loads(get(base + "/api/logs?q=100%25_done")[1])["events"]) == 1  # LIKE wildcards are literal
    assert json.loads(get(base + "/api/logs?q=alpha&start=2999-01-01T00:00:00Z")[1])["events"] == []
    assert get(base + "/api/logs?start=garbage")[0] == 400
    assert get(base + "/api/logs?level=NOPE")[0] == 400


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
    token = re.search(r"name='csrf' value='([^']+)'", page).group(1)

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(base + "/export", data=f"csrf={token}&device=a".encode(), method="POST")
    with pytest.raises(urllib.error.HTTPError) as exc:
        opener.open(req)
    assert exc.value.code == 303
    listing = get(base + "/exports")[1]
    name = re.search(r"/exports/(esphome-log-export-[^']+\.tar\.gz)", listing).group(1)
    status, _, headers = get(base + "/exports/" + name)
    assert status == 200 and headers["Content-Type"] == "application/gzip"
    for bad in ("../collector.sqlite3", "..%2fcollector.sqlite3", "notes.txt", "%2e%2e/x"):
        assert get(base + "/exports/" + bad)[0] == 404


def test_allowed_hosts(tmp_path, make_config):
    cfg = make_config([{"name": "a", "address": "1.1.1.1"}], web={"enabled": True, "allowed_hosts": ["logs.example"]})
    cfg = dataclasses.replace(cfg, web=dataclasses.replace(cfg.web, port=0))
    st.Storage(cfg.db_path).close()
    server = WebServer(cfg)
    server.start()
    try:
        base = f"http://127.0.0.1:{server.port}"
        assert get(base + "/api/status")[0] == 403
        assert get(base + "/api/status", headers={"Host": "logs.example"})[0] == 200
    finally:
        server.stop()


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
