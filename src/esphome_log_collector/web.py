"""Small read-only web UI (standard library only; disabled unless enabled in YAML).

It never controls devices. The only state-changing operation is "create export", which
writes a sanitized tarball into the export directory. There is no authentication:
bind to localhost (default) or place it behind an authenticated reverse proxy.
"""

from __future__ import annotations

import hmac
import html
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

from .config import Config
from .export import EXPORT_NAME_RE, ExportError, create_export
from .parsing import LEVELS, strip_ansi
from .redact import Redactor
from .storage import COLLECTOR_EVENTS, LOG, connect
from .timeutil import parse_ts

log = logging.getLogger("web")
MAX_POST_BYTES = 64 * 1024
EVENT_TYPES = (LOG, *COLLECTOR_EVENTS)
_STYLE = """
:root {
  color-scheme: light;
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  color: #1e293b;
  background: #eef3f9;
}
* { box-sizing: border-box; }
body {
  max-width: 1440px;
  margin: 0 auto;
  padding: clamp(1rem, 3vw, 2.5rem);
  background: radial-gradient(ellipse at top left, #fff 0, #f4f7fb 58%, #eaf0f8 100%);
  min-height: 100vh;
}
nav {
  display: flex;
  flex-wrap: wrap;
  gap: .5rem;
  padding: .4rem;
  width: fit-content;
  background: #e7edf6;
  border: 1px solid #d7e0ec;
  border-radius: 999px;
}
a {
  color: #155eef;
  text-decoration: none;
}
nav a {
  padding: .55rem .9rem;
  color: #475569;
  font-size: .9rem;
  font-weight: 650;
  border-radius: 999px;
}
nav a:hover, nav a:focus-visible {
  color: #123ea8;
  background: #fff;
  outline: none;
}
h1 {
  margin: 1.5rem 0 1rem;
  color: #172554;
  font-size: clamp(1.7rem, 4vw, 2.4rem);
  letter-spacing: -.04em;
}
form, ul {
  padding: 1rem;
  background: #fff;
  border: 1px solid #dce5f0;
  border-radius: 1rem;
  box-shadow: 0 8px 24px #1e293b0b;
}
form {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: .7rem;
}
form p { margin: 0; }
input, select, button {
  min-height: 2.5rem;
  padding: .5rem .7rem;
  color: #1e293b;
  font: inherit;
  background: #fff;
  border: 1px solid #cbd5e1;
  border-radius: .55rem;
}
input:focus, select:focus, button:focus-visible {
  border-color: #528bff;
  outline: 3px solid #528bff35;
}
button {
  padding-inline: 1rem;
  color: #fff;
  font-weight: 700;
  background: #2563eb;
  border-color: #2563eb;
  cursor: pointer;
}
button:hover { background: #1d4ed8; }
table {
  width: 100%;
  margin: 1rem 0;
  overflow: hidden;
  background: #fff;
  border: 1px solid #dce5f0;
  border-collapse: separate;
  border-spacing: 0;
  border-radius: 1rem;
  box-shadow: 0 8px 24px #1e293b0b;
}
td, th {
  padding: .7rem .8rem;
  border-bottom: 1px solid #e8edf4;
  font-size: .84rem;
  text-align: left;
  vertical-align: top;
}
th {
  position: sticky;
  top: 0;
  color: #475569;
  font-size: .75rem;
  font-weight: 750;
  letter-spacing: .06em;
  text-transform: uppercase;
  background: #f5f8fc;
}
tr:last-child td { border-bottom: 0; }
tr:hover td { background: #f7faff; }
td.m {
  max-width: 48rem;
  color: #334155;
  font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.ERROR, .CRITICAL {
  color: #b42318;
  font-weight: 750;
  background: #fff1f0;
}
.WARNING { color: #a15c00; font-weight: 700; }
ul { padding-left: 2.25rem; }
li { padding: .25rem 0; }
p { line-height: 1.6; }
@media (max-width: 760px) {
  body { padding: 1rem .75rem; }
  table { display: block; overflow-x: auto; }
  td.m { min-width: 20rem; }
}
"""


class BadRequest(Exception):
    pass


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _log_filters(params: dict[str, str]) -> tuple[list[str], list[str]]:
    where, args = [], []
    if params.get("device"):
        where.append("device = ?")
        args.append(params["device"])
    try:
        if params.get("start"):
            where.append("ts >= ?")
            args.append(parse_ts(params["start"]))
        if params.get("end"):
            where.append("ts < ?")
            args.append(parse_ts(params["end"]))
    except ValueError as err:
        raise BadRequest(str(err)) from err
    if params.get("level"):
        if params["level"] not in {*LEVELS.values(), "CRITICAL"}:
            raise BadRequest(f"unknown level {params['level']!r}")
        where.append("level = ?")
        args.append(params["level"])
    if params.get("type"):
        if params["type"] not in EVENT_TYPES:
            raise BadRequest(f"unknown event type {params['type']!r}")
        where.append("event_type = ?")
        args.append(params["type"])
    if params.get("q"):
        where.append("raw LIKE ? ESCAPE '\\'")
        args.append(f"%{_like_escape(params['q'])}%")
    return where, args


def query_logs(conn: sqlite3.Connection, params: dict[str, str], page: int, page_size: int) -> tuple[list[sqlite3.Row], bool]:
    where, args = _log_filters(params)
    sql = "SELECT id, ts, device, session_id, event_type, level, component, message, raw FROM events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
    rows = conn.execute(sql, (*args, page_size + 1, (page - 1) * page_size)).fetchall()
    return rows[:page_size], len(rows) > page_size


def query_new_logs(conn: sqlite3.Connection, params: dict[str, str], after: int) -> list[sqlite3.Row]:
    where, args = _log_filters(params)
    where.append("id > ?")
    args.append(str(after))
    sql = "SELECT id, ts, device, session_id, event_type, level, component, message, raw FROM events"
    sql += " WHERE " + " AND ".join(where) + " ORDER BY id LIMIT 200"
    return conn.execute(sql, args).fetchall()


class WebServer:
    def __init__(self, config: Config, redactor: Redactor | None = None) -> None:
        self.config = config
        self.redactor = redactor or Redactor()
        self.csrf_token = secrets.token_urlsafe(32)
        self.allowed_hosts = {h.lower() for h in config.web.allowed_hosts}
        server = self

        class Handler(_Handler):
            app = server

        self.httpd = ThreadingHTTPServer((config.web.bind, config.web.port), Handler)
        self.httpd.daemon_threads = True
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        return self.httpd.server_address[1]

    def start(self) -> None:
        self._thread = threading.Thread(target=self.httpd.serve_forever, name="web", daemon=True)
        self._thread.start()
        log.info("web UI listening on http://%s:%d", self.config.web.bind, self.port)

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread:
            self._thread.join(timeout=5)


class _Handler(BaseHTTPRequestHandler):
    app: WebServer
    server_version = "esphome-log-collector"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:  # route access logs to the container log
        log.debug("%s - %s", self.address_string(), fmt % args)

    # ---- plumbing ----
    def _send(
        self, status: int, body: bytes, ctype: str = "text/html; charset=utf-8", extra: dict | None = None,
        script_nonce: str | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        csp = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
        if script_nonce:
            csp += f"; script-src 'nonce-{script_nonce}'; connect-src 'self'"
        self.send_header("Content-Security-Policy", csp)
        for k, v in (extra or {}).items():
            self.send_header(k, v.replace("\r", "").replace("\n", ""))  # never allow header injection
        self.end_headers()
        self.wfile.write(body)

    def _page(self, title: str, body: str, status: int = 200, script_nonce: str | None = None) -> None:
        nav = '<nav><a href="/">Status</a><a href="/logs">Logs</a><a href="/tail">Tail</a><a href="/exports">Exports</a></nav>'
        doc = (f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title>"
               "<meta name='viewport' content='width=device-width, initial-scale=1'>"
               f"<style>{_STYLE}</style></head><body>{nav}<h1>{html.escape(title)}</h1>{body}</body></html>")
        self._send(status, doc.encode("utf-8"), script_nonce=script_nonce)

    def _json(self, payload, status: int = 200) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json")

    def _host_ok(self) -> bool:
        allowed = self.app.allowed_hosts
        if not allowed:
            return True
        host = (self.headers.get("Host") or "").lower()
        host = host.rsplit(":", 1)[0] if not host.endswith("]") else host
        return host in allowed

    def _db(self):
        return closing(connect(self.app.config.db_path, readonly=True))

    def _dispatch(self, method: str) -> None:
        if not self._host_ok():
            return self._send(403, b"host not allowed", "text/plain")
        url = urlparse(self.path)
        params = {k: v[0] for k, v in parse_qs(url.query, max_num_fields=20).items()}
        try:
            if method == "GET":
                self._route_get(url.path, params)
            else:
                self._route_post(url.path)
        except BadRequest as err:
            self._page("Bad request", f"<p>{html.escape(str(err))}</p>", 400)
        except sqlite3.Error as err:
            log.error("web UI database error: %s", err)
            self._page("Database unavailable", "<p>The collector database could not be read.</p>", 503)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def _method_not_allowed(self) -> None:
        self._send(405, b"method not allowed", "text/plain", {"Allow": "GET, POST"})

    do_PUT = do_DELETE = do_PATCH = _method_not_allowed  # noqa: N815

    # ---- routes ----
    def _route_get(self, path: str, p: dict[str, str]) -> None:
        if path == "/":
            return self._status_page()
        if path == "/logs":
            return self._logs_page(p)
        if path == "/tail":
            return self._tail_page(p)
        if path == "/exports":
            return self._exports_page()
        if path.startswith("/exports/"):
            return self._download(path[len("/exports/"):])
        if path == "/api/status":
            with self._db() as conn:
                return self._json([dict(r) for r in conn.execute("SELECT * FROM device_status ORDER BY device")])
        if path == "/api/logs":
            rows, more, _ = self._fetch_logs(p)
            return self._json({"events": [{**dict(r), "clean": strip_ansi(r["raw"])} for r in rows], "has_next": more})
        if path == "/api/tail":
            return self._tail_stream(p)
        self._page("Not found", "<p>Not found.</p>", 404)

    def _route_post(self, path: str) -> None:
        if path != "/export":
            return self._page("Not found", "<p>Not found.</p>", 404)
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError as err:
            raise BadRequest("invalid Content-Length") from err
        if not 0 <= length <= MAX_POST_BYTES:
            raise BadRequest("invalid or too large request body")
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"), max_num_fields=50)
        token = (form.get("csrf") or [""])[0]
        if not hmac.compare_digest(token, self.app.csrf_token):
            return self._page("Forbidden", "<p>Invalid or missing CSRF token; reload the form.</p>", 403)
        try:
            path_out = create_export(
                self.app.config.db_path, self.app.config.export_dir,
                devices=form.get("device") or None,
                start=(form.get("start") or [""])[0] or None, end=(form.get("end") or [""])[0] or None,
                include_configs=bool(form.get("include_configs")), redactor=self.app.redactor,
            )
        except ExportError as err:
            raise BadRequest(str(err)) from err
        log.info("web UI created export %s", path_out.name)
        self._send(303, b"", "text/plain", {"Location": "/exports"})

    def _fetch_logs(self, p: dict[str, str]):
        try:
            page = max(1, int(p.get("page", "1")))
        except ValueError as err:
            raise BadRequest("page must be an integer") from err
        size = self.app.config.web.page_size
        try:
            if p.get("page_size"):
                size = min(500, max(1, int(p["page_size"])))
        except ValueError as err:
            raise BadRequest("page_size must be an integer") from err
        with self._db() as conn:
            rows, more = query_logs(conn, p, page, size)
        return rows, more, page

    def _devices(self) -> list[str]:
        with self._db() as conn:
            return [r[0] for r in conn.execute("SELECT device FROM device_status ORDER BY device")]

    def _status_page(self) -> None:
        with self._db() as conn:
            rows = conn.execute("SELECT * FROM device_status ORDER BY device").fetchall()
        cells = "".join(
            "<tr>" + "".join(f"<td>{html.escape(str(r[k] if r[k] is not None else ''))}</td>" for k in
                             ("device", "address", "backend", "source", "state", "last_line_at", "attempts",
                              "next_retry_at", "last_error")) + "</tr>"
            for r in rows)
        head = "".join(f"<th>{h}</th>" for h in ("Device", "Address", "Backend", "Source", "State", "Last line (UTC)",
                                                  "Attempts", "Next retry (UTC)", "Last error"))
        self._page("Collector status", f"<table><tr>{head}</tr>{cells}</table>")

    def _logs_page(self, p: dict[str, str]) -> None:
        rows, more, page = self._fetch_logs(p)
        esc = html.escape
        devices = "".join(f"<option{' selected' if d == p.get('device') else ''}>{esc(d)}</option>" for d in self._devices())
        levels = "".join(f"<option{' selected' if v == p.get('level') else ''}>{v}</option>" for v in LEVELS.values())
        types = "".join(f"<option{' selected' if t == p.get('type') else ''}>{t}</option>" for t in EVENT_TYPES)
        form = (f"<form method='get' action='/logs'>Device <select name='device'><option value=''>all</option>{devices}</select> "
                f"Level <select name='level'><option value=''>any</option>{levels}</select> "
                f"Type <select name='type'><option value=''>any</option>{types}</select> "
                f"From <input name='start' value='{esc(p.get('start', ''), True)}' placeholder='2025-01-31T12:00:00Z'> "
                f"To <input name='end' value='{esc(p.get('end', ''), True)}'> "
                f"Text <input name='q' value='{esc(p.get('q', ''), True)}'> <button>Search</button></form>")
        body_rows = "".join(
            f"<tr><td>{esc(r['ts'])}</td><td>{esc(r['device'])}</td><td class='{esc(r['level'] or '')}'>{esc(r['level'] or '')}</td>"
            f"<td>{esc(r['component'] or '')}</td><td>{'' if r['event_type'] == LOG else '<b>[' + esc(r['event_type']) + ']</b> '}"
            f"</td><td class='m'>{esc(strip_ansi(r['raw']))}</td></tr>" for r in rows)
        base = {k: v for k, v in p.items() if k != "page" and v}

        def link(n: int, label: str) -> str:
            qs = "&".join(f"{quote(k)}={quote(v)}" for k, v in {**base, "page": str(n)}.items())
            return f"<a href='/logs?{esc(qs, True)}'>{label}</a> "

        pager = (link(page - 1, "&laquo; newer") if page > 1 else "") + f"page {page} " + (link(page + 1, "older &raquo;") if more else "")
        self._page("Logs", f"{form}<p>{pager}</p><table><tr><th>Time (UTC)</th><th>Device</th><th>Level</th>"
                           f"<th>Component</th><th>Type</th><th>Line (ANSI removed)</th></tr>{body_rows}</table><p>{pager}</p>")

    def _tail_page(self, p: dict[str, str]) -> None:
        size = min(500, max(1, self.app.config.web.page_size))
        with self._db() as conn:
            conn.execute("BEGIN")
            rows, _ = query_logs(conn, p, 1, size)
            cursor = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
            conn.commit()

        esc = html.escape
        devices = "".join(f"<option{' selected' if d == p.get('device') else ''}>{esc(d)}</option>" for d in self._devices())
        levels = "".join(f"<option{' selected' if v == p.get('level') else ''}>{v}</option>" for v in LEVELS.values())
        types = "".join(f"<option{' selected' if t == p.get('type') else ''}>{t}</option>" for t in EVENT_TYPES)
        form = (f"<form method='get' action='/tail'>Device <select name='device'><option value=''>all</option>{devices}</select> "
                f"Level <select name='level'><option value=''>any</option>{levels}</select> "
                f"Type <select name='type'><option value=''>any</option>{types}</select> "
                f"Text <input name='q' value='{esc(p.get('q', ''), True)}'> <button>Tail</button></form>")
        body_rows = "".join(
            f"<tr><td>{esc(r['ts'])}</td><td>{esc(r['device'])}</td><td class='{esc(r['level'] or '')}'>{esc(r['level'] or '')}</td>"
            f"<td>{esc(r['component'] or '')}</td><td>{'' if r['event_type'] == LOG else '<b>[' + esc(r['event_type']) + ']</b> '}"
            f"</td><td class='m'>{esc(strip_ansi(r['raw']))}</td></tr>" for r in reversed(rows)
        )
        stream_params = {k: v for k, v in p.items() if k in {"device", "level", "type", "q"} and v}
        stream_params["after"] = str(cursor)
        stream_url = "/api/tail?" + "&".join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in stream_params.items())
        nonce = secrets.token_urlsafe(18)
        script = f"""<script nonce="{nonce}">
const tailState = document.getElementById("tail-state");
const tailRows = document.querySelector("#tail-rows");
const source = new EventSource({json.dumps(stream_url)});
source.onopen = () => {{ tailState.textContent = "Live"; }};
source.onerror = () => {{ tailState.textContent = "Reconnecting…"; }};
source.onmessage = (message) => {{
  const event = JSON.parse(message.data);
  const row = document.createElement("tr");
  for (const value of [event.ts, event.device, event.level || "", event.component || ""]) {{
    const cell = document.createElement("td");
    cell.textContent = value;
    row.appendChild(cell);
  }}
  const typeCell = document.createElement("td");
  typeCell.textContent = event.event_type === "log" ? "" : "[" + event.event_type + "]";
  row.appendChild(typeCell);
  const lineCell = document.createElement("td");
  lineCell.className = "m";
  lineCell.textContent = event.clean;
  row.appendChild(lineCell);
  const stayAtBottom = window.innerHeight + window.scrollY >= document.body.scrollHeight - 40;
  tailRows.appendChild(row);
  while (tailRows.rows.length > 500) tailRows.deleteRow(0);
  if (stayAtBottom) window.scrollTo(0, document.body.scrollHeight);
}};
window.scrollTo(0, document.body.scrollHeight);
</script>"""
        self._page("Live log tail", f"{form}<p>Stream: <strong id='tail-state' aria-live='polite'>Connecting…</strong></p>"
                                   "<table><thead><tr><th>Time (UTC)</th><th>Device</th><th>Level</th><th>Component</th>"
                                   "<th>Type</th><th>Line (ANSI removed)</th></tr></thead>"
                                   f"<tbody id='tail-rows'>{body_rows}</tbody></table>{script}", script_nonce=nonce)

    def _tail_stream(self, p: dict[str, str]) -> None:
        try:
            after = int(self.headers.get("Last-Event-ID") or p.get("after", "0"))
            if after < 0:
                raise ValueError
        except ValueError as err:
            raise BadRequest("after must be a non-negative integer") from err
        _log_filters(p)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(b": connected\n\n")
        self.wfile.flush()
        last_heartbeat = time.monotonic()
        try:
            while True:
                with self._db() as conn:
                    rows = query_new_logs(conn, p, after)
                for row in rows:
                    event = {**dict(row), "clean": strip_ansi(row["raw"])}
                    payload = json.dumps(event, ensure_ascii=False).encode("utf-8")
                    self.wfile.write(f"id: {row['id']}\ndata: ".encode("ascii") + payload + b"\n\n")
                    self.wfile.flush()
                    after = row["id"]
                now = time.monotonic()
                if now - last_heartbeat >= 15:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    last_heartbeat = now
                time.sleep(0.5)
        except ConnectionError:
            return
        except sqlite3.Error:
            log.exception("web UI tail stream database error")
            return

    def _export_files(self) -> list[Path]:
        d = self.app.config.export_dir
        if not d.is_dir():
            return []
        return sorted((f for f in d.iterdir() if f.is_file() and not f.is_symlink() and EXPORT_NAME_RE.match(f.name)),
                      reverse=True)

    def _exports_page(self) -> None:
        esc = html.escape
        files = "".join(f"<li><a href='/exports/{esc(f.name, True)}'>{esc(f.name)}</a> ({f.stat().st_size} bytes)</li>"
                        for f in self._export_files())
        devices = "".join(f"<label><input type='checkbox' name='device' value='{esc(d, True)}'> {esc(d)}</label> "
                          for d in self._devices())
        form = (f"<form method='post' action='/export'><input type='hidden' name='csrf' value='{self.app.csrf_token}'>"
                f"<p>Devices (none selected = all): {devices}</p>"
                "<p>From (UTC, inclusive) <input name='start'> To (UTC, exclusive) <input name='end'> "
                "<label><input type='checkbox' name='include_configs' value='1' checked> sanitized configurations</label> "
                "<button>Create export</button></p></form>")
        self._page("Exports", f"{form}<ul>{files}</ul>")

    def _download(self, name: str) -> None:
        if not EXPORT_NAME_RE.match(name):  # rejects anything but our own generated names (no traversal)
            return self._page("Not found", "<p>Not found.</p>", 404)
        path = self.app.config.export_dir / name
        if not path.is_file() or path.is_symlink():
            return self._page("Not found", "<p>Not found.</p>", 404)
        with path.open("rb") as fh:
            size = os.fstat(fh.fileno()).st_size
            self.send_response(200)
            self.send_header("Content-Type", "application/gzip")
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition", f'attachment; filename="{name}"')
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            while chunk := fh.read(1 << 20):
                self.wfile.write(chunk)
