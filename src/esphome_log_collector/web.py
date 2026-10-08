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
_STYLE = ("body{font-family:sans-serif;margin:1em}table{border-collapse:collapse}td,th{border:1px solid #ccc;"
          "padding:2px 6px;font-size:13px;vertical-align:top}td.m{font-family:monospace;white-space:pre-wrap}"
          ".ERROR,.CRITICAL{color:#b00}.WARNING{color:#a60}nav a{margin-right:1em}")


class BadRequest(Exception):
    pass


def _like_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def query_logs(conn: sqlite3.Connection, params: dict[str, str], page: int, page_size: int) -> tuple[list[sqlite3.Row], bool]:
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
    sql = "SELECT id, ts, device, session_id, event_type, level, component, message, raw FROM events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
    rows = conn.execute(sql, (*args, page_size + 1, (page - 1) * page_size)).fetchall()
    return rows[:page_size], len(rows) > page_size


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

    def log_message(self, fmt: str, *args) -> None:  # route access logs to the container log
        log.debug("%s - %s", self.address_string(), fmt % args)

    # ---- plumbing ----
    def _send(self, status: int, body: bytes, ctype: str = "text/html; charset=utf-8", extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
        for k, v in (extra or {}).items():
            self.send_header(k, v.replace("\r", "").replace("\n", ""))  # never allow header injection
        self.end_headers()
        self.wfile.write(body)

    def _page(self, title: str, body: str, status: int = 200) -> None:
        nav = '<nav><a href="/">Status</a><a href="/logs">Logs</a><a href="/exports">Exports</a></nav>'
        doc = (f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title>"
               f"<style>{_STYLE}</style></head><body>{nav}<h1>{html.escape(title)}</h1>{body}</body></html>")
        self._send(status, doc.encode("utf-8"))

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
