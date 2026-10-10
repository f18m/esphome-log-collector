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
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from string import Template
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
STATE_INDICATORS = {
    "connected": ("●", "connected"),
    "starting": ("◌", "starting"),
    "connecting": ("◌", "connecting"),
    "backoff": ("↻", "backoff"),
    "stopped": ("■", "stopped"),
}
STATIC_ASSETS = {
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
    "/static/favicon.svg": ("favicon.svg", "image/svg+xml; charset=utf-8"),
    "/static/tail.js": ("tail.js", "text/javascript; charset=utf-8"),
    "/static/ui.js": ("ui.js", "text/javascript; charset=utf-8"),
}
LOG_LEVEL_FILTERS = (*LEVELS.values(), "CRITICAL")


@lru_cache(maxsize=None)
def _template(name: str) -> Template:
    source = files(__package__).joinpath("web_assets", "templates", name).read_text(encoding="utf-8")
    return Template(source)


def _render(template_name: str, **values: str) -> str:
    return _template(template_name).substitute(values)


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
        if params["level"] not in LOG_LEVEL_FILTERS:
            raise BadRequest(f"unknown level {params['level']!r}")
        threshold = LOG_LEVEL_FILTERS.index(params["level"])
        matching_levels = LOG_LEVEL_FILTERS[threshold:]
        where.append(f"level IN ({', '.join('?' for _ in matching_levels)})")
        args.extend(matching_levels)
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
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'",
        )
        for k, v in (extra or {}).items():
            self.send_header(k, v.replace("\r", "").replace("\n", ""))  # never allow header injection
        self.end_headers()
        self.wfile.write(body)

    def _page(self, title: str, template: str, status: int = 200, **values: str) -> None:
        content = _render(template, **values)
        path = urlparse(self.path).path
        active_page = (
            "status" if path == "/" else
            "logs" if path == "/logs" else
            "tail" if path == "/tail" else
            "exports" if path == "/exports" or path.startswith("/exports/") else
            ""
        )
        document_values = {
            "title": html.escape(title),
            "content": content,
            "page_class": f"{active_page}-page" if active_page in {"logs", "tail"} else "",
        }
        for page in ("status", "logs", "tail", "exports"):
            selected = page == active_page
            document_values[f"{page}_class"] = "active" if selected else ""
            document_values[f"{page}_current"] = 'aria-current="page"' if selected else ""
        document = _render("base.html", **document_values)
        self._send(status, document.encode("utf-8"))

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
                if url.path in STATIC_ASSETS:
                    filename, content_type = STATIC_ASSETS[url.path]
                    body = files(__package__).joinpath("web_assets", "static", filename).read_bytes()
                    self._send(200, body, content_type)
                else:
                    self._route_get(url.path, params)
            else:
                self._route_post(url.path)
        except BadRequest as err:
            self._page("Bad request", "message.html", 400, message=html.escape(str(err)))
        except sqlite3.Error as err:
            log.error("web UI database error: %s", err)
            self._page("Database unavailable", "message.html", 503, message="The collector database could not be read.")

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
        self._page("Not found", "message.html", 404, message="Not found.")

    def _route_post(self, path: str) -> None:
        if path != "/export":
            return self._page("Not found", "message.html", 404, message="Not found.")
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError as err:
            raise BadRequest("invalid Content-Length") from err
        if not 0 <= length <= MAX_POST_BYTES:
            raise BadRequest("invalid or too large request body")
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"), max_num_fields=50)
        token = (form.get("csrf") or [""])[0]
        if not hmac.compare_digest(token, self.app.csrf_token):
            return self._page(
                "Forbidden", "message.html", 403,
                message="Invalid or missing CSRF token; reload the form.",
            )
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

    def _options(self, values, selected: str | None, label_suffix: str = "") -> str:
        return "".join(
            _render(
                "log_options.html",
                value=html.escape(value, quote=True),
                label=html.escape(value + label_suffix),
                selected=" selected" if value == selected else "",
            )
            for value in values
        )

    def _tail_lines(self, rows) -> str:
        rendered = []
        for row in rows:
            event_marker = "" if row["event_type"] == LOG else f"[{html.escape(row['event_type'])}]"
            rendered.append(
                _render(
                    "tail_line.html",
                    ts=html.escape(row["ts"]),
                    device=html.escape(row["device"]),
                    level=html.escape(row["level"] or ""),
                    component=html.escape(row["component"] or ""),
                    event_marker=event_marker,
                    line=html.escape(strip_ansi(row["raw"])),
                )
            )
        return "".join(rendered)

    def _status_page(self) -> None:
        with self._db() as conn:
            rows = conn.execute(
                """
                SELECT device_status.*,
                       (SELECT COUNT(*) FROM events
                        WHERE events.device = device_status.device AND events.event_type = ?)
                           AS log_count
                FROM device_status
                ORDER BY device
                """,
                (LOG,),
            ).fetchall()
        columns = (
            "device", "address", "backend", "source", "state", "last_line_at", "log_count",
            "attempts", "next_retry_at", "last_error",
        )
        rendered = []
        for row in rows:
            values = {
                key: html.escape(str(row[key] if row[key] is not None else ""))
                for key in columns
            }
            values["next_retry_at"] = html.escape(row["next_retry_at"] or "-")
            values["last_error"] = html.escape(row["last_error"] or "none")
            icon, state_class = STATE_INDICATORS.get(row["state"], ("●", "unknown"))
            values["state_indicator"] = (
                f'<span class="state-indicator state-{state_class}" '
                f'title="{values["state"]}" aria-label="{values["state"]}">{icon}</span>'
            )
            rendered.append(_render("status_row.html", **values))
        self._page("Collector status", "status.html", rows="".join(rendered))

    def _logs_page(self, p: dict[str, str]) -> None:
        rows, more, page = self._fetch_logs(p)
        devices = self._options(self._devices(), p.get("device"))
        levels = self._options(LOG_LEVEL_FILTERS, p.get("level"), " or higher")
        types = self._options(list(EVENT_TYPES), p.get("type"))
        body_rows = self._tail_lines(rows)
        base = {k: v for k, v in p.items() if k != "page" and v}

        def link(n: int, label: str) -> str:
            qs = "&".join(f"{quote(k)}={quote(v)}" for k, v in {**base, "page": str(n)}.items())
            return _render("pager_link.html", query=html.escape(qs, quote=True), label=label)

        pager = (
            (link(page - 1, "&laquo; newer") + " " if page > 1 else "")
            + f"page {page} "
            + (link(page + 1, "older &raquo;") if more else "")
        )
        self._page(
            "Logs",
            "logs.html",
            devices=devices,
            levels=levels,
            types=types,
            start=html.escape(parse_ts(p["start"])[:19] if p.get("start") else "", quote=True),
            end=html.escape(parse_ts(p["end"])[:19] if p.get("end") else "", quote=True),
            query=html.escape(p.get("q", ""), quote=True),
            pager=pager,
            rows=body_rows,
        )

    def _tail_page(self, p: dict[str, str]) -> None:
        size = min(500, max(1, self.app.config.web.page_size))
        with self._db() as conn:
            conn.execute("BEGIN")
            rows, _ = query_logs(conn, p, 1, size)
            cursor = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
            conn.commit()

        devices = self._options(self._devices(), p.get("device"))
        levels = self._options(LOG_LEVEL_FILTERS, p.get("level"), " or higher")
        types = self._options(list(EVENT_TYPES), p.get("type"))
        body_rows = self._tail_lines(reversed(rows))
        stream_params = {k: v for k, v in p.items() if k in {"device", "level", "type", "q"} and v}
        stream_params["after"] = str(cursor)
        stream_url = "/api/tail?" + "&".join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in stream_params.items())
        self._page(
            "Live Tail",
            "tail.html",
            devices=devices,
            levels=levels,
            types=types,
            query=html.escape(p.get("q", ""), quote=True),
            stream_url=html.escape(stream_url, quote=True),
            rows=body_rows,
        )

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
        rendered_files = "".join(
            _render(
                "export_file.html",
                href=html.escape(file.name, quote=True),
                name=html.escape(file.name),
                size=str(file.stat().st_size),
            )
            for file in self._export_files()
        )
        devices = "".join(
            _render(
                "export_device.html",
                value=html.escape(device, quote=True),
                label=html.escape(device),
            )
            for device in self._devices()
        )
        self._page(
            "Exports",
            "exports.html",
            csrf_token=html.escape(self.app.csrf_token, quote=True),
            devices=devices,
            files=rendered_files,
        )

    def _download(self, name: str) -> None:
        if not EXPORT_NAME_RE.match(name):  # rejects anything but our own generated names (no traversal)
            return self._page("Not found", "message.html", 404, message="Not found.")
        path = self.app.config.export_dir / name
        if not path.is_file() or path.is_symlink():
            return self._page("Not found", "message.html", 404, message="Not found.")
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
