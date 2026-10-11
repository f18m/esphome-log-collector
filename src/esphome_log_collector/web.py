"""Small read-only web UI served by FastAPI/uvicorn (disabled unless enabled in YAML).

It never controls devices. The only state-changing operation is "create export", which
writes a sanitized tarball into the export directory. There is no authentication:
bind to localhost (default) or place it behind an authenticated reverse proxy.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import html
import json
import logging
import secrets
import sqlite3
import time
from collections.abc import AsyncIterator, Iterator
from contextlib import closing
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from string import Template
from typing import Annotated, Any
from urllib.parse import parse_qs, quote

import uvicorn
from fastapi import APIRouter, FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
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
API_VERSION = "1.0.0"  # version of the HTTP API contract (not the package version)
TAIL_POLL_SECONDS = 0.5
TAIL_KEEPALIVE_SECONDS = 15
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'none'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'"
    ),
}


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


# ---- API models (the OpenAPI contract; explicit fields, never derived from SELECT *) ----
class ErrorResponse(BaseModel):
    """JSON error body returned by every /api/* endpoint."""

    error: str = Field(description="Human-readable error message.")


class DeviceStatus(BaseModel):
    device: str
    address: str | None = None
    backend: str | None = None
    source: str | None = None
    state: str = Field(description="Collector state, e.g. connected, connecting, backoff, stopped.")
    session_id: str | None = None
    updated_at: str
    last_line_at: str | None = None
    last_error: str | None = None
    last_error_at: str | None = None
    attempts: int
    next_retry_at: str | None = None


class LogEvent(BaseModel):
    id: int = Field(description="Monotonic event id; also used as the SSE event id.")
    ts: str = Field(description="UTC timestamp of the event.")
    device: str
    session_id: str
    event_type: str = Field(description="'log' or a collector event type.", examples=list(EVENT_TYPES))
    level: str | None = None
    component: str | None = None
    message: str | None = None
    raw: str = Field(description="Original line, possibly containing ANSI escapes.")
    clean: str = Field(description="`raw` with ANSI escape sequences removed.")


class LogPage(BaseModel):
    events: list[LogEvent] = Field(description="Events, newest first.")
    has_next: bool = Field(description="True when an older page exists.")


_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    400: {"model": ErrorResponse, "description": "Invalid parameter."},
    403: {"description": "Host header not allowed (plain text body).", "content": {"text/plain": {"schema": {"type": "string"}}}},
    503: {"model": ErrorResponse, "description": "The collector database could not be read."},
}
_FILTER_DOC = {
    "device": "Only events of this device.",
    "start": "Inclusive start (ISO-8601, UTC if no zone).",
    "end": "Exclusive end (ISO-8601, UTC if no zone).",
    "level": "Minimum log level.",
    "type": "Only this event type.",
    "q": "Case-insensitive substring match on the raw line (LIKE wildcards are literal).",
}
Device = Annotated[str | None, Query(description=_FILTER_DOC["device"])]
Start = Annotated[str | None, Query(description=_FILTER_DOC["start"])]
End = Annotated[str | None, Query(description=_FILTER_DOC["end"])]
Level = Annotated[str | None, Query(description=_FILTER_DOC["level"], json_schema_extra={"enum": list(LOG_LEVEL_FILTERS)})]
EventType = Annotated[str | None, Query(alias="type", description=_FILTER_DOC["type"], json_schema_extra={"enum": list(EVENT_TYPES)})]
Text = Annotated[str | None, Query(description=_FILTER_DOC["q"])]

SSE_DESCRIPTION = (
    "Server-Sent Events stream (`text/event-stream`). The stream starts with the comment `: connected`; "
    "a `: keepalive` comment is sent every 15 seconds when idle. Each new event is sent as "
    "`id: <event id>\\ndata: <LogEvent JSON>\\n\\n`, in ascending id order. Resume with the `after` "
    "parameter or the `Last-Event-ID` header (the header wins), as EventSource does on reconnect."
)


class WebState:
    """Everything the request handlers need; shared by the app and the server wrapper."""

    def __init__(self, config: Config, redactor: Redactor | None = None) -> None:
        self.config = config
        self.redactor = redactor or Redactor()
        self.csrf_token = secrets.token_urlsafe(32)
        self.allowed_hosts = {h.lower() for h in config.web.allowed_hosts}
        self.stopping = False
        self.active_streams = 0

    def db(self):
        return closing(connect(self.config.db_path, readonly=True))


def _state(request: Request) -> WebState:
    return request.app.state.web


def _params(request: Request) -> dict[str, str]:
    params: dict[str, str] = {}
    for key, value in request.query_params.multi_items():
        params.setdefault(key, value)
    return params


def _filters(device: str | None, start: str | None, end: str | None, level: str | None,
             type_: str | None, q: str | None) -> dict[str, str]:
    values = {"device": device, "start": start, "end": end, "level": level, "type": type_, "q": q}
    return {k: v for k, v in values.items() if v}


# ---- HTML rendering ----
def _page(request: Request, title: str, template: str, status: int = 200, **values: str) -> HTMLResponse:
    content = _render(template, **values)
    path = request.url.path
    active_page = (
        "status" if path == "/" else
        "logs" if path == "/logs" else
        "tail" if path == "/tail" else
        "exports" if path == "/exports" or path.startswith("/exports/") else
        ""
    )
    document_values = {
        "title": html.escape(title),
        "version": html.escape(__version__),
        "content": content,
        "page_class": f"{active_page}-page" if active_page in {"logs", "tail"} else "",
    }
    for page in ("status", "logs", "tail", "exports"):
        selected = page == active_page
        document_values[f"{page}_class"] = "active" if selected else ""
        document_values[f"{page}_current"] = 'aria-current="page"' if selected else ""
    return HTMLResponse(_render("base.html", **document_values), status_code=status)


def _error(request: Request, status: int, message: str, title: str, headers: dict[str, str] | None = None) -> Response:
    """JSON for /api/* and /openapi.json clients, the HTML message page for everything else."""
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": message}, status_code=status, headers=headers)
    response = _page(request, title, "message.html", status, message=html.escape(message))
    response.headers.update(headers or {})
    return response


def _options(values, selected: str | None, label_suffix: str = "") -> str:
    return "".join(
        _render(
            "log_options.html",
            value=html.escape(value, quote=True),
            label=html.escape(value + label_suffix),
            selected=" selected" if value == selected else "",
        )
        for value in values
    )


def _tail_lines(rows) -> str:
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


def _devices(state: WebState) -> list[str]:
    with state.db() as conn:
        return [r[0] for r in conn.execute("SELECT device FROM device_status ORDER BY device")]


def _clamp_page(page: int, page_size: int | None, default_size: int) -> tuple[int, int]:
    return max(1, page), (min(500, max(1, page_size)) if page_size else default_size)


def _event(row: sqlite3.Row) -> dict[str, Any]:
    return {**dict(row), "clean": strip_ansi(row["raw"])}


# ---- routes ----
router = APIRouter()


@router.get("/static/{name}", include_in_schema=False)
def static_asset(request: Request, name: str) -> Response:
    asset = STATIC_ASSETS.get(request.url.path)
    if asset is None:
        return _error(request, 404, "Not found.", "Not found")
    filename, content_type = asset
    body = files(__package__).joinpath("web_assets", "static", filename).read_bytes()
    return Response(body, media_type=content_type)


@router.get("/", include_in_schema=False, response_class=HTMLResponse)
def status_page(request: Request) -> Response:
    with _state(request).db() as conn:
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
    return _page(request, "Collector status", "status.html", rows="".join(rendered))


@router.get("/logs", include_in_schema=False, response_class=HTMLResponse)
def logs_page(request: Request) -> Response:
    state, p = _state(request), _params(request)
    try:
        page = max(1, int(p.get("page", "1")))
        size = min(500, max(1, int(p["page_size"]))) if p.get("page_size") else state.config.web.page_size
    except ValueError as err:
        raise BadRequest("page and page_size must be integers") from err
    with state.db() as conn:
        rows, more = query_logs(conn, p, page, size)
    devices = _options(_devices(state), p.get("device"))
    levels = _options(LOG_LEVEL_FILTERS, p.get("level"), " or higher")
    types = _options(list(EVENT_TYPES), p.get("type"))
    base = {k: v for k, v in p.items() if k != "page" and v}

    def link(n: int, label: str) -> str:
        qs = "&".join(f"{quote(k)}={quote(v)}" for k, v in {**base, "page": str(n)}.items())
        return _render("pager_link.html", query=html.escape(qs, quote=True), label=label)

    pager = (
        (link(page - 1, "&laquo; newer") + " " if page > 1 else "")
        + f"page {page} "
        + (link(page + 1, "older &raquo;") if more else "")
    )
    return _page(
        request,
        "Logs",
        "logs.html",
        devices=devices,
        levels=levels,
        types=types,
        start=html.escape(parse_ts(p["start"])[:19] if p.get("start") else "", quote=True),
        end=html.escape(parse_ts(p["end"])[:19] if p.get("end") else "", quote=True),
        query=html.escape(p.get("q", ""), quote=True),
        pager=pager,
        rows=_tail_lines(rows),
    )


@router.get("/tail", include_in_schema=False, response_class=HTMLResponse)
def tail_page(request: Request) -> Response:
    state, p = _state(request), _params(request)
    size = min(500, max(1, state.config.web.page_size))
    with state.db() as conn:
        conn.execute("BEGIN")
        rows, _ = query_logs(conn, p, 1, size)
        cursor = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
        conn.commit()
    stream_params = {k: v for k, v in p.items() if k in {"device", "level", "type", "q"} and v}
    stream_params["after"] = str(cursor)
    stream_url = "/api/tail?" + "&".join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in stream_params.items())
    return _page(
        request,
        "Live Tail",
        "tail.html",
        devices=_options(_devices(state), p.get("device")),
        levels=_options(LOG_LEVEL_FILTERS, p.get("level"), " or higher"),
        types=_options(list(EVENT_TYPES), p.get("type")),
        query=html.escape(p.get("q", ""), quote=True),
        stream_url=html.escape(stream_url, quote=True),
        rows=_tail_lines(reversed(rows)),
    )


def _export_files(state: WebState) -> list[Path]:
    d = state.config.export_dir
    if not d.is_dir():
        return []
    return sorted((f for f in d.iterdir() if f.is_file() and not f.is_symlink() and EXPORT_NAME_RE.match(f.name)),
                  reverse=True)


@router.get("/exports", include_in_schema=False, response_class=HTMLResponse)
def exports_page(request: Request) -> Response:
    state = _state(request)
    rendered_files = "".join(
        _render(
            "export_file.html",
            href=html.escape(file.name, quote=True),
            name=html.escape(file.name),
            size=str(file.stat().st_size),
        )
        for file in _export_files(state)
    )
    devices = "".join(
        _render("export_device.html", value=html.escape(device, quote=True), label=html.escape(device))
        for device in _devices(state)
    )
    return _page(
        request, "Exports", "exports.html",
        csrf_token=html.escape(state.csrf_token, quote=True), devices=devices, files=rendered_files,
    )


@router.get("/exports/{name:path}", include_in_schema=False)
def download_export(request: Request, name: str) -> Response:
    if not EXPORT_NAME_RE.match(name):  # rejects anything but our own generated names (no traversal)
        return _error(request, 404, "Not found.", "Not found")
    path = _state(request).config.export_dir / name
    if not path.is_file() or path.is_symlink():
        return _error(request, 404, "Not found.", "Not found")
    return FileResponse(path, media_type="application/gzip", filename=name, content_disposition_type="attachment")


@router.post("/export", include_in_schema=False)
async def create_export_action(request: Request) -> Response:
    state = _state(request)
    try:
        length = int(request.headers.get("content-length") or 0)
    except ValueError as err:
        raise BadRequest("invalid Content-Length") from err
    if not 0 <= length <= MAX_POST_BYTES:
        raise BadRequest("invalid or too large request body")
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_POST_BYTES:
            raise BadRequest("invalid or too large request body")
    try:
        form = parse_qs(body.decode("utf-8", "replace"), max_num_fields=50)
    except ValueError as err:
        raise BadRequest("too many form fields") from err
    token = (form.get("csrf") or [""])[0]
    if not hmac.compare_digest(token.encode(), state.csrf_token.encode()):
        return _page(request, "Forbidden", "message.html", 403,
                     message="Invalid or missing CSRF token; reload the form.")
    try:
        path_out = await asyncio.to_thread(
            create_export, state.config.db_path, state.config.export_dir,
            devices=form.get("device") or None,
            start=(form.get("start") or [""])[0] or None, end=(form.get("end") or [""])[0] or None,
            include_configs=bool(form.get("include_configs")), redactor=state.redactor,
        )
    except ExportError as err:
        raise BadRequest(str(err)) from err
    log.info("web UI created export %s", path_out.name)
    return Response(status_code=303, headers={"Location": "/exports"})


@router.get(
    "/api/status", response_model=list[DeviceStatus], responses={k: v for k, v in _ERROR_RESPONSES.items() if k != 400},
    summary="Collector status of every known device", tags=["api"],
)
def api_status(request: Request) -> list[dict[str, Any]]:
    columns = ", ".join(DeviceStatus.model_fields)
    with _state(request).db() as conn:
        return [dict(r) for r in conn.execute(f"SELECT {columns} FROM device_status ORDER BY device")]


@router.get(
    "/api/logs", response_model=LogPage, responses=_ERROR_RESPONSES,
    summary="Search stored events (newest first, paginated)", tags=["api"],
)
def api_logs(
    request: Request,
    device: Device = None, start: Start = None, end: End = None, level: Level = None,
    type_: EventType = None, q: Text = None,
    page: Annotated[int, Query(description="1-based page number (values below 1 are treated as 1).")] = 1,
    page_size: Annotated[int | None, Query(description="Events per page, clamped to 1..500; default is web.page_size.")] = None,
) -> dict[str, Any]:
    state = _state(request)
    page, size = _clamp_page(page, page_size, state.config.web.page_size)
    with state.db() as conn:
        rows, more = query_logs(conn, _filters(device, start, end, level, type_, q), page, size)
    return {"events": [_event(r) for r in rows], "has_next": more}


def _poll_new_logs(state: WebState, params: dict[str, str], after: int) -> list[dict[str, Any]]:
    with state.db() as conn:
        return [_event(r) for r in query_new_logs(conn, params, after)]


async def _tail_events(state: WebState, params: dict[str, str], after: int) -> AsyncIterator[bytes]:
    state.active_streams += 1
    try:
        yield b": connected\n\n"
        last_heartbeat = time.monotonic()
        while not state.stopping:
            try:
                events = await asyncio.to_thread(_poll_new_logs, state, params, after)  # keep SQLite off the loop
            except sqlite3.Error:
                log.exception("web UI tail stream database error")
                return
            for event in events:
                payload = json.dumps(event, ensure_ascii=False).encode("utf-8")
                yield f"id: {event['id']}\ndata: ".encode("ascii") + payload + b"\n\n"
                after = event["id"]
            now = time.monotonic()
            if now - last_heartbeat >= TAIL_KEEPALIVE_SECONDS:
                yield b": keepalive\n\n"
                last_heartbeat = now
            if len(events) < 200:
                await asyncio.sleep(TAIL_POLL_SECONDS)
    finally:
        state.active_streams -= 1


@router.get(
    "/api/tail", summary="Live tail as Server-Sent Events", tags=["api"], response_class=StreamingResponse,
    responses={
        200: {"description": SSE_DESCRIPTION, "content": {"text/event-stream": {"schema": {"type": "string"}}}},
        **{k: v for k, v in _ERROR_RESPONSES.items() if k != 503},
    },
)
async def api_tail(
    request: Request,
    device: Device = None, start: Start = None, end: End = None, level: Level = None,
    type_: EventType = None, q: Text = None,
    after: Annotated[int, Query(description="Only stream events with an id greater than this (non-negative).")] = 0,
    last_event_id: Annotated[str | None, Header(description="Set by EventSource on reconnect; overrides `after`.")] = None,
) -> Response:
    try:
        cursor = int(last_event_id) if last_event_id else after
        if cursor < 0:
            raise ValueError
    except ValueError as err:
        raise BadRequest("after must be a non-negative integer") from err
    params = _filters(device, start, end, level, type_, q)
    _log_filters(params)  # validate everything before the 200 headers are sent
    return StreamingResponse(
        _tail_events(_state(request), params, cursor),
        media_type="text/event-stream; charset=utf-8",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        },
    )


# ---- application ----
class _SecurityMiddleware:
    """Allowed-Host check plus default security headers (responses may override them)."""

    def __init__(self, app, allowed_hosts: set[str]) -> None:
        self.app = app
        self.allowed_hosts = allowed_hosts

    def _host_ok(self, scope) -> bool:
        if not self.allowed_hosts:
            return True
        host = next((v.decode("latin-1") for k, v in scope["headers"] if k == b"host"), "").lower()
        host = host.rsplit(":", 1)[0] if not host.endswith("]") else host
        return host in self.allowed_hosts

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_with_headers(message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {k.lower() for k, _ in headers}
                for key, value in SECURITY_HEADERS.items():
                    if key.lower().encode() not in present:
                        headers.append((key.lower().encode(), value.encode()))
                message = {**message, "headers": headers}
            await send(message)

        if not self._host_ok(scope):
            return await PlainTextResponse("host not allowed", status_code=403)(scope, receive, send_with_headers)
        await self.app(scope, receive, send_with_headers)


def _strip_validation_errors(schema: dict[str, Any]) -> dict[str, Any]:
    """Validation failures are reported as 400 ErrorResponse, so drop FastAPI's default 422."""
    for operations in schema.get("paths", {}).values():
        for operation in operations.values():
            operation.get("responses", {}).pop("422", None)
    for name in ("HTTPValidationError", "ValidationError"):
        schema.get("components", {}).get("schemas", {}).pop(name, None)
    return schema


def create_app(state: WebState | None = None) -> FastAPI:
    """Build the application. ``state`` may be None when only the OpenAPI schema is needed."""
    app = FastAPI(
        title="ESPHome Log Collector",
        version=API_VERSION,
        description=(
            "Read-only HTTP API of the web UI. There is no authentication: bind to localhost or put an "
            "authenticated reverse proxy in front. The HTML pages, `POST /export` (CSRF-protected) and "
            "`GET /exports/{name}` downloads belong to the browser UI and are not part of this contract."
        ),
        docs_url=None, redoc_url=None, openapi_url="/openapi.json",
    )
    app.state.web = state
    app.include_router(router)
    app.add_middleware(_SecurityMiddleware, allowed_hosts=state.allowed_hosts if state else set())

    @app.exception_handler(BadRequest)
    async def bad_request(request: Request, err: BadRequest) -> Response:
        return _error(request, 400, str(err), "Bad request")

    @app.exception_handler(RequestValidationError)
    async def invalid_parameters(request: Request, err: RequestValidationError) -> Response:
        first = err.errors()[0]
        name = ".".join(str(part) for part in first["loc"][1:]) or "request"
        return _error(request, 400, f"invalid {name}: {first['msg']}", "Bad request")

    @app.exception_handler(sqlite3.Error)
    async def database_error(request: Request, err: sqlite3.Error) -> Response:
        log.error("web UI database error: %s", err)
        return _error(request, 503, "The collector database could not be read.", "Database unavailable")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, err: StarletteHTTPException) -> Response:
        if err.status_code == 405 and request.method != "POST":
            return PlainTextResponse("method not allowed", status_code=405, headers={"Allow": "GET, POST"})
        if err.status_code in (404, 405):  # POST to anything but /export has always been "not found"
            return _error(request, 404, "Not found.", "Not found")
        return _error(request, err.status_code, str(err.detail), "Error")

    original_openapi = app.openapi

    def openapi() -> dict[str, Any]:
        if app.openapi_schema is None:
            _strip_validation_errors(original_openapi())
        return app.openapi_schema

    app.openapi = openapi  # type: ignore[method-assign]
    return app


class _Server(uvicorn.Server):
    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield  # the collector owns SIGINT/SIGTERM; uvicorn must not replace those handlers


class WebServer:
    """Runs the FastAPI app with uvicorn on the collector's event loop."""

    def __init__(self, config: Config, redactor: Redactor | None = None) -> None:
        self.config = config
        self.state = WebState(config, redactor)
        self.app = create_app(self.state)
        self._server: _Server | None = None
        self._task: asyncio.Task | None = None

    @property
    def csrf_token(self) -> str:
        return self.state.csrf_token

    @property
    def port(self) -> int:
        assert self._server is not None and self._server.servers, "web server not started"
        return self._server.servers[0].sockets[0].getsockname()[1]

    async def start(self) -> None:
        web = self.config.web
        self._server = _Server(uvicorn.Config(
            self.app, host=web.bind, port=web.port, log_config=None, access_log=False, lifespan="off",
            http="h11", ws="none", server_header=False, timeout_graceful_shutdown=5,
        ))
        self._task = asyncio.create_task(self._serve(), name="web")
        while not self._server.started:
            if self._task.done():
                self._task.result()
            await asyncio.sleep(0.01)
        log.info("web UI listening on http://%s:%d", web.bind, self.port)

    async def _serve(self) -> None:
        assert self._server is not None
        try:
            await self._server.serve()
        except SystemExit as err:  # uvicorn exits the process when it cannot bind
            raise OSError(f"cannot start web UI on {self.config.web.bind}:{self.config.web.port}") from err

    async def stop(self) -> None:
        """Stop accepting connections, end tail streams and wait for in-flight requests."""
        if self._server is None or self._task is None:
            return
        self.state.stopping = True
        self._server.should_exit = True
        with contextlib.suppress(OSError):
            await self._task
