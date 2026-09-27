# SPDX-License-Identifier: MIT
"""The local dashboard (K100): pages for a person, served by `arcaeon serve`.

A browser cannot send the bearer token an agent sends, so the dashboard signs
a browser in with a one-time code instead:

1. A caller holding serve.token asks for a code: `POST /session/code` with
   `Authorization: Bearer <token>` (or `X-Arcaeon-Token`) answers
   `{"code", "url", "expires_in", "exit": 0}`. `arcaeon open` (K107) does this
   and prints or opens the url. In the same process, `issue_code(server)`.
2. `GET /?t=<code>` exchanges the code, once, for a session cookie
   (`arcaeon_session`, HttpOnly, SameSite=Strict, Path=/) and redirects to `/`
   so the code leaves the address bar. The code is single-use and expires
   after CODE_TTL seconds; a second use, or a late one, is 401.
3. Every page and static file then needs that cookie or the bearer token.
   Without either it is 401 with a page saying how to get a fresh link.

Every page answer carries `Content-Security-Policy: default-src 'self'` (plus
no framing, forms to this origin only, no base tag), so a page loads nothing
from anywhere else: no CDN, no external font, no external fetch.

Pages are server-rendered HTML (arcaeon.serve.pages), so they read without
JavaScript; static/app.js only adds small conveniences. A page that reads a
file goes through the server's own fence (serve/fence.py) and the same handler
core the JSON routes use, and journals its call as that route does (K015).

Mounting. DashboardHandler answers the page paths ahead of the route table
and hands every other path to the server's own Handler unchanged. `mount(srv)`
switches a server made by `server.make_server` over to it.
"""
from __future__ import annotations

import importlib
import secrets
import threading
import time
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from arcaeon.serve import MAX_BODY, auth
from arcaeon.serve import server as S

STATIC = Path(__file__).resolve().parent / "static"
STATIC_PREFIX = "/static/"
#: Files served from static/ by name; nothing else under it is reachable.
STATIC_FILES = {"placeholder.css": "text/css; charset=utf-8",
                "app.js": "text/javascript; charset=utf-8"}

COOKIE = "arcaeon_session"
CODE_PATH = "/session/code"
#: Seconds a one-time code stays good.
CODE_TTL = 120
#: Seconds a browser session stays good.
SESSION_TTL = 12 * 3600

CSP = ("default-src 'self'; base-uri 'none'; form-action 'self'; "
       "frame-ancestors 'none'")
PAGE_HEADERS = {"Content-Security-Policy": CSP, "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer"}

#: Page path -> the module that renders it (`render(req) -> (status, html)`,
#: plus METHODS, the methods it answers). Imported on first use.
PAGES = {
    "/": "arcaeon.serve.pages.home",
    "/status": "arcaeon.serve.pages.status",
    "/verify": "arcaeon.serve.pages.verify",
}

#: The clock codes and sessions are timed by (tests move it).
_now = time.monotonic
_LOCK = threading.Lock()


class Sessions:
    """One-time codes and the browser sessions they became. Thread-safe."""

    def __init__(self):
        self._codes: dict[str, float] = {}
        self._sessions: dict[str, float] = {}
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        for d in (self._codes, self._sessions):
            for k in [k for k, exp in d.items() if exp < now]:
                del d[k]

    def issue_code(self) -> str:
        code = secrets.token_urlsafe(32)
        with self._lock:
            now = _now()
            self._prune(now)
            self._codes[code] = now + CODE_TTL
        return code

    def redeem(self, code: str) -> str | None:
        """A new session id for a good code (the code is spent), else None."""
        with self._lock:
            now = _now()
            exp = self._codes.pop(code, None)
            if exp is None or exp < now:
                return None
            sid = secrets.token_urlsafe(32)
            self._sessions[sid] = now + SESSION_TTL
            return sid

    def valid(self, sid: str | None) -> bool:
        if not sid:
            return False
        with self._lock:
            exp = self._sessions.get(sid)
            if exp is None:
                return False
            if exp < _now():
                del self._sessions[sid]
                return False
            return True


def sessions(server) -> Sessions:
    """The server's session store, made on first use."""
    with _LOCK:
        s = getattr(server, "dashboard_sessions", None)
        if s is None:
            s = Sessions()
            server.dashboard_sessions = s
        return s


def issue_code(server) -> str:
    """A fresh one-time code for this server (in-process `arcaeon open`)."""
    return sessions(server).issue_code()


@dataclass
class PageRequest:
    """What a page renderer gets: never the headers, never the token."""
    method: str
    path: str
    server: object
    query: dict = field(default_factory=dict)
    form: dict = field(default_factory=dict)

    @property
    def fence(self):
        return getattr(self.server, "fence", None)


def _last(d: dict) -> dict:
    return {k: v[-1] for k, v in d.items() if v}


def _common():
    from arcaeon.serve.pages import common
    return common


class DashboardHandler(S.Handler):
    """The server's Handler, with the dashboard's pages in front of it."""

    def _dispatch(self) -> None:
        split = urlsplit(self.path)
        path = split.path
        if not (path in PAGES or path == CODE_PATH or path.startswith(STATIC_PREFIX)):
            super()._dispatch()
            return
        if not self._host_ok():
            self.close_connection = True
            self._error(400, "this server answers only on its loopback address")
            return
        if path == CODE_PATH:
            self._mint()
            return
        query = parse_qs(split.query, keep_blank_values=True)
        if path == "/" and "t" in query and self.command == "GET":
            self._redeem(query["t"][-1])
            return
        if not self._page_authorized():
            self.close_connection = True          # an unread form stays unread
            self._page(401, _common().unauthorized())
            return
        if path.startswith(STATIC_PREFIX):
            self._static(path[len(STATIC_PREFIX):])
            return
        mod = importlib.import_module(PAGES[path])
        methods = getattr(mod, "METHODS", ("GET",))
        if self.command not in methods:
            self.close_connection = True
            self._page(405, _common().simple_page(
                "Not here", f"{self.command} is not answered on this page."),
                headers={"Allow": ", ".join(methods)})
            return
        form: dict = {}
        if self.command == "POST":
            got = self._read_form()
            if got is None:
                return
            form = got
        req = PageRequest(self.command, path, self.server, _last(query), form)
        try:
            status, html = mod.render(req)
        except Exception as e:  # noqa: BLE001  never a traceback, never a green
            status, html = 200, _common().could_not_finish(type(e).__name__)
        self._page(status, html)

    # --- session -------------------------------------------------------------
    def _cookie_sid(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            c = SimpleCookie(raw)
        except CookieError:
            return None
        m = c.get(COOKIE)
        return m.value if m is not None else None

    def _page_authorized(self) -> bool:
        token = getattr(self.server, "token", None)
        if token is None:
            return True
        if auth.presented(self.headers) is not None:
            return auth.check(token, self.headers) is None
        return sessions(self.server).valid(self._cookie_sid())

    def _redeem(self, code: str) -> None:
        sid = sessions(self.server).redeem(code)
        if sid is None:
            self._page(401, _common().unauthorized(used=True))
            return
        cookie = (f"{COOKIE}={sid}; Path=/; HttpOnly; SameSite=Strict; "
                  f"Max-Age={SESSION_TTL}")
        self._page(303, _common().simple_page(
            "Signed in", 'Signed in. <a href="/">Open the dashboard</a>.'),
            headers={"Location": "/", "Set-Cookie": cookie})

    def _mint(self) -> None:
        if self.command != "POST":
            self._send(405, {"error": f"{self.command} is not allowed on {CODE_PATH}",
                             "allow": ["POST"]}, headers={"Allow": "POST"})
            return
        token = getattr(self.server, "token", None)
        if token is not None:
            problem = auth.check(token, self.headers)
            if problem is not None:
                self.close_connection = True
                self._send(401, {"error": problem},
                           headers={"WWW-Authenticate": 'Bearer realm="arcaeon"'})
                return
        _body, sent = self._read_body()
        if sent:
            return
        code = issue_code(self.server)
        self._send(200, {"code": code, "url": f"{self.server.url}/?t={code}",
                         "expires_in": CODE_TTL, "exit": 0})

    # --- plumbing ------------------------------------------------------------
    def _page(self, status: int, html: str, *, headers: dict | None = None) -> None:
        self._send(status, html, content_type="text/html; charset=utf-8",
                   headers={**PAGE_HEADERS, **(headers or {})})

    def _static(self, name: str) -> None:
        ctype = STATIC_FILES.get(name)
        if ctype is None:
            self._page(404, _common().simple_page("Not found", "No such file."))
            return
        self._send(200, (STATIC / name).read_bytes(), content_type=ctype,
                   headers=PAGE_HEADERS)

    def _read_form(self) -> dict | None:
        """The POSTed form as {name: last value}, or None (an answer was sent)."""
        common = _common()
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            self._page(400, common.simple_page("Not read", "Send the form with a length."))
            return None
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n < 0:
                raise ValueError
        except ValueError:
            self.close_connection = True
            self._page(400, common.simple_page("Not read", "The form length is not a length."))
            return None
        if n > MAX_BODY:
            self.close_connection = True
            self._page(413, common.simple_page(
                "Too large", f"The form is over {MAX_BODY // (1024 * 1024)} MB."))
            return None
        raw = self.rfile.read(n) if n else b""
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if raw and ctype != "application/x-www-form-urlencoded":
            self._page(400, common.simple_page("Not read", "Send the page's own form."))
            return None
        try:
            parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True,
                              max_num_fields=64)
        except (UnicodeDecodeError, ValueError):
            self._page(400, common.simple_page("Not read", "The form is not UTF-8."))
            return None
        return _last(parsed)


def mount(server):
    """Answer the dashboard's pages on `server` (made by server.make_server)."""
    server.RequestHandlerClass = DashboardHandler
    sessions(server)
    return server


def make_dashboard_server(*args, **kwargs):
    """server.make_server(...) with the dashboard mounted."""
    return mount(S.make_server(*args, **kwargs))


def index(body: dict | None = None) -> str:
    """GET / from the route table (a bearer-token caller on an unmounted
    server): the home page's HTML."""
    from arcaeon.serve.pages import home
    return home.page()


__all__ = ["CODE_PATH", "CODE_TTL", "COOKIE", "CSP", "PAGES", "SESSION_TTL",
           "DashboardHandler", "PageRequest", "Sessions", "index", "issue_code",
           "make_dashboard_server", "mount", "sessions"]
