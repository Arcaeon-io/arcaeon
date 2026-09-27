# SPDX-License-Identifier: MIT
"""The HTTP server: stdlib ThreadingHTTPServer over the route table.

LOOPBACK ONLY. The server binds 127.0.0.1 and nothing else; make_server()
refuses any other host, and so does `arcaeon serve --host`. Putting it on a
network is a deploy decision, not a flag. Requests whose Host header names
anything but this loopback address are refused too (400), so a web page
elsewhere cannot reach it through a DNS name that points at 127.0.0.1.

Status codes (section 0 of the batch): 200 whenever a verdict was reached,
MATCHED, BROKEN and COULD NOT LOOK alike, with the CLI's JSON plus `exit`.
400 bad usage (not JSON, a field the route's schema refuses, a bad Host),
404 no such route (or a declared route whose handler is not built yet),
405 a known path with another method, 413 a body over MAX_BODY. A verdict
never rides in the HTTP status. A handler whose answer is exit 2 (bad usage:
a missing field, a path and content together, a kind not built) is 400
with that body. A handler that raises is COULD NOT LOOK
(exit 3) in a 200 body, naming the exception class only: the CLI's rule.

The request log goes to stderr as method, path (query string dropped) and
status. It never carries a header or a body, so a token cannot reach it.

Token auth (K005, serve/auth.py): every route but /health and /openapi.json
needs the serve.token value as a bearer token or X-Arcaeon-Token; without
it, 401. The check runs before the body is read.

Path fence (K006, serve/fence.py): every path a request names is resolved
against the served root, symlinks followed, and refused with 400 `outside
the served root` if it leaves it.

Paid lane (K012): a route with tier "paid" (and /v1/pin with remote) can
spend only if the server was started with allow_paid (`--allow-paid`) AND
ARCAEON_KEY is set. A handler reads the flag through current_server(),
never from the request body, so a request cannot grant itself the spend.

Activity journal (K015): every call that reaches a handler appends one line
to the journal `arcaeon status` reads, verb `serve:<route path>` (so
`serve:/v1/verify`), the verdict word the answer carries (else the word for
its exit code), its exit, and as target the sha256 the journal already uses
for the first path field the request named (content-in calls have none).
The open routes (/health, /openapi.json) are not journaled: a liveness probe
looked at nothing, and polling it would bury the calls status reports. A
request refused before a handler ran (401, 404, 405, 413, a schema 400) is
not a call on anything and is not journaled either. ARCAEON_JOURNAL=0 writes
nothing. A journal that cannot be written never changes a response: the
append swallows every error, and so does the call around it.

`run()` writes <ARCAEON_HOME or ~/.arcaeon>/serve.json (pid, port, url) once
the socket is bound, and removes it on a clean exit if it is still ours.
"""
from __future__ import annotations

import contextvars
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from arcaeon import verdict as V
from arcaeon.serve import DEFAULT_PORT, MAX_BODY
from arcaeon.serve import auth
from arcaeon.serve import fence as F
from arcaeon.serve import routes as R

LOOPBACK = "127.0.0.1"
REFUSE_HOST = "exposing the server is a deploy decision"
SERVE_JSON = "serve.json"
#: A too-large body up to this size is read and dropped before the 413, so a
#: client still writing its body receives the answer instead of a reset.
_DRAIN_LIMIT = 4 * MAX_BODY


#: make_server's default for `token`: load (or on first run create) serve.token.
AUTO = object()


#: The server answering the current request, for a handler that needs its
#: settings (K012's allow_paid). Set by Handler._dispatch around the call.
_CURRENT: contextvars.ContextVar = contextvars.ContextVar("arcaeon_serve_current", default=None)


def current_server():
    """The Server answering this request, or None outside a request."""
    return _CURRENT.get()


class HostRefused(ValueError):
    """A bind address other than loopback was asked for."""


def health(body: dict | None = None) -> dict:
    """GET /health: the server is up. Open (no token), no side effects."""
    return {"ok": True}


JOURNAL_PREFIX = "serve:"


def journal_call(route: R.Route, body, result) -> None:
    """One activity-journal line for an answered HTTP call (K015). Never raises."""
    if route.open:
        return
    try:
        from arcaeon import journal
        rc = result.get("exit") if isinstance(result, dict) else V.EXIT_GOOD
        if not isinstance(rc, int):
            rc = V.EXIT_GOOD
        word = result.get("verdict") if isinstance(result, dict) else None
        verb = JOURNAL_PREFIX + route.path
        if not isinstance(word, str) or not word:
            word = journal.word_for(verb, rc)
        target = None
        if isinstance(body, dict):
            target = next((body[f] for f in F.PATH_FIELDS
                           if isinstance(body.get(f), str) and body[f]), None)
        journal.append(verb, word, rc, target)
    except Exception:  # noqa: BLE001  the journal never changes a response
        pass


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, indent=1).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "arcaeon-serve"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # --- plumbing ----------------------------------------------------------
    def log_message(self, fmt, *args):  # noqa: D401  the stdlib hook
        """Silenced: log_request below writes the one line we keep."""

    def log_request(self, code="-", size="-"):
        path = urlsplit(self.path).path
        try:
            print(f"arcaeon serve: {self.command} {path} {int(code)}", file=sys.stderr,
                  flush=True)
        except (ValueError, TypeError, OSError):
            pass

    def _send(self, status: int, payload, *, content_type="application/json; charset=utf-8",
              headers: dict | None = None) -> None:
        data = payload if isinstance(payload, bytes) else (
            payload.encode("utf-8") if isinstance(payload, str) else _json_bytes(payload))
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _error(self, status: int, msg: str, **extra) -> None:
        body = {"error": msg, **extra}
        if status == 400:
            body.setdefault("exit", V.EXIT_USAGE)
        self._send(status, body)

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").strip().lower()
        port = self.server.server_address[1]
        return host in {f"127.0.0.1:{port}", f"localhost:{port}", "127.0.0.1", "localhost"}

    def _drain(self, n: int) -> None:
        left = min(n, _DRAIN_LIMIT)
        while left > 0:
            chunk = self.rfile.read(min(left, 1 << 16))
            if not chunk:
                break
            left -= len(chunk)

    def _read_body(self):
        """(body dict or None, error already sent?)."""
        raw_len = self.headers.get("Content-Length")
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            self._error(400, "send the body with a Content-Length, not chunked")
            return None, True
        if raw_len is None:
            return {}, False
        try:
            n = int(raw_len)
            if n < 0:
                raise ValueError
        except ValueError:
            self.close_connection = True
            self._error(400, "Content-Length is not a length")
            return None, True
        if n > MAX_BODY:
            self.close_connection = True
            if n <= _DRAIN_LIMIT:
                self._drain(n)
            self._send(413, {"error": f"the body is over {MAX_BODY // (1024 * 1024)} MB",
                             "limit": MAX_BODY})
            return None, True
        if n == 0:
            return {}, False
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8")), False
        except (UnicodeDecodeError, ValueError):
            self._error(400, "the body is not UTF-8 JSON")
            return None, True

    # --- dispatch -----------------------------------------------------------
    def _dispatch(self) -> None:
        path = urlsplit(self.path).path
        if not self._host_ok():
            self.close_connection = True
            self._error(400, "this server answers only on its loopback address")
            return
        route = R.find(self.command, path)
        if route is None:
            allowed = R.methods_for(path)
            if allowed:
                self._send(405, {"error": f"{self.command} is not allowed on {path}",
                                 "allow": allowed}, headers={"Allow": ", ".join(allowed)})
            else:
                self._error(404, f"no route {path}")
            return
        if not self._authorized(route):
            return
        body, sent = self._read_body() if self.command == "POST" else ({}, False)
        if sent:
            return
        problem = R.validate(route, body)
        if problem:
            self._error(400, problem)
            return
        fence = getattr(self.server, "fence", None)
        if fence is not None:
            try:
                body = fence.apply(body)
            except F.OutsideRoot as e:
                self._error(400, str(e))
                return
        try:
            fn = route.resolve()
        except (ImportError, AttributeError):
            self._error(404, f"{path} is declared but not built in this checkout")
            return
        tok = _CURRENT.set(self.server)
        try:
            result = fn(body)
        except Exception as e:  # noqa: BLE001  never a traceback, never a green
            result = {"verdict": V.COULD_NOT_LOOK, "exit": V.EXIT_COULD_NOT_LOOK,
                      "error": f"could not finish: {type(e).__name__} [internal_error]"}
        finally:
            _CURRENT.reset(tok)
        journal_call(route, body, result)
        if isinstance(result, str):
            self._send(200, result, content_type="text/html; charset=utf-8")
        elif isinstance(result, dict) and result.get("exit") == V.EXIT_USAGE:
            self._send(400, result)          # bad usage is the request, not a verdict
        else:
            self._send(200, result)

    def _authorized(self, route: R.Route) -> bool:
        """The token check (K005). True: carry on. False: a 401 was sent.
        Open routes (/health, /openapi.json) need no token. The 401 body
        names the headers to use and never echoes what was sent."""
        token = getattr(self.server, "token", None)
        if route.open or token is None:
            return True
        problem = auth.check(token, self.headers)
        if problem is None:
            return True
        self.close_connection = True          # an unread body stays unread
        self._send(401, {"error": problem},
                   headers={"WWW-Authenticate": 'Bearer realm="arcaeon"'})
        return False

    def do_GET(self):     # noqa: N802  stdlib names
        self._dispatch()

    def do_POST(self):    # noqa: N802
        self._dispatch()

    def do_PUT(self):     # noqa: N802
        self._dispatch()

    def do_DELETE(self):  # noqa: N802
        self._dispatch()

    def do_PATCH(self):   # noqa: N802
        self._dispatch()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False       # a second server on a busy port fails loud
    #: The bearer token every non-open route needs; None turns auth off
    #: (embedding and tests only; `arcaeon serve` always sets one).
    token: str | None = None
    #: The served root's path fence (K006); None: paths are not fenced.
    fence: F.Fence | None = None
    #: Started with --allow-paid (K012): the paid lane may spend when a key is set.
    allow_paid: bool = False

    @property
    def url(self) -> str:
        return f"http://{LOOPBACK}:{self.server_address[1]}"


def make_server(host: str = LOOPBACK, port: int = DEFAULT_PORT, *, token=AUTO,
                root=AUTO, allow_paid: bool = False) -> Server:
    """A bound, not yet serving, server. Any host but 127.0.0.1 is refused.

    `token`: AUTO (the default) loads serve.token, creating it on first run;
    a string uses that token; None serves without auth (tests, embedding).
    `root`: AUTO (the default) fences every request path to the current
    directory; a directory fences to that; None does not fence. A root that
    is not a directory raises NotADirectoryError.
    `allow_paid`: the second opt-in for the paid lane (K012); off by default."""
    if host != LOOPBACK:
        raise HostRefused(f"refusing --host {host}: {REFUSE_HOST}; "
                          f"arcaeon serve binds {LOOPBACK} only")
    fence = None if root is None else F.Fence(os.getcwd() if root is AUTO else root)
    tok = auth.load_or_create() if token is AUTO else token
    srv = Server((LOOPBACK, port), Handler)
    srv.token, srv.fence, srv.allow_paid = tok, fence, bool(allow_paid)
    return srv


def serve_json_path() -> Path:
    from arcaeon import journal
    return journal.home() / SERVE_JSON


def write_serve_json(server: Server) -> Path:
    p = serve_json_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps({"pid": os.getpid(), "port": server.server_address[1],
                               "url": server.url}, indent=1) + "\n", encoding="utf-8")
    os.replace(tmp, p)
    return p


def remove_serve_json() -> None:
    """Remove serve.json only if it still names this process."""
    p = serve_json_path()
    try:
        if json.loads(p.read_text(encoding="utf-8")).get("pid") == os.getpid():
            p.unlink()
    except (OSError, ValueError, AttributeError):
        pass


def run(server: Server, *, ready: threading.Event | None = None, out=None) -> None:
    """Serve until interrupted or shut down; serve.json lives exactly that long."""
    out = out or sys.stdout
    write_serve_json(server)
    try:
        print(f"arcaeon serve: listening on {server.url} (loopback only; Ctrl+C stops)",
              file=out, flush=True)
        if ready is not None:
            ready.set()
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        remove_serve_json()
