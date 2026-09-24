# SPDX-License-Identifier: MIT
"""The HTTP forward mode: the agent-side tape for an agent that talks to an HTTP MCP server.

    arcaeon-adapter --ledger seam.jsonl --tape agent.tape.jsonl \\
        --http-forward https://tools.example.com/mcp --listen 127.0.0.1:8765

Point the agent at `http://127.0.0.1:8765/` (or at the upstream's own path on
the listener) instead of at the server. Every request is forwarded to the
upstream; every answer, JSON or SSE, is relayed back; each `tools/call` gets one
seam row and one `arcaeon-tape/1` row with the SAME digests the stdio path
writes and arcaeon-receipt's `call_proxy` writes on the tool side, so
`arcaeon-ledger reconcile agent.tape tool.tape` lines them up.

The stdio seam needed nothing like this because it sits in a pipe. An HTTP MCP
client opens its own connections, so the listener is the pipe: the agent is
configured to talk to it, exactly as a stdio server is wrapped by editing one
line of config.

FIDELITY, SAME RULE AS THE PIPE
-------------------------------
Bytes are forwarded first and observed second, from a copy. For a response:

  * The status code, the reason phrase and every end-to-end header reach the
    agent as the upstream sent them, in order. Nothing is added: no `Server`,
    no `Date`, no receipt header (that is call_proxy's job on the tool side).
    Hop-by-hop headers (`Connection`, `Transfer-Encoding`, ...) belong to one
    connection and are not forwarded, as RFC 9110 requires of any proxy; nor is
    any header a `Connection` header NAMES (RFC 9110 7.6.1), in either direction.
  * The body is relayed piece by piece as it arrives, never buffered whole, so
    an SSE stream that stays open for minutes reaches the agent live. A sized
    body keeps its `Content-Length`. A body the upstream chunked, or delimited
    by closing the connection, is re-chunked to the agent: the body bytes are
    identical, only the per-connection framing is this hop's own.
  * The observer reads a copy AFTER the write. `Content-Encoding` is relayed
    untouched; the copy is decompressed (stdlib zlib) only to read the answer.
  * If the upstream cannot be reached the agent gets a plain `502`, never a
    JSON-RPC answer no server gave.

PAIRING
-------
A `tools/call` is opened when its POST is sent upstream (a batch opens each
call in order). Its answer is read from the response to that POST, as JSON, a
JSON batch, or `data:` events of `text/event-stream`, parsed the same way as
call_proxy parses them. It may also arrive later, on any other response in the
same `Mcp-Session-Id` (a GET stream, the older HTTP+SSE transport), which is
why a `202` leaves the call OPEN. Any other response that ends without the
answer (an error status, a stream that closed early, an upstream that never
answered) closes it `unanswered` then, so it does not hold every later tape
row hostage until the session ends. Calls still open when the session ends
are written `unanswered`, as on the pipe.

Ids are paired within their `Mcp-Session-Id`, FIFO: an answer pairs with the
OLDEST open call of its id, a call never overwrites another, and each call sent
gets exactly one tape row and one seam row (the rule in `observer.py`, and
call_proxy's on the tool side). Two clients without session ids sharing one
listener with colliding ids would still mis-pair between them; give each agent
its own listener.

The tape never costs a call: every observation is inside a try, failures are
counted and reported in `session_end`, and the relay goes on.

Stdlib only (`http.server`, `http.client`, `zlib`).
"""
from __future__ import annotations

import contextlib
import http.client
import os
import re
import signal
import sys
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from ._ledger import backend, open_ledger
from ._version import IMPL, VERSION
from .observer import DEFAULT_MAX_FRAME, SeamObserver
from .tape import WITNESS_KEY_ENV, TapeWriter, pin_at_session_end

__all__ = ["SEAM_HTTP", "KEEP_OPEN_STATUSES", "ForwardServer", "build_forward_server",
           "run_http_forward"]

SEAM_HTTP = "mcp-http"

#: A response with this status leaves the exchange's calls open: the answer is
#: expected on a later response in the same session (Streamable HTTP's GET
#: stream, the 2024-11-05 HTTP+SSE transport). Every other status that arrives
#: without the answer closes the call `unanswered`.
KEEP_OPEN_STATUSES = frozenset({202})

CHUNK = 65536

#: One connection's business, never forwarded (RFC 9110 7.6.1). `host` and
#: `content-length` are set by this hop for its own connection; `expect` is
#: answered by the listener itself.
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
    "trailer", "trailers", "transfer-encoding", "upgrade", "proxy-connection",
})
_NOT_FORWARDED_UP = HOP_BY_HOP | {"host", "content-length", "expect"}


def _connection_named(items) -> frozenset:
    """Header names listed in any `Connection` header, lowercased. RFC 9110
    7.6.1: a proxy removes the `Connection` header AND every header it names
    ("Connection: close, X-Secret" makes X-Secret this hop's own business)."""
    out = set()
    for k, v in items:
        if k.lower() == "connection":
            out.update(t.strip().lower() for t in (v or "").split(",") if t.strip())
    return frozenset(out)

_EOL = re.compile(rb"\r\n|\r|\n")


# -- reading answers from a copy of the response ------------------------------

class _SSEFrames:
    """Incremental `text/event-stream` parser: pieces in, event `data` out.

    Lines end in CRLF, LF or CR; a blank line dispatches the event; the `data`
    lines of one event are joined with LF, one leading space stripped
    (WHATWG). A CR at the very end of a piece is held back, since it may be the
    first half of a CRLF. At the end of the stream a last event with no
    closing blank line is still dispatched, the lenient reading call_proxy
    also takes, so both sides see the same answers.
    """

    def __init__(self, max_frame: int = DEFAULT_MAX_FRAME):
        self.max_frame = max_frame
        self._buf = b""
        self._data: list = []
        self._size = 0
        self.oversize = 0

    def _dispatch(self):
        data = b"\n".join(self._data)
        self._data, self._size = [], 0
        return data

    def _line(self, line: bytes, out: list) -> None:
        if not line:
            if self._data:
                out.append(self._dispatch())
            return
        if line.startswith(b"data:"):
            v = line[5:]
            if v.startswith(b" "):
                v = v[1:]
            self._size += len(v)
            if self._size > self.max_frame:
                self._data, self._size = [], 0
                self.oversize += 1
                return
            self._data.append(v)

    def feed(self, piece: bytes) -> list:
        out: list = []
        self._buf += piece
        pos = 0
        while True:
            m = _EOL.search(self._buf, pos)
            if m is None or (m.group() == b"\r" and m.end() == len(self._buf)):
                break
            self._line(self._buf[pos:m.start()], out)
            pos = m.end()
        self._buf = self._buf[pos:]
        if len(self._buf) > self.max_frame:      # a line with no end in sight
            self._buf = b""
            self.oversize += 1
        return out

    def close(self) -> list:
        out: list = []
        if self._buf:
            self._line(self._buf.rstrip(b"\r"), out)
            self._buf = b""
        if self._data:
            out.append(self._dispatch())
        return out


class _AnswerWatcher:
    """Reads the JSON-RPC answers out of a COPY of one response body.

    A JSON body is held (up to `max_frame`) and handed over whole at the end,
    because a JSON value is not readable until it is complete; an SSE body is
    handed over event by event, as it streams. Frames go to
    `SeamObserver.observe_server_frame`, which reads an object or a batch.
    """

    def __init__(self, content_type: str, content_encoding: str,
                 max_frame: int = DEFAULT_MAX_FRAME):
        self.sse = "text/event-stream" in (content_type or "").lower()
        enc = (content_encoding or "").strip().lower()
        # 47 = zlib or gzip header, auto-detected. Any other coding: the copy
        # stays unreadable and the call closes unanswered, which is the truth
        # about what this side could read.
        self._dec = zlib.decompressobj(47) if enc in ("gzip", "x-gzip", "deflate") else None
        self._unreadable = bool(enc) and enc != "identity" and self._dec is None
        self.max_frame = max_frame
        self._sse = _SSEFrames(max_frame) if self.sse else None
        self._buf = bytearray()
        self.oversize = 0
        self._over = False

    def _plain(self, piece: bytes) -> bytes:
        if self._dec is None:
            return piece
        try:
            return self._dec.decompress(piece)
        except zlib.error:
            self._unreadable = True
            return b""

    def feed(self, piece: bytes) -> list:
        if self._unreadable:
            return []
        data = self._plain(piece)
        if self._sse is not None:
            return self._sse.feed(data)
        if not self._over:
            self._buf += data
            if len(self._buf) > self.max_frame:
                self._buf = bytearray()
                self._over = True
                self.oversize += 1
        return []

    def close(self) -> list:
        if self._unreadable:
            return []
        if self._sse is not None:
            out = self._sse.close()
            self.oversize += self._sse.oversize
            return out
        if self._over or not self._buf.strip():
            return []
        return [bytes(self._buf)]


# -- the listener -------------------------------------------------------------

def _upstream_short(resp) -> bool:
    """True when a sized upstream body ended before its Content-Length.
    `http.client` counts `length` down as `read1` returns bytes and stops at
    the first empty read without raising, so what is left over is the shortfall."""
    return bool(resp.length)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: "ForwardServer"

    def log_message(self, fmt, *args):  # noqa: A003
        pass  # the seam log is the record

    def do_GET(self):
        self._exchange("GET")

    def do_POST(self):
        self._exchange("POST")

    def do_PUT(self):
        self._exchange("PUT")

    def do_DELETE(self):
        self._exchange("DELETE")

    def do_PATCH(self):
        self._exchange("PATCH")

    def do_OPTIONS(self):
        self._exchange("OPTIONS")

    def do_HEAD(self):
        self._exchange("HEAD")

    def _read_body(self) -> bytes:
        n = self.headers.get("Content-Length")
        if n is not None:
            n = int(n)
            return self.rfile.read(n) if n > 0 else b""
        if "chunked" in (self.headers.get("Transfer-Encoding") or "").lower():
            out = []
            while True:
                size = int(self.rfile.readline().split(b";", 1)[0].strip() or b"0", 16)
                if size == 0:
                    while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                        pass
                    return b"".join(out)
                out.append(self.rfile.read(size))
                self.rfile.read(2)
        return b""

    def _exchange(self, method: str) -> None:
        srv = self.server
        try:
            body = self._read_body()
        except (OSError, ValueError):
            self.send_error(400, "could not read request body")
            return
        scope = self.headers.get("Mcp-Session-Id") or None
        srv.count("exchanges")
        with srv.in_flight():
            self._forward(method, body, scope)

    def _forward(self, method: str, body: bytes, scope) -> None:
        srv = self.server

        conn = srv.connect()
        err = None
        try:
            conn.putrequest(method, srv.target(self.path), skip_accept_encoding=True)
            named = _connection_named(self.headers.items())
            for k, v in self.headers.items():
                if k.lower() not in _NOT_FORWARDED_UP and k.lower() not in named:
                    conn.putheader(k, v)
            if body or method in ("POST", "PUT", "PATCH"):
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body or None)
        except (OSError, http.client.HTTPException) as e:
            err = e
        # The request has crossed (or failed to cross) this side: open its calls
        # now, before waiting on the answer, so the index order is send order.
        opened = srv.observe_request(method, body, scope)
        resp = None
        if err is None:
            try:
                resp = conn.getresponse()
            except (OSError, http.client.HTTPException) as e:
                err = e
        if err is not None:
            conn.close()
            srv.count("upstream_errors")
            srv.close_calls(opened, f"upstream_error:{type(err).__name__}")
            self._bad_gateway(err)
            return
        try:
            delivered = self._relay(method, resp, scope)
        finally:
            conn.close()
        if opened and not (delivered and resp.status in srv.keep_open()):
            srv.close_calls(opened, f"no_answer_in_response:{resp.status}")

    def _bad_gateway(self, err) -> None:
        raw = f"arcaeon-adapter: upstream unreachable ({type(err).__name__})\n".encode()
        try:
            self.send_response_only(502)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        except OSError:
            pass

    def _relay(self, method: str, resp, scope) -> bool:
        """Status, headers, body to the agent; a copy of the body to the observer.
        Returns False when the agent could not be written to (it never got the
        whole answer)."""
        srv = self.server
        no_body = (method == "HEAD" or resp.status in (204, 304) or 100 <= resp.status < 200)
        corrupt = srv.corruptor()
        rechunk = not no_body and (resp.chunked or resp.length is None or corrupt is not None)
        watcher = srv.watcher(resp.getheader("Content-Type", ""),
                              resp.getheader("Content-Encoding", ""))
        try:
            self.send_response_only(resp.status, resp.reason)
            named = _connection_named(resp.getheaders())
            for k, v in resp.getheaders():
                lk = k.lower()
                if lk in HOP_BY_HOP or lk in named or (rechunk and lk == "content-length"):
                    continue
                self.send_header(k, v)
            if rechunk:
                self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
        except OSError:
            srv.count("relay_errors")
            self.close_connection = True
            return False
        ok = True
        while not no_body:
            try:
                piece = resp.read1(CHUNK)
            except (OSError, http.client.HTTPException, ValueError):
                srv.count("relay_errors")
                ok = False  # the upstream broke off; the agent's body is short
                self.close_connection = True
                break
            if not piece:
                break
            out = corrupt.feed(piece) if corrupt is not None else piece
            try:
                if out:
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(out), out) if rechunk else out)
                    self.wfile.flush()
            except OSError:
                srv.count("relay_errors")
                self.close_connection = True
                return False
            srv.observe_answers(watcher, watcher.feed, piece, scope)
        if ok and not no_body and not rechunk and _upstream_short(resp):
            # The upstream closed before its own Content-Length. The agent was
            # promised that length too: close its connection, so it sees the
            # same short body and EOF it would have seen directly, instead of
            # waiting on a keep-alive socket for bytes that will never come.
            srv.count("relay_errors")
            ok = False
            self.close_connection = True
        if corrupt is not None:
            tail = corrupt.close()
            if tail:
                try:
                    self.wfile.write(b"%x\r\n%s\r\n" % (len(tail), tail))
                except OSError:
                    pass
        if rechunk and ok:
            try:
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except OSError:
                srv.count("relay_errors")
                self.close_connection = True
                return False
        srv.observe_answers(watcher, lambda _p: watcher.close(), b"", scope)
        srv.add_oversize(watcher.oversize)
        return ok


class ForwardServer(ThreadingHTTPServer):
    """The listener plus the session it records. `close()` ends both, once."""

    daemon_threads = True
    allow_reuse_address = False
    #: Seconds `close()` waits for in-flight exchanges before ending the session.
    drain_timeout = 5.0

    def __init__(self, listen_addr, upstream: str, *, observer: SeamObserver,
                 tape, max_frame: int, upstream_timeout: float, pin_witness=None,
                 tape_path=None, tape_namespace=None, tape_pair=None):
        super().__init__(listen_addr, _Handler)
        u = urlsplit(upstream)
        self.upstream_scheme = u.scheme
        self.upstream_host = u.hostname
        self.upstream_port = u.port or (443 if u.scheme == "https" else 80)
        self.upstream_path = u.path or ""
        self.upstream_query = u.query
        self.upstream_timeout = upstream_timeout
        self.observer = observer
        self.tape = tape
        self.max_frame = max_frame
        self._pin = (pin_witness, tape_path, tape_namespace, tape_pair)
        self._lock = threading.Lock()
        self._counts = {"exchanges": 0, "upstream_errors": 0, "relay_errors": 0,
                        "observe_failures": 0, "oversize": 0}
        self._ended = None
        self._closing = False
        self._serving = None
        self._idle = threading.Condition(self._lock)
        self._inflight = 0
        self._fault = os.environ.get(_fault_env())

    # -- helpers the handler calls ---------------------------------------

    @property
    def port(self) -> int:
        return self.server_address[1]

    @property
    def url(self) -> str:
        return f"http://{self.server_address[0]}:{self.server_address[1]}"

    def count(self, name: str, n: int = 1) -> None:
        with self._lock:
            self._counts[name] += n

    def add_oversize(self, n: int) -> None:
        if n:
            self.count("oversize", n)

    @contextlib.contextmanager
    def in_flight(self):
        """One exchange being forwarded and observed. `close()` waits (bounded)
        for these to finish, so an answer the agent already has is on the tape
        before the session is closed behind it."""
        with self._lock:
            self._inflight += 1
        try:
            yield
        finally:
            with self._lock:
                self._inflight -= 1
                self._idle.notify_all()

    def keep_open(self):
        return KEEP_OPEN_STATUSES

    def connect(self):
        cls = http.client.HTTPSConnection if self.upstream_scheme == "https" \
            else http.client.HTTPConnection
        return cls(self.upstream_host, self.upstream_port, timeout=self.upstream_timeout)

    def target(self, path: str) -> str:
        """The upstream request target. The listener mirrors the upstream origin;
        a request to `/` goes to the upstream URL's own path (and query)."""
        bare, _, query = path.partition("?")
        if bare in ("", "/") and self.upstream_path not in ("", "/"):
            q = query or self.upstream_query
            return self.upstream_path + (f"?{q}" if q else "")
        return path or "/"

    def watcher(self, ctype: str, enc: str):
        return _AnswerWatcher(ctype, enc, self.max_frame)

    def corruptor(self):
        if not self._fault:
            return None
        from .proxy import _Corruptor
        return _Corruptor(self._fault)

    def observe_request(self, method: str, body: bytes, scope) -> list:
        if method != "POST" or not body or self._ended is not None:
            return []
        if len(body) > self.max_frame:
            self.count("oversize")
            return []
        try:
            return self.observer.observe_client_frame(body, scope) or []
        except Exception:
            self.count("observe_failures")
            return []

    def observe_answers(self, watcher, step, piece: bytes, scope) -> None:
        if self._ended is not None:
            return
        try:
            frames = step(piece)
        except Exception:
            self.count("observe_failures")
            return
        for frame in frames:
            try:
                self.observer.observe_server_frame(frame, scope)
            except Exception:
                self.count("observe_failures")

    def close_calls(self, handles: list, reason: str) -> None:
        if not handles or self._ended is not None:
            return
        try:
            self.observer.close_unanswered(handles, reason=reason)
        except Exception:
            self.count("observe_failures")

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> "ForwardServer":
        """Serve on a background thread (tests, embedding). The CLI serves in
        the main thread through `run_http_forward`."""
        t = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.1},
                             name="arcaeon-http-forward", daemon=True)
        self._serving = t
        t.start()
        return self

    def close(self, reason: str = "shutdown") -> dict:
        """Stop listening, end the session, pin if asked. Idempotent: the
        second call returns the first call's `session_end` row."""
        with self._lock:
            if self._closing:
                return self._ended or {}
            self._closing = True
        if self._serving is not None:
            self.shutdown()
        self.server_close()
        with self._lock:
            # Exchanges already accepted finish (their answers were relayed, so
            # they belong on the tape). A stream that stays open past the drain
            # window is cut off here: its calls are flushed `unanswered` below.
            self._idle.wait_for(lambda: self._inflight == 0, timeout=self.drain_timeout)
            self._ended = {}
        obs, tape = self.observer, self.tape
        orphans = obs.flush_pending(reason=f"session_ended:{reason}")
        tape_pin = None
        if tape is not None:
            tape.flush()
            witness, tape_path, ns, pair = self._pin
            if witness:
                tape_pin = pin_at_session_end(tape_path, witness_url=witness,
                                              key=os.environ.get(WITNESS_KEY_ENV),
                                              namespace=ns, pair=pair)
        c = dict(self._counts)
        end = obs.session_end(
            reason=reason, exit_code=None, unanswered=orphans or None,
            exchanges=c["exchanges"], upstream_errors=c["upstream_errors"] or None,
            relay_errors=c["relay_errors"] or None,
            observe_failures=c["observe_failures"] or None,
            oversize_frames_unlogged=c["oversize"] or None,
            tape_calls=tape.calls if tape else None,
            tape_failures=(obs.tape_failures + tape.write_failures) or None
            if tape else None,
            tape_pin=tape_pin)
        self._ended = end
        return end


def _fault_env() -> str:
    from .proxy import FAULT_ENV
    return FAULT_ENV


def _parse_listen(listen: str):
    host, sep, port = (listen or "").rpartition(":")
    if not sep or not port.isdigit():
        raise ValueError(f"--listen wants HOST:PORT, not {listen!r}")
    return (host.strip("[]") or "127.0.0.1", int(port))


def check_upstream(upstream: str) -> None:
    u = urlsplit(upstream or "")
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError(f"--http-forward wants an http:// or https:// URL, not {upstream!r}")


def _label(upstream: str) -> str:
    u = urlsplit(upstream)
    return f"{u.hostname}:{u.port or (443 if u.scheme == 'https' else 80)}{u.path or '/'}"


def build_forward_server(upstream: str, listen: str = "127.0.0.1:0", *, ledger_path,
                         tape_path=None, side: str = "agent", tape_namespace=None,
                         server: str | None = None, session: str | None = None,
                         raw: bool = False, max_frame: int = DEFAULT_MAX_FRAME,
                         upstream_timeout: float = 300.0, pin_witness=None,
                         tape_pair=None) -> ForwardServer:
    """Bind the listener, open the seam log and the tape, write `session_begin`.
    Raises ValueError on a bad URL or listen address and OSError when the
    address cannot be bound, before anything is written."""
    from .proxy import _redact_argv, _digest
    check_upstream(upstream)
    addr = _parse_listen(listen)
    log = open_ledger(ledger_path)
    tape = TapeWriter(tape_path, side=side, namespace=tape_namespace) if tape_path else None
    obs = SeamObserver(log.append, server=server or _label(upstream), session=session,
                       raw=raw, impl=IMPL, tape=tape, seam=SEAM_HTTP)
    srv = ForwardServer(addr, upstream, observer=obs, tape=tape, max_frame=max_frame,
                        upstream_timeout=upstream_timeout, pin_witness=pin_witness,
                        tape_path=tape_path, tape_namespace=tape_namespace,
                        tape_pair=tape_pair)
    safe, redactions = _redact_argv([upstream])
    obs.session_begin(
        adapter_version=VERSION, ledger_backend=backend(), transport="http-forward",
        upstream=safe[0], command_redactions=redactions or None,
        upstream_digest=_digest(upstream), listen=srv.url, cwd=os.getcwd(), pid=os.getpid(),
        raw_payloads=raw, fault_injected=srv._fault or None,
        tape=str(tape_path) if tape else None, tape_side=side if tape else None,
        tape_namespace=tape_namespace if tape else None)
    if srv._fault:
        sys.stderr.write(f"arcaeon-adapter: WARNING {_fault_env()}={srv._fault} is set; "
                         f"this process is DELIBERATELY CORRUPTING relayed bytes. "
                         f"Test harness only.\n")
    return srv


def run_http_forward(upstream: str, listen: str, ledger_path, **kw) -> int:
    """The CLI's HTTP forward mode: serve until interrupted (Ctrl+C, SIGTERM,
    Ctrl+Break), then end the session. Exit 0 on a clean stop, 1 when the
    listener could not start (that attempt is still bracketed in the seam log)."""
    try:
        srv = build_forward_server(upstream, listen, ledger_path=ledger_path, **kw)
    except OSError as e:
        from .proxy import _redact_argv
        sys.stderr.write(f"arcaeon-adapter: cannot listen on {listen}: {e}\n")
        obs = SeamObserver(open_ledger(ledger_path).append, server=_label(upstream),
                           session=kw.get("session"), impl=IMPL, seam=SEAM_HTTP)
        obs.session_begin(adapter_version=VERSION, ledger_backend=backend(),
                          transport="http-forward", upstream=_redact_argv([upstream])[0][0],
                          listen=listen, pid=os.getpid())
        obs.session_end(reason="listen_failed", exit_code=1, error=str(e)[:300])
        return 1
    if srv.server_address[0] not in ("127.0.0.1", "::1", "localhost"):
        sys.stderr.write("arcaeon-adapter: WARNING the listener is not on loopback; anyone "
                         "who can reach it can call the upstream through it.\n")

    def interrupt(signum, frame):
        raise KeyboardInterrupt

    for name in ("SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, interrupt)
            except (ValueError, OSError):
                pass  # not the main thread: Ctrl+C still works
    safe = kw.get("server") or _label(upstream)
    sys.stderr.write(f"arcaeon-adapter: http-forward listening on {srv.url} -> {safe}\n")
    sys.stderr.flush()
    reason = "shutdown"
    try:
        srv.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        reason = "interrupt"
    finally:
        srv.close(reason)
    return 0
