"""arcaeon_receipt.call_proxy: a reverse proxy that issues a Receipted-Call
receipt for every request it forwards, without the seller's application
code doing anything.

    python -m arcaeon.record.receipt.call_proxy --listen 127.0.0.1:8402 \
        --upstream http://127.0.0.1:9000 --seller acme --ledger calls.log.jsonl

Put this in front of the real service (the thing a buyer pays to call over
x402 or a kin protocol) so the seller cannot ship the receipt selectively:
every request that reaches the upstream, and every response that comes back,
gets one `call.call_receipt(...)` row, whether the handler behind it
cooperates or not. Same shape of argument as arcaeon-adapter's stdio seam
(`arcaeon_adapter/proxy.py`): sit in the pipe the traffic already has to
cross, in a process the seller's own handler code doesn't own.

BYTE FIDELITY, WITH ONE STRUCTURAL DIFFERENCE FROM THE STDIO SEAM
------------------------------------------------------------------
The stdio adapter can write bytes downstream and observe a copy of the same
chunk without waiting for more, because a stdio frame is not modified by
being watched. An HTTP response is different: `call_receipt` digests the
COMPLETE response body, and the receipt digest goes into a header this
proxy adds to the response it sends the client -- and HTTP headers must be
sent before the body. So the response is read to completion from the
upstream, the receipt is built, and only then is anything written to the
client. What "byte-for-byte" means here is narrower and still real: the
status line, every non-hop-by-hop header, and the body reach the client
unmodified -- no re-serialization, no re-encoding, no text-mode translation
-- just not incrementally while still arriving. Chunked transfer-encoding
from the upstream is decoded by `http.client` and re-sent to the client as
a plain `Content-Length` body of the identical bytes; the alternative
(re-chunking to preserve the wire encoding) would not change a single byte
the caller sees and was not worth the complexity.

WHAT IT WRITES
--------------
One `call.call_receipt(...)` receipt per request/response pair, to
`--ledger`. Digests only by default (`call.py`'s own contract): request
body, response body and any payment header are hashed, never stored, unless
`--raw-payloads` is passed -- and that flag prints a loud warning to stderr
at startup, because it is a data-retention decision the seller must own,
not a default. `anchor` is always off here; one OTS stamp per call is the
wrong cadence for a $0.30 request, and `core.py`'s `witness` pin over the
ledger head is what a buyer actually needs day to day (batch-anchoring the
ledger head is a separate, periodic job, not this proxy's).

Two response headers are added on every call, success or failure:
`X-Arcaeon-Receipt: <body_digest>` and
`X-Arcaeon-Receipt-URL: /_arcaeon/receipt/<body_digest>` -- the receipt's
OWN digest (from `core.build_receipt`), not the response body's, so a buyer
who just paid for the call can pull the whole receipt back over the same
connection class. `GET /_arcaeon/receipt/<body_digest>` serves it from an
in-memory LRU (last 1000) backed by `--receipts-dir` (one JSON file per
receipt, named by the hex TAIL of the digest -- the digest string itself
contains colons, which is not a legal filename on Windows). `GET
/_arcaeon/health` reports the ledger's row count and chain head.

UPSTREAM CONNECTION FAILURE
----------------------------
A seller's upstream dying is exactly the kind of thing a buyer needs
proof of, one way or the other -- so a connection failure is still
receipted, not just answered with a bare 502. `call.call_receipt`'s public
signature has no slot for a transport-level failure note, though, so that
one path (`_build_call_receipt` below, `upstream_error=...`) builds the
check locally from `call.py`'s own exported KIND/SCOPE/digest-helpers
instead of calling `call.call_receipt` -- everything else about the
receipt (shape, scope statement, ledger row, witness pin) is identical to
what that function would have produced. See the accompanying report for
the small addition to `call.call_receipt` (an optional `error=` kwarg)
that would let this proxy call the public function unconditionally
instead of partially reimplementing it for one branch.

THE TOOL-SIDE TAPE (`--tape`, completeness slice 2)
---------------------------------------------------
With `--tape PATH`, this proxy also keeps the TOOL side's call tape
(`arcaeon-tape/1`): one row per MCP `tools/call` it forwards, with the digest
of the request and of the answer as this side saw them. It is the same writer
(`arcaeon_adapter.tape.TapeWriter`) and the same digests as the agent-side
tape the arcaeon-adapter keeps, so `arcaeon-ledger reconcile agent.tape
tool.tape` can say MATCHED n of n, MISSING at k, ALTERED at k, or COULD NOT
LOOK. Two calls, one on each side of `_forward()` in `_proxy()`:
`open_call()` when a JSON-RPC `tools/call` request body arrives (a batch opens
one per call, in order), `close_call()` with the matching answer by JSON-RPC
id, read from an `application/json` or `text/event-stream` body (a gzip or
deflate `Content-Encoding` is undone on a copy first; the caller still gets
the encoded bytes). A `202` leaves the call OPEN: its answer may come later
on another response in the same `Mcp-Session-Id` (the GET stream), and that
answer closes it with the real response digest. Any other response without
the answer (an error, an unreadable body, an upstream that never answered)
closes it `unanswered` then, never guessed; a call still open when the proxy
stops is written `unanswered` then. This is the arcaeon-adapter's HTTP
forward rule, so the two tapes agree. Because this proxy reads each response
whole before relaying it (see BYTE FIDELITY above), a GET stream's answers
reach the tape, and the caller, when that stream's response ends. Non-MCP
traffic is not on the tape. A `tools/call` whose id is not a string, number
or null (JSON-RPC 2.0; e.g. `true`) is invalid but was still sent: it is
taped at once with status `invalid_id` and no answer, and no answer is ever
paired to it, the adapter's rule too, so both tapes agree on it.

The writer is imported, not vendored: it lives in the arcaeon-ledger repo
(the `arcaeon-adapter` package, stdlib only). When it is not installed the
proxy still forwards every call and writes every receipt; `/_arcaeon/health`
reports `tape: {"on": false, "reason": ...}` and startup says so on stderr.
A tape failure never costs a call or its receipt; failures are counted in
health. A missing tool tape then reads COULD NOT LOOK in reconcile, which is
the truth.

Stdlib only, plus arcaeon-receipt and arcaeon-ledger (already required by
`call.py`). No third-party HTTP library. The tape needs `arcaeon-adapter`
(optional; see above).
"""
from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import threading
import time
import zlib
from collections import OrderedDict
from http.client import HTTPConnection, HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, urlsplit

from arcaeon.record.ledger import Ledger, verify_file

from . import call
from .core import build_receipt

__all__ = ["main", "build_server", "CallProxyHandler", "ReceiptStore"]

#: RFC 7230 6.1 hop-by-hop headers -- never forwarded either direction. A
#: reverse proxy terminates and re-establishes the connection on each side,
#: so these describe THIS hop, not the one on the other side of us.
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade",
})

RECEIPT_PATH_PREFIX = "/_arcaeon/receipt/"
HEALTH_PATH = "/_arcaeon/health"

LRU_MAX = 1000


# --------------------------------------------------------------------------
# receipt store: in-memory LRU + optional on-disk directory
# --------------------------------------------------------------------------

class ReceiptStore:
    """Last-1000 in-memory LRU, optionally backed by one JSON file per
    receipt on disk, so a buyer can fetch the receipt for a call they just
    paid for even after 1000 more calls happened. Thread-safe: many worker
    threads in ThreadingHTTPServer read and write this concurrently."""

    def __init__(self, receipts_dir: Optional[str | Path] = None, maxsize: int = LRU_MAX):
        self._lock = threading.Lock()
        self._lru: "OrderedDict[str, dict]" = OrderedDict()
        self._maxsize = maxsize
        self.dir = Path(receipts_dir) if receipts_dir else None
        if self.dir is not None:
            self.dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _hex_tail(digest: str) -> str:
        """The hex half of a self-describing digest string
        (`sha256:json-c14n:1:<hex>`) -- the part that is a legal filename
        on every platform, including Windows, where the digest's own colons
        are not."""
        return digest.rsplit(":", 1)[-1]

    def put(self, digest: str, receipt: dict) -> None:
        with self._lock:
            self._lru[digest] = receipt
            self._lru.move_to_end(digest)
            while len(self._lru) > self._maxsize:
                self._lru.popitem(last=False)
        if self.dir is not None:
            path = self.dir / f"{self._hex_tail(digest)}.json"
            path.write_text(json.dumps(receipt, ensure_ascii=False), encoding="utf-8")

    def get(self, digest: str) -> Optional[dict]:
        # The digest arrives from a URL path. The body_digest equality check
        # below already refuses a wrong file, but the filename must never be
        # built from anything but a 64-hex tail: no traversal, no surprises.
        if not re.fullmatch(r"[0-9a-f]{64}", self._hex_tail(digest) or ""):
            return None
        with self._lock:
            rc = self._lru.get(digest)
            if rc is not None:
                self._lru.move_to_end(digest)
                return rc
        if self.dir is None:
            return None
        path = self.dir / f"{self._hex_tail(digest)}.json"
        if not path.exists():
            return None
        try:
            rc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if rc.get("body_digest") != digest:
            return None  # hex-tail collision guard: wrong receipt under this filename
        with self._lock:
            self._lru[digest] = rc
            self._lru.move_to_end(digest)
            while len(self._lru) > self._maxsize:
                self._lru.popitem(last=False)
        return rc


# --------------------------------------------------------------------------
# receipt building (the normal path delegates to call.call_receipt; the
# upstream-failure path cannot, see module docstring)
# --------------------------------------------------------------------------

def _build_call_receipt(request: dict, response: dict, *, ledger_path, namespace: str,
                        seller: str, elapsed_ms: int, raw_payloads: bool, witness: bool,
                        upstream_error: Optional[str] = None) -> dict:
    if upstream_error is None:
        return call.call_receipt(request, response, ledger_path=ledger_path, namespace=namespace,
                                 seller=seller, elapsed_ms=elapsed_ms, raw_payloads=raw_payloads,
                                 witness=witness, anchor=False)
    pay = call._payment_header(request.get("headers"))
    check = {"method": request.get("method", "GET"), "url": request.get("url", ""),
             "request_digest": call._digest_any(request.get("body")),
             "response_status": response.get("status"),
             "response_digest": call._digest_any(response.get("body")),
             "payment_header_digest": call._digest_any(pay) if pay is not None else None,
             "elapsed_ms": elapsed_ms,
             "upstream_error": upstream_error}
    if raw_payloads:
        check["request_body"] = request.get("body")
        check["response_body"] = response.get("body")
    subject = {"seller": seller or "(unnamed)", "endpoint": request.get("url", ""),
               "raw_payloads": raw_payloads}
    return build_receipt(call.KIND, subject, [check], call.SCOPE, ledger_path=ledger_path,
                         namespace=namespace, witness=witness, anchor=False)


# --------------------------------------------------------------------------
# the tool-side tape (see module docstring, "THE TOOL-SIDE TAPE")
# --------------------------------------------------------------------------

def _load_tape_writer():
    """(TapeWriter class, None) when the writer is installed, else (None, why).

    Lazy on purpose: the proxy must start, forward and receipt without it."""
    try:
        from arcaeon.record.adapter.tape import TapeWriter
    except Exception as e:  # ImportError, or a broken install: either way, no tape
        return None, f"{type(e).__name__}: {e}"
    return TapeWriter, None


def _valid_rpc_id(rpc_id) -> bool:
    """JSON-RPC 2.0: an id is a string, a number, or null. `bool` is excluded
    explicitly because Python's `True` is an `int`. The SAME predicate as the
    arcaeon-adapter's `tape.valid_rpc_id` (kept here, not imported, because the
    tape writer is optional); keep them identical."""
    if isinstance(rpc_id, bool):
        return False
    return rpc_id is None or isinstance(rpc_id, (str, int, float))


def _render_invalid_id(rpc_id) -> str:
    """An invalid id as compact JSON (the adapter's `render_invalid_id`)."""
    try:
        text = json.dumps(rpc_id, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError, RecursionError):
        text = f"<{type(rpc_id).__name__}>"
    return text if len(text) <= 200 else text[:197] + "..."


def _tape_calls(body: bytes) -> list:
    """The `tools/call` requests in a JSON-RPC body, in order: [(id, params)].
    Notifications (no id) are not calls anyone waits on; anything else, or a
    body that is not JSON, yields nothing."""
    try:
        msg = json.loads(body)
    except (ValueError, RecursionError, UnicodeDecodeError):
        return []
    out = []
    for m in (msg if isinstance(msg, list) else [msg]):
        if isinstance(m, dict) and m.get("method") == "tools/call" and m.get("id") is not None:
            out.append((m.get("id"), m.get("params")))
    return out


#: A response with this status leaves its calls OPEN on the tape: the answer is
#: expected later, on another response in the same `Mcp-Session-Id` (the GET
#: stream of Streamable HTTP, the older HTTP+SSE transport). Same rule as the
#: arcaeon-adapter's HTTP forward mode (`KEEP_OPEN_STATUSES` there), so the two
#: tapes agree. Every other response without the answer closes it `unanswered`.
KEEP_OPEN_STATUSES = frozenset({202})


def _decoded(body: bytes, header_items):
    """The body as the JSON-RPC layer wrote it: gzip/deflate undone, on a COPY.
    The caller still gets the encoded bytes untouched. None when the coding is
    one this side cannot read (the answer then goes unanswered, which is the
    truth about what this side could see), as the adapter does."""
    enc = ""
    for k, v in header_items or []:
        if k.lower() == "content-encoding":
            enc = v.strip().lower()
    if enc in ("", "identity"):
        return body
    if enc not in ("gzip", "x-gzip", "deflate"):
        return None
    try:
        d = zlib.decompressobj(47)  # 47: zlib or gzip header, auto-detected
        return d.decompress(body) + d.flush()
    except zlib.error:
        return None


def _tape_answers(body: bytes, header_items) -> list:
    """JSON-RPC answers in a response body, IN ORDER, as [(id key, answer)].
    Every answer, duplicates included: a batch that reuses an id carries one
    answer per call, and each pairs with its own call (FIFO, see `_ToolTape`).
    Reads a JSON object, a JSON batch, or the `data:` events of a
    `text/event-stream` body, after undoing a gzip/deflate Content-Encoding on
    a copy."""
    ctype = ""
    for k, v in header_items or []:
        if k.lower() == "content-type":
            ctype = v.lower()
    body = _decoded(body, header_items)
    if body is None:
        return []
    try:
        text = body.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return []
    msgs = []
    if "text/event-stream" in ctype:
        for event in re.split(r"\r?\n\r?\n", text):
            data = "\n".join(ln[5:].lstrip(" ") for ln in re.split(r"\r?\n", event)
                             if ln.startswith("data:"))
            if data:
                try:
                    msgs.append(json.loads(data))
                except (ValueError, RecursionError):
                    continue
    else:
        try:
            msgs.append(json.loads(text))
        except (ValueError, RecursionError):
            return []
    out = []
    for m in msgs:
        for a in (m if isinstance(m, list) else [m]):
            if isinstance(a, dict) and ("result" in a or "error" in a) and \
                    a.get("id") is not None and _valid_rpc_id(a.get("id")):
                out.append((_id_key(a.get("id")), a))
    return out


def _id_key(rpc_id):
    return json.dumps(rpc_id, sort_keys=True)


class _ToolTape:
    """The two calls around `_forward()`. Never raises into the request path.

    PAIRING, the same rule as the arcaeon-adapter's `SeamObserver` so the two
    tapes agree: open calls are queued per (`Mcp-Session-Id`, id) in send
    order; an answer pairs with the OLDEST open call of its id, whether that
    call was sent in this exchange or left open by an earlier 202; a call never
    overwrites another; every sent call gets exactly one tape row; a call still
    unpaired when the proxy stops is `unanswered` (`writer.flush()`); a call
    whose id is not a string, number or null (JSON-RPC 2.0) is taped at once
    `invalid_id` with no answer and never paired (`_valid_rpc_id`). Reusing
    an id violates JSON-RPC, but a completeness recorder must not lose or
    double-count a call over it (the old dict kept the FIRST answer per id, so
    both calls of a duplicated id were taped with the same answer, while the
    agent side taped something else)."""

    def __init__(self, writer):
        self.writer = writer
        self.failures = 0
        self._lock = threading.Lock()
        #: (Mcp-Session-Id, id key) -> tape idxs of the open calls of that id,
        #: OLDEST FIRST: calls in flight in an exchange, and calls a 202 left
        #: open waiting for their answer on a later response in the session.
        self._open: dict = {}

    def _fail(self):
        with self._lock:
            self.failures += 1

    def _enqueue(self, key, idx) -> None:
        """Queue a call behind any open call of the same key. Never replaces
        one (a break arm in the tests swaps this for an overwrite)."""
        self._open.setdefault(key, []).append(idx)

    def _take_oldest(self, key):
        q = self._open.get(key)
        if not q:
            return None
        idx = q.pop(0)
        if not q:
            del self._open[key]
        return idx

    def _take(self, key, idx) -> bool:
        q = self._open.get(key)
        if not q or idx not in q:
            return False
        q.remove(idx)
        if not q:
            del self._open[key]
        return True

    def open(self, body: bytes, scope=None) -> list:
        opened = []
        try:
            for rpc_id, params in _tape_calls(body):
                if not _valid_rpc_id(rpc_id):
                    self._invalid(params, rpc_id)
                    continue  # taped `invalid_id` now; no answer pairs to it
                idx = self.writer.open_call(params, rpc_id)
                key = (scope, _id_key(rpc_id))
                with self._lock:
                    self._enqueue(key, idx)
                opened.append((idx, key))
        except Exception:
            self._fail()
        return opened

    def _invalid(self, params, rpc_id) -> None:
        """A `tools/call` whose id is not a string, number or null (true, false,
        an object, an array): invalid JSON-RPC, but it was SENT, so it gets
        exactly one tape row, `status: invalid_id`, `resp: null`, written now,
        and is never queued, so no answer can pair to it. The adapter's
        `SeamObserver` does the same, so the two tapes agree (MATCHED)."""
        inv = getattr(self.writer, "invalid_call", None)
        if inv is not None:
            inv(params, rpc_id)
            return
        # A tape writer from before `invalid_call`: the row still exists
        # (closed with no answer, which that writer calls `unanswered`).
        self.writer.close_call(self.writer.open_call(params, _render_invalid_id(rpc_id)), None)

    def close(self, opened: list, body, header_items, status=None, scope=None) -> None:
        """Pair this response's answers, in order, with the oldest open call of
        each id in this session (this exchange's or one a 202 left open). Then
        the exchange's calls still open: left open on a 202, otherwise closed
        `unanswered` now. `body` None: the upstream never answered."""
        with self._lock:
            waiting = any(s == scope for s, _ in self._open)
        if not opened and not waiting:
            return
        try:
            answers = _tape_answers(body, header_items) if body is not None else []
        except Exception:
            answers = []
            self._fail()
        for k, a in answers or []:
            with self._lock:
                idx = self._take_oldest((scope, k))
            if idx is None:
                continue
            try:
                self.writer.close_call(idx, a)
            except Exception:
                self._fail()
        if body is not None and status in KEEP_OPEN_STATUSES:
            return
        for idx, key in opened:
            with self._lock:
                still = self._take(key, idx)
            if not still:
                continue
            try:
                self.writer.close_call(idx, None)
            except Exception:
                self._fail()

    def status(self) -> dict:
        return {"on": True, "path": str(self.writer.path), "side": self.writer.side,
                "namespace": self.writer.namespace, "calls": self.writer.calls,
                "failures": self.failures + self.writer.write_failures}


def _read_chunked(rfile) -> bytes:
    """Minimal chunked-transfer-encoding reader for an incoming request body.
    Content-Length covers the overwhelming majority of real traffic (every
    x402 client library in the wild sends one); this exists so a chunked
    request is not silently truncated to an empty body instead."""
    out = []
    while True:
        line = rfile.readline()
        if not line:
            break
        size_str = line.split(b";", 1)[0].strip()
        try:
            size = int(size_str, 16)
        except ValueError:
            break
        if size == 0:
            while True:
                trailer = rfile.readline()
                if trailer in (b"\r\n", b"\n", b""):
                    break
            break
        out.append(rfile.read(size))
        rfile.read(2)  # trailing CRLF after the chunk data
    return b"".join(out)


# --------------------------------------------------------------------------
# the HTTP handler
# --------------------------------------------------------------------------

class CallProxyHandler(BaseHTTPRequestHandler):
    """One instance per connection (ThreadingHTTPServer runs each on its own
    thread). Class attributes below are bound per-server by `build_server`
    via a dynamically-created subclass -- the stdlib `http.server` idiom for
    handing a handler class configuration without a constructor it doesn't
    control the arguments of."""

    protocol_version = "HTTP/1.1"

    upstream_scheme = "http"
    upstream_host = "127.0.0.1"
    upstream_port = 80
    upstream_timeout: float = 30.0
    seller = ""
    ledger_path = "calls.log.jsonl"
    namespace = "receipted-call"
    witness = True
    raw_payloads = False
    store: "Optional[ReceiptStore]" = None
    tape: "Optional[_ToolTape]" = None
    tape_off_reason = "no --tape configured"

    def log_message(self, fmt, *args):  # noqa: A003 -- stdlib override
        pass  # the ledger is the record; stderr chatter is not

    # -- routing --------------------------------------------------------

    def do_GET(self):
        if self.path == HEALTH_PATH:
            return self._health()
        if self.path.startswith(RECEIPT_PATH_PREFIX):
            return self._serve_receipt()
        self._proxy("GET")

    def do_HEAD(self):
        self._proxy("HEAD")

    def do_POST(self):
        self._proxy("POST")

    def do_PUT(self):
        self._proxy("PUT")

    def do_DELETE(self):
        self._proxy("DELETE")

    def do_PATCH(self):
        self._proxy("PATCH")

    def do_OPTIONS(self):
        self._proxy("OPTIONS")

    # -- the receipted forward --------------------------------------------

    def _read_request_body(self) -> bytes:
        length = self.headers.get("Content-Length")
        if length is not None:
            try:
                n = int(length)
            except ValueError:
                n = 0
            return self.rfile.read(n) if n > 0 else b""
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            return _read_chunked(self.rfile)
        return b""

    def _filtered_request_headers(self) -> dict:
        out = {}
        for k, v in self.headers.items():
            lk = k.lower()
            if lk in HOP_BY_HOP or lk in ("host", "content-length"):
                continue
            out[k] = v
        return out

    def _upstream_url(self) -> str:
        return f"{self.upstream_scheme}://{self.upstream_host}:{self.upstream_port}{self.path}"

    def _forward(self, method: str, body: bytes):
        """Send `body` to the upstream, return (status, header_items, body_bytes).
        Raises OSError/socket.error/TimeoutError on connection failure -- the
        caller turns that into a 502 receipt."""
        conn_cls = HTTPSConnection if self.upstream_scheme == "https" else HTTPConnection
        conn = conn_cls(self.upstream_host, self.upstream_port, timeout=self.upstream_timeout)
        try:
            headers = self._filtered_request_headers()
            conn.request(method, self.path, body=(body or None), headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            return resp.status, resp.getheaders(), resp_body
        finally:
            conn.close()

    def _proxy(self, method: str) -> None:
        try:
            body = self._read_request_body()
        except (OSError, ValueError):
            self.send_error(400, "could not read request body")
            return

        request = {"method": method, "url": self._upstream_url(),
                   "headers": dict(self.headers.items()), "body": body}
        scope = self.headers.get("Mcp-Session-Id") or None
        opened = self.tape.open(body, scope) if self.tape is not None else []
        t0 = time.perf_counter()
        try:
            status, resp_header_items, resp_body = self._forward(method, body)
            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            response = {"status": status, "body": resp_body}
            receipt = _build_call_receipt(
                request, response, ledger_path=self.ledger_path, namespace=self.namespace,
                seller=self.seller, elapsed_ms=elapsed_ms, raw_payloads=self.raw_payloads,
                witness=self.witness)
        except (OSError, socket.error, TimeoutError, ConnectionError) as e:
            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            status = 502
            resp_header_items = []
            resp_body = b""
            detail = str(e)[:300]
            response = {"status": 502, "body": {"error": "upstream_error", "detail": detail}}
            receipt = _build_call_receipt(
                request, response, ledger_path=self.ledger_path, namespace=self.namespace,
                seller=self.seller, elapsed_ms=elapsed_ms, raw_payloads=self.raw_payloads,
                witness=self.witness, upstream_error=detail)
            resp_body_for_tape = None  # the upstream never answered: unanswered
        else:
            resp_body_for_tape = resp_body
        if self.tape is not None:
            self.tape.close(opened, resp_body_for_tape, resp_header_items, status, scope)

        digest = receipt["body_digest"]
        if self.store is not None:
            self.store.put(digest, receipt)
        self._send_response(status, resp_header_items, resp_body, digest,
                            no_body=(method == "HEAD"))

    def _send_response(self, status: int, header_items, body: bytes, digest: str,
                       *, no_body: bool = False) -> None:
        self.send_response(status)
        for k, v in header_items:
            if k.lower() in HOP_BY_HOP or k.lower() == "content-length":
                continue
            self.send_header(k, v)
        self.send_header("X-Arcaeon-Receipt", digest)
        self.send_header("X-Arcaeon-Receipt-URL", f"{RECEIPT_PATH_PREFIX}{digest}")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and not no_body:
            self.wfile.write(body)

    # -- introspection endpoints ------------------------------------------

    def _write_json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _health(self) -> None:
        # The status code IS the verdict. A probe that reads only the status
        # line must not see 200 over a ledger that cannot be read or does not
        # verify. head() alone is not enough: on a corrupt file it returns
        # chain="genesis", rows=0 without raising (arcaeon-ledger 0.7.5), which
        # is indistinguishable from a brand-new ledger, so verify first.
        try:
            res = verify_file(self.ledger_path)
            if not res.ok:
                self._write_json(503, {"ok": False,
                                       "error": f"ledger does not verify: {res.first_break}"[:200],
                                       "ledger": str(self.ledger_path), "seller": self.seller,
                                       "tape": self._tape_status()})
                return
            head = Ledger(self.ledger_path).head()
            self._write_json(200, {"ok": True, "rows": head.rows, "chain": head.chain,
                                   "as_of": head.as_of, "ledger": str(self.ledger_path),
                                   "seller": self.seller, "tape": self._tape_status()})
        except (OSError, ValueError) as e:
            self._write_json(503, {"ok": False, "error": str(e)[:200],
                                   "ledger": str(self.ledger_path), "seller": self.seller,
                                   "tape": self._tape_status()})

    def _tape_status(self) -> dict:
        if self.tape is not None:
            return self.tape.status()
        return {"on": False, "reason": self.tape_off_reason}

    def _serve_receipt(self) -> None:
        digest = unquote(self.path[len(RECEIPT_PATH_PREFIX):])
        receipt = self.store.get(digest) if self.store is not None else None
        if receipt is None:
            self._write_json(404, {"error": "not_found", "digest": digest})
            return
        self._write_json(200, receipt)


# --------------------------------------------------------------------------
# server construction / CLI
# --------------------------------------------------------------------------

def build_server(*, listen: str, upstream: str, seller: str, ledger_path,
                 namespace: str = "receipted-call", witness: bool = True,
                 raw_payloads: bool = False, receipts_dir=None,
                 upstream_timeout: float = 30.0, tape_path=None,
                 tape_namespace: Optional[str] = None,
                 tape_side: str = "tool") -> ThreadingHTTPServer:
    """Build (but do not start) the proxy server. Split out from `main` so
    tests can construct one directly, on an ephemeral port, without going
    through argv or `serve_forever`."""
    host, _, port_s = listen.rpartition(":")
    host = host or "127.0.0.1"
    port = int(port_s)

    up = urlsplit(upstream)
    if up.scheme not in ("http", "https") or not up.hostname:
        raise ValueError(f"--upstream must be a full http(s) base URL, got {upstream!r}")
    upstream_port = up.port or (443 if up.scheme == "https" else 80)

    store = ReceiptStore(receipts_dir)
    tape, tape_off = None, "no --tape configured"
    if tape_path:
        writer_cls, why = _load_tape_writer()
        if writer_cls is None:
            tape_off = f"--tape set but the tape writer is not installed ({why}); pip install arcaeon-adapter"
        else:
            tape = _ToolTape(writer_cls(tape_path, side=tape_side, namespace=tape_namespace))
    handler = type("BoundCallProxyHandler", (CallProxyHandler,), {
        "upstream_scheme": up.scheme,
        "upstream_host": up.hostname,
        "upstream_port": upstream_port,
        "upstream_timeout": upstream_timeout,
        "seller": seller,
        "ledger_path": str(ledger_path),
        "namespace": namespace,
        "witness": witness,
        "raw_payloads": raw_payloads,
        "store": store,
        "tape": tape,
        "tape_off_reason": tape_off,
    })
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    server.tape = tape
    server.tape_status = tape.status() if tape is not None else {"on": False, "reason": tape_off}
    return server


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="python -m arcaeon.record.receipt.call_proxy",
        description="Reverse proxy that issues a Receipted-Call receipt for every "
                    "request it forwards to an upstream.")
    ap.add_argument("--listen", default="127.0.0.1:8402", help="host:port to listen on")
    ap.add_argument("--upstream", required=True,
                    help="upstream base URL, e.g. http://127.0.0.1:9000")
    ap.add_argument("--seller", default="", help="seller name recorded on every receipt")
    ap.add_argument("--ledger", default="calls.log.jsonl", help="ledger path")
    ap.add_argument("--namespace", default="receipted-call")
    ap.add_argument("--no-witness", action="store_true",
                    help="skip the witness pin (default: pin the ledger head every call)")
    ap.add_argument("--receipts-dir", default=None,
                    help="persist one JSON file per receipt here, named by the hex tail "
                         "of its body digest, so a receipt survives past the in-memory LRU")
    ap.add_argument("--raw-payloads", action="store_true",
                    help="embed request/response bodies in the receipt check. OFF by "
                         "default -- digests only. A data-retention decision the seller "
                         "must own; this prints a warning to stderr when set.")
    ap.add_argument("--upstream-timeout", type=float, default=30.0)
    ap.add_argument("--tape", default=None,
                    help="also keep the TOOL side's call tape (arcaeon-tape/1) here: one row "
                         "per MCP tools/call, for `arcaeon-ledger reconcile` against the "
                         "agent side's tape. Needs arcaeon-adapter; without it the proxy "
                         "still runs and says the tape is off")
    ap.add_argument("--tape-namespace", default=None,
                    help="witness namespace this tape is pinned under (recorded in each row)")
    args = ap.parse_args(argv)

    if args.raw_payloads:
        sys.stderr.write(
            "arcaeon-receipt call-proxy: WARNING --raw-payloads is set. Every request "
            "and response body that crosses this proxy will be stored VERBATIM in "
            "receipts (in-memory LRU and --receipts-dir). This is a data-retention "
            "decision the seller must own -- confirm that is intended before serving "
            "real traffic.\n")
        sys.stderr.flush()

    try:
        server = build_server(listen=args.listen, upstream=args.upstream, seller=args.seller,
                              ledger_path=args.ledger, namespace=args.namespace,
                              witness=not args.no_witness, raw_payloads=args.raw_payloads,
                              receipts_dir=args.receipts_dir,
                              upstream_timeout=args.upstream_timeout,
                              tape_path=args.tape, tape_namespace=args.tape_namespace)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if args.tape and not server.tape_status["on"]:
        sys.stderr.write(f"arcaeon-receipt call-proxy: WARNING tape is OFF: "
                         f"{server.tape_status['reason']}\n")
    host, port = server.server_address[0], server.server_address[1]
    print(f"arcaeon-receipt call-proxy listening on {host}:{port} -> {args.upstream}",
          file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
        if server.tape is not None:
            server.tape.writer.flush()  # any call still open is written unanswered
    return 0


if __name__ == "__main__":
    sys.exit(main())
