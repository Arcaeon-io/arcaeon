# SPDX-License-Identifier: MIT
"""The tape: one row per tool call, in call order, from ONE side of the call.

Two tapes and a counter. The agent side and the tool side each keep a tape of
the same calls, written independently, in processes neither party's model owns.
`arcaeon_ledger.reconcile` lines them up and says MATCHED n of n, MISSING at
call k, ALTERED at call k, or COULD NOT LOOK.

    agent side:  arcaeon-adapter --ledger seam.jsonl --tape agent.tape.jsonl -- <server>
    tool side:   arcaeon-adapter --ledger seam.jsonl --tape tool.tape.jsonl --side tool -- <server>

The tool side is the same binary wrapped around the server where the server
runs. For a server that is not a stdio process, `TapeWriter` is the whole
integration: `open_call()` when a request arrives, `close_call()` with the
response. That is the one line a tool vendor has to add.

THE ROW (format `arcaeon-tape/1`)
---------------------------------
    {"evt": "tape_call", "tape": "arcaeon-tape/1", "side": "agent"|"tool",
     "ns": <namespace or null>, "idx": k, "tool": <name>, "rpc_id": <id>,
     "req":  "sha256:json-c14n:v1:<hex>",   digest of {"name", "arguments"}
     "resp": "sha256:json-c14n:v1:<hex>" | null,   digest of {"result"} or {"error"}
     "status": "ok"|"error"|"unanswered"|"invalid_id", "ts": ..., "chain": ...}

`invalid_id`: JSON-RPC 2.0 says an id is a string, a number, or null. A
`tools/call` whose id is anything else (true, false, an object, an array) was
still SENT, so it gets its row, but it is not a request anyone can answer: the
row is written at once with `resp: null`, and no answer is ever paired to it.
Its `rpc_id` is the id as compact JSON (`"true"`, `'{"k":1}'`), so a reader can
tell it from a string id. A null or absent id is a notification: no row. Both
recorders (the adapter and arcaeon-receipt's call_proxy) use this rule, so the
two tapes agree on an invalid call and reconcile reads it MATCHED.

`idx` is allocated when the REQUEST is seen (pipe order) and rows are COMMITTED
in idx order: row n of a tape is call n. That is what makes the witness pin a
counter: a pin of `{rows: n, chain: h}` says "calls 1..n, head h". A call still
in flight holds later rows in memory until it answers or the session ends
(then it is written `unanswered`); that is the price of the invariant, and it
is stated rather than hidden.

The digests are content digests over the parsed JSON-RPC, identical on both
sides by construction (same function, same canonical JSON), so a relay that
re-serializes a frame without changing it does not break a match, and a relay
that changes one character does. `rpc_id` is carried for a human reading the
tape but is NOT in either digest: a legitimate relay may renumber ids.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from ._ledger import digest_json, open_ledger

__all__ = ["TAPE_FORMAT", "SIDES", "TapeWriter", "request_digest", "response_digest",
           "pin_at_session_end", "WITNESS_KEY_ENV", "INVALID_ID", "valid_rpc_id",
           "render_invalid_id"]

#: The witness bearer key is read from the environment, never from argv: argv
#: is recorded (redacted) in `session_begin`, and a key has no business there.
WITNESS_KEY_ENV = "ARCAEON_WITNESS_KEY"

TAPE_FORMAT = "arcaeon-tape/1"
SIDES = ("agent", "tool")

#: The status of a call whose JSON-RPC id is not a string, number or null.
INVALID_ID = "invalid_id"


def valid_rpc_id(rpc_id: Any) -> bool:
    """JSON-RPC 2.0: an id is a string, a number, or null. `bool` is excluded
    explicitly because Python's `True` is an `int`. arcaeon-receipt's call_proxy
    carries the same predicate (`_valid_rpc_id`); keep them identical."""
    if isinstance(rpc_id, bool):
        return False
    return rpc_id is None or isinstance(rpc_id, (str, int, float))


def render_invalid_id(rpc_id: Any) -> str:
    """An invalid id as compact JSON, for a human reading the row (capped)."""
    try:
        text = json.dumps(rpc_id, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except (TypeError, ValueError, RecursionError):
        text = f"<{type(rpc_id).__name__}>"
    return text if len(text) <= 200 else text[:197] + "..."


def _safe(value: Any) -> str:
    try:
        return digest_json(value)
    except Exception as e:  # NaN, recursion: name the failure, never invent a hash
        return f"undigestible:{type(e).__name__}"


def request_digest(params: Any) -> str:
    """Digest of a `tools/call` request's `params`, as this side saw them."""
    if not isinstance(params, dict):
        params = {}
    args = params.get("arguments")
    return _safe({"name": params.get("name"),
                  "arguments": {} if args is None else args})


def response_digest(msg: dict) -> str:
    """Digest of a JSON-RPC response: its `error` if it has one, else its `result`."""
    if "error" in msg:
        return _safe({"error": msg.get("error")})
    return _safe({"result": msg.get("result")})


def _status(msg: dict) -> str:
    if "error" in msg:
        return "error"
    res = msg.get("result")
    return "error" if isinstance(res, dict) and res.get("isError") is True else "ok"


class TapeWriter:
    """Allocate call indices in arrival order; commit rows in index order.

    Thread-safe. Resumes numbering from an existing tape, so a restarted
    recorder continues at n+1 instead of writing a second call 1.
    """

    def __init__(self, path: str | Path, *, side: str = "agent",
                 namespace: str | None = None, emit=None):
        if side not in SIDES:
            raise ValueError(f"side must be one of {SIDES}, not {side!r}")
        self.path = Path(path)
        self.side = side
        self.namespace = namespace
        self._emit = emit or open_ledger(self.path).append
        self._lock = threading.Lock()
        last = self._last_idx()
        self._next = last + 1
        self._committed = last
        self._open: dict[int, dict] = {}      # idx -> row awaiting its response
        self._ready: dict[int, dict] = {}     # idx -> finished row awaiting its turn
        #: Rows whose write raised. The index is skipped (not retried forever), so
        #: the tape shows a GAP at that call: reconcile reads it as MISSING on this
        #: side, which is the truth. Reported by the proxy in `session_end`.
        self.write_failures = 0

    def _last_idx(self) -> int:
        last = 0
        try:
            text = self.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return 0
        for raw in text.split("\n"):
            try:
                row = json.loads(raw)
            except (ValueError, RecursionError):
                continue
            if isinstance(row, dict) and row.get("evt") == "tape_call" \
                    and isinstance(row.get("idx"), int):
                last = max(last, row["idx"])
        return last

    @property
    def calls(self) -> int:
        """Indices allocated so far (the count this side will eventually pin)."""
        return self._next - 1

    def open_call(self, params: Any, rpc_id: Any = None) -> int:
        """A request crossed this side. Returns its call index."""
        tool = params.get("name") if isinstance(params, dict) else None
        with self._lock:
            idx = self._next
            self._next += 1
            self._open[idx] = {
                "evt": "tape_call", "tape": TAPE_FORMAT, "side": self.side,
                "ns": self.namespace, "idx": idx,
                "tool": tool if isinstance(tool, str) else None,
                "rpc_id": None if rpc_id is None or isinstance(rpc_id, bool) else str(rpc_id),
                "req": request_digest(params),
            }
            return idx

    def invalid_call(self, params: Any, rpc_id: Any) -> int:
        """A request with an INVALID id (see `valid_rpc_id`) crossed this side.
        It gets its index and its row now, `status: invalid_id`, `resp: null`:
        no answer can be paired to it. Returns its call index."""
        tool = params.get("name") if isinstance(params, dict) else None
        with self._lock:
            idx = self._next
            self._next += 1
            self._ready[idx] = {
                "evt": "tape_call", "tape": TAPE_FORMAT, "side": self.side,
                "ns": self.namespace, "idx": idx,
                "tool": tool if isinstance(tool, str) else None,
                "rpc_id": render_invalid_id(rpc_id),
                "req": request_digest(params),
                "resp": None, "status": INVALID_ID,
            }
            self._drain()
            return idx

    def close_call(self, idx: int, msg: dict | None) -> None:
        """The response for call `idx` crossed this side (`msg=None`: it never will)."""
        with self._lock:
            row = self._open.pop(idx, None)
            if row is None:
                return
            if msg is None:
                row.update(resp=None, status="unanswered")
            else:
                row.update(resp=response_digest(msg), status=_status(msg))
            self._ready[idx] = row
            self._drain()

    def flush(self) -> int:
        """Session over: every call still open is written `unanswered`. Returns how many."""
        with self._lock:
            n = len(self._open)
            for idx, row in list(self._open.items()):
                row.update(resp=None, status="unanswered")
                self._ready[idx] = row
            self._open.clear()
            self._drain()
            return n

    def _drain(self) -> None:
        while self._committed + 1 in self._ready:
            k = self._committed + 1
            row = self._ready.pop(k)
            try:
                self._emit(row)
            except Exception:
                self.write_failures += 1
            self._committed = k


def pin_at_session_end(tape_path, *, witness_url: str, key: str | None,
                       namespace: str | None = None, pair: str | None = None,
                       out_path=None) -> dict:
    """Session over: pin this tape's head at the hosted witness. NEVER raises.

    The counter half of "two tapes and a counter": `rows` = calls on this tape,
    `chain` = its head. Uses `arcaeon_ledger.tape_pin.pin_tape` (which goes
    through the ledger's own `publish_head`), so the refusals are the ledger's:
    an empty or unverified tape is never pinned. Pinning needs the real
    library; without it the answer is `could_not_pin`, named, and the session
    ends normally. The pin record is also written to `out_path` (default
    `<tape>.pin.json`) for `arcaeon-ledger reconcile --pin`.

    Returns the pin record (`status: "pinned"`) or `{status, reason}` with
    status one of `could_not_pin`, `pin_refused`, `pin_failed`.
    """
    try:
        from arcaeon.record.ledger.tape_pin import pin_tape
        from arcaeon.record.ledger.witness import HostedWitness, HostedWitnessError
    except Exception as e:
        return {"status": "could_not_pin",
                "reason": f"arcaeon-ledger with tape pinning is not installed "
                          f"({type(e).__name__}: {e})"[:300]}
    if not key:
        return {"status": "could_not_pin",
                "reason": f"no witness key: set {WITNESS_KEY_ENV}"}
    try:
        pin = pin_tape(tape_path, HostedWitness(witness_url, key),
                       namespace=namespace, pair=pair)
    except HostedWitnessError as e:
        return {"status": "pin_failed", "http_status": e.status, "reason": str(e)[:300]}
    except (ValueError, OSError) as e:
        return {"status": "pin_refused", "reason": str(e)[:300]}
    except Exception as e:  # a pinning bug must not become the session's crash
        return {"status": "pin_failed", "reason": f"{type(e).__name__}: {e}"[:300]}
    out = Path(out_path) if out_path else Path(str(tape_path) + ".pin.json")
    try:
        out.write_text(json.dumps(pin, indent=1), encoding="utf-8")
        pin["pin_file"] = str(out)
    except OSError as e:
        pin["pin_file_error"] = str(e)[:200]
    return pin
