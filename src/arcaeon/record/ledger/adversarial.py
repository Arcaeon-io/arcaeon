# SPDX-License-Identifier: MIT
"""Hostile stdio lines for JSON-RPC servers, and a runner that feeds them.

Any MCP server that reads newline-delimited JSON-RPC off stdin has the same
front door, and the same ways to fall through it: a parser that raises the one
exception the loop does not catch, a `.get` on something that is not a dict, a
response the encoder cannot write. `HOSTILE_STDIO_LINES` is the list of shapes
that have found real holes, kept in ONE place so every server in the line runs
the same list and a new shape reaches all of them at once.

The bar each line is measured against, for every server:

  1. the process does not crash (exit code 0 on a clean EOF, no traceback on
     stderr), and
  2. every rejection is a JSON-RPC error object on stdout
     (`{"jsonrpc": "2.0", "id": ..., "error": {...}}`), or, for a tool-level
     argument problem, an `isError` tool result, never a traceback and never
     a silent drop of a message that carried an id.

A notification (no `id`) is allowed to draw silence: JSON-RPC 2.0 says so. A
parse error is NOT: the spec answers it with an error whose id is null, and a
server that skips the line instead has told the caller nothing.

Each entry is `(name, line, why)`: `line` is bytes WITHOUT the trailing newline
(bytes, because two of the cases are not valid text). The token `__TOOL__` is
replaced by the runner with a tool name the server under test actually
advertises, so the argument-shape cases reach the dispatcher rather than
stopping at "unknown tool".

`fuzz_line()` runs one line against one fresh process and classifies what came
back; `run_all()` maps that over the list. A fresh process per line is the
whole design: a crash on line 7 of a stream is a crash on "something in the
stream", a crash on line 7 alone has a name.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Iterable, Optional, Sequence

TOOL_TOKEN = b"__TOOL__"

_DEEP = 100_000


def _req(**fields) -> bytes:
    return json.dumps(fields, separators=(",", ":")).encode("utf-8")


#: (name, line_bytes, why). See module docstring for the bar.
HOSTILE_STDIO_LINES: list = [
    ("truncated_json",
     b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{',
     "Unterminated object. Must draw a -32700 parse error, not a silent skip."),
    ("top_level_array_empty",
     b"[]",
     "Valid JSON, wrong type: an empty batch. Spec says -32600 invalid request. "
     "A loop that does `msg.get(...)` on a list raises AttributeError here."),
    ("top_level_number",
     b"42",
     "Valid JSON, not an object. Same `.get` crash on an int."),
    ("top_level_string",
     b'"x"',
     "Valid JSON, not an object. Same `.get` crash on a str."),
    ("top_level_null",
     b"null",
     "Valid JSON, decodes to None. `None.get` is the crash; also the one shape "
     "a `if not msg` guard confuses with an empty line."),
    ("ten_mb_line",
     _req(jsonrpc="2.0", id=1, method="tools/call",
          params={"name": "__TOOL__", "arguments": {"pad": "A" * (10 * 1024 * 1024)}}),
     "A single 10 MB request line. Must be read, parsed and answered (or "
     "refused) without exhausting memory or hanging; a line-length cap that "
     "drops it silently fails the bar too."),
    ("lone_surrogate_escape",
     b'{"jsonrpc":"2.0","id":1,"method":"\\ud800","params":{}}',
     "A JSON escape for an unpaired surrogate. Python's json accepts it; the "
     "reply echoes the method name, and a UTF-8 encoder in strict mode raises "
     "UnicodeEncodeError on the way OUT. Tests the write path, not the parser."),
    ("embedded_nul_byte",
     b'{"jsonrpc":"2.0","id":1,"method":"init\x00ialize"}',
     "A raw NUL byte inside a string literal (a control char, so invalid "
     "JSON). Parse error expected; a C-string-terminated reader truncates."),
    ("invalid_utf8_bytes",
     b'{"jsonrpc":"2.0","id":1,"method":"\xff\xfe"}',
     "Bytes that are not UTF-8 at all. A text-mode stdin decoding strictly "
     "raises UnicodeDecodeError in the read loop itself, before any try block "
     "around the parser; a -32700 or a method-not-found is the bar."),
    ("escaped_nul_in_method",
     b'{"jsonrpc":"2.0","id":1,"method":"init\\u0000ialize"}',
     "The same NUL as a legal escape: valid JSON whose method contains U+0000. "
     "Must be answered as an unknown method, and the echo must not truncate."),
    ("deep_nesting_100k",
     b'{"jsonrpc":"2.0","id":1,"method":"x","params":' + b"[" * _DEEP + b"]" * _DEEP + b"}",
     "100k nested arrays. CPython's C decoder raises RecursionError, not "
     "ValueError, so `except ValueError` walks straight past it and the "
     "process dies. The one shape that killed the ledger server on 2026-09-01."),
    ("request_missing_id",
     b'{"jsonrpc":"2.0","method":"tools/list","params":{}}',
     "A well-formed request with no id, which JSON-RPC defines as a "
     "notification. Silence is the correct answer; a reply here is a bug."),
    ("unknown_method",
     b'{"jsonrpc":"2.0","id":1,"method":"no/such"}',
     "Must draw -32601 method not found with the same id."),
    ("method_not_string",
     b'{"jsonrpc":"2.0","id":1,"method":{},"params":{}}',
     "`method` is an object. Anything that formats or compares it as a string "
     "must not crash; -32600 expected."),
    ("tools_call_missing_name",
     b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{}}}',
     "tools/call with no tool name. -32602 invalid params, or an isError "
     "result; never a KeyError."),
    ("tools_call_arguments_string",
     b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"__TOOL__","arguments":"x"}}',
     "`arguments` is a string, not an object. `args.get(...)` raises "
     "AttributeError if the shape is not checked first."),
    ("params_string",
     b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"x"}',
     "`params` is a string. `params.get(...)` is the crash."),
    ("params_array",
     b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[1,2]}',
     "`params` is a non-empty array (legal in JSON-RPC, meaningless in MCP). "
     "`params.get` is the crash again, and `params or {}` does not save it."),
    ("id_is_object",
     b'{"jsonrpc":"2.0","id":{"a":1},"method":"tools/list"}',
     "An unhashable id. Anything that puts ids in a set or dict dies here; the "
     "spec says id is string, number or null, so -32600 is fair."),
    ("batch_array",
     b'[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"no/such"}]',
     "A JSON-RPC batch. MCP dropped batching in 2025-06-18; a server may refuse "
     "it, but it must refuse with an error object, not a traceback."),
    ("malformed_notification",
     b'{"jsonrpc":"2.0","method":42,"params":"nope"}',
     "No id AND a non-string method AND string params. A notification the "
     "server cannot even classify; silence or an error, never a crash."),
    ("wrong_jsonrpc_version",
     b'{"jsonrpc":"1.0","id":1,"method":"tools/list"}',
     "Wrong protocol version field. Refuse (-32600) or serve; must not crash."),
    ("empty_object",
     b"{}",
     "An object with nothing in it: no id, no method. Notification-shaped, so "
     "silence is acceptable; a crash on the missing method is not."),
]


@dataclass
class Outcome:
    """What one hostile line produced. `kind` is one of:

      jsonrpc_error   stdout carried {"jsonrpc":"2.0","error":{...}}
      result          stdout carried a result (tool-level isError is noted)
      traceback       stderr carried a Python traceback
      silence         nothing on stdout, no traceback, process exited
      timeout         process did not exit within the per-case timeout
      exit            process exited non-zero with no traceback text
    """
    name: str
    kind: str
    exit_code: Optional[int]
    stdout_lines: list = field(default_factory=list)
    stderr_tail: str = ""
    is_error_result: bool = False
    note: str = ""

    @property
    def crashed(self) -> bool:
        return self.kind in ("traceback", "timeout", "exit")

    def passes_bar(self, *, notification: bool = False) -> bool:
        """The bar from the module docstring. A notification may draw silence."""
        if self.crashed:
            return False
        if self.kind == "silence":
            return notification
        return True


INITIALIZE = _req(jsonrpc="2.0", id=0, method="initialize", params={
    "protocolVersion": "2025-06-18", "capabilities": {},
    "clientInfo": {"name": "arcaeon-adversarial", "version": "0"}})
INITIALIZED = _req(jsonrpc="2.0", method="notifications/initialized")


def _classify(name: str, stdout: bytes, stderr: bytes, code: Optional[int],
              timed_out: bool, *, skip_ids: Sequence = ()) -> Outcome:
    err_text = stderr.decode("utf-8", "replace")
    tail = err_text[-1500:].encode("ascii", "backslashreplace").decode("ascii")
    lines = []
    for raw in stdout.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            lines.append(json.loads(raw))
        except ValueError:
            lines.append({"_unparseable": raw[:200].decode("utf-8", "replace")})
    # Drop the preamble's own replies (initialize has id 0).
    lines = [m for m in lines if not (isinstance(m, dict) and m.get("id") in skip_ids)]
    if timed_out:
        return Outcome(name, "timeout", code, lines, tail)
    if "Traceback (most recent call last)" in err_text:
        return Outcome(name, "traceback", code, lines, tail)
    if code not in (0, None):
        return Outcome(name, "exit", code, lines, tail)
    for m in lines:
        if isinstance(m, dict) and "error" in m and m.get("jsonrpc") == "2.0":
            msg = (str(m["error"].get("message", ""))[:160]
                   if isinstance(m["error"], dict) else "")
            # The note is for a console; a server that echoes a lone surrogate
            # back must not take the harness down with it (it did, once).
            msg = msg.encode("ascii", "backslashreplace").decode("ascii")
            return Outcome(name, "jsonrpc_error", code, lines, tail, note=msg)
    for m in lines:
        if isinstance(m, dict) and "result" in m:
            res = m["result"]
            is_err = isinstance(res, dict) and bool(res.get("isError"))
            return Outcome(name, "result", code, lines, tail, is_error_result=is_err)
    if lines:
        return Outcome(name, "exit", code, lines, tail, note="unparseable stdout")
    return Outcome(name, "silence", code, lines, tail)


def _pump(stream, sink: list) -> None:
    for chunk in iter(stream.readline, b""):
        sink.append(chunk)


def fuzz_line(cmd: Sequence[str], name: str, line: bytes, *, timeout: float = 30.0,
              init: bool = False, tool: str = "ledger_verify", env=None,
              cwd=None, grace: float = 5.0) -> Outcome:
    """Feed ONE line to ONE fresh process and classify the reply.

    `init=True` sends a valid initialize + initialized first, so the line lands
    on a server that is past its handshake (the SDK servers refuse everything
    else before it, which would mask the tool-argument cases). The initialize
    reply (id 0) is filtered out of the outcome.

    stdin is NOT closed the moment the line is written. The SDK servers cancel
    in-flight work when stdin hits EOF, so a close-immediately harness reads
    "the handler was cancelled" as "the server was silent", and reads it
    differently run to run. The line is written, the harness waits up to
    `grace` seconds for any reply beyond the handshake's, and only then closes
    stdin and waits (up to `timeout`) for the exit. A case that answers pays
    nothing; a silent case pays `grace`.
    """
    payload = line.replace(TOOL_TOKEN, tool.encode("utf-8"))
    data = (INITIALIZE + b"\n" + INITIALIZED + b"\n" if init else b"") + payload + b"\n"
    run_env = dict(os.environ if env is None else env)
    run_env.setdefault("PYTHONIOENCODING", "utf-8")
    proc = subprocess.Popen(list(cmd), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=run_env, cwd=cwd)
    out_chunks: list = []
    err_chunks: list = []
    readers = [threading.Thread(target=_pump, args=(proc.stdout, out_chunks), daemon=True),
               threading.Thread(target=_pump, args=(proc.stderr, err_chunks), daemon=True)]
    for t in readers:
        t.start()
    expected_before = 1 if init else 0  # the initialize reply
    timed_out = False
    try:
        try:
            proc.stdin.write(data)
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass  # the process died on the way in; the exit code says so
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline and proc.poll() is None:
            if len(out_chunks) > expected_before:
                break
            time.sleep(0.02)
        try:
            proc.stdin.close()
        except OSError:
            pass
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        proc.wait()
    for t in readers:
        t.join(timeout=5)
    return _classify(name, b"".join(out_chunks), b"".join(err_chunks), proc.returncode,
                     timed_out, skip_ids=(0,) if init else ())


def sanity(cmd: Sequence[str], *, timeout: float = 30.0, env=None, cwd=None) -> Outcome:
    """A valid initialize must draw a result: proves the harness is talking to
    a server at all, before any hostile line is read as evidence."""
    return fuzz_line(cmd, "sanity_initialize", INITIALIZE, timeout=timeout,
                     init=False, env=env, cwd=cwd)


def run_all(cmd: Sequence[str], *, cases: Iterable = None, timeout: float = 30.0,
            init: bool = False, tool: str = "ledger_verify", env=None,
            cwd=None, grace: float = 5.0) -> list:
    return [fuzz_line(cmd, name, line, timeout=timeout, init=init, tool=tool,
                      env=env, cwd=cwd, grace=grace)
            for name, line, _why in (HOSTILE_STDIO_LINES if cases is None else cases)]


NOTIFICATION_CASES = frozenset({"request_missing_id", "malformed_notification",
                                "empty_object"})

#: Cases the `mcp` Python SDK (2.0.0) stdio transport drops WITHOUT a reply:
#: its reader turns any line pydantic cannot validate as a JSONRPCMessage into
#: an Exception item on the read stream, and the server-side dispatcher logs
#: that at DEBUG and returns (`mcp/shared/jsonrpc_dispatcher.py`, `_dispatch`:
#: `if self.on_stream_exception is None: logger.debug(...); return`). The
#: server side never sets `on_stream_exception`, so there is no hook for a
#: -32700 / -32600 reply short of replacing the transport. A server built on
#: the SDK cannot meet the second half of the bar for these; its suite asserts
#: crash-free for all of them and "answered" only for the rest. Measured
#: 2026-09-02 against arcaeon-connector and mcp-vet, both modes.
SDK_STDIO_SILENT_CASES = frozenset({
    "truncated_json", "top_level_array_empty", "top_level_number",
    "top_level_string", "top_level_null", "lone_surrogate_escape",
    "embedded_nul_byte", "deep_nesting_100k", "method_not_string",
    "params_string", "params_array", "id_is_object", "batch_array",
    "wrong_jsonrpc_version",
})


def failures(outcomes: Iterable[Outcome]) -> list:
    """The outcomes that miss the bar, notification cases allowed silence."""
    return [o for o in outcomes
            if not o.passes_bar(notification=o.name in NOTIFICATION_CASES)]


def python_module_cmd(module: str, *args: str) -> list:
    return [sys.executable, "-m", module, *args]
