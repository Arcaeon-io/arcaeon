# SPDX-License-Identifier: MIT
"""The MCP server's front door under hostile stdin (2026-09-02, K19).

`python -m arcaeon.record.ledger.mcp_server` reads newline-delimited JSON-RPC off
stdin. `for line in sys.stdin` + `_loads(line)` + `handle(msg, ...)` is three
places a stranger's bytes can end the process, and a ledger server that a
tamperer can stop with one line is a ledger server that stops keeping records
exactly when it matters.

The bar, from `arcaeon_ledger.adversarial`: no line crashes the process, and
every rejection of a message carrying an id is a JSON-RPC error object (or an
isError tool result), never a traceback and never silence. Notification-shaped
lines may draw silence.

Written BEFORE the fixes. First run: 7 tracebacks (`[]`, `42`, `"x"`, `null`,
`params` as a string, `params` as an array, a batch array: every one an
AttributeError on `.get`), 1 UnicodeDecodeError in the read loop (invalid
UTF-8), and 4 silent drops where the spec wants -32700 (truncated JSON, a raw
NUL byte, 100k-deep nesting, which `_loads` retypes to ValueError and the loop
then swallowed, and invalid UTF-8 once the decode no longer raises).

The subprocess tests are the real thing; the in-process `handle()` / `main()`
tests are the same failures pinned at the function boundary so a regression
names its line without spawning anything.
"""
from __future__ import annotations

import io
import json
import sys

import pytest

from arcaeon.record.ledger import Ledger
from arcaeon.record.ledger import adversarial as adv
from arcaeon.record.ledger.mcp_server import handle, main


def _cmd(tmp_path):
    return [sys.executable, "-m", "arcaeon.record.ledger.mcp_server",
            "--log", str(tmp_path / "agent.log.jsonl")]


# --- over a real pipe --------------------------------------------------------

def test_sanity_a_valid_initialize_gets_a_result_over_stdio(tmp_path):
    """Proves the harness is talking to the server before any hostile line is
    read as evidence about it."""
    o = adv.sanity(_cmd(tmp_path), timeout=60)
    assert o.kind == "result", (o.kind, o.exit_code, o.stderr_tail)
    assert o.exit_code == 0


@pytest.mark.parametrize("name,line,why", adv.HOSTILE_STDIO_LINES,
                         ids=[c[0] for c in adv.HOSTILE_STDIO_LINES])
def test_hostile_line_never_crashes_and_never_goes_unanswered(tmp_path, name, line, why):
    o = adv.fuzz_line(_cmd(tmp_path), name, line, timeout=60, tool="ledger_verify")
    ok = o.passes_bar(notification=name in adv.NOTIFICATION_CASES)
    assert ok, (f"{name}: {why}\n  outcome={o.kind} exit={o.exit_code} "
                f"stdout={o.stdout_lines[:2]}\n{o.stderr_tail}")


# --- the same holes at the function boundary ---------------------------------

@pytest.mark.parametrize("msg", [[], 42, "x", None, [{"jsonrpc": "2.0", "id": 1}]],
                         ids=["list", "int", "str", "none", "batch"])
def test_handle_answers_a_non_object_message_with_invalid_request(tmp_path, msg):
    """Anything that is not a JSON object cannot carry a request; the answer is
    -32600 with a null id, per JSON-RPC 2.0, not an AttributeError on `.get`."""
    resp = handle(msg, Ledger(tmp_path / "a.jsonl"))
    assert resp is not None
    assert resp["error"]["code"] == -32600, resp
    assert resp["id"] is None


@pytest.mark.parametrize("params", ["x", [1, 2], 7])
def test_handle_answers_non_object_params_with_invalid_params(tmp_path, params):
    resp = handle({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": params},
                  Ledger(tmp_path / "a.jsonl"))
    assert resp["error"]["code"] == -32602, resp
    assert resp["id"] == 9


def test_handle_refuses_string_arguments_in_words(tmp_path):
    """`arguments: "x"` used to land as an isError whose text was the
    interpreter's own `'str' object has no attribute 'get'`. Crash-free by
    accident is still by accident; the refusal should say what was wrong."""
    resp = handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                   "params": {"name": "ledger_verify", "arguments": "x"}},
                  Ledger(tmp_path / "a.jsonl"))
    assert resp["result"]["isError"] is True, resp
    text = json.loads(resp["result"]["content"][0]["text"])["error"]
    assert "arguments must be a JSON object" in text, text
    assert "attribute" not in text, text


def _drive(monkeypatch, tmp_path, raw: str) -> list:
    """Run main()'s stdin loop over one line in-process; return the replies."""
    monkeypatch.setattr(sys, "stdin", io.StringIO(raw + "\n"))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    assert main(["--log", str(tmp_path / "agent.log.jsonl")]) == 0
    return [json.loads(l) for l in out.getvalue().splitlines() if l.strip()]


@pytest.mark.parametrize("raw", [
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{',
    '{"jsonrpc":"2.0","id":1,"method":"x","params":' + "[" * 100_000 + "]" * 100_000 + "}",
    "not json at all",
], ids=["truncated", "deep_nesting", "prose"])
def test_main_answers_a_parse_error_with_minus_32700_not_silence(monkeypatch, tmp_path, raw):
    """A line the server cannot parse used to be `continue`d past. The caller
    then waits on a request the server never acknowledged. JSON-RPC says answer
    with -32700 and a null id, and so does this test."""
    replies = _drive(monkeypatch, tmp_path, raw)
    assert len(replies) == 1, replies
    assert replies[0]["error"]["code"] == -32700, replies
    assert replies[0]["id"] is None
    # The reply must not echo the hostile bytes back (a 100k-deep line quoted
    # into an error message is a 100k-deep error message).
    assert len(json.dumps(replies[0])) < 500, len(json.dumps(replies[0]))


def test_main_still_ignores_blank_lines(monkeypatch, tmp_path):
    assert _drive(monkeypatch, tmp_path, "   ") == []
