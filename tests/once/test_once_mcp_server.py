"""MCP stdio server robustness -- audit 2026-09-01.

The server is a long-lived stdio loop; one malformed line must not take it
down and leave every later request unanswered. 0.2.1 died on three inputs a
misbehaving client can send: a JSON array/scalar where a message object was
expected, a non-object `params`, and a line nested past the JSON parser's
recursion depth (RecursionError is not a ValueError).

Run: pytest test_mcp_server.py
"""
from __future__ import annotations

import json
import subprocess
import sys

from arcaeon.record.once import __version__
from arcaeon.record.once.mcp_server import handle


def _run_server(stdin_text: str) -> list:
    proc = subprocess.run(
        [sys.executable, "-m", "arcaeon.record.once.mcp_server"],
        input=stdin_text, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert "Traceback" not in proc.stderr, proc.stderr
    return [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]


def test_non_object_json_line_is_answered_and_server_stays_up():
    """0.2.2 stopped the crash by skipping these lines in silence. JSON-RPC 2.0
    answers a non-object request with Invalid Request and a null id, and a
    caller that sent a request and got nothing waits forever - a hang is a
    quieter version of the same defect. What this test is really for, that the
    initialize sent AFTER the bad lines still gets answered, is unchanged."""
    out = _run_server('[1, 2]\n"x"\n42\n'
                      '{"id": 1, "method": "initialize"}\n')
    assert [r["id"] for r in out] == [None, None, None, 1]
    assert all(r["error"]["code"] == -32600 for r in out[:3]), out
    assert out[-1]["result"]["serverInfo"]["version"] == __version__


def test_non_object_params_returns_an_error_result_not_a_crash():
    out = _run_server('{"id": 1, "method": "tools/call", "params": [1]}\n'
                      '{"id": 2, "method": "tools/call", "params": '
                      '{"name": "guard_side_effect", "arguments": [1]}}\n'
                      '{"id": 3, "method": "tools/list"}\n')
    assert [r["id"] for r in out] == [1, 2, 3]
    assert out[0]["result"]["isError"] is True
    assert out[1]["result"]["isError"] is True
    assert out[2]["result"]["tools"]


def test_deeply_nested_line_is_answered_not_a_recursion_error():
    """Nested past the parser used to kill the server, then (0.2.2) was skipped
    in silence. It now returns a -32700 parse error with a null id. The hostile
    line is never echoed into the message: a 100k-deep line quoted back is a
    100k-deep message, which is the same denial-of-service one hop later."""
    out = _run_server("[" * 100_000 + "\n"
                      '{"id": 1, "method": "initialize"}\n')
    assert [r["id"] for r in out] == [None, 1]
    assert out[0]["error"]["code"] == -32700
    assert len(json.dumps(out[0])) < 500, "the hostile line was echoed back"


def test_handle_non_dict_params_direct():
    resp = handle({"id": 7, "method": "tools/call", "params": "nope"})
    assert resp["id"] == 7 and resp["result"]["isError"] is True
