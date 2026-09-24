"""A cut error string handed back to the caller must say it was cut.

Board item 48 (2026-09-05), from the silent-truncation audit: the stdin loop
answered a malformed line with `parse error: <first 200 chars>` and no marker,
so a caller could not tell a short complaint from the head of a long one. The
cut is right -- quoting a 100k-deep line's failure back whole is the same
denial of service one hop later -- and stays. Only the silence is fixed.

Two seams, on purpose:

  * `_clip_error` directly, which is where the decision lives;
  * the bytes written to stdout by `main()`, which is what a client actually
    reads. A helper that behaves and a loop that never calls it would pass the
    first alone.

The stdlib's own JSON errors run 36 to 80 characters, so the limit does not
fire against `json` as it ships. The must-hit therefore replaces the parser
with one that raises a long ValueError -- the shape a swapped parser or a
fatter wrapper produces -- and the must-miss drives a REAL malformed line so
the pair is not two halves of the same mock.

Run: pytest test_error_truncation.py
"""
from __future__ import annotations

import io
import json

from arcaeon.record.ledger import mcp_server


LIMIT = mcp_server.ERROR_TEXT_MAX


def _drive(tmp_path, line: str, raiser=None) -> list:
    """Run one line through main()'s real stdin loop and return the emitted
    JSON-RPC objects. `raiser`, when given, replaces the parser so a chosen
    exception reaches the except branch."""
    real_stdin, real_stdout = mcp_server.sys.stdin, mcp_server.sys.stdout
    real_loads = mcp_server._loads
    out = io.StringIO()
    try:
        mcp_server.sys.stdin = io.StringIO(line)
        mcp_server.sys.stdout = out
        if raiser is not None:
            mcp_server._loads = raiser
        rc = mcp_server.main(["--log", str(tmp_path / "agent.log.jsonl")])
    finally:
        mcp_server.sys.stdin, mcp_server.sys.stdout = real_stdin, real_stdout
        mcp_server._loads = real_loads
    assert rc == 0
    return [json.loads(x) for x in out.getvalue().splitlines() if x.strip()]


# --------------------------------------------------------------- unit seam

def test_clip_error_marks_a_cut_and_reports_the_true_length():
    detail = "E" * 4000
    msg, data = mcp_server._clip_error(detail)
    assert "truncated" in msg
    assert "4000" in msg, "the caller is told the head length, not the real one"
    assert msg.startswith("E" * LIMIT)
    assert data == {"error_truncated": True, "error_len": 4000,
                    "error_shown": LIMIT}
    # the cut still happens: the receipt must not become an excuse to echo
    assert len(msg) < len(detail) / 4


def test_clip_error_leaves_an_intact_error_alone():
    detail = "Expecting value: line 1 column 1 (char 0)"
    msg, data = mcp_server._clip_error(detail)
    assert msg == detail
    assert data is None, "an untruncated error must not be labelled truncated"


def test_clip_error_at_exactly_the_limit_is_not_a_cut():
    msg, data = mcp_server._clip_error("x" * LIMIT)
    assert msg == "x" * LIMIT and data is None


def test_clip_error_one_over_the_limit_is_a_cut():
    msg, data = mcp_server._clip_error("x" * (LIMIT + 1))
    assert data is not None and data["error_len"] == LIMIT + 1
    assert "truncated" in msg


# ------------------------------------------------------------- stdout seam

def test_long_parse_error_reaches_the_caller_with_its_receipt(tmp_path):
    """MUST-HIT, measured on the bytes written to stdout."""
    def _long(_raw):
        raise ValueError("nesting too deep to parse: " + "D" * 9000)

    out = _drive(tmp_path, "{bad}\n", raiser=_long)
    assert len(out) == 1
    err = out[0]["error"]
    assert err["code"] == -32700 and out[0]["id"] is None
    assert "truncated" in err["message"]
    assert str(9000 + len("nesting too deep to parse: ")) in err["message"]
    assert err["data"]["error_truncated"] is True
    assert err["data"]["error_len"] == 9000 + len("nesting too deep to parse: ")
    # the hostile text is still not echoed back
    assert len(json.dumps(out[0])) < 500


def test_a_real_malformed_line_is_answered_with_no_truncation_claim(tmp_path):
    """MUST-MISS, driven through the REAL parser. The stdlib's message is
    short, so nothing is cut and nothing may claim otherwise."""
    out = _drive(tmp_path, "{not json at all\n")
    assert len(out) == 1
    err = out[0]["error"]
    assert err["code"] == -32700
    assert "truncat" not in err["message"].lower()
    assert "data" not in err, f"an intact error carried a truncation receipt: {err}"
    assert err["message"].startswith("parse error: ")


def test_the_deeply_nested_line_still_gets_a_bounded_answer(tmp_path):
    """The regression the cut exists for. 0.7.3 retyped RecursionError; the
    receipt must not have reopened the echo it was added beside."""
    out = _drive(tmp_path, "[" * 100_000 + "\n")
    assert len(out) == 1
    assert out[0]["error"]["code"] == -32700
    assert len(json.dumps(out[0])) < 500, "the hostile line was echoed back"


def test_tool_call_error_reflecting_a_huge_argument_is_clipped(tmp_path):
    """2026-09-05 audit finding. This board item's clip covered the stdin-loop
    parse-error seam (`main`'s `except ValueError`); the TOOL-CALL error seam
    in `_dispatch_tool`'s `except Exception` was missed. `_ns_path` builds its
    refusal message with `got {namespace!r}`, reflecting the WHOLE offending
    namespace verbatim -- so a caller sending a half-megabyte namespace got a
    half-megabyte reply back. Same amplification `_clip_error` exists to
    stop, arriving through a different door than the one it was found on."""
    huge_ns = "A" * 500_000
    req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "prove_my_conduct",
                                 "arguments": {"namespace": huge_ns, "events": []}}})
    out = _drive(tmp_path, req + "\n")
    assert len(out) == 1
    resp = out[0]
    assert resp["result"]["isError"] is True
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert "truncated" in payload["error"]
    assert payload["error_truncated"] is True
    assert payload["error_len"] > LIMIT
    # the reply itself is bounded, not a mirror of the 500k-char input
    assert len(json.dumps(resp)) < 1000


def test_tool_call_ordinary_error_keeps_its_wire_shape(tmp_path):
    """An intact, short tool-call error must not gain the clip's extra keys —
    same discipline as `test_clip_error_leaves_an_intact_error_alone`, checked
    through the real dispatch path this time."""
    req = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "prove_my_conduct",
                                 "arguments": {"namespace": "not valid!", "events": []}}})
    out = _drive(tmp_path, req + "\n")
    payload = json.loads(out[0]["result"]["content"][0]["text"])
    assert set(payload.keys()) == {"error"}
    assert "truncat" not in payload["error"].lower()


def test_ordinary_errors_keep_their_wire_shape(tmp_path):
    """_error grew an optional member. Every error that has no data must look
    exactly as it did before: no empty `data`, no null `data`."""
    resp = mcp_server._error(3, -32601, "method not found: nope")
    assert resp == {"jsonrpc": "2.0", "id": 3,
                    "error": {"code": -32601, "message": "method not found: nope"}}
    out = _drive(tmp_path, '{"id": 3, "method": "nope"}\n')
    assert "data" not in out[0]["error"]
