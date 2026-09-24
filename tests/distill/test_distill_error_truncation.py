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

from arcaeon.save.distill import mcp_server


LIMIT = mcp_server.ERROR_TEXT_MAX


class _Parser:
    """Stands in for the module's `json`, overriding only loads. Scoped to the
    module under test, so the real json module is never mutated."""

    def __init__(self, body):
        self._body = body

    def loads(self, raw):
        raise ValueError(self._body)

    def dumps(self, *a, **k):
        return json.dumps(*a, **k)


def _drive(line: str, body: str | None = None) -> list:
    """Run one line through main()'s real stdin loop and return the emitted
    JSON-RPC objects. `body`, when given, is the parse failure the replaced
    parser raises."""
    real_stdin, real_stdout = mcp_server.sys.stdin, mcp_server.sys.stdout
    real_json = mcp_server.json
    out = io.StringIO()
    try:
        mcp_server.sys.stdin = io.StringIO(line)
        mcp_server.sys.stdout = out
        if body is not None:
            mcp_server.json = _Parser(body)
        rc = mcp_server.main([])
    finally:
        mcp_server.sys.stdin, mcp_server.sys.stdout = real_stdin, real_stdout
        mcp_server.json = real_json
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

def test_long_parse_error_reaches_the_caller_with_its_receipt():
    """MUST-HIT, measured on the bytes written to stdout."""
    body = "nesting too deep to parse: " + "D" * 9000
    out = _drive("{bad}\n", body=body)
    assert len(out) == 1
    err = out[0]["error"]
    assert err["code"] == -32700 and out[0]["id"] is None
    assert "truncated" in err["message"]
    assert str(len(body)) in err["message"]
    assert err["data"]["error_truncated"] is True
    assert err["data"]["error_len"] == len(body)
    # the hostile text is still not echoed back
    assert len(json.dumps(out[0])) < 500


def test_a_real_malformed_line_is_answered_with_no_truncation_claim():
    """MUST-MISS, driven through the REAL parser. The stdlib's message is
    short, so nothing is cut and nothing may claim otherwise."""
    out = _drive("{not json at all\n")
    assert len(out) == 1
    err = out[0]["error"]
    assert err["code"] == -32700
    assert "truncat" not in err["message"].lower()
    assert "data" not in err, f"an intact error carried a truncation receipt: {err}"
    assert err["message"].startswith("parse error: ")


def test_the_deeply_nested_line_still_gets_a_bounded_answer():
    """The regression the cut exists for. The receipt must not have reopened
    the echo it was added beside."""
    out = _drive("[" * 100_000 + "\n")
    assert len(out) == 1
    assert out[0]["error"]["code"] == -32700
    assert len(json.dumps(out[0])) < 500, "the hostile line was echoed back"


def test_ordinary_errors_keep_their_wire_shape():
    """_error grew an optional member. Every error that has no data must look
    exactly as it did before: no empty `data`, no null `data`."""
    resp = mcp_server._error(3, -32601, "method not found: nope")
    assert resp == {"jsonrpc": "2.0", "id": 3,
                    "error": {"code": -32601, "message": "method not found: nope"}}
    out = _drive('{"id": 3, "method": "nope"}\n')
    assert "data" not in out[0]["error"]
