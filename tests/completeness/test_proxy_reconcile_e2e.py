# SPDX-License-Identifier: MIT
"""Completeness, end to end: `arcaeon proxy` + a server's own tape + `arcaeon reconcile`.

The question: you can prove nothing in a record was changed, but can you prove
everything got written? For tool calls, the answer is two tapes of the same
calls, kept by two processes, lined up:

    client --stdio--> arcaeon proxy --tape agent.tape --> _tape_server.py --tape tool.tape
                      (writes one row per tools/call)     (keeps its OWN tape)

then `arcaeon reconcile agent.tape tool.tape`. Everything here is the shipped
CLI run as a subprocess (`python -m arcaeon proxy`, `python -m arcaeon
reconcile`); the only thing that is not shipped is the tiny server, which
stands in for any MCP server that keeps its own tape.

  (a) every call through the proxy             -> MATCHED n of n, exit 0
  (b) one call sent straight to the server     -> MISSING for exactly that call
  (c) one proxy row edited after the fact      -> ALTERED at that call
  (d) the server's tape cannot be read         -> COULD NOT LOOK, exit 3, never MATCHED

The limit this does not test, because no test can: a call that crossed
neither recorder leaves a row on neither tape and is invisible to reconcile.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from arcaeon.record import row as ROW

HERE = Path(__file__).resolve().parent
SERVER = [sys.executable, str(HERE / "_tape_server.py")]
ARCAEON = [sys.executable, "-m", "arcaeon"]


def _call(mid: int, a: int, b: int = 1) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": mid, "method": "tools/call",
                       "params": {"name": "add", "arguments": {"a": a, "b": b}}}).encode()


def _stream(*calls: bytes) -> bytes:
    init = json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18"}}).encode()
    note = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()
    return b"\n".join([init, note, *calls]) + b"\n"


def _answers(stdout: bytes) -> dict:
    out = {}
    for line in stdout.splitlines():
        msg = json.loads(line)
        out[msg["id"]] = msg
    return out


def _through_proxy(tmp: Path, *calls: bytes) -> subprocess.CompletedProcess:
    """One client session through `arcaeon proxy`, wrapping the tape server."""
    cmd = ARCAEON + ["proxy", "--ledger", str(tmp / "seam.jsonl"),
                     "--tape", str(tmp / "agent.tape.jsonl"), "--"] + \
        SERVER + ["--tape", str(tmp / "tool.tape.jsonl")]
    p = subprocess.run(cmd, input=_stream(*calls), capture_output=True, timeout=120)
    assert p.returncode == 0, p.stderr.decode(errors="replace")
    assert len(_answers(p.stdout)) == len(calls) + 1   # every call answered, plus initialize
    return p


def _around_proxy(tmp: Path, *calls: bytes) -> subprocess.CompletedProcess:
    """One client session straight to the server: the proxy is not in the pipe."""
    cmd = SERVER + ["--tape", str(tmp / "tool.tape.jsonl")]
    p = subprocess.run(cmd, input=_stream(*calls), capture_output=True, timeout=120)
    assert p.returncode == 0, p.stderr.decode(errors="replace")
    return p


def _reconcile(agent_tape, tool_tape) -> tuple[int, dict]:
    p = subprocess.run(ARCAEON + ["reconcile", str(agent_tape), str(tool_tape)],
                       capture_output=True, timeout=120)
    assert p.stdout, p.stderr.decode(errors="replace")   # an answer, never a traceback
    return p.returncode, json.loads(p.stdout)


def _rows(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def _write(path: Path, rows: list[dict], *, rechain: bool) -> None:
    prev = ROW.GENESIS
    out = []
    for r in rows:
        if rechain:
            r = {k: v for k, v in r.items() if k != "chain"}
            r["chain"] = ROW.chain(prev, r)
            prev = r["chain"]
        out.append(json.dumps(r, ensure_ascii=False))
    path.write_text("\n".join(out) + "\n", encoding="utf-8")


# -- (a) everything through the proxy ----------------------------------------

def test_a_every_call_through_the_proxy_is_matched(tmp_path):
    _through_proxy(tmp_path, _call(1, 10), _call(2, 20), _call(3, 30))
    _through_proxy(tmp_path, _call(1, 40), _call(2, 50))      # a second session appends

    agent, tool = _rows(tmp_path / "agent.tape.jsonl"), _rows(tmp_path / "tool.tape.jsonl")
    assert [r["idx"] for r in agent] == [r["idx"] for r in tool] == [1, 2, 3, 4, 5]
    assert {r["side"] for r in agent} == {"agent"} and {r["side"] for r in tool} == {"tool"}

    code, r = _reconcile(tmp_path / "agent.tape.jsonl", tmp_path / "tool.tape.jsonl")
    assert (code, r["verdict"], r["summary"]) == (0, "MATCHED", "MATCHED 5 of 5"), r
    assert r["findings"] == [] and r["could_not_look"] == []
    # argument order does not matter: reconcile reads each tape's side from its rows
    code, r = _reconcile(tmp_path / "tool.tape.jsonl", tmp_path / "agent.tape.jsonl")
    assert (code, r["summary"]) == (0, "MATCHED 5 of 5"), r


# -- (b) one call around the proxy -------------------------------------------

def test_b_one_call_straight_to_the_server_is_missing_for_exactly_that_call(tmp_path):
    _through_proxy(tmp_path, _call(1, 10), _call(2, 20))
    _around_proxy(tmp_path, _call(7, 999))                   # the side door
    _through_proxy(tmp_path, _call(1, 30))

    agent, tool = _rows(tmp_path / "agent.tape.jsonl"), _rows(tmp_path / "tool.tape.jsonl")
    assert len(agent) == 3 and len(tool) == 4
    side_door = tool[2]
    assert side_door["idx"] == 3 and side_door["rpc_id"] == "7"

    code, r = _reconcile(tmp_path / "agent.tape.jsonl", tmp_path / "tool.tape.jsonl")
    assert (code, r["verdict"]) == (1, "MISSING"), r
    # exactly one finding, about exactly that call: on the server's tape (tool
    # call 3), not on the proxy's (`side` names the SHORT tape)
    assert len(r["findings"]) == 1, r["findings"]
    f = r["findings"][0]
    assert (f["verdict"], f["at"], f["index_side"], f["side"]) == ("MISSING", 3, "tool", "agent"), f
    assert (r["at"], r["side"]) == (3, "agent")
    # the calls that did go through the proxy still line up
    assert r["matched"] == 3


# -- (c) one proxy row edited after the fact ---------------------------------

@pytest.mark.parametrize("rechain", [False, True], ids=["plain-edit", "edit-and-rechain"])
def test_c_one_proxy_row_edited_after_the_fact_is_altered(tmp_path, rechain):
    _through_proxy(tmp_path, _call(1, 10), _call(2, 20), _call(3, 30))
    agent_tape = tmp_path / "agent.tape.jsonl"
    rows = _rows(agent_tape)
    # call 2's response digest is rewritten to the digest of a different answer.
    # plain-edit leaves the chain as it was (the tape no longer verifies);
    # edit-and-rechain is a forger who recomputes every chain value, so the
    # proxy's tape verifies on its own and only the server's tape contradicts it.
    rows[1]["resp"] = rows[0]["resp"]
    _write(agent_tape, rows, rechain=rechain)

    code, r = _reconcile(agent_tape, tmp_path / "tool.tape.jsonl")
    assert (code, r["verdict"], r["at"]) == (1, "ALTERED", 2), r
    assert r["verdict"] != "MATCHED"


# -- (d) the server's tape cannot be read ------------------------------------

def _missing(p: Path):
    p.unlink()


def _directory(p: Path):
    p.unlink()
    p.mkdir()


def _too_deep(p: Path):
    p.write_text("[" * 600 + "]" * 600 + "\n", encoding="utf-8")


UNREADABLE = {"missing": _missing, "directory": _directory, "nested-too-deep": _too_deep}


@pytest.mark.parametrize("damage", list(UNREADABLE), ids=list(UNREADABLE))
def test_d_server_tape_unreadable_is_could_not_look_never_matched(tmp_path, damage):
    _through_proxy(tmp_path, _call(1, 10), _call(2, 20))
    tool_tape = tmp_path / "tool.tape.jsonl"
    UNREADABLE[damage](tool_tape)

    code, r = _reconcile(tmp_path / "agent.tape.jsonl", tool_tape)
    assert r["verdict"] != "MATCHED"
    assert (code, r["verdict"]) == (3, "COULD_NOT_LOOK"), r
    assert r["summary"].startswith("COULD NOT LOOK"), r["summary"]
    assert r["could_not_look"] and r["reason_word"], r


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0,
                    reason="root reads a mode-000 file; the other unreadable cases still ran")
def test_d_server_tape_without_read_permission_is_could_not_look(tmp_path):
    _through_proxy(tmp_path, _call(1, 10))
    tool_tape = tmp_path / "tool.tape.jsonl"
    tool_tape.chmod(0)
    try:
        code, r = _reconcile(tmp_path / "agent.tape.jsonl", tool_tape)
    finally:
        tool_tape.chmod(0o600)
    assert (code, r["verdict"]) == (3, "COULD_NOT_LOOK"), r


# -- (d, beside it) a server tape that CAN be read but is not an honest tape ---
#
# Not COULD NOT LOOK, by design (tests/test_chain_end_to_end.py says the same):
# reconcile read every byte, and what it read does not verify, so it says
# ALTERED. An empty server tape it also read: the server says it got no calls,
# so every proxy call is MISSING on the server side. Neither is ever MATCHED.

@pytest.mark.parametrize("content,verdict", [
    (b"\x00\x01 these bytes are not a tape \xff\n", "ALTERED"),
    (b'{"hello": "world"}\n', "ALTERED"),
    (b"", "MISSING"),
], ids=["garbage-bytes", "json-but-not-a-tape", "empty"])
def test_d_server_tape_readable_but_not_honest_is_never_matched(tmp_path, content, verdict):
    _through_proxy(tmp_path, _call(1, 10), _call(2, 20))
    tool_tape = tmp_path / "tool.tape.jsonl"
    tool_tape.write_bytes(content)

    code, r = _reconcile(tmp_path / "agent.tape.jsonl", tool_tape)
    assert r["verdict"] != "MATCHED"
    assert (code, r["verdict"]) == (1, verdict), r
