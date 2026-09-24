# SPDX-License-Identifier: MIT
"""The tape: agent side and tool side must write the SAME digests for the same
call, and DIFFERENT digests when the call is changed between them.

The process-level tests build the real chain, three processes deep:

    client -> proxy(--side agent) -> tamper hop -> proxy(--side tool) -> echo server

and then read both tapes. Reconciling them needs `arcaeon_ledger.reconcile`
(arcaeon-ledger >= the completeness slice); those assertions are skipped, loudly,
on an older ledger, while the digest assertions always run.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from arcaeon.record.adapter.observer import SeamObserver
from arcaeon.record.adapter.proxy import FAULT_ENV
from arcaeon.record.adapter.tape import TAPE_FORMAT, TapeWriter, request_digest, response_digest

ROOT = Path(__file__).resolve().parent
ECHO = [sys.executable, "-m", "arcaeon.record.adapter._echo_server"]
HOP = [sys.executable, str(ROOT / "_tape_tamper_hop.py")]


def _rows(path):
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").split("\n") if l.strip()]


# -- unit: the writer --------------------------------------------------------

def test_rows_commit_in_index_order_even_when_answers_arrive_out_of_order(tmp_path):
    t = TapeWriter(tmp_path / "t.jsonl", side="tool", namespace="ns")
    i1 = t.open_call({"name": "a"}, 1)
    i2 = t.open_call({"name": "b"}, 2)
    i3 = t.open_call({"name": "c"}, 3)
    t.close_call(i3, {"id": 3, "result": {}})
    t.close_call(i2, {"id": 2, "result": {}})
    assert _rows(tmp_path / "t.jsonl") == []          # call 1 still open: nothing may pass it
    t.close_call(i1, {"id": 1, "result": {}})
    rows = _rows(tmp_path / "t.jsonl")
    assert [r["idx"] for r in rows] == [1, 2, 3]
    assert [r["tool"] for r in rows] == ["a", "b", "c"]
    assert all(r["tape"] == TAPE_FORMAT and r["side"] == "tool" and r["ns"] == "ns" for r in rows)


def test_flush_writes_open_calls_unanswered(tmp_path):
    t = TapeWriter(tmp_path / "t.jsonl")
    t.open_call({"name": "quiet"}, 1)
    i2 = t.open_call({"name": "echo"}, 2)
    t.close_call(i2, {"id": 2, "result": {"x": 1}})
    assert t.flush() == 1
    rows = _rows(tmp_path / "t.jsonl")
    assert [(r["idx"], r["status"], r["resp"] is None) for r in rows] == \
        [(1, "unanswered", True), (2, "ok", False)]


def test_numbering_resumes_after_a_restart(tmp_path):
    p = tmp_path / "t.jsonl"
    t = TapeWriter(p)
    t.close_call(t.open_call({"name": "a"}), {"result": {}})
    t2 = TapeWriter(p)
    t2.close_call(t2.open_call({"name": "b"}), {"result": {}})
    assert [r["idx"] for r in _rows(p)] == [1, 2]


def test_a_failed_write_leaves_a_visible_gap_not_a_renumbering(tmp_path):
    written = []

    def emit(row):
        if row["idx"] == 2:
            raise OSError("disk full")
        written.append(row)

    t = TapeWriter(tmp_path / "t.jsonl", emit=emit)
    for k in range(3):
        t.close_call(t.open_call({"name": f"c{k}"}), {"result": {}})
    assert [r["idx"] for r in written] == [1, 3] and t.write_failures == 1


def test_bad_side_is_refused(tmp_path):
    with pytest.raises(ValueError):
        TapeWriter(tmp_path / "t.jsonl", side="middle")


def test_digests_are_content_not_bytes_and_cover_the_tool_name():
    a = request_digest({"name": "echo", "arguments": {"a": 1, "b": 2}})
    assert a == request_digest(json.loads('{"arguments":{"b":2,"a":1},"name":"echo"}'))
    assert a != request_digest({"name": "echo2", "arguments": {"a": 1, "b": 2}})
    assert request_digest({"name": "x"}) == request_digest({"name": "x", "arguments": {}})
    ok = response_digest({"id": 1, "result": {"v": 1}})
    assert ok == response_digest({"id": 99, "result": {"v": 1}})     # id is not content
    assert ok != response_digest({"id": 1, "result": {"v": 2}})
    assert ok != response_digest({"id": 1, "error": {"v": 1}})       # error != result


def test_observer_feeds_the_tape_and_a_tape_failure_never_costs_the_seam_row(tmp_path):
    seam = []

    class Boom:
        calls = 0
        write_failures = 0

        def open_call(self, *a):
            raise RuntimeError("tape down")

    obs = SeamObserver(seam.append, server="s", tape=Boom())
    obs.observe_client_frame(b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
                             b'"params":{"name":"echo","arguments":{}}}')
    obs.observe_server_frame(b'{"jsonrpc":"2.0","id":1,"result":{}}')
    assert [r["evt"] for r in seam] == ["tool_call"] and obs.tape_failures == 1


# -- process level: two proxies, a hop between them --------------------------

def _tool(mid, name, text=None):
    params = {"name": name, "arguments": {} if text is None else {"text": text}}
    return json.dumps({"jsonrpc": "2.0", "id": mid, "method": "tools/call",
                       "params": params}).encode()


STREAM = b"\n".join([
    json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"}}).encode(),
    _tool(1, "echo", "one"),
    _tool(2, "echo", "alter me"),
    _tool(3, "echo", "drop me"),
    _tool(4, "boom"),
    _tool(5, "quiet"),
    _tool(6, "echo", "six"),
]) + b"\n"


def _chain(tmp, mode):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env.pop(FAULT_ENV, None)
    proxy = [sys.executable, "-m", "arcaeon.record.adapter.proxy"]
    tool_side = proxy + ["--ledger", str(tmp / "tool.seam.jsonl"), "--tape",
                         str(tmp / "tool.tape.jsonl"), "--side", "tool",
                         "--tape-namespace", "demo-tool", "--"] + ECHO
    agent_side = proxy + ["--ledger", str(tmp / "agent.seam.jsonl"), "--tape",
                          str(tmp / "agent.tape.jsonl"), "--side", "agent",
                          "--tape-namespace", "demo-agent", "--"] + HOP + [mode, "--"] + tool_side
    p = subprocess.run(agent_side, input=STREAM, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, env=env, timeout=120)
    return p, _rows(tmp / "agent.tape.jsonl"), _rows(tmp / "tool.tape.jsonl")


def _reconcile(tmp):
    R = pytest.importorskip("arcaeon.prove.reconcile",
                            reason="arcaeon-ledger without reconcile: digest checks still ran")
    return R.reconcile(tmp / "agent.tape.jsonl", tmp / "tool.tape.jsonl")


def test_clean_chain_both_tapes_carry_identical_digests(tmp_path):
    p, a, t = _chain(tmp_path, "clean")
    assert p.returncode == 0, p.stderr.decode(errors="replace")
    assert len(a) == len(t) == 6
    for ra, rt in zip(a, t):
        assert (ra["idx"], ra["req"], ra["resp"], ra["status"]) == \
            (rt["idx"], rt["req"], rt["resp"], rt["status"])
        assert ra["side"] == "agent" and rt["side"] == "tool"
    assert [r["status"] for r in a] == ["ok", "ok", "ok", "error", "unanswered", "ok"]
    seam_end = [r for r in _rows(tmp_path / "agent.seam.jsonl") if r["evt"] == "session_end"]
    assert seam_end and seam_end[-1]["tape_calls"] == 6
    r = _reconcile(tmp_path)
    assert r.summary == "MATCHED 6 of 6", r.summary


def test_response_altered_in_transit_gives_different_digests(tmp_path):
    p, a, t = _chain(tmp_path, "alter_response")
    assert len(a) == len(t) == 6
    assert all(ra["req"] == rt["req"] for ra, rt in zip(a, t))
    diff = [ra["idx"] for ra, rt in zip(a, t) if ra["resp"] != rt["resp"]]
    assert diff == [2], diff
    r = _reconcile(tmp_path)
    assert (r.verdict, r.at) == ("ALTERED", 2), r.summary


def test_request_dropped_in_transit_is_missing_on_the_tool_tape(tmp_path):
    p, a, t = _chain(tmp_path, "drop_request")
    assert len(a) == 6 and len(t) == 5
    assert a[2]["status"] == "unanswered"
    r = _reconcile(tmp_path)
    assert (r.verdict, r.at, r.side) == ("MISSING", 3, "tool"), r.summary


def test_meaning_preserving_reserialization_still_matches(tmp_path):
    p, a, t = _chain(tmp_path, "reserialize")
    assert all(ra["resp"] == rt["resp"] for ra, rt in zip(a, t))
    assert _reconcile(tmp_path).verdict == "MATCHED"


# -- the counter: pin the tape head at session end (completeness slice 2) -----

import http.server
import threading


class _Witness:
    """Mock of the hosted witness's POST /api/pin (today's pin.js rules:
    namespace/rows/chain validated, unknown fields accepted and not stored).
    Never the live witness."""

    def __init__(self, key="k-test", status=None):
        self.key, self.forced, self.bodies = key, status, []
        w = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                w.bodies.append((self.headers.get("Authorization"), body))
                if self.headers.get("Authorization") != f"Bearer {w.key}":
                    code, out = 401, {"error": "invalid or missing bearer key"}
                elif w.forced:
                    code, out = w.forced, {"error": "forced"}
                else:
                    pin = {k: body[k] for k in ("namespace", "rows", "chain")}
                    pin["chain"] = pin["chain"].lower()
                    code, out = 201, {"ok": True, "pin": dict(pin, seq=1)}
                raw = json.dumps(out).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


def _pinned_session(tmp, witness, key):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env.pop(FAULT_ENV, None)
    env.pop("ARCAEON_WITNESS_KEY", None)
    if key is not None:
        env["ARCAEON_WITNESS_KEY"] = key
    cmd = [sys.executable, "-m", "arcaeon.record.adapter.proxy", "--ledger", str(tmp / "seam.jsonl"),
           "--tape", str(tmp / "agent.tape.jsonl"), "--tape-namespace", "demo-agent",
           "--tape-pair", "demo-tool", "--pin-witness", witness.url, "--"] + ECHO
    stream = b"\n".join([_tool(1, "echo", "a"), _tool(2, "echo", "b"), _tool(3, "boom")]) + b"\n"
    p = subprocess.run(cmd, input=stream, capture_output=True, env=env, timeout=120)
    end = [r for r in _rows(tmp / "seam.jsonl") if r["evt"] == "session_end"][-1]
    return p, end


def check_session_end_pin(tmp_path):
    pytest.importorskip("arcaeon.record.ledger.tape_pin", reason="arcaeon-ledger without tape pinning")
    w = _Witness()
    try:
        p, end = _pinned_session(tmp_path, w, w.key)
    finally:
        w.close()
    assert p.returncode == 0, p.stderr.decode(errors="replace")
    pin = end["tape_pin"]
    assert pin["status"] == "pinned" and pin["rows"] == 3, pin
    auth, body = w.bodies[-1]
    assert (body["namespace"], body["rows"], body["pair"], body["record_format"]) == \
        ("demo-agent", 3, "demo-tool", "arcaeon-tape/1")
    assert pin["extra_fields"] == "dropped_by_witness"
    saved = json.loads((tmp_path / "agent.tape.jsonl.pin.json").read_text(encoding="utf-8"))
    assert saved["chain"] == pin["chain"] == _rows(tmp_path / "agent.tape.jsonl")[-1]["chain"]
    assert w.key not in (tmp_path / "seam.jsonl").read_text(encoding="utf-8")
    return pin


def test_session_end_pins_the_tape_head_and_writes_the_pin_file(tmp_path):
    check_session_end_pin(tmp_path)


def test_no_witness_key_is_named_in_session_end_and_the_session_still_succeeds(tmp_path):
    w = _Witness()
    try:
        p, end = _pinned_session(tmp_path, w, None)
    finally:
        w.close()
    assert p.returncode == 0 and w.bodies == []
    assert end["tape_pin"]["status"] == "could_not_pin"
    assert "ARCAEON_WITNESS_KEY" in end["tape_pin"]["reason"]


def test_a_witness_refusal_is_named_and_never_changes_the_exit_code(tmp_path):
    pytest.importorskip("arcaeon.record.ledger.tape_pin", reason="arcaeon-ledger without tape pinning")
    w = _Witness()
    try:
        p, end = _pinned_session(tmp_path, w, "wrong-key")
    finally:
        w.close()
    assert p.returncode == 0
    assert (end["tape_pin"]["status"], end["tape_pin"]["http_status"]) == ("pin_failed", 401)
    assert not (tmp_path / "agent.tape.jsonl.pin.json").exists()


def test_without_the_ledger_library_pinning_is_could_not_pin_not_a_crash(tmp_path, monkeypatch):
    import builtins
    from arcaeon.record.adapter.tape import pin_at_session_end
    real_import = builtins.__import__

    def no_ledger(name, *a, **k):
        if name.startswith("arcaeon.record.ledger"):
            raise ImportError("No module named 'arcaeon.record.ledger'")
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", no_ledger)
    out = pin_at_session_end(tmp_path / "t.jsonl", witness_url="http://127.0.0.1:9", key="k")
    assert out["status"] == "could_not_pin" and "not installed" in out["reason"]


def test_breakarm_a_pinner_that_pins_one_call_short_is_caught(tmp_path, monkeypatch):
    TPm = pytest.importorskip("arcaeon.record.ledger.tape_pin")
    real = TPm.pin_tape

    def short(path, store, **kw):
        pin = real(path, store, **kw)
        return dict(pin, rows=pin["rows"] - 1)
    # the proxy runs in a subprocess, so the lie is planted where the subprocess
    # will import it: a sitecustomize on its PYTHONPATH.
    liar = tmp_path / "liar"
    liar.mkdir()
    (liar / "sitecustomize.py").write_text(
        "import arcaeon.record.ledger.tape_pin as T\n"
        "_r = T.pin_tape\n"
        "def _short(p, s, **k):\n"
        "    d = _r(p, s, **k)\n"
        "    return dict(d, rows=d['rows'] - 1)\n"
        "T.pin_tape = _short\n", encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", str(liar) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    with pytest.raises(AssertionError):
        check_session_end_pin(tmp_path)


def test_an_invalid_id_call_is_rowed_at_once_in_its_index_order(tmp_path):
    """`invalid_call` takes the next index and finishes the row immediately
    (`invalid_id`, no response), but it is still committed in index order: it
    waits behind an earlier call that is still open."""
    from arcaeon.record.adapter.tape import INVALID_ID, valid_rpc_id
    assert [valid_rpc_id(x) for x in (1, 1.5, "a", None, True, False, {}, [])] == \
        [True, True, True, True, False, False, False, False]
    w = TapeWriter(tmp_path / "t.jsonl")
    first = w.open_call({"name": "a"}, 1)
    bad = w.invalid_call({"name": "b"}, True)
    assert (first, bad) == (1, 2) and _rows(tmp_path / "t.jsonl") == []
    w.close_call(first, {"jsonrpc": "2.0", "id": 1, "result": {}})
    rows = _rows(tmp_path / "t.jsonl")
    assert [(r["idx"], r["rpc_id"], r["status"], r["resp"]) for r in rows] == \
        [(1, "1", "ok", response_digest({"result": {}})), (2, "true", INVALID_ID, None)]
    assert rows[1]["req"] == request_digest({"name": "b"})
    w.close_call(bad, {"jsonrpc": "2.0", "id": True, "result": {}})   # nothing to close
    assert w.flush() == 0 and len(_rows(tmp_path / "t.jsonl")) == 2
