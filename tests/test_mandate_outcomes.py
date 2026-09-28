"""The mandate gate's outcome words and the drift count, on every surface.

    pytest tests/test_mandate_outcomes.py

Every gate row carries `outcome`, one of inside, outside_forwarded, blocked,
never_attempted, could_not_look (arcaeon.record.adapter.mandate_gate.OUTCOMES).
`session_end` carries `mandate_no_matching_mandate`: calls no mandate rule
matched at all, apart from calls a rule matched and refused. The evidence
pack's mandate_rows.json carries the same count for its window.

Each outcome is produced on each surface where it can occur: the stdio proxy
(a real subprocess over the KH5 stub tool), http_forward and call_proxy (over
the KH5 loopback stub). Only loopback stubs this test starts and stops.
"""
from __future__ import annotations

import http.client
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SRC = str(HERE.parent / "src")
HEAVY = HERE / "heavy"
STUB = str(HEAVY / "kh5_stub_tool.py")
sys.path.insert(0, str(HEAVY))
import kh5_stub_tool  # noqa: E402  the KH5 fixture

from arcaeon.record.adapter import mandate_gate  # noqa: E402

MANDATE = {
    "who": "outcome-agent",
    "allowed_acts": ["search_*", "place_order"],
    "forbidden_acts": ["refund"],
    "spend_cap": {"amount": "15.00", "currency": "USD"},
}

#: (tool params, rowed outcome record-only, rowed outcome enforce, no rule matched)
SCRIPT = [
    ({"name": "search_items", "arguments": {"q": "lamp"}}, None, None, False),
    ({"name": "refund", "arguments": {"order": "A-1"}},
     "outside_forwarded", "blocked", False),
    ({"name": "send_email", "arguments": {"to": "x@example.test"}},
     "outside_forwarded", "blocked", True),
    ({"name": "wander", "arguments": {}}, "outside_forwarded", "blocked", True),
    ({"name": "place_order", "arguments": {"total": "lots", "currency": "USD"}},
     "could_not_look", "could_not_look", False),
]

SURFACES = ("stdio_proxy", "http_forward", "call_proxy")


def _frame(i: int, params: dict) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                       "params": params}).encode()


def _rows(path) -> list:
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def _gate_rows(rows) -> list:
    return [r for r in rows if r.get("evt") in ("mandate_outside", "mandate_could_not_look",
                                                "mandate_cap_exceeded")]


def _end(rows) -> dict:
    ends = [r for r in rows if r.get("evt") == "session_end"]
    assert len(ends) == 1, [r.get("evt") for r in rows]
    return ends[0]


# -- one session per surface, driven one request at a time --------------------

class _Stdio:
    def __init__(self, work: Path, mandate: Path, enforce: bool, max_frame=None):
        self.ledger = work / "stdio.seam.jsonl"
        self.recv = work / "stdio.received.txt"
        self.recv.write_text("", encoding="utf-8")
        env = dict(os.environ)
        env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
        env.pop("ARCAEON_ADAPTER_SELFTEST_CORRUPT", None)
        argv = [sys.executable, "-m", "arcaeon.record.adapter.proxy",
                "--ledger", str(self.ledger), "--mandate", str(mandate)]
        if enforce:
            argv.append("--mandate-enforce")
        if max_frame is not None:
            argv += ["--max-frame", str(max_frame)]
        self.p = subprocess.Popen(argv + ["--", sys.executable, STUB, str(self.recv)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, env=env)

    def send(self, body: bytes, reply: bool = True):
        self.p.stdin.write(body + b"\n")
        self.p.stdin.flush()
        if not reply:
            return None
        return json.loads(self.p.stdout.readline())

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=60)
        finally:
            if self.p.poll() is None:
                self.p.kill()
        self.received = [x for x in self.recv.read_text(encoding="utf-8").splitlines() if x]
        return _rows(self.ledger)


def _http(port: int, path: str, body: bytes):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        c.request("POST", path, body=body, headers={"Content-Type": "application/json"})
        r = c.getresponse()
        data = r.read()
    finally:
        c.close()
    try:
        return json.loads(data)
    except ValueError:
        return {"http_status": r.status}


class _HttpForward:
    def __init__(self, work: Path, mandate: Path, enforce: bool, max_frame=None):
        from arcaeon.record.adapter import http_forward as HF
        self.ledger = work / "http.seam.jsonl"
        self.up = kh5_stub_tool.HttpStub()
        kw = {} if max_frame is None else {"max_frame": max_frame}
        self.srv = HF.build_forward_server(self.up.url, ledger_path=self.ledger,
                                           mandate_path=mandate,
                                           mandate_enforce=enforce, **kw).start()

    def send(self, body: bytes, reply: bool = True):
        return _http(self.srv.port, "/", body)

    def close(self):
        time.sleep(0.3)                       # record-only judges after forwarding
        try:
            self.srv.close()
        finally:
            self.up.close()
        self.received = list(self.up.received)
        return _rows(self.ledger)


class _CallProxy:
    def __init__(self, work: Path, mandate: Path, enforce: bool, max_frame=None):
        from arcaeon.record.receipt import call_proxy
        self.log = work / "call.mandate.jsonl"
        self.up = kh5_stub_tool.HttpStub()
        self.srv = call_proxy.build_server(
            listen="127.0.0.1:0", upstream=self.up.base, seller="outcomes",
            ledger_path=work / "calls.log.jsonl", witness=False,
            mandate_path=mandate, mandate_enforce=enforce, mandate_log=self.log)
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()

    def send(self, body: bytes, reply: bool = True):
        return _http(self.srv.server_address[1], "/mcp", body)

    def close(self):
        time.sleep(0.3)
        try:
            self.srv.shutdown()
            self.srv.server_close()
            self.srv.mandate_close()
            self.t.join(timeout=10)
        finally:
            self.up.close()
        self.received = list(self.up.received)
        return _rows(self.log)


OPEN = {"stdio_proxy": _Stdio, "http_forward": _HttpForward, "call_proxy": _CallProxy}


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arcaeon-home"))
    monkeypatch.delenv("ARCAEON_JOURNAL", raising=False)


def _mandate(tmp_path, body=MANDATE) -> Path:
    p = tmp_path / "mandate.json"
    p.write_text(json.dumps(body), encoding="utf-8")
    return p


def _run_script(surface, tmp_path, enforce):
    work = tmp_path / surface
    work.mkdir()
    mandate = _mandate(tmp_path)
    s = OPEN[surface](work, mandate, enforce)
    try:
        replies = {i: s.send(_frame(i, p)) for i, (p, *_rest) in enumerate(SCRIPT, 1)}
    finally:
        rows = s.close()
    return s, replies, rows, mandate


# -- the words ------------------------------------------------------------------

def test_the_five_words_are_fixed():
    assert mandate_gate.OUTCOMES == ("inside", "outside_forwarded", "blocked",
                                     "never_attempted", "could_not_look")
    assert set(mandate_gate.OUTCOME_MEANINGS) == set(mandate_gate.OUTCOMES)


# -- inside, outside_forwarded, blocked, could_not_look; the drift count --------

@pytest.mark.parametrize("enforce", [False, True], ids=["record-only", "enforce"])
@pytest.mark.parametrize("surface", SURFACES)
def test_each_rowed_call_carries_its_outcome_and_the_drift_count_is_two(
        tmp_path, surface, enforce):
    s, replies, rows, _ = _run_script(surface, tmp_path, enforce)
    gate = _gate_rows(rows)
    want = [(p["name"], en if enforce else ro) for p, ro, en, _ in SCRIPT
            if (en if enforce else ro) is not None]
    assert [(r["tool"], r["outcome"]) for r in gate] == want
    for r in gate:
        assert r["outcome"] in mandate_gate.OUTCOMES
        assert r["action"] == ("blocked" if enforce else "forwarded")   # kept as before
        assert "verdict" in r and "rule" in r and "reason" in r
    # the drift flag rides only on the calls no rule matched
    assert [r["tool"] for r in gate if r.get("no_matching_mandate")] == \
        ["send_email", "wander"]
    end = _end(rows)
    assert end["mandate_no_matching_mandate"] == 2
    assert end["mandate_outside"] == 3 and end["mandate_inside"] == 1
    # inside is counted, not rowed; it reached the tool either way
    assert "search_items" in s.received
    if enforce:
        assert s.received == ["search_items"]
        assert all(replies[i]["error"]["code"] == -32001 for i in (2, 3, 4, 5))
    else:
        assert s.received == [p["name"] for p, *_ in SCRIPT]


def test_a_rule_that_matched_and_refused_is_not_drift():
    g = mandate_gate.MandateGate.from_dict(MANDATE)
    assert "no_matching_mandate" not in g.detail({"name": "refund"})[2]
    assert g.detail({"name": "send_email"})[2].get("no_matching_mandate") is True
    assert "no_matching_mandate" not in g.detail({"name": "search_x"})[2]
    # no allowed_acts list: a call nothing names is inside by default, and drift
    open_gate = mandate_gate.MandateGate.from_dict({"forbidden_acts": ["refund"]})
    v, _, extra = open_gate.detail({"name": "anything"})
    assert v == "inside" and extra.get("no_matching_mandate") is True
    assert "no_matching_mandate" not in open_gate.detail({"name": "refund"})[2]


def test_no_drift_no_count_on_session_end(tmp_path):
    work = tmp_path / "w"
    work.mkdir()
    s = _HttpForward(work, _mandate(tmp_path), False)
    try:
        s.send(_frame(1, {"name": "search_items", "arguments": {}}))
    finally:
        rows = s.close()
    assert _end(rows).get("mandate_no_matching_mandate") is None


# -- never_attempted: the gate could not run --------------------------------------

@pytest.mark.parametrize("surface", SURFACES)
def test_missing_mandate_at_start_is_never_attempted(tmp_path, surface):
    work = tmp_path / surface
    work.mkdir()
    s = OPEN[surface](work, tmp_path / "absent.json", False)
    try:
        s.send(_frame(1, {"name": "search_items", "arguments": {}}))
    finally:
        rows = s.close()
    (r,) = _gate_rows(rows)
    assert r["outcome"] == "never_attempted" and r["verdict"] == "could_not_look"
    assert r["reason"].startswith("the gate could not run: ")
    assert r["rule"] == "mandate_file" and r["reason_word"] == "missing"


@pytest.mark.parametrize("enforce", [False, True], ids=["record-only", "enforce"])
@pytest.mark.parametrize("surface", SURFACES)
def test_mandate_that_vanishes_mid_run_is_never_attempted_with_its_reason(
        tmp_path, surface, enforce):
    work = tmp_path / surface
    work.mkdir()
    mandate = _mandate(tmp_path)
    s = OPEN[surface](work, mandate, enforce)
    try:
        first = s.send(_frame(1, {"name": "search_items", "arguments": {}}))
        assert "result" in first
        time.sleep(0.3)                  # record-only: call 1 is judged after it went out
        mandate.unlink()
        second = s.send(_frame(2, {"name": "search_more", "arguments": {}}))
    finally:
        rows = s.close()
    gate = _gate_rows(rows)
    assert [r["tool"] for r in gate] == ["search_more"], gate
    r = gate[0]
    assert r["outcome"] == "never_attempted" and r["verdict"] == "could_not_look"
    assert r["rule"] == "mandate_file" and r["reason_word"] == "missing"
    assert r["reason"].startswith("the gate could not run: the mandate file is missing")
    changed = [x for x in rows if x.get("evt") == "mandate_changed"]
    assert len(changed) == 1 and changed[0]["file_status"] == "missing"
    if enforce:
        assert second["error"]["code"] == -32001 and "search_more" not in s.received
    else:
        assert "result" in second and "search_more" in s.received


# -- never_attempted: refused before the gate --------------------------------------

@pytest.mark.parametrize("surface", ["stdio_proxy", "http_forward"])
def test_oversize_frame_under_enforce_is_refused_before_the_gate(tmp_path, surface):
    work = tmp_path / surface
    work.mkdir()
    s = OPEN[surface](work, _mandate(tmp_path), True, max_frame=400)
    big = _frame(1, {"name": "search_items", "arguments": {"q": "x" * 1000}})
    try:
        if surface == "stdio_proxy":
            # past the limit before any newline arrives: the frame cannot be held
            s.p.stdin.write(big)
            s.p.stdin.flush()
            time.sleep(0.5)
            got = s.send(b"", reply=False)
        else:
            got = s.send(big)
    finally:
        rows = s.close()
    (r,) = _gate_rows(rows)
    assert r["outcome"] == "never_attempted" and r["action"] == "blocked"
    assert r["reason"].startswith("refused before the gate: ")
    assert r["reason_word"] == "bounded"
    assert s.received == []
    if surface == "http_forward":
        assert got == {"http_status": 413}


@pytest.mark.parametrize("surface", ["http_forward", "call_proxy"])
def test_unparsed_request_under_enforce_is_refused_before_the_gate(tmp_path, surface):
    work = tmp_path / surface
    work.mkdir()
    s = OPEN[surface](work, _mandate(tmp_path), True)
    try:
        got = s.send(b"this is not json")
    finally:
        rows = s.close()
    (r,) = _gate_rows(rows)
    assert r["outcome"] == "never_attempted" and r["judged_reason"] == "unparsed"
    assert r["reason"].startswith("refused before the gate: ")
    assert got["error"]["code"] == -32001 and s.received == []


def test_unparsed_line_on_stdio_goes_through_so_it_is_could_not_look(tmp_path):
    """stdio forwards a non-JSON line byte-identical even under enforce, so it
    was not refused: it went through unjudged, and the word says so."""
    work = tmp_path / "stdio"
    work.mkdir()
    s = _Stdio(work, _mandate(tmp_path), True)
    try:
        s.send(b"this is not json", reply=False)
    finally:
        rows = s.close()
    (r,) = _gate_rows(rows)
    assert r["outcome"] == "could_not_look" and r["action"] == "forwarded"


# -- the evidence pack carries the drift count ------------------------------------

def test_pack_summary_carries_no_matching_mandate_and_the_outcomes(tmp_path):
    from arcaeon import verdict as V
    from arcaeon.prove.evidence_pack import MANDATE_ROWS, build_pack
    from arcaeon.prove.evidence_pack_verify import verify_pack
    s, _, rows, mandate = _run_script("stdio_proxy", tmp_path, False)
    out = tmp_path / "pack"
    res = build_pack(s.ledger, out, mandate=mandate)
    assert res["exit"] == 0, res
    sec = json.loads((out / MANDATE_ROWS).read_text(encoding="utf-8"))
    assert sec["no_matching_mandate"] == 2
    assert sec["outcomes"] == {"could_not_look": 1, "outside_forwarded": 3}
    assert sec["counts"] == {"inside": 1, "outside": 3, "could_not_look": 1}
    block = json.loads((out / "manifest.json").read_text(encoding="utf-8"))["mandate"]
    assert block["no_matching_mandate"] == 2
    assert block["outcomes"] == {"could_not_look": 1, "outside_forwarded": 3}
    v = verify_pack(out)
    assert v["verdict"] == V.VERIFIED, v
