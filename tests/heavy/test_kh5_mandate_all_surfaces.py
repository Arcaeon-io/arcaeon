"""KH5: the mandate gate on every surface, end to end.

One six-call script (two inside, two outside, one over the session total, one
the gate cannot judge) runs through each of the three surfaces that take a
mandate:

    stdio_proxy   arcaeon.record.adapter.proxy, a real subprocess over a stub child
    http_forward  arcaeon.record.adapter.http_forward, over a loopback stub upstream
    call_proxy    arcaeon.record.receipt.call_proxy, over the same kind of stub

first record-only, then enforce. The gate's rows from all three ledgers must
agree row for row: same events, same verdicts, same judged reasons, same
actions, same order. Then the enforce differences are asserted by name: every
call the gate did not find inside is answered by the gate (JSON-RPC -32001)
and never reaches the tool, and only the inside calls count toward the spend.

THE NORMALIZATION (the only things removed before rows are compared):
  1. VOLATILE: per-session ids, per-row timestamps, chain links and the
     JSON-RPC id the agent chose. Never compared.
  2. SURFACE_LABEL: `seam`, `seam_impl`, `server`, the stamp saying WHICH
     surface wrote the row. Taken out of the cross-surface comparison but
     asserted on its own: every row of a ledger carries its own surface's seam.
  3. A key whose value is None is the same as a key that is absent (the row
     writer leaves None fields out).
Every other key the gate wrote is compared, including the reason text, the
rule, the args digest, the mandate path and sha256, and the spend figures.

Only loopback stubs this test starts and stops. ARCAEON_HOME points into
tmp_path, so the session-end hook (K077) writes there and never to ~/.arcaeon.
"""
from __future__ import annotations

import http.client
import json
import os
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
SRC = str(HERE.parents[1] / "src")
STUB = str(HERE / "kh5_stub_tool.py")
sys.path.insert(0, str(HERE))
import kh5_stub_tool  # noqa: E402  the fixture sits next to this file

MANDATE = {
    "who": "kh5-agent",
    "allowed_acts": ["search_*", "get_quote", "place_order"],
    "forbidden_acts": ["delete_*", "refund"],
    "spend_cap": {"amount": "15.00", "total": "20.00", "currency": "USD"},
}

#: (what the call is, tools/call params). JSON-RPC ids are 1..6 in this order.
SCRIPT = [
    ("inside", {"name": "search_items", "arguments": {"q": "desk lamp"}}),
    ("outside", {"name": "refund", "arguments": {"order": "A-100"}}),
    ("inside", {"name": "place_order", "arguments": {"total": "12.00", "currency": "USD"}}),
    ("outside", {"name": "send_email", "arguments": {"to": "someone@example.test"}}),
    ("over_total", {"name": "place_order", "arguments": {"total": "9.00", "currency": "USD"}}),
    ("unjudgeable", {"name": "place_order", "arguments": {"total": "lots", "currency": "USD"}}),
]
IDS = list(range(1, len(SCRIPT) + 1))
INSIDE_IDS = [i for i, (kind, _) in zip(IDS, SCRIPT) if kind == "inside"]
HELD_IDS = [i for i in IDS if i not in INSIDE_IDS]

#: Removed before comparing rows across surfaces: ids, timestamps, chain links.
VOLATILE = frozenset({"ts", "t", "time", "seq", "chain", "prev", "prev_chain", "hash",
                      "session", "session_id", "rpc_id", "row_id", "id"})

#: Which surface wrote a row: asserted per surface, not compared across them.
SURFACE_LABEL = frozenset({"seam", "seam_impl", "server"})
SEAM_OF = {"stdio_proxy": "mcp-stdio", "http_forward": "mcp-http", "call_proxy": "call-proxy"}

#: The event each non-inside call must be written as, in script order.
WANT_EVENTS = ["mandate_loaded", "mandate_outside", "mandate_outside",
               "mandate_cap_exceeded", "mandate_could_not_look"]


def _frames() -> list[dict]:
    return [{"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": p}
            for i, (_, p) in zip(IDS, SCRIPT)]


@dataclass
class Run:
    replies: dict               # JSON-RPC id -> the message the agent got back
    received: list              # tool names the stub tool actually received, in order
    rows: list                  # every row of the surface's mandate-bearing ledger
    extra: dict = field(default_factory=dict)


def _read_rows(path) -> list:
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def _post(port: int, path: str, frame: dict) -> dict:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        c.request("POST", path, body=json.dumps(frame).encode(),
                  headers={"Content-Type": "application/json"})
        return json.loads(c.getresponse().read())
    finally:
        c.close()


# -- the three surfaces -------------------------------------------------------

def run_stdio(work: Path, mandate: Path, enforce: bool, home: Path) -> Run:
    ledger = work / "stdio.seam.jsonl"
    received = work / "stdio.received.txt"
    received.write_text("", encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    env["ARCAEON_HOME"] = str(home)
    env.pop("ARCAEON_JOURNAL", None)
    env.pop("ARCAEON_ADAPTER_SELFTEST_CORRUPT", None)
    argv = [sys.executable, "-m", "arcaeon.record.adapter.proxy", "--ledger", str(ledger),
            "--mandate", str(mandate)]
    if enforce:
        argv.append("--mandate-enforce")
    stdin = b"".join(json.dumps(f).encode() + b"\n" for f in _frames())
    p = subprocess.run(argv + ["--", sys.executable, STUB, str(received)], input=stdin,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, timeout=120)
    assert p.returncode == 0, p.stderr.decode("utf-8", "replace")
    replies = {}
    for line in p.stdout.splitlines():
        if line.strip():
            msg = json.loads(line)
            replies[msg["id"]] = msg
    names = [x for x in received.read_text(encoding="utf-8").splitlines() if x]
    return Run(replies, names, _read_rows(ledger))


def run_http_forward(work: Path, mandate: Path, enforce: bool, home: Path) -> Run:
    from arcaeon.record.adapter import http_forward as HF
    ledger = work / "http.seam.jsonl"
    up = kh5_stub_tool.HttpStub()
    try:
        srv = HF.build_forward_server(up.url, ledger_path=ledger, mandate_path=mandate,
                                      mandate_enforce=enforce).start()
        try:
            replies = {f["id"]: _post(srv.port, "/", f) for f in _frames()}
        finally:
            srv.close()
    finally:
        up.close()
    return Run(replies, list(up.received), _read_rows(ledger))


def run_call_proxy(work: Path, mandate: Path, enforce: bool, home: Path) -> Run:
    from arcaeon.record.receipt import call_proxy
    log = work / "call.mandate.jsonl"
    up = kh5_stub_tool.HttpStub()
    try:
        srv = call_proxy.build_server(
            listen="127.0.0.1:0", upstream=up.base, seller="kh5",
            ledger_path=work / "calls.log.jsonl", witness=False,
            mandate_path=mandate, mandate_enforce=enforce, mandate_log=log)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            replies = {f["id"]: _post(srv.server_address[1], "/mcp", f) for f in _frames()}
        finally:
            srv.shutdown()
            srv.server_close()
            srv.mandate_close()
            t.join(timeout=10)
    finally:
        up.close()
    return Run(replies, list(up.received), _read_rows(log),
               {"receipts": _read_rows(work / "calls.log.jsonl")})


SURFACES = {"stdio_proxy": run_stdio, "http_forward": run_http_forward,
            "call_proxy": run_call_proxy}


# -- normalization ------------------------------------------------------------

def gate_rows(rows: list) -> list:
    """The gate's own rows (every `mandate_*` event), in ledger order, with the
    VOLATILE keys removed. This is the stated normalization, nothing more."""
    return [{k: v for k, v in r.items()
             if k not in VOLATILE and k not in SURFACE_LABEL and v is not None}
            for r in rows if str(r.get("evt", "")).startswith("mandate_")]


def _drop_none(d: dict) -> dict:
    return {k: v for k, v in d.items() if v is not None}


def end_counts(rows: list) -> dict:
    """The mandate fields of the session_end row."""
    ends = [r for r in rows if r.get("evt") == "session_end"]
    assert len(ends) == 1, f"expected one session_end, got {len(ends)}"
    return {k: v for k, v in ends[0].items() if k.startswith("mandate_") and v is not None}


def begin_mandate(rows: list) -> dict:
    begin = rows[0]
    assert begin["evt"] == "session_begin"
    return {k: begin.get(k) for k in ("mandate_mode", "mandate_status",
                                      "mandate_file_sha256", "mandate_body_digest",
                                      "mandate_who")}


# -- the runs (each mode once, all three surfaces, shared across the tests) ---

@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    base = tmp_path_factory.mktemp("kh5")
    home = base / "arcaeon-home"
    mandate = base / "mandate.json"
    mandate.write_text(json.dumps(MANDATE, indent=2) + "\n", encoding="utf-8")
    saved = {k: os.environ.get(k) for k in ("ARCAEON_HOME", "ARCAEON_JOURNAL")}
    os.environ["ARCAEON_HOME"] = str(home)
    os.environ.pop("ARCAEON_JOURNAL", None)
    out = {}
    try:
        for mode in ("record-only", "enforce"):
            for name, runner in SURFACES.items():
                work = base / mode / name
                work.mkdir(parents=True)
                out[(mode, name)] = runner(work, mandate, mode == "enforce", home)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    out["home"] = home
    out["mandate"] = mandate
    return out


# -- record-only --------------------------------------------------------------

@pytest.mark.parametrize("surface", sorted(SURFACES))
def test_record_only_forwards_all_six_and_answers_with_the_tool(runs, surface):
    r = runs[("record-only", surface)]
    assert r.received == [p["name"] for _, p in SCRIPT], "a call never reached the tool"
    for i, (_, p) in zip(IDS, SCRIPT):
        msg = r.replies[i]
        assert "error" not in msg, f"{surface}: record-only withheld call {i}: {msg}"
        assert msg["result"]["content"][0]["text"] == f"ran {p['name']}"


@pytest.mark.parametrize("surface", sorted(SURFACES))
def test_record_only_rows_name_each_call_the_gate_did_not_find_inside(runs, surface):
    rows = gate_rows(runs[("record-only", surface)].rows)
    assert [r["evt"] for r in rows] == WANT_EVENTS
    judged = rows[1:]
    assert [r["tool"] for r in judged] == ["refund", "send_email", "place_order",
                                           "place_order"]
    assert [r["rule"] for r in judged] == ["forbidden_acts", "allowed_acts",
                                           "spend_cap.total", "spend_cap"]
    assert [r["verdict"] for r in judged] == ["outside", "outside", "outside",
                                              "could_not_look"]
    assert all(r["mandate_mode"] == "record-only" for r in rows)
    assert all(r["action"] == "forwarded" for r in judged)
    cap = judged[2]
    assert (cap["amount"], cap["session_spent_before"], cap["session_spent"],
            cap["session_total_cap"]) == ("9.00", "12.00", "21.00", "20.00")
    assert judged[3]["reason_word"] == "unreadable"
    assert end_counts(runs[("record-only", surface)].rows) == _drop_none({
        "mandate_inside": 2, "mandate_outside": 3, "mandate_could_not_look": 1,
        "mandate_blocked": None, "mandate_cap_exceeded": 1, "mandate_changes": None,
        "mandate_spent": "21.00"})


# -- the heart of KH5: three ledgers, one story ---------------------------------

@pytest.mark.parametrize("mode", ["record-only", "enforce"])
def test_three_ledgers_agree_row_for_row(runs, mode):
    ref_name = "stdio_proxy"
    ref = gate_rows(runs[(mode, ref_name)].rows)
    assert len(ref) == len(WANT_EVENTS)
    for name in sorted(SURFACES):
        got = gate_rows(runs[(mode, name)].rows)
        assert len(got) == len(ref), f"{mode}: {name} has {len(got)} gate rows, " \
                                     f"{ref_name} has {len(ref)}"
        for n, (a, b) in enumerate(zip(ref, got)):
            assert a == b, f"{mode}: gate row {n} differs, {ref_name} vs {name}:\n" \
                           f"{a}\n{b}"
        assert end_counts(runs[(mode, name)].rows) == end_counts(runs[(mode, ref_name)].rows)
        assert begin_mandate(runs[(mode, name)].rows) == \
            begin_mandate(runs[(mode, ref_name)].rows)


def test_the_normalization_removes_only_ids_and_times(runs):
    """Every key a gate row carries, except VOLATILE, is part of the comparison:
    the reason text, the rule and the args digest are compared, not skipped."""
    raw = [r for r in runs[("record-only", "call_proxy")].rows
           if str(r.get("evt", "")).startswith("mandate_")]
    kept = gate_rows(runs[("record-only", "call_proxy")].rows)
    for a, b in zip(raw, kept):
        assert set(a) - set(b) <= VOLATILE | SURFACE_LABEL | {
            k for k, v in a.items() if v is None}
    judged = kept[1:]
    for key in ("reason", "rule", "verdict", "action", "args_digest", "tool",
                "mandate_file_sha256"):
        assert all(key in r for r in judged), f"{key} is not compared"
    # The comparison is not vacuous: the four judged rows are all different.
    assert len({json.dumps(r, sort_keys=True) for r in judged}) == 4


@pytest.mark.parametrize("mode", ["record-only", "enforce"])
@pytest.mark.parametrize("surface", sorted(SURFACES))
def test_each_ledger_is_stamped_by_its_own_surface(runs, mode, surface):
    """The surface label the comparison sets aside: one seam per ledger, and
    it is the surface's own, so three agreeing ledgers are three writers."""
    rows = runs[(mode, surface)].rows
    seams = {r.get("seam") for r in rows}
    assert len(seams) == 1, seams
    assert seams == {SEAM_OF[surface]}
    assert all(runs[(mode, other)].rows[0].get("seam") != rows[0].get("seam")
               for other in SURFACES if other != surface)


# -- enforce, and exactly how it differs ----------------------------------------

@pytest.mark.parametrize("surface", sorted(SURFACES))
def test_enforce_answers_held_calls_itself_and_never_forwards_them(runs, surface):
    r = runs[("enforce", surface)]
    assert r.received == ["search_items", "place_order"], \
        f"{surface}: enforce forwarded a call the gate did not find inside: {r.received}"
    for i in INSIDE_IDS:
        name = SCRIPT[i - 1][1]["name"]
        assert r.replies[i]["result"]["content"][0]["text"] == f"ran {name}"
    want_verdict = {2: "outside", 4: "outside", 5: "outside", 6: "could_not_look"}
    for i in HELD_IDS:
        msg = r.replies[i]
        assert "result" not in msg, f"{surface}: call {i} got a tool answer under enforce"
        assert msg["error"]["code"] == -32001
        assert msg["error"]["data"] == {"mandate": want_verdict[i]}
        assert msg["error"]["message"].startswith("blocked by mandate")


@pytest.mark.parametrize("surface", sorted(SURFACES))
def test_enforce_rows_are_the_record_only_rows_with_the_stated_differences(runs, surface):
    """Same calls, same verdicts, same reasons, same order. What moves under
    enforce, and only that: the mode, the action (blocked), and the cap row's
    running total, because a blocked spend never ran and never counts."""
    ro = gate_rows(runs[("record-only", surface)].rows)
    en = gate_rows(runs[("enforce", surface)].rows)
    expect = []
    for row in ro:
        row = dict(row, mandate_mode="enforce")
        if row["evt"] != "mandate_loaded":
            row["action"] = "blocked"
        if row["evt"] == "mandate_cap_exceeded":
            row["session_spent"] = None
        expect.append(_drop_none(row))
    assert en == expect
    assert end_counts(runs[("enforce", surface)].rows) == _drop_none({
        "mandate_inside": 2, "mandate_outside": 3, "mandate_could_not_look": 1,
        "mandate_blocked": 4, "mandate_cap_exceeded": 1, "mandate_changes": None,
        "mandate_spent": "12.00"})
    assert begin_mandate(runs[("enforce", surface)].rows)["mandate_mode"] == "enforce"
    assert begin_mandate(runs[("record-only", surface)].rows)["mandate_mode"] == "record-only"


def test_call_proxy_writes_receipts_only_for_what_it_forwarded(runs):
    """call_proxy's receipt ledger is the other half of 'never forwarded': a
    held call got no receipt, because it never reached the upstream."""
    ro = runs[("record-only", "call_proxy")].extra["receipts"]
    en = runs[("enforce", "call_proxy")].extra["receipts"]
    assert len(ro) == len(SCRIPT)
    assert len(en) == len(INSIDE_IDS)


# -- the session-end hook stayed in the temp home --------------------------------

def test_session_end_hook_wrote_only_into_the_temp_home(runs):
    from arcaeon import status
    home = runs["home"]
    rows = _read_rows(home / status.MANDATE_FILENAME)
    assert len(rows) == 2 * len(SURFACES), rows
    assert sorted(r["mode"] for r in rows) == ["enforce"] * 3 + ["record-only"] * 3
    sha = __import__("hashlib").sha256(runs["mandate"].read_bytes()).hexdigest()
    assert all(r["mandate_file_sha256"] == sha for r in rows)
