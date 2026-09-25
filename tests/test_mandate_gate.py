"""The mandate gate: evaluate() unit cases, and the proxy's record-only,
enforce, unreadable and fingerprint behavior against the real _echo_server.

    pytest tests/test_mandate_gate.py -k evaluate
    pytest tests/test_mandate_gate.py -k record_only
    pytest tests/test_mandate_gate.py -k enforce
    pytest tests/test_mandate_gate.py -k unreadable
    pytest tests/test_mandate_gate.py -k fingerprint
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from arcaeon.record.adapter import mandate_gate as mg
from arcaeon.record.adapter._ledger import verify_seam_log
from arcaeon.record.deal import Deal

SRC = str(Path(__file__).resolve().parents[1] / "src")
ECHO = [sys.executable, "-m", "arcaeon.record.adapter._echo_server"]

MANDATE = {
    "who": "purchasing-agent@acme",
    "allowed_acts": ["echo", "big", "place_*"],
    "forbidden_acts": ["boom"],
    "spend_cap": {"amount": "60.00", "currency": "USD", "merchant": "acme-store"},
    "not_before": "2026-01-01T00:00:00Z",
    "not_after": "2099-12-31T00:00:00Z",
}
AT = "2026-09-25T12:00:00Z"


def _call(name, **args):
    return {"name": name, "arguments": args}


# -- evaluate ------------------------------------------------------------------

def test_evaluate_allowed_tool_is_inside():
    v, why = mg.evaluate(MANDATE, _call("echo", text="hi"), AT)
    assert v == mg.INSIDE, why


def test_evaluate_forbidden_tool_is_outside_even_if_allowed():
    m = dict(MANDATE, allowed_acts=["*"])
    v, why = mg.evaluate(m, _call("boom"), AT)
    assert v == mg.OUTSIDE and "forbidden_acts" in why


def test_evaluate_tool_not_in_allowed_list_is_outside():
    v, why = mg.evaluate(MANDATE, _call("quiet"), AT)
    assert v == mg.OUTSIDE and "allowed_acts" in why


def test_evaluate_empty_allowed_list_means_anything_not_forbidden():
    v, _ = mg.evaluate({"forbidden_acts": ["boom"]}, _call("quiet"), AT)
    assert v == mg.INSIDE


def test_evaluate_window_before_and_after():
    assert mg.evaluate(MANDATE, _call("echo"), "2025-06-01T00:00:00Z")[0] == mg.OUTSIDE
    assert mg.evaluate(MANDATE, _call("echo"), "2100-01-01T00:00:00Z")[0] == mg.OUTSIDE


def test_evaluate_spend_inside_cap_uses_deal_check_mandate():
    v, why = mg.evaluate(MANDATE, _call("place_order", total="19.00", currency="USD",
                                        seller="acme-store"), AT)
    assert v == mg.INSIDE, why
    assert "inside the mandate" in why   # deal.check_mandate's own sentence


def test_evaluate_spend_over_cap_wrong_currency_wrong_merchant():
    base = dict(currency="USD", seller="acme-store")
    assert mg.evaluate(MANDATE, _call("place_order", total="61.00", **base), AT)[0] \
        == mg.OUTSIDE
    v, why = mg.evaluate(MANDATE, _call("place_order", total="1", currency="EUR",
                                        seller="acme-store"), AT)
    assert v == mg.OUTSIDE and "currency" in why
    v, why = mg.evaluate(MANDATE, _call("place_order", total="1", currency="USD",
                                        seller="evil-shop"), AT)
    assert v == mg.OUTSIDE and "merchant" in why


def test_evaluate_unreadable_amount_is_could_not_look():
    gate = mg.MandateGate.from_dict(MANDATE)
    v, why, extra = gate.detail(_call("place_order", total="lots", currency="USD",
                                      seller="acme-store"), AT)
    assert v == mg.COULD_NOT_LOOK, why
    assert extra["reason_word"] == "unreadable"


def test_evaluate_missing_or_unreadable_mandate_is_could_not_look(tmp_path):
    missing = mg.load(tmp_path / "nope.json")
    assert missing.status == "missing"
    assert missing.evaluate(_call("echo"), AT)[0] == mg.COULD_NOT_LOOK
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    g = mg.load(bad)
    assert g.status == "unreadable" and g.file_sha256
    assert g.evaluate(_call("echo"), AT)[0] == mg.COULD_NOT_LOOK
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"allowed_acts": "echo"}), encoding="utf-8")
    assert mg.load(wrong).status == "unreadable"


def test_evaluate_no_tool_name_is_could_not_look():
    assert mg.evaluate(MANDATE, {"arguments": {}}, AT)[0] == mg.COULD_NOT_LOOK


def test_evaluate_reads_a_deal_lane_mandate_and_its_sealed_sidecar(tmp_path):
    sealed = tmp_path / "mandate.sealed.json"
    row = Deal(tmp_path / "buyer.jsonl", "buyer", "d-1").mandate(
        merchant="acme-store", cap="60.00", currency="USD",
        not_before="2026-01-01T00:00:00Z", not_after="2099-12-31T00:00:00Z",
        may=["place_order"], may_not=["refund"], sealed=sealed)
    gate = mg.load(sealed)
    assert gate.ok, gate.error
    call = _call("place_order", total="70.00", currency="USD", seller="acme-store")
    assert gate.evaluate(call, AT)[0] == mg.OUTSIDE
    assert gate.evaluate(_call("refund"), AT)[0] == mg.OUTSIDE
    # the body digest the proxy pins is the digest the deal row recorded
    body = json.loads(sealed.read_text(encoding="utf-8"))["mandate"]
    plain = tmp_path / "body.json"
    plain.write_text(json.dumps(body), encoding="utf-8")
    assert mg.load(plain).body_digest == row["mandate_digest"]


def test_evaluate_is_pure_and_returns_a_pair():
    out = mg.evaluate(MANDATE, _call("echo"), AT)
    assert isinstance(out, tuple) and len(out) == 2 and out[0] in mg.VERDICTS


# -- the proxy ---------------------------------------------------------------

def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    env.pop("ARCAEON_ADAPTER_SELFTEST_CORRUPT", None)
    return env


def _frame(mid, method, params=None):
    m = {"jsonrpc": "2.0", "id": mid, "method": method}
    if params is not None:
        m["params"] = params
    return json.dumps(m).encode()


STREAM = b"\n".join([
    _frame(1, "initialize", {"protocolVersion": "2025-06-18",
                             "clientInfo": {"name": "pytest", "version": "1"}}),
    _frame(2, "tools/list"),
    _frame(3, "tools/call", {"name": "echo", "arguments": {"text": "hello"}}),
    _frame(4, "tools/call", {"name": "boom", "arguments": {}}),
    _frame(5, "tools/call", {"name": "echo", "arguments": {"text": "after"}}),
]) + b"\n"


def _run(argv_extra, ledger, stream=STREAM, cmd=None):
    argv = [sys.executable, "-m", "arcaeon.record.adapter.proxy", "--ledger", str(ledger)]
    argv += list(argv_extra) + ["--"] + list(cmd or ECHO)
    return subprocess.run(argv, input=stream, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=_env(), timeout=120)


def _direct(stream=STREAM):
    return subprocess.run(ECHO, input=stream, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, env=_env(), timeout=120).stdout


def _rows(path):
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def _responses(out: bytes) -> dict:
    return {m["id"]: m for m in (json.loads(l) for l in out.splitlines() if l.strip())}


@pytest.fixture
def mandate_file(tmp_path):
    p = tmp_path / "mandate.json"
    p.write_text(json.dumps(MANDATE), encoding="utf-8")
    return p


def test_record_only_outside_call_is_forwarded_and_rowed(tmp_path, mandate_file):
    ledger = tmp_path / "seam.jsonl"
    p = _run(["--mandate", str(mandate_file)], ledger)
    assert p.returncode == 0, p.stderr
    # still forwarded: byte-identical to the unproxied control
    assert p.stdout == _direct()
    rows = _rows(ledger)
    outside = [r for r in rows if r["evt"] == "mandate_outside"]
    assert len(outside) == 1, rows
    o = outside[0]
    assert o["tool"] == "boom" and o["rule"] == "forbidden_acts"
    assert o["action"] == "forwarded" and o["mandate_mode"] == "record-only"
    assert o["who"] == MANDATE["who"] and o["rpc_id"] == "4"
    # the boom call still got its ordinary tool_call row
    assert [r["tool"] for r in rows if r["evt"] == "tool_call"] == ["echo", "boom", "echo"]
    end = rows[-1]
    assert end["evt"] == "session_end"
    assert end["mandate_inside"] == 2 and end["mandate_outside"] == 1
    assert "mandate_blocked" not in end
    assert verify_seam_log(ledger).ok is True


def test_record_only_is_the_default_without_the_enforce_flag(tmp_path, mandate_file):
    ledger = tmp_path / "seam.jsonl"
    _run(["--mandate", str(mandate_file)], ledger)
    assert _rows(ledger)[0]["mandate_mode"] == "record-only"


def test_enforce_outside_call_gets_a_jsonrpc_error_and_a_row(tmp_path, mandate_file):
    ledger = tmp_path / "seam.jsonl"
    p = _run(["--mandate", str(mandate_file), "--mandate-enforce"], ledger)
    assert p.returncode == 0, p.stderr
    resp = _responses(p.stdout)
    assert resp[4]["error"]["code"] == -32001
    assert "mandate" in resp[4]["error"]["message"]
    # the inside calls went through untouched, in order, around the block
    assert resp[3]["result"]["content"][0]["text"] == "hello"
    assert resp[5]["result"]["content"][0]["text"] == "after"
    # every request answered exactly once, each line a whole frame (the proxy's
    # own answer may arrive before the server's: JSON-RPC pairs by id)
    ids = [json.loads(l)["id"] for l in p.stdout.splitlines()]
    assert sorted(ids) == [1, 2, 3, 4, 5]
    rows = _rows(ledger)
    assert rows[0]["mandate_mode"] == "enforce"
    o = [r for r in rows if r["evt"] == "mandate_outside"]
    assert len(o) == 1 and o[0]["action"] == "blocked" and o[0]["tool"] == "boom"
    calls = {r["rpc_id"]: r for r in rows if r["evt"] == "tool_call"}
    assert calls["4"]["status"] == "error"          # the attempt and the answer, paired
    assert rows[-1]["mandate_blocked"] == 1
    assert verify_seam_log(ledger).ok is True


def test_enforce_inside_only_stream_is_byte_identical(tmp_path, mandate_file):
    stream = b"\n".join([_frame(1, "tools/call", {"name": "echo", "arguments": {"text": "a"}}),
                         b"not json at all",
                         _frame(2, "tools/call", {"name": "big", "arguments": {"n": 300000}}),
                         _frame(3, "tools/call", {"name": "echo", "arguments": {"text": "z"}})])
    ledger = tmp_path / "seam.jsonl"
    p = _run(["--mandate", str(mandate_file), "--mandate-enforce"], ledger, stream=stream)
    assert p.stdout == _direct(stream)


def test_enforce_injected_error_waits_for_a_frame_boundary():
    """A server frame arriving in two chunks must not have the proxy's error
    reply spliced into its middle."""
    import io
    from arcaeon.record.adapter.proxy import _AlignedWriter
    sink = io.BytesIO()
    w = _AlignedWriter(sink)
    w.write(b'{"id":1,"res')
    w.inject(b'{"id":9,"error":{}}\n')
    assert sink.getvalue() == b'{"id":1,"res'      # held
    w.write(b'ult":1}\n')
    assert sink.getvalue() == b'{"id":1,"result":1}\n{"id":9,"error":{}}\n'
    w.inject(b'{"id":10}\n')                           # at a boundary: goes now
    assert sink.getvalue().endswith(b'{"id":10}\n')


def test_enforce_is_off_by_default_nothing_blocked(tmp_path, mandate_file):
    ledger = tmp_path / "seam.jsonl"
    p = _run(["--mandate", str(mandate_file)], ledger)
    assert "error" not in _responses(p.stdout)[4]


def test_enforce_without_mandate_is_a_usage_error(tmp_path):
    p = _run(["--mandate-enforce"], tmp_path / "seam.jsonl")
    assert p.returncode == 2


def test_unreadable_mandate_record_only_rows_every_call_never_blocks(tmp_path):
    bad = tmp_path / "mandate.json"
    bad.write_text("{nope", encoding="utf-8")
    ledger = tmp_path / "seam.jsonl"
    p = _run(["--mandate", str(bad)], ledger)
    assert p.returncode == 0
    assert p.stdout == _direct()
    rows = _rows(ledger)
    assert rows[0]["mandate_status"] == "unreadable"
    cnl = [r for r in rows if r["evt"] == "mandate_could_not_look"]
    assert len(cnl) == 3, rows
    assert all(r["action"] == "forwarded" and r["reason_word"] == "unreadable" for r in cnl)


def test_missing_mandate_record_only_rows_every_call(tmp_path):
    ledger = tmp_path / "seam.jsonl"
    p = _run(["--mandate", str(tmp_path / "absent.json")], ledger)
    assert p.returncode == 0 and p.stdout == _direct()
    cnl = [r for r in _rows(ledger) if r["evt"] == "mandate_could_not_look"]
    assert len(cnl) == 3 and all(r["reason_word"] == "missing" for r in cnl)


@pytest.mark.parametrize("kind", ["missing", "unreadable"])
def test_unreadable_or_missing_mandate_enforce_refuses_to_start_exit_3(tmp_path, kind):
    path = tmp_path / "mandate.json"
    if kind == "unreadable":
        path.write_text("[1, 2", encoding="utf-8")
    ledger = tmp_path / "seam.jsonl"
    p = _run(["--mandate", str(path), "--mandate-enforce"], ledger)
    assert p.returncode == 3, p.stderr
    assert p.stdout == b""                      # the server never started
    assert b"refus" in p.stderr
    rows = _rows(ledger)
    assert rows[-1]["evt"] == "session_end" and rows[-1]["reason"] == "mandate_unreadable"


def test_fingerprint_first_row_records_sha256_of_the_mandate_file(tmp_path, mandate_file):
    ledger = tmp_path / "seam.jsonl"
    _run(["--mandate", str(mandate_file)], ledger)
    first = _rows(ledger)[0]
    assert first["evt"] == "session_begin"
    want = hashlib.sha256(mandate_file.read_bytes()).hexdigest()
    assert first["mandate_file_sha256"] == want
    assert first["mandate_file_digest"] == "sha256:raw-bytes:v1:" + want
    assert first["mandate_status"] == "loaded"


def test_fingerprint_changes_when_the_mandate_file_changes(tmp_path, mandate_file):
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    _run(["--mandate", str(mandate_file)], a)
    mandate_file.write_text(json.dumps(dict(MANDATE, forbidden_acts=[])), encoding="utf-8")
    _run(["--mandate", str(mandate_file)], b)
    assert _rows(a)[0]["mandate_file_sha256"] != _rows(b)[0]["mandate_file_sha256"]
