"""K073: the session spend total (`spend_cap.total`), record-only by default.

    pytest tests/test_mandate_total.py

Unit cases on the gate (evaluate stays pure; only add_spend moves the total),
then the stdio proxy end to end against the real _echo_server: a session that
crosses the total writes `mandate_cap_exceeded`, forwards the call (record-only)
and reports the total in session_end; under --mandate-enforce the crossing call
is blocked and adds nothing.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import pytest

from arcaeon.record.adapter import mandate_gate as mg
from arcaeon.record.adapter._ledger import verify_seam_log

SRC = str(Path(__file__).resolve().parents[1] / "src")
ECHO = [sys.executable, "-m", "arcaeon.record.adapter._echo_server"]
AT = "2026-09-27T12:00:00Z"

MANDATE = {
    "who": "purchasing-agent@acme",
    "allowed_acts": ["echo", "place_*"],
    "spend_cap": {"amount": "60.00", "total": "100.00", "currency": "USD",
                  "merchant": "acme-store"},
}


def _spend(total, **extra):
    return {"name": "place_order",
            "arguments": {"total": total, "currency": "USD", "seller": "acme-store", **extra}}


# -- the gate ------------------------------------------------------------------

def test_evaluate_is_pure_and_total_moves_only_by_add_spend():
    gate = mg.MandateGate.from_dict(MANDATE)
    for _ in range(5):
        assert gate.evaluate(_spend("50.00"), AT)[0] == mg.INSIDE
    assert gate.spent == Decimal(0)
    assert gate.add_spend("50.00") == Decimal("50.00")
    assert gate.evaluate(_spend("50.00"), AT)[0] == mg.INSIDE      # exactly at the total
    gate.add_spend("50.00")
    v, why, extra = gate.detail(_spend("0.01"), AT)
    assert v == mg.OUTSIDE
    assert extra["rule"] == "spend_cap.total" and extra["evt"] == mg.CAP_EXCEEDED_EVT
    assert extra["session_spent_before"] == "100.00"
    assert extra["session_total_cap"] == "100.00"
    assert extra["spend_amount"] == "0.01"
    assert "100.00" in why


def test_per_call_cap_unchanged_and_checked_first():
    gate = mg.MandateGate.from_dict(MANDATE)
    v, why, extra = gate.detail(_spend("61.00"), AT)
    assert v == mg.OUTSIDE and extra["rule"] == "spend_cap"
    assert "evt" not in extra


def test_no_total_means_no_running_total():
    m = {"spend_cap": {"amount": "60.00", "currency": "USD"}}
    gate = mg.MandateGate.from_dict(m)
    for _ in range(10):
        gate.add_spend("60.00")
    assert gate.total_cap is None
    v, _, extra = gate.detail({"name": "buy", "arguments": {"total": "60.00",
                                                             "currency": "USD"}}, AT)
    assert v == mg.INSIDE and extra["rule"] == "spend_cap"


def test_total_without_per_call_amount_caps_one_call_at_the_total():
    m = {"spend_cap": {"total": "100.00", "currency": "USD"}}
    gate = mg.MandateGate.from_dict(m)
    call = lambda t: {"name": "buy", "arguments": {"total": t, "currency": "USD"}}
    assert gate.evaluate(call("100.00"), AT)[0] == mg.INSIDE
    assert gate.evaluate(call("100.01"), AT)[0] == mg.OUTSIDE


def test_unreadable_total_makes_the_mandate_unreadable(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"spend_cap": {"amount": "5", "total": "lots"}}), encoding="utf-8")
    gate = mg.load(p)
    assert gate.status == "unreadable" and "spend_cap.total" in gate.error
    assert gate.evaluate(_spend("1"), AT)[0] == mg.COULD_NOT_LOOK


def test_unreadable_amount_adds_nothing():
    gate = mg.MandateGate.from_dict(MANDATE)
    assert gate.add_spend("lots") == Decimal(0)


# -- the stdio proxy -----------------------------------------------------------

def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    env.pop("ARCAEON_ADAPTER_SELFTEST_CORRUPT", None)
    return env


def _run(tmp_path, totals, enforce=False):
    mandate = tmp_path / "mandate.json"
    mandate.write_text(json.dumps(MANDATE), encoding="utf-8")
    ledger = tmp_path / "seam.jsonl"
    frames = b"".join(
        json.dumps({"jsonrpc": "2.0", "id": i + 1, "method": "tools/call",
                    "params": {"name": "echo", "arguments": {
                        "text": f"t{i}", "total": t, "currency": "USD",
                        "seller": "acme-store"}}}).encode() + b"\n"
        for i, t in enumerate(totals))
    argv = [sys.executable, "-m", "arcaeon.record.adapter.proxy", "--ledger", str(ledger),
            "--mandate", str(mandate)]
    if enforce:
        argv.append("--mandate-enforce")
    p = subprocess.run(argv + ["--"] + ECHO, input=frames, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, env=_env(), timeout=120)
    replies = [json.loads(x) for x in p.stdout.splitlines() if x.strip()]
    rows = [json.loads(x) for x in ledger.read_text(encoding="utf-8").splitlines()
            if x.strip()]
    return replies, rows, ledger


def test_record_only_crossing_writes_cap_exceeded_and_forwards(tmp_path):
    replies, rows, ledger = _run(tmp_path, ["40.00", "40.00", "40.00", "5.00"])
    assert len(replies) == 4 and all("error" not in r for r in replies)
    over = [r for r in rows if r["evt"] == "mandate_cap_exceeded"]
    assert [r["rpc_id"] for r in over] == ["3", "4"]
    first = over[0]
    assert first["verdict"] == "outside" and first["rule"] == "spend_cap.total"
    assert first["action"] == "forwarded" and first["mandate_mode"] == "record-only"
    assert first["amount"] == "40.00"
    assert first["session_spent_before"] == "80.00"
    assert first["session_spent"] == "120.00"
    assert first["session_total_cap"] == "100.00"
    assert not [r for r in rows if r["evt"] == "mandate_outside"]
    end = rows[-1]
    assert end["evt"] == "session_end"
    assert end["mandate_cap_exceeded"] == 2 and end["mandate_spent"] == "125.00"
    assert end["mandate_inside"] == 2 and end["mandate_outside"] == 2
    assert not end.get("mandate_blocked")
    assert verify_seam_log(ledger).ok is True


def test_enforce_blocks_the_crossing_call_and_it_adds_nothing(tmp_path):
    replies, rows, _ = _run(tmp_path, ["40.00", "40.00", "40.00", "20.00"], enforce=True)
    by_id = {r["id"]: r for r in replies}
    assert "error" in by_id[3] and by_id[3]["error"]["code"] == -32001
    assert "error" not in by_id[4]                       # 80 + 20 = 100, at the total
    over = [r for r in rows if r["evt"] == "mandate_cap_exceeded"]
    assert len(over) == 1 and over[0]["action"] == "blocked"
    assert over[0].get("session_spent") is None
    end = rows[-1]
    assert end["mandate_spent"] == "100.00" and end["mandate_blocked"] == 1


def test_session_without_total_has_no_spent_field(tmp_path):
    mandate = tmp_path / "m.json"
    mandate.write_text(json.dumps({"allowed_acts": ["echo"]}), encoding="utf-8")
    ledger = tmp_path / "s.jsonl"
    frame = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "echo", "arguments": {"text": "x"}}}
    subprocess.run([sys.executable, "-m", "arcaeon.record.adapter.proxy", "--ledger",
                    str(ledger), "--mandate", str(mandate), "--"] + ECHO,
                   input=json.dumps(frame).encode() + b"\n", stdout=subprocess.PIPE,
                   stderr=subprocess.PIPE, env=_env(), timeout=120)
    end = [json.loads(x) for x in ledger.read_text(encoding="utf-8").splitlines()][-1]
    assert end["evt"] == "session_end" and end.get("mandate_spent") is None
    assert not end.get("mandate_cap_exceeded")


@pytest.fixture(autouse=True)
def _arcaeon_home(tmp_path, monkeypatch):
    """A gated session appends its counts under ARCAEON_HOME (K077); keep a
    test's sessions out of the real ~/.arcaeon."""
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arc_home"))
