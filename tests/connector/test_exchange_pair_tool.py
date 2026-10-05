"""L3-RECON: the MCP tool `exchange_pair_reconcile`.

    pytest tests/connector/test_exchange_pair_tool.py

Import only: it answers what arcaeon.prove.exchange_log.pair returns (the
four disagreement classes included), with `exit`, and leaves exactly one
call-record row. Bad usage (a negative window) is a tool error. Throwaway
keys in tmp_path; no network.
"""
from __future__ import annotations

import asyncio
import base64
import json
import secrets
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("mcp", reason="the connector IS an MCP server")
pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

from mcp import Client  # noqa: E402

from arcaeon import verdict as V  # noqa: E402
from arcaeon.mcp.server import (  # noqa: E402
    ALL_TOOLS,
    EXCHANGE_TOOLS,
    FREE_TOOLS,
    build_server,
    verify_call_record,
)
from arcaeon.prove import exchange_log as X  # noqa: E402
from arcaeon.record.ledger import Ledger  # noqa: E402

T0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("ARCAEON_LEDGER_LOG", str(tmp_path / "agent.log.jsonl"))
    monkeypatch.setenv("ARCAEON_LEDGER_NS_DIR", str(tmp_path / "ledgers"))
    monkeypatch.setenv("MCP_VET_AUDIT_LEDGER", str(tmp_path / "vet_audit.jsonl"))
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(tmp_path / "arcaeon.calls.jsonl"))
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    return tmp_path / "arcaeon.calls.jsonl"


def _key(tmp_path, name):
    from arcaeon.prove.vet import receipts as R
    seed = secrets.token_bytes(32)
    p = tmp_path / f"{name}.key"
    p.write_text(base64.b64encode(seed).decode("ascii") + "\n", encoding="ascii")
    return p, R.did_key(R.public_key_from_seed(seed))


@pytest.fixture
def logs(tmp_path):
    ka, da = _key(tmp_path, "a")
    kb, db = _key(tmp_path, "b")
    f = tmp_path / "deliverable.csv"
    f.write_bytes(b"id,grade\n1,A\n")
    la, lb = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    for log, key, other, ex, word, at in (
            (la, ka, db, "ex-1", V.VERIFIED, T0), (lb, kb, da, "ex-1", V.BROKEN, T0),
            (la, ka, db, "ex-2", V.VERIFIED, T0),
            (lb, kb, da, "ex-2", V.VERIFIED, T0 + timedelta(seconds=120)),
            (la, ka, db, "ex-3", V.VERIFIED, T0)):
        X.react(log, key_file=key, exchange_id=ex, counterparty=other, file=f,
                reaction=word, at=at)
    return la, lb


def _session(calls):
    async def go():
        out = []
        async with Client(build_server()) as client:
            names = sorted(t.name for t in (await client.list_tools()).tools)
            for tool, args in calls:
                res = await client.call_tool(tool, args)
                sc = res.structured_content
                if sc is not None:
                    payload = sc.get("result", sc) if isinstance(sc, dict) else sc
                else:
                    text = "".join(getattr(c, "text", "") for c in res.content)
                    try:
                        payload = json.loads(text)
                    except ValueError:
                        payload = text
                out.append((bool(res.is_error), payload))
        return names, out
    return asyncio.run(go())


def _one(tool, args):
    return _session([(tool, args)])[1][0]


def test_the_tool_is_listed_and_free(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    names, _ = _session([])
    assert EXCHANGE_TOOLS == ("exchange_pair_reconcile",)
    assert "exchange_pair_reconcile" in names and names == sorted(ALL_TOOLS)
    assert "exchange_pair_reconcile" in FREE_TOOLS


def test_answers_what_pair_returns_with_classes(monkeypatch, tmp_path, logs):
    _isolate(monkeypatch, tmp_path)
    la, lb = logs
    err, got = _one("exchange_pair_reconcile", {"log_a": str(la), "log_b": str(lb)})
    assert not err, got
    lib = X.pair(la, lb)
    assert got["verdict"] == lib["verdict"] == V.VERIFIED and got["exit"] == 0
    assert got["disagreements"] == lib["disagreements"] == {
        "missing": 1, "mismatched": 1, "late": 0, "retracted": 0}
    assert [e["disagreement"] for e in got["exchanges"]] == ["mismatched", None, "missing"]
    assert got["late_after"] == X.DEFAULT_LATE_AFTER


def test_one_exchange_and_a_window(monkeypatch, tmp_path, logs):
    _isolate(monkeypatch, tmp_path)
    la, lb = logs
    err, got = _one("exchange_pair_reconcile", {"log_a": str(la), "log_b": str(lb),
                                                "exchange": "ex-2", "late_after": 60})
    assert not err, got
    assert [e["exchange_id"] for e in got["exchanges"]] == ["ex-2"]
    assert got["exchanges"][0]["disagreement"] == "late"
    assert got["exchange"] == "ex-2" and got["exchange_found"] is True
    assert got["disagreements"] == {"missing": 0, "mismatched": 0, "late": 1, "retracted": 0}
    err, got = _one("exchange_pair_reconcile", {"log_a": str(la), "log_b": str(lb),
                                                "exchange": "ex-404"})
    assert not err and got["exchange_found"] is False and got["exchanges"] == []


def test_unreadable_log_is_could_not_look_exit_3(monkeypatch, tmp_path, logs):
    _isolate(monkeypatch, tmp_path)
    la, _ = logs
    err, got = _one("exchange_pair_reconcile", {"log_a": str(la),
                                                "log_b": str(tmp_path / "nope.jsonl")})
    assert not err and got["verdict"] == V.COULD_NOT_LOOK and got["exit"] == 3


def test_bad_window_is_a_tool_error_and_every_call_is_recorded(monkeypatch, tmp_path, logs):
    rec = _isolate(monkeypatch, tmp_path)
    la, lb = logs
    _, out = _session([("exchange_pair_reconcile",
                        {"log_a": str(la), "log_b": str(lb), "late_after": -1}),
                       ("exchange_pair_reconcile", {"log_a": str(la), "log_b": str(lb)})])
    assert out[0][0] is True and "late_after" in str(out[0][1])
    assert out[1][0] is False
    rows = list(Ledger(rec))
    assert [r["tool"] for r in rows] == ["exchange_pair_reconcile"] * 2
    assert [r["ok"] for r in rows] == [False, True]
    assert verify_call_record(rec)["ok"] is True
