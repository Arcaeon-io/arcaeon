"""K078: the MCP tool `mandate_check`.

    pytest tests/connector/test_mandate_check_tool.py

One call judged against a mandate file through the connector: inside, outside
or could_not_look, with `exit` 0, 1 or 3, key for key what
`arcaeon.record.mandate_cli.check` answers (import only, never a second
implementation). It is free, blocks nothing, writes no mandate row, and leaves
exactly one call-record row like every other tool.
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="the connector IS an MCP server")

from mcp import Client  # noqa: E402

from arcaeon.mcp.server import (  # noqa: E402
    ALL_TOOLS,
    FREE_TOOLS,
    MANDATE_TOOLS,
    build_server,
    verify_call_record,
)
from arcaeon.record import mandate_cli  # noqa: E402
from _load import must_match  # noqa: E402

DOC = (Path(__file__).resolve().parents[2] / "docs" / "MANDATE_GATE.md").read_text(
    encoding="utf-8")
EXAMPLE = json.loads(must_match(r"```json\n(.*?)```", DOC, re.S).group(1))
AT = "2026-10-01T12:00:00Z"            # inside the example's window


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("ARCAEON_LEDGER_LOG", str(tmp_path / "agent.log.jsonl"))
    monkeypatch.setenv("ARCAEON_LEDGER_NS_DIR", str(tmp_path / "ledgers"))
    monkeypatch.setenv("MCP_VET_AUDIT_LEDGER", str(tmp_path / "vet_audit.jsonl"))
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(tmp_path / "arcaeon.calls.jsonl"))
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arc_home"))
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    return tmp_path / "arcaeon.calls.jsonl"


@pytest.fixture
def example(tmp_path) -> Path:
    p = tmp_path / "docs-example.json"
    p.write_text(json.dumps(EXAMPLE), encoding="utf-8")
    return p


def _session(calls):
    async def go():
        out = []
        async with Client(build_server()) as client:
            names = sorted(t.name for t in (await client.list_tools()).tools)
            for args in calls:
                res = await client.call_tool("mandate_check", args)
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


def _one(args):
    _, out = _session([args])
    return out[0]


def test_the_tool_is_listed_and_free(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    names, _ = _session([])
    assert MANDATE_TOOLS == ("mandate_check",)
    assert "mandate_check" in names and names == sorted(ALL_TOOLS)
    assert "mandate_check" in FREE_TOOLS


def test_inside_is_exit_0_and_matches_the_library(monkeypatch, tmp_path, example):
    _isolate(monkeypatch, tmp_path)
    fields = {"name": "place_order", "total": "19.00", "currency": "USD",
              "seller": "acme-store"}
    err, res = _one({"mandate": str(example), "fields": fields, "at": AT})
    assert not err, res
    assert res["verdict"] == "inside" and res["exit"] == 0 and res["blocks"] is False
    want = mandate_cli.check(str(example), fields, at=AT)
    assert {k: v for k, v in res.items() if k != "exit"} == want


def test_forbidden_is_outside_exit_1_with_the_reason(monkeypatch, tmp_path, example):
    _isolate(monkeypatch, tmp_path)
    err, res = _one({"mandate": str(example), "fields": {"name": "refund"}})
    assert not err, res
    assert res["verdict"] == "outside" and res["exit"] == 1
    assert res["rule"] == "forbidden_acts"
    assert res["reason"] == "tool 'refund' matches forbidden_acts pattern 'refund'"


def test_over_the_cap_is_outside(monkeypatch, tmp_path, example):
    _isolate(monkeypatch, tmp_path)
    err, res = _one({"mandate": str(example), "at": AT, "fields": {
        "name": "place_order", "total": "61.00", "currency": "USD", "seller": "acme-store"}})
    assert not err, res
    assert res["verdict"] == "outside" and res["exit"] == 1


def test_session_total_uses_spent(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    m = tmp_path / "total.json"
    m.write_text(json.dumps({"spend_cap": {"amount": "60.00", "total": "100.00",
                                           "currency": "USD"}}), encoding="utf-8")
    fields = {"name": "place_order", "total": "30.00", "currency": "USD"}
    _, out = _session([{"mandate": str(m), "fields": fields},
                       {"mandate": str(m), "fields": fields, "spent": "80.00"}])
    assert out[0][1]["verdict"] == "inside"
    assert out[1][1]["verdict"] == "outside" and out[1][1]["rule"] == "spend_cap.total"


def test_missing_mandate_is_could_not_look_exit_3(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    err, res = _one({"mandate": str(tmp_path / "nope.json"), "fields": {"name": "echo"}})
    assert not err, res
    assert res["verdict"] == "could_not_look" and res["exit"] == 3
    assert res["reason_word"] in ("missing", "unreadable")
    assert res["looked_for"] and res["where"]


def test_no_name_is_a_refusal_with_its_text(monkeypatch, tmp_path, example):
    _isolate(monkeypatch, tmp_path)
    err, res = _one({"mandate": str(example), "fields": {"total": "1.00"}})
    assert err is True
    assert "name" in str(res)


def test_one_call_record_row_and_no_mandate_row_anywhere(monkeypatch, tmp_path, example):
    rec = _isolate(monkeypatch, tmp_path)
    before = sorted(p.name for p in tmp_path.rglob("*") if p.is_file())
    _one({"mandate": str(example), "fields": {"name": "refund"}})
    rows = [json.loads(x) for x in rec.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert [r["tool"] for r in rows] == ["mandate_check"]
    assert rows[0]["ok"] is True
    assert verify_call_record(rec)["ok"] is True
    after = sorted(p.name for p in tmp_path.rglob("*") if p.is_file())
    # the call record and its lock file; nothing else was written
    assert set(after) - set(before) <= {rec.name, rec.name + ".lock"}
    assert rec.name in after
    assert example.read_text(encoding="utf-8") == json.dumps(EXAMPLE)
