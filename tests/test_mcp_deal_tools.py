"""The connector exposes the deal lane: deal_mandate, deal_commit, deal_dispute,
calling arcaeon.record.deal (import only), each leaving a call-record row."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

pytest.importorskip("mcp", reason="the connector IS an MCP server")

from mcp import Client  # noqa: E402

from arcaeon.mcp.server import ALL_TOOLS, DEAL_TOOLS, FREE_TOOLS, build_server  # noqa: E402
from arcaeon.record.deal import Deal, dispute  # noqa: E402

ITEMS = [{"sku": "pens-12", "qty": 2, "unit_price": "9.50"}]


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("ARCAEON_LEDGER_LOG", str(tmp_path / "agent.log.jsonl"))
    monkeypatch.setenv("ARCAEON_LEDGER_NS_DIR", str(tmp_path / "ledgers"))
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(tmp_path / "arcaeon.calls.jsonl"))
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    return tmp_path / "arcaeon.calls.jsonl"


def _session(calls):
    async def go():
        out = []
        async with Client(build_server()) as client:
            tools = await client.list_tools()
            names = sorted(t.name for t in tools.tools)
            for name, args in calls:
                res = await client.call_tool(name, args)
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


def test_deal_tools_are_on_the_list_and_free(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    names, _ = _session([])
    assert set(DEAL_TOOLS) <= set(names)
    assert names == sorted(ALL_TOOLS)
    assert set(DEAL_TOOLS) <= set(FREE_TOOLS)


def test_deal_mandate_commit_dispute_on_tmp_ledgers(monkeypatch, tmp_path):
    rec = _isolate(monkeypatch, tmp_path)
    buyer, seller = str(tmp_path / "buyer.jsonl"), str(tmp_path / "seller.jsonl")
    commit = {"deal": "d-mcp1", "items": ITEMS, "total": "19.00", "currency": "USD",
              "seller": "acme-store"}
    _, results = _session([
        ("deal_mandate", {"ledger": buyer, "deal": "d-mcp1", "merchant": "acme-store",
                          "cap": "60.00", "currency": "USD"}),
        ("deal_commit", dict(commit, ledger=buyer, party="buyer")),
        ("deal_commit", dict(commit, ledger=seller, party="seller")),
        ("deal_dispute", {"deal": "d-mcp1", "buyer": buyer, "seller": seller}),
    ])
    assert not [p for err, p in results if err], results
    (_, mandate), (_, bcommit), (_, scommit), (_, verdict) = results
    assert mandate["kind"] == "deal.mandate" and mandate["mandate_digest"]
    assert bcommit["inside_mandate"] is True
    assert scommit["party"] == "seller"
    # the tool's verdict is the library's verdict, over the same files
    assert verdict["verdict"] == dispute("d-mcp1", buyer, seller).verdict
    # the seller's commit cites no mandate_digest, so the two commits differ
    assert verdict["verdict"] != "MATCHED", verdict
    rows = [json.loads(l) for l in Path(rec).read_text(encoding="utf-8").splitlines()]
    assert [r["tool"] for r in rows] == ["deal_mandate", "deal_commit", "deal_commit",
                                          "deal_dispute"]
    assert all(r["ok"] for r in rows)


def test_deal_dispute_matched_when_both_sides_agree(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    buyer, seller = tmp_path / "b.jsonl", tmp_path / "s.jsonl"
    b = Deal(buyer, "buyer", "d-2")
    md = b.mandate(merchant="acme-store", cap="60.00", currency="USD")["mandate_digest"]
    b.commit(items=ITEMS, total="19.00", currency="USD", seller="acme-store")
    Deal(seller, "seller", "d-2").commit(items=ITEMS, total="19.00", currency="USD",
                                         seller="acme-store", mandate_digest=md)
    _, [(err, verdict)] = _session([("deal_dispute", {"deal": "d-2", "buyer": str(buyer),
                                                      "seller": str(seller)})])
    assert not err and verdict["verdict"] == "MATCHED", verdict


def test_deal_commit_refusal_is_recorded_as_a_refusal(monkeypatch, tmp_path):
    rec = _isolate(monkeypatch, tmp_path)
    _, [(err, _)] = _session([("deal_commit", {
        "ledger": str(tmp_path / "x.jsonl"), "deal": "d-3", "party": "broker",
        "items": ITEMS, "total": "1", "currency": "USD", "seller": "s"})])
    assert err
    row = json.loads(Path(rec).read_text(encoding="utf-8").splitlines()[-1])
    assert row["tool"] == "deal_commit" and row["ok"] is False
