"""K044: MCP tools second_read_submit and second_read_compare.

Driven through a real MCP round-trip (the SDK's in-process client), the same
way the other connector tests are. Two agents file their own readings over
MCP into two ledgers, and compare lines them up. No model is called.
"""
import asyncio
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

pytest.importorskip("mcp", reason="the connector IS an MCP server")

from mcp import Client  # noqa: E402

from arcaeon.mcp.server import (  # noqa: E402
    ALL_TOOLS,
    FREE_TOOLS,
    PAID_TOOLS,
    SECOND_READ_TOOLS,
    build_server,
    call_record_path,
)

CRITERION = "Does the claim state the dispatch time?"


def _call(tool, args=None):
    async def go():
        async with Client(build_server()) as client:
            res = await client.call_tool(tool, args or {})
            sc = res.structured_content
            if sc is not None:
                payload = sc.get("result", sc) if isinstance(sc, dict) else sc
            else:
                text = "".join(getattr(c, "text", "") for c in res.content)
                try:
                    payload = json.loads(text)
                except ValueError:
                    payload = text
            return bool(res.is_error), payload
    return asyncio.run(go())


def _tool_names():
    async def go():
        async with Client(build_server()) as client:
            return sorted(t.name for t in (await client.list_tools()).tools)
    return asyncio.run(go())


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("ARCAEON_LEDGER_LOG", str(tmp_path / "agent.log.jsonl"))
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(tmp_path / "arcaeon.calls.jsonl"))
    monkeypatch.delenv("ARCAEON_KEY", raising=False)


def _submit(ledger, reader_id, provider, claim_id, reading, **kw):
    args = {"ledger": str(ledger), "reader_id": reader_id, "provider": provider,
            "claim_id": claim_id, "claim": f"claim {claim_id}", "reading": reading,
            "criterion": CRITERION, **kw}
    return _call("second_read_submit", args)


def test_the_tool_list_counts_the_two_new_tools():
    names = _tool_names()
    assert SECOND_READ_TOOLS == ("second_read_submit", "second_read_compare")
    assert "second_read_submit" in names and "second_read_compare" in names
    assert names == sorted(ALL_TOOLS) and len(names) == 19  # K069 added two
    assert set(SECOND_READ_TOOLS) <= set(FREE_TOOLS)
    assert not set(SECOND_READ_TOOLS) & set(PAID_TOOLS)


def test_two_agents_submit_over_mcp_and_compare_lines_them_up(tmp_path):
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    rows_a = {"c1": "yes", "c2": "no", "c3": "undetermined"}
    rows_b = {"c1": "yes", "c2": "yes", "c3": "no"}
    for cid, word in rows_a.items():
        err, res = _submit(a, "agent-a", "vendor-one", cid, word, near_match_id=f"n-{cid}")
        assert not err and res["written"] is True and res["exit"] == 0, res
    for cid, word in rows_b.items():
        err, res = _submit(b, "agent-b", "vendor-two", cid, word)
        assert not err and res["exit"] == 0, res
    err, res = _call("second_read_compare", {"a": str(a), "b": str(b)})
    assert not err, res
    assert res["verdict"] == "COMPARED" and res["exit"] == 0
    s = res["summary"]
    assert s["disagreed"] == 2 and s["read"] == 3 and s["not_yet_informative"] is True
    assert isinstance(s["disagreed"], int) and isinstance(s["read"], int)
    dis = {c["claim_id"]: c for c in res["claims"] if c["status"] == "DISAGREED"}
    assert set(dis) == {"c2", "c3"}
    c3 = dis["c3"]
    assert c3["a"]["reading"] == "undetermined" and c3["b"]["reading"] == "no"
    assert c3["a"]["reader_id"] == "agent-a" and c3["b"]["reader_id"] == "agent-b"
    assert c3["a"]["near_match_id"] == "n-c3" and c3["b"]["near_match_id"] is None
    assert res["independence"] == "distinct_provider_self_asserted"
    assert "independent" not in json.dumps(res)


def test_a_missing_ledger_is_could_not_look_not_a_tool_error(tmp_path):
    a = tmp_path / "a.jsonl"
    _submit(a, "agent-a", "p", "c1", "yes")
    err, res = _call("second_read_compare", {"a": str(a), "b": str(tmp_path / "absent.jsonl")})
    assert not err
    assert res["verdict"] == "COULD NOT LOOK" and res["exit"] == 3
    assert res["summary"]["disagreed"] is None and res["summary"]["read"] is None
    assert res["summary"]["counts_reason"]


def test_one_reader_on_both_sides_is_bounded(tmp_path):
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    _submit(a, "Agent-A", "p", "c1", "yes")
    _submit(b, "agent-a", "p", "c1", "no")
    err, res = _call("second_read_compare", {"a": str(a), "b": str(b)})
    assert not err and res["exit"] == 3 and res["reason_word"] == "bounded"


def test_an_unknown_criterion_is_exit_3_not_an_error(tmp_path):
    a = tmp_path / "a.jsonl"
    _submit(a, "agent-a", "p", "c1", "yes")
    err, res = _call("second_read_submit", {
        "ledger": str(a), "reader_id": "agent-a", "provider": "p", "claim_id": "c2",
        "claim": "x", "reading": "no", "criterion_sha256": "0" * 64})
    assert not err and res["written"] is False and res["exit"] == 3
    assert res["reason_word"] == "name_not_found"


def test_a_bad_reading_word_is_a_tool_error_naming_it(tmp_path):
    err, res = _submit(tmp_path / "a.jsonl", "agent-a", "p", "c1", "probably")
    assert err
    assert "probably" in str(res) or "reading" in str(res)
    assert not (tmp_path / "a.jsonl").exists() or "probably" not in (
        tmp_path / "a.jsonl").read_text(encoding="utf-8")


def test_each_call_leaves_one_record_row(tmp_path):
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    _submit(a, "agent-a", "p1", "c1", "yes")
    _submit(b, "agent-b", "p2", "c1", "yes")
    _call("second_read_compare", {"a": str(a), "b": str(b)})
    rows = [json.loads(x) for x in call_record_path().read_text(encoding="utf-8").splitlines()
            if x.strip()]
    assert [r["tool"] for r in rows] == ["second_read_submit", "second_read_submit",
                                         "second_read_compare"]
    assert all(r["ok"] is True for r in rows)
