"""The MCP tool `evidence_pack_second_reader` answers what the library does.

    pytest tests/connector/test_second_reader_tool.py

Import only: `format="json"` answers key for key what
arcaeon.prove.second_reader.second_reader(...).to_dict() returns, `exit`
included; markdown and table carry the same text as the report's own
renderers. A bad format is a tool error; every verdict is an answer.
"""
from __future__ import annotations

import asyncio
import json
import shutil

import pytest

pytest.importorskip("mcp", reason="the connector IS an MCP server")

from mcp import Client  # noqa: E402

from arcaeon.mcp.server import ALL_TOOLS, EVIDENCE_TOOLS, FREE_TOOLS, build_server  # noqa: E402
from arcaeon.prove.evidence_pack import build_pack  # noqa: E402
from arcaeon.prove.second_reader import Report, second_reader  # noqa: E402
from arcaeon.record.ledger import Ledger  # noqa: E402
from arcaeon.record.ledger.witness import WitnessStore, publish_head  # noqa: E402

ROWS = [
    {"ts": "2026-09-01T10:00:00Z", "system_id": "sys-a", "agent": "agent-a",
     "event": "system_start"},
    {"ts": "2026-09-01T11:00:00Z", "system_id": "sys-b", "agent": "agent-b",
     "event": "tool_call", "inputs": {"q": "lookup"}},
    {"ts": "2026-09-02T09:30:00Z", "system_id": "sys-a", "agent": "agent-a",
     "event": "decision", "decision": "escalate", "outputs": {"to": "desk"}},
    {"ts": "2026-09-03T08:00:00Z", "system_id": "sys-b", "agent": "agent-b",
     "event": "system_stop"},
]


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("ARCAEON_LEDGER_LOG", str(tmp_path / "agent.log.jsonl"))
    monkeypatch.setenv("ARCAEON_LEDGER_NS_DIR", str(tmp_path / "ledgers"))
    monkeypatch.setenv("MCP_VET_AUDIT_LEDGER", str(tmp_path / "vet_audit.jsonl"))
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(tmp_path / "arcaeon.calls.jsonl"))
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arc_home"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    monkeypatch.delenv("ARCAEON_KEY", raising=False)


@pytest.fixture
def demo(tmp_path):
    """The demo pack, its pin file and the byte-tampered copy."""
    led = tmp_path / "ledger.jsonl"
    lg = Ledger(led)
    for r in ROWS:
        lg.append(r)
    pins = tmp_path / "witness.jsonl"
    publish_head(WitnessStore(pins), "acme", lg)
    pack = tmp_path / "pack"
    build_pack(led, pack, witness=str(pins), witness_namespace="acme",
               system_id="sys-a", provider="Demo Provider")
    bad = tmp_path / "tampered"
    shutil.copytree(pack, bad)
    for name, a, b in (("records.jsonl", b"lookup", b"lookuq"),
                       ("README.md", b"folder", b"fo1der")):
        (bad / name).write_bytes((bad / name).read_bytes().replace(a, b))
    return pack, pins, bad


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


def test_the_tool_is_listed_and_free(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    names, _ = _session([])
    assert "evidence_pack_second_reader" in EVIDENCE_TOOLS
    assert "evidence_pack_second_reader" in names and names == sorted(ALL_TOOLS)
    assert "evidence_pack_second_reader" in FREE_TOOLS


def test_the_tool_returns_the_same_report(monkeypatch, tmp_path, demo):
    _isolate(monkeypatch, tmp_path)
    pack, pins, bad = demo
    _, out = _session([
        ("evidence_pack_second_reader", {"pack_path": str(pack)}),
        ("evidence_pack_second_reader", {"pack_path": str(pack), "witness_path": str(pins)}),
        ("evidence_pack_second_reader", {"pack_path": str(bad), "format": "json"}),
    ])
    for (err, got), (p, w) in zip(out, ((pack, None), (pack, pins), (bad, None))):
        assert not err, got
        want = second_reader(p, witness=w)
        assert got == json.loads(want.to_json())
        assert Report.from_dict(got) == want
    assert [o[1]["exit"] for o in out] == [3, 0, 1]
    assert [o[1]["verdict"] for o in out] == ["COULD NOT LOOK", "VERIFIED", "BROKEN"]


def test_markdown_and_table_formats(monkeypatch, tmp_path, demo):
    _isolate(monkeypatch, tmp_path)
    pack, pins, _ = demo
    _, out = _session([
        ("evidence_pack_second_reader", {"pack_path": str(pack), "witness_path": str(pins),
                                         "format": "markdown"}),
        ("evidence_pack_second_reader", {"pack_path": str(pack), "format": "table"}),
    ])
    (e1, md), (e2, tb) = out
    assert not (e1 or e2)
    assert md["markdown"] == second_reader(pack, witness=pins).to_markdown()
    assert md["exit"] == 0 and tb["exit"] == 3
    assert tb["table"] == second_reader(pack).to_table()


def test_a_bad_format_is_a_tool_error(monkeypatch, tmp_path, demo):
    _isolate(monkeypatch, tmp_path)
    pack, _, _ = demo
    _, [(err, payload)] = _session([
        ("evidence_pack_second_reader", {"pack_path": str(pack), "format": "yaml"})])
    assert err and "format" in str(payload)
