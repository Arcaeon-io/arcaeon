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


def _call_record_isolation(monkeypatch, tmp_path):
    """test_connector_call_record.py's isolation, then this file's (which adds
    ARCAEON_HOME and the journal switch), so nothing touches ~/.arcaeon.
    Returns the call-record path."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_connector_call_record import _isolate as _cr_isolate
    rec = _cr_isolate(monkeypatch, tmp_path)
    _isolate(monkeypatch, tmp_path)
    return rec


def _call_rows(rec):
    from test_connector_call_record import _rows
    return _rows(rec)


def test_a_pack_path_that_does_not_exist_is_could_not_look(monkeypatch, tmp_path):
    """No pack at all is an answer (COULD NOT LOOK, exit 3), not an MCP
    exception, and the call still leaves its ok:true row."""
    rec = _call_record_isolation(monkeypatch, tmp_path)
    missing = tmp_path / "no-such-pack"
    _, out = _session([
        ("evidence_pack_second_reader", {"pack_path": str(missing)}),
        ("evidence_pack_second_reader", {"pack_path": str(missing), "format": "table"}),
    ])
    (e1, got), (e2, tb) = out
    assert not (e1 or e2), out
    assert got["verdict"] == "COULD NOT LOOK" and got["exit"] == 3, got
    assert got == json.loads(second_reader(missing).to_json())
    assert tb["verdict"] == "COULD NOT LOOK" and tb["exit"] == 3, tb
    rows = _call_rows(rec)
    assert [r["tool"] for r in rows] == ["evidence_pack_second_reader"] * 2, rows
    assert all(r["ok"] is True and "error" not in r for r in rows), rows


def test_a_witness_path_that_cannot_be_read_is_could_not_look(monkeypatch, tmp_path, demo):
    """A pin file that is missing, a directory or not JSON: exit 3 through the
    tool, the pin row's reason names the file (976a00c), no MCP exception, and
    one ok:true call-record row per call."""
    rec = _call_record_isolation(monkeypatch, tmp_path)
    pack, _, _ = demo
    pins_dir = tmp_path / "pins-dir"
    pins_dir.mkdir()
    not_json = tmp_path / "pins.txt"
    not_json.write_text("this is not a pin file\n{not json either\n", encoding="utf-8")
    witnesses = [tmp_path / "no-such-pins.jsonl", pins_dir, not_json]
    _, out = _session([
        ("evidence_pack_second_reader", {"pack_path": str(pack), "witness_path": str(w)})
        for w in witnesses])
    for (err, got), w in zip(out, witnesses):
        assert not err, got
        assert got["verdict"] == "COULD NOT LOOK" and got["exit"] == 3, got
        assert got["witness"] == str(w)
        pin = [r for r in got["rows"] if r["kind"] == "pin"]
        assert len(pin) == 1, got["rows"]
        assert pin[0]["verdict"] == "COULD NOT LOOK" and pin[0]["recomputed"] is None
        assert f"(pin file {w})" in pin[0]["how"], pin[0]["how"]
        assert got == json.loads(second_reader(pack, witness=w).to_json())
    rows = _call_rows(rec)
    assert [r["tool"] for r in rows] == ["evidence_pack_second_reader"] * 3, rows
    assert all(r["ok"] is True and "error" not in r for r in rows), rows
