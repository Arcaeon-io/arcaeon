"""K069: the MCP tools `evidence_pack_build` and `evidence_pack_verify`.

    pytest tests/connector/test_evidence_tools.py

Import only: each answers key for key what arcaeon.prove.evidence_pack.
build_pack / evidence_pack_verify.verify_pack return, `exit` included, and
leaves exactly one call-record row. A COULD NOT LOOK is an answer with exit
3, never a tool success read as green; bad usage is a tool error.
"""
from __future__ import annotations

import asyncio
import json

import pytest

pytest.importorskip("mcp", reason="the connector IS an MCP server")

from mcp import Client  # noqa: E402

from arcaeon.mcp.server import (  # noqa: E402
    ALL_TOOLS,
    EVIDENCE_TOOLS,
    FREE_TOOLS,
    build_server,
    verify_call_record,
)
from arcaeon.prove.evidence_pack_verify import verify_pack  # noqa: E402
from arcaeon.record.ledger import Ledger  # noqa: E402

STAMP = "2026-09-27T12:00:00Z"
ROWS = [
    {"ts": "2026-09-01T10:00:00Z", "system_id": "sys-a", "agent": "agent-a",
     "event": "system_start"},
    {"ts": "2026-09-01T11:00:00Z", "system_id": "sys-b", "agent": "agent-b",
     "event": "tool_call"},
    {"ts": "2026-09-02T09:30:00Z", "system_id": "sys-a", "agent": "agent-a",
     "event": "decision", "decision": "escalate"},
]


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("ARCAEON_LEDGER_LOG", str(tmp_path / "agent.log.jsonl"))
    monkeypatch.setenv("ARCAEON_LEDGER_NS_DIR", str(tmp_path / "ledgers"))
    monkeypatch.setenv("MCP_VET_AUDIT_LEDGER", str(tmp_path / "vet_audit.jsonl"))
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(tmp_path / "arcaeon.calls.jsonl"))
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arc_home"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    return tmp_path / "arcaeon.calls.jsonl"


@pytest.fixture
def ledger(tmp_path):
    p = tmp_path / "ledger.jsonl"
    lg = Ledger(p)
    for r in ROWS:
        lg.append(r)
    return p


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


def test_both_tools_are_listed_and_free(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    names, _ = _session([])
    assert EVIDENCE_TOOLS == ("evidence_pack_build", "evidence_pack_verify")
    assert set(EVIDENCE_TOOLS) <= set(names) and names == sorted(ALL_TOOLS)
    assert set(EVIDENCE_TOOLS) <= set(FREE_TOOLS)


def test_build_then_verify_matches_the_library(monkeypatch, tmp_path, ledger):
    _isolate(monkeypatch, tmp_path)
    out = tmp_path / "pack"
    err, built = _one("evidence_pack_build", {"ledger": str(ledger), "out": str(out),
                                              "agent": "agent-a", "formats": ["aat"]})
    assert not err, built
    assert built["verdict"] == "VERIFIED" and built["exit"] == 0
    assert built["window"]["rows"] == 2 and "aat.jsonl" in built["files"]
    err, v = _one("evidence_pack_verify", {"pack": str(out)})
    assert not err and v == json.loads(json.dumps(verify_pack(out)))
    assert v["exit"] == 0


def test_zip_through_the_tool_is_byte_identical_and_verifies(monkeypatch, tmp_path,
                                                             ledger):
    _isolate(monkeypatch, tmp_path)
    _, out = _session([
        ("evidence_pack_build", {"ledger": str(ledger), "out": str(tmp_path / "z1"),
                                 "zip": True, "built_at": STAMP}),
        ("evidence_pack_build", {"ledger": str(ledger), "out": str(tmp_path / "z2"),
                                 "zip": True, "built_at": STAMP}),
        ("evidence_pack_verify", {"pack": str(tmp_path / "z1.zip")}),
    ])
    (e1, a), (e2, b), (e3, v) = out
    assert not (e1 or e2 or e3)
    assert a["zip_sha256"] == b["zip_sha256"]
    assert v["exit"] == 0 and v["zip"]["sha256"] == a["zip_sha256"]


def test_could_not_look_is_exit_3_never_green(monkeypatch, tmp_path, ledger):
    _isolate(monkeypatch, tmp_path)
    out = tmp_path / "pack"
    err, built = _one("evidence_pack_build", {"ledger": str(ledger), "out": str(out),
                                              "agent": "nobody"})
    assert not err and built["verdict"] == "COULD NOT LOOK" and built["exit"] == 3
    assert built["reason_word"] == "empty"
    err, v = _one("evidence_pack_verify", {"pack": str(out)})
    assert not err and v["exit"] == 3
    err, v = _one("evidence_pack_verify", {"pack": str(tmp_path / "nothing-here")})
    assert not err and v["exit"] == 3 and v["reason_word"] == "missing"


def test_a_tampered_pack_is_broken_naming_the_file(monkeypatch, tmp_path, ledger):
    _isolate(monkeypatch, tmp_path)
    out = tmp_path / "pack"
    _one("evidence_pack_build", {"ledger": str(ledger), "out": str(out)})
    w = out / "window.jsonl"
    w.write_bytes(w.read_bytes().replace(b"escalate", b"escalatE", 1))
    err, v = _one("evidence_pack_verify", {"pack": str(out)})
    assert not err and v["verdict"] == "BROKEN" and v["exit"] == 1
    assert "window.jsonl" in v["finding"]


def test_bad_usage_is_a_tool_error_with_its_text(monkeypatch, tmp_path, ledger):
    _isolate(monkeypatch, tmp_path)
    busy = tmp_path / "busy"
    busy.mkdir()
    (busy / "x").write_text("x", encoding="utf-8")
    err, res = _one("evidence_pack_build", {"ledger": str(ledger), "out": str(busy)})
    assert err is True and "not an empty folder" in str(res)
    err, res = _one("evidence_pack_build", {"ledger": str(ledger),
                                            "out": str(tmp_path / "p"),
                                            "built_at": "yesterday"})
    assert err is True and "built-at" in str(res)


def test_one_call_record_row_per_call(monkeypatch, tmp_path, ledger):
    rec = _isolate(monkeypatch, tmp_path)
    out = tmp_path / "pack"
    _session([("evidence_pack_build", {"ledger": str(ledger), "out": str(out)}),
              ("evidence_pack_verify", {"pack": str(out)})])
    rows = [json.loads(x) for x in rec.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert [r["tool"] for r in rows] == ["evidence_pack_build", "evidence_pack_verify"]
    assert all(r["ok"] is True for r in rows)
    assert verify_call_record(rec)["ok"] is True
