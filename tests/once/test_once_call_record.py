"""Call-record tests, added 2026-09-02 (see CHANGELOG)."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import tempfile

# A scratch once-ledger so the tests never write ./once.log.jsonl into the
# repo. Re-claiming k-1 returns claimed=False, which is a result, not an error.
GOOD_ARGS = {"action": "claim", "key": "k-1",
             "ledger_path": str(Path(tempfile.mkdtemp(prefix="once_cr_")) / "once.log.jsonl")}


# --------------------------------------------------------------------------
# The server's own call record (OWASP MCP08). arcaeon-mcp-vet graded this
# server gate 0 of 4 on 2026-09-02: a tools/call left nothing behind.
# --------------------------------------------------------------------------

def _calls_rows(path):
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]


def test_every_tool_call_leaves_a_chained_record(tmp_path, monkeypatch):
    from arcaeon.record.once import mcp_server
    from arcaeon.record.call_record import verify_call_record
    rec = tmp_path / "calls.jsonl"
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(rec))
    r = mcp_server.handle({"id": 1, "method": "tools/call", "params": {
        "name": "guard_side_effect", "arguments": GOOD_ARGS}})
    assert "isError" not in r["result"], r
    rows = _calls_rows(rec)
    assert len(rows) == 1
    row = rows[0]
    assert row["tool"] == "guard_side_effect" and row["ok"] is True
    assert row["ts"].endswith("+00:00") and len(row["chain"]) == 32
    assert row["args"] == GOOD_ARGS
    assert row["args_digest"] == hashlib.sha256(
        json.dumps(row["args"], sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
    assert verify_call_record(rec) == {"ok": True, "rows": 1, "first_break": None}


def test_failed_calls_are_recorded_and_tampering_is_caught(tmp_path, monkeypatch):
    from arcaeon.record.once import mcp_server
    from arcaeon.record.call_record import verify_call_record
    rec = tmp_path / "calls.jsonl"
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(rec))
    mcp_server.handle({"id": 1, "method": "tools/call", "params": {
        "name": "guard_side_effect", "arguments": GOOD_ARGS}})
    bad = mcp_server.handle({"id": 2, "method": "tools/call", "params": {
        "name": "guard_side_effect", "arguments": {}}})
    assert bad["result"]["isError"] is True
    unk = mcp_server.handle({"id": 3, "method": "tools/call", "params": {"name": "nope"}})
    assert unk["result"]["isError"] is True
    rows = _calls_rows(rec)
    assert [r["ok"] for r in rows] == [True, False, False]
    assert "required" in rows[1]["error"]
    assert rows[2]["tool"] == "nope"
    assert verify_call_record(rec)["ok"] is True
    lines = rec.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"ok": false', '"ok": true')
    rec.write_text("\n".join(lines) + "\n", encoding="utf-8")
    v = verify_call_record(rec)
    assert v["ok"] is False and v["first_break"] == 2


def test_call_record_verifies_under_arcaeon_ledger(tmp_path, monkeypatch):
    """Same chain format as arcaeon-ledger on purpose: one record format
    across our servers, and a reader with the full ledger installed can
    verify this file with the tool they already have."""
    pytest.importorskip("arcaeon.record.ledger")
    from arcaeon.record.ledger import verify_file
    from arcaeon.record.once import mcp_server
    rec = tmp_path / "calls.jsonl"
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(rec))
    for i in range(3):
        mcp_server.handle({"id": i, "method": "tools/call", "params": {
            "name": "guard_side_effect", "arguments": GOOD_ARGS}})
    v = verify_file(str(rec))
    assert v.ok is True and v.rows == 3, v


def test_verify_calls_flag(tmp_path, monkeypatch):
    from arcaeon.record.once import mcp_server
    rec = tmp_path / "calls.jsonl"
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(rec))
    mcp_server.handle({"id": 1, "method": "tools/call", "params": {
        "name": "guard_side_effect", "arguments": GOOD_ARGS}})
    proc = subprocess.run([sys.executable, "-m", "arcaeon.record.once.mcp_server", "--verify-calls"],
                          capture_output=True, cwd=str(Path(__file__).resolve().parent),
                          env={**os.environ, "ARCAEON_CALL_RECORD": str(rec)}, timeout=30)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    out = json.loads(proc.stdout.decode())
    assert out["ok"] is True and out["rows"] == 1
