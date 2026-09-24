"""Tests for arcaeon-ledger-mcp.

Proves three things:
  1. the module imports and the MCP server object builds,
  2. all three tools register with the server (via the SDK's list_tools),
  3. a real round-trip through the tool functions works end to end — create,
     append two rows, verify passes, then tamper a row on disk and verify names
     the exact broken line.

Run: python test_server.py     (also discoverable by pytest)
"""
from __future__ import annotations

import asyncio
import datetime as _dt
import hashlib
import json
import tempfile
from pathlib import Path

# Imports the real pip-installed `arcaeon_ledger` package, like the server does.
# No sibling-checkout sys.path fallback: a missing package must fail loudly
# rather than silently load the stale projects/ledger copy.
from arcaeon.mcp import ledger_server as srv

import contextlib
import os


@contextlib.contextmanager
def _root(d):
    """Tools only touch .jsonl files under ARCAEON_LEDGER_ROOT (2026-09-01)."""
    old = os.environ.get(srv._ROOT_ENV)
    os.environ[srv._ROOT_ENV] = str(d)
    try:
        yield
    finally:
        if old is None:
            os.environ.pop(srv._ROOT_ENV, None)
        else:
            os.environ[srv._ROOT_ENV] = old


def test_import_and_server_builds():
    assert srv.mcp is not None
    assert srv.mcp.name == "arcaeon-ledger"
    print("PASS import + MCPServer builds (name='arcaeon-ledger')")


def test_tools_register():
    tools = asyncio.run(srv.mcp.list_tools())
    names = {t.name for t in tools}
    assert {"ledger_create", "ledger_append", "ledger_verify"} <= names, names
    print(f"PASS tools register via SDK list_tools -> {sorted(names)}")


def test_roundtrip_via_tool_functions():
    with tempfile.TemporaryDirectory() as d, _root(d):
        p = Path(d) / "agent.log.jsonl"

        # create/open: fresh path -> does not exist yet, verifies vacuously
        c = srv.ledger_create(str(p))
        assert c["exists"] is False and c["rows"] == 0, c

        # append two rows -> each returns a chain hash
        h1 = srv.ledger_append(str(p), {"tool": "search", "q": "weather"})
        h2 = srv.ledger_append(str(p), {"tool": "payment", "amount": "49.00"})
        assert h1["ok"] and h2["ok"] and h1["chain"] and h2["chain"], (h1, h2)
        assert h1["chain"] != h2["chain"]

        # verify clean -> ok, 2 rows chained, no break
        v = srv.ledger_verify(str(p))
        assert v["ok"] is True and v["rows"] == 2 and v["chained"] == 2, v
        assert v["first_break"] is None, v
        print(f"PASS append x2 + verify clean {{ok:{v['ok']}, rows:{v['rows']}, "
              f"chained:{v['chained']}, first_break:{v['first_break']}}}")

        # tamper row 1 on disk, keep its now-wrong chain
        lines = p.read_text(encoding="utf-8").splitlines()
        obj = json.loads(lines[0])
        obj["amount"] = "9999.00"
        lines[0] = json.dumps(obj, ensure_ascii=False)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")

        vt = srv.ledger_verify(str(p))
        assert vt["ok"] is False, "tamper went undetected!"
        assert vt["first_break"] == "line 1: chain mismatch", vt
        print(f"PASS tamper caught: ok={vt['ok']}, first_break='{vt['first_break']}'")


def test_call_through_sdk_dispatch():
    """Exercise the SDK's own call_tool dispatch (not just the raw functions)."""
    with tempfile.TemporaryDirectory() as d, _root(d):
        p = Path(d) / "b.jsonl"

        async def go():
            r1 = await srv.mcp.call_tool("ledger_append",
                                         {"path": str(p), "record": {"n": 1}})
            r2 = await srv.mcp.call_tool("ledger_verify", {"path": str(p)})
            return r1, r2

        r1, r2 = asyncio.run(go())
        assert r1.is_error is False, r1
        assert r1.structured_content and r1.structured_content.get("chain"), r1
        assert r2.structured_content["ok"] is True, r2
        print(f"PASS SDK call_tool dispatch: append chain="
              f"{r1.structured_content['chain']}, verify ok="
              f"{r2.structured_content['ok']}")


if __name__ == "__main__":
    test_import_and_server_builds()
    test_tools_register()
    test_roundtrip_via_tool_functions()
    test_call_through_sdk_dispatch()
    print("\nALL PASS — module imports, tools register, "
          "append/verify round-trip and tamper detection hold over the MCP layer.")


def test_ledger_append_record_carries_audit_completeness_fields():
    """2026-09-05 fix, item 147: mcp_vet's OWASP MCP08 audit-record check
    failed `server.py:110` at gate 2 (completeness) — the row `ledger_append`
    wrote had no tool name, no timestamp, and no args/input digest a static
    scan could find (FAILURE_DISTRIBUTION_2026-09-02_sample200.md section 1,
    first row). The fix stamps all three onto every row, server-side, so they
    cannot be omitted or spoofed by the caller: `tool` is this tool's own
    literal name, `ts` is the server's own UTC clock, `args_digest` is a
    sha256 over exactly what the caller submitted, taken before enrichment.
    This reads the row back OFF DISK (not the tool's return value) so it
    proves what actually landed in the tamper-evident ledger, not just what
    the function computed in memory."""
    with tempfile.TemporaryDirectory() as d, _root(d):
        p = Path(d) / "audit.jsonl"
        record = {"tool": "spoofed-tool-name", "q": "weather", "amount": "1.00"}
        expected_digest = hashlib.sha256(
            json.dumps(record, sort_keys=True, default=str, ensure_ascii=False)
            .encode("utf-8")
        ).hexdigest()

        h = srv.ledger_append(str(p), record)
        assert h["ok"], h

        row = json.loads(p.read_text(encoding="utf-8").splitlines()[0])
        # tool name: the SERVER's own, never the caller-supplied "tool" key —
        # a caller must not be able to spoof which tool ran in its own audit row.
        assert row["tool"] == "ledger_append", row
        # timestamp: present and ISO-8601-parseable (the server's clock).
        assert "ts" in row, row
        _dt.datetime.fromisoformat(row["ts"])
        # args digest: sha256 of exactly the caller-supplied record, pre-enrichment.
        assert row["args_digest"] == expected_digest, (row["args_digest"], expected_digest)
        print("PASS ledger_append row carries tool/ts/args_digest "
              f"(gate-2 completeness fields): {row}")


def test_paths_outside_the_root_or_not_jsonl_are_refused():
    """2026-09-01 audit: a model-supplied `path` with no fence is append-to-any-
    file. Outside the root, or not .jsonl, is a plain error — never a redirect."""
    with tempfile.TemporaryDirectory() as d, _root(d):
        inside = Path(d) / "ok.jsonl"
        assert srv.ledger_create(str(inside))["exists"] is False
        assert srv.ledger_create("rel/sub.jsonl")["exists"] is False
        for bad in [str(Path(d).parent / "escape.jsonl"), "../escape.jsonl",
                    str(Path(d) / "notes.txt"), str(Path(d) / "x.jsonl" / ".." / ".." / "y.jsonl")]:
            try:
                srv.ledger_append(bad, {"tool": "x"})
            except ValueError as e:
                assert "path" in str(e)
            else:
                raise AssertionError(f"accepted {bad!r}")
