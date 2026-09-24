"""MCP-server tests (C-agent-02) — the checker exposed over MCP has to be proven
through an actual protocol round-trip, not by calling the Python function and
hoping the wiring works. These drive the server with the SDK's in-process
client: real initialize, real tools/list, real tools/call, real result parsing.

Written BEFORE mcp_vet/server.py existed; the first run failed on the missing
module, which is the point.
"""
import asyncio
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

pytest.importorskip("mcp", reason="MCP server lane needs the `mcp` extra")

from mcp import Client  # noqa: E402

from arcaeon.prove.vet.server import build_server  # noqa: E402

# A planted-vulnerable MCP server: a tool handler that fetches a URL taken
# straight from tool input. mcp_vet must call this ssrf/high at line 6.
VULNERABLE = '''from mcp.server.fastmcp import FastMCP
import urllib.request
mcp = FastMCP("planted")

@mcp.tool()
def fetch(url):
    return urllib.request.urlopen(url).read()

mcp.run(transport="stdio")
'''

# Same shape, no tainted sink: a fixed constant target and a local transport.
#
# It grew an audit trail on 2026-08-30, when the MCP08 `audit-record` class
# landed: a served MCP server whose tool calls leave no record is no longer
# "clean," it is a gate-1 finding. So the clean fixture now has to be clean
# under all six classes — a hash-chained, complete, verifiable per-call record.
# Which is the point of the class: this is what passing MCP08 looks like.
CLEAN = '''from mcp.server.fastmcp import FastMCP
import hashlib, json, time

mcp = FastMCP("clean")
_head = "0" * 64


def _audit(tool, args):
    global _head
    rec = {"ts": time.time(), "tool": tool, "args": args, "prev": _head}
    _head = hashlib.sha256((_head + json.dumps(rec, sort_keys=True)).encode()).hexdigest()
    rec["chain"] = _head
    with open("audit.jsonl", "a") as fh:
        fh.write(json.dumps(rec) + "\\n")


def verify_audit_chain(path="audit.jsonl"):
    prev = "0" * 64
    with open(path) as fh:
        for line in fh:
            row = json.loads(line)
            got = row.pop("chain")
            if hashlib.sha256((prev + json.dumps(row, sort_keys=True)).encode()).hexdigest() != got:
                return False
            prev = got
    return True


@mcp.tool()
def add(a, b):
    _audit("add", {"a": a, "b": b})
    return a + b

mcp.run(transport="stdio")
'''


def _payload(result):
    """Pull the tool's return value out of a CallToolResult, whichever way the
    SDK chose to carry it (structured output, or JSON in a text block)."""
    assert not result.is_error, result.content
    sc = result.structured_content
    if sc is not None:
        return sc.get("result", sc) if isinstance(sc, dict) else sc
    text = "".join(getattr(c, "text", "") for c in result.content)
    return json.loads(text)


def _call(tool, args):
    async def go():
        async with Client(build_server(), raise_exceptions=True) as client:
            return _payload(await client.call_tool(tool, args))
    return asyncio.run(go())


def _write(tmp_path, name, src):
    p = tmp_path / name
    p.write_text(src, encoding="utf-8")
    return str(p)


def test_server_advertises_its_three_tools():
    """Two through v0.0.6. `mcp_vet_audit_verify` joined them in v0.0.7 when the
    server grew its own tamper-evident call record — the verifier ships WITH the
    trail, because a record nobody outside can recompute is a claim, not
    evidence."""
    async def go():
        async with Client(build_server()) as client:
            return sorted(t.name for t in (await client.list_tools()).tools)
    assert _call is not None
    assert asyncio.run(go()) == ["mcp_vet_audit_verify", "mcp_vet_grade",
                                 "mcp_vet_scan"]


def test_scan_returns_the_planted_finding(tmp_path):
    findings = _call("mcp_vet_scan", {"path": _write(tmp_path, "bad.py", VULNERABLE)})
    assert isinstance(findings, list), findings
    ssrf = [f for f in findings if f["check"] == "ssrf"]
    assert ssrf, f"planted ssrf not returned over MCP: {findings}"
    assert ssrf[0]["severity"] == "high", ssrf
    assert ssrf[0]["line"] == 7, ssrf  # the urlopen line, not a vague file-level red


def test_scan_is_silent_on_the_clean_fixture(tmp_path):
    findings = _call("mcp_vet_scan", {"path": _write(tmp_path, "ok.py", CLEAN)})
    assert findings == [], f"clean fixture must return nothing, got {findings}"


def test_grade_matches_the_cli_grade_including_hash(tmp_path):
    """The MCP tool must hand back the SAME artifact the CLI emits — a summary
    would break re-testability, which is the only thing this project sells."""
    from arcaeon.prove.vet.grade import grade_source

    path = _write(tmp_path, "bad.py", VULNERABLE)
    got = _call("mcp_vet_grade", {"path": path})
    want = json.loads(grade_source(VULNERABLE, path).to_json())

    assert got["source_sha256"] == hashlib.sha256(VULNERABLE.encode()).hexdigest()
    assert got["verdict"] == "high-severity findings", got["verdict"]
    assert got["findings"] == want["findings"], (got["findings"], want["findings"])
    assert got["blind_spots"] == want["blind_spots"]
    assert got["tool_version"] == want["tool_version"]


def test_grade_reproduces_through_verify(tmp_path):
    """End to end: take the grade the MCP tool returned and run the public
    verify() against the same bytes. If that does not reproduce, the server is
    emitting something other than a real grade."""
    from arcaeon.prove.vet.grade import verify

    got = _call("mcp_vet_grade", {"path": _write(tmp_path, "bad.py", VULNERABLE)})
    assert verify(got, VULNERABLE)["reproduced"] is True


def test_missing_file_is_an_error_not_a_clean_bill(tmp_path):
    """A scanner that returns 'no findings' for a path it could not read is the
    worst possible failure mode: a silent green."""
    async def go():
        async with Client(build_server()) as client:
            return await client.call_tool("mcp_vet_scan", {"path": str(tmp_path / "nope.py")})
    r = asyncio.run(go())
    assert r.is_error, f"missing file must error, got {r.content}"
