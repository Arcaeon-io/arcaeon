"""The server's OWN audit trail (board B2b, 2026-08-30). Written BEFORE the
wiring existed; the first run failed on `AttributeError: module 'mcp_vet.server'
has no attribute 'audit_ledger_path'`, which is the point.

v0.0.6 shipped an MCP08 `audit-record` check and scored **high** on the server
that ships it: `mcp_vet_scan` read whatever file it was handed and kept no
record of having done it. That finding was published rather than fixed in the
same breath, deliberately. This is the fix, and the rule for it is that the four
gates must be met by a REAL record - an actual hash-chained row in an actual
`arcaeon_ledger` file, verifiable by an independent party - not by arranging
source text that satisfies the heuristic. So every gate has a runtime test here,
not just the static one at the bottom:

  gate 1 presence           -> a scan through the MCP client leaves exactly one row
  gate 2 completeness       -> that row carries tool, ts, path, source_sha256
  gate 3 tamper-evidence    -> editing the row is DETECTED, not merely chained
  gate 4 reconstructability -> `mcp_vet_audit_verify` names the broken line

The decisive test is the last one: our own server source now passes the check we
published a self-finding on. It is only allowed to pass because the tests above
prove the record is real.
"""
import asyncio
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

pytest.importorskip("mcp", reason="the MCP server lane needs the `mcp` extra")
pytest.importorskip("arcaeon.record.ledger", reason="the audit lane needs the [audit] extra")

from mcp import Client  # noqa: E402

from arcaeon.prove.vet import server as srv  # noqa: E402
from arcaeon.prove.vet.checks import scan_source  # noqa: E402

SCANNED = 'from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")\n'


def _payload(result):
    assert not result.is_error, result.content
    sc = result.structured_content
    if sc is not None:
        return sc.get("result", sc) if isinstance(sc, dict) else sc
    return json.loads("".join(getattr(c, "text", "") for c in result.content))


def _call(tool, args):
    async def go():
        async with Client(srv.build_server(), raise_exceptions=True) as client:
            return _payload(await client.call_tool(tool, args))
    return asyncio.run(go())


def _target(tmp_path, src=SCANNED, name="target.py"):
    p = tmp_path / name
    p.write_text(src, encoding="utf-8")
    return str(p)


def _rows(path):
    text = Path(path).read_text(encoding="utf-8")
    return [json.loads(l) for l in text.splitlines() if l.strip()]


@pytest.fixture()
def ledger(tmp_path, monkeypatch):
    """Point the server at a ledger of our own for this test only."""
    p = tmp_path / "led" / "audit.jsonl"
    monkeypatch.setenv("MCP_VET_AUDIT_LEDGER", str(p))
    return p


# --- gate 1: the record exists at all ---------------------------------------

def test_a_scan_through_the_client_appends_exactly_one_row(tmp_path, ledger):
    """Exactly one. A tool call that writes two rows is as wrong as one that
    writes none - a record set nobody can count is not a record set."""
    _call("mcp_vet_scan", {"path": _target(tmp_path)})
    assert ledger.exists(), f"no ledger written at {ledger}"
    rows = _rows(ledger)
    assert len(rows) == 1, rows


def test_grade_is_recorded_too(tmp_path, ledger):
    _call("mcp_vet_grade", {"path": _target(tmp_path)})
    rows = _rows(ledger)
    assert len(rows) == 1 and rows[0]["tool"] == "mcp_vet_grade", rows


def test_two_calls_two_rows_and_the_chain_links_them(tmp_path, ledger):
    _call("mcp_vet_scan", {"path": _target(tmp_path)})
    _call("mcp_vet_grade", {"path": _target(tmp_path)})
    rows = _rows(ledger)
    assert [r["tool"] for r in rows] == ["mcp_vet_scan", "mcp_vet_grade"], rows
    assert _call("mcp_vet_audit_verify", {})["rows"] == 2


# --- gate 2: the record says WHAT happened ----------------------------------

def test_the_row_carries_tool_timestamp_path_and_source_hash(tmp_path, ledger):
    """The four fields that make a row an audit record instead of a heartbeat.
    `source_sha256` is the load-bearing one: it pins the exact bytes that were
    graded, so the row is re-testable the same way a grade artifact is."""
    path = _target(tmp_path)
    findings = _call("mcp_vet_scan", {"path": path})
    row = _rows(ledger)[0]

    assert row["tool"] == "mcp_vet_scan", row
    assert row["ts"].endswith("Z") and row["ts"][:2] == "20", row["ts"]
    assert row["args"]["path"] == path, row
    assert row["source_sha256"] == hashlib.sha256(SCANNED.encode()).hexdigest(), row
    assert row["findings"] == len(findings), row
    assert "verdict" in row, row


def test_a_failed_call_is_recorded_rather_than_vanishing(tmp_path, ledger):
    """A scanner that answers nothing for a file it could not read is a silent
    green; an audit trail that forgets the call entirely is the same sin one
    layer down."""
    async def go():
        async with Client(srv.build_server()) as client:
            return await client.call_tool("mcp_vet_scan",
                                          {"path": str(tmp_path / "nope.py")})
    r = asyncio.run(go())
    assert r.is_error, r.content
    rows = _rows(ledger)
    assert len(rows) == 1 and rows[0]["error"], rows
    assert rows[0]["source_sha256"] is None, rows


# --- gates 3 + 4: a silent edit is DETECTED and NAMED -----------------------

def test_a_clean_ledger_verifies_clean(tmp_path, ledger):
    _call("mcp_vet_scan", {"path": _target(tmp_path)})
    r = _call("mcp_vet_audit_verify", {})
    assert r["enabled"] is True, r
    assert r["ok"] is True, r
    assert r["rows"] == 1 and r["first_break"] is None, r


def test_a_tampered_row_is_named_by_audit_verify(tmp_path, ledger):
    """The whole point of gate 3. Rewrite the recorded path in row 1 - the file
    still parses, still looks like an audit log, and the verifier must call the
    exact line."""
    _call("mcp_vet_scan", {"path": _target(tmp_path)})
    _call("mcp_vet_scan", {"path": _target(tmp_path)})

    lines = ledger.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[0])
    row["args"]["path"] = "C:/something/else.py"
    lines[0] = json.dumps(row)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    r = _call("mcp_vet_audit_verify", {})
    assert r["ok"] is False, r
    assert r["first_break"] and "1" in r["first_break"], r
    assert r["rows"] == 2, r


def test_audit_verify_is_advertised_as_a_tool():
    async def go():
        async with Client(srv.build_server()) as client:
            return sorted(t.name for t in (await client.list_tools()).tools)
    assert asyncio.run(go()) == ["mcp_vet_audit_verify", "mcp_vet_grade",
                                 "mcp_vet_scan"]


def test_verifying_does_not_write_to_the_ledger_it_verifies(tmp_path, ledger):
    """A deliberate per-handler gap in our own trail, tested so it stays
    deliberate: a verify that mutates its own subject can never report on
    itself. This is the coverage gap the tool already confesses as a blind
    spot, and we sit in it knowingly rather than by accident."""
    _call("mcp_vet_scan", {"path": _target(tmp_path)})
    before = ledger.read_bytes()
    _call("mcp_vet_audit_verify", {})
    assert ledger.read_bytes() == before


# --- the env var, and the operator's real home ------------------------------

def test_the_env_var_redirects_and_home_is_never_touched(tmp_path, monkeypatch):
    """`MCP_VET_AUDIT_LEDGER` must be read at CALL time, not import time, and
    nothing may land in ~/.mcp_vet while it is set."""
    home = Path.home() / ".mcp_vet"
    before = (sorted((p.name, p.stat().st_mtime_ns) for p in home.iterdir())
              if home.is_dir() else None)

    p = tmp_path / "elsewhere" / "trail.jsonl"
    monkeypatch.setenv("MCP_VET_AUDIT_LEDGER", str(p))
    _call("mcp_vet_scan", {"path": _target(tmp_path)})

    assert srv.audit_ledger_path() == p
    assert len(_rows(p)) == 1
    after = (sorted((q.name, q.stat().st_mtime_ns) for q in home.iterdir())
             if home.is_dir() else None)
    assert after == before, f"~/.mcp_vet was touched: {before} -> {after}"


def test_the_default_path_is_under_the_users_home(monkeypatch):
    monkeypatch.delenv("MCP_VET_AUDIT_LEDGER", raising=False)
    assert srv.audit_ledger_path() == Path.home() / ".mcp_vet" / "audit.jsonl"


# --- the optional dependency is optional, and never silently off ------------

def test_without_the_ledger_package_the_server_runs_and_says_the_record_is_off(
        tmp_path, ledger, monkeypatch):
    """The failure mode to avoid is not "no audit trail" - it is an audit trail
    the operator believes exists. Scanning must keep working, and the status has
    to be loud in the tool result AND in the server instructions."""
    monkeypatch.setattr(srv, "AUDIT_AVAILABLE", False)
    monkeypatch.setattr(srv, "Ledger", None)

    findings = _call("mcp_vet_scan", {"path": _target(tmp_path)})
    assert findings == [], findings          # the scan still works
    assert not ledger.exists(), "wrote a ledger with the package disabled"

    r = _call("mcp_vet_audit_verify", {})
    assert r["enabled"] is False, r
    assert r["ok"] is None, r
    assert "arcaeon" in r["detail"].lower(), r["detail"]
    assert "OFF" in srv.audit_status_line(), srv.audit_status_line()


def test_the_instructions_carry_the_audit_status():
    line = srv.audit_status_line()
    assert line in srv.build_instructions(), (line, srv.build_instructions())
    assert "ON" in line or "OFF" in line, line


def test_the_audit_extra_is_declared_optional_not_required():
    """The scanner core stays stdlib-only: a security checker that drags in a
    dependency tree is a supply-chain surface of its own."""
    import tomllib
    cfg = tomllib.loads((Path(__file__).resolve().parent / "pyproject.toml")
                        .read_text(encoding="utf-8"))["project"]
    assert cfg.get("dependencies", []) == [], cfg.get("dependencies")
    extras = cfg["optional-dependencies"]
    assert any("arcaeon" in d for d in extras.get("audit", [])), extras


# --- the same verdict without an MCP client ---------------------------------

def test_the_cli_verifies_the_same_ledger(tmp_path, ledger, capsys):
    """An audit trail only checkable through our own MCP server is a claim.
    `mcp-vet audit-verify` is the same recomputation from a shell, exit 0 only
    on a full green."""
    from arcaeon.prove.vet.__main__ import main

    _call("mcp_vet_scan", {"path": _target(tmp_path)})
    assert main(["audit-verify"]) == 0
    assert json.loads(capsys.readouterr().out)["rows"] == 1


def test_the_cli_exits_nonzero_on_a_broken_chain(tmp_path, ledger, capsys):
    from arcaeon.prove.vet.__main__ import main

    _call("mcp_vet_scan", {"path": _target(tmp_path)})
    _call("mcp_vet_scan", {"path": _target(tmp_path)})
    lines = ledger.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[0])
    row["findings"] = 99
    lines[0] = json.dumps(row)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert main(["audit-verify"]) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False and out["first_break"], out


def test_the_cli_does_not_exit_zero_on_an_empty_record(tmp_path, monkeypatch, capsys):
    """No rows is not a green. A verifier that reports success over a file that
    records nothing is the silent green in its purest form."""
    from arcaeon.prove.vet.__main__ import main

    monkeypatch.setenv("MCP_VET_AUDIT_LEDGER", str(tmp_path / "nothing.jsonl"))
    assert main(["audit-verify"]) == 3
    assert json.loads(capsys.readouterr().out)["rows"] == 0


# --- the decisive one -------------------------------------------------------

def test_our_own_server_now_meets_all_four_gates():
    """v0.0.6 published this file as `audit-record / high`, all four gates
    false. It is now clean under its own check - and clean under all six
    classes, so the silence is not one check being bought with another."""
    src = (Path(__file__).resolve().parents[2] / "src" / "arcaeon" / "prove" / "vet" / "server.py"
           ).read_text(encoding="utf-8")
    fs = scan_source(src, "mcp_vet/server.py")
    assert [f for f in fs if f.check == "audit-record"] == [], fs
    assert fs == [], fs
