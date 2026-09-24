"""arcaeon (the connector) — tests, written BEFORE the package existed.

The product claim is small and checkable: ONE install, ONE stdio server, every
tool from arcaeon-ledger and mcp-vet on one list, plus a status tool, plus a
paid lane that refuses politely instead of exploding. Each of those sentences
gets a test, and every test drives the server through a real MCP round-trip
(the SDK's in-process client: real tools/list, real tools/call, real result
parsing) rather than calling the Python function and hoping the wiring holds.

The first run of this file failed at `import arcaeon.mcp` — that is the
point of writing it first.
"""
import asyncio
import json
import sys
import os
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

pytest.importorskip("mcp", reason="the connector IS an MCP server")

from mcp import Client  # noqa: E402

from arcaeon.mcp import __version__  # noqa: E402
from arcaeon.mcp.server import (  # noqa: E402
    LEDGER_TOOLS,
    PAID_TOOLS,
    VET_TOOLS,
    WITNESS_TOOLS,
    build_server,
)

# Same planted-vulnerable fixture mcp_vet grades itself against: a tool handler
# that fetches a URL taken straight from tool input. If the scan comes back
# clean through the connector, the re-export is decorative.
VULNERABLE = '''from mcp.server.fastmcp import FastMCP
import urllib.request
mcp = FastMCP("planted")

@mcp.tool()
def fetch(url):
    return urllib.request.urlopen(url).read()

mcp.run(transport="stdio")
'''


def _payload(result):
    """The tool's return value out of a CallToolResult, whichever way the SDK
    carried it (structured output, or JSON/text in a content block)."""
    assert not result.is_error, result.content
    sc = result.structured_content
    if sc is not None:
        return sc.get("result", sc) if isinstance(sc, dict) else sc
    text = "".join(getattr(c, "text", "") for c in result.content)
    try:
        return json.loads(text)
    except ValueError:
        return text


def _call(tool, args=None):
    async def go():
        async with Client(build_server(), raise_exceptions=True) as client:
            return _payload(await client.call_tool(tool, args or {}))
    return asyncio.run(go())


def _tool_names():
    async def go():
        async with Client(build_server()) as client:
            return sorted(t.name for t in (await client.list_tools()).tools)
    return asyncio.run(go())


def _isolate(monkeypatch, tmp_path):
    """Point the connector's ledger at a throwaway file, and make sure no real
    key is inherited from the developer's shell into a gating test."""
    monkeypatch.setenv("ARCAEON_LEDGER_LOG", str(tmp_path / "agent.log.jsonl"))
    monkeypatch.setenv("ARCAEON_LEDGER_NS_DIR", str(tmp_path / "ledgers"))
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    # The optional license gate is off by default and must STAY off for every
    # test that is not about it; a developer's shell must not be able to turn
    # it on underneath the free-lane assertions.
    for var in ("LICENSE_GATE_REQUIRED", "ARCAEON_LICENSE_KEY",
                "LICENSE_GATE_MODULE", "LICENSE_GATE_SECRET"):
        monkeypatch.delenv(var, raising=False)


# --- the whole point: one install, one tool list ---------------------------

def test_one_install_exposes_the_full_tool_list():
    """Everything from both servers, namespaced, plus arcaeon_status.

    The brief's arithmetic is ledger + vet + 1; the witness pair is the paid
    lane wrapped on top of it, so it is counted explicitly rather than folded
    into either side. Both the count and the exact names are asserted: a count
    alone passes if a tool is silently renamed.
    """
    names = _tool_names()
    assert len(names) == len(LEDGER_TOOLS) + len(VET_TOOLS) + len(WITNESS_TOOLS) + 1
    assert names == sorted([
        "arcaeon_status",
        "ledger_append",
        "ledger_declare_break",
        "ledger_prove_my_conduct",
        "ledger_verify",
        "ledger_verify_peer_ledger",
        "vet_audit_verify",
        "vet_grade",
        "vet_scan",
        "witness_pin",
        "witness_renew",
    ])


def test_every_underlying_ledger_tool_is_re_exported():
    """Drift guard. If arcaeon-ledger grows a tool and the connector does not,
    this goes red and names it — the failure mode of a bundler is silently
    shipping less than the thing it bundles."""
    from arcaeon.record.ledger.mcp_server import TOOLS as UPSTREAM

    exported = set(_tool_names())
    missing = [t["name"] for t in UPSTREAM
               if LEDGER_TOOLS.get(t["name"]) not in exported]
    assert not missing, f"arcaeon-ledger tools not re-exported: {missing}"


def test_every_underlying_vet_tool_is_re_exported():
    """Same guard on the other side."""
    from arcaeon.prove.vet.server import build_server as build_vet

    async def go():
        async with Client(build_vet()) as client:
            return [t.name for t in (await client.list_tools()).tools]

    exported = set(_tool_names())
    missing = [n for n in asyncio.run(go()) if VET_TOOLS.get(n) not in exported]
    assert not missing, f"mcp-vet tools not re-exported: {missing}"


# --- the free lane actually works through the connector --------------------

def test_ledger_round_trip_through_the_connector(monkeypatch, tmp_path):
    """Append a row, then verify the chain — both over MCP, against a real file.
    A re-export that returns plausible JSON without touching the ledger would
    pass a shape check and fail this."""
    _isolate(monkeypatch, tmp_path)

    appended = _call("ledger_append", {"record": {"op": "test", "what": "round trip"}})
    assert appended["ok"] is True, appended
    assert isinstance(appended["chain"], str) and appended["chain"], appended

    verified = _call("ledger_verify", {})
    assert verified["ok"] is True, verified
    assert verified["rows"] == 1, verified

    log = Path(tmp_path / "agent.log.jsonl")
    assert log.exists(), "the connector reported a chain for a file it never wrote"
    row = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
    assert row["chain"] == appended["chain"], (row, appended)


def test_vet_scan_of_the_planted_fixture(tmp_path):
    """The planted ssrf must come back through the connector with its line."""
    target = tmp_path / "bad.py"
    target.write_text(VULNERABLE, encoding="utf-8")

    findings = _call("vet_scan", {"path": str(target)})
    ssrf = [f for f in findings if f["check"] == "ssrf"]
    assert ssrf, f"planted ssrf not returned through the connector: {findings}"
    assert ssrf[0]["severity"] == "high", ssrf
    assert ssrf[0]["line"] == 7, ssrf


def test_vet_audit_verify_reads_the_shared_audit_ledger(monkeypatch, tmp_path):
    """vet_audit_verify has no source file of its own to scan — it recomputes
    the chain over mcp-vet's OWN call-record ledger, which lives at
    `$MCP_VET_AUDIT_LEDGER` (the same var mcp-vet's own conftest.py redirects,
    for the identical reason: never touch the developer's real
    `~/.mcp_vet/audit.jsonl`). Populate that ledger with real `mcp_vet_scan`
    calls against mcp-vet's own server, then check the connector's
    `vet_audit_verify` reports the same chain intact — a re-export that
    silently pointed at a different ledger would still return SOMETHING here,
    just not rows == 2."""
    ledger = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MCP_VET_AUDIT_LEDGER", str(ledger))

    from arcaeon.prove.vet.server import build_server as build_vet

    target = tmp_path / "clean.py"
    target.write_text("x = 1\n", encoding="utf-8")

    async def populate():
        async with Client(build_vet(), raise_exceptions=True) as client:
            await client.call_tool("mcp_vet_scan", {"path": str(target)})
            await client.call_tool("mcp_vet_scan", {"path": str(target)})

    asyncio.run(populate())
    assert ledger.is_file(), "setup did not write the shared audit ledger"

    out = _call("vet_audit_verify", {})
    assert out["enabled"] is True, out
    assert out["ok"] is True, out
    assert out["rows"] == 2, out
    assert out["breaks"] == 0, out
    assert out["first_break"] is None, out


def test_vet_scan_through_the_connector_is_recorded_in_mcp_vets_ledger(monkeypatch, tmp_path):
    """C-agent-31. `vet_scan` used to call `mcp_vet.checks.scan_source` straight,
    bypassing mcp-vet's own `_record_call` — a vet call through the connector
    left no row in mcp-vet's audit ledger while the identical call through
    mcp-vet's own server did. The fix moved to mcp-vet 0.0.8's library-level
    `scan_recorded`, and the connector now calls that. Point mcp-vet's ledger
    at a throwaway file, make exactly one `vet_scan` call through the
    connector, and check the row landed and verifies clean — through the
    connector's OWN `vet_audit_verify`, not by reaching around it."""
    ledger = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MCP_VET_AUDIT_LEDGER", str(ledger))

    target = tmp_path / "clean.py"
    target.write_text("x = 1\n", encoding="utf-8")

    findings = _call("vet_scan", {"path": str(target)})
    assert findings == [], findings
    assert ledger.is_file(), "vet_scan through the connector wrote no audit row"

    rows = [json.loads(l) for l in ledger.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(rows) == 1, rows
    assert rows[0]["tool"] == "mcp_vet_scan", rows[0]

    verified = _call("vet_audit_verify", {})
    assert verified["rows"] == 1, verified
    assert verified["ok"] is True, verified


def test_vet_grade_through_the_connector_is_recorded_too(monkeypatch, tmp_path):
    """Same guard on the sibling tool — a fix that only covers `vet_scan` and
    leaves `vet_grade` calling the unrecorded path straight is half a fix."""
    ledger = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MCP_VET_AUDIT_LEDGER", str(ledger))

    target = tmp_path / "clean.py"
    target.write_text("x = 1\n", encoding="utf-8")

    _call("vet_grade", {"path": str(target)})
    rows = [json.loads(l) for l in ledger.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(rows) == 1 and rows[0]["tool"] == "mcp_vet_grade", rows

    verified = _call("vet_audit_verify", {})
    assert verified["rows"] == 1 and verified["ok"] is True, verified


def test_vet_scan_and_grade_descriptions_match_upstream():
    """The connector's `vet_scan` / `vet_grade` descriptions must be the exact
    text mcp-vet's own server advertises for `mcp_vet_scan` / `mcp_vet_grade`
    — imported off `mcp_vet.server`'s `SCAN_DESCRIPTION` / `GRADE_DESCRIPTION`
    rather than hand-copied, so the text a client reads cannot drift from what
    mcp-vet actually does (including the sentence that the call is recorded,
    which a hand-copied string had gone stale on before this fix)."""
    from arcaeon.prove.vet.server import build_server as build_vet

    async def go():
        async with Client(build_vet()) as vc, Client(build_server()) as cc:
            vet_descs = {t.name: t.description for t in (await vc.list_tools()).tools}
            conn_descs = {t.name: t.description for t in (await cc.list_tools()).tools}
        return vet_descs, conn_descs

    vet_descs, conn_descs = asyncio.run(go())
    for upstream_name in ("mcp_vet_scan", "mcp_vet_grade"):
        local_name = VET_TOOLS[upstream_name]
        assert conn_descs[local_name] == vet_descs[upstream_name], (
            local_name, conn_descs[local_name], vet_descs[upstream_name])


def test_arcaeon_status_reports_versions_and_the_free_paid_split():
    st = _call("arcaeon_status", {})
    assert st["connector_version"] == __version__
    assert st["components"]["arcaeon-ledger"], st
    assert st["components"]["mcp-vet"], st
    assert sorted(st["paid_tools"]) == sorted(PAID_TOOLS)
    # free + paid must partition the advertised list, or the status tool is
    # telling a customer something the server does not do.
    assert sorted(st["free_tools"] + st["paid_tools"]) == _tool_names()
    assert st["key_present"] in (True, False)


# --- the paid lane: refuse politely, pass through when paid ----------------

def test_paid_tool_without_key_returns_upgrade_message_not_a_traceback(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)

    out = _call("witness_pin", {"namespace": "arcaeon-demo", "rows": 1, "chain": "abcd1234"})
    text = out if isinstance(out, str) else json.dumps(out)

    assert "https://buy.stripe.com/aFa4gAb10ead3xy35f0RG08" in text, text
    assert "$5" in text, text
    assert "ARCAEON_KEY" in text, text
    for leak in ("Traceback", 'File "', "urllib", "Exception"):
        assert leak not in text, f"stack-trace leak in the upgrade message: {text}"


def test_paid_tool_with_a_key_passes_through_to_the_witness(monkeypatch, tmp_path):
    """With a key set, the gate is out of the way and the real arguments reach
    the underlying call. The HTTP hop is stubbed so the test does not spend a
    live pin, but the stub asserts on exactly what the gate handed it."""
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "dummy-key-not-real")

    seen = {}

    def fake_post(url, body, key, timeout=20.0):
        seen.update(url=url, body=body, key=key)
        return 201, {"ok": True, "pin": {"namespace": body["namespace"],
                                         "rows": body["rows"], "chain": body["chain"]}}

    monkeypatch.setattr("arcaeon.remote.witness._http_post", fake_post)

    out = _call("witness_pin", {"namespace": "arcaeon-demo", "rows": 42, "chain": "a1b2c3d4"})

    assert seen["key"] == "dummy-key-not-real", seen
    assert seen["url"].endswith("/api/pin"), seen
    assert seen["body"] == {"namespace": "arcaeon-demo", "rows": 42, "chain": "a1b2c3d4"}, seen
    assert out["ok"] is True, out
    assert out["status"] == 201, out


def test_renew_is_gated_and_routed_like_pin(monkeypatch, tmp_path):
    """Two paid tools, one gate — the second must not be a copy that forgot it."""
    _isolate(monkeypatch, tmp_path)
    ungated = _call("witness_renew", {"namespace": "arcaeon-demo", "rows": 1, "chain": "abcd1234"})
    assert "buy.stripe.com" in (ungated if isinstance(ungated, str) else json.dumps(ungated))

    monkeypatch.setenv("ARCAEON_KEY", "dummy-key-not-real")
    seen = {}
    monkeypatch.setattr(
        "arcaeon.remote.witness._http_post",
        lambda url, body, key, timeout=20.0: (seen.update(url=url) or (200, {"ok": True})),
    )
    _call("witness_renew", {"namespace": "arcaeon-demo", "rows": 42, "chain": "a1b2c3d4"})
    assert seen["url"].endswith("/api/renew"), seen


def test_the_upgrade_message_survives_a_windows_console(monkeypatch, tmp_path):
    """The refusal is the one string here that gets PRINTED rather than rendered
    by a client, and a cp1252 console turns a stray em-dash into a replacement
    glyph. A payment message that arrives visibly corrupted reads like the bug
    it is denying."""
    _isolate(monkeypatch, tmp_path)
    out = _call("witness_pin", {"namespace": "arcaeon-demo", "rows": 1, "chain": "abcd1234"})
    text = out if isinstance(out, str) else json.dumps(out)
    assert text.isascii(), [c for c in text if not c.isascii()]


# --- the packaged thing, not just the importable one -----------------------

def test_the_installed_entry_point_serves_over_real_stdio(tmp_path):
    """Everything above drives the server in-process. This one spawns
    `python -m arcaeon.mcp` as a subprocess and talks MCP down a real
    pipe, because 'one install and it works' is a claim about the PACKAGE:
    console script, module entry, transport and all. An in-process pass with a
    broken entry point is a green for something nobody can run.

    The pipe is driven with raw newline-delimited JSON-RPC rather than the SDK's
    client, on purpose: the client class is the piece whose constructor changed
    between SDK 2.0 and 2.1, and a transport test that only passes on the SDK
    version we happen to have installed is not a transport test.
    """
    import os
    import subprocess
    import threading

    env = dict(os.environ)
    env.pop("ARCAEON_KEY", None)
    env["ARCAEON_LEDGER_LOG"] = str(tmp_path / "agent.log.jsonl")
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONPATH"] = os.pathsep.join(
        [str(Path(__file__).resolve().parent), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)

    proc = subprocess.Popen(
        [sys.executable, "-m", "arcaeon.mcp"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, text=True, encoding="utf-8", bufsize=1)
    watchdog = threading.Timer(60.0, proc.kill)
    watchdog.start()

    def send(msg):
        proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()

    def expect(id_):
        line = proc.stdout.readline()
        assert line, f"server died before answering id={id_}; stderr:\n{proc.stderr.read()}"
        msg = json.loads(line)
        assert msg.get("id") == id_, msg
        assert "error" not in msg, msg
        return msg["result"]

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "connector-test", "version": "0"}}})
        expect(1)
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        names = sorted(t["name"] for t in expect(2)["tools"])

        send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "ledger_append", "arguments": {"record": {"op": "stdio smoke"}}}})
        appended = json.loads("".join(c.get("text", "") for c in expect(3)["content"]))

        send({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "witness_pin",
            "arguments": {"namespace": "n", "rows": 1, "chain": "ab"}}})
        gated_text = "".join(c.get("text", "") for c in expect(4)["content"])
    finally:
        watchdog.cancel()
        proc.stdin.close()
        proc.kill()
        proc.wait(timeout=15)

    assert len(names) == len(LEDGER_TOOLS) + len(VET_TOOLS) + len(WITNESS_TOOLS) + 1, names
    assert appended["ok"] is True, appended
    assert "buy.stripe.com" in gated_text, gated_text


def test_a_free_tool_never_asks_for_a_key(monkeypatch, tmp_path):
    """The gate must be scoped to the paid list. A gate that fires on a free
    tool turns a free install into a paywall, which is the opposite of the
    pitch."""
    _isolate(monkeypatch, tmp_path)
    out = _call("ledger_append", {"record": {"op": "free"}})
    assert out["ok"] is True, out


# --- the optional license gate (idea I-daniel-17) ---------------------------
# Off by default, fails closed when on, and refuses a key minted for somebody
# else's ledger namespace. Four tests because there are four outcomes and the
# dangerous one is the middle: a required gate that passes because its own
# implementation is missing looks enforced and is nothing.

REPO_ROOT = Path(__file__).resolve().parents[2]


def _gate(monkeypatch):
    """Make the private implementation of the gate importable, the same
    way an installed `arcaeon_license_gate` would be."""
    # PRIVATE PIECE: the gate implementation lives in a private checkout's
    # bridge/license_gate and is NOT shipped in arcaeon. Set ARCAEON_PRIVATE_ROOT
    # to that checkout to run these two tests; elsewhere they skip, by name.
    env = os.environ.get("ARCAEON_PRIVATE_ROOT")
    if not env:
        pytest.skip("private piece: ARCAEON_PRIVATE_ROOT is not set (the license "
                    "gate implementation is not part of arcaeon)")
    root = Path(env)
    if not (root / "bridge" / "license_gate" / "gate.py").is_file():
        pytest.skip("private piece: bridge.license_gate is not under "
                    "ARCAEON_PRIVATE_ROOT")
    monkeypatch.syspath_prepend(str(root))
    monkeypatch.setenv("LICENSE_GATE_MODULE", "bridge.license_gate.gate")
    monkeypatch.setenv("LICENSE_GATE_SECRET", "connector-test-secret-not-real")
    from bridge.license_gate import gate as g
    return g


def test_the_license_gate_is_off_unless_asked_for(monkeypatch, tmp_path):
    """The default install is free and ungated: no license env set, no gate
    module needed, and the paid tool falls through to the ordinary upgrade
    message rather than to a licensing refusal."""
    _isolate(monkeypatch, tmp_path)
    out = _call("witness_pin", {"namespace": "acme-ledger", "rows": 1, "chain": "abcd1234"})
    text = out if isinstance(out, str) else json.dumps(out)
    assert "license" not in text.lower(), text
    assert "buy.stripe.com" in text, text

    st = _call("arcaeon_status")
    assert st["license_gate"]["required"] is False
    assert st["license_gate"]["gate_module"] is None


def test_a_required_gate_with_no_gate_installed_fails_closed(monkeypatch, tmp_path):
    """The failure worth catching. LICENSE_GATE_REQUIRED=1 and nothing to check
    with must REFUSE — a required check that silently passes is worse than no
    check, because somebody believes it is running."""
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("LICENSE_GATE_REQUIRED", "1")
    monkeypatch.setenv("LICENSE_GATE_MODULE", "no_such_license_gate_module")

    out = _call("witness_pin", {"namespace": "acme-ledger", "rows": 1, "chain": "abcd1234"})
    text = out if isinstance(out, str) else json.dumps(out)
    assert "no license gate module is installed" in text, text
    assert text.isascii(), [c for c in text if not c.isascii()]


def test_a_licensed_namespace_passes_through_to_the_witness(monkeypatch, tmp_path):
    """Gate on, correct key: the paid call reaches the witness untouched."""
    _isolate(monkeypatch, tmp_path)
    g = _gate(monkeypatch)
    monkeypatch.setenv("LICENSE_GATE_REQUIRED", "1")
    monkeypatch.setenv("ARCAEON_LICENSE_KEY", g.issue_key("acme-ledger"))
    monkeypatch.setenv("ARCAEON_KEY", "dummy-key-not-real")

    seen = {}
    monkeypatch.setattr(
        "arcaeon.remote.witness._http_post",
        lambda url, body, key, timeout=20.0: (seen.update(body=body) or (201, {"ok": True})),
    )

    out = _call("witness_pin", {"namespace": "acme-ledger", "rows": 7, "chain": "a1b2c3d4"})
    assert out["ok"] is True, out
    assert seen["body"]["namespace"] == "acme-ledger", seen


def test_a_key_for_another_namespace_is_refused_and_never_reaches_the_witness(
        monkeypatch, tmp_path):
    """The entanglement, end to end: the license is bound to the ledger
    namespace being pinned, so a borrowed key would have to pin under the
    lender's name. It refuses BEFORE the HTTP hop — a refusal that still spends
    a pin is not a gate."""
    _isolate(monkeypatch, tmp_path)
    g = _gate(monkeypatch)
    monkeypatch.setenv("LICENSE_GATE_REQUIRED", "1")
    monkeypatch.setenv("ARCAEON_LICENSE_KEY", g.issue_key("globex-ledger"))
    monkeypatch.setenv("ARCAEON_KEY", "dummy-key-not-real")

    posted = []
    monkeypatch.setattr(
        "arcaeon.remote.witness._http_post",
        lambda *a, **k: posted.append(a) or (201, {"ok": True}),
    )

    out = _call("witness_pin", {"namespace": "acme-ledger", "rows": 7, "chain": "a1b2c3d4"})
    text = out if isinstance(out, str) else json.dumps(out)
    assert posted == [], "a refused call still spent a witness pin"
    assert "identity_mismatch" in text, text
    assert "globex-ledger" in text and "acme-ledger" in text, text
    assert text.isascii(), [c for c in text if not c.isascii()]


def test_readme_does_not_claim_the_install_is_broken():
    """2026-09-01 audit: the README kept a 'pip install arcaeon does not work
    yet' confession after all three packages were live on PyPI — the wrong
    direction of stale. The README may not say the install is broken."""
    text = (Path(__file__).resolve().parent / "README.md").read_text(encoding="utf-8")
    assert "does not work yet" not in text
    assert "pip install arcaeon" in text


def test_server_info_version_is_the_package_version():
    """qa-fixes item 8: MCP serverInfo said 0.1.4 on an arcaeon 0.9.0 install."""
    import arcaeon
    from arcaeon import mcp as mcp_pkg
    assert mcp_pkg.__version__ == arcaeon.__version__
