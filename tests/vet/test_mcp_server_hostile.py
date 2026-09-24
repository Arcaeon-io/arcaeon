"""mcp_vet's MCP server under hostile input (2026-09-02, K20 + K21).

Two things a stranger can do to `mcp-vet serve` that the round-trip tests in
`test_mcp_server.py` never try:

  1. Feed it bytes that are not a request. The server runs on the `mcp` SDK's
     stdio transport, so the parser is not ours; the bar we CAN hold is that
     no line ends the process, and that every line the SDK accepts as a
     request gets an answer. The SDK drops what it cannot validate without a
     reply (see `SDK_SILENT` below); that is recorded here as a known limit,
     not passed off as a pass.

  2. Point the path argument outside the directory the operator meant. The
     scanner reads the file it is given, by design and disclosed in the module
     docstring. `MCP_VET_SCAN_ROOT` turns that exposure into a fence: with it
     set, every path (relative, absolute, traversal, UNC, drive-relative, a
     symlink that points out) must resolve to a file INSIDE the root or the
     call is refused as a tool error. Unset, behaviour is unchanged.

Written BEFORE the fence existed. First run: every containment test failed
(the server read `..\\..\\outside.py` happily), and the hostile-line tests
passed, which is the SDK's doing, not ours.

The hostile-line list is VENDORED here from
`arcaeon_ledger.adversarial.HOSTILE_STDIO_LINES` (arcaeon-ledger, the canonical
copy). arcaeon-ledger is only an OPTIONAL extra of this package
(`mcp-vet[audit]`), so this file cannot import it unconditionally; the copy is
pinned against upstream by `test_vendored_hostile_lines_match_upstream`
whenever the extra is present, so the two cannot drift silently.
"""
import asyncio
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

pytest.importorskip("mcp", reason="MCP server lane needs the `mcp` extra")

from mcp import Client  # noqa: E402

from arcaeon.prove.vet.server import SCAN_ROOT_ENV, build_server  # noqa: E402

# --- vendored from arcaeon_ledger.adversarial (arcaeon-ledger >= 0.7.5) --------
# Source of truth: arcaeon_ledger/adversarial.py in the arcaeon-ledger package
# (`HOSTILE_STDIO_LINES`). Kept byte-identical; the drift test below enforces
# it when the upstream package is importable. Only (name, line) is vendored;
# the per-case rationale lives upstream.
_DEEP = 100_000
_TEN_MB = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": "__TOOL__",
                                 "arguments": {"pad": "A" * (10 * 1024 * 1024)}}},
                     separators=(",", ":")).encode("utf-8")

HOSTILE_STDIO_LINES = [
    ("truncated_json", b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{'),
    ("top_level_array_empty", b"[]"),
    ("top_level_number", b"42"),
    ("top_level_string", b'"x"'),
    ("top_level_null", b"null"),
    ("ten_mb_line", _TEN_MB),
    ("lone_surrogate_escape", b'{"jsonrpc":"2.0","id":1,"method":"\\ud800","params":{}}'),
    ("embedded_nul_byte", b'{"jsonrpc":"2.0","id":1,"method":"init\x00ialize"}'),
    ("invalid_utf8_bytes", b'{"jsonrpc":"2.0","id":1,"method":"\xff\xfe"}'),
    ("escaped_nul_in_method", b'{"jsonrpc":"2.0","id":1,"method":"init\\u0000ialize"}'),
    ("deep_nesting_100k",
     b'{"jsonrpc":"2.0","id":1,"method":"x","params":' + b"[" * _DEEP + b"]" * _DEEP + b"}"),
    ("request_missing_id", b'{"jsonrpc":"2.0","method":"tools/list","params":{}}'),
    ("unknown_method", b'{"jsonrpc":"2.0","id":1,"method":"no/such"}'),
    ("method_not_string", b'{"jsonrpc":"2.0","id":1,"method":{},"params":{}}'),
    ("tools_call_missing_name",
     b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{}}}'),
    ("tools_call_arguments_string",
     b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"__TOOL__","arguments":"x"}}'),
    ("params_string", b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"x"}'),
    ("params_array", b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[1,2]}'),
    ("id_is_object", b'{"jsonrpc":"2.0","id":{"a":1},"method":"tools/list"}'),
    ("batch_array",
     b'[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"no/such"}]'),
    ("malformed_notification", b'{"jsonrpc":"2.0","method":42,"params":"nope"}'),
    ("wrong_jsonrpc_version", b'{"jsonrpc":"1.0","id":1,"method":"tools/list"}'),
    ("empty_object", b"{}"),
]
NOTIFICATION_CASES = frozenset({"request_missing_id", "malformed_notification", "empty_object"})
SDK_SILENT = frozenset({
    "truncated_json", "top_level_array_empty", "top_level_number", "top_level_string",
    "top_level_null", "lone_surrogate_escape", "embedded_nul_byte", "deep_nesting_100k",
    "method_not_string", "params_string", "params_array", "id_is_object", "batch_array",
    "wrong_jsonrpc_version",
})
# --- end vendored ---------------------------------------------------------------

INITIALIZE = json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {},
    "clientInfo": {"name": "mcp-vet-hostile", "version": "0"}}}).encode()
INITIALIZED = b'{"jsonrpc":"2.0","method":"notifications/initialized"}'


def test_vendored_hostile_lines_match_upstream():
    adv = pytest.importorskip(
        "arcaeon.record.ledger.adversarial",
        reason="arcaeon-ledger >= 0.7.5 not installed; vendored copy unchecked")
    upstream = [(n, l) for n, l, _why in adv.HOSTILE_STDIO_LINES]
    assert HOSTILE_STDIO_LINES == upstream, "vendored list drifted from arcaeon_ledger.adversarial"
    assert NOTIFICATION_CASES == adv.NOTIFICATION_CASES
    assert SDK_SILENT == adv.SDK_STDIO_SILENT_CASES


def _feed(line: bytes, tmp_path, *, grace=5.0, timeout=60.0):
    """One fresh `mcp-vet serve`, handshake, ONE hostile line, then EOF.
    Returns (exit_code, stdout_replies_after_handshake, stderr_text)."""
    env = dict(os.environ, PYTHONIOENCODING="utf-8",
               MCP_VET_AUDIT_LEDGER=str(tmp_path / "audit.jsonl"))
    proc = subprocess.Popen([sys.executable, "-m", "arcaeon.prove.vet", "serve"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=env)
    out, err = [], []

    def pump(stream, sink):
        for chunk in iter(stream.readline, b""):
            sink.append(chunk)
    ts = [threading.Thread(target=pump, args=(proc.stdout, out), daemon=True),
          threading.Thread(target=pump, args=(proc.stderr, err), daemon=True)]
    for t in ts:
        t.start()
    try:
        proc.stdin.write(INITIALIZE + b"\n" + INITIALIZED + b"\n"
                         + line.replace(b"__TOOL__", b"mcp_vet_scan") + b"\n")
        proc.stdin.flush()
    except OSError:
        pass
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline and proc.poll() is None and len(out) <= 1:
        time.sleep(0.02)
    try:
        proc.stdin.close()
    except OSError:
        pass
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        pytest.fail("server did not exit after EOF")
    for t in ts:
        t.join(5)
    replies = [json.loads(l) for l in out if l.strip()]
    replies = [r for r in replies if not (isinstance(r, dict) and r.get("id") == 0)]
    return proc.returncode, replies, b"".join(err).decode("utf-8", "replace")


def test_sanity_initialize_is_answered_over_real_stdio(tmp_path):
    code, replies, err = _feed(b'{"jsonrpc":"2.0","id":7,"method":"tools/list"}', tmp_path)
    assert code == 0, err
    assert replies and replies[0]["id"] == 7 and "result" in replies[0], replies


@pytest.mark.parametrize("name,line", HOSTILE_STDIO_LINES, ids=[c[0] for c in HOSTILE_STDIO_LINES])
def test_hostile_line_never_crashes_the_server(tmp_path, name, line):
    code, replies, err = _feed(line, tmp_path)
    assert "Traceback" not in err, f"{name}: traceback on stderr\n{err[-1500:]}"
    assert code == 0, f"{name}: exit {code}\n{err[-1500:]}"
    if name in NOTIFICATION_CASES or name in SDK_SILENT:
        return  # silence is spec-correct (notification) or the SDK's known drop
    assert replies, f"{name}: a message with an id drew no reply"
    r = replies[0]
    assert "error" in r or "result" in r, r


# --- containment of the path argument -------------------------------------------

def _scan(path: str):
    async def go():
        async with Client(build_server()) as client:
            return await client.call_tool("mcp_vet_scan", {"path": path})
    return asyncio.run(go())


def _text(result) -> str:
    return "".join(getattr(c, "text", "") for c in result.content)


@pytest.fixture
def fenced(tmp_path, monkeypatch):
    """A root with one legitimate file inside and one secret outside."""
    root = tmp_path / "root"
    root.mkdir()
    (root / "inside.py").write_text("x = 1\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text("import os\nos.system('rm -rf /')\n", encoding="utf-8")
    monkeypatch.setenv(SCAN_ROOT_ENV, str(root))
    monkeypatch.chdir(tmp_path)  # cwd is OUTSIDE the root on purpose
    return root, outside


def test_inside_the_root_still_scans(fenced):
    root, _ = fenced
    for p in ("inside.py", str(root / "inside.py")):
        r = _scan(p)
        assert not r.is_error, (p, r.content)


def test_traversal_out_of_the_root_is_refused(fenced):
    root, outside = fenced
    for p in ("..\\outside.py", "../outside.py", "sub\\..\\..\\outside.py",
              str(root) + "\\..\\outside.py"):
        r = _scan(p)
        assert r.is_error, f"{p!r} escaped the root: {_text(r)[:200]}"
        assert "MCP_VET_SCAN_ROOT" in _text(r), _text(r)


def test_absolute_path_outside_the_root_is_refused(fenced):
    _, outside = fenced
    r = _scan(str(outside))
    assert r.is_error, _text(r)
    r = _scan(str(Path(__file__).resolve()))  # this very file, definitely outside
    assert r.is_error, _text(r)


def test_unc_path_is_refused(fenced):
    for p in (r"\\localhost\c$\Windows\win.ini", "//localhost/c$/Windows/win.ini",
              r"\\?\C:\Windows\win.ini"):
        r = _scan(p)
        assert r.is_error, f"{p!r}: {_text(r)[:200]}"


def test_drive_relative_path_is_refused(fenced):
    """`C:outside.py` means 'outside.py in the current directory of drive C',
    and the current directory is outside the root."""
    _, outside = fenced
    drive = outside.drive or "C:"
    r = _scan(f"{drive}{outside.name}")
    assert r.is_error, _text(r)


def test_symlink_pointing_out_of_the_root_is_refused(fenced):
    root, outside = fenced
    link = root / "link.py"
    try:
        os.symlink(str(outside), str(link))
    except (OSError, NotImplementedError) as e:
        pytest.skip(f"cannot create a symlink here: {e}")
    r = _scan("link.py")
    assert r.is_error, f"symlink out of the root was followed: {_text(r)[:200]}"


def test_without_the_env_var_behaviour_is_unchanged(tmp_path, monkeypatch):
    """The fence is opt-in. Unset, the disclosed exposure stands and the old
    tests' absolute tmp paths keep working."""
    monkeypatch.delenv(SCAN_ROOT_ENV, raising=False)
    p = tmp_path / "anywhere.py"
    p.write_text("x = 1\n", encoding="utf-8")
    assert not _scan(str(p)).is_error


# --- 2026-09-05 input fuzz: the fence covers audit_verify too, and no argument ---
# --- can blow up the reply or the record, or erase a call from it -----------------

def _call(tool: str, args: dict):
    async def go():
        async with Client(build_server()) as client:
            return await client.call_tool(tool, args)
    return asyncio.run(go())


def _audit_rows(monkeypatch, tmp_path):
    """Point the audit ledger at a fresh file for one test; return a reader."""
    p = tmp_path / "audit.jsonl"
    monkeypatch.setenv("MCP_VET_AUDIT_LEDGER", str(p))

    def rows():
        if not p.exists():
            return []
        return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    return rows


def test_audit_verify_on_a_path_outside_the_root_is_refused(fenced):
    """Before the fix `mcp_vet_audit_verify` took a caller-named path straight
    to `verify_file`: with the fence up, `mcp_vet_scan` on the outside file was
    refused and `mcp_vet_audit_verify` on the same file returned rows=1 plus
    the first unparseable line number. An existence-and-line-count oracle on
    any file, through the tool the fence forgot."""
    root, outside = fenced
    r = _call("mcp_vet_audit_verify", {"path": str(outside)})
    assert r.is_error, _text(r)
    assert "MCP_VET_SCAN_ROOT" in _text(r) and "rows" not in _text(r)
    # Missing and present are refused identically: no oracle.
    r2 = _call("mcp_vet_audit_verify", {"path": str(outside.with_name("nope.jsonl"))})
    assert r2.is_error and _text(r2).replace("nope.jsonl", "outside.py") == _text(r)
    r3 = _call("mcp_vet_audit_verify", {"path": "../outside.py"})
    assert r3.is_error, _text(r3)


def test_audit_verify_still_reads_its_own_ledger_outside_the_root(fenced, monkeypatch, tmp_path):
    """The server's own audit ledger lives under ~ by default, i.e. outside any
    scan root; it is the one out-of-root file this tool exists to read."""
    pytest.importorskip("arcaeon.record.ledger", reason="the audit lane needs the [audit] extra")
    rows = _audit_rows(monkeypatch, tmp_path)   # tmp_path is outside root/
    _scan("inside.py")
    assert len(rows()) == 1
    ledger = str(tmp_path / "audit.jsonl")
    for args in ({}, {"path": ledger}):
        r = _call("mcp_vet_audit_verify", args)
        assert not r.is_error, _text(r)
        payload = json.loads(_text(r))
        assert payload["rows"] == 1 and payload["ok"] is True, payload


def test_a_megabyte_path_gets_a_bounded_reply_and_a_bounded_audit_row(monkeypatch, tmp_path):
    """1 MB path -> a 1 MB error reply and a 2 MB audit row (path echoed in
    args AND in the error text), per call, unbounded. Now: the echo is clipped
    to PATH_ECHO_MAX, the digest of the full path is kept."""
    pytest.importorskip("arcaeon.record.ledger", reason="the audit lane needs the [audit] extra")
    import hashlib
    from arcaeon.prove.vet.server import PATH_ECHO_MAX
    monkeypatch.delenv(SCAN_ROOT_ENV, raising=False)
    rows = _audit_rows(monkeypatch, tmp_path)
    big = "A" * (1 << 20)
    for tool in ("mcp_vet_scan", "mcp_vet_grade", "mcp_vet_audit_verify"):
        r = _call(tool, {"path": big})
        assert len(_text(r)) < 4096, (tool, len(_text(r)))
    row = rows()[0]
    assert len(json.dumps(row)) < 8192
    assert row["args"]["path"].startswith("A" * PATH_ECHO_MAX)
    assert row["args"]["path_len"] == len(big)
    assert row["args"]["path_sha256"] == hashlib.sha256(big.encode()).hexdigest()
    assert len(row["error"]) <= 2000 + 40


def test_a_lone_surrogate_in_the_path_still_leaves_an_audit_row(monkeypatch, tmp_path):
    """The JSON escape \\ud800 is legal JSON. It reached `_record_call` inside args.path and
    the error text, and the ledger's strict utf-8 write raised: no row, and a
    caller told 'could not be written'. The call stays on the record."""
    pytest.importorskip("arcaeon.record.ledger", reason="the audit lane needs the [audit] extra")
    monkeypatch.delenv(SCAN_ROOT_ENV, raising=False)
    rows = _audit_rows(monkeypatch, tmp_path)
    r = _call("mcp_vet_scan", {"path": "\ud800"})
    assert r.is_error
    assert "could not be written" not in _text(r), _text(r)
    assert len(rows()) == 1
    row = rows()[0]
    assert row["tool"] == "mcp_vet_scan" and row["error"]
    assert row["args"]["path"] == "?" and "path_sha256" in row["args"]  # encode('replace') -> ?
    payload = json.loads(_text(_call("mcp_vet_audit_verify", {})))
    assert payload["ok"] is True and payload["rows"] == 1
