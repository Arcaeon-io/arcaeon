"""The connector's OWN call record (OWASP MCP08), added 2026-09-02 for 0.1.4.

mcp-vet's `audit-record` check graded `arcaeon_connector/server.py` gate 0 of
4 on 2026-09-02: eleven tool handlers and not one of them left a record that
the connector had been called. The ledger tools write the caller's ledger and
the vet tools write mcp-vet's, so every existing recording test here was about
somebody else's record. These tests are about the connector's.

Every test drives the server through a real MCP round-trip (the SDK's
in-process client), the same way test_connector.py does, so a `_record_call`
that was wired to a handler the SDK never reaches would not count.
"""
import asyncio
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

pytest.importorskip("mcp", reason="the connector IS an MCP server")

from mcp import Client  # noqa: E402

from arcaeon.mcp.server import (  # noqa: E402
    ALL_TOOLS,
    build_server,
    call_record_path,
    verify_call_record,
)

CLEAN_SERVER = "x = 1\n"


def _call(tool, args=None):
    """One tools/call; returns (is_error, payload) so a refused call is a
    result to assert on rather than an exception to dodge."""
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


def _rows(path):
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines()
            if l.strip()]


def _isolate(monkeypatch, tmp_path):
    """Everything the connector can write goes under tmp: the caller's ledger,
    the per-namespace ledgers, mcp-vet's audit ledger, and the connector's own
    call record (the subject here). No key, license gate off."""
    monkeypatch.setenv("ARCAEON_LEDGER_LOG", str(tmp_path / "agent.log.jsonl"))
    monkeypatch.setenv("ARCAEON_LEDGER_NS_DIR", str(tmp_path / "ledgers"))
    monkeypatch.setenv("MCP_VET_AUDIT_LEDGER", str(tmp_path / "vet_audit.jsonl"))
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(tmp_path / "arcaeon.calls.jsonl"))
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    for var in ("LICENSE_GATE_REQUIRED", "ARCAEON_LICENSE_KEY",
                "LICENSE_GATE_MODULE", "LICENSE_GATE_SECRET"):
        monkeypatch.delenv(var, raising=False)
    return tmp_path / "arcaeon.calls.jsonl"


def _drive_every_tool_once(tmp_path):
    """One call per advertised tool, in an order where each succeeds: a
    namespace ledger is written by prove_my_conduct and then tampered so
    declare_break has a real break to declare. Returns {tool: (is_error,
    payload)}."""
    clean = tmp_path / "clean.py"
    clean.write_text(CLEAN_SERVER, encoding="utf-8")
    out = {}

    out["ledger_append"] = _call("ledger_append", {"record": {"op": "test"}})
    out["ledger_verify"] = _call("ledger_verify", {"strict": True})
    out["ledger_prove_my_conduct"] = _call(
        "ledger_prove_my_conduct", {"namespace": "acme", "events": ["did a thing"]})
    peer_text = (tmp_path / "agent.log.jsonl").read_text(encoding="utf-8")
    out["ledger_verify_peer_ledger"] = _call(
        "ledger_verify_peer_ledger", {"jsonl_text": peer_text, "strict": True})
    ns_file = tmp_path / "ledgers" / "acme.jsonl"
    assert ns_file.is_file(), sorted(p.name for p in (tmp_path / "ledgers").iterdir())
    # a hand-appended, unchained row: the break declare_break exists for
    with ns_file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"op": "conduct", "event": "typed in by hand"}) + "\n")
    out["ledger_declare_break"] = _call(
        "ledger_declare_break", {"namespace": "acme", "reason": "test fixture hand-append"})
    out["vet_scan"] = _call("vet_scan", {"path": str(clean)})
    out["vet_grade"] = _call("vet_grade", {"path": str(clean)})
    out["vet_audit_verify"] = _call("vet_audit_verify", {})
    out["witness_pin"] = _call("witness_pin", {"namespace": "acme", "rows": 1, "chain": "ab"})
    out["witness_renew"] = _call("witness_renew", {"namespace": "acme", "rows": 1, "chain": "ab"})
    out["arcaeon_status"] = _call("arcaeon_status", {})
    return out


# --- one record per tool ---------------------------------------------------

def test_every_tool_leaves_exactly_one_record_with_its_own_name(monkeypatch, tmp_path):
    """Eleven tools, eleven rows, eleven names, in call order. The count alone
    would pass if one handler recorded twice and another not at all, so the
    names are asserted as a list, not a set."""
    rec = _isolate(monkeypatch, tmp_path)
    results = _drive_every_tool_once(tmp_path)

    failed = {t: p for t, (err, p) in results.items() if err}
    assert not failed, f"the fixture drive itself refused: {failed}"
    assert sorted(results) == sorted(ALL_TOOLS), (sorted(results), ALL_TOOLS)

    rows = _rows(rec)
    assert len(rows) == len(ALL_TOOLS) == 11, [r["tool"] for r in rows]
    assert [r["tool"] for r in rows] == list(results), [r["tool"] for r in rows]
    assert all(r["ok"] is True for r in rows), [(r["tool"], r.get("error")) for r in rows]
    for r in rows:
        assert r["op"] == "tool_call", r
        assert r["ts"].endswith("+00:00"), r["ts"]         # UTC, said so
        assert len(r["args_digest"]) == 64, r               # sha256 hex
        assert r["args_digest_alg"] == "sha256", r
        assert isinstance(r["chain"], str) and r["chain"], r
        assert "args" not in r, "arguments must be digested, not copied"


def test_the_chain_verifies_and_a_tampered_row_is_named(monkeypatch, tmp_path):
    """Gate 4: the record set can be checked by someone who was not there.
    Three verifiers agree on the same bytes: the connector's own
    `verify_call_record`, arcaeon-ledger's `verify_file` (the format is
    theirs), and the connector's `ledger_verify_peer_ledger` TOOL, which is
    how an agent on the other side of the pipe would do it. Then one row is
    edited and all three name the line."""
    rec = _isolate(monkeypatch, tmp_path)
    _drive_every_tool_once(tmp_path)

    v = verify_call_record(rec)
    assert v["ok"] is True and v["rows"] == 11 and v["breaks"] == 0, v
    assert v["first_break"] is None, v

    from arcaeon.record.ledger import verify_file
    lib = verify_file(rec, strict=True)
    assert lib.ok is True and lib.rows == 11, lib

    err, through_tool = _call("ledger_verify_peer_ledger",
                              {"jsonl_text": rec.read_text(encoding="utf-8"), "strict": True})
    assert not err, through_tool
    assert through_tool["rows"] == 11, through_tool
    assert through_tool.get("ok", through_tool.get("chain_verified")) is True, through_tool
    # that verification was itself a tool call, so it is row 12 now
    assert [r["tool"] for r in _rows(rec)][-1] == "ledger_verify_peer_ledger"

    lines = rec.read_text(encoding="utf-8").splitlines()
    assert '"ok": true' in lines[4], lines[4]
    lines[4] = lines[4].replace('"ok": true', '"ok": false')   # flip row 5's outcome
    rec.write_text("\n".join(lines) + "\n", encoding="utf-8")

    v = verify_call_record(rec)
    assert v["ok"] is False and v["breaks"] >= 1, v
    assert v["first_break"] and "5" in str(v["first_break"]), v
    assert verify_file(rec, strict=True).ok is False


# --- failure is recorded as failure ----------------------------------------

def test_a_refused_call_is_recorded_as_a_failure_not_a_success(monkeypatch, tmp_path):
    """`_record_call` runs AFTER the work and carries the outcome, so a call
    the ledger refused (declare_break on a namespace with no ledger) lands as
    ok:false with the refusal text, and the caller still gets the error. A
    record that was written before the work would have said ok:true here."""
    rec = _isolate(monkeypatch, tmp_path)
    err, payload = _call("ledger_declare_break", {"namespace": "ghost", "reason": "why not"})
    assert err, payload
    assert "no ledger for namespace" in json.dumps(payload), payload

    rows = _rows(rec)
    assert len(rows) == 1, rows
    assert rows[0]["tool"] == "ledger_declare_break"
    assert rows[0]["ok"] is False, rows[0]
    assert "no ledger for namespace" in rows[0]["error"], rows[0]
    assert verify_call_record(rec)["ok"] is True


def test_a_paid_tool_refusal_is_a_recorded_success(monkeypatch, tmp_path):
    """The no-key upgrade message is the designed answer, not a failure: the
    connector did exactly what it says it does. So the row says ok:true and
    the digest covers the arguments the caller actually sent."""
    rec = _isolate(monkeypatch, tmp_path)
    args = {"namespace": "acme", "rows": 3, "chain": "abcd"}
    err, payload = _call("witness_pin", args)
    assert not err and "buy.stripe.com" in json.dumps(payload), payload

    row = _rows(rec)[0]
    assert row["tool"] == "witness_pin" and row["ok"] is True, row
    canonical = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    assert row["args_digest"] == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert row["args_bytes"] == len(canonical)


# --- where it lives --------------------------------------------------------

def test_call_record_env_var_is_read_and_the_default_sits_beside_the_ledger(monkeypatch, tmp_path):
    """The override is `ARCAEON_CALL_RECORD`, the same variable the other four
    Arcaeon servers honour. Without it the record lives in the ledger log's
    directory, never IN the ledger log: the caller's conduct record and the
    connector's call record are two files, so `ledger_verify` keeps counting
    only the caller's rows."""
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(tmp_path / "elsewhere" / "calls.jsonl"))
    _call("arcaeon_status", {})
    assert (tmp_path / "elsewhere" / "calls.jsonl").is_file()
    assert not (tmp_path / "arcaeon.calls.jsonl").exists()

    monkeypatch.delenv("ARCAEON_CALL_RECORD")
    assert call_record_path() == (tmp_path / "agent.log.jsonl").resolve().parent / "arcaeon.calls.jsonl"
    _call("ledger_append", {"record": {"op": "one"}})
    _call("ledger_append", {"record": {"op": "two"}})
    assert (tmp_path / "arcaeon.calls.jsonl").is_file()
    err, verified = _call("ledger_verify", {"strict": True})
    assert not err and verified["rows"] == 2, verified   # the caller's rows only
    assert verify_call_record()["rows"] == 3               # two appends + this verify

    err, st = _call("arcaeon_status", {})
    assert st["call_record_path"] == str(call_record_path()), st


def test_verify_call_record_with_no_record_is_null_not_green():
    """No file is not a passing chain. `ok` is None, the way arcaeon-ledger's
    bounded verdicts are, so an `if ok:` reader fails safe."""
    v = verify_call_record(Path("no") / "such" / "record.jsonl")
    assert v["ok"] is None and v["rows"] == 0, v


def test_a_lone_surrogate_in_an_argument_still_leaves_a_record(monkeypatch, tmp_path):
    """The JSON escape \\ud800 is legal JSON and arrives as a lone surrogate.
    Upstream quotes the argument back in its error ("not a readable file:
    <path>"), that text went into `row["error"]`, and `Ledger.append`'s strict
    utf-8 write refused the row: the call vanished from the connector's own
    record and the caller was told the record could not be written (2026-09-05
    input fuzz). Every tool that takes a string gets the character; every call
    must land as ok:false with a row."""
    rec = _isolate(monkeypatch, tmp_path)
    cases = [
        ("vet_scan", {"path": "\ud800"}),
        ("vet_grade", {"path": "\ud800"}),
        ("ledger_append", {"record": {"a": "\ud800"}}),
        ("ledger_prove_my_conduct", {"namespace": "\ud800", "events": ["e"]}),
        ("ledger_prove_my_conduct", {"namespace": "ok", "events": ["\ud800"]}),
        ("ledger_declare_break", {"namespace": "\ud800", "reason": "r"}),
        ("ledger_verify_peer_ledger", {"jsonl_text": "{\"a\":\"\ud800\"}\n"}),
    ]
    for tool, args in cases:
        err, payload = _call(tool, args)
        # verify_peer_ledger is the one case that is not a refusal: the text
        # is one unchained row, which is a bounded (ok: null) verdict.
        assert err or tool == "ledger_verify_peer_ledger", (tool, payload)
        assert "could not be written" not in json.dumps(payload, ensure_ascii=True), (tool, payload)
    rows = _rows(rec)
    assert [r["tool"] for r in rows] == [t for t, _ in cases], rows
    assert [r["ok"] for r in rows] == [False] * 6 + [True], rows
    assert verify_call_record(rec)["ok"] is True


def test_an_upstream_error_quoting_a_surrogate_does_not_lose_the_row(monkeypatch, tmp_path):
    """The connector's own defense, exercised directly: an upstream that quotes
    the raw argument back (mcp-vet without its audit extra raises
    FileNotFoundError("not a readable file: <path>") verbatim) hands
    `_record_call` an error string with a lone surrogate in it. Without the
    replace step, `Ledger.append` raised and the connector re-raised
    "could not be written" -- the call lost, the caller misinformed."""
    from arcaeon.mcp.server import _Outcome, _record_call
    rec = _isolate(monkeypatch, tmp_path)
    err = FileNotFoundError("not a readable file: \ud800")
    with pytest.raises(FileNotFoundError):
        _record_call("vet_scan", {"path": "\ud800"}, _Outcome(error=err))
    rows = _rows(rec)
    assert len(rows) == 1 and rows[0]["ok"] is False, rows
    assert rows[0]["error"].startswith("FileNotFoundError: not a readable file: "), rows[0]
    assert verify_call_record(rec)["ok"] is True
