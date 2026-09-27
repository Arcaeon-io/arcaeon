"""K061: `arcaeon export --format agent-audit-trail`, the field mapping.

The fixture is a real proxy tape: the stdio proxy's SeamObserver writing into
a Ledger (session_begin, an ok tool call, a failing tool call, session_end),
plus one enforce-mode mandate block row in the gate's own shape.
"""
import json

import pytest

from arcaeon import verdict as V
from arcaeon.prove import aat_cli
from arcaeon.prove.aat_export import AGENT_URI_PREFIX, NEVER_EMITTED, export_aat, map_row
from arcaeon.record.adapter.observer import SeamObserver
from arcaeon.record.ledger import Ledger

SESSION = "0b7c2a6e-1f7e-4c55-9a53-2d7f0e1b9c11"
ALLOWED = {"timestamp", "agent_id", "session_id", "action_type", "action_detail",
           "response_hash", "input_hash", "output_hash", "outcome", "sequence_number",
           "recording_component", "chain", "source_line",
           "prev_hash"}  # K062: the draft's own chain field


def _frame(obj):
    return (json.dumps(obj) + "\n").encode("utf-8")


@pytest.fixture
def tape(tmp_path):
    p = tmp_path / "tape.jsonl"
    lg = Ledger(p)
    obs = SeamObserver(lg.append, server="files", session=SESSION)
    obs.session_begin()
    obs.observe_client_frame(_frame({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                     "params": {"name": "read_file",
                                                "arguments": {"path": "a.txt"}}}))
    obs.observe_server_frame(_frame({"jsonrpc": "2.0", "id": 1,
                                     "result": {"content": [{"type": "text",
                                                             "text": "hi"}]}}))
    obs.observe_client_frame(_frame({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                     "params": {"name": "delete_file",
                                                "arguments": {"path": "b.txt"}}}))
    obs.observe_server_frame(_frame({"jsonrpc": "2.0", "id": 2,
                                     "error": {"code": -32000, "message": "no"}}))
    with obs._lock:
        obs._row("mandate_outside", verdict="outside", rule="tools", reason="not allowed",
                 tool="wire_money", args_digest="sha256:json-c14n:v1:" + "0" * 64,
                 mandate_mode="enforce", action="blocked")
    obs.session_end(reason="eof", exit_code=0)
    return p


@pytest.fixture
def exported(tape, tmp_path):
    out = tmp_path / "aat.jsonl"
    res = export_aat(tape, out)
    recs = [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines()]
    return res, recs, tape


def _by_type(recs, t):
    return [r for r in recs if r.get("action_type") == t]


def test_one_record_per_row_verified(exported):
    res, recs, tape = exported
    assert res["verdict"] == V.VERIFIED and res["exit"] == 0
    assert len(recs) == len(tape.read_bytes().splitlines()) == 5
    assert [r["source_line"] for r in recs] == [1, 2, 3, 4, 5]


def test_only_can_emit_now_fields(exported):
    _, recs, _ = exported
    for r in recs:
        assert set(r) <= ALLOWED, set(r) - ALLOWED
        if "action_detail" in r:
            assert set(r["action_detail"]) <= {"tool_name", "parameters_hash"}


def test_never_record_id_signature_or_trust_level_above_l1(exported):
    _, recs, _ = exported
    for r in recs:
        assert "record_id" not in r and "signature" not in r and "signer_kid" not in r
        assert r.get("trust_level", "L0") in ("L0", "L1")
        for f in NEVER_EMITTED:
            assert f not in r


def test_tool_calls_map_their_fields(exported, tape):
    _, recs, _ = exported
    rows = [json.loads(l) for l in tape.read_text(encoding="utf-8").splitlines()]
    calls = _by_type(recs, "tool_call")
    assert [c["action_detail"]["tool_name"] for c in calls] == ["read_file", "delete_file"]
    assert [c["outcome"] for c in calls] == ["success", "failure"]
    for c in calls:
        row = rows[c["source_line"] - 1]
        assert c["timestamp"] == row["ts"]
        assert c["session_id"] == SESSION
        assert c["sequence_number"] == row["seq"]
        assert c["action_detail"]["parameters_hash"] == row["args_digest"]
        assert c["response_hash"] == row["result_digest"]
        assert c["recording_component"].startswith("arcaeon proxy (mcp-stdio")


def test_original_chain_on_every_record(exported, tape):
    _, recs, _ = exported
    rows = [json.loads(l) for l in tape.read_text(encoding="utf-8").splitlines()]
    assert [r["chain"] for r in recs] == [row["chain"] for row in rows]


def test_lifecycle_and_denied(exported):
    _, recs, _ = exported
    assert len(_by_type(recs, "lifecycle")) == 2
    (block,) = _by_type(recs, "decision")
    assert block["outcome"] == "denied"
    assert block["action_detail"]["tool_name"] == "wire_money"


def test_proxy_rows_have_no_agent_id_guessed(exported):
    """The proxy tape names the server, not the agent: agent_id is left out."""
    _, recs, _ = exported
    assert all("agent_id" not in r for r in recs)


def test_agent_id_uri_prefix_and_input_output_hashes():
    r = map_row({"ts": "2026-09-01T10:00:00Z", "agent": "desk bot/1", "event": "decision",
                 "inputs": {"q": 1}, "outputs": {"a": 2}, "chain": "ab" * 16})
    assert r["agent_id"] == AGENT_URI_PREFIX + "desk%20bot%2F1"
    assert r["input_hash"].startswith("sha256:") and r["output_hash"].startswith("sha256:")
    assert r["input_hash"] != r["output_hash"]
    assert r["action_type"] == "decision" and "outcome" not in r
    assert map_row({"system_id": "sys-a"})["agent_id"] == AGENT_URI_PREFIX + "sys-a"


def test_unknown_kind_leaves_action_type_out():
    assert "action_type" not in map_row({"event": "reference_check"})


def test_jsonl_only_and_never_overwrites(tape, tmp_path):
    from arcaeon.prove.aat_export import AatUsageError
    with pytest.raises(AatUsageError):
        export_aat(tape, tmp_path / "aat.csv")
    out = tmp_path / "aat.jsonl"
    out.write_text("", encoding="utf-8")
    with pytest.raises(AatUsageError):
        export_aat(tape, out)


def test_broken_source_is_exit_1_and_still_exported(tape, tmp_path):
    tape.write_bytes(tape.read_bytes().replace(b"read_file", b"read_fils"))
    res = export_aat(tape, tmp_path / "aat.jsonl")
    assert res["verdict"] == V.BROKEN and res["exit"] == 1 and res["records"] == 5


def test_cli(tape, tmp_path, capsys):
    out = tmp_path / "aat.jsonl"
    rc = aat_cli.main(["--format", "agent-audit-trail", str(tape), "--out", str(out)])
    assert rc == 0
    assert capsys.readouterr().out.startswith("VERIFIED: 5 record(s)")
    assert aat_cli.main(["--format", "csv", str(tape), "--out", str(out)]) == 2
    assert aat_cli.main(["--format", "agent-audit-trail", str(tmp_path / "none.jsonl"),
                         "--out", str(tmp_path / "x.jsonl")]) == 3
