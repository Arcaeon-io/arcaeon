"""Live tests for `mcp-vet probe` (2026-09-05): a real stdio server
(tests/fixtures/probe_server.py) launched as a subprocess, a real
initialize / tools/list / tools/call round-trip through the SDK's client,
and the artifact the CLI prints.

What has to be true, per fixture tool:
  list_posts        filters for real, rejects unknown keys  -> no finding
  list_comments     ignores user_id, swallows unknown keys  -> BOTH verdicts
  get_post          one item                                -> blind spot
  create_post       no readOnlyHint                         -> blind spot, and
                                                               NEVER called
  list_ratelimited  first call 429s                         -> no finding, no
                                                               blind spot, two
                                                               control calls
plus the cap, the artifact's framing fields, the missing-SDK message, and a
connection failure landing as a blind spot with a non-zero exit.

Two PLANTED RED tests carry the verdicts list_comments must draw: if the
check ever skipped silently they fail while every "yields nothing" test
would still pass.
"""
import json
import os
import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

pytest.importorskip("mcp", reason="the probe lane needs the `mcp` extra")

from arcaeon.prove.vet import probe as probe_mod  # noqa: E402
from arcaeon.prove.vet.__main__ import main  # noqa: E402
from arcaeon.prove.vet.badge_cli import NOT_A_CERTIFICATION  # noqa: E402
from arcaeon.prove.vet.dynamic_checks import (  # noqa: E402
    DOES_NOT_BIND, UNKNOWN_ACCEPTED, dynamic_check_names)
from arcaeon.prove.vet.probe import ProbeSession, run_probe  # noqa: E402

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "tests" / "fixtures" / "probe_server.py"
SERVER_CMD = [sys.executable, str(FIXTURE)]


@pytest.fixture(scope="module")
def counter_file(tmp_path_factory):
    return tmp_path_factory.mktemp("probe") / "create_post_calls.txt"


@pytest.fixture(scope="module")
def probed(counter_file):
    """One full probe of the fixture server, shared by the tests that read
    it. The env var is how create_post reports being called."""
    env = {**os.environ, "MCP_VET_PROBE_COUNTER": str(counter_file)}
    log = []
    art = run_probe(SERVER_CMD, env=env, backoff_base=0.01, timeout=30, call_log=log)
    art["_call_log"] = log        # test-only; never in the printed artifact
    return art


def _findings_for(art, tool):
    return [f for f in art["findings"] if f["file"] == tool]


def _blind(art, tool):
    return [b for b in art["blind_spots"] if b["tool"] == tool]


# --- per-tool outcomes -------------------------------------------------------

def test_connected_and_listed_all_five(probed):
    assert probed["connected"] is True
    assert probed["tools_listed"] == 5
    assert probed["cap_hit"] is False
    assert probed["calls_made"] <= probed["call_cap"]


def test_honest_tool_draws_no_finding(probed):
    assert _findings_for(probed, "list_posts") == []
    assert _blind(probed, "list_posts") == []


def test_PLANTED_RED_ignored_param_draws_does_not_bind(probed):
    """PLANTED RED: list_comments declares user_id and ignores it. The probe
    MUST say so, with the counts it compared."""
    fs = [f for f in _findings_for(probed, "list_comments") if DOES_NOT_BIND in f["detail"]]
    assert len(fs) == 1, probed["findings"]
    f = fs[0]
    assert f["check"] == "param-binding-liveness" and f["severity"] == "high"
    assert f["line"] == 0
    assert "user_id=" in f["detail"] and "returned 9 item(s), control returned 9" in f["detail"]


def test_PLANTED_RED_swallowed_unknown_key_draws_unknown_accepted(probed):
    """PLANTED RED: list_comments accepts a key outside its schema with a
    success result. The probe MUST say so and name the key it sent."""
    fs = [f for f in _findings_for(probed, "list_comments") if UNKNOWN_ACCEPTED in f["detail"]]
    assert len(fs) == 1, probed["findings"]
    assert fs[0]["severity"] == "medium"
    assert "mcp_vet_unknown_probe_" in fs[0]["detail"]


def test_singular_tool_is_a_blind_spot_not_a_finding(probed):
    assert _findings_for(probed, "get_post") == []
    b = _blind(probed, "get_post")
    assert len(b) == 1 and "naturally singular" in b[0]["reason"]
    assert "returned 1" in b[0]["reason"]


def test_write_tool_is_a_blind_spot_and_was_never_called(probed, counter_file):
    assert _findings_for(probed, "create_post") == []
    b = _blind(probed, "create_post")
    assert len(b) == 1 and "readOnlyHint" in b[0]["reason"]
    assert not counter_file.exists(), counter_file.read_text() if counter_file.exists() else ""


def test_rate_limited_tool_recovers_through_backoff(probed):
    assert _findings_for(probed, "list_ratelimited") == []
    assert _blind(probed, "list_ratelimited") == []
    controls = [(a, e) for n, a, e in probed["_call_log"]
                if n == "list_ratelimited" and a == {}]
    assert len(controls) == 2, controls
    assert controls[0][1] is not None and "429" in controls[0][1]
    assert controls[1][1] is None


def test_only_read_only_tools_were_probed(probed):
    assert probed["tools_probed"] == 4      # everything but create_post
    called = {n for n, _, _ in probed["_call_log"]}
    assert "create_post" not in called
    assert called == {"list_posts", "list_comments", "get_post", "list_ratelimited"}


def test_artifact_never_carries_the_call_log(probed):
    """The log is a test/operator aid handed back through `call_log=`; the
    printed artifact stays the documented shape."""
    art = run_probe(SERVER_CMD, max_calls=1, backoff_base=0.01, timeout=30)
    assert "_call_log" not in art and "call_log" not in art


# --- the artifact's framing --------------------------------------------------

def test_artifact_carries_the_framing_fields(probed):
    assert probed["kind"] == "mcp_vet_probe"
    assert probed["not_a_certification"] == NOT_A_CERTIFICATION
    assert probed["dynamic_checks_run"] == dynamic_check_names()
    assert probed["server_command"] == SERVER_CMD
    assert probed["call_cap"] == probe_mod.DEFAULT_MAX_CALLS
    # observed_at is a real, timezone-aware ISO-8601 UTC instant
    ts = datetime.fromisoformat(probed["observed_at"])
    assert ts.tzinfo is not None and ts.utcoffset().total_seconds() == 0
    assert "one observation" in probed["scope_note"].lower()
    assert "what we were allowed to test binds" in probed["scope_note"]
    assert "TOOL NAME" in probed["site_convention"]


def test_artifact_is_json_serialisable(probed):
    art = {k: v for k, v in probed.items() if k != "_call_log"}
    assert json.loads(json.dumps(art)) == art


# --- the cap -----------------------------------------------------------------

def test_cap_stops_calls_and_is_stated():
    art = run_probe(SERVER_CMD, max_calls=2, backoff_base=0.01, timeout=30)
    assert art["connected"] is True
    assert art["cap_hit"] is True
    assert art["calls_made"] == 2 and art["call_cap"] == 2
    reasons = [b["reason"] for b in art["blind_spots"]]
    assert any("call cap (2) reached before this tool was fully probed" in r for r in reasons)
    assert sum("not probed: call cap (2) reached" in r for r in reasons) == 4
    # a probe cut short is not a clean probe: the artifact must not report
    # the tools it never reached as anything but blind spots
    assert {b["tool"] for b in art["blind_spots"]} == {
        "list_posts", "list_comments", "get_post", "create_post", "list_ratelimited"}


# --- the harness's own fences --------------------------------------------------

def test_session_refuses_a_tool_not_seen_read_only():
    """Second fence, independent of the check: whatever a check asks for,
    the harness will not call a tool it has not seen annotated read-only."""
    s = ProbeSession(client=None, loop=None)
    with pytest.raises(RuntimeError, match="not annotated readOnlyHint"):
        s.call("create_post", {})
    assert s.calls_made == 0


def test_rate_limit_backoff_is_bounded(monkeypatch):
    """A server that 429s forever gets RATE_RETRIES retries, every one of
    them counted against the cap, and then the error is returned. No spiral."""
    import asyncio

    class AlwaysLimited:
        async def call_tool(self, name, arguments, read_timeout_seconds=None):
            from types import SimpleNamespace
            return SimpleNamespace(is_error=True,
                                   content=[SimpleNamespace(text="429 rate limited")],
                                   structured_content=None)
    sleeps = []
    monkeypatch.setattr(probe_mod.time, "sleep", lambda s: sleeps.append(s))
    loop = asyncio.new_event_loop()
    try:
        s = ProbeSession(client=AlwaysLimited(), loop=loop, backoff_base=0.5,
                         read_only_tools={"t"})
        out = s.call("t", {})
    finally:
        loop.close()
    assert out.error and "429" in out.error
    assert s.calls_made == probe_mod.RATE_RETRIES + 1
    assert sleeps == [0.5, 1.0, 2.0]


# --- failure modes -----------------------------------------------------------

def test_connection_failure_is_a_blind_spot_and_nonzero_exit(capsys):
    cmd = [sys.executable, str(HERE / "tests" / "fixtures" / "no_such_probe_server.py")]
    art = run_probe(cmd, timeout=30)
    assert art["connected"] is False
    assert art["findings"] == []
    assert art["tools_listed"] == 0 and art["calls_made"] == 0
    assert len(art["blind_spots"]) == 1
    assert art["blind_spots"][0]["tool"] is None
    assert art["blind_spots"][0]["reason"].startswith("connection failed: ")
    # and the CLI: exit 2, the JSON still printed, the reason on the summary
    rc = main(["probe", "--json", "--timeout", "30", "--"] + cmd)
    assert rc == 2
    out = json.loads(capsys.readouterr().out)
    assert out["connected"] is False and out["kind"] == "mcp_vet_probe"


def test_cli_needs_the_extra_message(monkeypatch, capsys):
    monkeypatch.setitem(sys.modules, "mcp", None)
    rc = main(["probe", "--", sys.executable, "whatever.py"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "needs the MCP Python SDK" in err and "[mcp]" in err


def test_cli_without_a_command_says_so(capsys):
    assert main(["probe"]) == 2
    assert "needs a server command" in capsys.readouterr().err


def test_cli_summary_and_exit_code(capsys, counter_file):
    """Exit 1 on the high finding, summary names the tool and the verdict."""
    os.environ["MCP_VET_PROBE_COUNTER"] = str(counter_file)
    try:
        rc = main(["probe", "--timeout", "30", "--"] + SERVER_CMD)
    finally:
        os.environ.pop("MCP_VET_PROBE_COUNTER", None)
    assert rc == 1
    out = capsys.readouterr().out
    assert "tools listed 5, probed 4" in out
    assert "@ tool list_comments: %s" % DOES_NOT_BIND in out
    assert "blind spot: create_post" in out
    assert "dynamic checks run: param-binding-liveness" in out
    assert NOT_A_CERTIFICATION in out
    assert not counter_file.exists()


def test_cli_json_flag_prints_only_the_artifact(capsys):
    rc = main(["probe", "--json", "--max-calls", "1", "--timeout", "30", "--"] + SERVER_CMD)
    assert rc == 0                                     # cap hit, nothing found
    art = json.loads(capsys.readouterr().out)
    assert art["cap_hit"] is True and art["calls_made"] == 1
    assert art["dynamic_checks_run"] == dynamic_check_names()
