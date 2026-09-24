# SPDX-License-Identifier: MIT
"""Agent-facing MCP tools (0.7.0): prove_my_conduct / verify_peer_ledger / declare_break.

The three existing tools are ledger-operator tools — append a row, verify a file.
These three are AGENT tools, and the difference is who the output is for:

  prove_my_conduct   — an agent logs a batch of what it just did and gets back a
                       single chain head it can hand its principal.
  verify_peer_ledger — an agent is handed ANOTHER agent's exported log as text
                       and has to decide whether to trust it, without ever
                       touching that agent's filesystem.
  declare_break      — an agent whose own log is broken names the break rather
                       than quietly re-minting a chain that verifies.

Every test here asserts the honesty properties the library already enforces, at
the tool boundary where a client actually reads them: a bounded scan is never
reported as a green, a tampered line is named by its exact number, and a declared
break stays permanently counted.
"""
from __future__ import annotations

import json

import pytest

from arcaeon.record.ledger import Ledger, verify_file


# --- helpers ----------------------------------------------------------------

def _call(name, arguments, log, ns_dir=None, mid=1):
    """Drive one tools/call through the real JSON-RPC handler, as a client does."""
    from arcaeon.record.ledger.mcp_server import handle
    msg = {"jsonrpc": "2.0", "id": mid, "method": "tools/call",
           "params": {"name": name, "arguments": arguments}}
    resp = handle(msg, log, ns_dir=ns_dir)
    assert resp is not None and "result" in resp, resp
    payload = json.loads(resp["result"]["content"][0]["text"])
    return payload, bool(resp["result"].get("isError"))


def _home(tmp_path):
    """The server's own --log plus the namespace dir the tools write under."""
    return Ledger(tmp_path / "agent.log.jsonl"), tmp_path / "ledgers"


def _export(path):
    return path.read_text(encoding="utf-8")


def _ledgers(ns):
    """Ledger files in the namespace dir, ignoring the append-lock sidecars."""
    return sorted(p.name for p in ns.iterdir() if p.suffix == ".jsonl")


# --- prove_my_conduct -------------------------------------------------------

def test_prove_my_conduct_appends_events_and_returns_a_handable_head(tmp_path):
    """The core of C-agent-05: three events in, one chain head out, chain green.

    `head_hash` is the thing the agent gives its principal, so it must be the
    real tip of the real file — not a value the tool computed for the reply.
    """
    log, ns = _home(tmp_path)
    payload, is_err = _call("prove_my_conduct",
                            {"namespace": "billing-agent",
                             "events": ["read invoice 41", "charged $12.00", "emailed receipt"]},
                            log, ns_dir=ns)
    assert not is_err, payload
    assert payload["rows"] == 3, payload
    assert payload["appended"] == 3
    assert payload["chain_verified"] is True
    assert payload["verified_scope"] == "full"

    written = ns / "billing-agent.jsonl"
    assert written.exists(), _ledgers(ns)
    assert payload["head_hash"] == Ledger(written).head().chain
    assert [r["event"] for r in Ledger(written)] == [
        "read invoice 41", "charged $12.00", "emailed receipt"]


def test_prove_my_conduct_extends_the_same_namespace_across_calls(tmp_path):
    """A second batch continues one chain; it does not start a second log."""
    log, ns = _home(tmp_path)
    first, _ = _call("prove_my_conduct", {"namespace": "billing-agent",
                                          "events": ["one"]}, log, ns_dir=ns)
    second, _ = _call("prove_my_conduct", {"namespace": "billing-agent",
                                           "events": ["two", "three"]}, log, ns_dir=ns)
    assert first["rows"] == 1 and second["rows"] == 3
    assert second["appended"] == 2
    assert second["head_hash"] != first["head_hash"]
    assert _ledgers(ns) == ["billing-agent.jsonl"]
    assert verify_file(ns / "billing-agent.jsonl").ok is True


def test_prove_my_conduct_keeps_namespaces_separate(tmp_path):
    log, ns = _home(tmp_path)
    _call("prove_my_conduct", {"namespace": "alpha", "events": ["a"]}, log, ns_dir=ns)
    b, _ = _call("prove_my_conduct", {"namespace": "beta", "events": ["b"]}, log, ns_dir=ns)
    assert b["rows"] == 1
    assert _ledgers(ns) == ["alpha.jsonl", "beta.jsonl"]


def test_prove_my_conduct_reports_a_broken_chain_instead_of_a_green(tmp_path):
    """The tool must never launder its own file: tamper the namespace log and
    `chain_verified` goes false with the break named."""
    log, ns = _home(tmp_path)
    _call("prove_my_conduct", {"namespace": "x", "events": ["a", "b"]}, log, ns_dir=ns)
    p = ns / "x.jsonl"
    lines = p.read_text(encoding="utf-8").split("\n")
    row = json.loads(lines[0])
    row["event"] = "something else entirely"
    lines[0] = json.dumps(row)
    p.write_text("\n".join(lines), encoding="utf-8")

    payload, _ = _call("prove_my_conduct", {"namespace": "x", "events": ["c"]}, log, ns_dir=ns)
    assert payload["chain_verified"] is False, payload
    # The edited row's own chain field no longer matches its recomputed content,
    # so the break is AT line 1 -- not deferred to a successor.
    assert payload["first_break"] == 1, payload


@pytest.mark.parametrize("bad", ["../escape", "a/b", "a\\b", "..", "", "   ", "nul\x00l"])
def test_prove_my_conduct_refuses_a_namespace_that_could_leave_the_dir(tmp_path, bad):
    """A namespace is a name, not a path. Traversal is refused, not sanitized
    into something surprising — and nothing is written anywhere."""
    log, ns = _home(tmp_path)
    payload, is_err = _call("prove_my_conduct", {"namespace": bad, "events": ["x"]},
                            log, ns_dir=ns)
    assert is_err, payload
    assert "namespace" in payload["error"]
    assert not ns.exists() or _ledgers(ns) == []
    assert not (tmp_path / "escape.jsonl").exists()


@pytest.mark.parametrize("events", [None, "not a list", [1, 2], ["ok", None], [{"a": 1}]])
def test_prove_my_conduct_refuses_events_that_are_not_strings(tmp_path, events):
    log, ns = _home(tmp_path)
    payload, is_err = _call("prove_my_conduct", {"namespace": "n", "events": events},
                            log, ns_dir=ns)
    assert is_err, payload
    assert "events" in payload["error"]


def test_prove_my_conduct_with_no_events_reads_without_writing(tmp_path):
    """An empty batch is a legitimate 'what is my head right now' — and it must
    append nothing, so a caller can't accidentally pad its own record."""
    log, ns = _home(tmp_path)
    _call("prove_my_conduct", {"namespace": "n", "events": ["a"]}, log, ns_dir=ns)
    payload, is_err = _call("prove_my_conduct", {"namespace": "n", "events": []},
                            log, ns_dir=ns)
    assert not is_err, payload
    assert payload["appended"] == 0 and payload["rows"] == 1


# --- verify_peer_ledger -----------------------------------------------------

def test_verify_peer_ledger_greens_a_clean_export(tmp_path):
    p = tmp_path / "peer.jsonl"
    peer = Ledger(p)
    for i in range(5):
        peer.append({"op": "step", "n": i})
    payload, is_err = _call("verify_peer_ledger", {"jsonl_text": _export(p)},
                            Ledger(tmp_path / "agent.log.jsonl"))
    assert not is_err, payload
    assert payload["ok"] is True
    assert payload["rows"] == 5
    assert payload["first_break"] is None
    assert payload["declared_breaks"] == 0


def test_verify_peer_ledger_names_the_exact_tampered_line(tmp_path):
    """C-agent-06's whole point: edit ONE line of a peer's export and get that
    line's number back, as an integer a calling agent can act on."""
    p = tmp_path / "peer.jsonl"
    peer = Ledger(p)
    for i in range(5):
        peer.append({"op": "step", "n": i})
    lines = _export(p).split("\n")
    row = json.loads(lines[2])            # line 3, 1-based
    row["n"] = 999
    lines[2] = json.dumps(row)
    tampered = "\n".join(lines)

    payload, _ = _call("verify_peer_ledger", {"jsonl_text": tampered},
                       Ledger(tmp_path / "agent.log.jsonl"))
    assert payload["ok"] is False, payload
    # The edited row still carries its ORIGINAL chain field, which no longer
    # matches its recomputed content: the break is named at line 3 itself.
    assert payload["first_break"] == 3, payload
    assert "line 3" in payload["first_break_detail"]
    assert payload["breaks"] == 1
    assert payload["rows"] == 5


def test_verify_peer_ledger_names_a_deleted_line(tmp_path):
    p = tmp_path / "peer.jsonl"
    peer = Ledger(p)
    for i in range(4):
        peer.append({"op": "step", "n": i})
    lines = [l for l in _export(p).split("\n") if l.strip()]
    del lines[1]                          # drop the old line 2
    payload, _ = _call("verify_peer_ledger", {"jsonl_text": "\n".join(lines)},
                       Ledger(tmp_path / "agent.log.jsonl"))
    assert payload["ok"] is False
    assert payload["first_break"] == 2, payload


def test_verify_peer_ledger_counts_a_declared_break_and_stays_bounded(tmp_path):
    """A peer who NAMED their break gets credit for naming it — declared_breaks
    is 1, first_break is None — and still does not get a green."""
    from arcaeon.record.ledger import declare_break
    p = tmp_path / "peer.jsonl"
    peer = Ledger(p)
    peer.append({"op": "create"})
    peer.append({"op": "update"})
    with p.open("ab") as fh:
        fh.write(b'{"op": "update", "note": "by hand during an incident"}\n')
    declare_break(p, 3, "hand-appended during the 08-15 incident")

    payload, _ = _call("verify_peer_ledger", {"jsonl_text": _export(p)},
                       Ledger(tmp_path / "agent.log.jsonl"))
    assert payload["declared_breaks"] == 1, payload
    assert payload["ok"] is None, payload          # bounded, never True
    assert payload["first_break"] is None
    assert payload["verified_scope"] == "bounded_declared_break"
    assert payload["declared"] == [
        "line 3: declared break (hand-appended during the 08-15 incident)"]


def test_verify_peer_ledger_does_not_green_an_unchained_export(tmp_path):
    """A peer sends rows with no chain at all. That is not a pass."""
    text = '{"op": "a"}\n{"op": "b"}\n'
    payload, _ = _call("verify_peer_ledger", {"jsonl_text": text},
                       Ledger(tmp_path / "agent.log.jsonl"))
    assert payload["ok"] is None, payload
    assert payload["verified_scope"] == "bounded_prechain_skipped"
    assert payload["prechain"] == 2


def test_verify_peer_ledger_strict_hard_fails_an_unchained_export(tmp_path):
    payload, _ = _call("verify_peer_ledger",
                       {"jsonl_text": '{"op": "a"}\n', "strict": True},
                       Ledger(tmp_path / "agent.log.jsonl"))
    assert payload["ok"] is False, payload
    assert payload["first_break"] == 1


def test_verify_peer_ledger_names_the_line_of_unparseable_garbage(tmp_path):
    p = tmp_path / "peer.jsonl"
    Ledger(p).append({"op": "a"})
    payload, _ = _call("verify_peer_ledger",
                       {"jsonl_text": _export(p) + "not json at all\n"},
                       Ledger(tmp_path / "agent.log.jsonl"))
    assert payload["ok"] is False
    assert payload["first_break"] == 2, payload


def test_verify_peer_ledger_never_touches_the_callers_own_log(tmp_path):
    """Verifying a peer is a pure read of the TEXT — the server's own ledger
    must be byte-identical afterwards."""
    own = tmp_path / "agent.log.jsonl"
    log = Ledger(own)
    log.append({"op": "mine"})
    before = own.read_bytes()
    _call("verify_peer_ledger", {"jsonl_text": '{"op": "theirs"}\n'}, log)
    assert own.read_bytes() == before


@pytest.mark.parametrize("bad", [None, 42, {"a": 1}, ["a"]])
def test_verify_peer_ledger_refuses_non_text(tmp_path, bad):
    payload, is_err = _call("verify_peer_ledger", {"jsonl_text": bad},
                            Ledger(tmp_path / "agent.log.jsonl"))
    assert is_err, payload
    assert "jsonl_text" in payload["error"]


def test_verify_peer_ledger_empty_text_is_not_a_green(tmp_path):
    payload, _ = _call("verify_peer_ledger", {"jsonl_text": ""},
                       Ledger(tmp_path / "agent.log.jsonl"))
    assert payload["rows"] == 0
    assert payload["ok"] is not True, payload


# --- declare_break ----------------------------------------------------------

def test_declare_break_tool_declares_the_break_verify_already_found(tmp_path):
    """C-agent-11: the agent names its own break by namespace + reason; the tool
    finds the orphan line the verifier reported and pins it."""
    log, ns = _home(tmp_path)
    _call("prove_my_conduct", {"namespace": "mine", "events": ["a", "b"]}, log, ns_dir=ns)
    p = ns / "mine.jsonl"
    with p.open("ab") as fh:
        fh.write(b'{"op": "update", "note": "written outside the tool"}\n')
    assert verify_file(p).ok is False

    payload, is_err = _call("declare_break",
                            {"namespace": "mine", "reason": "incident: hand-written row"},
                            log, ns_dir=ns)
    assert not is_err, payload
    assert payload["declared_line"] == 3, payload
    assert payload["reason"] == "incident: hand-written row"

    r = verify_file(p)
    assert r.ok is None and r.breaks == 0
    assert r.declared_breaks == 1
    assert payload["declared_breaks"] == 1
    assert payload["chain_verified"] is None
    assert payload["verified_scope"] == "bounded_declared_break"


def test_declare_break_tool_refuses_when_nothing_is_broken(tmp_path):
    """Declaring a break that does not exist would be a lie in the record."""
    log, ns = _home(tmp_path)
    _call("prove_my_conduct", {"namespace": "clean", "events": ["a"]}, log, ns_dir=ns)
    before = (ns / "clean.jsonl").read_bytes()
    payload, is_err = _call("declare_break", {"namespace": "clean", "reason": "just in case"},
                            log, ns_dir=ns)
    assert is_err, payload
    assert "no break" in payload["error"].lower()
    assert (ns / "clean.jsonl").read_bytes() == before


@pytest.mark.parametrize("reason", ["", "   ", None, 7])
def test_declare_break_tool_refuses_a_blank_reason(tmp_path, reason):
    log, ns = _home(tmp_path)
    _call("prove_my_conduct", {"namespace": "mine", "events": ["a"]}, log, ns_dir=ns)
    p = ns / "mine.jsonl"
    with p.open("ab") as fh:
        fh.write(b'{"op": "x"}\n')
    payload, is_err = _call("declare_break", {"namespace": "mine", "reason": reason},
                            log, ns_dir=ns)
    assert is_err, payload
    assert "reason" in payload["error"]
    assert verify_file(p).declared_breaks == 0


def test_declare_break_tool_refuses_traversal_and_unknown_namespace(tmp_path):
    log, ns = _home(tmp_path)
    payload, is_err = _call("declare_break", {"namespace": "../etc", "reason": "why"},
                            log, ns_dir=ns)
    assert is_err and "namespace" in payload["error"]
    payload, is_err = _call("declare_break", {"namespace": "ghost", "reason": "why"},
                            log, ns_dir=ns)
    assert is_err, payload


def test_declare_break_tool_declares_one_break_at_a_time(tmp_path):
    """Two orphans: declaring names the FIRST and leaves the second red, so a
    second break can never ride in on one sentence."""
    log, ns = _home(tmp_path)
    _call("prove_my_conduct", {"namespace": "mine", "events": ["a", "b"]}, log, ns_dir=ns)
    p = ns / "mine.jsonl"
    with p.open("ab") as fh:
        fh.write(b'{"op": "x", "note": "one"}\n')
        fh.write(b'{"op": "y", "note": "two"}\n')
    payload, is_err = _call("declare_break", {"namespace": "mine", "reason": "first orphan"},
                            log, ns_dir=ns)
    assert not is_err, payload
    assert payload["declared_line"] == 3
    r = verify_file(p)
    assert r.ok is False and r.breaks == 1 and r.declared_breaks == 1
    assert payload["chain_verified"] is False


# --- the schema a client actually reads -------------------------------------

def test_the_three_agent_tools_are_advertised_with_usable_schemas():
    """A tool a client cannot discover, or whose args it cannot fill, is not
    shipped. This asserts the tools/list surface, not just the handler."""
    from arcaeon.record.ledger.mcp_server import handle, TOOLS
    names = {t["name"] for t in TOOLS}
    assert {"prove_my_conduct", "verify_peer_ledger", "declare_break"} <= names
    assert {"ledger_append", "ledger_verify"} <= names   # nothing was displaced

    listed = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    Ledger("unused.jsonl"))["result"]["tools"]
    by_name = {t["name"]: t for t in listed}

    prove = by_name["prove_my_conduct"]["inputSchema"]
    assert prove["required"] == ["namespace", "events"]
    assert prove["properties"]["events"]["type"] == "array"
    assert prove["properties"]["events"]["items"]["type"] == "string"

    peer = by_name["verify_peer_ledger"]["inputSchema"]
    assert peer["required"] == ["jsonl_text"]
    assert "strict" in peer["properties"]

    dec = by_name["declare_break"]["inputSchema"]
    assert dec["required"] == ["namespace", "reason"]

    for name in ("prove_my_conduct", "verify_peer_ledger", "declare_break"):
        assert len(by_name[name]["description"]) > 80, name


def test_handle_still_works_without_the_ns_dir_argument(tmp_path):
    """Back-compat: the 0.6.0 two-argument call site must keep working."""
    from arcaeon.record.ledger.mcp_server import handle
    log = Ledger(tmp_path / "agent.log.jsonl")
    resp = handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "ledger_append", "arguments": {"record": {"a": 1}}}}, log)
    assert json.loads(resp["result"]["content"][0]["text"])["ok"] is True

    resp = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                   "params": {"name": "prove_my_conduct",
                              "arguments": {"namespace": "defaulted", "events": ["a"]}}}, log)
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert payload["rows"] == 1, payload
    # default namespace dir sits beside the server's own log
    assert (tmp_path / "ledgers" / "defaulted.jsonl").exists()


def test_prove_my_conduct_empty_batch_on_new_namespace_is_not_a_tamper_verdict(tmp_path):
    """0.7.2 (2026-09-01 audit): events=[] on a namespace that had never been
    written returned breaks=1 / chain_verified=False — verify_file on a file
    that did not exist, reported as a broken chain. A missing ledger is not a
    tampered one. Now a refusal that names the situation, and no file created."""
    log, ns = _home(tmp_path)
    payload, is_err = _call("prove_my_conduct", {"namespace": "never", "events": []},
                            log, ns_dir=ns)
    assert is_err, payload
    assert "no ledger yet" in payload["error"]
    assert not (ns / "never.jsonl").exists()


# --- the server's OWN call record (0.7.4, OWASP MCP08) ----------------------
# Graded by arcaeon-mcp-vet's audit-record check on 2026-09-02, with our own
# server first in the queue: gate 1 of 4. `prove_my_conduct` appended the
# CALLER's events and nothing recorded the call itself -- no tool name, no
# timestamp, no args. A ledger server that keeps everyone's record but its
# own. These were red before `calls_path` existed.

def _calls_rows(log):
    from arcaeon.record.ledger.mcp_server import calls_path
    p = calls_path(log)
    if not p.exists():
        return []
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]


def test_every_tool_call_leaves_a_chained_record_with_tool_ts_and_args(tmp_path):
    log, ns = _home(tmp_path)
    _call("prove_my_conduct", {"namespace": "a1", "events": ["did x"]}, log, ns)
    _call("ledger_append", {"record": {"k": "v"}}, log, ns, mid=2)
    rows = _calls_rows(log)
    assert [r["tool"] for r in rows] == ["prove_my_conduct", "ledger_append"]
    for r in rows:
        assert r["ts"].endswith("Z") or "+" in r["ts"]
        assert len(r["args_digest"]) == 64
        assert r["ok"] is True
        assert "chain" in r                       # a Ledger row, not a plain line
    assert rows[1]["args"] == {"record": {"k": "v"}}
    from arcaeon.record.ledger.mcp_server import calls_path
    assert verify_file(calls_path(log)).ok is True


def test_a_failed_call_is_recorded_too_with_its_error(tmp_path):
    log, ns = _home(tmp_path)
    payload, is_err = _call("prove_my_conduct", {"namespace": "../x", "events": []}, log, ns)
    assert is_err
    rows = _calls_rows(log)
    assert len(rows) == 1 and rows[0]["ok"] is False and rows[0]["error"]
    assert rows[0]["tool"] == "prove_my_conduct"


def test_ledger_verify_reports_the_call_record_verdict_too(tmp_path):
    """Reconstructability: the record set is checkable through the same tool
    a caller already uses, not only by someone who knows the sidecar exists."""
    log, ns = _home(tmp_path)
    log.append({"e": 1})
    _call("ledger_append", {"record": {"k": 1}}, log, ns)
    payload, is_err = _call("ledger_verify", {}, log, ns, mid=2)
    assert not is_err
    assert payload["calls_record"]["ok"] is True
    # 1, not 2: the verify call's own row is written AFTER the tool runs, so a
    # verify cannot see itself. (First draft of this test said 2; the code
    # was right and the test was wrong, which is the cheaper way round.)
    assert payload["calls_record"]["rows"] == 1
    assert len(_calls_rows(log)) == 2                # ...but it is there afterwards


def test_oversized_args_keep_the_digest_and_drop_the_body(tmp_path):
    log, ns = _home(tmp_path)
    big = {"record": {"blob": "x" * 20000}}
    _call("ledger_append", big, log, ns)
    r = _calls_rows(log)[0]
    assert r["args"] is None and r["args_bytes"] > 4096
    import hashlib
    assert r["args_digest"] == hashlib.sha256(
        json.dumps(big, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


# --- 2026-09-05 input fuzz: strict is a boolean, and one hostile character ---
# --- cannot erase a call from the server's own record -------------------------

@pytest.mark.parametrize("bad", ["false", "no", 0, 2, [], {}])
def test_strict_that_is_not_a_boolean_is_refused_not_coerced(tmp_path, bad):
    """`bool("false")` is True. A caller sending the string "false" got strict
    mode and a `ok: false` verdict over an unchained-prefix ledger it asked to
    have judged leniently. Both strict-taking tools refuse by name now."""
    log, ns = _home(tmp_path)
    payload, is_err = _call("ledger_verify", {"strict": bad}, log, ns)
    assert is_err and "strict must be a JSON boolean" in payload["error"]
    payload, is_err = _call("verify_peer_ledger", {"jsonl_text": "{}\n", "strict": bad},
                            log, ns, mid=2)
    assert is_err and "strict must be a JSON boolean" in payload["error"]


def test_strict_true_false_and_absent_still_work(tmp_path):
    log, ns = _home(tmp_path)
    (tmp_path / "agent.log.jsonl").write_text('{"pre": 1}\n', encoding="utf-8")
    lenient, _ = _call("ledger_verify", {"strict": False}, log, ns)
    absent, _ = _call("ledger_verify", {}, log, ns, mid=2)
    null, _ = _call("ledger_verify", {"strict": None}, log, ns, mid=3)
    hard, _ = _call("ledger_verify", {"strict": True}, log, ns, mid=4)
    assert lenient["ok"] is None and absent["ok"] is None and null["ok"] is None
    assert hard["ok"] is False


def test_a_lone_surrogate_in_the_args_still_leaves_a_call_record_row(tmp_path):
    """The JSON escape \\ud800 is legal JSON and passes json.loads as a lone surrogate. The
    inlined args body cannot be written strictly, so before the fix the row was
    dropped and the caller told the record could not be written. The call must
    stay on the record: digest kept, body omitted and the omission named."""
    log, ns = _home(tmp_path)
    args = {"record": {"a": "\ud800"}}
    payload, is_err = _call("ledger_append", args, log, ns)
    assert is_err and "call record could not be written" not in payload["error"]
    rows = _calls_rows(log)
    assert len(rows) == 1
    r = rows[0]
    assert r["tool"] == "ledger_append" and r["ok"] is False
    assert r["args"] is None and "surrogate" in r["args_omitted"]
    assert len(r["args_digest"]) == 64
    from arcaeon.record.ledger.mcp_server import calls_path
    assert verify_file(calls_path(log)).ok is True


def test_a_lone_surrogate_in_a_conduct_event_refuses_the_whole_batch(tmp_path):
    """Ledger.append refuses per row, so a bad third event used to land the first
    two. A batch is one act: nothing is written, and the reply names the index."""
    log, ns = _home(tmp_path)
    payload, is_err = _call("prove_my_conduct",
                            {"namespace": "s1", "events": ["a", "b", "\ud800"]}, log, ns)
    assert is_err and "events[2]" in payload["error"]
    assert not (ns / "s1.jsonl").exists()
    assert len(_calls_rows(log)) == 1 and _calls_rows(log)[0]["ok"] is False


def test_a_megabyte_tool_name_is_clipped_in_the_call_record(tmp_path):
    log, ns = _home(tmp_path)
    payload, is_err = _call("x" * (1 << 20), {}, log, ns)
    assert is_err
    r = _calls_rows(log)[0]
    assert len(r["tool"]) == 256 and r["ok"] is False
