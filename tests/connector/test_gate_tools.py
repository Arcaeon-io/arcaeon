"""verify_bundle and gate_decide on the front door (D051 / TE-22).

`arcaeon mcp` answers the labeled-exchange envelope's verify and the gate over
it: verify_bundle is arcaeon.prove.envelope.verify, gate_decide is
arcaeon.prove.gate.decide(...).to_dict(). The tests check the tools return the
library's own answer (same verdict, same decision), carry the honest-limits
line, refuse a bad action as a tool error, and fence every path under
$ARCAEON_BUNDLE_ROOT.

Every test drives the server through the SDK's in-process client; every key is
a throwaway seed under tmp_path and nothing reaches the network. No HTTP route
calls envelope.verify (grep src/arcaeon/serve), so there is no route parity
test here: the library is the only other surface, and parity is held to it.
"""
import asyncio
import base64
import json
import secrets
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

pytest.importorskip("mcp", reason="the connector IS an MCP server")
pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

from mcp import Client  # noqa: E402

from arcaeon import verdict as V  # noqa: E402
from arcaeon.mcp.server import (  # noqa: E402
    ALL_TOOLS,
    FREE_TOOLS,
    GATE_TOOLS,
    build_server,
)
from arcaeon.prove import envelope as E  # noqa: E402
from arcaeon.prove import gate as G  # noqa: E402

BIND = {"label": "week 3 grades", "audience": "instructor-1", "deal": "d-7f3a",
        "purpose": "grading", "not_after": "7d"}
BODY = b"name,grade\nunit-a,pass\n"


def _payload(res):
    sc = res.structured_content
    if sc is not None:
        return sc.get("result", sc) if isinstance(sc, dict) else sc
    text = "".join(getattr(c, "text", "") for c in res.content)
    try:
        return json.loads(text)
    except ValueError:
        return text


def _call(tool, args):
    async def go():
        async with Client(build_server()) as client:
            res = await client.call_tool(tool, args)
            return bool(res.is_error), _payload(res)
    return asyncio.run(go())


def _listed():
    async def go():
        async with Client(build_server()) as client:
            return {t.name: t for t in (await client.list_tools()).tools}
    return asyncio.run(go())


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("ARCAEON_LEDGER_LOG", str(tmp_path / "state" / "agent.log.jsonl"))
    monkeypatch.setenv("ARCAEON_LEDGER_NS_DIR", str(tmp_path / "ledgers"))
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(tmp_path / "arcaeon.calls.jsonl"))
    monkeypatch.setenv("ARCAEON_BUNDLE_ROOT", str(tmp_path / "in"))
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    monkeypatch.chdir(tmp_path)


# --- fixtures: the same shapes tests/test_gate.py builds ----------------------------

def _make(tmp_path: Path, verdict: str):
    """A handed file under tmp/in whose envelope verifies to `verdict`."""
    f = tmp_path / "in" / "grades.csv"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(BODY)
    key = None
    if verdict != V.COULD_NOT_LOOK:                   # unsigned: who sealed it is unknown
        key = tmp_path / "seal.key"
        key.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
                       encoding="ascii")
    env = E.seal(f, key_file=key, **BIND)
    sigs = env["dsseEnvelope"]["signatures"]
    did = sigs[0]["keyid"] if sigs else "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    if verdict == V.BROKEN:
        f.write_bytes(BODY + b"unit-b,pass\n")         # bytes changed after sealing
    return f, did


VERDICTS = (V.VERIFIED, V.BROKEN, V.COULD_NOT_LOOK)
IDS = [v.replace(" ", "_") for v in VERDICTS]


# --- listed ---------------------------------------------------------------------------

def test_both_tools_are_listed_free_and_described():
    listed = _listed()
    assert GATE_TOOLS == ("verify_bundle", "gate_decide")
    for name in GATE_TOOLS:
        assert name in listed and name in ALL_TOOLS and name in FREE_TOOLS, name
        assert "never" in listed[name].description and "true or safe" in listed[name].description
    tool = listed["gate_decide"]
    schema = getattr(tool, "input_schema", None) or getattr(tool, "inputSchema")  # SDK 2.x / 1.x
    action = schema["properties"]["action"]
    assert action.get("enum") == list(G.ACTIONS), action


# --- verify_bundle: the three words, the same as the library -------------------------

@pytest.mark.parametrize("verdict", VERDICTS, ids=IDS)
def test_verify_bundle_answers_the_library_verdict(tmp_path, verdict):
    f, did = _make(tmp_path, verdict)
    err, got = _call("verify_bundle", {"file": str(f), "audience": "instructor-1",
                                       "signers": [did]})
    assert not err, got
    lib = E.verify(f, audience="instructor-1", signers=[did])
    assert got["verdict"] == lib["verdict"] == verdict
    assert got["reason"] == lib["reason"] and got["steps"] == lib["steps"]
    assert got["exit_code"] == {V.VERIFIED: 0, V.BROKEN: 1, V.COULD_NOT_LOOK: 3}[verdict]
    assert "never means the content is true or safe" in got["honest_limits"]
    if verdict == V.COULD_NOT_LOOK:
        assert got["could_not_check"]["reason_word"] in V.REASON_WORDS
        assert got["could_not_check"]["looked_for"]
    else:
        assert got["could_not_check"] is None
    if verdict == V.BROKEN:
        assert any("bytes changed" in x for x in got["findings"]), got["findings"]


def test_verify_bundle_missing_sidecar_is_could_not_look(tmp_path):
    f = tmp_path / "in" / "loose.txt"
    f.parent.mkdir()
    f.write_bytes(b"no envelope\n")
    err, got = _call("verify_bundle", {"file": str(f), "audience": "instructor-1"})
    assert not err, got
    assert got["verdict"] == V.COULD_NOT_LOOK and got["exit_code"] == 3
    assert got["could_not_check"]["reason_word"] == "missing"


def test_verify_bundle_takes_a_sidecar_under_another_name(tmp_path):
    f, did = _make(tmp_path, V.VERIFIED)
    moved = f.parent / "label.json"
    E.envelope_path(f).rename(moved)
    err, got = _call("verify_bundle", {"file": str(f), "envelope": str(moved),
                                       "audience": "instructor-1", "signers": [did],
                                       "deal": "d-7f3a", "purpose": "grading"})
    assert not err and got["verdict"] == V.VERIFIED, got


# --- gate_decide: allow and refuse per verdict, as the library decides --------------

CASES = [(V.VERIFIED, "pay", "allow"), (V.VERIFIED, "irreversible", "allow"),
         (V.BROKEN, "read", "refuse"), (V.BROKEN, "pay", "refuse"),
         (V.COULD_NOT_LOOK, "read", "allow"), (V.COULD_NOT_LOOK, "act", "refuse")]


@pytest.mark.parametrize("verdict,action,want", CASES,
                         ids=[f"{v.replace(' ', '_')}-{a}" for v, a, _ in CASES])
def test_gate_decide_matches_the_rule_table(tmp_path, verdict, action, want):
    f, did = _make(tmp_path, verdict)
    # D073 / R3-1: act, pay and irreversible need the exchange named to be allowed
    bound = {"deal": "d-7f3a", "purpose": "grading"} if verdict == V.VERIFIED else {}
    err, got = _call("gate_decide", {"file": str(f), "action": action,
                                     "audience": "instructor-1", "signers": [did], **bound})
    assert not err, got
    lib = G.decide(f, action=action, audience="instructor-1", signers=[did], **bound,
                   ledger=(tmp_path / "lib.jsonl") if bound else None)
    assert got["decision"] == lib.decision == want
    assert got["verdict"] == verdict and got["action"] == action
    assert got["reason"].startswith(f"{want} {action}: {verdict}")
    assert got["exit_code"] == lib.exit_code
    assert got["honest_limits"] == G.ALLOW_MEANS and got["limits"][0] == G.ALLOW_MEANS
    if verdict == V.COULD_NOT_LOOK:
        assert got["could_not_check"] and got["could_not_check"]["looked_for"]
    else:
        assert got["could_not_check"] is None
    assert got["evidence"] is None                     # no deal id: no pack


def test_gate_decide_broken_with_a_deal_writes_the_pack_in_the_state_dir(tmp_path):
    f, did = _make(tmp_path, V.BROKEN)
    err, got = _call("gate_decide", {"file": str(f), "action": "pay", "deal": "d-7f3a",
                                     "audience": "instructor-1", "signers": [did]})
    assert not err, got
    assert got["decision"] == "refuse" and got["evidence"], got
    ev = Path(got["evidence"])
    assert ev.is_relative_to(tmp_path / "state" / "DEAL-d-7f3a" / "gate"), ev
    assert json.loads((ev / "evidence.json").read_text(encoding="utf-8"))["verdict"] == V.BROKEN
    rows = [json.loads(x) for x in (tmp_path / "state" / "agent.log.jsonl")
            .read_text(encoding="utf-8").splitlines() if x.strip()]
    assert [r["kind"] for r in rows] == ["gate.evidence"], rows   # the connector's own chain


def test_a_bad_action_is_a_tool_error_not_a_crash(tmp_path):
    f, did = _make(tmp_path, V.VERIFIED)
    err, got = _call("gate_decide", {"file": str(f), "action": "delete",
                                     "audience": "instructor-1", "signers": [did]})
    assert err, got
    assert "action" in str(got), got
    # and the server is still answering after it
    err, ok = _call("gate_decide", {"file": str(f), "action": "read",
                                    "audience": "instructor-1", "signers": [did]})
    assert not err and ok["decision"] == "allow", ok


def test_bad_signers_is_a_tool_error(tmp_path):
    f, _ = _make(tmp_path, V.VERIFIED)
    err, got = _call("verify_bundle", {"file": str(f), "signers": [1, 2]})
    assert err, got


# --- the path fence ---------------------------------------------------------------------

@pytest.mark.parametrize("tool", GATE_TOOLS)
def test_a_file_outside_the_root_is_refused(tmp_path, tool):
    outside = tmp_path / "secret.txt"
    outside.write_bytes(b"not yours\n")
    args = {"file": str(outside), "audience": "instructor-1"}
    if tool == "gate_decide":
        args["action"] = "read"
    err, got = _call(tool, args)
    assert err, got
    assert "ARCAEON_BUNDLE_ROOT" in str(got), got


@pytest.mark.parametrize("tool", GATE_TOOLS)
def test_a_dotdot_or_outside_envelope_is_refused(tmp_path, tool):
    f, did = _make(tmp_path, V.VERIFIED)
    (tmp_path / "evil.envelope.json").write_text("{}", encoding="utf-8")
    for env in ("../evil.envelope.json", str(tmp_path / "evil.envelope.json")):
        args = {"file": "grades.csv", "envelope": env, "audience": "instructor-1",
                "signers": [did]}
        if tool == "gate_decide":
            args["action"] = "read"
        err, got = _call(tool, args)
        assert err and "ARCAEON_BUNDLE_ROOT" in str(got), (env, got)


def test_a_relative_path_resolves_under_the_root(tmp_path):
    _, did = _make(tmp_path, V.VERIFIED)
    err, got = _call("verify_bundle", {"file": "grades.csv", "audience": "instructor-1",
                                       "signers": [did]})
    assert not err and got["verdict"] == V.VERIFIED, got


def test_every_call_is_recorded_refusals_included(tmp_path):
    f, did = _make(tmp_path, V.VERIFIED)
    _call("verify_bundle", {"file": str(f), "audience": "instructor-1", "signers": [did]})
    _call("gate_decide", {"file": str(tmp_path / "x"), "action": "read",
                          "audience": "instructor-1"})
    rows = [json.loads(x) for x in (tmp_path / "arcaeon.calls.jsonl")
            .read_text(encoding="utf-8").splitlines() if x.strip()]
    assert [(r["tool"], r["ok"]) for r in rows] == [("verify_bundle", True),
                                                     ("gate_decide", False)]


# --- enforce: block (default-on) or warn (L4-01) ---------------------------------------

WOULD = "would refuse in block mode"


def test_gate_decide_default_is_block_and_says_so(tmp_path, monkeypatch):
    monkeypatch.delenv("ARCAEON_GATE_MODE", raising=False)
    f, did = _make(tmp_path, V.BROKEN)
    err, got = _call("gate_decide", {"file": str(f), "action": "pay",
                                     "audience": "instructor-1", "signers": [did]})
    assert not err and got["decision"] == "refuse" and got["exit_code"] == 1, got
    assert (got["enforce_mode"], got["enforce_source"]) == ("block", "default")


def test_gate_decide_enforce_warn_lets_it_through_loudly(tmp_path):
    f, did = _make(tmp_path, V.COULD_NOT_LOOK)
    err, got = _call("gate_decide", {"file": str(f), "action": "act", "enforce": "warn",
                                     "audience": "instructor-1", "signers": [did]})
    assert not err, got
    assert got["decision"] == "allow" and got["exit_code"] == 0
    assert got["would_refuse"] is True and got["would_exit_code"] == 3
    assert WOULD in got["warning"]
    assert (got["enforce_mode"], got["enforce_source"]) == ("warn", "flag")


def test_gate_decide_env_warn_and_argument_beats_it(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_GATE_MODE", "warn")
    f, did = _make(tmp_path, V.BROKEN)
    args = {"file": str(f), "action": "pay", "audience": "instructor-1", "signers": [did]}
    err, got = _call("gate_decide", args)
    assert not err and (got["decision"], got["enforce_source"]) == ("allow", "env"), got
    err, got = _call("gate_decide", {**args, "enforce": "block"})
    assert not err and (got["decision"], got["enforce_mode"]) == ("refuse", "block"), got


def test_gate_decide_unknown_enforce_is_a_tool_error(tmp_path, monkeypatch):
    f, did = _make(tmp_path, V.VERIFIED)
    err, got = _call("gate_decide", {"file": str(f), "action": "read", "enforce": "maybe",
                                     "audience": "instructor-1", "signers": [did]})
    assert err, got
    monkeypatch.setenv("ARCAEON_GATE_MODE", "maybe")
    err, got = _call("gate_decide", {"file": str(f), "action": "read",
                                     "audience": "instructor-1", "signers": [did]})
    assert err and "ARCAEON_GATE_MODE" in str(got), got


def test_verify_bundle_alone_stays_a_report(tmp_path):
    f, did = _make(tmp_path, V.BROKEN)
    err, got = _call("verify_bundle", {"file": str(f), "audience": "instructor-1",
                                       "signers": [did]})
    assert not err and got["verdict"] == V.BROKEN
    assert "decision" not in got and "enforce_mode" not in got


@pytest.mark.parametrize("enforce,want", [("block", "refuse"), ("warn", "allow")])
def test_verify_bundle_with_an_action_answers_allow_or_refuse(tmp_path, enforce, want):
    f, did = _make(tmp_path, V.BROKEN)
    err, got = _call("verify_bundle", {"file": str(f), "audience": "instructor-1",
                                       "signers": [did], "action": "pay", "enforce": enforce})
    assert not err, got
    assert got["verdict"] == V.BROKEN and got["exit_code"] == 1      # the report, unchanged
    assert got["action"] == "pay" and got["decision"] == want
    assert got["would_refuse"] is True
    assert (got["enforce_mode"], got["enforce_source"]) == (enforce, "flag")
    assert (WOULD in (got["warning"] or "")) == (enforce == "warn")


def test_verify_bundle_with_an_action_matches_gate_decide(tmp_path):
    f, did = _make(tmp_path, V.VERIFIED)
    for action in G.ACTIONS:
        args = {"file": str(f), "audience": "instructor-1", "signers": [did], "action": action,
                "deal": "d-7f3a", "purpose": "grading"}
        _, v = _call("verify_bundle", args)
        _, g = _call("gate_decide", args)
        assert v["decision"] == g["decision"] == "allow", (action, v, g)
    _, v = _call("verify_bundle", {"file": str(f), "audience": "instructor-1",
                                   "signers": [did], "action": "pay"})     # unbound pay
    assert v["decision"] == "refuse" and v["verdict"] == V.VERIFIED, v


def test_verify_bundle_with_an_action_writes_nothing(tmp_path):
    f, did = _make(tmp_path, V.BROKEN)
    err, got = _call("verify_bundle", {"file": str(f), "audience": "instructor-1",
                                       "signers": [did], "action": "pay", "deal": "d-7f3a",
                                       "purpose": "grading"})
    assert not err and got["decision"] == "refuse", got
    assert not (tmp_path / "state").exists() or not any((tmp_path / "state").rglob("evidence.json"))


def test_verify_bundle_bad_action_or_enforce_is_a_tool_error(tmp_path):
    f, did = _make(tmp_path, V.VERIFIED)
    base = {"file": str(f), "audience": "instructor-1", "signers": [did]}
    assert _call("verify_bundle", {**base, "action": "delete"})[0]
    assert _call("verify_bundle", {**base, "action": "read", "enforce": "maybe"})[0]
