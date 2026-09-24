"""0.2.3 — sell-code audit, 2026-09-01. Each test was RED against 0.2.2.

Four findings, none of them a verdict change on an honest record:

  1. The MCP server DIED on one malformed stdin line: a JSON array / string /
     number / null parsed fine and then `msg.get` raised AttributeError out
     of `main()`; a line nested past the parser raised RecursionError past
     the `except ValueError`; `params` given as an array crashed before the
     per-call try. The docstring promised "never crash the server on one
     bad call". Now: JSON-RPC Invalid Request / Invalid Params errors, and
     the loop keeps reading.
  2. `ContinuitySnapshot.from_dict` / `from_json` raised AttributeError on a
     non-object instead of the documented ValueError, and `validate()` let
     an `id_scheme` outside {"index", "content"} through — a policy value
     `snapshot()` can never seal, which then blew up at the first
     `added_since_seal()` call instead of at load.
  3. `verdict_from_dict` loaded records whose `divergences` held non-object
     entries (crashing `to_dict` / `verdict_digest` / `by_severity` later),
     whose `notes` was not a list (TypeError mid-load), or whose
     `policy.strict` was a non-bool — a policy the loader then read by
     truthiness. All three are now refused at load.
  4. README said "PyPI publish scheduled 2026-08-15; until then install from
     the GitHub repo" (0.2.1 is on PyPI) and "51 pytest cases" (94 before
     this file). Both reworded; the Status line now tracks __version__.
"""
import io
import json
import sys
from pathlib import Path

import pytest

import arcaeon.prove.continuity as ac
from arcaeon.prove.continuity import mcp_server as m

MANIFEST = {"identity_anchors": ["I am a continuity, carried forward"],
            "open_commitments": ["ship 0.2.3"]}


@pytest.fixture(scope="module")
def snap():
    return ac.snapshot(MANIFEST, label="hardening")


@pytest.fixture(scope="module")
def good_verdict(snap):
    return ac.verify_continuation(snap, restated=ac.restate(MANIFEST)).to_dict()


def _copy(d):
    return json.loads(json.dumps(d))


# --------------------------------------------------------------------------
# 1. the MCP server survives a hostile line
# --------------------------------------------------------------------------

@pytest.mark.parametrize("msg", [[1], "x", 7, None, 1.5])
def test_non_object_message_is_an_invalid_request_not_a_crash(msg):
    resp = m.handle(msg)
    assert resp["error"]["code"] == -32600 and resp["id"] is None


@pytest.mark.parametrize("params", [[1], "x", 7])
def test_non_object_params_is_invalid_params(params):
    resp = m.handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": params})
    assert resp["id"] == 4 and resp["error"]["code"] == -32602


@pytest.mark.parametrize("args", [[1], "x", 7])
def test_non_object_arguments_is_invalid_params(args):
    resp = m.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                     "params": {"name": "continuity_snapshot", "arguments": args}})
    assert resp["id"] == 5 and resp["error"]["code"] == -32602


def test_main_loop_outlives_bad_lines(monkeypatch, capsys):
    """One array line, one line nested past the parser, then a real
    request: the server must still answer the real one."""
    deep = "[" * 100000 + "]" * 100000
    lines = ["[1,2]", deep, "not json",
             json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/list"})]
    monkeypatch.setattr(sys, "stdin", io.StringIO("\n".join(lines) + "\n"))
    assert m.main() == 0
    out = [json.loads(l) for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert any(r.get("id") == 9 and "tools" in r.get("result", {}) for r in out), out


def test_honest_tool_call_still_works():
    """GREEN CONTROL: the gates must not eat a real call."""
    resp = m.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                     "params": {"name": "continuity_snapshot",
                                "arguments": {"manifest": MANIFEST}}})
    assert "isError" not in resp["result"], resp
    body = json.loads(resp["result"]["content"][0]["text"])
    assert body["schema"] == ac.SNAPSHOT_SCHEMA and body["digest"]


# --------------------------------------------------------------------------
# 2. the snapshot loader refuses, it does not trip
# --------------------------------------------------------------------------

@pytest.mark.parametrize("payload", ["[1]", '"x"', "7", "null"])
def test_snapshot_from_json_non_object_is_a_value_error(payload):
    with pytest.raises(ValueError, match="not an arcaeon-continuity snapshot"):
        ac.ContinuitySnapshot.from_json(payload)


def test_snapshot_from_dict_non_object_is_a_value_error():
    with pytest.raises(ValueError, match="expected a JSON object"):
        ac.ContinuitySnapshot.from_dict(["not", "a", "snapshot"])


@pytest.mark.parametrize("scheme", ["bogus", "", None, 3])
def test_snapshot_with_unknown_id_scheme_is_refused_at_load(snap, scheme):
    d = snap.to_dict()
    d["id_scheme"] = scheme
    with pytest.raises(ValueError, match="id_scheme must be"):
        ac.ContinuitySnapshot.from_dict(d)


def test_snapshot_round_trip_still_loads(snap):
    """GREEN CONTROL, both schemes."""
    assert ac.ContinuitySnapshot.from_json(snap.to_json()).digest == snap.digest
    content = ac.snapshot(MANIFEST, id_scheme="content")
    assert ac.ContinuitySnapshot.from_json(content.to_json()).id_scheme == "content"


# --------------------------------------------------------------------------
# 3. the verdict loader refuses shapes its own readers would trip on
# --------------------------------------------------------------------------

@pytest.mark.parametrize("entry", ["not a dict", None, 7, ["id"]])
def test_non_object_divergence_entries_are_refused(good_verdict, entry):
    bad = _copy(good_verdict)
    bad.update(faithful=False, comparison="divergence", divergences=[entry])
    bad.pop("verdict_digest")
    with pytest.raises(ValueError, match="divergence objects"):
        ac.verdict_from_dict(bad)


@pytest.mark.parametrize("notes", [5, "note", {"a": 1}])
def test_non_list_notes_are_refused(good_verdict, notes):
    bad = _copy(good_verdict)
    bad["notes"] = notes
    with pytest.raises(ValueError, match="notes must be a list"):
        ac.verdict_from_dict(bad)


@pytest.mark.parametrize("strict", ["no", 1, 0, None, "true"])
def test_non_bool_policy_strict_is_refused(good_verdict, strict):
    bad = _copy(good_verdict)
    bad["policy"] = {"strict": strict, "id_scheme": "index"}
    bad.pop("verdict_digest")
    with pytest.raises(ac.UnsupportedVerdictVersion, match="policy.strict"):
        ac.verdict_from_dict(bad)


@pytest.mark.parametrize("policy", [[], "strict", 7])
def test_non_object_policy_is_refused(good_verdict, policy):
    bad = _copy(good_verdict)
    bad["policy"] = policy
    bad.pop("verdict_digest")
    with pytest.raises(ValueError, match="policy must be an object"):
        ac.verdict_from_dict(bad)


def test_honest_verdict_still_loads_and_serializes(good_verdict):
    """GREEN CONTROL: strict pass, loose pass, and a real divergence."""
    v = ac.verdict_from_dict(_copy(good_verdict))
    assert v.comparison == "exact_match" and v.to_dict()["verdict_digest"]
    snap = ac.snapshot(MANIFEST)
    restated = ac.restate(MANIFEST)
    restated["open_commitments:0"] = "something else"
    for strict in (True, False):
        raw = ac.verify_continuation(snap, restated=restated, strict=strict).to_dict()
        loaded = ac.verdict_from_dict(_copy(raw))
        assert loaded.comparison == "divergence" and loaded.by_severity


# --------------------------------------------------------------------------
# 4. README says what is true about the package
# --------------------------------------------------------------------------

def test_readme_does_not_claim_pypi_is_pending():
    readme = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")
    assert "PyPI publish scheduled" not in readme
    assert "until then install from the GitHub repo" not in readme


def test_readme_status_names_the_shipped_version():
    readme = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")
    assert f"\nv{ac.__version__}. " in readme, "README Status line lags the package"
    assert "51\npytest cases" not in readme and "51 pytest cases" not in readme
