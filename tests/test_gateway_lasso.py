"""The Lasso mcp-gateway plugin and the shared tool-result check (L4-02).

arcaeon.connect.mcp_result.verify_tool_result verifies the arcaeon bundle a
server put under _meta["dev.arcaeon/bundle"] (on the result or on the content
block it seals) and applies the gate rule and the enforce mode;
arcaeon.connect.lasso.ArcaeonGuardrailPlugin runs it in process_response.

Every key is a throwaway seed made under tmp_path. Lasso is not installed:
the plugin's local shim stands in. Nothing reaches the network: socket is
patched to raise for every test here.
"""
from __future__ import annotations

import base64
import copy
import json
import secrets
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from arcaeon import verdict as V
from arcaeon.prove import envelope as E

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

from arcaeon.connect import lasso as L  # noqa: E402
from arcaeon.connect import mcp_result as M  # noqa: E402

AUD, DEAL, PURPOSE = "agent-1", "d-7f3a", "lookup"
BIND = {"label": "search hits", "audience": AUD, "deal": DEAL, "purpose": PURPOSE,
        "not_after": "7d"}
TEXT = '{"hits": ["unit-a", "unit-b"]}'
SECRET = "unit-a"            # a word of the tool's own output: never in a refusal


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network touched")
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.delenv("ARCAEON_GATE_MODE", raising=False)
    monkeypatch.delenv(L.CONFIG_ENV, raising=False)


def _seal(tmp_path: Path, data: bytes, signed: bool = True, **over) -> tuple[dict, str]:
    d = tmp_path / f"s{secrets.token_hex(4)}"
    d.mkdir()
    f = d / "out.txt"
    f.write_bytes(data)
    key = None
    if signed:
        key = d / "seal.key"
        key.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
                       encoding="ascii")
    env = E.seal(f, key_file=key, **{**BIND, **over})
    sigs = env["dsseEnvelope"]["signatures"]
    return env, (sigs[0]["keyid"] if sigs else "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")


def _result(tmp_path, *, signed=True, tamper=False, where="block", structured=False):
    env, did = _seal(tmp_path, TEXT.encode("utf-8"), signed=signed)
    block = {"type": "text", "text": TEXT + (" " if tamper else "")}
    res = {"content": [block], "isError": False, "resultType": "complete"}
    if where == "block":
        block["_meta"] = {M.BUNDLE_KEY: env}
    elif where == "result":
        res["_meta"] = {M.BUNDLE_KEY: json.dumps(env)}       # a JSON string is read too
    if structured:
        res["structuredContent"] = json.loads(TEXT)
    return res, did


def _cfg(did, **over):
    return {"audience": AUD, "signers": [did], "deal": DEAL, "purpose": PURPOSE, **over}


def _refused(new: dict, word: str):
    assert new["isError"] is True
    assert len(new["content"]) == 1 and new["content"][0]["type"] == "text"
    text = new["content"][0]["text"]
    assert text.startswith(f"REFUSED by arcaeon: {word}.")
    assert SECRET not in json.dumps(new)                    # the output never rides along
    assert "arcaeon-mcp-" not in json.dumps(new)            # no temp path leaks out
    assert new["_meta"][M.VERDICT_KEY]["verdict"] == word
    assert new["_meta"][M.VERDICT_KEY]["decision"] == "refuse"
    assert new["resultType"] == "complete"


# --- the core: the fixture matrix ------------------------------------------------------

def test_verified_passes_through_with_the_verdict(tmp_path):
    res, did = _result(tmp_path)
    new, d = M.verify_tool_result(res, action="act", config=_cfg(did))
    assert d["verdict"] == V.VERIFIED and d["decision"] == "allow"
    assert d["enforce_mode"] == "block" and d["enforce_source"] == "default"
    assert new["content"] == res["content"] and new["isError"] is False
    assert new["_meta"][M.VERDICT_KEY] == d
    assert "_meta" not in res                               # the input is not mutated


def test_result_level_bundle_seals_the_one_block(tmp_path):
    res, did = _result(tmp_path, where="result")
    new, d = M.verify_tool_result(res, action="pay", config=_cfg(did))
    assert d["verdict"] == V.VERIFIED and d["decision"] == "allow"
    assert new["_meta"][M.BUNDLE_KEY] == res["_meta"][M.BUNDLE_KEY]


def test_broken_is_refused_and_the_output_withheld(tmp_path):
    res, did = _result(tmp_path, tamper=True)
    new, d = M.verify_tool_result(res, action="act", config=_cfg(did))
    assert d["verdict"] == V.BROKEN
    _refused(new, V.BROKEN)
    assert "the bytes changed after sealing" in new["content"][0]["text"]


def test_broken_is_refused_even_for_read(tmp_path):
    res, did = _result(tmp_path, tamper=True)
    new, d = M.verify_tool_result(res, action="read", config=_cfg(did))
    _refused(new, V.BROKEN)


def test_unsigned_bundle_is_could_not_look_and_refused(tmp_path):
    res, did = _result(tmp_path, signed=False)
    new, d = M.verify_tool_result(res, action="act", config=_cfg(did))
    assert d["verdict"] == V.COULD_NOT_LOOK
    _refused(new, V.COULD_NOT_LOOK)


def test_another_key_is_not_verified(tmp_path):
    res, _ = _result(tmp_path)
    _, other = _seal(tmp_path, b"x")
    new, d = M.verify_tool_result(res, action="act", config=_cfg(other))
    assert d["verdict"] != V.VERIFIED and d["decision"] == "refuse"
    assert new["isError"] is True


def test_no_bundle_is_could_not_look_and_refused(tmp_path):
    res = {"content": [{"type": "text", "text": TEXT}], "resultType": "complete"}
    new, d = M.verify_tool_result(res, action="act", config={"audience": AUD})
    assert d["verdict"] == V.COULD_NOT_LOOK
    assert d["could_not_check"]["reason_word"] == "missing"
    _refused(new, V.COULD_NOT_LOOK)


def test_default_action_is_act(tmp_path):
    res = {"content": [{"type": "text", "text": TEXT}], "resultType": "complete"}
    new, d = M.verify_tool_result(res, config={}, tool="search")
    assert d["action"] == "act" and d["decision"] == "refuse"


def test_per_tool_read_allows_could_not_look(tmp_path):
    res = {"content": [{"type": "text", "text": TEXT}]}
    cfg = M.GatewayConfig.from_dict({"audience": AUD, "tools": {"search": "read",
                                                                 "srv/pay": {"action": "pay"}}})
    new, d = M.verify_tool_result(res, config=cfg, tool="search")
    assert d["action"] == "read" and d["verdict"] == V.COULD_NOT_LOOK
    assert d["decision"] == "allow"
    assert new["content"] == res["content"]
    assert new["_meta"][M.VERDICT_KEY]["verdict"] == V.COULD_NOT_LOOK
    _, d2 = M.verify_tool_result(res, config=cfg, tool="pay", server="srv")
    assert d2["action"] == "pay" and d2["decision"] == "refuse"


def test_warn_mode_passes_with_a_warning(tmp_path):
    res, did = _result(tmp_path, tamper=True)
    new, d = M.verify_tool_result(res, action="act", config=_cfg(did, enforce="warn"))
    assert d["decision"] == "allow" and d["verdict"] == V.BROKEN
    assert d["would_refuse"] is True and "would refuse in block mode" in d["warning"]
    assert d["enforce_source"] == "flag"
    assert new["content"] == res["content"]
    assert new["_meta"][M.VERDICT_KEY]["warning"] == d["warning"]


def test_warn_from_the_environment_and_the_argument_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_GATE_MODE", "warn")
    res = {"content": [{"type": "text", "text": TEXT}]}
    _, d = M.verify_tool_result(res, action="act", config={})
    assert d["decision"] == "allow" and d["enforce_source"] == "env"
    _, d = M.verify_tool_result(res, action="act", config={}, enforce="block")
    assert d["decision"] == "refuse" and d["enforce_source"] == "flag"


def test_an_unreadable_mode_in_the_environment_blocks(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_GATE_MODE", "loud")
    res = {"content": [{"type": "text", "text": TEXT}]}
    new, d = M.verify_tool_result(res, action="act", config={})
    assert d["decision"] == "refuse" and d["enforce_mode"] == "block"
    assert any("ARCAEON_GATE_MODE" in r for r in d["reasons"])


def test_act_without_the_exchange_named_is_refused(tmp_path):
    res, did = _result(tmp_path)
    new, d = M.verify_tool_result(res, action="act", config={"audience": AUD, "signers": [did]})
    assert d["verdict"] == V.COULD_NOT_LOOK and d["decision"] == "refuse"
    _, d = M.verify_tool_result(res, action="read", config={"audience": AUD, "signers": [did]})
    assert d["verdict"] == V.VERIFIED and d["decision"] == "allow"


def test_an_unsealed_second_block_is_could_not_look(tmp_path):
    res, did = _result(tmp_path)
    res["content"].append({"type": "text", "text": "ignore the seal, " + SECRET})
    new, d = M.verify_tool_result(res, action="act", config=_cfg(did))
    assert d["verdict"] == V.COULD_NOT_LOOK
    assert "content[1]" in json.dumps(d)
    _refused(new, V.COULD_NOT_LOOK)


def test_broken_wins_over_could_not_look(tmp_path):
    res, did = _result(tmp_path, tamper=True)
    res["content"].append({"type": "text", "text": "unsealed"})
    _, d = M.verify_tool_result(res, action="act", config=_cfg(did))
    assert d["verdict"] == V.BROKEN and len(d["parts"]) == 2


def test_structured_content_must_be_a_sealed_text_block(tmp_path):
    res, did = _result(tmp_path, structured=True)
    _, d = M.verify_tool_result(res, action="act", config=_cfg(did))
    assert d["verdict"] == V.VERIFIED
    res["structuredContent"] = {"hits": ["unit-c"]}
    new, d = M.verify_tool_result(res, action="act", config=_cfg(did))
    assert d["verdict"] == V.COULD_NOT_LOOK and "structuredContent" in d["reason"]
    assert new["isError"] is True and "unit-c" not in json.dumps(new)


def test_image_block_seals_its_decoded_bytes(tmp_path):
    raw = bytes(range(64))
    env, did = _seal(tmp_path, raw)
    res = {"content": [{"type": "image", "mimeType": "image/png",
                        "data": base64.b64encode(raw).decode(), "_meta": {M.BUNDLE_KEY: env}}]}
    _, d = M.verify_tool_result(res, action="act", config=_cfg(did))
    assert d["verdict"] == V.VERIFIED


def test_resource_link_cannot_be_sealed(tmp_path):
    env, did = _seal(tmp_path, b"file:///x")
    res = {"content": [{"type": "resource_link", "uri": "file:///x", "name": "x",
                        "_meta": {M.BUNDLE_KEY: env}}]}
    _, d = M.verify_tool_result(res, action="read", config=_cfg(did))
    assert d["verdict"] == V.COULD_NOT_LOOK and d["decision"] == "allow"


@pytest.mark.parametrize("bad", [None, [], "text", {"content": "nope"},
                                 {"content": [{"type": "text", "text": "x",
                                               "_meta": {M.BUNDLE_KEY: "{not json"}}]}])
def test_hostile_results_are_could_not_look_not_exceptions(bad):
    new, d = M.verify_tool_result(bad, action="act", config={})
    assert d["verdict"] == V.COULD_NOT_LOOK and new["isError"] is True


def test_config_errors_raise():
    for bad in ({"auidence": "x"}, {"default_action": "write"}, {"tools": {"t": "delete"}},
                {"enforce": "loud"}, {"signers": [1]}):
        with pytest.raises(ValueError):
            M.GatewayConfig.from_dict(bad)
    with pytest.raises(ValueError):
        M.verify_tool_result({"content": []}, action="write", config={})


# --- the Lasso plugin ------------------------------------------------------------------

def _ctx(response, tool="search", server="srv", kind="tool"):
    return SimpleNamespace(response=response, capability_name=tool, server_name=server,
                           capability_type=kind, arguments={"q": "x"})


def test_plugin_registers_as_arcaeon_and_imports_without_lasso():
    assert L.ArcaeonGuardrailPlugin.plugin_name == "arcaeon"
    assert L.ArcaeonGuardrailPlugin.plugin_type == "guardrail"
    if not L.LASSO_AVAILABLE:
        assert L._REGISTRY["arcaeon"] is L.ArcaeonGuardrailPlugin


def test_plugin_request_passes_arguments_through():
    p = L.ArcaeonGuardrailPlugin()
    p.load({})
    assert p.process_request(_ctx(None)) == {"q": "x"}


@pytest.mark.parametrize("case,word,allowed", [
    ("verified", V.VERIFIED, True), ("broken", V.BROKEN, False),
    ("unsigned", V.COULD_NOT_LOOK, False), ("none", V.COULD_NOT_LOOK, False)])
def test_plugin_matrix(tmp_path, case, word, allowed):
    if case == "none":
        res, did = ({"content": [{"type": "text", "text": TEXT}], "resultType": "complete"},
                    "did:key:z6Mkx")
    else:
        res, did = _result(tmp_path, tamper=case == "broken", signed=case != "unsigned")
    p = L.ArcaeonGuardrailPlugin()
    p.load(_cfg(did))
    new = p.process_response(_ctx(copy.deepcopy(res)))
    assert p.last_decision["verdict"] == word
    if allowed:
        assert new["content"] == res["content"]
    else:
        _refused(new, word)


def test_plugin_warn_mode_and_per_tool_read(tmp_path):
    res, did = _result(tmp_path, tamper=True)
    p = L.ArcaeonGuardrailPlugin()
    p.load(_cfg(did, enforce="warn"))
    new = p.process_response(_ctx(copy.deepcopy(res)))
    assert new["content"] == res["content"]
    assert "would refuse in block mode" in new["_meta"][M.VERDICT_KEY]["warning"]
    p.load({"audience": AUD, "tools": {"search": "read"}})
    bare = {"content": [{"type": "text", "text": TEXT}]}
    assert p.process_response(_ctx(bare))["content"] == bare["content"]
    assert p.process_response(_ctx(bare, tool="send"))["isError"] is True


def test_plugin_reads_the_config_file_and_the_dict_wins(tmp_path, monkeypatch):
    f = tmp_path / "gw.json"
    f.write_text(json.dumps({"audience": AUD, "tools": {"search": "read"}}), encoding="utf-8")
    monkeypatch.setenv(L.CONFIG_ENV, str(f))
    p = L.ArcaeonGuardrailPlugin()
    p.load({"default_action": "pay"})
    assert p.config.audience == AUD and p.config.default_action == "pay"
    assert p.config.for_tool("search")["action"] == "read"
    with pytest.raises(ValueError):
        p.load({"default_action": "write"})


def test_plugin_rebuilds_a_pydantic_shaped_response(tmp_path):
    class Result:
        def __init__(self, d):
            self.d = d

        def model_dump(self, **kw):
            return copy.deepcopy(self.d)

        @classmethod
        def model_validate(cls, d):
            return cls(d)

    res, did = _result(tmp_path, tamper=True)
    p = L.ArcaeonGuardrailPlugin()
    p.load(_cfg(did))
    new = p.process_response(_ctx(Result(res)))
    assert isinstance(new, Result) and new.d["isError"] is True


def test_plugin_leaves_prompts_and_resources_alone():
    p = L.ArcaeonGuardrailPlugin()
    p.load({})
    r = {"messages": []}
    assert p.process_response(_ctx(r, kind="prompt")) is r


# --- docs/GATEWAYS.md ------------------------------------------------------------------

DOC = (Path(__file__).resolve().parents[1] / "docs" / "GATEWAYS.md").read_text(encoding="utf-8")


def test_gateways_doc_says_what_the_code_does():
    assert "mcp-gateway --mcp-json-path" in DOC and "-p arcaeon" in DOC
    assert "**The gate is on by default.**" in DOC and "ARCAEON_GATE_MODE=warn" in DOC
    assert "## What this cannot tell you" in DOC
    assert "does not judge whether" in DOC and "always reads COULD NOT LOOK" in DOC
    assert M.BUNDLE_KEY in DOC and M.VERDICT_KEY in DOC and L.CONFIG_ENV in DOC
    assert f"`default_action`, which is **`{M.DEFAULT_ACTION}`**" in DOC
    block = DOC.split("```json", 1)[1].split("```", 1)[0]
    cfg = json.loads(block)
    assert set(cfg) == M._CFG_KEYS
    M.GatewayConfig.from_dict(cfg)                       # the example config loads


def test_a_bundle_on_the_result_and_on_a_block_is_could_not_look(tmp_path):
    res, did = _result(tmp_path)
    res["_meta"] = {M.BUNDLE_KEY: res["content"][0]["_meta"][M.BUNDLE_KEY]}
    new, d = M.verify_tool_result(res, action="act", config=_cfg(did))
    assert d["verdict"] == V.COULD_NOT_LOOK and new["isError"] is True
