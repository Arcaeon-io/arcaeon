"""The Docker MCP Gateway after-interceptor (L4-03).

    docker mcp gateway run --interceptor 'after:exec:arcaeon gate mcp-after --config FILE'

The interceptor reads the bare CallToolResult JSON Docker's gateway writes on
stdin and writes the (possibly rewritten) CallToolResult on stdout, the check being
arcaeon.connect.mcp_result.verify_tool_result. Exit 0 for any stdin: the
gateway must always get JSON back; malformed stdin is a refusal result, not a
crash.

Run as a real subprocess under a temp ARCAEON_HOME, with socket patched to
raise inside the child (and in this process). Every key is a throwaway seed.
"""
from __future__ import annotations

import base64
import io
import json
import os
import secrets
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from arcaeon import verdict as V
from arcaeon.prove import envelope as E

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

from arcaeon.connect import docker_after as D  # noqa: E402
from arcaeon.connect import mcp_result as M  # noqa: E402

AUD, DEAL, PURPOSE = "agent-1", "d-7f3a", "lookup"
BIND = {"label": "search hits", "audience": AUD, "deal": DEAL, "purpose": PURPOSE,
        "not_after": "7d"}
TEXT = '{"hits": ["unit-a"]}'
SECRET = "unit-a"
ROOT = Path(__file__).resolve().parents[1]

# The child patches socket before arcaeon is imported, then runs the CLI. It
# patches connect and name lookup, not the class itself: modules imported
# later (ssl, asyncio) subclass socket.socket.
CHILD = ("import socket,sys\n"
         "def boom(*a,**k): raise AssertionError('network touched')\n"
         "socket.socket.connect=boom; socket.socket.connect_ex=boom\n"
         "socket.create_connection=boom; socket.getaddrinfo=boom\n"
         "from arcaeon.connect.docker_after import main\n"
         "sys.exit(main(sys.argv[1:]))\n")
CHILD_GATE = CHILD.replace("from arcaeon.connect.docker_after import main",
                           "from arcaeon.cli import main as _m\n"
                           "main = lambda a: _m(['gate', 'mcp-after', *a])")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network touched")
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.delenv("ARCAEON_GATE_MODE", raising=False)
    monkeypatch.delenv("ARCAEON_GATEWAY_CONFIG", raising=False)


def _seal(tmp_path: Path, data: bytes, signed: bool = True) -> tuple[dict, str]:
    d = tmp_path / f"s{secrets.token_hex(4)}"
    d.mkdir()
    f = d / "out.txt"
    f.write_bytes(data)
    key = None
    if signed:
        key = d / "seal.key"
        key.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
                       encoding="ascii")
    env = E.seal(f, key_file=key, **BIND)
    sigs = env["dsseEnvelope"]["signatures"]
    return env, (sigs[0]["keyid"] if sigs else "did:key:z6Mkx")


def _result(tmp_path, case: str) -> tuple[dict, str]:
    if case == "none":
        return {"content": [{"type": "text", "text": TEXT}], "resultType": "complete"}, \
            "did:key:z6Mkx"
    env, did = _seal(tmp_path, TEXT.encode("utf-8"), signed=case != "unsigned")
    text = TEXT + (" " if case == "broken" else "")
    return {"content": [{"type": "text", "text": text, "_meta": {M.BUNDLE_KEY: env}}],
            "resultType": "complete"}, did


def _config(tmp_path, did, **over) -> Path:
    p = tmp_path / f"gw-{secrets.token_hex(3)}.json"
    p.write_text(json.dumps({"audience": AUD, "signers": [did], "deal": DEAL,
                             "purpose": PURPOSE, **over}), encoding="utf-8")
    return p


def _run(tmp_path, stdin: bytes, *args, env_extra=None, child=CHILD):
    env = {**os.environ, "ARCAEON_HOME": str(tmp_path / "home"),
           "PYTHONPATH": str(ROOT / "src")}
    env.pop("ARCAEON_GATE_MODE", None)
    env.pop("ARCAEON_GATEWAY_CONFIG", None)
    env.update(env_extra or {})
    p = subprocess.run([sys.executable, "-c", child, *map(str, args)], input=stdin,
                       capture_output=True, env=env, timeout=60, cwd=tmp_path)
    return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace")


def _refused(out: dict, word: str):
    assert out["isError"] is True
    assert out["content"][0]["text"].startswith(f"REFUSED by arcaeon: {word}.")
    assert SECRET not in json.dumps(out)
    assert out["_meta"][M.VERDICT_KEY]["verdict"] == word


# --- the subprocess matrix -------------------------------------------------------------

@pytest.mark.parametrize("case,word,allowed", [
    ("verified", V.VERIFIED, True), ("broken", V.BROKEN, False),
    ("unsigned", V.COULD_NOT_LOOK, False), ("none", V.COULD_NOT_LOOK, False)])
def test_matrix_over_stdin_and_stdout(tmp_path, case, word, allowed):
    res, did = _result(tmp_path, case)
    code, out, err = _run(tmp_path, json.dumps(res).encode(), "--config",
                          _config(tmp_path, did))
    assert code == 0, err
    out = json.loads(out)
    assert out["_meta"][M.VERDICT_KEY]["verdict"] == word
    if allowed:
        assert out["content"] == res["content"] and out.get("isError") is not True
    else:
        _refused(out, word)
    assert word in err                                      # one line for the gateway log


def test_warn_mode_passes_with_a_warning(tmp_path):
    res, did = _result(tmp_path, "broken")
    code, out, _ = _run(tmp_path, json.dumps(res).encode(), "--config",
                        _config(tmp_path, did), env_extra={"ARCAEON_GATE_MODE": "warn"})
    out = json.loads(out)
    assert code == 0 and out["content"] == res["content"]
    assert "would refuse in block mode" in out["_meta"][M.VERDICT_KEY]["warning"]
    code, out, _ = _run(tmp_path, json.dumps(res).encode(), "--config",
                        _config(tmp_path, did), "--enforce", "block",
                        env_extra={"ARCAEON_GATE_MODE": "warn"})
    assert json.loads(out)["isError"] is True


def test_per_tool_read_allows_could_not_look(tmp_path):
    res, _ = _result(tmp_path, "none")
    cfg = _config(tmp_path, "did:key:z6Mkx", tools={"search": "read"})
    code, out, _ = _run(tmp_path, json.dumps(res).encode(), "--config", cfg, "--tool", "search")
    out = json.loads(out)
    assert code == 0 and out["content"] == res["content"]
    assert out["_meta"][M.VERDICT_KEY]["action"] == "read"
    code, out, _ = _run(tmp_path, json.dumps(res).encode(), "--config", cfg, "--tool", "send")
    _refused(json.loads(out), V.COULD_NOT_LOOK)


# --- the real shape: docker/mcp-gateway a34df45d, pkg/interceptors/interceptors.go ------
# After the call the gateway writes json.Marshal(*mcp.CallToolResult) to stdin
# (l.119-122), unmarshals non-empty stdout into mcp.CallToolResult (l.133-139),
# and keeps the original when stdout is empty (l.142). See
# tests/fixtures/docker_mcp_gateway/README.md.

FIX = ROOT / "tests" / "fixtures" / "docker_mcp_gateway"
GO_RESULT_KEYS = {"_meta", "content", "structuredContent", "isError"}   # protocol.go l.76-120


def _go_bytes(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sample() -> dict:
    return json.loads((FIX / "after_stdin_tool_result.json").read_bytes())


def _sealed_sample(tmp_path, signed=True) -> tuple[dict, str]:
    s = _sample()
    env, did = _seal(tmp_path, s["content"][0]["text"].encode("utf-8"), signed=signed)
    s["content"][0]["_meta"] = {M.BUNDLE_KEY: env}       # TextContent: type, text, _meta
    return s, did


def _as_go_reads_it(out: bytes) -> dict:
    """What CallToolResult.UnmarshalJSON keeps: the struct's fields only."""
    assert out.strip(), "empty stdout would let the original result through (l.142)"
    obj = json.loads(out)
    assert isinstance(obj, dict) and isinstance(obj.get("content"), list)
    assert all(isinstance(b, dict) and isinstance(b.get("type"), str) for b in obj["content"])
    return {k: v for k, v in obj.items() if k in GO_RESULT_KEYS}


def test_the_fixture_is_a_bare_call_tool_result():
    raw = (FIX / "after_stdin_tool_result.json").read_bytes()
    assert raw == _go_bytes(_sample())                   # compact, as json.Marshal writes it
    assert set(_sample()) <= GO_RESULT_KEYS and "jsonrpc" not in _sample()


def test_real_shape_verified_passes_through(tmp_path):
    s, did = _sealed_sample(tmp_path)
    code, out, err = _run(tmp_path, _go_bytes(s), "--config", _config(tmp_path, did))
    assert code == 0, err
    got = _as_go_reads_it(out)
    assert got["content"] == s["content"] and not got.get("isError")
    assert got["_meta"][M.VERDICT_KEY]["verdict"] == V.VERIFIED


@pytest.mark.parametrize("signed", [False, None])
def test_real_shape_unverified_is_refused_by_default(tmp_path, signed):
    if signed is None:
        s, did = _sample(), "did:key:z6Mkx"              # the fixture as-is: nothing sealed
    else:
        s, did = _sealed_sample(tmp_path, signed=False)
    code, out, err = _run(tmp_path, _go_bytes(s), "--config", _config(tmp_path, did))
    assert code == 0, err
    got = _as_go_reads_it(out)
    _refused(got, V.COULD_NOT_LOOK)


def test_real_shape_opt_out_still_works(tmp_path):
    s = _sample()
    code, out, _ = _run(tmp_path, _go_bytes(s), "--config", _config(tmp_path, "did:key:z6Mkx"),
                        "--enforce", "warn")
    got = _as_go_reads_it(out)
    assert code == 0 and got["content"] == s["content"] and not got.get("isError")
    assert "would refuse in block mode" in got["_meta"][M.VERDICT_KEY]["warning"]
    code, out, _ = _run(tmp_path, _go_bytes(s), "--config", _config(tmp_path, "did:key:z6Mkx"),
                        env_extra={"ARCAEON_GATE_MODE": "warn"})
    assert _as_go_reads_it(out)["content"] == s["content"]


def test_null_stdin_is_the_gateway_error_and_passes_through(tmp_path):
    raw = (FIX / "after_stdin_error_null.json").read_bytes()
    assert raw == b"null"
    code, out, err = _run(tmp_path, raw)
    assert code == 0 and out == b""                      # empty: the gateway keeps its error
    assert "error" in err


@pytest.mark.parametrize("msg", [
    {"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": TEXT}]}},
    {"request": {"params": {"name": "search"}},
     "response": {"content": [{"type": "text", "text": TEXT}]}},
    {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "bad"}}])
def test_envelopes_docker_never_sends_are_refused_as_not_a_result(tmp_path, msg):
    cfg = _config(tmp_path, "did:key:z6Mkx", tools={"search": "read"}, default_action="read")
    code, out, _ = _run(tmp_path, json.dumps(msg).encode(), "--config", cfg)
    got = _as_go_reads_it(out)
    _refused(got, V.COULD_NOT_LOOK)
    assert "CallToolResult" in got["content"][0]["text"]


def test_a_tool_name_inside_the_result_is_not_read(tmp_path):
    s = {**_sample(), "params": {"name": "search"}}       # server-supplied: never trusted
    cfg = _config(tmp_path, "did:key:z6Mkx", tools={"search": "read"})
    code, out, _ = _run(tmp_path, json.dumps(s).encode(), "--config", cfg)
    got = _as_go_reads_it(out)
    _refused(got, V.COULD_NOT_LOOK)
    assert got["_meta"][M.VERDICT_KEY]["action"] == "act"


@pytest.mark.parametrize("stdin", [b"", b"not json", b"[1, 2]", b'{"a": 1, "a": 2}',
                                   b"\xff\xfe\x00", b'"just a string"', b"{}"])
def test_malformed_stdin_is_a_refusal_not_a_crash(tmp_path, stdin):
    code, out, err = _run(tmp_path, stdin)
    assert code == 0, err
    out = json.loads(out)
    assert out["isError"] is True
    assert out["_meta"][M.VERDICT_KEY]["verdict"] == V.COULD_NOT_LOOK
    assert "Traceback" not in err


def test_the_gate_verb_runs_the_same_interceptor(tmp_path):
    res, did = _result(tmp_path, "verified")
    code, out, err = _run(tmp_path, json.dumps(res).encode(), "--config",
                          _config(tmp_path, did), child=CHILD_GATE)
    assert code == 0, err
    assert json.loads(out)["_meta"][M.VERDICT_KEY]["verdict"] == V.VERIFIED


def test_config_from_the_environment(tmp_path):
    res, did = _result(tmp_path, "verified")
    code, out, _ = _run(tmp_path, json.dumps(res).encode(),
                        env_extra={"ARCAEON_GATEWAY_CONFIG": str(_config(tmp_path, did))})
    assert code == 0 and json.loads(out)["_meta"][M.VERDICT_KEY]["verdict"] == V.VERIFIED


@pytest.mark.parametrize("args", [["--config", "missing.json"], ["--action", "write"],
                                  ["--enforce", "loud"], ["--bogus"]])
def test_bad_arguments_still_answer_json_and_refuse(tmp_path, args):
    res, _ = _result(tmp_path, "none")
    code, out, err = _run(tmp_path, json.dumps(res).encode(), *args)
    assert code == 2 and err.strip()
    out = json.loads(out)
    assert out["isError"] is True and SECRET not in json.dumps(out)


# --- in process ------------------------------------------------------------------------

def test_main_in_process_with_streams(tmp_path):
    res, did = _result(tmp_path, "broken")
    sin = io.BytesIO(json.dumps(res).encode())
    sout, serr = io.BytesIO(), io.StringIO()
    code = D.main(["--config", str(_config(tmp_path, did))], stdin=sin, stdout=sout,
                  stderr=serr)
    assert code == 0
    _refused(json.loads(sout.getvalue()), V.BROKEN)


def test_oversized_stdin_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(D, "MAX_STDIN_BYTES", 16)
    sout = io.BytesIO()
    assert D.main([], stdin=io.BytesIO(b'{"content": []}' + b" " * 32), stdout=sout,
                  stderr=io.StringIO()) == 0
    assert json.loads(sout.getvalue())["isError"] is True


def test_help_exits_zero():
    sout = io.BytesIO()
    serr = io.StringIO()
    assert D.main(["--help"], stdin=io.BytesIO(b""), stdout=sout, stderr=serr) == 0


# --- docs ------------------------------------------------------------------------------

def test_gateways_doc_has_the_docker_section():
    doc = (ROOT / "docs" / "GATEWAYS.md").read_text(encoding="utf-8")
    assert "docker mcp gateway run --interceptor" in doc
    assert "after:exec:arcaeon gate mcp-after" in doc
    assert "## Docker MCP Gateway (L4-03)" in doc
    assert "a34df45d4ec0e941a9853ad768c4f6cd818966b3" in doc            # the cite (L4-05)
    assert "pkg/interceptors/interceptors.go" in doc
    assert "Not yet confirmed: the exact JSON Docker" not in doc
