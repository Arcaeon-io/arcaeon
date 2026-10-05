"""The A2A witness extension's reference receiver (D062 / TE-23). Fixture A2A
messages carry a labeled-exchange envelope in an Artifact's metadata under
https://arcaeon.io/a2a/witness/v1; the receiver hands it to the gate. Every key
is a throwaway seed in tmp_path; nothing reaches the network."""
from __future__ import annotations

import base64
import copy
import json
import secrets
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import a2a_receiver as A
from arcaeon.prove import envelope as E
from arcaeon.prove import gate as G

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

URI = "https://arcaeon.io/a2a/witness/v1"
BIND = {"label": "week 3 grades", "audience": "instructor-1", "deal": "d-7f3a",
        "purpose": "grading", "not_after": "7d"}
BODY = b"name,grade\nunit-a,pass\n"
ME = "instructor-1"


@pytest.fixture(autouse=True)
def _cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


def _sealed(tmp_path: Path, signed: bool = True):
    """(sidecar object, signer did) for BODY sealed for ME."""
    f = tmp_path / "seal" / "grades.csv"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(BODY)
    key = None
    if signed:
        key = tmp_path / "seal.key"
        key.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"), encoding="ascii")
    env = E.seal(f, key_file=key, **BIND)
    sigs = env["dsseEnvelope"]["signatures"]
    return env, (sigs[0]["keyid"] if sigs else
                 "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")


def _artifact(env: dict | None, inline: bool = True, art_id: str = "grades-001") -> dict:
    a = {"artifactId": art_id, "name": "week 3 grades",
         "parts": [{"raw": base64.b64encode(BODY).decode("ascii"), "filename": "grades.csv",
                    "mediaType": "text/csv"} if inline else
                   {"url": "https://files.example/grades.csv", "filename": "grades.csv"}]}
    if env is not None:
        A.attach_envelope(a, env)
    return a


def _task(*artifacts) -> dict:
    """A JSON-RPC response around a Task (A2A 1.0 shapes)."""
    return {"jsonrpc": "2.0", "id": "1",
            "result": {"task": {"id": "t-1", "contextId": "c-1",
                                "status": {"state": "TASK_STATE_COMPLETED"},
                                "artifacts": list(artifacts)}}}


def _b(o) -> bytes:
    return json.dumps(o).encode("utf-8")


def _ex(tmp_path: Path) -> dict:
    """act, pay and irreversible need the exchange named (F2, R3); a deal needs a ledger (D066)."""
    return {"deal": "d-7f3a", "purpose": "grading", "ledger": tmp_path / "ledger.jsonl",
            "record_dir": tmp_path / "rec"}


def _ex_cli(tmp_path: Path) -> list:
    return ["--deal", "d-7f3a", "--purpose", "grading",
            "--ledger", str(tmp_path / "ledger.jsonl"), "--record-dir", str(tmp_path / "rec")]


# --- the fixture cases the item names -------------------------------------------------

def test_good_artifact_allows_every_action(tmp_path):
    env, did = _sealed(tmp_path)
    msg = _b(_task(_artifact(env)))
    for action in G.ACTIONS:
        d = A.receive(msg, BODY, action=action, audience=ME, signers=[did], **_ex(tmp_path))
        assert d.verdict == V.VERIFIED and d.decision == "allow", d.reason
        assert d.exit_code == 0
    assert d.a2a["carrier"] == "artifact" and d.a2a["id"] == "grades-001"
    assert d.a2a["listed"] is True and d.a2a["file_from"] == "given"
    assert "does not say the content is true or safe" in d.reason


def test_good_artifact_inline_raw_part(tmp_path):
    env, did = _sealed(tmp_path)
    d = A.receive(_b(_task(_artifact(env))), None, action="pay", audience=ME, signers=[did],
                  **_ex(tmp_path))
    assert d.verdict == V.VERIFIED and d.allowed and d.a2a["file_from"] == "inline part"


def test_tampered_file_is_broken_and_refused(tmp_path):
    env, did = _sealed(tmp_path)
    msg = _b(_task(_artifact(env)))
    for action in G.ACTIONS:
        d = A.receive(msg, BODY + b"unit-b,pass\n", action=action, audience=ME, signers=[did])
        assert d.verdict == V.BROKEN and d.decision == "refuse" and d.exit_code == 1
    assert any("bytes changed" in r for r in d.reasons)


def test_tampered_inline_part_is_broken(tmp_path):
    env, did = _sealed(tmp_path)
    a = _artifact(env)
    a["parts"][0]["raw"] = base64.b64encode(BODY.replace(b"pass", b"fail")).decode("ascii")
    d = A.receive(_b(_task(a)), None, action="read", audience=ME, signers=[did])
    assert d.verdict == V.BROKEN and not d.allowed


def test_tampered_envelope_payload_is_broken(tmp_path):
    env, did = _sealed(tmp_path)
    env = copy.deepcopy(env)
    stmt = json.loads(base64.b64decode(env["dsseEnvelope"]["payload"]))
    stmt["predicate"]["binding"]["audience"] = "someone-else"
    env["dsseEnvelope"]["payload"] = base64.b64encode(
        json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode()).decode()
    d = A.receive(_b(_task(_artifact(env))), BODY, action="read", audience=ME, signers=[did])
    assert d.verdict == V.BROKEN and not d.allowed


@pytest.mark.parametrize("strip", ["metadata", "value", "both"])
def test_stripped_metadata_is_could_not_look_read_only(tmp_path, strip):
    env, did = _sealed(tmp_path)
    a = _artifact(env)
    if strip in ("metadata", "both"):
        del a["metadata"]
    if strip == "value":
        a["metadata"] = {"other": 1}
    if strip == "both":
        del a["extensions"]
    msg = _b(_task(a))
    got = {act: A.receive(msg, BODY, action=act, audience=ME, signers=[did], **_ex(tmp_path))
           for act in G.ACTIONS}
    assert {a_: d.decision for a_, d in got.items()} == {
        "read": "allow", "act": "refuse", "pay": "refuse", "irreversible": "refuse"}
    d = got["pay"]
    assert d.verdict == V.COULD_NOT_LOOK and d.exit_code == 3
    assert d.could_not_check["reason_word"] == "missing"
    assert d.a2a["listed"] is (strip != "both")
    if strip != "both":
        assert "lists https://arcaeon.io/a2a/witness/v1" in d.reason


def test_wrong_audience_is_broken(tmp_path):
    env, did = _sealed(tmp_path)
    d = A.receive(_b(_task(_artifact(env))), BODY, action="read", audience="instructor-2",
                  signers=[did])
    assert d.verdict == V.BROKEN and not d.allowed
    assert any("audience: sealed for 'instructor-1'" in r for r in d.reasons)


def test_wrong_signer_and_no_signer(tmp_path):
    env, did = _sealed(tmp_path)
    other = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    msg = _b(_task(_artifact(env)))
    assert A.receive(msg, BODY, action="read", audience=ME, signers=[other]).verdict == V.BROKEN
    d = A.receive(msg, BODY, action="act", audience=ME, signers=[], **_ex(tmp_path))
    assert d.verdict == V.COULD_NOT_LOOK and not d.allowed


def test_unsigned_envelope_is_could_not_look(tmp_path):
    env, did = _sealed(tmp_path, signed=False)
    d = A.receive(_b(_task(_artifact(env))), BODY, action="pay", audience=ME, signers=[did])
    assert d.verdict == V.COULD_NOT_LOOK and not d.allowed


# --- declared, listed, activated ---------------------------------------------------

def test_listing_and_activation_change_no_verdict(tmp_path):
    """The spec (4.6, topics/extensions) separates declaring (AgentCard),
    activating (A2A-Extensions header) and listing (the carrier's
    `extensions`). None is signed, so none moves the verdict here."""
    env, did = _sealed(tmp_path)
    a = _artifact(env)
    a["extensions"] = []                              # value present, not listed
    msg = _b(_task(a))
    for activated in (None, "", "https://example.com/other/v1", f"x/v1, {URI}"):
        d = A.receive(msg, BODY, action="pay", audience=ME, signers=[did], activated=activated,
                      **_ex(tmp_path))
        assert d.verdict == V.VERIFIED and d.allowed
        assert d.a2a["listed"] is False
        assert d.a2a["activated"] is (None if activated is None else URI in activated)
    tampered = A.receive(msg, BODY + b"x", action="read", audience=ME, signers=[did],
                         activated=URI)
    assert tampered.verdict == V.BROKEN


def test_declared_but_not_activated_still_gates(tmp_path):
    """An agent that declares the extension but whose request did not activate
    it still runs the gate: no envelope is COULD NOT LOOK, read only."""
    card = {"name": "grader", "capabilities": {"extensions": [A.agent_extension()]}}
    assert A.declares(card) and not A.declares({"capabilities": {"extensions": [{"uri": "x"}]}})
    _, did = _sealed(tmp_path)
    msg = _b(_task(_artifact(None)))
    d = A.receive(msg, BODY, action="act", audience=ME, signers=[did], activated=[],
                  **_ex(tmp_path))
    assert d.verdict == V.COULD_NOT_LOOK and not d.allowed and d.a2a["activated"] is False
    assert A.receive(msg, BODY, action="read", audience=ME, signers=[did]).allowed


# --- carriers -----------------------------------------------------------------------

def test_message_carrier_and_bare_artifact_and_update_event(tmp_path):
    env, did = _sealed(tmp_path)
    m = {"messageId": "m-1", "role": "ROLE_USER",
         "parts": [{"raw": base64.b64encode(BODY).decode(), "filename": "grades.csv"}]}
    A.attach_envelope(m, env)
    shapes = [{"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {"message": m}},
              _artifact(env), {"taskId": "t", "contextId": "c", "artifact": _artifact(env)}]
    for o in shapes:
        d = A.receive(_b(o), None, action="pay", audience=ME, signers=[did], **_ex(tmp_path))
        assert d.verdict == V.VERIFIED, (o, d.reason)
    assert A.receive(_b(shapes[0]), None, action="pay", audience=ME,
                     signers=[did], **_ex(tmp_path)).a2a["carrier"] == "message"


def test_v03_file_part_shape(tmp_path):
    env, did = _sealed(tmp_path)
    a = {"artifactId": "a", "parts": [{"kind": "file", "file": {
        "bytes": base64.b64encode(BODY).decode(), "name": "grades.csv", "mimeType": "text/csv"}}]}
    A.attach_envelope(a, env)
    d = A.receive(_b({"kind": "task", "id": "t", "artifacts": [a]}), None, action="pay",
                  audience=ME, signers=[did], **_ex(tmp_path))
    assert d.verdict == V.VERIFIED


def test_two_carriers_need_an_artifact_id(tmp_path):
    env, did = _sealed(tmp_path)
    msg = _b(_task(_artifact(env, art_id="a1"), _artifact(env, art_id="a2")))
    d = A.receive(msg, BODY, action="read", audience=ME, signers=[did])
    assert d.verdict == V.COULD_NOT_LOOK and d.could_not_check["reason_word"] == "bounded"
    d = A.receive(msg, BODY, action="pay", audience=ME, signers=[did], artifact_id="a2",
                  **_ex(tmp_path))
    assert d.verdict == V.VERIFIED and d.a2a["id"] == "a2"
    d = A.receive(msg, BODY, action="read", audience=ME, signers=[did], artifact_id="nope")
    assert d.verdict == V.COULD_NOT_LOOK and d.could_not_check["reason_word"] == "missing"


def test_url_part_is_never_fetched(tmp_path):
    env, did = _sealed(tmp_path)
    d = A.receive(_b(_task(_artifact(env, inline=False))), None, action="act", audience=ME,
                  signers=[did], **_ex(tmp_path))
    assert d.verdict == V.COULD_NOT_LOOK and "never fetched" in d.reason


def test_stray_key_beside_envelope_is_broken(tmp_path):
    env, did = _sealed(tmp_path)
    a = _artifact(env)
    a["metadata"][URI]["trusted"] = True
    d = A.receive(_b(_task(a)), BODY, action="read", audience=ME, signers=[did])
    assert d.verdict == V.BROKEN and any("a2a:trusted" in r for r in d.reasons)


# --- hostile JSON: an answer, never a traceback --------------------------------------

HOSTILE = [b"", b"not json", b"\xff\xfe", b"[]", b"null", b"[" * 100000, b'{"a":' * 50000,
           b'{"result":{"result":{"result":{"result":{"result":{"result":{"result":{"result":'
           b'{"result":{"result":{}}}}}}}}}}}',
           _b({"artifactId": 1, "parts": "x"}), _b({"artifacts": [None, 1, "x", []]}),
           _b({"artifactId": "a", "parts": [None, 1, {"raw": 5}], "metadata": {URI: None}}),
           _b({"artifactId": "a", "parts": [], "metadata": {URI: {"envelope": "x"}}}),
           _b({"artifactId": "a", "parts": [], "metadata": {URI: {"envelope": {}}}}),
           _b({"artifactId": "a", "parts": [{"raw": "!!notb64"}],
               "metadata": {URI: {"envelope": {"mediaType": E.MEDIA_TYPE}}}}),
           _b({"artifactId": "a", "parts": [{"raw": "", "filename": "../../x"}],
               "metadata": {URI: {"envelope": {"mediaType": 1}}}}),
           b'{"artifactId": "a", "artifactId": "b", "parts": []}',
           b'{"artifactId": "a", "parts": [], "metadata": {"' + URI.encode() +
           b'": {"envelope": {"x": "\\ud800"}}}}']


@pytest.mark.parametrize("raw", HOSTILE, ids=range(len(HOSTILE)))
def test_hostile_message_never_raises_never_allows_act(tmp_path, raw):
    d = A.receive(raw, BODY, action="act", audience=ME, signers=["did:key:z6Mk"],
                  **_ex(tmp_path))
    assert d.verdict in (V.COULD_NOT_LOOK, V.BROKEN) and not d.allowed
    json.dumps(d.to_dict())


def test_duplicate_key_message_is_unreadable():
    d = A.receive(b'{"artifactId": "a", "artifactId": "b", "parts": []}', BODY, action="read",
                  audience=ME)
    assert d.verdict == V.COULD_NOT_LOOK and d.could_not_check["reason_word"] == "unreadable"


def test_oversize_message_not_read(monkeypatch):
    monkeypatch.setattr(A, "MAX_MESSAGE_BYTES", 10)
    d = A.receive(b'{"artifactId": "a", "parts": []}', BODY, action="read", audience=ME)
    assert d.verdict == V.COULD_NOT_LOOK and "not read" in d.reason


def test_unknown_action_raises():
    with pytest.raises(ValueError):
        A.receive(b"{}", BODY, action="delete", audience=ME)


# --- evidence and the CLI ------------------------------------------------------------

def test_broken_with_deal_writes_evidence_with_the_message(tmp_path):
    env, did = _sealed(tmp_path)
    msg = _b(_task(_artifact(env)))
    d = A.receive(msg, BODY + b"x", action="pay", audience=ME, signers=[did], deal="d-7f3a",
                  record_dir=tmp_path / "rec", ledger=tmp_path / "ledger.jsonl")
    assert d.verdict == V.BROKEN and d.evidence
    ev = json.loads((Path(d.evidence) / "evidence.json").read_text(encoding="utf-8"))
    assert ev["a2a"]["message"]["copy"] == "bundle/a2a-message.json"
    assert (Path(d.evidence) / "bundle" / "a2a-message.json").read_bytes() == msg
    assert "arcaeon-a2a-" not in json.dumps(ev) and "arcaeon-a2a-" not in json.dumps(d.to_dict())
    from arcaeon.prove import dispute_packet as P
    p = P.from_evidence(d.evidence)
    assert p["verdict"] == V.BROKEN and p["handed"]["file"] == "A2A artifact 'grades-001' file 'grades.csv'"
    assert "arcaeon-a2a-" not in P.render_markdown(p)
    # D066 on the stack: the message is in the pack before the row, so the row still matches
    assert d.chain_row and d.chain_error is None
    assert G.verify_evidence_pack(Path(d.evidence), d.chain_row)["verdict"] == V.VERIFIED


def test_cli_gate_a2a(tmp_path, capsys):
    env, did = _sealed(tmp_path)
    m = tmp_path / "msg.json"
    m.write_bytes(_b(_task(_artifact(env))))
    f = tmp_path / "grades.csv"
    f.write_bytes(BODY)
    base = ["gate", "a2a", "--message", str(m), "--audience", ME, "--signer", did]
    assert cli.main(base + ["--action", "pay", "--file", str(f), *_ex_cli(tmp_path)]) == 0
    assert capsys.readouterr().out.startswith("allow pay: VERIFIED")
    assert cli.main(base + ["--action", "pay", *_ex_cli(tmp_path)]) == 0                      # inline raw part
    f.write_bytes(BODY + b"x")
    capsys.readouterr()
    assert cli.main(base + ["--action", "read", "--file", str(f), "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["verdict"] == V.BROKEN
    m.write_bytes(_b(_task(_artifact(None))))
    assert cli.main(base + ["--action", "act", "--file", str(f), *_ex_cli(tmp_path)]) == 3
    assert cli.main(base + ["--action", "read", "--file", str(f)]) == 0
    assert cli.main(["gate", "a2a", "--message", str(tmp_path / "gone.json"), "--audience", ME,
                     "--signer", did, "--action", "pay"]) == 3
    assert cli.main(["gate", "a2a", "--audience", ME, "--signer", did, "--action", "pay"]) == 2
    assert cli.main(base + ["--action", "delete"]) == 2


def test_cli_json_carries_a2a(tmp_path, capsys):
    env, did = _sealed(tmp_path)
    m = tmp_path / "msg.json"
    m.write_bytes(_b(_task(_artifact(env))))
    capsys.readouterr()
    assert cli.main(["gate", "a2a", "--message", str(m), "--audience", ME, "--signer", did,
                     "--action", "pay", "--activated", URI, "--json", *_ex_cli(tmp_path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["decision"] == "allow" and out["a2a"]["extension"] == URI
    assert out["a2a"]["activated"] is True and out["file"].startswith("A2A artifact")


def test_deal_without_ledger_raises_before_anything(tmp_path):
    """D066 on the stack: a deal id needs the party's own ledger, as in gate.decide."""
    with pytest.raises(ValueError):
        A.receive(b"{}", BODY, action="pay", audience=ME, deal="d-7f3a")


# --- F2: pay / irreversible need the exchange named (no cross-deal replay) -----------

@pytest.mark.parametrize("action", ["pay", "irreversible"])
def test_pay_without_deal_is_could_not_look_not_a_traceback(tmp_path, action):
    env, did = _sealed(tmp_path)                    # sealed for deal d-7f3a, purpose grading
    msg = _b(_task(_artifact(env)))
    d = A.receive(msg, BODY, action=action, audience=ME, signers=[did])
    assert d.verdict == V.COULD_NOT_LOOK and d.decision == "refuse" and d.exit_code == 3
    assert "pass --deal and --purpose so the envelope is held to this exchange" in d.reasons
    assert d.evidence is None and d.a2a["carrier"] == "artifact"
    json.dumps(d.to_dict())
    d = A.receive(msg, BODY, action=action, audience=ME, signers=[did], deal="d-7f3a",
                  ledger=tmp_path / "ledger.jsonl", record_dir=tmp_path / "rec")
    assert d.verdict == V.COULD_NOT_LOOK and not d.allowed
    assert "pass --purpose so the envelope is held to this exchange" in d.reasons
    assert d.evidence and d.chain_row                # a refusal with a deal is evidence


@pytest.mark.parametrize("where", ["decide", "on_pack"])
def test_gate_raising_is_could_not_look_not_a_traceback(tmp_path, monkeypatch, where):
    """F1: receive's own catch-all covers G.decide and on_pack; type named, no message."""
    secret = "C:/secret/path/do-not-echo"
    real = A.G.decide

    def fake(*a, on_pack=None, **kw):
        if where == "decide":
            raise RuntimeError(secret)
        on_pack(tmp_path / "no-such-pack")              # a decide that lets on_pack raise
        return real(*a, on_pack=on_pack, **kw)

    monkeypatch.setattr(A.G, "decide", fake)
    monkeypatch.setattr(A, "_evidence_a2a", lambda *a: (_ for _ in ()).throw(OSError(secret)))
    env, did = _sealed(tmp_path)
    d = A.receive(_b(_task(_artifact(env))), BODY, action="pay", audience=ME, signers=[did],
                  **_ex(tmp_path))
    assert d.verdict == V.COULD_NOT_LOOK and d.decision == "refuse" and not d.allowed
    word = "RuntimeError" if where == "decide" else "OSError"
    assert word in d.reason and secret not in json.dumps(d.to_dict(), default=str)


def test_cli_gate_a2a_pay_without_deal_is_3(tmp_path, capsys):
    env, did = _sealed(tmp_path)
    m = tmp_path / "msg.json"
    m.write_bytes(_b(_task(_artifact(env))))
    assert cli.main(["gate", "a2a", "--message", str(m), "--audience", ME, "--signer", did,
                     "--action", "pay"]) == 3
    assert "pass --deal and --purpose so the envelope is held to this exchange" in capsys.readouterr().out
