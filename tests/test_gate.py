"""The gate (TE-21 / D050): `arcaeon gate decide` turns the envelope's verdict
and an action into allow or refuse. Every key here is a throwaway seed written
to tmp_path; nothing reaches the network."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from datetime import datetime
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import envelope as E
from arcaeon.prove import gate as G

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

BIND = {"label": "week 3 grades", "audience": "instructor-1", "deal": "d-7f3a",
        "purpose": "grading", "not_after": "7d"}
BODY = b"name,grade\nunit-a,pass\n"


def _key(tmp_path: Path) -> Path:
    k = tmp_path / "seal.key"
    k.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"), encoding="ascii")
    return k


def _sealed(tmp_path: Path, signed: bool = True):
    f = tmp_path / "in" / "grades.csv"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(BODY)
    env = E.seal(f, key_file=_key(tmp_path) if signed else None, **BIND)
    sigs = env["dsseEnvelope"]["signatures"]
    return f, (sigs[0]["keyid"] if sigs else "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")


def _make(tmp_path: Path, verdict: str):
    """A handed file whose envelope verifies to `verdict`."""
    if verdict == V.COULD_NOT_LOOK:
        return _sealed(tmp_path, signed=False)        # unsigned: who sealed it is unknown
    f, did = _sealed(tmp_path)
    if verdict == V.BROKEN:
        f.write_bytes(BODY + b"unit-b,pass\n")         # bytes changed after sealing
    return f, did


@pytest.fixture(autouse=True)
def _cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)                        # a default record_dir lands in tmp


# --- the table: 3 verdicts x 4 actions ------------------------------------------------

TABLE = [(V.VERIFIED, "read", "allow"), (V.VERIFIED, "act", "allow"),
         (V.VERIFIED, "pay", "allow"), (V.VERIFIED, "irreversible", "allow"),
         (V.BROKEN, "read", "refuse"), (V.BROKEN, "act", "refuse"),
         (V.BROKEN, "pay", "refuse"), (V.BROKEN, "irreversible", "refuse"),
         (V.COULD_NOT_LOOK, "read", "allow"), (V.COULD_NOT_LOOK, "act", "refuse"),
         (V.COULD_NOT_LOOK, "pay", "refuse"), (V.COULD_NOT_LOOK, "irreversible", "refuse")]


@pytest.mark.parametrize("verdict,action,want", TABLE,
                         ids=[f"{v.replace(' ', '_')}-{a}" for v, a, _ in TABLE])
def test_rule_table_cell(tmp_path, verdict, action, want):
    f, did = _make(tmp_path, verdict)
    d = G.decide(f, action=action, audience="instructor-1", signers=[did],
                 record_dir=tmp_path / "rec")
    assert d.verdict == verdict
    assert d.decision == want and d.allowed is (want == "allow") and bool(d) is d.allowed
    assert d.reason.startswith(f"{want} {action}: {verdict}")
    want_exit = 0 if want == "allow" else (1 if verdict == V.BROKEN else 3)
    assert d.exit_code == want_exit
    assert not (tmp_path / "rec").exists()             # no deal id: nothing written
    assert len(TABLE) == 12


def test_allow_never_claims_true_or_safe(tmp_path):
    f, did = _make(tmp_path, V.VERIFIED)
    d = G.decide(f, action="irreversible", audience="instructor-1", signers=[did])
    assert "unchanged since the key you named sealed them" in d.reason
    assert "does not say the content is true or safe" in d.reason
    low = d.reason.lower().replace("does not say the content is true or safe", "")
    assert "is true" not in low and "is safe" not in low


# --- the evidence pack ----------------------------------------------------------------

def test_broken_with_deal_writes_evidence_pack(tmp_path):
    f, did = _make(tmp_path, V.BROKEN)
    rec = tmp_path / "rec"
    d = G.decide(f, action="pay", audience="instructor-1", signers=[did], deal="d-7f3a",
                 record_dir=rec)
    assert d.decision == "refuse" and d.verdict == V.BROKEN and d.exit_code == 1
    out = Path(d.evidence)
    assert out.parent == rec / "DEAL-d-7f3a" / "gate"
    assert re.fullmatch(r"\d{8}T\d{6}Z-[0-9a-f]{12}", out.name)
    assert f"Evidence pack written to {out}" in d.reason
    ev = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    assert ev["kind"] == G.EVIDENCE_KIND
    assert ev["deal"] == "d-7f3a" and ev["action"] == "pay"
    assert ev["decision"] == "refuse" and ev["verdict"] == V.BROKEN
    assert ev["reasons"] and any("sha256" in r for r in ev["reasons"])
    assert ev["reason"] == d.reason.split(" Evidence pack written")[0]
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", ev["at"])
    datetime.strptime(ev["at"], "%Y-%m-%dT%H:%M:%SZ")
    copy = out / ev["file"]["copy"]
    assert copy.read_bytes() == f.read_bytes()
    assert ev["file"]["sha256"] == hashlib.sha256(f.read_bytes()).hexdigest()
    assert ev["file"]["bytes"] == len(f.read_bytes())
    side = E.envelope_path(f)
    assert (out / ev["envelope"]["copy"]).read_bytes() == side.read_bytes()
    assert ev["envelope"]["sha256"] == hashlib.sha256(side.read_bytes()).hexdigest()
    assert ev["audience"] == "instructor-1" and ev["signers"] == [did]
    assert ev["report"]["verdict"] == V.BROKEN


def test_two_packs_for_one_deal_do_not_overwrite(tmp_path):
    f, did = _make(tmp_path, V.BROKEN)
    kw = dict(action="act", audience="instructor-1", signers=[did], deal="d-7f3a",
              record_dir=tmp_path / "rec")
    a, b = G.decide(f, **kw), G.decide(f, **kw)
    assert a.evidence != b.evidence
    assert (Path(a.evidence) / "evidence.json").is_file()
    assert (Path(b.evidence) / "evidence.json").is_file()


def test_broken_without_deal_writes_no_pack(tmp_path):
    f, did = _make(tmp_path, V.BROKEN)
    before = sorted(p.name for p in tmp_path.iterdir())
    d = G.decide(f, action="pay", audience="instructor-1", signers=[did])
    assert d.decision == "refuse" and d.evidence is None
    assert "no evidence pack was written" in d.reason
    assert sorted(p.name for p in tmp_path.iterdir()) == before
    assert not list(tmp_path.glob("DEAL-*"))


def test_no_pack_on_verified_or_could_not_look_with_deal(tmp_path):
    for verdict in (V.VERIFIED, V.COULD_NOT_LOOK):
        sub = tmp_path / verdict.replace(" ", "_")
        sub.mkdir()
        f, did = _make(sub, verdict)
        d = G.decide(f, action="pay", audience="instructor-1", signers=[did], deal="d-7f3a",
                     record_dir=sub / "rec")
        assert d.evidence is None and not (sub / "rec").exists()


def test_unsafe_deal_id_stays_inside_record_dir(tmp_path):
    f, did = _make(tmp_path, V.BROKEN)
    rec = tmp_path / "rec"
    d = G.decide(f, action="read", audience="instructor-1", signers=[did],
                 deal="../../escape", record_dir=rec)
    out = Path(d.evidence).resolve()
    assert rec.resolve() in out.parents
    assert out.parent.parent.name.startswith("DEAL-sha256-")


# --- COULD NOT LOOK names what it could not check -------------------------------------

def test_could_not_look_reason_names_the_unchecked_thing(tmp_path):
    f, did = _make(tmp_path, V.COULD_NOT_LOOK)
    d = G.decide(f, action="pay", audience="instructor-1", signers=[did])
    assert d.decision == "refuse" and d.verdict == V.COULD_NOT_LOOK
    assert d.could_not_check["looked_for"] == "a signature on the envelope"
    assert d.could_not_check["reason_word"] == "missing"
    assert "could not check a signature on the envelope (missing)" in d.reason
    assert "UNSIGNED" in d.reason and "Only read is allowed" in d.reason
    r = G.decide(f, action="read", audience="instructor-1", signers=[did])
    assert r.decision == "allow" and "could not check a signature on the envelope" in r.reason


def test_could_not_look_without_signer_names_the_signer(tmp_path):
    f, _ = _make(tmp_path, V.VERIFIED)
    d = G.decide(f, action="act", audience="instructor-1", signers=[])
    assert d.verdict == V.COULD_NOT_LOOK and d.decision == "refuse"
    assert "the key you trust (--signer)" in d.reason


def test_missing_sidecar_is_could_not_look_read_only(tmp_path):
    f = tmp_path / "bare.txt"
    f.write_bytes(BODY)
    d = G.decide(f, action="irreversible", audience="instructor-1", signers=["did:key:zX"])
    assert d.verdict == V.COULD_NOT_LOOK and d.decision == "refuse"
    assert "the envelope sidecar (missing)" in d.reason


# --- binding: wrong audience or deal is BROKEN, refused -------------------------------

def test_wrong_audience_is_broken_and_refused(tmp_path):
    f, did = _make(tmp_path, V.VERIFIED)
    d = G.decide(f, action="read", audience="Instructor-1", signers=[did])
    assert d.verdict == V.BROKEN and d.decision == "refuse" and d.exit_code == 1
    assert "audience: sealed for 'instructor-1'" in d.reason


def test_wrong_deal_is_broken_and_packed_in_the_receivers_deal(tmp_path):
    f, did = _make(tmp_path, V.VERIFIED)
    d = G.decide(f, action="pay", audience="instructor-1", signers=[did], deal="d-other",
                 record_dir=tmp_path / "rec")
    assert d.verdict == V.BROKEN and d.decision == "refuse"
    assert "deal: sealed for 'd-7f3a'" in d.reason
    assert Path(d.evidence).parent.parent.name == "DEAL-d-other"


# --- one verifier ---------------------------------------------------------------------

def test_gate_uses_envelope_verify_and_nothing_else(tmp_path, monkeypatch):
    calls = []

    def fake(file, envelope=None, **kw):
        calls.append((file, envelope, kw))
        return {"verdict": V.VERIFIED, "reason": E.PROVES, "findings": []}

    monkeypatch.setattr(E, "verify", fake)
    d = G.decide(tmp_path / "nothing-here", action="pay", audience="me", signers=["did:key:zA"],
                 deal="d-1", purpose="p")
    assert d.decision == "allow" and len(calls) == 1
    kw = calls[0][2]
    assert kw["audience"] == "me" and kw["signers"] == ["did:key:zA"]
    assert kw["deal"] == "d-1" and kw["purpose"] == "p"


def test_unknown_verdict_word_from_verify_is_never_allowed_beyond_read(tmp_path, monkeypatch):
    monkeypatch.setattr(E, "verify", lambda *a, **k: {"verdict": "MAYBE", "reason": "?"})
    assert G.decide(tmp_path / "x", action="pay", audience="me").decision == "refuse"


def test_unknown_action_raises(tmp_path):
    with pytest.raises(ValueError):
        G.decide(tmp_path / "x", action="spend", audience="me")


# --- the CLI ----------------------------------------------------------------------------

def _cli(f, did, *extra):
    return cli.main(["gate", "decide", "--envelope", str(E.envelope_path(f)),
                     "--audience", "instructor-1", "--signer", did, *extra])


def test_cli_exit_codes_and_output(tmp_path, capsys):
    f, did = _make(tmp_path, V.VERIFIED)
    assert _cli(f, did, "--action", "pay") == 0
    assert capsys.readouterr().out.startswith("allow pay: VERIFIED")
    assert _cli(f, did, "--action", "pay", "--json") == 0
    j = json.loads(capsys.readouterr().out)
    assert j["decision"] == "allow" and j["exit_code"] == 0 and j["verdict"] == V.VERIFIED
    # the handed file itself, sidecar beside it
    assert cli.main(["gate", "decide", "--envelope", str(f), "--audience", "instructor-1",
                     "--signer", did, "--action", "act"]) == 0
    capsys.readouterr()
    f.write_bytes(b"changed")
    assert _cli(f, did, "--action", "read", "--deal", "d-7f3a",
                "--record-dir", str(tmp_path / "rec")) == 1
    assert capsys.readouterr().out.startswith("refuse read: BROKEN")
    assert list((tmp_path / "rec" / "DEAL-d-7f3a" / "gate").iterdir())


def test_cli_could_not_look_refuse_is_3_and_read_is_0(tmp_path, capsys):
    f, did = _make(tmp_path, V.COULD_NOT_LOOK)
    assert _cli(f, did, "--action", "irreversible") == 3
    assert _cli(f, did, "--action", "read") == 0


def test_cli_usage_errors_are_2(tmp_path, capsys):
    f, did = _make(tmp_path, V.VERIFIED)
    assert _cli(f, did, "--action", "spend") == 2
    assert _cli(f, did) == 2                                        # no --action
    assert cli.main(["gate", "decide", "--envelope", str(f), "--audience", "instructor-1",
                     "--action", "read"]) == 2                     # no --signer
    assert cli.main(["gate", "frob"]) == 2
    assert cli.main(["gate", "decide", "--envelope", str(f), "--nope"]) == 2
    assert cli.main(["gate", "--help"]) == 0
    assert "irreversible" in capsys.readouterr().out
