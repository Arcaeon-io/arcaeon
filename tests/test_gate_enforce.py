"""The gate, default-on (L4-01): `arcaeon gate decide --enforce {warn,block}`.

block refuses act, pay and irreversible on anything not VERIFIED (BROKEN, or
COULD NOT LOOK, a missing envelope included), exactly as gate.decide always
has. warn computes the same decision, lets it through (exit 0) and says loudly
that block mode would refuse. The mode comes from --enforce, else
ARCAEON_GATE_MODE, else the signed latest.json's block_after (cache only, no
network), else block: no signed answer means block (fail closed).

Every key is a throwaway seed under tmp_path; the check-in signing key is the
TEST key under tests/fixtures/checkin, patched into the module constant.
Nothing reaches the network: checkin._open raises if anything tries.
"""
from __future__ import annotations

import base64
import copy
import json
import secrets
from datetime import date
from pathlib import Path

import pytest

from arcaeon import __version__, checkin, cli
from arcaeon import verdict as V
from arcaeon.prove import envelope as E
from arcaeon.prove import gate as G
from arcaeon.prove import gate_mode as M
from arcaeon.prove import jcs

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

FIX = Path(__file__).resolve().parent / "fixtures" / "checkin"
TEST_SEED = base64.b64decode((FIX / "TEST_ONLY_checkin_key.b64").read_text().strip())
OTHER_SEED = base64.b64decode((FIX / "TEST_ONLY_checkin_other_key.b64").read_text().strip())

BIND = {"label": "week 3 grades", "audience": "instructor-1", "deal": "d-7f3a",
        "purpose": "grading", "not_after": "7d"}
BODY = b"name,grade\nunit-a,pass\n"
GUARDED = ("act", "pay", "irreversible")
WOULD = "would refuse in block mode"


# --- fixtures ------------------------------------------------------------------------

def _sealed(tmp_path: Path, signed: bool = True):
    f = tmp_path / "in" / "grades.csv"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(BODY)
    key = None
    if signed:
        key = tmp_path / "seal.key"
        key.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"), encoding="ascii")
    env = E.seal(f, key_file=key, **BIND)
    sigs = env["dsseEnvelope"]["signatures"]
    return f, (sigs[0]["keyid"] if sigs else "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")


def _make(tmp_path: Path, verdict: str):
    if verdict == V.COULD_NOT_LOOK:
        return _sealed(tmp_path, signed=False)
    f, did = _sealed(tmp_path)
    if verdict == V.BROKEN:
        f.write_bytes(BODY + b"unit-b,pass\n")
    return f, did


def _loose(tmp_path: Path) -> Path:
    """A handed file with no envelope at all."""
    f = tmp_path / "in" / "loose.csv"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(BODY)
    return f


def _did(seed: bytes) -> str:
    from cryptography.hazmat.primitives import serialization as S
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from arcaeon.prove.vet.receipts import did_key
    pub = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        S.Encoding.Raw, S.PublicFormat.Raw)
    return did_key(pub)


def _doc(block_after, seed=TEST_SEED) -> dict:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    p = {"kind": "arcaeon.latest", "schema": 1, "latest": "99.0.0", "minimum_supported": "0.1.0",
         "block_after": block_after, "notice": None, "issued_at": "2026-10-05T00:00:00Z"}
    sig = ed25519.Ed25519PrivateKey.from_private_bytes(seed).sign(jcs.canonicalize(p))
    return {"payload": p, "signatures": [{"keyid": _did(seed),
                                          "sig": base64.b64encode(sig).decode()}]}


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv(M.ENV, raising=False)
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "ah"))

    def no_network(*a, **k):
        raise AssertionError("the gate path must never touch the network")
    monkeypatch.setattr(checkin, "_open", no_network)


@pytest.fixture
def latest(monkeypatch, tmp_path):
    """Write a cached latest.json answer; check-in on, the TEST key trusted."""
    monkeypatch.delenv("ARCAEON_NO_CHECKIN", raising=False)
    monkeypatch.setattr(checkin, "CHECKIN_KEYS", (_did(TEST_SEED),))

    def write(doc):
        p = tmp_path / "ah" / "checkin.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"signed": {"doc": doc, "fetched_at": "2026-10-05T00:00:00Z",
                                            "source": checkin.DEFAULT_URL}}), encoding="utf-8")
    return write


FUTURE = {"version": "99.1.0", "date": "2099-01-01"}


def _decide(f, did, action, tmp_path, **kw):
    return G.decide(f, action=action, audience="instructor-1", signers=[did], deal="d-7f3a",
                    purpose="grading", record_dir=tmp_path / "rec",
                    ledger=tmp_path / "tape.jsonl", **kw)


# --- block: the existing refusals, unchanged ----------------------------------------

@pytest.mark.parametrize("verdict", [V.BROKEN, V.COULD_NOT_LOOK])
@pytest.mark.parametrize("action", GUARDED)
def test_block_refuses_guarded_actions_on_anything_not_verified(tmp_path, verdict, action):
    f, did = _make(tmp_path, verdict)
    d = _decide(f, did, action, tmp_path, enforce="block")
    assert d.decision == G.REFUSE and not d.allowed
    assert d.exit_code == (1 if verdict == V.BROKEN else 3)
    out = d.to_dict()
    assert out["enforce_mode"] == "block" and out["enforce_source"] == "flag"
    assert out["would_refuse"] is True and out["warning"] is None


@pytest.mark.parametrize("action", GUARDED)
def test_block_no_envelope_at_all_is_could_not_look_and_refused(tmp_path, action):
    f = _loose(tmp_path)
    d = _decide(f, "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", action,
                tmp_path, enforce="block")
    assert d.verdict == V.COULD_NOT_LOOK and d.decision == G.REFUSE and d.exit_code == 3
    assert d.could_not_check["reason_word"] == "missing"


def test_block_read_stays_allowed_on_could_not_look(tmp_path):
    f = _loose(tmp_path)
    d = G.decide(f, action="read", audience="instructor-1", signers=[], enforce="block")
    assert d.decision == G.ALLOW and d.exit_code == 0
    assert d.to_dict()["would_refuse"] is False


def test_block_matches_the_library_default(tmp_path):
    """block is what decide answered before modes existed: same decision, same exit."""
    for verdict in (V.VERIFIED, V.BROKEN, V.COULD_NOT_LOOK):
        sub = tmp_path / verdict.replace(" ", "_")
        sub.mkdir()
        f, did = _make(sub, verdict)
        for action in G.ACTIONS:
            a = G.decide(f, action=action, audience="instructor-1", signers=[did],
                         deal="d-7f3a", purpose="grading", record_dir=sub / "r1",
                         ledger=sub / "t1.jsonl")
            b = G.decide(f, action=action, audience="instructor-1", signers=[did],
                         deal="d-7f3a", purpose="grading", record_dir=sub / "r2",
                         ledger=sub / "t2.jsonl", enforce="block")
            assert (a.decision, a.exit_code) == (b.decision, b.exit_code), (verdict, action)
            assert a.to_dict()["enforce_mode"] == "block"


# --- warn: computed, reported, let through ------------------------------------------

@pytest.mark.parametrize("verdict,would_exit", [(V.BROKEN, 1), (V.COULD_NOT_LOOK, 3)])
@pytest.mark.parametrize("action", GUARDED)
def test_warn_lets_it_through_and_says_block_would_refuse(tmp_path, verdict, would_exit, action):
    f, did = _make(tmp_path, verdict)
    d = _decide(f, did, action, tmp_path, enforce="warn")
    assert d.decision == G.ALLOW and d.allowed and d.exit_code == 0
    out = d.to_dict()
    assert out["enforce_mode"] == "warn" and out["enforce_source"] == "flag"
    assert out["would_refuse"] is True and out["would_exit_code"] == would_exit
    assert WOULD in out["warning"] and WOULD in d.reason
    assert out["verdict"] == verdict                   # the verdict is never softened
    assert d.evidence and Path(d.evidence, "evidence.json").is_file()   # still recorded


def test_warn_no_envelope_lets_it_through_with_the_warning(tmp_path):
    f = _loose(tmp_path)
    d = _decide(f, "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK", "pay",
                tmp_path, enforce="warn")
    assert d.verdict == V.COULD_NOT_LOOK and d.decision == G.ALLOW and d.exit_code == 0
    assert d.to_dict()["would_refuse"] is True


def test_warn_on_an_allow_says_nothing(tmp_path):
    f, did = _make(tmp_path, V.VERIFIED)
    d = _decide(f, did, "pay", tmp_path, enforce="warn")
    out = d.to_dict()
    assert d.decision == G.ALLOW and out["would_refuse"] is False and out["warning"] is None
    assert WOULD not in d.reason


# --- the sources ------------------------------------------------------------------------

def test_default_with_nothing_cached_is_block(monkeypatch):
    monkeypatch.delenv("ARCAEON_NO_CHECKIN", raising=False)
    m = M.resolve()
    assert (m.mode, m.source) == ("block", "default")


def test_default_with_checkin_off_is_block():
    m = M.resolve()                                   # the suite runs with check-in off
    assert (m.mode, m.source) == ("block", "default")


def test_shipped_build_trusts_no_key_so_a_cached_answer_cannot_warn(latest, monkeypatch):
    latest(_doc(FUTURE))
    monkeypatch.setattr(checkin, "CHECKIN_KEYS", ())
    m = M.resolve()
    assert (m.mode, m.source) == ("block", "default")


def test_signed_block_after_in_the_future_is_warn(latest):
    latest(_doc(FUTURE))
    m = M.resolve(today=date(2026, 10, 5))
    assert (m.mode, m.source) == ("warn", "latest.json")


def test_signed_block_after_date_passed_is_block(latest):
    latest(_doc({"version": "99.1.0", "date": "2026-10-01"}))
    m = M.resolve(today=date(2026, 10, 5))
    assert (m.mode, m.source) == ("block", "latest.json")


def test_signed_block_after_on_the_day_is_block(latest):
    latest(_doc({"version": "99.1.0", "date": "2026-10-05"}))
    assert M.resolve(today=date(2026, 10, 5)).mode == "block"


def test_signed_block_after_version_reached_is_block(latest):
    latest(_doc({"version": __version__, "date": "2099-01-01"}))
    m = M.resolve(today=date(2026, 10, 5))
    assert (m.mode, m.source) == ("block", "latest.json")


def test_signed_block_after_only_a_date_in_the_future_is_warn(latest):
    latest(_doc({"version": None, "date": "2099-01-01"}))
    assert M.resolve(today=date(2026, 10, 5)).mode == "warn"


def test_signed_but_no_block_after_is_block(latest):
    latest(_doc(None))
    m = M.resolve(today=date(2026, 10, 5))
    assert (m.mode, m.source) == ("block", "default")


def test_signed_block_after_with_a_bad_date_is_block(latest):
    latest(_doc({"version": None, "date": "next spring"}))
    assert M.resolve(today=date(2026, 10, 5)).mode == "block"


def test_env_warn_and_block(monkeypatch):
    monkeypatch.setenv(M.ENV, "warn")
    assert (M.resolve().mode, M.resolve().source) == ("warn", "env")
    monkeypatch.setenv(M.ENV, "block")
    assert (M.resolve().mode, M.resolve().source) == ("block", "env")


def test_flag_beats_env_beats_latest(latest, monkeypatch):
    latest(_doc({"version": "0.0.1", "date": "2000-01-01"}))            # latest.json: block
    assert M.resolve(today=date(2026, 10, 5)).source == "latest.json"
    monkeypatch.setenv(M.ENV, "warn")
    assert (M.resolve().mode, M.resolve().source) == ("warn", "env")     # env beats latest
    assert (M.resolve("block").mode, M.resolve("block").source) == ("block", "flag")
    monkeypatch.setenv(M.ENV, "block")
    latest(_doc(FUTURE))                                                # latest.json: warn
    assert (M.resolve().mode, M.resolve().source) == ("block", "env")
    assert (M.resolve("warn").mode, M.resolve("warn").source) == ("warn", "flag")


@pytest.mark.parametrize("bad", ["maybe", "WARNING", "off", "0"])
def test_unknown_values_are_an_error(monkeypatch, bad):
    with pytest.raises(ValueError, match="warn or block"):
        M.resolve(bad)
    monkeypatch.setenv(M.ENV, bad)
    with pytest.raises(ValueError, match=M.ENV):
        M.resolve()


# --- a tampered or unsigned latest.json cannot downgrade to warn ----------------------

def test_edited_payload_cannot_downgrade(latest):
    d = _doc({"version": "0.0.1", "date": "2000-01-01"})
    d = copy.deepcopy(d)
    d["payload"]["block_after"] = FUTURE                # edited after signing
    latest(d)
    m = M.resolve(today=date(2026, 10, 5))
    assert (m.mode, m.source) == ("block", "default")


def test_untrusted_signer_cannot_downgrade(latest):
    latest(_doc(FUTURE, seed=OTHER_SEED))
    assert (M.resolve(today=date(2026, 10, 5)).mode, M.resolve().source) == ("block", "default")


def test_unsigned_document_cannot_downgrade(latest):
    d = _doc(FUTURE)
    d["signatures"] = []
    latest(d)
    assert M.resolve(today=date(2026, 10, 5)).mode == "block"


def test_garbage_cache_cannot_downgrade(latest, tmp_path):
    p = tmp_path / "ah" / "checkin.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("{not json", encoding="utf-8")
    assert M.resolve(today=date(2026, 10, 5)).mode == "block"


def test_pypi_fallback_cannot_downgrade(latest, tmp_path):
    p = tmp_path / "ah" / "checkin.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"pypi": {"latest": "99.0.0", "source": checkin.PYPI_URL},
                             "last_attempt": {"signature": "COULD NOT LOOK",
                                              "reason": "arcaeon.io could not be reached"}}),
                 encoding="utf-8")
    assert M.resolve(today=date(2026, 10, 5)).mode == "block"


# --- the command line ---------------------------------------------------------------

def _cli(capsys, f, did, action, *extra):
    code = cli.main(["gate", "decide", "--envelope", str(f), "--audience", "instructor-1",
                     "--signer", did, "--action", action, *extra])
    out = capsys.readouterr()
    return code, out.out, out.err


def test_cli_block_refuses_and_reports_the_mode(tmp_path, capsys):
    f, did = _make(tmp_path, V.BROKEN)
    code, out, _ = _cli(capsys, f, did, "pay", "--enforce", "block", "--json")
    got = json.loads(out)
    assert code == 1 and got["decision"] == "refuse"
    assert (got["enforce_mode"], got["enforce_source"]) == ("block", "flag")


def test_cli_default_is_block(tmp_path, capsys):
    f, did = _make(tmp_path, V.BROKEN)
    code, out, _ = _cli(capsys, f, did, "pay", "--json")
    got = json.loads(out)
    assert code == 1 and (got["enforce_mode"], got["enforce_source"]) == ("block", "default")


def test_cli_warn_exits_0_with_a_loud_line(tmp_path, capsys):
    f, did = _make(tmp_path, V.BROKEN)
    code, out, err = _cli(capsys, f, did, "pay", "--enforce", "warn")
    assert code == 0
    assert WOULD in out and "WARNING" in err and WOULD in err


def test_cli_env_warn_and_flag_beats_it(tmp_path, capsys, monkeypatch):
    f, did = _make(tmp_path, V.COULD_NOT_LOOK)
    monkeypatch.setenv(M.ENV, "warn")
    code, out, _ = _cli(capsys, f, did, "act", "--json")
    got = json.loads(out)
    assert code == 0 and (got["enforce_mode"], got["enforce_source"]) == ("warn", "env")
    code, out, _ = _cli(capsys, f, did, "act", "--json", "--enforce", "block")
    got = json.loads(out)
    assert code == 3 and (got["enforce_mode"], got["enforce_source"]) == ("block", "flag")


def test_cli_latest_json_window_is_warn(tmp_path, capsys, latest):
    latest(_doc(FUTURE))
    f, did = _make(tmp_path, V.BROKEN)
    code, out, _ = _cli(capsys, f, did, "pay", "--json")
    got = json.loads(out)
    assert code == 0 and (got["enforce_mode"], got["enforce_source"]) == ("warn", "latest.json")


def test_cli_unknown_enforce_or_env_is_usage(tmp_path, capsys, monkeypatch):
    f, did = _make(tmp_path, V.VERIFIED)
    code, _, err = _cli(capsys, f, did, "read", "--enforce", "maybe")
    assert code == 2 and "--enforce" in err
    monkeypatch.setenv(M.ENV, "maybe")
    code, _, err = _cli(capsys, f, did, "read")
    assert code == 2 and M.ENV in err
