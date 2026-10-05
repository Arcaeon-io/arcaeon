"""L2-12b: the predicate version says whether checks[] may be there.

A seal with carried check rows writes predicate version 2; a seal without
them writes version 1 and stays byte-identical to before. `verify` reads
versions 1 and 2. Any other version (3, "2", a bool, a float, missing) is
COULD NOT LOOK naming the version: this verifier does not know that
predicate, so it never reads it as if carried rows were absent. A version-1
predicate that carries a checks key contradicts its own version: BROKEN.
`gate decide` follows the envelope's word. Throwaway keys in tmp_path, HOME
pointed at tmp_path; nothing reaches the network."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

import pytest

from arcaeon import verdict as V
from arcaeon.connector import core
from arcaeon.prove import envelope as E
from arcaeon.prove import gate as G

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

AUD = "instructor-1"
BIND = {"label": "week 3 grades", "audience": AUD, "deal": "d-7f3a", "purpose": "grading",
        "not_after": "7d"}
BODY = b"name,grade\nunit-a,pass\n"
SHA = hashlib.sha256(BODY).hexdigest()
NOW = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)
DOC = Path(__file__).resolve().parents[1] / "docs" / "ENVELOPE.md"


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(tmp_path / "home"))


def _key(tmp_path: Path) -> Path:
    k = tmp_path / "seal.key"
    k.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"), encoding="ascii")
    return k


def _file(tmp_path: Path) -> Path:
    f = tmp_path / "in" / "grades.csv"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(BODY)
    return f


def _row(verdict=V.BROKEN) -> dict:
    row = core.relayed_row(core.adapter_for("mockscan"), b"{}", "2026-10-05T12:00:00Z")
    row.update(vendor={"name": "mcp-scan", "adapter_version": "1"}, vendor_id="req-1",
               vendor_word="w", relayed_verdict=verdict, mapping={"rule": "table"},
               subject={"name": "grades.csv", "sha256": SHA})
    return row


def _stmt(env: dict) -> dict:
    return json.loads(base64.b64decode(env["dsseEnvelope"]["payload"]))


def _resign(f: Path, key: Path, mutate) -> str:
    """Re-sign the sidecar after `mutate(predicate)`: a sealer writing by hand."""
    from arcaeon.prove.vet import receipts as R
    env = json.loads(E.envelope_path(f).read_text(encoding="utf-8"))
    stmt = _stmt(env)
    mutate(stmt["predicate"])
    payload = json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    seed = base64.b64decode(key.read_text(encoding="ascii"))
    sig = R._sign_bytes(seed, E.pae(E.PAYLOAD_TYPE, payload))
    env["dsseEnvelope"]["payload"] = base64.b64encode(payload).decode("ascii")
    env["dsseEnvelope"]["signatures"][0]["sig"] = base64.b64encode(sig).decode("ascii")
    E.envelope_path(f).write_text(json.dumps(env, indent=1) + "\n", encoding="utf-8")
    return env["dsseEnvelope"]["signatures"][0]["keyid"]


def _sealed(tmp_path, *, checks=None):
    f, k = _file(tmp_path), _key(tmp_path)
    extra = {} if checks is None else {"checks": checks}
    env = E.seal(f, key_file=k, force=True, **BIND, **extra)
    return f, k, env, env["dsseEnvelope"]["signatures"][0]["keyid"]


def _ex(tmp_path) -> dict:
    return {"deal": "d-7f3a", "purpose": "grading", "ledger": tmp_path / "tape.jsonl",
            "record_dir": tmp_path / "rec"}


# --- seal: which version is written ----------------------------------------------------

def test_known_versions_are_one_and_two():
    assert E.PREDICATE_VERSION == 1
    assert E.PREDICATE_VERSION_CHECKS == 2
    assert E.PREDICATE_VERSIONS == (1, 2)


def test_seal_without_checks_writes_version_1_byte_identical(tmp_path):
    f, k = _file(tmp_path), _key(tmp_path)
    a = E.seal(f, key_file=k, force=True, now=NOW, **BIND)
    first = E.envelope_path(f).read_bytes()
    E.seal(f, key_file=k, force=True, now=NOW, checks=(), **BIND)
    assert E.envelope_path(f).read_bytes() == first
    pred = _stmt(a)["predicate"]
    assert pred["version"] == 1 and "checks" not in pred
    # the exact bytes a pre-checks[] seal wrote: version 1, no checks key
    assert b'"version":1' in base64.b64decode(a["dsseEnvelope"]["payload"])


def test_seal_with_checks_writes_version_2_and_verifies(tmp_path):
    f, _, env, did = _sealed(tmp_path, checks=[_row()])
    pred = _stmt(env)["predicate"]
    assert pred["version"] == 2 and len(pred["checks"]) == 1
    r = E.verify(f, audience=AUD, signers=[did])
    assert r["verdict"] == V.VERIFIED
    assert r["sealed"]["version"] == 2 and r["sealed"]["checks"] == pred["checks"]


def test_version_2_carried_broken_still_vetoes_at_the_gate(tmp_path):
    f, _, _, did = _sealed(tmp_path, checks=[_row(V.BROKEN)])
    d = G.decide(f, action="pay", audience=AUD, signers=[did], **_ex(tmp_path))
    assert d.verdict == V.VERIFIED and d.veto == G.CHECKER_BROKEN and d.exit_code == 1


def test_version_2_without_checks_key_verifies(tmp_path):
    f, k, _, _ = _sealed(tmp_path)
    did = _resign(f, k, lambda p: p.__setitem__("version", 2))
    assert E.verify(f, audience=AUD, signers=[did])["verdict"] == V.VERIFIED


# --- verify: a version this verifier does not know --------------------------------------

UNKNOWN = [3, 0, -1, "2", "1", True, False, 2.0, 1.0, None, [2], {"v": 2}]
UNKNOWN_IDS = ["3", "0", "-1", "str-2", "str-1", "true", "false", "float-2", "float-1",
               "null", "list", "object"]


@pytest.mark.parametrize("version", UNKNOWN, ids=UNKNOWN_IDS)
@pytest.mark.parametrize("with_checks", [True, False], ids=["checks", "no-checks"])
def test_unknown_version_is_could_not_look_naming_it(tmp_path, version, with_checks):
    f, k, _, _ = _sealed(tmp_path, checks=[_row()] if with_checks else None)
    did = _resign(f, k, lambda p: p.__setitem__("version", version))
    r = E.verify(f, audience=AUD, signers=[did])
    assert r["verdict"] == V.COULD_NOT_LOOK, r["reason"]
    assert "version" in r["reason"] and json.dumps(version) in r["reason"]
    assert r["reason_word"] == "unreadable"
    assert r["steps"]["binding"] == V.COULD_NOT_LOOK


@pytest.mark.parametrize("with_checks", [True, False], ids=["checks", "no-checks"])
def test_missing_version_is_could_not_look_naming_it(tmp_path, with_checks):
    f, k, _, _ = _sealed(tmp_path, checks=[_row()] if with_checks else None)
    did = _resign(f, k, lambda p: p.pop("version"))
    r = E.verify(f, audience=AUD, signers=[did])
    assert r["verdict"] == V.COULD_NOT_LOOK, r["reason"]
    assert "no version" in r["reason"] and r["reason_word"] == "missing"


def test_unknown_version_gate_refuses_everything_but_read(tmp_path):
    f, k, _, _ = _sealed(tmp_path, checks=[_row(V.BROKEN)])
    did = _resign(f, k, lambda p: p.__setitem__("version", 3))
    for action in ("act", "pay", "irreversible"):
        d = G.decide(f, action=action, audience=AUD, signers=[did], **_ex(tmp_path))
        assert d.decision == "refuse" and d.verdict == V.COULD_NOT_LOOK
        assert "version 3" in d.reason and d.exit_code == 3
    assert G.decide(f, action="read", audience=AUD, signers=[did]).allowed


def test_changed_bytes_stay_broken_under_an_unknown_version(tmp_path):
    f, k, _, _ = _sealed(tmp_path)
    did = _resign(f, k, lambda p: p.__setitem__("version", 3))
    f.write_bytes(BODY + b"unit-b,fail\n")
    assert E.verify(f, audience=AUD, signers=[did])["verdict"] == V.BROKEN


def test_cli_verify_unknown_version_exits_could_not_look(tmp_path, capsys):
    f, k, _, _ = _sealed(tmp_path, checks=[_row()])
    did = _resign(f, k, lambda p: p.__setitem__("version", 3))
    rc = E.main(["verify", str(f), "--audience", AUD, "--signer", did])
    assert rc == V.EXIT_COULD_NOT_LOOK
    assert "version 3" in capsys.readouterr().err


# --- verify: version 1 carrying a checks key -------------------------------------------

@pytest.mark.parametrize("value", [[], "x", None], ids=["empty", "str", "null"])
def test_version_1_with_any_checks_key_is_broken(tmp_path, value):
    f, k, _, _ = _sealed(tmp_path)
    did = _resign(f, k, lambda p: p.__setitem__("checks", value))
    r = E.verify(f, audience=AUD, signers=[did])
    assert r["verdict"] == V.BROKEN
    assert "version 1" in r["reason"] and "checks" in r["reason"]


def test_version_1_with_carried_rows_is_broken_and_gate_refuses_read(tmp_path):
    f, k, _, _ = _sealed(tmp_path, checks=[_row(V.VERIFIED)])
    did = _resign(f, k, lambda p: p.__setitem__("version", 1))
    r = E.verify(f, audience=AUD, signers=[did])
    assert r["verdict"] == V.BROKEN and r["steps"]["binding"] == V.BROKEN
    for action in ("read", "pay"):
        d = G.decide(f, action=action, audience=AUD, signers=[did], **_ex(tmp_path))
        assert d.decision == "refuse" and d.verdict == V.BROKEN and d.exit_code == 1


# --- docs ------------------------------------------------------------------------------

def test_envelope_doc_has_the_version_table():
    text = DOC.read_text(encoding="utf-8")
    assert "| `version` |" in text
    assert "| 1 |" in text and "| 2 |" in text
    assert "COULD NOT LOOK" in text and "predicate version is still 1" not in text


def test_module_docstring_states_both_versions():
    assert "version 2" in E.__doc__ and "version 1" in E.__doc__
