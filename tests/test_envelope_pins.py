"""`envelope verify --pins DIR`: the pin_ref resolved offline against a local
clone of a pins repo (tips/<chain>/<stamp>/statement.json). VERIFIED only when
the pin's statement digest matches; the pin not there or the folder not
readable is COULD NOT LOOK; the named pin there with another digest is BROKEN.
The fixture pins are synthetic; nothing reaches the network."""
from __future__ import annotations

import base64
import json
import secrets
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import envelope as E
from arcaeon.record.row import digest_json

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

PINS = Path(__file__).parent / "fixtures" / "envelope_pins" / "tips"
CHAIN = "arcaeon-demo"
STAMP = "2026-10-01T1200Z"
#: sha256 of tests/fixtures/envelope_pins/tips/arcaeon-demo/2026-10-01T1200Z/statement.json
PIN1 = "f56121d2abeb803760d7ce2e3f2e727ba076ee137d48433a99738cdad45837b0"
PIN2 = "39021d254b7a84bea9ad751b4fda1610576cacf1c7289bd8f5c0e891b3c36291"
OTHER = "ab" * 32
WIT = f"https://witness.example/tips/{CHAIN}/{STAMP}/statement.json"
BIND = {"label": "week 3 grades", "audience": "instructor-1", "deal": "d-7f3a",
        "purpose": "grading", "not_after": "7d"}


def _sealed(tmp_path: Path, **over):
    f = tmp_path / "grades.csv"
    f.write_bytes(b"name,grade\nunit-a,pass\n")
    k = tmp_path / "seal.key"
    k.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"), encoding="ascii")
    env = E.seal(f, key_file=k, **{**BIND, **over})
    return f, env["dsseEnvelope"]["signatures"][0]["keyid"]


def _v(f, did, **kw):
    return E.verify(f, audience="instructor-1", signers=[did], **kw)


def test_fixture_digests_are_the_statement_bytes():
    import hashlib
    raw = (PINS / CHAIN / STAMP / "statement.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == PIN1


def test_without_pins_nothing_changes(tmp_path):
    f, did = _sealed(tmp_path, pin_ref="sha256:" + PIN1, witness_ref=WIT)
    r = _v(f, did, require_witness=True)
    assert r["verdict"] == V.COULD_NOT_LOOK and r["reason_word"] == "network"
    assert r["steps"]["witness"] == V.COULD_NOT_LOOK


@pytest.mark.parametrize("wit", [WIT, None, "urn:pin:arcaeon-demo:2026-10-01T1200Z"])
def test_pin_found_digest_matches_verified(tmp_path, wit):
    f, did = _sealed(tmp_path, pin_ref="sha256:" + PIN1, witness_ref=wit)
    r = _v(f, did, require_witness=True, pins=PINS)
    assert r["verdict"] == V.VERIFIED, r
    assert r["steps"]["witness"] == V.VERIFIED
    assert r["pin"]["statement_sha256"] == PIN1
    assert r["pin"]["folder"].replace("\\", "/").endswith(f"{CHAIN}/{STAMP}")


@pytest.mark.parametrize("root", [PINS, PINS / CHAIN, PINS / CHAIN / STAMP,
                                  PINS.parent])
def test_pins_may_be_tips_its_chain_or_the_stamp_folder(tmp_path, root):
    f, did = _sealed(tmp_path, pin_ref="sha256:" + PIN1, witness_ref=WIT)
    assert _v(f, did, require_witness=True, pins=root)["verdict"] == V.VERIFIED


def test_raw_bytes_and_json_c14n_pin_ref_forms(tmp_path):
    f, did = _sealed(tmp_path, pin_ref="sha256:raw-bytes:v1:" + PIN2)
    assert _v(f, did, require_witness=True, pins=PINS)["verdict"] == V.VERIFIED
    st = json.loads((PINS / CHAIN / STAMP / "statement.json").read_bytes())
    f, did = _sealed(tmp_path, pin_ref=digest_json(st), force=True)
    r = _v(f, did, require_witness=True, pins=PINS)
    assert r["verdict"] == V.VERIFIED, r


@pytest.mark.parametrize("require", [True, False])
def test_named_pin_with_another_digest_is_broken(tmp_path, require):
    f, did = _sealed(tmp_path, pin_ref="sha256:" + OTHER, witness_ref=WIT)
    r = _v(f, did, require_witness=require, pins=PINS)
    assert r["verdict"] == V.BROKEN, r
    assert r["steps"]["witness"] == V.BROKEN
    assert PIN1 in r["reason"] and OTHER in r["reason"]


def test_digest_not_in_clone_and_no_locator_could_not_look(tmp_path):
    f, did = _sealed(tmp_path, pin_ref="sha256:" + OTHER)
    r = _v(f, did, require_witness=True, pins=PINS)
    assert r["verdict"] == V.COULD_NOT_LOOK and r["reason_word"] == "missing"
    assert r["steps"]["witness"] == V.COULD_NOT_LOOK


def test_named_pin_missing_from_clone_could_not_look(tmp_path):
    wit = f"https://witness.example/tips/{CHAIN}/2026-09-30T0000Z/statement.json"
    f, did = _sealed(tmp_path, pin_ref="sha256:" + PIN1, witness_ref=wit)
    r = _v(f, did, require_witness=True, pins=PINS)
    assert r["verdict"] == V.COULD_NOT_LOOK and r["reason_word"] == "missing"


@pytest.mark.parametrize("kind", ["absent", "file"])
def test_pins_dir_unreadable_could_not_look(tmp_path, kind):
    f, did = _sealed(tmp_path, pin_ref="sha256:" + PIN1, witness_ref=WIT)
    d = tmp_path / "nope"
    if kind == "file":
        d.write_text("x", encoding="ascii")
    r = _v(f, did, require_witness=True, pins=d)
    assert r["verdict"] == V.COULD_NOT_LOOK
    assert r["reason_word"] in ("missing", "unreadable")


def test_witness_ref_only_still_could_not_look_with_pins(tmp_path):
    f, did = _sealed(tmp_path, witness_ref=WIT)
    r = _v(f, did, require_witness=True, pins=PINS)
    assert r["verdict"] == V.COULD_NOT_LOOK and r["steps"]["witness"] == V.COULD_NOT_LOOK


def test_cli_pins_exit_codes(tmp_path, capsys):
    for i, (ref, code) in enumerate((
            (PIN1, V.EXIT_GOOD), (OTHER, V.EXIT_BAD))):
        d = tmp_path / str(i)
        d.mkdir()
        f, did = _sealed(d, pin_ref="sha256:" + ref, witness_ref=WIT)
        rc = cli.main(["envelope", "verify", str(f), "--audience", "instructor-1",
                       "--signer", did, "--require-witness", "--pins", str(PINS)])
        assert rc == code
    rc = cli.main(["envelope", "verify", str(f), "--audience", "instructor-1",
                   "--signer", did, "--require-witness", "--pins", str(tmp_path / "x")])
    assert rc == V.EXIT_COULD_NOT_LOOK
    capsys.readouterr()
