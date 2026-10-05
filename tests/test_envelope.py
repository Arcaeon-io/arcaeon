"""The labeled-exchange envelope (docs/ENVELOPE.md): seal a file for one
exchange, verify before acting. Every key here is a throwaway seed written
to tmp_path; nothing reaches the network."""
from __future__ import annotations

import base64
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import envelope as E

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

BIND = {"label": "week 3 grades", "audience": "instructor-1", "deal": "d-7f3a",
        "purpose": "grading", "not_after": "7d"}


def _key(tmp_path: Path, name: str = "seal.key") -> Path:
    k = tmp_path / name
    k.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"), encoding="ascii")
    return k


def _sealed(tmp_path: Path, **over):
    f = tmp_path / "grades.csv"
    f.write_bytes(b"name,grade\nunit-a,pass\n")
    env = E.seal(f, key_file=_key(tmp_path), **{**BIND, **over})
    return f, env["dsseEnvelope"]["signatures"][0]["keyid"]


def _statement(env_path: Path) -> dict:
    env = json.loads(env_path.read_text(encoding="utf-8"))
    return json.loads(base64.b64decode(env["dsseEnvelope"]["payload"]))


def _ok(f, did, **kw):
    return E.verify(f, audience=kw.pop("audience", "instructor-1"), signers=[did], **kw)


# --- the round trip ---------------------------------------------------------------

def test_round_trip_verified(tmp_path):
    f, did = _sealed(tmp_path, pin_ref="sha256:" + "ab" * 32,
                     witness_ref="https://witness.example/pins/1", chain="ledger-1",
                     flags=["reviewed"])
    side = tmp_path / "grades.csv.envelope.json"
    assert side.is_file()
    stmt = _statement(side)
    assert stmt["_type"] == E.STATEMENT_TYPE and stmt["predicateType"] == E.PREDICATE_TYPE
    assert stmt["subject"][0]["digest"]["sha256"] == __import__("hashlib").sha256(
        f.read_bytes()).hexdigest()
    p = stmt["predicate"]
    assert p["binding"]["audience"] == "instructor-1" and p["sealed_by"]["key"] == did
    r = _ok(f, did, deal="d-7f3a", purpose="grading")
    assert r["verdict"] == V.VERIFIED, r
    assert r["steps"] == {"envelope": V.VERIFIED, "signature": V.VERIFIED, "file": V.VERIFIED,
                          "binding": V.VERIFIED, "witness": V.COULD_NOT_LOOK}
    # the refs are recorded and named as not resolved, never VERIFIED
    assert any("not resolved" in n for n in r["not_checked"])


def test_witness_step_not_claimed_without_refs_and_required_witness_cannot_look(tmp_path):
    f, did = _sealed(tmp_path)
    r = _ok(f, did)
    assert r["verdict"] == V.VERIFIED and r["steps"]["witness"] == E.NOT_CLAIMED
    r = _ok(f, did, require_witness=True)
    assert r["verdict"] == V.COULD_NOT_LOOK and r["reason_word"] == "network"


def test_dsse_pae_is_the_spec_encoding():
    assert E.pae("t", b"ab") == b"DSSEv1 1 t 2 ab"


# --- BROKEN -----------------------------------------------------------------------

def test_tampered_file_is_broken(tmp_path):
    f, did = _sealed(tmp_path)
    f.write_bytes(b"name,grade\nunit-a,FAIL\n")
    r = _ok(f, did)
    assert r["verdict"] == V.BROKEN and r["steps"]["file"] == V.BROKEN
    assert "bytes changed" in r["reason"]


@pytest.mark.parametrize("edit", [
    lambda p: p["predicate"].update(label="week 4 grades"),
    lambda p: p["predicate"]["binding"].update(audience="someone-else"),
    lambda p: p["predicate"]["binding"].update(not_after="2099-01-01T00:00:00Z"),
    lambda p: p["subject"][0]["digest"].update(sha256="0" * 64),
])
def test_tampered_sidecar_fields_are_broken(tmp_path, edit):
    f, did = _sealed(tmp_path)
    side = E.envelope_path(f)
    env = json.loads(side.read_text(encoding="utf-8"))
    stmt = json.loads(base64.b64decode(env["dsseEnvelope"]["payload"]))
    edit(stmt)
    env["dsseEnvelope"]["payload"] = base64.b64encode(
        json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode()).decode()
    side.write_text(json.dumps(env), encoding="utf-8")
    r = _ok(f, did)
    assert r["verdict"] == V.BROKEN and r["steps"]["signature"] == V.BROKEN, r


def test_field_added_outside_the_signature_is_broken(tmp_path):
    f, did = _sealed(tmp_path)
    side = E.envelope_path(f)
    env = json.loads(side.read_text(encoding="utf-8"))
    env["verdict"] = "VERIFIED"
    side.write_text(json.dumps(env), encoding="utf-8")
    r = _ok(f, did)
    assert r["verdict"] == V.BROKEN and r["steps"]["envelope"] == V.BROKEN


def test_resealed_by_another_key_is_broken_against_the_named_signer(tmp_path):
    f, did = _sealed(tmp_path)
    E.seal(f, key_file=_key(tmp_path, "other.key"), force=True, **BIND)
    r = _ok(f, did)
    assert r["verdict"] == V.BROKEN and "not by the signer you named" in r["reason"]


def test_wrong_audience_is_broken(tmp_path):
    f, did = _sealed(tmp_path)
    r = _ok(f, did, audience="instructor-2")
    assert r["verdict"] == V.BROKEN and r["steps"]["binding"] == V.BROKEN
    assert "audience" in r["reason"]


@pytest.mark.parametrize("field,value", [("deal", "d-other"), ("purpose", "payroll")])
def test_wrong_deal_or_purpose_is_broken(tmp_path, field, value):
    f, did = _sealed(tmp_path)
    r = _ok(f, did, **{field: value})
    assert r["verdict"] == V.BROKEN and field in r["reason"]


def test_expired_not_after_is_broken(tmp_path):
    f, did = _sealed(tmp_path, not_after="1h")
    later = datetime.now(timezone.utc) + timedelta(hours=2)
    r = _ok(f, did, now=later)
    assert r["verdict"] == V.BROKEN and "expired" in r["reason"]


def test_unbound_statement_from_another_sealer_is_broken(tmp_path):
    """A validly signed statement with no binding (made by some other tool
    with the same key) is refused: an unbound envelope can be replayed."""
    from arcaeon.prove.vet import receipts as R
    f = tmp_path / "x.bin"
    f.write_bytes(b"x")
    seed = secrets.token_bytes(32)
    did = R.did_key(R.public_key_from_seed(seed))
    stmt = E.build_statement(f, key_id=did, **BIND)
    del stmt["predicate"]["binding"]["deal"]
    payload = json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode()
    sig = R._sign_bytes(seed, E.pae(E.PAYLOAD_TYPE, payload))
    E.envelope_path(f).write_text(json.dumps({"mediaType": E.MEDIA_TYPE, "dsseEnvelope": {
        "payloadType": E.PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": did, "sig": base64.b64encode(sig).decode()}]}}),
        encoding="utf-8")
    r = E.verify(f, audience="instructor-1", signers=[did])
    assert r["verdict"] == V.BROKEN and "unbound" in r["reason"]


# --- seal refuses -----------------------------------------------------------------

@pytest.mark.parametrize("missing", ["label", "audience", "deal", "purpose", "not_after"])
def test_missing_binding_field_refused_at_seal(tmp_path, missing):
    f = tmp_path / "a.txt"
    f.write_text("a", encoding="utf-8")
    with pytest.raises(E.SealError, match="unbound|missing"):
        E.seal(f, key_file=_key(tmp_path), **{**BIND, missing: None})
    assert not E.envelope_path(f).exists()


def test_cli_seal_refuses_without_binding_and_writes_nothing(tmp_path, capsys):
    f = tmp_path / "a.txt"
    f.write_text("a", encoding="utf-8")
    rc = cli.main(["envelope", "seal", str(f), "--label", "x", "--audience", "r"])
    assert rc == V.EXIT_USAGE
    err = capsys.readouterr().err
    assert "--deal" in err and "--purpose" in err and "--not-after" in err
    assert not E.envelope_path(f).exists()


@pytest.mark.parametrize("over,match", [
    ({"not_after": "2001-01-01T00:00:00Z"}, "not after now"),
    ({"not_after": "2030-01-01T00:00:00"}, "zone"),
    ({"pin_ref": "abc"}, "pin-ref"),
    ({"witness_ref": "http://plain"}, "witness-ref"),
    ({"flags": ["Not Ok"]}, "flag"),
    ({"audience": "two\nlines"}, "one line"),
])
def test_seal_refuses_bad_shapes(tmp_path, over, match):
    f = tmp_path / "a.txt"
    f.write_text("a", encoding="utf-8")
    with pytest.raises(E.SealError, match=match):
        E.seal(f, key_file=_key(tmp_path), **{**BIND, **over})
    assert not E.envelope_path(f).exists()


def test_seal_will_not_overwrite_without_force(tmp_path):
    f, _ = _sealed(tmp_path)
    with pytest.raises(E.SealError, match="already exists"):
        E.seal(f, key_file=_key(tmp_path, "k2"), **BIND)


# --- COULD NOT LOOK ---------------------------------------------------------------

def test_missing_sidecar_could_not_look(tmp_path, capsys):
    f = tmp_path / "a.txt"
    f.write_text("a", encoding="utf-8")
    rc = cli.main(["envelope", "verify", str(f), "--audience", "r"])
    assert rc == V.EXIT_COULD_NOT_LOOK
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == V.COULD_NOT_LOOK and out["reason_word"] == "missing"


@pytest.mark.parametrize("garbage", [
    b"\xff\xfe not text", b"{not json", b"[]", b'{"a": 1, "a": 2}', b"[" * 100_000,
    b'{"mediaType": "application/vnd.arcaeon.envelope.v1+json"}',
    b'{"mediaType": "application/vnd.arcaeon.envelope.v1+json", "dsseEnvelope": '
    b'{"payloadType": "application/vnd.in-toto+json", "payload": "!!", "signatures": []}}',
], ids=["binary", "not-json", "list", "duplicate-key", "nesting-bomb", "no-dsse", "bad-base64"])
def test_garbage_sidecar_could_not_look_no_traceback(tmp_path, capsys, garbage):
    f = tmp_path / "a.txt"
    f.write_text("a", encoding="utf-8")
    E.envelope_path(f).write_bytes(garbage)
    rc = cli.main(["envelope", "verify", str(f), "--audience", "r", "--signer", "did:key:zX"])
    assert rc == V.EXIT_COULD_NOT_LOOK
    cap = capsys.readouterr()
    assert "Traceback" not in cap.out + cap.err
    out = json.loads(cap.out)
    assert out["verdict"] == V.COULD_NOT_LOOK and out["reason_word"] == "unreadable"


def test_unsigned_envelope_could_not_look(tmp_path, capsys):
    f = tmp_path / "a.txt"
    f.write_text("a", encoding="utf-8")
    rc = cli.main(["envelope", "seal", str(f), "--label", "x", "--audience", "r", "--deal",
                   "d-1", "--purpose", "p", "--not-after", "1d"])
    assert rc == 0 and "UNSIGNED" in capsys.readouterr().err
    r = E.verify(f, audience="r")
    assert r["verdict"] == V.COULD_NOT_LOOK and r["steps"]["signature"] == V.COULD_NOT_LOOK
    assert r["steps"]["file"] == V.VERIFIED and "UNSIGNED" in r["reason"]
    f.write_text("b", encoding="utf-8")          # a changed file is still BROKEN, signed or not
    assert E.verify(f, audience="r")["verdict"] == V.BROKEN


def test_no_signer_or_no_audience_could_not_look(tmp_path):
    f, did = _sealed(tmp_path)
    r = E.verify(f, audience="instructor-1")
    assert r["verdict"] == V.COULD_NOT_LOOK and r["reason_word"] == "bounded"
    assert did in r["reason"]
    r = E.verify(f, signers=[did])
    assert r["verdict"] == V.COULD_NOT_LOOK and r["steps"]["binding"] == V.COULD_NOT_LOOK


def test_missing_file_with_sidecar_could_not_look(tmp_path):
    f, did = _sealed(tmp_path)
    f.unlink()
    r = _ok(f, did)
    assert r["verdict"] == V.COULD_NOT_LOOK and r["reason_word"] == "missing"


# --- frozen-spec amendments ---------------------------------------------------------

def _write_signed(f: Path, payload: bytes, seeds) -> list[str]:
    """Write a sidecar for `f` carrying `payload` signed by each seed in turn."""
    from arcaeon.prove.vet import receipts as R
    sigs, dids = [], []
    for seed in seeds:
        did = R.did_key(R.public_key_from_seed(seed))
        sig = R._sign_bytes(seed, E.pae(E.PAYLOAD_TYPE, payload))
        sigs.append({"keyid": did, "sig": base64.b64encode(sig).decode()})
        dids.append(did)
    E.envelope_path(f).write_text(json.dumps({"mediaType": E.MEDIA_TYPE, "dsseEnvelope": {
        "payloadType": E.PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(),
        "signatures": sigs}}), encoding="utf-8")
    return dids


@pytest.mark.parametrize("original,doubled", [
    ('"label":"week 3 grades"', '"label":"week 3 grades","label":"week 4 grades"'),
    ('"audience":"instructor-1"', '"audience":"someone-else","audience":"instructor-1"'),
    ('"predicateType":', '"predicateType":"https://example.invalid/other","predicateType":'),
], ids=["label", "binding-audience", "predicateType"])
def test_duplicate_key_inside_signed_payload_could_not_look(tmp_path, original, doubled):
    """Amendment (a): a duplicate key inside the payload is unreadable, even
    when the signature over those exact bytes is valid. Under last-key-wins
    two parsers would read two different labels."""
    f = tmp_path / "grades.csv"
    f.write_bytes(b"name,grade\nunit-a,pass\n")
    seed = secrets.token_bytes(32)
    from arcaeon.prove.vet import receipts as R
    did = R.did_key(R.public_key_from_seed(seed))
    stmt = E.build_statement(f, key_id=did, **BIND)
    text = json.dumps(stmt, sort_keys=True, separators=(",", ":"))
    assert text.count(original) == 1
    payload = text.replace(original, doubled).encode("utf-8")
    _write_signed(f, payload, [seed])
    r = E.verify(f, audience="instructor-1", signers=[did])
    assert r["steps"]["signature"] == V.VERIFIED, r     # only the duplicate is wrong
    assert r["verdict"] == V.COULD_NOT_LOOK and r["reason_word"] == "unreadable", r
    assert r["steps"]["envelope"] == V.COULD_NOT_LOOK
    assert "repeats a key" in r["reason"], r["reason"]


@pytest.mark.parametrize("given", [
    "instruсtor-1",          # Cyrillic es in place of Latin c (homoglyph)
    "Instructor-1",               # case
    "INSTRUCTOR-1",
    "instructor-1 ",              # trailing space
    " instructor-1",              # leading space
    "instructor‑1",          # non-breaking hyphen
], ids=["homoglyph", "case", "upper", "trailing-space", "leading-space", "nb-hyphen"])
def test_binding_audience_compares_exact_bytes(tmp_path, given):
    """Amendment (b): no Unicode normalization, no case folding, no trimming."""
    f, did = _sealed(tmp_path)
    r = _ok(f, did, audience=given)
    assert r["verdict"] == V.BROKEN and r["steps"]["binding"] == V.BROKEN, r
    assert r["reason"].startswith("audience: sealed for"), r["reason"]


def test_binding_homoglyph_sealed_side_is_broken_for_the_latin_receiver(tmp_path):
    f, did = _sealed(tmp_path, audience="instructor-1".replace("o", "о"))  # Cyrillic o
    assert _ok(f, did, audience="instructor-1")["verdict"] == V.BROKEN
    assert _ok(f, did, audience="instructor-1".replace("o", "о"))["verdict"] == V.VERIFIED


def test_binding_unicode_normal_forms_are_not_equal(tmp_path):
    nfc, nfd = "café-desk", "café-desk"
    f, did = _sealed(tmp_path, audience=nfc)
    r = _ok(f, did, audience=nfd)
    assert r["verdict"] == V.BROKEN and "audience" in r["reason"]
    assert _ok(f, did, audience=nfc)["verdict"] == V.VERIFIED


def test_seal_keeps_binding_text_byte_for_byte(tmp_path):
    f, did = _sealed(tmp_path, audience="instructor-1 ")
    b = _statement(E.envelope_path(f))["predicate"]["binding"]
    assert b["audience"] == "instructor-1 "
    assert _ok(f, did, audience="instructor-1")["verdict"] == V.BROKEN
    assert _ok(f, did, audience="instructor-1 ")["verdict"] == V.VERIFIED


@pytest.mark.parametrize("field,given", [
    ("deal", "D-7F3A"), ("deal", "d-7f3a "), ("deal", "d-7f3а"),   # Cyrillic a
    ("purpose", "Grading"), ("purpose", " grading"), ("purpose", "grаding"),
])
def test_binding_deal_and_purpose_compare_exact_bytes(tmp_path, field, given):
    f, did = _sealed(tmp_path)
    r = _ok(f, did, **{field: given})
    assert r["verdict"] == V.BROKEN and r["steps"]["binding"] == V.BROKEN, r
    assert f"{field}: sealed for" in r["reason"]


@pytest.mark.parametrize("bad_first", [False, True], ids=["good-then-bad", "bad-then-good"])
@pytest.mark.parametrize("kind", ["other-payload", "flipped-sig", "malformed-keyid",
                                  "not-an-object"])
def test_any_signature_that_fails_is_broken_even_beside_a_good_one(tmp_path, kind, bad_first):
    """Amendment (c): several signature entries; one fails, one is from the
    named signer and verifies. BROKEN: a failing entry is tamper evidence."""
    from arcaeon.prove.vet import receipts as R
    f = tmp_path / "grades.csv"
    f.write_bytes(b"name,grade\nunit-a,pass\n")
    good_seed, other_seed = secrets.token_bytes(32), secrets.token_bytes(32)
    good = R.did_key(R.public_key_from_seed(good_seed))
    other = R.did_key(R.public_key_from_seed(other_seed))
    stmt = E.build_statement(f, key_id=good, **BIND)
    payload = json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    _write_signed(f, payload, [good_seed])
    assert E.verify(f, audience="instructor-1", signers=[good])["verdict"] == V.VERIFIED
    if kind == "other-payload":
        bad = {"keyid": other, "sig": base64.b64encode(R._sign_bytes(
            other_seed, E.pae(E.PAYLOAD_TYPE, payload + b" "))).decode()}
    elif kind == "flipped-sig":
        raw = bytearray(R._sign_bytes(other_seed, E.pae(E.PAYLOAD_TYPE, payload)))
        raw[0] ^= 1
        bad = {"keyid": other, "sig": base64.b64encode(bytes(raw)).decode()}
    elif kind == "malformed-keyid":
        bad = {"keyid": "did:key:zNOTAKEY", "sig": base64.b64encode(b"x" * 64).decode()}
    else:
        bad = "VERIFIED"
    side = E.envelope_path(f)
    env = json.loads(side.read_text(encoding="utf-8"))
    sigs = env["dsseEnvelope"]["signatures"]
    env["dsseEnvelope"]["signatures"] = [bad] + sigs if bad_first else sigs + [bad]
    side.write_text(json.dumps(env), encoding="utf-8")
    r = E.verify(f, audience="instructor-1", signers=[good])
    assert r["verdict"] == V.BROKEN and r["steps"]["signature"] == V.BROKEN, r
    assert any(m.startswith(f"signature {0 if bad_first else 1}") for m in r["findings"]), r


def test_two_good_signatures_from_named_signers_verify(tmp_path):
    from arcaeon.prove.vet import receipts as R
    f = tmp_path / "grades.csv"
    f.write_bytes(b"name,grade\nunit-a,pass\n")
    s1, s2 = secrets.token_bytes(32), secrets.token_bytes(32)
    d1 = R.did_key(R.public_key_from_seed(s1))
    stmt = E.build_statement(f, key_id=d1, **BIND)
    payload = json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    dids = _write_signed(f, payload, [s1, s2])
    r = E.verify(f, audience="instructor-1", signers=dids)
    assert r["verdict"] == V.VERIFIED, r


def test_not_after_is_judged_by_the_receivers_clock(tmp_path):
    """Amendment (d), a stated limit: a receiver whose clock is behind accepts
    an envelope that has expired by the true time."""
    f, did = _sealed(tmp_path, not_after="1h")
    true_now = datetime.now(timezone.utc) + timedelta(hours=2)
    assert _ok(f, did, now=true_now)["verdict"] == V.BROKEN
    slow_clock = true_now - timedelta(hours=3)
    assert _ok(f, did, now=slow_clock)["verdict"] == V.VERIFIED
    assert "receiver's clock" in E.DOES_NOT_PROVE


def test_spec_names_the_amendments():
    doc = (Path(__file__).resolve().parents[1] / "docs" / "ENVELOPE.md").read_text(
        encoding="utf-8")
    assert "exact bytes" in doc
    assert "never into VERIFIED" in doc
    assert "receiver's clock" in doc
    assert "duplicate key inside the payload" in doc
    assert E.PREDICATE_TYPE == "https://arcaeon.io/labeled-exchange/v1"


# --- the CLI end to end -------------------------------------------------------------

def test_cli_round_trip_and_exit_codes(tmp_path, capsys):
    f = tmp_path / "a.txt"
    f.write_text("hello", encoding="utf-8")
    k = _key(tmp_path)
    assert cli.main(["envelope", "seal", str(f), "--label", "greeting", "--audience", "r",
                     "--deal", "d-1", "--purpose", "p", "--not-after", "1d",
                     "--key", str(k)]) == 0
    did = json.loads(capsys.readouterr().out)["signer"]
    assert did.startswith("did:key:z6Mk")
    assert cli.main(["envelope", "verify", str(f), "--audience", "r", "--signer", did]) == 0
    cap = capsys.readouterr()
    assert json.loads(cap.out)["verdict"] == V.VERIFIED and cap.err.startswith("VERIFIED: ")
    assert cli.main(["envelope", "verify", str(f), "--audience", "x", "--signer", did]) == 1
    assert capsys.readouterr().err.startswith("BROKEN: ")
    assert cli.main(["envelope", "frob"]) == V.EXIT_USAGE
    assert cli.main(["envelope", "verify", str(f), "--nope"]) == V.EXIT_USAGE


# --- the file sha256 in the report (D054 gap: the OCSF export reads it) -------------

def _sha(p: Path) -> str:
    return __import__("hashlib").sha256(p.read_bytes()).hexdigest()


def test_verify_json_carries_the_file_sha256_on_every_word(tmp_path, capsys):
    f, did = _sealed(tmp_path)
    assert cli.main(["envelope", "verify", str(f), "--audience", "instructor-1",
                     "--signer", did]) == 0
    assert json.loads(capsys.readouterr().out)["file_sha256"] == _sha(f)
    r = E.verify(f, audience="instructor-1")                    # COULD NOT LOOK, no --signer
    assert r["verdict"] == V.COULD_NOT_LOOK and r["file_sha256"] == _sha(f)
    f.write_bytes(b"name,grade\nunit-a,FAIL\n")                 # BROKEN: the bytes handed now
    r = _ok(f, did)
    assert r["verdict"] == V.BROKEN and r["file_sha256"] == _sha(f)
    side = tmp_path / "grades.csv.envelope.json"
    side.unlink()                                                # COULD NOT LOOK, no sidecar
    r = _ok(f, did)
    assert r["verdict"] == V.COULD_NOT_LOOK and r["file_sha256"] == _sha(f)


def test_verify_json_file_sha256_is_null_when_the_file_cannot_be_read(tmp_path):
    f, did = _sealed(tmp_path)
    f.unlink()
    r = _ok(f, did)
    assert r["verdict"] == V.COULD_NOT_LOOK
    assert "file_sha256" in r and r["file_sha256"] is None
