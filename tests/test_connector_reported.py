# SPDX-License-Identifier: MIT
"""L2-07: the generic "reported by sender" adapter. Any checker with no adapter of
its own: the sender hands a small documented JSON row and gets a relayed
check.verdict row back, always unsigned, always reported_by_sender. Fixtures are
synthetic: no real vendor, request, key or signature. No network."""
from __future__ import annotations

import base64
import hashlib
import inspect
import json
from pathlib import Path

import pytest

from arcaeon.connector import ROW_KIND, VendorAdapter, adapter_for, import_verdict, recheck
from arcaeon.connector import reported as R
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "reported"
ONE = (FIX / "one_row.json").read_bytes()
ROWS = (FIX / "rows.json").read_bytes()
SPOOF = (FIX / "spoof_opa.json").read_bytes()
SIGNED = (FIX / "claims_signed.json").read_bytes()
AT = "2026-10-05T12:00:00Z"
INPUT = b"synthetic input bytes for the reported adapter\n"
INPUT_SHA = hashlib.sha256(INPUT).hexdigest()
H = "b436d12b75064780d55b2407edaca0e04422496b269b5b028cd9834651afc119"


def _ing(raw, **kw):
    return R.ingest(raw, received_at=AT, **kw)


def _one(**fields):
    doc = {"vendor": "acme-scan", "verdict": "pass", "input_sha256": H}
    doc.update(fields)
    doc = {k: v for k, v in doc.items() if v is not None}
    rows = _ing(json.dumps(doc).encode())
    assert len(rows) == 1
    return rows[0]


def _sealed(r):
    assert r["signed_by_vendor"] is False
    assert r["standing"] == "reported_by_sender"
    assert r["attestation"]["status"] == "NONE" and r["attestation"]["checked_by_us"] is False
    assert r["vendor"] == {"name": "reported", "adapter_version": "1"}
    assert r["kind"] == ROW_KIND and r["relayed"] is True and r["checked_by_us"] is False
    assert "verdict" not in r


# --- the adapter --------------------------------------------------------------------

def test_adapter_is_on_the_one_base_and_registered():
    assert isinstance(R.REPORTED, VendorAdapter) and R.REPORTED.one_row_per_payload is False
    assert adapter_for("reported") is R.REPORTED
    assert R.STANDING == "reported_by_sender"


def test_ingest_takes_no_argument_that_can_change_the_standing():
    params = set(inspect.signature(R.ingest).parameters)
    assert params == {"raw", "received_at"}


# --- the row ------------------------------------------------------------------------

def test_one_row_has_the_documented_fields():
    rows = _ing(ONE)
    assert len(rows) == 1
    r = rows[0]
    _sealed(r)
    assert r["relayed_verdict"] == VERIFIED and r["vendor_word"] == "VERIFIED"
    assert r["mapping"] == {"rule": "table"}
    assert r["input_sha256"] == H
    assert r["vendor_id"] == "req-0001"
    assert r["at"] == "2026-10-05T10:00:00Z" and r["received_at"] == AT
    assert r["subject"] == {"name": "reported:input", "sha256": H}
    rep = r["reported"]
    assert rep["vendor"] == "acme-scan" and rep["detail"] == "no findings"
    assert rep["input_source"] == "claimed_sha256" and rep["row_index"] == 0
    assert r["vendor_payload_digest"].startswith("sha256:raw-bytes:v1:")
    assert r["vendor_payload_bytes"] == len(ONE)
    assert "could_not_look" not in r


def test_a_list_gives_one_row_per_entry_in_order():
    rows = _ing(ROWS)
    got = [(r["reported"]["row_index"], r["vendor_word"], r["relayed_verdict"]) for r in rows]
    assert got == [
        (0, "VERIFIED", VERIFIED),
        (1, "fail", BROKEN),
        (2, "pass", VERIFIED),
        (3, "pass", BROKEN),
        (4, "looks fine", COULD_NOT_LOOK),
        (5, "COULD NOT LOOK", COULD_NOT_LOOK),
    ]
    for r in rows:
        _sealed(r)


# --- mapping ------------------------------------------------------------------------

@pytest.mark.parametrize("word,ours", [
    ("VERIFIED", VERIFIED), ("verified", VERIFIED), ("  Verified ", VERIFIED),
    ("BROKEN", BROKEN), ("broken", BROKEN),
    ("COULD NOT LOOK", COULD_NOT_LOOK), ("could_not_look", COULD_NOT_LOOK),
])
def test_our_three_words_map_to_themselves(word, ours):
    r = _one(verdict=word)
    assert r["relayed_verdict"] == ours and r["mapping"] == {"rule": "table"}
    assert r["vendor_word"] == word


@pytest.mark.parametrize("word,ours", [
    ("pass", VERIFIED), ("PASS", VERIFIED), ("passed", VERIFIED),
    ("fail", BROKEN), ("FAIL", BROKEN), ("failed", BROKEN),
])
def test_documented_aliases(word, ours):
    r = _one(verdict=word)
    assert r["relayed_verdict"] == ours and r["mapping"] == {"rule": "table"}
    assert r["vendor_word"] == word


def test_the_table_is_exactly_the_documented_one():
    assert R.TABLE == {
        "verified": VERIFIED, "pass": VERIFIED, "passed": VERIFIED,
        "broken": BROKEN, "fail": BROKEN, "failed": BROKEN,
        "could not look": COULD_NOT_LOOK, "could_not_look": COULD_NOT_LOOK,
    }


@pytest.mark.parametrize("word", ["ok", "allow", "true", "clean", "safe", "VERIFIED!",
                                  "verifiedd", "", "   "])
def test_an_unknown_word_is_could_not_look(word):
    r = _one(verdict=word)
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    assert r["mapping"] == {"rule": "unknown_word"}
    assert r["vendor_word"] == word
    assert r["could_not_look"]["reason_word"] == "name_not_found"


@pytest.mark.parametrize("word", [True, 1, None, ["pass"], {"w": "pass"}])
def test_a_verdict_that_is_not_a_string_is_could_not_look(word):
    doc = {"vendor": "acme-scan", "input_sha256": H}
    if word is not None:
        doc["verdict"] = word
    r = _ing(json.dumps(doc).encode())[0]
    assert r["relayed_verdict"] == COULD_NOT_LOOK and r["vendor_word"] is None
    _sealed(r)


# --- input bytes and digests --------------------------------------------------------

def test_input_bytes_are_digested_by_us():
    r = _one(input_sha256=None, input_b64=base64.b64encode(INPUT).decode())
    assert r["input_sha256"] == INPUT_SHA
    assert r["subject"]["sha256"] == INPUT_SHA
    assert r["reported"]["input_source"] == "bytes"
    assert r["reported"]["input_bytes"] == len(INPUT)
    assert r["relayed_verdict"] == VERIFIED


def test_bytes_and_a_matching_claim_agree():
    r = _one(input_sha256=INPUT_SHA.upper(), input_b64=base64.b64encode(INPUT).decode())
    assert r["relayed_verdict"] == VERIFIED and r["input_sha256"] == INPUT_SHA
    assert r["reported"]["input_source"] == "bytes_and_claimed_sha256"


@pytest.mark.parametrize("word", ["pass", "fail", "looks fine", "COULD NOT LOOK"])
def test_claimed_digest_that_does_not_match_the_bytes_is_broken(word):
    r = _one(verdict=word, input_sha256=H, input_b64=base64.b64encode(INPUT).decode())
    assert r["relayed_verdict"] == BROKEN
    assert r["reported"]["reason"] == "claimed digest does not match the bytes"
    assert r["mapping"] == {"rule": "digest_mismatch"}
    assert r["vendor_word"] == word
    assert r["input_sha256"] == INPUT_SHA and r["reported"]["claimed_input_sha256"] == H
    assert "could_not_look" not in r
    _sealed(r)


def test_no_input_at_all_is_could_not_look():
    r = _one(input_sha256=None)
    assert r["relayed_verdict"] == COULD_NOT_LOOK and r["input_sha256"] is None
    assert r["could_not_look"]["reason_word"] == "missing"


@pytest.mark.parametrize("bad", ["abc", "g" * 64, "a" * 63, "sha256:" + "a" * 64, 5, None])
def test_a_bad_claimed_digest_is_could_not_look(bad):
    doc = {"vendor": "acme-scan", "verdict": "pass", "input_sha256": bad}
    r = _ing(json.dumps(doc).encode())[0]
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    _sealed(r)


@pytest.mark.parametrize("bad", ["not base64!!", "QUJD\n", 7, ""])
def test_bad_input_bytes_are_could_not_look(bad):
    r = _one(input_sha256=None, input_b64=bad)
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    assert r["could_not_look"]["reason_word"] in ("unreadable", "empty")


# --- the vendor name ----------------------------------------------------------------

def test_a_row_claiming_vendor_opa_stays_generic():
    rows = _ing(SPOOF)
    assert len(rows) == 1
    r = rows[0]
    _sealed(r)
    assert r["reported"]["vendor"] == "opa"
    assert "decision" not in r
    # "allowed" is an OPA adapter word, not one of ours: generic table, not OPA's
    assert r["relayed_verdict"] == COULD_NOT_LOOK and r["mapping"] == {"rule": "unknown_word"}
    assert recheck(r, SPOOF)["verdict"] == COULD_NOT_LOOK


@pytest.mark.parametrize("name", ["opa", "mcp-scan", "mockscan", "cedar", "reported"])
def test_no_vendor_name_selects_another_adapter(name):
    r = _one(vendor=name, verdict="pass")
    _sealed(r)
    assert r["reported"]["vendor"] == name and r["relayed_verdict"] == VERIFIED


def test_vendor_name_is_length_bounded():
    r = _one(vendor="v" * (R.MAX_VENDOR_CHARS + 1))
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    assert r["could_not_look"]["reason_word"] == "bounded"
    assert r["reported"]["vendor"] is None
    ok = _one(vendor="v" * R.MAX_VENDOR_CHARS)
    assert ok["relayed_verdict"] == VERIFIED


@pytest.mark.parametrize("bad,why", [(None, "missing"), ("", "missing"), ("   ", "missing"),
                                     (5, "unreadable"), (["opa"], "unreadable")])
def test_a_missing_or_non_text_vendor_is_could_not_look(bad, why):
    doc = {"verdict": "pass", "input_sha256": H}
    if bad is not None:
        doc["vendor"] = bad
    r = _ing(json.dumps(doc).encode())[0]
    assert r["relayed_verdict"] == COULD_NOT_LOOK and r["could_not_look"]["reason_word"] == why


def test_long_detail_and_id_are_cut():
    r = _one(detail="d" * 5000, vendor_request_id="i" * 5000, at="t" * 5000)
    assert len(r["reported"]["detail"]) <= 256 and len(r["vendor_id"]) <= 256
    assert len(r["at"]) <= 256


# --- unsigned, always ---------------------------------------------------------------

def test_a_row_claiming_a_signature_is_still_unsigned():
    rows = _ing(SIGNED)
    assert len(rows) == 1
    r = rows[0]
    _sealed(r)
    assert r["attestation"]["claimed"] is None
    blob = json.dumps(r)
    assert "MEUCIQ" not in blob and "VALID" not in blob
    assert set(r["reported"]["ignored_keys"]) == {"signed_by_vendor", "standing", "signature",
                                                  "attestation"}


def test_every_row_of_every_fixture_and_failure_is_sealed():
    bodies = [ONE, ROWS, SPOOF, SIGNED, b"", b"not json", b"[]", b"{}", b"7", None,
              b"{\"a\": 1, \"a\": 2}", b"[" * 100000, b"\xff\xfe"]
    for raw in bodies:
        for r in _ing(raw):
            _sealed(r)
            assert set(r) >= {"input_sha256", "at", "reported", "received_at"}


# --- hostile bodies: one COULD NOT LOOK row, never a crash --------------------------

@pytest.mark.parametrize("raw,why", [
    (b"", "empty"),
    (b"not json", "unreadable"),
    (b"\xff\xfe\x00", "unreadable"),
    (b"{\"vendor\": \"a\", \"vendor\": \"b\", \"verdict\": \"pass\"}", "unreadable"),
    (b"[" * 100000 + b"]" * 100000, "unreadable"),
    (json.dumps({"vendor": "a", "verdict": "pass", "detail": [[[[[[[[[[[["x"]]]]]]]]]]]]}).encode(),
     "unreadable"),
    (b"[]", "empty"),
    (b"\"pass\"", "name_not_found"),
    (b"null", "name_not_found"),
    (None, "unreadable"),
    (12, "unreadable"),
], ids=["empty", "not_json", "not_utf8", "duplicate_key", "nested_100k", "too_deep",
        "empty_list", "a_string", "null", "none", "an_int"])
def test_hostile_bodies_are_one_could_not_look_row(raw, why):
    rows = _ing(raw)
    assert len(rows) == 1
    assert rows[0]["relayed_verdict"] == COULD_NOT_LOOK
    assert rows[0]["could_not_look"]["reason_word"] == why
    _sealed(rows[0])


def test_an_empty_object_is_one_could_not_look_row():
    rows = _ing(b"{}")
    assert len(rows) == 1 and rows[0]["relayed_verdict"] == COULD_NOT_LOOK


def test_the_8_mib_bound():
    assert R.MAX_PAYLOAD_BYTES == 8 << 20
    big = b"{\"vendor\": \"a\", \"verdict\": \"pass\", \"detail\": \"" + b"x" * (8 << 20) + b"\"}"
    rows = _ing(big)
    assert len(rows) == 1 and rows[0]["could_not_look"]["reason_word"] == "bounded"
    assert rows[0]["vendor_payload_bytes"] == len(big)
    assert rows[0]["input_sha256"] is None


def test_an_entry_that_is_not_an_object_is_its_own_row():
    rows = _ing(json.dumps([1, {"vendor": "a", "verdict": "pass", "input_sha256": H}]).encode())
    assert [r["relayed_verdict"] for r in rows] == [COULD_NOT_LOOK, VERIFIED]


def test_the_row_cap(monkeypatch):
    assert R.MAX_ROWS == 1000
    monkeypatch.setattr(R, "MAX_ROWS", 2)
    doc = [{"vendor": "a", "verdict": "pass", "input_sha256": H}] * 3
    rows = _ing(json.dumps(doc).encode())
    assert len(rows) == 3
    assert [r["relayed_verdict"] for r in rows[:2]] == [VERIFIED, VERIFIED]
    assert rows[-1]["relayed_verdict"] == COULD_NOT_LOOK
    assert rows[-1]["could_not_look"]["reason_word"] == "bounded"
    _sealed(rows[-1])


def test_a_str_body_is_read_as_utf8():
    assert _ing(ONE.decode())[0]["relayed_verdict"] == VERIFIED


# --- rollup (T4): never VERIFIED by itself ------------------------------------------

def test_rollup_of_all_verified_rows_is_not_verified():
    rows = _ing(ONE) + _ing(ONE)
    assert all(r["relayed_verdict"] == VERIFIED for r in rows)
    out = R.rollup(rows)
    assert out["relayed_verdict"] == COULD_NOT_LOOK
    assert out["signed_by_vendor"] is False and out["standing"] == "reported_by_sender"
    assert out["counts"] == {VERIFIED: 2, BROKEN: 0, COULD_NOT_LOOK: 0}
    assert "verdict" not in out


def test_rollup_keeps_a_relayed_broken():
    out = R.rollup(_ing(ROWS))
    assert out["relayed_verdict"] == BROKEN
    assert out["counts"] == {VERIFIED: 2, BROKEN: 2, COULD_NOT_LOOK: 2}


def test_rollup_ignores_rows_that_are_not_ours():
    forged = dict(_ing(ONE)[0])
    forged["vendor"] = {"name": "opa", "adapter_version": "1"}
    out = R.rollup([forged, "x", None])
    assert out["relayed_verdict"] == COULD_NOT_LOOK
    assert out["counts"] == {VERIFIED: 0, BROKEN: 0, COULD_NOT_LOOK: 0}  # not ours: not counted
    assert out["not_ours"] == 3 and out["rows"] == 0
    assert R.rollup("not a list")["relayed_verdict"] == COULD_NOT_LOOK


def test_seal_never_turns_broken_into_verified():
    rows = _ing(ROWS)
    for r in rows:
        r2 = json.loads(json.dumps(r))
        R._seal([r2], None)
        if r["relayed_verdict"] == BROKEN:
            assert r2["relayed_verdict"] == BROKEN


def test_seal_refuses_a_verified_without_a_clean_reading():
    r = _ing(ROWS)[4]  # unknown word, COULD NOT LOOK
    r["relayed_verdict"] = VERIFIED  # tampered after ingest
    R._seal([r], None)
    assert r["relayed_verdict"] == COULD_NOT_LOOK


# --- the one-payload core paths -----------------------------------------------------

def test_not_rechecked_or_imported_as_one_verdict():
    rows = _ing(ONE)
    assert recheck(rows[0], ONE)["verdict"] == COULD_NOT_LOOK
    one = import_verdict(R.REPORTED, ONE)
    assert one["relayed_verdict"] == COULD_NOT_LOOK


def test_ingest_is_deterministic():
    assert _ing(ROWS) == _ing(ROWS)


# --- the doc ------------------------------------------------------------------------

def test_doc_section_is_before_the_digest_section_and_names_the_limit():
    doc = (ROOT / "docs" / "CONNECTOR_ADAPTER.md").read_text(encoding="utf-8")
    a = doc.index("## Reported by sender (generic)")
    b = doc.index("## The sha256:jcs:v1 digest")
    assert a < b
    sec = doc[a:b]
    assert "### What this cannot prove" in sec
    assert "only that the sender said it" in sec
    for word in R.TABLE:
        assert f"`{word}`" in sec, word
    assert "—" not in sec and "–" not in sec
