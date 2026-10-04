"""D011: the connector adapter shape (arcaeon.connector).

A vendor's verdict JSON becomes one RELAYED chain row; the row re-checks against
the payload; the row exports as an in-toto Statement an outside reader parses.
"""
import hashlib
import json

import pytest

from arcaeon.connector import (OUR_WORDS, PREDICATE_TYPE, ROW_KIND, STATEMENT_TYPE, Extracted,
                               StatementError, VendorAdapter, export_row, import_verdict,
                               map_word, parse_statement, recheck, statement_bytes,
                               statement_for_check)
from arcaeon.connector.mockscan import MOCKSCAN, TABLE
from arcaeon.record.ledger import Ledger
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED

TARGET = hashlib.sha256(b"the report bytes").hexdigest()


def payload(result="pass", **over):
    doc = {"scanner": "mockscan", "scan_id": "ms-0001", "result": result,
           "target": {"name": "report.pdf", "sha256": TARGET},
           "signature": {"alg": "ed25519", "keyid": "mockscan-2026", "sig": "A" * 88}}
    doc.update(over)
    return json.dumps(doc).encode("utf-8")


ALWAYS = ("kind", "relayed", "checked_by_us", "vendor", "vendor_id", "vendor_word",
          "relayed_verdict", "mapping", "subject", "attestation", "vendor_payload_digest",
          "vendor_payload_bytes", "received_at")


def assert_relayed(row):
    for k in ALWAYS:
        assert k in row, k
    assert row["kind"] == ROW_KIND
    assert row["relayed"] is True and row["checked_by_us"] is False
    assert "verdict" not in row  # never a bare verdict a script could take for ours
    assert row["relayed_verdict"] in OUR_WORDS
    assert row["attestation"]["checked_by_us"] is False
    assert row["attestation"]["status"] in ("CLAIMED", "NONE")


# --- the mapping table ---------------------------------------------------------------

@pytest.mark.parametrize("word,ours", [
    ("pass", VERIFIED), ("fail", BROKEN), ("error", COULD_NOT_LOOK),
    ("unknown", COULD_NOT_LOOK), ("skipped", COULD_NOT_LOOK),
    ("PASS", VERIFIED), (" Fail ", BROKEN),
    ("passed", COULD_NOT_LOOK), ("ok", COULD_NOT_LOOK), ("VERIFIED", COULD_NOT_LOOK),
    ("", COULD_NOT_LOOK), ("pass,fail", COULD_NOT_LOOK), ("pаss", COULD_NOT_LOOK),
    (True, COULD_NOT_LOOK), (1, COULD_NOT_LOOK), (None, COULD_NOT_LOOK),
    (["pass"], COULD_NOT_LOOK), ({"pass": True}, COULD_NOT_LOOK),
])
def test_mapping_table(word, ours):
    row = import_verdict(MOCKSCAN, payload(word))
    assert_relayed(row)
    assert row["relayed_verdict"] == ours
    if ours != COULD_NOT_LOOK or (isinstance(word, str) and word.strip().casefold() in TABLE):
        assert row["mapping"]["rule"] == "table"
    else:
        assert row["mapping"]["rule"] in ("unknown_word", "not_a_word")
        assert row["could_not_look"]["reason_word"] == "name_not_found"


def test_only_table_hits_can_be_anything_but_could_not_look():
    for w in ("pass ", "fail", "nope", "Pass"):
        word, rule = map_word(MOCKSCAN, w)
        assert (rule == "table") == (word != COULD_NOT_LOOK or w.strip().casefold() in TABLE)


def test_a_table_cannot_map_outside_our_words():
    class Bad(VendorAdapter):
        name = "bad"
        table = {"pass": "OK"}

    with pytest.raises(TypeError):
        Bad()

    class Folded(VendorAdapter):
        name = "folded"
        table = {"Pass": VERIFIED}

    with pytest.raises(TypeError):
        Folded()


def test_ambiguous_payloads_could_not_look():
    # a second verdict field beside result
    row = import_verdict(MOCKSCAN, payload("pass", verdict="fail"))
    assert row["relayed_verdict"] == COULD_NOT_LOOK
    # a duplicate key: two honest parsers read two different verdicts
    dup = b'{"scanner":"mockscan","scan_id":"x","result":"fail","result":"pass"}'
    row = import_verdict(MOCKSCAN, dup)
    assert row["relayed_verdict"] == COULD_NOT_LOOK
    assert row["could_not_look"]["reason_word"] == "unreadable"
    # someone else's format read by the mockscan adapter
    row = import_verdict(MOCKSCAN, b'{"scanner":"other","result":"pass"}')
    assert row["relayed_verdict"] == COULD_NOT_LOOK
    # no result at all
    row = import_verdict(MOCKSCAN, b'{"scanner":"mockscan"}')
    assert row["relayed_verdict"] == COULD_NOT_LOOK


# --- provenance ------------------------------------------------------------------------

def test_provenance_fields():
    raw = payload("fail")
    row = import_verdict(MOCKSCAN, raw, received_at="2026-10-04T12:00:00Z")
    assert_relayed(row)
    assert row["vendor"] == {"name": "mockscan", "adapter_version": "1"}
    assert row["vendor_id"] == "ms-0001"
    assert row["vendor_word"] == "fail"
    assert row["relayed_verdict"] == BROKEN
    assert row["subject"] == {"name": "report.pdf", "sha256": TARGET}
    assert row["vendor_payload_digest"] == "sha256:raw-bytes:v1:" + hashlib.sha256(raw).hexdigest()
    assert row["vendor_payload_bytes"] == len(raw)
    assert row["received_at"] == "2026-10-04T12:00:00Z"
    att = row["attestation"]
    assert att["status"] == "CLAIMED" and att["checked_by_us"] is False
    assert att["claimed"]["alg"] == "ed25519" and att["claimed"]["keyid"] == "mockscan-2026"
    assert att["claimed"]["sig_digest"].startswith("sha256:raw-bytes:v1:")  # blob by digest
    assert "sig" not in att["claimed"]


def test_no_signature_is_none_and_a_bogus_one_is_only_claimed():
    doc = json.loads(payload("pass"))
    del doc["signature"]
    row = import_verdict(MOCKSCAN, json.dumps(doc).encode())
    assert row["attestation"] == {"status": "NONE", "checked_by_us": False, "claimed": None}
    row = import_verdict(MOCKSCAN, payload("pass", signature="trust me"))
    assert row["attestation"]["status"] == "CLAIMED"
    assert row["attestation"]["checked_by_us"] is False


def test_row_chains_into_a_ledger_and_reads_back(tmp_path):
    raw = payload("pass")
    row = import_verdict(MOCKSCAN, raw, keep_payload=True)
    log = Ledger(tmp_path / "checks.jsonl")
    chain = log.append(row)
    assert log.verify().ok is True
    [back] = list(log)
    assert back["chain"] == chain
    assert_relayed(back)
    assert recheck(back)["verdict"] == VERIFIED          # verbatim payload kept in the row
    assert recheck(back, raw)["verdict"] == VERIFIED     # or the caller's own copy


# --- tamper ----------------------------------------------------------------------------

def test_tampered_payload_after_import_is_broken():
    raw = payload("fail")
    row = import_verdict(MOCKSCAN, raw)
    tampered = raw.replace(b'"fail"', b'"pass"')
    r = recheck(row, tampered)
    assert r["verdict"] == BROKEN and r["fields"] == ["vendor_payload_digest"]
    one_byte = raw[:-1] + b" "
    assert recheck(row, one_byte)["verdict"] == BROKEN


def test_tampered_kept_payload_is_broken():
    row = import_verdict(MOCKSCAN, payload("fail"), keep_payload=True)
    row["vendor_payload"] = row["vendor_payload"].replace('"fail"', '"pass"')
    assert recheck(row)["verdict"] == BROKEN


def test_edited_row_is_broken_and_names_the_field():
    raw = payload("fail")
    row = import_verdict(MOCKSCAN, raw)
    row["relayed_verdict"] = VERIFIED
    r = recheck(row, raw)
    assert r["verdict"] == BROKEN and r["fields"] == ["relayed_verdict"]
    row = import_verdict(MOCKSCAN, raw)
    row["attestation"]["status"] = "VERIFIED"
    assert recheck(row, raw)["fields"] == ["attestation"]


def test_dropping_the_relayed_flag_is_broken():
    raw = payload("pass")
    for key, val in (("relayed", False), ("checked_by_us", True)):
        row = import_verdict(MOCKSCAN, raw)
        row[key] = val
        assert recheck(row, raw)["verdict"] == BROKEN
        with pytest.raises(StatementError):
            export_row(row)
    row = import_verdict(MOCKSCAN, raw)
    del row["relayed"]
    assert recheck(row, raw)["verdict"] == BROKEN


def test_recheck_could_not_look_cases():
    raw = payload("pass")
    row = import_verdict(MOCKSCAN, raw)
    assert recheck(row)["verdict"] == COULD_NOT_LOOK              # no payload kept or given
    assert recheck(row)["reason_word"] == "missing"
    assert recheck({"kind": "something else"}, raw)["verdict"] == COULD_NOT_LOOK
    assert recheck("not a row", raw)["verdict"] == COULD_NOT_LOOK
    other = dict(row, vendor={"name": "nobody", "adapter_version": "1"})
    assert recheck(other, raw)["verdict"] == COULD_NOT_LOOK       # no adapter for that vendor
    newer = dict(row, vendor={"name": "mockscan", "adapter_version": "2"})
    assert recheck(newer, raw)["verdict"] == COULD_NOT_LOOK       # cannot reproduce that table


def test_recheck_says_what_it_checked():
    raw = payload("pass")
    r = recheck(import_verdict(MOCKSCAN, raw), raw)
    assert r["verdict"] == VERIFIED and r["relayed_verdict"] == VERIFIED
    assert "NOT the vendor's own verdict" in r["what_was_checked"]


# --- hostile input -----------------------------------------------------------------------

HOSTILE = [
    b"", b"   ", b"not json", b"\xff\xfe\x00garbage", b"[1,2,3]", b"null", b'"pass"', b"42",
    b'{"scanner":"mockscan","result":', b"[" * 200_000, b'{"a":' * 50_000,
    json.dumps({"scanner": "mockscan", "result": "pass",
                "x": json.loads("[" * 40 + "]" * 40)}).encode(),
    b'{"scanner":"mockscan","result":NaN}', b'{"scanner":"mockscan","result":"pass"}' * 2,
    b"\x00" * 64,
]


@pytest.mark.parametrize("raw", HOSTILE, ids=range(len(HOSTILE)))
def test_hostile_payloads_could_not_look_without_a_traceback(raw):
    row = import_verdict(MOCKSCAN, raw)
    assert_relayed(row)
    assert row["relayed_verdict"] == COULD_NOT_LOOK
    assert row["could_not_look"]["reason_word"] in ("unreadable", "empty", "name_not_found")
    assert row["vendor_payload_digest"].startswith("sha256:raw-bytes:v1:")
    json.dumps(row)  # the row itself stays writable
    statement_bytes(export_row(row))  # and exportable (subject = the payload)


def test_huge_payload_is_digested_not_parsed():
    raw = b'{"scanner":"mockscan","result":"pass","pad":"' + b"x" * (2 << 20) + b'"}'
    row = import_verdict(MOCKSCAN, raw, keep_payload=True)
    assert row["relayed_verdict"] == COULD_NOT_LOOK
    assert row["vendor_payload_bytes"] == len(raw)
    assert "vendor_payload" not in row
    assert recheck(row, raw)["verdict"] == VERIFIED  # re-reads to the same COULD NOT LOOK row


@pytest.mark.parametrize("raw", [None, 12, {"result": "pass"}, ["pass"]])
def test_non_bytes_input_could_not_look(raw):
    row = import_verdict(MOCKSCAN, raw)
    assert_relayed(row)
    assert row["relayed_verdict"] == COULD_NOT_LOOK
    assert row["vendor_payload_digest"] is None


def test_hostile_strings_are_cut_and_made_safe():
    raw = payload("pass" + "z" * 5000, scan_id="\ud800" + "i" * 5000)
    row = import_verdict(MOCKSCAN, raw)
    assert row["relayed_verdict"] == COULD_NOT_LOOK
    assert len(row["vendor_word"]) <= 256 and len(row["vendor_id"]) <= 256
    statement_bytes(export_row(row))  # JCS refuses lone surrogates; none got through


def test_a_buggy_adapter_is_could_not_look():
    class Crashy(VendorAdapter):
        name = "crashy"
        table = {"pass": VERIFIED}

        def extract(self, doc):
            return 1 / 0

    class Wrong(VendorAdapter):
        name = "wrong"
        table = {"pass": VERIFIED}

        def extract(self, doc):
            return {"word": "pass"}

    for ad in (Crashy(), Wrong()):
        row = import_verdict(ad, b'{"result":"pass"}')
        assert_relayed(row)
        assert row["relayed_verdict"] == COULD_NOT_LOOK


def test_a_second_adapter_needs_only_extract_and_a_table():
    class Lite(VendorAdapter):
        name = "lite"
        version = "3"
        table = {"clean": VERIFIED, "flagged": BROKEN}

        def extract(self, doc):
            return Extracted(word=doc.get("status"), vendor_id=doc.get("id"))

    lite = Lite()
    raw = b'{"id":"r1","status":"flagged"}'
    row = import_verdict(lite, raw)
    assert row["relayed_verdict"] == BROKEN and row["subject"] is None
    assert recheck(row, raw, adapter=lite)["verdict"] == VERIFIED


# --- export ------------------------------------------------------------------------------

def test_export_round_trips_through_a_parse(tmp_path):
    raw = payload("fail")
    row = import_verdict(MOCKSCAN, raw, received_at="2026-10-04T12:00:00Z")
    chain = Ledger(tmp_path / "checks.jsonl").append(row)
    stmt = export_row(row, row_chain=chain, ledger="checks.jsonl", pin="pin-ref")
    data = statement_bytes(stmt)
    back = parse_statement(data)
    assert back == stmt
    assert parse_statement(data.decode("utf-8")) == stmt
    # a plain JSON reader sees the in-toto shape
    plain = json.loads(data)
    assert plain["_type"] == STATEMENT_TYPE
    assert plain["predicateType"] == PREDICATE_TYPE
    assert plain["subject"] == [{"name": "report.pdf", "digest": {"sha256": TARGET}}]
    pred = plain["predicate"]
    assert pred["relayed"] is True and pred["checked_by_us"] is False
    assert pred["relayed_verdict"] == BROKEN and "verdict" not in pred
    assert pred["subject_is"] == "checked_artifact"
    assert pred["chain"] == {"ledger": "checks.jsonl", "row_chain": chain, "pin": "pin-ref"}
    assert pred["vendor_payload_digest"] == row["vendor_payload_digest"]
    assert pred["attestation"]["status"] == "CLAIMED"
    # canonical: same statement, same bytes
    assert statement_bytes(json.loads(data)) == data


def test_export_without_a_named_artifact_names_the_payload():
    raw = b'{"scanner":"mockscan","scan_id":"ms-9","result":"pass"}'
    stmt = export_row(import_verdict(MOCKSCAN, raw))
    assert stmt["subject"][0]["digest"]["sha256"] == hashlib.sha256(raw).hexdigest()
    assert stmt["subject"][0]["name"] == "vendor-payload:mockscan/ms-9"
    assert stmt["predicate"]["subject_is"] == "vendor_payload"
    parse_statement(statement_bytes(stmt))


def test_our_own_check_exports_with_verdict_not_relayed():
    stmt = statement_for_check("report.pdf", TARGET, VERIFIED, checked_at="2026-10-04T12:00:00Z",
                               row_chain="abc", ledger="agent.jsonl")
    back = parse_statement(statement_bytes(stmt))
    assert back["predicate"]["relayed"] is False and back["predicate"]["verdict"] == VERIFIED
    assert "relayed_verdict" not in back["predicate"]
    with pytest.raises(StatementError):
        statement_for_check("x", TARGET, "OK")


@pytest.mark.parametrize("mutate", [
    lambda s: s.update(_type="https://in-toto.io/Statement/v0.1"),
    lambda s: s.update(predicateType="https://example.com/other"),
    lambda s: s.update(subject=[]),
    lambda s: s["subject"][0]["digest"].update(sha256="zz"),
    lambda s: s["predicate"].update(relayed_verdict="OK"),
    lambda s: s["predicate"].update(verdict=VERIFIED),          # both verdict keys
    lambda s: s["predicate"].pop("relayed"),
    lambda s: s["predicate"].update(checked_by_us=True),
    lambda s: s["predicate"].update(chain="x"),
])
def test_parse_refuses_what_the_predicate_does_not_define(mutate):
    stmt = export_row(import_verdict(MOCKSCAN, payload("pass")))
    mutate(stmt)
    with pytest.raises(StatementError):
        parse_statement(json.dumps(stmt))


PARSE_HOSTILE = [b"", b"garbage", b"[" * 200_000, b"\xff", "[]", 7, b"x" * ((1 << 20) + 1)]


@pytest.mark.parametrize("data", PARSE_HOSTILE, ids=range(len(PARSE_HOSTILE)))
def test_parse_hostile_raises_statement_error_only(data):
    with pytest.raises(StatementError):
        parse_statement(data)


# --- docs/CONNECTOR_ADAPTER.md: the example runs as written ------------------------------

def test_doc_example_runs_as_written(capsys):
    import re
    from pathlib import Path
    md = (Path(__file__).resolve().parents[1] / "docs" / "CONNECTOR_ADAPTER.md").read_text(
        encoding="utf-8")
    m = re.search(r"```python\n(.*?)```\n\n```text\n(.*?)```", md, re.S)
    assert m, "the adapter example and its output block are missing"
    exec(compile(m.group(1), "docs/CONNECTOR_ADAPTER.md", "exec"), {"__name__": "__doc__"})
    assert capsys.readouterr().out == m.group(2)
