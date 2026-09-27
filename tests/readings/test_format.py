"""K030: the arcaeon-reading/1 row: builder refuses bad rows; written rows chain and verify."""
import json

import pytest

from arcaeon.prove import readings as R
from arcaeon.record.ledger import verify_file

SENTENCE = "Does the claim name a time?"
CRIT = R.sha256_text(SENTENCE)
READER = {"id": "reader-a", "provider": "acme", "model": "m-1", "endpoint_host": "127.0.0.1"}


def _row(**kw):
    base = dict(claim_id="c1", claim_text="The call came in at 3 PM.", criterion_sha256=CRIT,
                reader=READER, reading="yes")
    base.update(kw)
    return R.build_reading(**base)


def test_format_constant():
    assert R.READING_FORMAT == "arcaeon-reading/1"
    assert R.READING_WORDS == ("yes", "no", "undetermined")


def test_row_shape():
    row = _row(near_match_id="c7", rationale="it says 3 PM", prompt_sha256=R.sha256_text("p"))
    assert row["evt"] == "reading" and row["format"] == R.READING_FORMAT
    assert row["claim_sha256"] == R.sha256_text("The call came in at 3 PM.")
    assert row["criterion_sha256"] == CRIT
    assert row["reader"] == READER
    assert row["near_match_id"] == "c7"
    assert row["rationale_sha256"] == R.sha256_text("it says 3 PM")
    assert "rationale" not in row  # text only with keep_text
    assert row["prompt_sha256"] == R.sha256_text("p")
    assert row["ts"].endswith("Z")


def test_keep_text_keeps_rationale():
    row = _row(rationale="because", keep_text=True)
    assert row["rationale"] == "because"


def test_no_rationale_is_explicit_null():
    row = _row()
    assert row["rationale_sha256"] is None and row["prompt_sha256"] is None
    assert "near_match_id" not in row


@pytest.mark.parametrize("word", ["true", "Yes", "maybe", "", None, "agreed"])
def test_builder_rejects_unknown_reading_word(word):
    with pytest.raises(R.ReadingError):
        _row(reading=word)


@pytest.mark.parametrize("bad", [
    dict(claim_id=""),
    dict(criterion_sha256="abc"),
    dict(reader={"id": "", "provider": "p", "model": None, "endpoint_host": None}),
    dict(reader={"id": "r", "provider": "", "model": None, "endpoint_host": None}),
    dict(reader={"id": "r", "provider": "p", "extra": 1}),
    dict(reader="reader-a"),
    dict(claim_text=None),
    dict(claim_sha256="0" * 64),  # disagrees with claim_text
    dict(prompt_sha256="xyz"),
    dict(near_match_id=""),
])
def test_builder_rejects_bad_fields(bad):
    with pytest.raises(R.ReadingError):
        _row(**bad)


def test_claim_by_digest_only():
    row = R.build_reading(claim_id="c1", claim_sha256="a" * 64, criterion_sha256=CRIT,
                          reader=READER, reading="undetermined")
    assert row["claim_sha256"] == "a" * 64


def _ledger(tmp_path):
    led = tmp_path / "a.readings.jsonl"
    R.freeze_criterion(led, SENTENCE)  # K031: a reading cites an earlier criterion
    return led


def test_written_ledger_verifies(tmp_path):
    led = _ledger(tmp_path)
    for i, word in enumerate(R.READING_WORDS):
        R.write_reading(led, _row(claim_id=f"c{i}", reading=word))
    res = verify_file(led)
    assert res.ok is True and res.rows == 4 and res.verified_scope == "full"
    rows = [json.loads(x) for x in led.read_text(encoding="utf-8").splitlines()][1:]
    assert all("chain" in r for r in rows)
    assert [r["reading"] for r in rows] == list(R.READING_WORDS)


def test_written_ledger_verifies_via_cli(tmp_path, capsys):
    from arcaeon import cli
    led = _ledger(tmp_path)
    R.write_reading(led, _row())
    code = cli.main(["verify", str(led)])
    out = capsys.readouterr().out
    assert code == 0 and "VERIFIED" in out


def test_edit_breaks_chain(tmp_path):
    led = _ledger(tmp_path)
    R.write_reading(led, _row(claim_id="c1"))
    R.write_reading(led, _row(claim_id="c2"))
    led.write_text(led.read_text(encoding="utf-8").replace('"yes"', '"no"', 1), encoding="utf-8")
    assert verify_file(led).ok is False


def test_write_refuses_unbuilt_row(tmp_path):
    with pytest.raises(R.ReadingError):
        R.write_reading(tmp_path / "x.jsonl", {"evt": "reading", "reading": "yes"})
    row = _row()
    row["reading"] = "maybe"
    with pytest.raises(R.ReadingError):
        R.write_reading(tmp_path / "x.jsonl", row)
