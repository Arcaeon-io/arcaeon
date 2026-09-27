"""K031: freeze the criterion; a reading must cite one frozen EARLIER in its ledger."""
import json

import pytest

from arcaeon.prove import readings as R
from arcaeon.record.ledger import Ledger, verify_file

SENTENCE = "Does the claim state the dispatch time?"
READER = {"id": "reader-a", "provider": "acme", "model": "m-1", "endpoint_host": None}


def _reading(crit, **kw):
    base = dict(claim_id="c1", claim_text="Units rolled at 0412.", criterion_sha256=crit,
                reader=READER, reading="yes")
    base.update(kw)
    return R.build_reading(**base)


def test_freeze_logs_sha_and_text(tmp_path):
    led = tmp_path / "l.jsonl"
    row = R.freeze_criterion(led, "  " + SENTENCE + "\r\n")
    assert row["evt"] == "criterion" and row["format"] == R.CRITERION_FORMAT
    assert row["text"] == SENTENCE
    assert row["criterion_sha256"] == R.sha256_text(SENTENCE)
    assert verify_file(led).ok is True


def test_empty_criterion_refused(tmp_path):
    with pytest.raises(R.ReadingError):
        R.freeze_criterion(tmp_path / "l.jsonl", " \n ")


def test_revision_is_new_row_old_stays(tmp_path):
    led = tmp_path / "l.jsonl"
    old = R.freeze_criterion(led, SENTENCE)
    new = R.freeze_criterion(led, SENTENCE + " Give the time as written.",
                             supersedes=old["criterion_sha256"])
    rows = list(Ledger(led))
    assert [r["criterion_sha256"] for r in rows] == [old["criterion_sha256"], new["criterion_sha256"]]
    assert rows[0]["text"] == SENTENCE and "supersedes" not in rows[0]
    assert rows[1]["supersedes"] == old["criterion_sha256"]
    assert verify_file(led).ok is True


def test_supersedes_unknown_refused(tmp_path):
    with pytest.raises(R.UnknownCriterionError):
        R.freeze_criterion(tmp_path / "l.jsonl", SENTENCE, supersedes="b" * 64)


def test_write_refuses_unfrozen_criterion(tmp_path):
    led = tmp_path / "l.jsonl"
    with pytest.raises(R.UnknownCriterionError):
        R.write_reading(led, _reading(R.sha256_text(SENTENCE)))
    assert not led.exists()


def test_load_ok(tmp_path):
    led = tmp_path / "l.jsonl"
    crit = R.freeze_criterion(led, SENTENCE)["criterion_sha256"]
    R.write_reading(led, _reading(crit))
    res = R.load_readings(led)
    assert res["ok"] is True and len(res["readings"]) == 1
    assert res["readings"][0]["line"] == 2 and res["criteria"] == {crit: 1}


def test_reading_before_its_criterion_is_name_not_found(tmp_path):
    led = tmp_path / "l.jsonl"
    crit = R.sha256_text(SENTENCE)
    Ledger(led).append(_reading(crit))          # raw append: skips the write-time check
    Ledger(led).append(R.build_criterion(SENTENCE))  # frozen AFTER the reading: too late
    assert verify_file(led).ok is True           # the chain is fine; the citation is not
    res = R.load_readings(led)
    assert res["ok"] is False
    assert res["reason_word"] == "name_not_found" and res["line"] == 1
    assert str(led) in res["where"] and set(res) >= {"looked_for", "where", "reason"}


def test_unknown_criterion_is_name_not_found(tmp_path):
    led = tmp_path / "l.jsonl"
    R.freeze_criterion(led, SENTENCE)
    Ledger(led).append(_reading("c" * 64))
    res = R.load_readings(led)
    assert res["ok"] is False and res["reason_word"] == "name_not_found" and res["line"] == 2


def test_malformed_reading_row_is_unreadable(tmp_path):
    led = tmp_path / "l.jsonl"
    crit = R.freeze_criterion(led, SENTENCE)["criterion_sha256"]
    bad = _reading(crit)
    bad["reading"] = "probably"
    Ledger(led).append(bad)
    res = R.load_readings(led)
    assert res["ok"] is False and res["reason_word"] == "unreadable" and res["line"] == 2


def test_missing_ledger(tmp_path):
    res = R.load_readings(tmp_path / "nope.jsonl")
    assert res["ok"] is False and res["reason_word"] == "missing"


def test_criterion_main(tmp_path, capsys):
    f = tmp_path / "crit.txt"
    f.write_text(SENTENCE + "\n", encoding="utf-8")
    led = tmp_path / "l.jsonl"
    assert R.criterion_main([str(f), "--ledger", str(led), "--json"]) == 0
    row = json.loads(capsys.readouterr().out)
    assert row["criterion_sha256"] == R.sha256_text(SENTENCE)
    assert R.criterion_main([str(f), "--ledger", str(led), "--supersedes",
                             row["criterion_sha256"]]) == 0
    assert "criterion frozen:" in capsys.readouterr().out
    assert len(list(Ledger(led))) == 2


def test_criterion_main_usage(tmp_path, capsys):
    led = tmp_path / "l.jsonl"
    assert R.criterion_main([str(tmp_path / "missing.txt"), "--ledger", str(led)]) == 2
    empty = tmp_path / "e.txt"
    empty.write_text("   ", encoding="utf-8")
    assert R.criterion_main([str(empty), "--ledger", str(led)]) == 2
    assert not led.exists()
