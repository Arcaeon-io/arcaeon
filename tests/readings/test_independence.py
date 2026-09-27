"""K033: the independence field. One reader on both sides is COULD NOT LOOK."""
import json
from pathlib import Path

from arcaeon.prove import readings as R
from arcaeon.prove import readings_compare as C

SENTENCE = "Does the claim state the dispatch time?"


def _reader(rid, provider):
    return {"id": rid, "provider": provider, "model": "m", "endpoint_host": None}


def _ledger(path, reader, rows):
    path = Path(path)
    crit = R.freeze_criterion(path, SENTENCE)["criterion_sha256"]
    for cid, word in rows:
        R.write_reading(path, R.build_reading(claim_id=cid, claim_text=f"claim {cid}",
                                              criterion_sha256=crit, reader=reader, reading=word))
    return path


ROWS = [("c1", "yes"), ("c2", "no")]


def test_same_reader_is_could_not_look_bounded(tmp_path):
    a = _ledger(tmp_path / "a.jsonl", _reader("r1", "acme"), ROWS)
    b = _ledger(tmp_path / "b.jsonl", _reader("r1", "acme"), [("c1", "no"), ("c2", "no")])
    res = C.compare(a, b)
    assert res["verdict"] == C.COULD_NOT_LOOK and res["exit"] == 3
    assert res["reason"] == "the same reader on both sides" and res["reason_word"] == "bounded"
    assert res["independence"] == C.SAME_READER
    assert all(c["status"] == C.COULD_NOT_LOOK and c["reason_word"] == "bounded"
               for c in res["claims"])
    assert res["summary"]["read"] == 0 and res["summary"]["disagreed"] == 0


def test_one_ledger_against_itself(tmp_path):
    a = _ledger(tmp_path / "a.jsonl", _reader("r1", "acme"), ROWS)
    res = C.compare(a, a)
    assert res["verdict"] == C.COULD_NOT_LOOK and res["reason"] == "the same reader on both sides"


def test_same_reader_outranks_missing(tmp_path):
    a = _ledger(tmp_path / "a.jsonl", _reader("r1", "acme"), ROWS)
    b = _ledger(tmp_path / "b.jsonl", _reader("r1", "acme"), ROWS[:1])
    assert C.compare(a, b)["verdict"] == C.COULD_NOT_LOOK


def test_same_provider(tmp_path):
    a = _ledger(tmp_path / "a.jsonl", _reader("r1", "acme"), ROWS)
    b = _ledger(tmp_path / "b.jsonl", _reader("r2", " ACME "), ROWS)
    res = C.compare(a, b)
    assert res["verdict"] == C.COMPARED
    assert res["independence"] == "same_provider"
    assert all(c["independence"] == "same_provider" for c in res["claims"])
    assert res["independence_counts"] == {"same_reader": 0, "same_provider": 2,
                                          "distinct_provider_self_asserted": 0}


def test_distinct_provider_self_asserted(tmp_path):
    a = _ledger(tmp_path / "a.jsonl", _reader("r1", "acme"), ROWS)
    b = _ledger(tmp_path / "b.jsonl", _reader("r2", "other"), ROWS)
    res = C.compare(a, b)
    assert res["verdict"] == C.COMPARED
    assert res["independence"] == "distinct_provider_self_asserted"
    assert res["independence_reason"] is None


def test_weakest_class_wins_at_top(tmp_path):
    a = tmp_path / "a.jsonl"
    crit = R.freeze_criterion(a, SENTENCE)["criterion_sha256"]
    b = tmp_path / "b.jsonl"
    R.freeze_criterion(b, SENTENCE)
    for led, reader, cid in ((a, _reader("r1", "acme"), "c1"), (a, _reader("r1", "acme"), "c2"),
                             (b, _reader("r2", "other"), "c1"), (b, _reader("r3", "acme"), "c2")):
        R.write_reading(led, R.build_reading(claim_id=cid, claim_text=f"claim {cid}",
                                             criterion_sha256=crit, reader=reader, reading="yes"))
    res = C.compare(a, b)
    assert res["independence"] == "same_provider"
    assert res["independence_counts"]["distinct_provider_self_asserted"] == 1


def test_nothing_lined_up_independence_is_null_with_reason(tmp_path):
    a = _ledger(tmp_path / "a.jsonl", _reader("r1", "acme"), [("c1", "yes")])
    b = _ledger(tmp_path / "b.jsonl", _reader("r2", "other"), [("c2", "yes")])
    res = C.compare(a, b)
    assert res["independence"] is None and res["independence_reason"]


def _scrub(res, *paths):
    text = json.dumps(res)
    for p in paths:
        text = text.replace(json.dumps(str(p))[1:-1], "P")
    return text


def test_the_word_absent_from_every_output(tmp_path):
    """Every verdict shape this module can print, scanned for the word."""
    outs = []
    pairs = [
        (_reader("r1", "acme"), _reader("r1", "acme")),
        (_reader("r1", "acme"), _reader("r2", "acme")),
        (_reader("r1", "acme"), _reader("r2", "other")),
    ]
    for i, (ra, rb) in enumerate(pairs):
        d = tmp_path / f"p{i}"
        d.mkdir()
        a = _ledger(d / "a.jsonl", ra, ROWS)
        b = _ledger(d / "b.jsonl", rb, [("c1", "no"), ("c3", "yes")])
        outs.append(_scrub(C.compare(a, b), a, b))
        outs.append(_scrub(C.compare(a, d / "none.jsonl"), a, d / "none.jsonl"))
        broken = d / "broken.jsonl"
        broken.write_text(a.read_text(encoding="utf-8").replace('"yes"', '"no"'), encoding="utf-8")
        outs.append(_scrub(C.compare(broken, b), broken, b))
    for text in outs:
        assert "independent" not in text.lower()
