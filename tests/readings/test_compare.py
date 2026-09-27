"""K032: the compare core: AGREED / DISAGREED / MISSING / COULD NOT LOOK per claim."""
import json
import tempfile
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from arcaeon.prove import readings as R
from arcaeon.prove import readings_compare as C
from arcaeon.record.ledger import Ledger

SENTENCE = "Does the claim state the dispatch time?"
CRIT = R.sha256_text(SENTENCE)
RA = {"id": "reader-a", "provider": "acme", "model": "m-1", "endpoint_host": "127.0.0.1"}
RB = {"id": "reader-b", "provider": "other", "model": "m-2", "endpoint_host": "127.0.0.1"}


def _ledger(path, reader, readings, sentence=SENTENCE):
    """readings: list of (claim_id, word) or (claim_id, word, near_match_id)."""
    path = Path(path)
    crit = R.freeze_criterion(path, sentence)["criterion_sha256"]
    for item in readings:
        cid, word = item[0], item[1]
        nm = item[2] if len(item) > 2 else None
        R.write_reading(path, R.build_reading(claim_id=cid, claim_text=f"claim {cid}",
                                              criterion_sha256=crit, reader=reader,
                                              reading=word, near_match_id=nm))
    return path


def _pairs(tmp_path, a_rows, b_rows):
    return (_ledger(tmp_path / "a.jsonl", RA, a_rows), _ledger(tmp_path / "b.jsonl", RB, b_rows))


def test_all_agreed_is_compared(tmp_path):
    a, b = _pairs(tmp_path, [("c1", "yes"), ("c2", "no")], [("c1", "yes"), ("c2", "no")])
    res = C.compare(a, b)
    assert res["verdict"] == C.COMPARED and res["exit"] == 0
    assert [c["status"] for c in res["claims"]] == [C.AGREED, C.AGREED]
    s = res["summary"]
    assert (s["disagreed"], s["read"]) == (0, 2) and s["not_yet_informative"] is True
    assert s["fraction"] == 0.0 and s["fraction_reason"] is None


def test_disagreed_is_filed_with_both_sides(tmp_path):
    a, b = _pairs(tmp_path, [("c1", "yes", "c9"), ("c2", "undetermined", "c4")],
                  [("c1", "no"), ("c2", "yes", "c5")])
    res = C.compare(a, b)
    assert res["verdict"] == C.COMPARED and res["exit"] == 0
    c1, c2 = res["claims"]
    assert c1["status"] == C.DISAGREED
    assert (c1["a"]["reading"], c1["b"]["reading"]) == ("yes", "no")
    assert (c1["a"]["reader_id"], c1["b"]["reader_id"]) == ("reader-a", "reader-b")
    assert (c1["a"]["near_match_id"], c1["b"]["near_match_id"]) == ("c9", None)
    assert c2["status"] == C.DISAGREED
    assert (c2["a"]["near_match_id"], c2["b"]["near_match_id"]) == ("c4", "c5")
    assert (res["summary"]["disagreed"], res["summary"]["read"]) == (2, 2)
    assert res["summary"]["fraction"] == 1.0


def test_undetermined_on_both_sides_carries_both_readers(tmp_path):
    a, b = _pairs(tmp_path, [("c1", "undetermined", "c3")], [("c1", "undetermined", "c3")])
    c1 = C.compare(a, b)["claims"][0]
    assert c1["status"] == C.AGREED
    assert c1["a"]["reader_id"] == "reader-a" and c1["b"]["reader_id"] == "reader-b"
    assert c1["a"]["near_match_id"] == c1["b"]["near_match_id"] == "c3"


def test_missing_names_short_side(tmp_path):
    a, b = _pairs(tmp_path, [("c1", "yes"), ("c2", "no")], [("c1", "yes"), ("c3", "no")])
    res = C.compare(a, b)
    assert res["verdict"] == C.MISSING and res["exit"] == 1
    by = {c["claim_id"]: c for c in res["claims"]}
    assert by["c2"]["status"] == C.MISSING and by["c2"]["side"] == "b"
    assert by["c2"]["where"] == str(b)
    assert by["c3"]["status"] == C.MISSING and by["c3"]["side"] == "a"
    s = res["summary"]
    assert (s["disagreed"], s["read"], s["missing"]) == (0, 1, 2)


def test_zero_read_fraction_is_null_with_reason(tmp_path):
    a, b = _pairs(tmp_path, [("c1", "yes")], [("c2", "no")])
    s = C.compare(a, b)["summary"]
    assert s["read"] == 0 and s["disagreed"] == 0
    assert s["fraction"] is None and s["fraction_reason"]


def test_informative_at_twenty(tmp_path):
    rows = [(f"c{i}", "yes") for i in range(20)]
    a, b = _pairs(tmp_path, rows, rows)
    assert C.compare(a, b)["summary"]["not_yet_informative"] is False
    (tmp_path / "x").mkdir()
    a2, b2 = _pairs(tmp_path / "x", rows[:19], rows[:19])
    assert C.compare(a2, b2)["summary"]["not_yet_informative"] is True


def test_reread_last_wins(tmp_path):
    a, b = _pairs(tmp_path, [("c1", "yes"), ("c1", "no")], [("c1", "no")])
    res = C.compare(a, b)
    assert res["claims"][0]["status"] == C.AGREED and res["claims"][0]["a"]["line"] == 3


def test_broken_names_ledger_and_line(tmp_path):
    a, b = _pairs(tmp_path, [("c1", "yes"), ("c2", "no")], [("c1", "yes"), ("c2", "no")])
    lines = b.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"yes"', '"no"')
    b.write_text("\n".join(lines) + "\n", encoding="utf-8")
    res = C.compare(a, b)
    assert res["verdict"] == C.BROKEN and res["exit"] == 1
    assert res["broken"]["ledger"] == "b" and res["broken"]["line"] == 2
    assert res["broken"]["where"] == str(b)
    assert res["summary"]["disagreed"] is None and res["summary"]["read"] is None
    assert res["summary"]["counts_reason"]


def test_missing_ledger_could_not_look(tmp_path):
    a = _ledger(tmp_path / "a.jsonl", RA, [("c1", "yes")])
    res = C.compare(a, tmp_path / "nope.jsonl")
    assert res["verdict"] == C.COULD_NOT_LOOK and res["exit"] == 3
    assert res["reason_word"] == "missing" and res["ledger"] == "b"


def test_empty_ledger_could_not_look(tmp_path):
    a = _ledger(tmp_path / "a.jsonl", RA, [("c1", "yes")])
    e = tmp_path / "e.jsonl"
    e.write_text("", encoding="utf-8")
    res = C.compare(a, e)
    assert res["verdict"] == C.COULD_NOT_LOOK and res["reason_word"] == "empty"


def test_no_readings_either_side(tmp_path):
    a, b = _pairs(tmp_path, [], [])
    res = C.compare(a, b)
    assert res["verdict"] == C.COULD_NOT_LOOK and res["reason_word"] == "empty"


def test_unknown_criterion_makes_compare_could_not_look(tmp_path):
    """K031's acceptance, at the compare: name_not_found."""
    a = _ledger(tmp_path / "a.jsonl", RA, [("c1", "yes")])
    b = tmp_path / "b.jsonl"
    Ledger(b).append(R.build_reading(claim_id="c1", claim_text="claim c1",
                                     criterion_sha256=CRIT, reader=RB, reading="yes"))
    res = C.compare(a, b)
    assert res["verdict"] == C.COULD_NOT_LOOK and res["exit"] == 3
    assert res["reason_word"] == "name_not_found" and res["ledger"] == "b" and res["line"] == 1


def test_different_criteria_per_claim_could_not_look(tmp_path):
    a = _ledger(tmp_path / "a.jsonl", RA, [("c1", "yes")])
    b = _ledger(tmp_path / "b.jsonl", RB, [("c1", "yes")], sentence="Another sentence?")
    res = C.compare(a, b)
    assert res["verdict"] == C.COULD_NOT_LOOK
    c1 = res["claims"][0]
    assert c1["status"] == C.COULD_NOT_LOOK and c1["a"]["reader_id"] and c1["b"]["reader_id"]
    assert res["summary"]["read"] == 0


def test_output_never_claims_truth(tmp_path):
    a, b = _pairs(tmp_path, [("c1", "yes")], [("c1", "no")])
    text = json.dumps(C.compare(a, b)).replace(json.dumps(str(a))[1:-1], "A")
    text = text.replace(json.dumps(str(b))[1:-1], "B").lower()
    for word in ("is true", "truth", "correct", "verified"):
        assert word not in text


_WORD = st.sampled_from(R.READING_WORDS)
_SIDE = st.one_of(st.none(), st.tuples(_WORD, st.one_of(st.none(), st.sampled_from(["n1", "n2"]))))


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(st.tuples(_SIDE, _SIDE), min_size=0, max_size=12))
def test_property_counts_and_reader_ids(plan):
    with tempfile.TemporaryDirectory() as d:
        a_rows, b_rows = [], []
        for i, (sa, sb) in enumerate(plan):
            if sa:
                a_rows.append((f"c{i}", sa[0], sa[1]))
            if sb:
                b_rows.append((f"c{i}", sb[0], sb[1]))
        a = _ledger(Path(d) / "a.jsonl", RA, a_rows)
        b = _ledger(Path(d) / "b.jsonl", RB, b_rows)
        res = C.compare(a, b)
        s = res["summary"]
        if not a_rows and not b_rows:
            assert res["verdict"] == C.COULD_NOT_LOOK
            return
        assert isinstance(s["disagreed"], int) and isinstance(s["read"], int)
        assert 0 <= s["disagreed"] <= s["read"]
        both = [(sa, sb) for sa, sb in plan if sa and sb]
        assert s["read"] == len(both)
        assert s["disagreed"] == sum(1 for sa, sb in both if sa[0] != sb[0])
        for c in res["claims"]:
            if c["status"] == C.DISAGREED:
                assert c["a"]["reader_id"] and c["b"]["reader_id"]
                assert c["a"]["reading"] != c["b"]["reading"]
                assert "near_match_id" in c["a"] and "near_match_id" in c["b"]
        assert (s["fraction"] is None) == (s["read"] == 0)
        assert s["not_yet_informative"] == (s["read"] < C.INFORMATIVE_AT)
