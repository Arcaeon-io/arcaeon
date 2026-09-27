"""Review-2 minor: reader ids that differ only by case (or width, or edge
whitespace) are one reader, at write time and at compare time."""
from arcaeon import verdict as V
from arcaeon.prove import readings as R
from arcaeon.prove.readings_compare import compare
from arcaeon.record.ledger import Ledger

SENTENCE = "Does the claim state the dispatch time?"


def _row(reader_id, provider="p1", reading="yes"):
    return R.build_reading(claim_id="c1", claim_text="t", reader={"id": reader_id,
                           "provider": provider, "model": None, "endpoint_host": None},
                           criterion_sha256=R.sha256_text(SENTENCE), reading=reading)


def test_canonical_form_is_nfkc_stripped_casefolded():
    assert R.canonical_reader_id("  Agent-A ") == "agent-a"
    assert R.canonical_reader_id("AGENT-A") == "agent-a"
    assert R.canonical_reader_id("Ａgent-a") == "agent-a"      # fullwidth A


def test_the_builder_stores_the_canonical_id():
    assert _row("Agent-A")["reader"]["id"] == "agent-a"


def test_ids_differing_only_by_case_are_the_same_reader(tmp_path):
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    for led, rid, prov in ((a, "Agent-A", "p1"), (b, "AGENT-a", "p2")):
        R.freeze_criterion(led, SENTENCE)
        R.write_reading(led, _row(rid, prov))
    res = compare(a, b)
    assert res["verdict"] == V.COULD_NOT_LOOK and res["reason_word"] == "bounded"


def test_a_hand_written_mixed_case_row_cannot_pass_as_a_second_reader(tmp_path):
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    R.freeze_criterion(a, SENTENCE)
    R.write_reading(a, _row("agent-a", "p1"))
    R.freeze_criterion(b, SENTENCE)
    raw = _row("x", "p2")
    raw["reader"]["id"] = "Agent-A"            # bypasses the builder, chained all the same
    Ledger(b).append(raw)
    res = compare(a, b)
    assert res["verdict"] == V.COULD_NOT_LOOK and res["reason_word"] == "bounded"
    claim = res["claims"][0]
    assert claim["independence"] == "same_reader"


def test_distinct_ids_still_line_up(tmp_path):
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    for led, rid, prov in ((a, "Agent-A", "p1"), (b, "Agent-B", "p2")):
        R.freeze_criterion(led, SENTENCE)
        R.write_reading(led, _row(rid, prov))
    res = compare(a, b)
    assert res["verdict"] == V.COMPARED
    assert res["claims"][0]["a"]["reader_id"] == "agent-a"
