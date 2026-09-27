"""K035: `reconcile --kind readings` dispatches to the readings compare;
the default (`tapes`) is byte-identical to the tape reconcile."""
import json

import pytest

import _arcaeon_chain as CH
from arcaeon import cli
from arcaeon.prove import readings as R
from arcaeon.prove import readings_compare as C
from arcaeon.prove import reconcile as REC

SENTENCE = "Does the claim state the dispatch time?"
RA = {"id": "reader-a", "provider": "acme", "model": "m-1", "endpoint_host": "127.0.0.1"}
RB = {"id": "reader-b", "provider": "other", "model": "m-2", "endpoint_host": "127.0.0.1"}


def _ledger(path, reader, readings):
    crit = R.freeze_criterion(path, SENTENCE)["criterion_sha256"]
    for cid, word in readings:
        R.write_reading(path, R.build_reading(claim_id=cid, claim_text=f"claim {cid}",
                                              criterion_sha256=crit, reader=reader,
                                              reading=word))
    return str(path)


@pytest.fixture()
def ledgers(tmp_path):
    a = _ledger(tmp_path / "a.jsonl", RA, [("c1", "yes"), ("c2", "no"), ("c3", "yes")])
    b = _ledger(tmp_path / "b.jsonl", RB, [("c1", "yes"), ("c2", "yes"), ("c3", "yes")])
    return a, b


@pytest.fixture()
def tapes(tmp_path):
    t = CH.record_session(tmp_path / "s")
    return str(t["agent_tape"]), str(t["tool_tape"])


def test_kind_readings_is_the_compare(ledgers, capsys):
    a, b = ledgers
    assert REC.main(["--kind", "readings", a, b]) == 0
    res = json.loads(capsys.readouterr().out)
    assert res["format"] == C.COMPARE_FORMAT and res["verdict"] == "COMPARED"
    assert (res["summary"]["disagreed"], res["summary"]["read"]) == (1, 3)
    assert res == json.loads(json.dumps(C.compare(a, b)))


def test_kind_may_come_after_the_paths(ledgers, capsys):
    a, b = ledgers
    assert REC.main([a, b, "--kind", "readings"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "COMPARED"


def test_kind_readings_exit_codes(ledgers, tmp_path, capsys):
    a, _ = ledgers
    assert REC.main(["--kind", "readings", a, str(tmp_path / "nope.jsonl")]) == 3
    short = _ledger(tmp_path / "short.jsonl", RB, [("c1", "yes")])
    assert REC.main(["--kind", "readings", a, short]) == 1
    capsys.readouterr()


@pytest.mark.parametrize("argv", [["--kind"], ["--kind", "cards", "a", "b"],
                                  ["--kind", "readings", "a"],
                                  ["--kind", "readings", "a", "b", "--pin", "p"]])
def test_kind_bad_usage_is_2(argv, capsys):
    assert REC.main(argv) == 2
    capsys.readouterr()


def test_default_is_byte_identical_to_the_tape_reconcile(tapes, capsys):
    a, b = tapes
    want = json.dumps(REC.reconcile(a, b).to_dict(), indent=1) + "\n"
    assert REC.main([a, b]) == 0
    plain = capsys.readouterr().out
    assert REC.main(["--kind", "tapes", a, b]) == 0
    explicit = capsys.readouterr().out
    assert plain == want and explicit == want


def test_default_legacy_and_missing_unchanged(tapes, tmp_path, capsys):
    a, _ = tapes
    gone = str(tmp_path / "gone.jsonl")
    assert REC.main([a, gone]) == 3
    assert REC.main([a, gone, "--legacy-exit"]) == 2
    assert REC.main(["--kind", "tapes", a, gone, "--legacy-exit"]) == 2
    capsys.readouterr()


def test_front_door(ledgers, tapes, capsys):
    a, b = ledgers
    assert cli.main(["reconcile", "--kind", "readings", a, b]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "COMPARED"
    ta, tb = tapes
    assert cli.main(["reconcile", ta, tb]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "MATCHED"


def test_readings_output_never_says_the_i_word(ledgers, capsys):
    # (the test name stays clear of the word: tmp_path carries it into paths)
    a, b = ledgers
    REC.main(["--kind", "readings", a, b])
    assert "independent" not in capsys.readouterr().out.lower()
