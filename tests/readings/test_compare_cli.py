"""K034: `arcaeon second-read compare A B`: the human line, --json, the exit codes."""
import json
from pathlib import Path

from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import readings as R
from arcaeon.prove import readings_cli as RC
from arcaeon.prove import readings_compare as C

SENTENCE = "Does the claim state the dispatch time?"
RA = {"id": "reader-a", "provider": "acme", "model": "m-1", "endpoint_host": "127.0.0.1"}
RB = {"id": "reader-b", "provider": "other", "model": "m-2", "endpoint_host": "127.0.0.1"}
ROOT = Path(__file__).resolve().parents[2]


def _ledger(path, reader, readings):
    crit = R.freeze_criterion(path, SENTENCE)["criterion_sha256"]
    for cid, word in readings:
        R.write_reading(path, R.build_reading(claim_id=cid, claim_text=f"claim {cid}",
                                              criterion_sha256=crit, reader=reader,
                                              reading=word))
    return path


def _pair(tmp_path, n=24, disagree=3, drop_b=0):
    a_rows = [(f"c{i}", "yes") for i in range(n)]
    b_rows = [(f"c{i}", "no" if i < disagree else "yes") for i in range(n - drop_b)]
    return (str(_ledger(tmp_path / "a.jsonl", RA, a_rows)),
            str(_ledger(tmp_path / "b.jsonl", RB, b_rows)))


def test_compared_is_a_verdict_word_that_exits_0():
    assert V.COMPARED == "COMPARED" and V.COMPARED in V.COMPARE_WORDS
    assert V.exit_for(V.COMPARED) == 0
    assert C.COMPARED is V.COMPARED
    assert C.EXIT_CODES == {"COMPARED": 0, "MISSING": 1, "BROKEN": 1, "COULD NOT LOOK": 3}


def test_words_md_explains_compared_without_claiming_truth():
    md = (ROOT / "docs" / "WORDS.md").read_text(encoding="utf-8")
    assert "**COMPARED.**" in md
    section = " ".join(md.split("**COMPARED.**", 1)[1].split("\n\n", 1)[0].split())
    assert "both ledgers were read and lined up" in section
    assert 'never "the claims are true"' in section


def test_human_first_line(tmp_path, capsys):
    a, b = _pair(tmp_path)
    rc = RC.main(["compare", a, b])
    out = capsys.readouterr().out.splitlines()
    assert rc == 0
    assert out[0] == "compared 24 claims: 3 disagreed of 24 read"
    assert out[1] == "COMPARED: both ledgers were read and lined up"
    assert sum(1 for line in out if line.strip().startswith("DISAGREED ")) == 3
    assert not any("not yet informative" in line for line in out)


def test_under_twenty_is_printed_and_marked(tmp_path, capsys):
    a, b = _pair(tmp_path, n=5, disagree=2)
    assert RC.main(["compare", a, b]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "compared 5 claims: 2 disagreed of 5 read"
    assert any(line.startswith("not yet informative") for line in out)


def test_json_is_the_compare_object(tmp_path, capsys):
    a, b = _pair(tmp_path)
    assert RC.main(["compare", a, b, "--json"]) == 0
    res = json.loads(capsys.readouterr().out)
    assert res["verdict"] == "COMPARED" and res["exit"] == 0
    assert (res["summary"]["disagreed"], res["summary"]["read"]) == (3, 24)
    assert res == json.loads(json.dumps(C.compare(a, b)))


def test_disagreed_rows_carry_both_readings_and_readers(tmp_path, capsys):
    a, b = _pair(tmp_path, n=3, disagree=1)
    RC.main(["compare", a, b, "--json"])
    res = json.loads(capsys.readouterr().out)
    d = [c for c in res["claims"] if c["status"] == "DISAGREED"]
    assert len(d) == 1
    assert (d[0]["a"]["reading"], d[0]["b"]["reading"]) == ("yes", "no")
    assert (d[0]["a"]["reader_id"], d[0]["b"]["reader_id"]) == ("reader-a", "reader-b")
    assert "near_match_id" in d[0]["a"] and "near_match_id" in d[0]["b"]


def test_missing_exits_1(tmp_path, capsys):
    a, b = _pair(tmp_path, n=4, disagree=0, drop_b=1)
    assert RC.main(["compare", a, b]) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "compared 4 claims: 0 disagreed of 3 read"
    assert out[1].startswith("MISSING")


def test_broken_exits_1_and_counts_are_null(tmp_path, capsys):
    a, b = _pair(tmp_path, n=3, disagree=0)
    p = Path(b)
    lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
    lines[1] = lines[1].replace('"yes"', '"no"', 1)
    p.write_text("".join(lines), encoding="utf-8")
    assert RC.main(["compare", a, b, "--json"]) == 1
    res = json.loads(capsys.readouterr().out)
    assert res["verdict"] == "BROKEN"
    assert res["summary"]["disagreed"] is None and res["summary"]["read"] is None
    assert res["summary"]["counts_reason"]
    assert RC.main(["compare", a, b]) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[0].startswith("BROKEN: ") and out[1].startswith("counts not computed: ")


def test_could_not_look_exits_3(tmp_path, capsys):
    a, _ = _pair(tmp_path, n=2, disagree=0)
    assert RC.main(["compare", a, str(tmp_path / "nope.jsonl")]) == 3
    assert capsys.readouterr().out.startswith("COULD NOT LOOK: ")


def test_same_reader_is_could_not_look(tmp_path, capsys):
    a = str(_ledger(tmp_path / "a.jsonl", RA, [("c1", "yes")]))
    b = str(_ledger(tmp_path / "b.jsonl", RA, [("c1", "no")]))
    assert RC.main(["compare", a, b]) == 3


def test_usage_is_2(tmp_path, capsys):
    assert RC.main([]) == 2
    assert RC.main(["compare", "only-one"]) == 2
    assert RC.main(["nosuch"]) == 2
    assert RC.main(["compare", "--help"]) == 0


def test_front_door_dispatches(tmp_path, capsys):
    a, b = _pair(tmp_path, n=2, disagree=1)
    assert cli.main(["second-read", "compare", a, b]) == 0
    assert capsys.readouterr().out.splitlines()[0] == "compared 2 claims: 1 disagreed of 2 read"
    assert cli.main(["second-read", "compare", a]) == 2


def test_no_output_word_claims_truth_or_independence(tmp_path, capsys):
    a, b = _pair(tmp_path, n=4, disagree=2, drop_b=1)
    RC.main(["compare", a, b])
    human = capsys.readouterr().out.lower()
    for word in ("independent", "true", "truth", "correct", "verified"):
        assert word not in human, word
    RC.main(["compare", a, b, "--json"])
    assert "independent" not in capsys.readouterr().out.lower()
