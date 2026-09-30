"""K042: `second-read run`: two readers, two ledgers, one compare, against two
127.0.0.1 stubs only."""
from __future__ import annotations

import json
import re

from arcaeon import verdict as V
from arcaeon.prove import readings as R
from arcaeon.prove import readings_cli as CLI
from arcaeon.record.ledger import verify_file
from readings.stub_llm import StubLLM
from _load import must_match

SENTENCE = "Does the claim state the dispatch time?"
_N = re.compile(r"claim number (\d+)")


def _claims_file(tmp_path, n=5):
    p = tmp_path / "claims.jsonl"
    p.write_text("".join(json.dumps({"claim_id": f"c{i}", "claim": f"claim number {i}",
                                     "near_match_id": f"n{i}"}) + "\n"
                         for i in range(1, n + 1)), encoding="utf-8")
    return p


def _crit(tmp_path):
    p = tmp_path / "crit.txt"
    p.write_text(SENTENCE, encoding="utf-8")
    return p


def _n(body):
    return int(must_match(_N, body["messages"][0]["content"]).group(1))


def _b_answers(i, body):
    return "no" if _n(body) in (2, 4) else "yes"


def _argv(tmp_path, sa, sb, *extra, ma="model-a", mb="model-b"):
    return ["run", "--claims", str(_claims_file(tmp_path)),
            "--reader-a", f"openai_compat:{ma}", "--base-url-a", sa.url + "/v1",
            "--ledger-a", str(tmp_path / "a.jsonl"),
            "--reader-b", f"openai_compat:{mb}", "--base-url-b", sb.url + "/v1",
            "--ledger-b", str(tmp_path / "b.jsonl"),
            "--criterion-file", str(_crit(tmp_path)), *extra]


def test_two_readers_disagreeing_on_two_of_five(tmp_path, capsys):
    with StubLLM(answers=["yes"]) as sa, StubLLM(answers=_b_answers) as sb:
        rc = CLI.main(_argv(tmp_path, sa, sb, "--send", "--json"))
        res = json.loads(capsys.readouterr().out)
    s = res["summary"]
    assert s["disagreed"] == 2 and s["read"] == 5 and s["not_yet_informative"] is True
    assert isinstance(s["disagreed"], int) and isinstance(s["read"], int)
    assert rc == 0 and res["exit"] == 0 and res["verdict"] == V.COMPARED
    assert res["requests"] == 10 and len(sa.requests) == 5 and len(sb.requests) == 5
    dis = [c for c in res["comparison"]["claims"] if c["status"] == "DISAGREED"]
    assert [c["claim_id"] for c in dis] == ["c2", "c4"]
    for c in dis:
        assert c["a"]["reading"] == "yes" and c["b"]["reading"] == "no"
        assert c["a"]["reader_id"] and c["b"]["reader_id"]
        assert c["a"]["reader_id"] != c["b"]["reader_id"]
        assert c["a"]["near_match_id"] == c["b"]["near_match_id"] == c["claim_id"].replace("c", "n")
    assert res["comparison"]["independence"] == "same_provider"
    for led in ("a.jsonl", "b.jsonl"):
        assert verify_file(tmp_path / led).ok is True
        assert len(R.load_readings(tmp_path / led)["readings"]) == 5
    assert "independent" not in json.dumps(res)


def test_human_first_line(tmp_path, capsys):
    with StubLLM(answers=["yes"]) as sa, StubLLM(answers=_b_answers) as sb:
        rc = CLI.main(_argv(tmp_path, sa, sb, "--send"))
    out = capsys.readouterr().out
    assert rc == 0
    assert out.startswith("compared 5 claims: 2 disagreed of 5 read\n")
    assert "not yet informative: fewer than 20 claims read (5)" in out
    assert "DISAGREED c2:" in out and "DISAGREED c4:" in out
    assert "reader a openai_compat:model-a@127.0.0.1: 5 readings written, 0 could not look" in out
    assert out.rstrip().endswith("agreement says nothing about whether a claim holds")
    for word in ("true", "correct", "verified", "independent"):
        assert word not in out.lower()


def test_a_claim_failing_on_one_side_is_missing_not_guessed(tmp_path, capsys):
    def a_fails_3(i, body):
        return StubLLM.FAIL if _n(body) == 3 else "yes"

    with StubLLM(answers=a_fails_3) as sa, StubLLM(answers=["yes"]) as sb:
        rc = CLI.main(_argv(tmp_path, sa, sb, "--send", "--json"))
        res = json.loads(capsys.readouterr().out)
    assert rc == V.EXIT_BAD and res["verdict"] == V.MISSING
    assert res["summary"]["read"] == 4 and res["summary"]["missing"] == 1
    assert [(c["side"], c["claim_id"], c["reason_word"]) for c in res["could_not_look"]] == [
        ("a", "c3", "network")]
    assert "c3" not in {r["claim_id"] for r in R.load_readings(tmp_path / "a.jsonl")["readings"]}


def test_a_claim_failing_on_both_sides_exits_could_not_look(tmp_path, capsys):
    def fails_3(i, body):
        return StubLLM.FAIL if _n(body) == 3 else "yes"

    with StubLLM(answers=fails_3) as sa, StubLLM(answers=fails_3) as sb:
        rc = CLI.main(_argv(tmp_path, sa, sb, "--send", "--json"))
        res = json.loads(capsys.readouterr().out)
    assert res["verdict"] == V.COMPARED and res["summary"]["read"] == 4
    assert rc == V.EXIT_COULD_NOT_LOOK and res["exit"] == V.EXIT_COULD_NOT_LOOK
    assert {c["side"] for c in res["could_not_look"]} == {"a", "b"}


def test_one_reader_on_both_sides_is_refused_before_any_request(tmp_path, capsys):
    with StubLLM(answers=["yes"]) as sa, StubLLM(answers=["yes"]) as sb:
        rc = CLI.main(_argv(tmp_path, sa, sb, "--send", "--json", ma="m", mb="m"))
        res = json.loads(capsys.readouterr().out)
        assert sa.requests == [] and sb.requests == []
    assert rc == V.EXIT_COULD_NOT_LOOK and res["reason_word"] == "bounded"
    assert res["reason"] == "the same reader on both sides"
    s = res["summary"]
    assert s["disagreed"] is None and s["read"] is None and s["counts_reason"]
    assert not (tmp_path / "a.jsonl").exists() and not (tmp_path / "b.jsonl").exists()


def test_one_ledger_on_both_sides_is_usage(tmp_path, capsys):
    with StubLLM(answers=["yes"]) as sa, StubLLM(answers=["yes"]) as sb:
        argv = _argv(tmp_path, sa, sb, "--send")
        argv[argv.index("--ledger-b") + 1] = str(tmp_path / "a.jsonl")
        rc = CLI.main(argv)
        assert sa.requests == [] and sb.requests == []
    assert rc == V.EXIT_USAGE and "two different ledgers" in capsys.readouterr().err


def test_the_criterion_can_come_from_ledger_a(tmp_path, capsys):
    sha = R.freeze_criterion(tmp_path / "a.jsonl", SENTENCE)["criterion_sha256"]
    with StubLLM(answers=["yes"]) as sa, StubLLM(answers=["yes"]) as sb:
        argv = _argv(tmp_path, sa, sb, "--send", "--json")
        i = argv.index("--criterion-file")
        argv[i:i + 2] = ["--criterion-sha256", sha]
        rc = CLI.main(argv)
        res = json.loads(capsys.readouterr().out)
    assert rc == 0 and res["criterion_sha256"] == sha
    assert res["summary"]["disagreed"] == 0 and res["summary"]["read"] == 5
    rows_b = [json.loads(x) for x in (tmp_path / "b.jsonl").read_text(encoding="utf-8").splitlines()]
    assert rows_b[0]["evt"] == "criterion" and rows_b[0]["criterion_sha256"] == sha


def test_run_is_listed_in_the_subcommands(capsys):
    assert CLI.main(["--help"]) == 0
    assert "run" in capsys.readouterr().out
