"""K041: `second-read ask` batches a claims file through one reader, against a
127.0.0.1 stub only. One retry at most; a failed call writes NO reading."""
from __future__ import annotations

import json
import re
import time

import pytest

from arcaeon import verdict as V
from arcaeon.prove import readings as R
from arcaeon.prove import readings_cli as CLI
from arcaeon.prove.readers import DEFAULT_TIMEOUT
from arcaeon.record.ledger import verify_file
from readings.stub_llm import StubLLM
from _load import must_match

SENTENCE = "Does the claim state the dispatch time?"
_N = re.compile(r"claim number (\d+)")


def _claims_file(tmp_path, n=9):
    p = tmp_path / "claims.jsonl"
    p.write_text("".join(json.dumps({"claim_id": f"c{i}", "claim": f"claim number {i}"}) + "\n"
                         for i in range(1, n + 1)), encoding="utf-8")
    return p


def _crit(tmp_path):
    p = tmp_path / "crit.txt"
    p.write_text(SENTENCE, encoding="utf-8")
    return p


def _run(capsys, argv):
    rc = CLI.main(["ask", *argv, "--json"])
    return rc, json.loads(capsys.readouterr().out)


def _every_third_claim_fails(i, body):
    n = int(must_match(_N, body["messages"][0]["content"]).group(1))
    return StubLLM.FAIL if n % 3 == 0 else ("yes" if n % 2 else "no")


def test_every_third_claim_failing_is_absent_from_the_ledger_and_listed(tmp_path, capsys):
    led = tmp_path / "r.jsonl"
    with StubLLM(answers=_every_third_claim_fails) as stub:
        rc, res = _run(capsys, ["--claims", str(_claims_file(tmp_path)),
                                "--reader", "openai_compat:m", "--base-url", stub.url + "/v1",
                                "--ledger", str(led), "--criterion-file", str(_crit(tmp_path)),
                                "--send"])
    failed = {"c3", "c6", "c9"}
    assert rc == V.EXIT_COULD_NOT_LOOK and res["exit"] == V.EXIT_COULD_NOT_LOOK
    assert res["counts"] == {"claims": 9, "written": 6, "could_not_look": 3}
    assert {c["claim_id"] for c in res["could_not_look"]} == failed
    for c in res["could_not_look"]:
        assert c["reason_word"] == "network" and c["looked_for"] and c["where"] == "127.0.0.1"
        assert "no reading was written" in c["reason"]
    # one retry at most: 6 answered once, 3 tried twice
    assert res["requests"] == 12 and len(stub.requests) == 12
    loaded = R.load_readings(led)
    assert loaded["ok"]
    ids = {r["claim_id"] for r in loaded["readings"]}
    assert ids == {f"c{i}" for i in range(1, 10)} - failed
    assert not ids & failed
    words = {r["claim_id"]: r["reading"] for r in loaded["readings"]}
    assert words["c1"] == "yes" and words["c2"] == "no"
    assert verify_file(led).ok is True


def test_one_retry_recovers_a_single_failure(tmp_path, capsys):
    led = tmp_path / "r.jsonl"
    with StubLLM(answers=lambda i, body: StubLLM.FAIL if i == 0 else "yes") as stub:
        rc, res = _run(capsys, ["--claims", str(_claims_file(tmp_path, 2)),
                                "--reader", "openai_compat:m", "--base-url", stub.url + "/v1",
                                "--ledger", str(led), "--criterion-file", str(_crit(tmp_path)),
                                "--send"])
    assert rc == 0 and res["counts"] == {"claims": 2, "written": 2, "could_not_look": 0}
    assert res["requests"] == 3 and res["could_not_look"] == []


def test_garbled_answers_are_listed_with_their_own_reason_word(tmp_path, capsys):
    led = tmp_path / "r.jsonl"
    with StubLLM(answers=[StubLLM.GARBLE]) as stub:
        rc, res = _run(capsys, ["--claims", str(_claims_file(tmp_path, 1)),
                                "--reader", "openai_compat:m", "--base-url", stub.url + "/v1",
                                "--ledger", str(led), "--criterion-file", str(_crit(tmp_path)),
                                "--send"])
    assert rc == V.EXIT_COULD_NOT_LOOK and res["could_not_look"][0]["reason_word"] == "unreadable"
    assert R.load_readings(led)["readings"] == []


def test_a_call_past_its_timeout_is_network_and_writes_nothing(tmp_path, capsys):
    led = tmp_path / "r.jsonl"

    def slow(i, body):
        time.sleep(1.5)
        return "yes"

    with StubLLM(answers=slow) as stub:
        rc, res = _run(capsys, ["--claims", str(_claims_file(tmp_path, 1)),
                                "--reader", "openai_compat:m", "--base-url", stub.url + "/v1",
                                "--ledger", str(led), "--criterion-file", str(_crit(tmp_path)),
                                "--timeout", "0.3", "--send"])
    assert rc == V.EXIT_COULD_NOT_LOOK and res["could_not_look"][0]["reason_word"] == "network"
    assert res["requests"] == 2
    assert R.load_readings(led)["readings"] == []


def test_the_default_timeout_is_30_seconds(tmp_path, capsys, monkeypatch):
    seen = {}
    from arcaeon.prove import readers

    real = readers.reader_from_spec

    def spy(spec, **kw):
        seen.update(kw)
        return real(spec, **kw)

    monkeypatch.setattr(readers, "reader_from_spec", spy)
    rc, _ = _run(capsys, ["--claims", str(_claims_file(tmp_path, 1)), "--reader", "ollama:m",
                          "--ledger", str(tmp_path / "r.jsonl"),
                          "--criterion-file", str(_crit(tmp_path))])
    assert rc == 0 and DEFAULT_TIMEOUT == 30.0 and seen["timeout"] == 30.0


def test_without_send_nothing_is_sent_or_written(tmp_path, capsys):
    led = tmp_path / "r.jsonl"
    with StubLLM(answers=["yes"]) as stub:
        rc, res = _run(capsys, ["--claims", str(_claims_file(tmp_path, 3)),
                                "--reader", "openai_compat:m", "--base-url", stub.url + "/v1",
                                "--ledger", str(led), "--criterion-file", str(_crit(tmp_path))])
    assert rc == 0 and res["sent"] is False and res["requests"] == 0
    assert stub.requests == [] and not led.exists()
    assert res["endpoint_host"] == "127.0.0.1" and res["claims"] == 3
    assert "claim number 1" in res["first_prompt"]


def test_the_criterion_can_come_from_the_ledger(tmp_path, capsys):
    led = tmp_path / "r.jsonl"
    sha = R.freeze_criterion(led, SENTENCE)["criterion_sha256"]
    with StubLLM(answers=["no"]) as stub:
        rc, res = _run(capsys, ["--claims", str(_claims_file(tmp_path, 1)),
                                "--reader", "openai_compat:m", "--base-url", stub.url + "/v1",
                                "--ledger", str(led), "--criterion-sha256", sha, "--send"])
    assert rc == 0 and res["criterion_sha256"] == sha
    rows = [json.loads(x) for x in led.read_text(encoding="utf-8").splitlines()]
    assert [r["evt"] for r in rows] == ["criterion", "reading"]     # not frozen twice


def test_human_output(tmp_path, capsys):
    led = tmp_path / "r.jsonl"
    with StubLLM(answers=_every_third_claim_fails) as stub:
        rc = CLI.main(["ask", "--claims", str(_claims_file(tmp_path, 3)),
                       "--reader", "openai_compat:m", "--base-url", stub.url + "/v1",
                       "--ledger", str(led), "--criterion-file", str(_crit(tmp_path)), "--send"])
    out = capsys.readouterr().out
    assert rc == 3
    assert out.startswith("asked 3 claims of openai_compat:m@127.0.0.1: 2 readings written, "
                          "1 could not look")
    assert "COULD NOT LOOK c3:" in out
    for word in ("true", "correct", "verified", "independent"):
        assert word not in out.lower()


@pytest.mark.parametrize("content,needle", [
    ('{"claim_id": "c1"}\n', "claim must be a string"),
    ('{"claim_id": "c1", "claim": "a"}\n{"claim_id": "c1", "claim": "b"}\n', "twice"),
    ("not json\n", "not JSON"),
    ("", "no claims"),
])
def test_bad_claims_files_are_usage(tmp_path, capsys, content, needle):
    p = tmp_path / "claims.jsonl"
    p.write_text(content, encoding="utf-8")
    rc = CLI.main(["ask", "--claims", str(p), "--reader", "ollama:m",
                   "--ledger", str(tmp_path / "r.jsonl"), "--criterion-file", str(_crit(tmp_path))])
    assert rc == 2 and needle in capsys.readouterr().err


def test_no_criterion_anywhere_is_usage(tmp_path, capsys):
    rc = CLI.main(["ask", "--claims", str(_claims_file(tmp_path, 1)), "--reader", "ollama:m",
                   "--ledger", str(tmp_path / "r.jsonl")])
    assert rc == 2 and "--criterion-file" in capsys.readouterr().err


def test_an_unset_key_variable_is_usage_before_any_request(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("ARCAEON_TEST_ASK_KEY", raising=False)
    with StubLLM(answers=["yes"]) as stub:
        rc = CLI.main(["ask", "--claims", str(_claims_file(tmp_path, 1)),
                       "--reader", "anthropic:m", "--base-url", stub.url,
                       "--key-env", "ARCAEON_TEST_ASK_KEY", "--ledger", str(tmp_path / "r.jsonl"),
                       "--criterion-file", str(_crit(tmp_path)), "--send"])
    assert rc == 2 and stub.requests == []
    assert "ARCAEON_TEST_ASK_KEY is not set" in capsys.readouterr().err
