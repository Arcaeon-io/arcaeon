"""K036: the OpenAI-compatible reader, against a 127.0.0.1 stub only."""
import json

import pytest

from arcaeon.prove import readings as R
from arcaeon.prove import readings_compare as C
from arcaeon.prove.readers import (PROMPT_TEMPLATE_SHA256, ReaderCallError, ReaderError,
                                   build_prompt, parse_answer)
from arcaeon.prove.readers.openai_compat import OpenAICompatReader
from readings.stub_llm import StubLLM

SENTENCE = "Does the claim state the dispatch time?"
SECRET = "sk-test-DO-NOT-LEAK-0123456789abcdef"


def _reader(stub, **kw):
    return OpenAICompatReader(base_url=stub.url + "/v1", model="stub-model", **kw)


@pytest.mark.parametrize("answer,word", [
    ("yes", "yes"), ("Yes.", "yes"), ("NO", "no"), ("no, it does not", "no"),
    ("undetermined", "undetermined"), ("**Yes**", "yes"), ("  yes\n", "yes"),
    ("Well, I think yes", "undetermined"), ("", "undetermined"), ("yesno", "undetermined"),
    ("The claim states a time, so the answer is yes.", "undetermined"), ("maybe", "undetermined"),
])
def test_strict_first_word(answer, word):
    assert parse_answer(answer) == word


def test_parse_non_text_is_undetermined():
    assert parse_answer(None) == "undetermined"


def test_yes_and_no_become_rows(tmp_path):
    with StubLLM(answers=["yes", "no"]) as stub:
        r = _reader(stub)
        y = r.read(claim_id="c1", claim_text="dispatched at 0412", criterion_text=SENTENCE)
        n = r.read(claim_id="c2", claim_text="units cleared", criterion_text=SENTENCE)
    assert (y["reading"], n["reading"]) == ("yes", "no")
    req = stub.requests[0]
    assert req["path"] == "/v1/chat/completions"
    assert req["body"]["model"] == "stub-model" and req["body"]["temperature"] == 0
    prompt = req["body"]["messages"][0]["content"]
    assert prompt == build_prompt(SENTENCE, "dispatched at 0412")
    assert y["prompt_sha256"] == R.sha256_text(prompt)
    assert y["prompt_template_sha256"] == PROMPT_TEMPLATE_SHA256
    assert y["criterion_sha256"] == R.sha256_text(SENTENCE)
    assert y["claim_sha256"] == R.sha256_text("dispatched at 0412")
    assert y["reader"] == {"id": f"openai_compat:stub-model@127.0.0.1",
                           "provider": "openai_compat", "model": "stub-model",
                           "endpoint_host": "127.0.0.1"}
    assert y["rationale_sha256"] == R.sha256_text("yes") and "rationale" not in y


def test_rambling_is_undetermined_with_the_raw_digest():
    ramble = "Well, it depends on what you mean by dispatch."
    with StubLLM(answers=[ramble]) as stub:
        row = _reader(stub).read(claim_id="c1", claim_text="x", criterion_text=SENTENCE)
    assert row["reading"] == "undetermined"
    assert row["rationale_sha256"] == R.sha256_text(ramble)


def test_keep_text_keeps_the_answer():
    with StubLLM(answers=["no, not stated"]) as stub:
        row = _reader(stub).read(claim_id="c1", claim_text="x", criterion_text=SENTENCE,
                                 keep_text=True, near_match_id="c7")
    assert row["rationale"] == "no, not stated" and row["near_match_id"] == "c7"


def test_the_key_comes_from_the_named_env_and_never_reaches_the_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_TEST_READER_KEY", SECRET)
    ledger = tmp_path / "b.jsonl"
    R.freeze_criterion(ledger, SENTENCE)
    with StubLLM(answers=["yes", "no", "hmm"]) as stub:
        r = _reader(stub, key_env="ARCAEON_TEST_READER_KEY")
        assert SECRET not in repr(r) and SECRET not in json.dumps(r.reader_info)
        for i in range(3):
            R.write_reading(ledger, r.read(claim_id=f"c{i}", claim_text=f"claim {i}",
                                           criterion_text=SENTENCE))
    assert all(q["headers"]["authorization"] == f"Bearer {SECRET}" for q in stub.requests)
    body = ledger.read_bytes()
    assert SECRET.encode() not in body and b"ARCAEON_TEST_READER_KEY" not in body
    res = R.load_readings(ledger)
    assert res["ok"] and [x["reading"] for x in res["readings"]] == ["yes", "no", "undetermined"]


def test_no_key_env_sends_no_authorization():
    with StubLLM(answers=["yes"]) as stub:
        _reader(stub).read(claim_id="c1", claim_text="x", criterion_text=SENTENCE)
    assert "authorization" not in stub.requests[0]["headers"]


def test_unset_key_env_names_the_variable_not_a_value(monkeypatch):
    monkeypatch.delenv("ARCAEON_TEST_UNSET_KEY", raising=False)
    with StubLLM(answers=["yes"]) as stub:
        r = _reader(stub, key_env="ARCAEON_TEST_UNSET_KEY")
        with pytest.raises(ReaderError, match="ARCAEON_TEST_UNSET_KEY is not set"):
            r.read(claim_id="c1", claim_text="x", criterion_text=SENTENCE)
    assert stub.requests == []


def test_a_failed_call_is_an_error_not_a_reading(monkeypatch):
    monkeypatch.setenv("ARCAEON_TEST_READER_KEY", SECRET)
    with StubLLM(answers=[StubLLM.FAIL]) as stub:
        r = _reader(stub, key_env="ARCAEON_TEST_READER_KEY")
        with pytest.raises(ReaderCallError) as e:
            r.read(claim_id="c1", claim_text="x", criterion_text=SENTENCE)
    assert e.value.reason_word == "network" and SECRET not in str(e.value)


def test_garbled_answer_is_unreadable():
    with StubLLM(answers=[StubLLM.GARBLE]) as stub:
        with pytest.raises(ReaderCallError) as e:
            _reader(stub).read(claim_id="c1", claim_text="x", criterion_text=SENTENCE)
    assert e.value.reason_word == "unreadable"


def test_nothing_listening_is_network():
    r = OpenAICompatReader(base_url="http://127.0.0.1:9/v1", model="m", timeout=2)
    with pytest.raises(ReaderCallError) as e:
        r.read(claim_id="c1", claim_text="x", criterion_text=SENTENCE)
    assert e.value.reason_word == "network"


@pytest.mark.parametrize("url", ["", "ftp://x/v1", "127.0.0.1:11434", "http:///v1"])
def test_bad_base_url_is_refused(url):
    with pytest.raises(ReaderError):
        OpenAICompatReader(base_url=url, model="m")


def test_two_stub_readers_compare(tmp_path):
    """End to end: two readers on two ledgers line up through compare."""
    claims = [(f"c{i}", f"claim {i}") for i in range(5)]
    paths = []
    with StubLLM(answers=["yes"]) as s1, StubLLM(answers=["yes", "no"]) as s2:
        for name, stub, prov in (("a", s1, "vendor-a"), ("b", s2, "vendor-b")):
            p = tmp_path / f"{name}.jsonl"
            R.freeze_criterion(p, SENTENCE)
            r = _reader(stub, provider=prov)
            for cid, text in claims:
                R.write_reading(p, r.read(claim_id=cid, claim_text=text, criterion_text=SENTENCE))
            paths.append(p)
    res = C.compare(*paths)
    assert res["verdict"] == "COMPARED"
    assert (res["summary"]["disagreed"], res["summary"]["read"]) == (2, 5)
    assert res["summary"]["not_yet_informative"] is True
    assert res["independence"] == "distinct_provider_self_asserted"
