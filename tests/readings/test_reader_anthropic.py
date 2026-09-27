"""K037: the Anthropic Messages reader, against a 127.0.0.1 stub only."""
import pytest

from arcaeon.prove import readings as R
from arcaeon.prove.readers import (PROMPT_TEMPLATE_SHA256, ReaderCallError, ReaderError,
                                   build_prompt)
from arcaeon.prove.readers.anthropic import ANTHROPIC_VERSION, DEFAULT_BASE_URL, AnthropicReader
from readings.stub_llm import StubLLM

SENTENCE = "Does the claim state the dispatch time?"
SECRET = "sk-ant-test-DO-NOT-LEAK-abcdef0123456789"
ENV = "ARCAEON_TEST_ANTHROPIC_KEY"


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv(ENV, SECRET)


def _reader(stub, **kw):
    return AnthropicReader(base_url=stub.url, model="claude-stub", key_env=ENV, **kw)


def test_the_default_endpoint_is_anthropic_and_nothing_is_called():
    r = AnthropicReader(model="claude-stub", key_env=ENV)
    assert r.base_url == DEFAULT_BASE_URL and r.endpoint_host == "api.anthropic.com"
    assert r.reader_info["provider"] == "anthropic"


def test_a_key_env_is_required():
    with pytest.raises(TypeError):
        AnthropicReader(model="m")  # key_env is a required keyword
    with pytest.raises(ReaderError):
        AnthropicReader(model="m", key_env=None)


@pytest.mark.parametrize("answer,word", [("yes", "yes"), ("No.", "no"),
                                         ("undetermined", "undetermined"),
                                         ("I would say yes", "undetermined")])
def test_same_strict_parse(answer, word):
    with StubLLM(answers=[answer]) as stub:
        row = _reader(stub).read(claim_id="c1", claim_text="x", criterion_text=SENTENCE)
    assert row["reading"] == word
    assert row["rationale_sha256"] == R.sha256_text(answer)


def test_headers_body_and_row(tmp_path):
    ledger = tmp_path / "a.jsonl"
    R.freeze_criterion(ledger, SENTENCE)
    with StubLLM(answers=["yes"]) as stub:
        row = _reader(stub).read(claim_id="c1", claim_text="dispatched at 0412",
                                 criterion_text=SENTENCE)
        R.write_reading(ledger, row)
    q = stub.requests[0]
    assert q["path"] == "/v1/messages"
    assert q["headers"]["x-api-key"] == SECRET
    assert q["headers"]["anthropic-version"] == ANTHROPIC_VERSION
    assert "authorization" not in q["headers"]
    assert q["body"]["model"] == "claude-stub" and q["body"]["temperature"] == 0
    assert q["body"]["messages"] == [{"role": "user",
                                      "content": build_prompt(SENTENCE, "dispatched at 0412")}]
    assert row["prompt_template_sha256"] == PROMPT_TEMPLATE_SHA256
    assert row["reader"]["provider"] == "anthropic" and row["reader"]["endpoint_host"] == "127.0.0.1"
    assert SECRET.encode() not in ledger.read_bytes()
    assert R.load_readings(ledger)["ok"]


def test_unset_key_is_refused_before_any_request(monkeypatch):
    monkeypatch.delenv(ENV)
    with StubLLM(answers=["yes"]) as stub:
        with pytest.raises(ReaderError, match=f"{ENV} is not set"):
            _reader(stub).read(claim_id="c1", claim_text="x", criterion_text=SENTENCE)
    assert stub.requests == []


def test_failed_call_is_network_and_never_shows_the_key():
    with StubLLM(answers=[StubLLM.FAIL]) as stub:
        with pytest.raises(ReaderCallError) as e:
            _reader(stub).read(claim_id="c1", claim_text="x", criterion_text=SENTENCE)
    assert e.value.reason_word == "network" and SECRET not in str(e.value)


def test_no_text_block_is_unreadable():
    with StubLLM(answers=[StubLLM.GARBLE]) as stub:
        with pytest.raises(ReaderCallError) as e:
            _reader(stub).read(claim_id="c1", claim_text="x", criterion_text=SENTENCE)
    assert e.value.reason_word == "unreadable"
