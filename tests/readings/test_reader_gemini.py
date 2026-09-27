"""K038: the Gemini generateContent reader, against a 127.0.0.1 stub only."""
import pytest

from arcaeon.prove import readings as R
from arcaeon.prove.readers import (PROMPT_TEMPLATE_SHA256, ReaderCallError, ReaderError,
                                   build_prompt)
from arcaeon.prove.readers.gemini import API_VERSION, DEFAULT_BASE_URL, GeminiReader
from readings.stub_llm import StubLLM

SENTENCE = "Does the claim state the dispatch time?"
SECRET = "AIza-test-DO-NOT-LEAK-abcdef0123456789"
ENV = "ARCAEON_TEST_GEMINI_KEY"


@pytest.fixture(autouse=True)
def _key(monkeypatch):
    monkeypatch.setenv(ENV, SECRET)


def _reader(stub, **kw):
    return GeminiReader(base_url=stub.url, model="gemini-stub", key_env=ENV, **kw)


def test_the_default_endpoint_is_google_and_nothing_is_called():
    r = GeminiReader(model="gemini-stub", key_env=ENV)
    assert r.base_url == DEFAULT_BASE_URL
    assert r.endpoint_host == "generativelanguage.googleapis.com"
    assert r.reader_info["provider"] == "google"


def test_a_key_env_is_required():
    with pytest.raises(TypeError):
        GeminiReader(model="m")  # key_env is a required keyword
    with pytest.raises(ReaderError):
        GeminiReader(model="m", key_env=None)


@pytest.mark.parametrize("answer,word", [("yes", "yes"), ("No.", "no"),
                                         ("**Undetermined**", "undetermined"),
                                         ("I would say yes", "undetermined"),
                                         ("", "undetermined")])
def test_same_strict_parse(answer, word):
    with StubLLM(answers=[answer]) as stub:
        row = _reader(stub).read(claim_id="c1", claim_text="x", criterion_text=SENTENCE)
    assert row["reading"] == word
    assert row["rationale_sha256"] == R.sha256_text(answer)


def test_path_headers_body_and_row(tmp_path):
    ledger = tmp_path / "a.jsonl"
    R.freeze_criterion(ledger, SENTENCE)
    with StubLLM(answers=["no"]) as stub:
        row = _reader(stub).read(claim_id="c1", claim_text="dispatched at 0412",
                                 criterion_text=SENTENCE)
        R.write_reading(ledger, row)
    q = stub.requests[0]
    assert q["path"] == f"/{API_VERSION}/models/gemini-stub:generateContent"
    assert SECRET not in q["path"]                      # the key never rides in the URL
    assert q["headers"]["x-goog-api-key"] == SECRET
    assert "authorization" not in q["headers"]
    assert q["body"]["contents"] == [{"role": "user", "parts": [
        {"text": build_prompt(SENTENCE, "dispatched at 0412")}]}]
    assert q["body"]["generationConfig"]["temperature"] == 0
    assert row["reading"] == "no"
    assert row["prompt_template_sha256"] == PROMPT_TEMPLATE_SHA256
    assert row["reader"] == {"id": "google:gemini-stub@127.0.0.1", "provider": "google",
                             "model": "gemini-stub", "endpoint_host": "127.0.0.1"}
    assert SECRET.encode() not in ledger.read_bytes()
    assert R.load_readings(ledger)["ok"]


def test_a_models_prefix_is_not_doubled():
    with StubLLM(answers=["yes"]) as stub:
        GeminiReader(base_url=stub.url, model="models/gemini-stub", key_env=ENV).read(
            claim_id="c1", claim_text="x", criterion_text=SENTENCE)
    assert stub.requests[0]["path"] == f"/{API_VERSION}/models/gemini-stub:generateContent"


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


def test_garbled_answer_is_unreadable():
    with StubLLM(answers=[StubLLM.GARBLE]) as stub:
        with pytest.raises(ReaderCallError) as e:
            _reader(stub).read(claim_id="c1", claim_text="x", criterion_text=SENTENCE)
    assert e.value.reason_word == "unreadable"
