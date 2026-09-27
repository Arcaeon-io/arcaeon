"""K039: the `ollama:<model>` preset, and one live read on this laptop.

The preset tests run by default against a 127.0.0.1 stub. The live test is
marked `live` and is skipped unless the run selects it (`-m live`); no `live`
marker is registered until K143, so the skip is done here, with a reason. It
uses a 3B-or-smaller model only (`qwen2.5-coder:3b`): a 7B spills to CPU and
steals the live CLI's cycles. It talks to 127.0.0.1:11434 and nothing else.
"""
import json
import urllib.request

import pytest

from arcaeon.prove import readings as R
from arcaeon.prove.readers import (OLLAMA_BASE_URL, PRESETS, ReaderError, build_prompt,
                                   reader_from_spec)
from arcaeon.prove.readers.anthropic import AnthropicReader
from arcaeon.prove.readers.gemini import GeminiReader
from arcaeon.prove.readers.openai_compat import OpenAICompatReader
from arcaeon.record.ledger import verify_file
from readings.stub_llm import StubLLM

LIVE_MODEL = "qwen2.5-coder:3b"
SENTENCE = "Does the claim state a time of day?"


# --- the preset (default run, stub only) ------------------------------------

def test_ollama_preset_is_the_openai_compatible_reader_on_loopback():
    r = reader_from_spec("ollama:qwen2.5-coder:3b")
    assert isinstance(r, OpenAICompatReader)
    assert OLLAMA_BASE_URL == "http://127.0.0.1:11434/v1"
    assert r.base_url == OLLAMA_BASE_URL and r.model == "qwen2.5-coder:3b"
    assert r.reader_info == {"id": "ollama:qwen2.5-coder:3b@127.0.0.1", "provider": "ollama",
                             "model": "qwen2.5-coder:3b", "endpoint_host": "127.0.0.1"}
    assert r.key_env is None


def test_ollama_preset_refuses_another_host():
    with pytest.raises(ReaderError, match="openai_compat"):
        reader_from_spec("ollama:m", base_url="https://example.invalid/v1")


@pytest.mark.parametrize("spec", ["ollama", "ollama:", "nope:m", "", None])
def test_bad_specs_are_refused(spec):
    with pytest.raises(ReaderError):
        reader_from_spec(spec)


def test_other_presets(monkeypatch):
    assert set(PRESETS) == {"ollama", "openai_compat", "anthropic", "gemini"}
    assert isinstance(reader_from_spec("anthropic:c", key_env="K"), AnthropicReader)
    assert isinstance(reader_from_spec("gemini:g", key_env="K"), GeminiReader)
    with pytest.raises(ReaderError):
        reader_from_spec("anthropic:c")
    with pytest.raises(ReaderError):
        reader_from_spec("openai_compat:m")
    r = reader_from_spec("openai_compat:m", base_url="http://127.0.0.1:9/v1", reader_id="me")
    assert r.reader_id == "me" and r.provider == "openai_compat"


def test_preset_reader_speaks_the_openai_shape_to_a_stub():
    with StubLLM(answers=["yes"]) as stub:
        r = reader_from_spec("openai_compat:qwen2.5-coder:3b", base_url=stub.url + "/v1")
        row = r.read(claim_id="c1", claim_text="at 0412", criterion_text=SENTENCE)
    assert stub.requests[0]["path"] == "/v1/chat/completions"
    assert stub.requests[0]["body"]["model"] == "qwen2.5-coder:3b"
    assert stub.requests[0]["body"]["messages"][0]["content"] == build_prompt(SENTENCE, "at 0412")
    assert row["reading"] == "yes"


# --- live (skipped by default) -----------------------------------------------

@pytest.fixture()
def live_ollama(request):
    if "live" not in (request.config.getoption("markexpr") or ""):
        pytest.skip("live test: calls the local ollama; run with -m live "
                    "(no live marker is registered until K143)")
    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=5) as resp:
            names = {m.get("name") for m in json.load(resp).get("models", [])}
    except (OSError, ValueError):
        pytest.skip("live test: ollama is not answering on 127.0.0.1:11434")
    if LIVE_MODEL not in names:
        pytest.skip(f"live test: {LIVE_MODEL} is not pulled in the local ollama")


@pytest.mark.live
def test_live_read_through_local_ollama(live_ollama, tmp_path):
    ledger = tmp_path / "live.jsonl"
    R.freeze_criterion(ledger, SENTENCE)
    reader = reader_from_spec(f"ollama:{LIVE_MODEL}", timeout=120)
    for cid, text in (("c1", "The unit was dispatched at 04:12 in the morning."),
                      ("c2", "The caller asked for an ambulance.")):
        row = reader.read(claim_id=cid, claim_text=text, criterion_text=SENTENCE)
        assert row["reading"] in R.READING_WORDS
        assert row["reader"]["provider"] == "ollama"
        assert row["reader"]["endpoint_host"] == "127.0.0.1"
        assert "rationale" not in row
        R.write_reading(ledger, row)
    loaded = R.load_readings(ledger)
    assert loaded["ok"] and len(loaded["readings"]) == 2
    assert verify_file(ledger).ok is True
