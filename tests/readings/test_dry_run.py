"""K046: outbound disclosure, dry run by default.

Sending a claim to a third-party model is a disclosure. Without `--send`,
`ask` and `run` print the endpoint host, the claim count and the first claim
as it would be sent, and make no request. A 127.0.0.1 stub counts requests:
zero without `--send`, for every backend.
"""
from __future__ import annotations

import json

import pytest

from arcaeon.prove import readings_cli as CLI
from readings.stub_llm import StubLLM

SENTENCE = "Does the claim state the dispatch time?"
FIRST = "Unit 12 was dispatched at 14:02."
KEY_ENV = "ARCAEON_TEST_DRY_RUN_KEY"


@pytest.fixture
def files(tmp_path):
    claims = tmp_path / "claims.jsonl"
    claims.write_text(json.dumps({"claim_id": "c1", "claim": FIRST}) + "\n"
                      + json.dumps({"claim_id": "c2", "claim": "A second claim."}) + "\n"
                      + json.dumps({"claim_id": "c3", "claim": "A third claim."}) + "\n",
                      encoding="utf-8")
    crit = tmp_path / "crit.txt"
    crit.write_text(SENTENCE, encoding="utf-8")
    return claims, crit


def _spec(preset, stub):
    """(reader spec, extra args) pointing a preset at the stub."""
    if preset == "openai_compat":
        return "openai_compat:m", ["--base-url", stub.url + "/v1"]
    return f"{preset}:m", ["--base-url", stub.url, "--key-env", KEY_ENV]


@pytest.mark.parametrize("preset", ["openai_compat", "anthropic", "gemini"])
def test_ask_without_send_makes_no_request(tmp_path, files, capsys, monkeypatch, preset):
    monkeypatch.setenv(KEY_ENV, "sk-dry-run-test-key-not-real")
    claims, crit = files
    led = tmp_path / "r.jsonl"
    with StubLLM(answers=["yes"]) as stub:
        spec, extra = _spec(preset, stub)
        rc = CLI.main(["ask", "--claims", str(claims), "--reader", spec, *extra,
                       "--ledger", str(led), "--criterion-file", str(crit)])
        assert stub.requests == []
    out = capsys.readouterr().out
    assert rc == 0
    assert out.startswith("dry run: nothing sent. would send 3 claims to 127.0.0.1 ")
    assert "first claim as it would be sent:" in out and FIRST in out
    assert "A second claim." not in out
    assert "sk-dry-run-test-key-not-real" not in out
    assert not led.exists()


@pytest.mark.parametrize("preset", ["openai_compat", "anthropic", "gemini"])
def test_run_without_send_makes_no_request(tmp_path, files, capsys, monkeypatch, preset):
    monkeypatch.setenv(KEY_ENV, "sk-dry-run-test-key-not-real")
    claims, crit = files
    with StubLLM(answers=["yes"]) as sa, StubLLM(answers=["no"]) as sb:
        spec_a, extra_a = _spec(preset, sa)
        spec_b, extra_b = _spec("openai_compat", sb)
        extra_a = [x + "-a" if x.startswith("--") else x for x in extra_a]
        extra_b = [x + "-b" if x.startswith("--") else x for x in extra_b]
        rc = CLI.main(["run", "--claims", str(claims),
                       "--reader-a", spec_a, *extra_a, "--ledger-a", str(tmp_path / "a.jsonl"),
                       "--reader-b", spec_b.replace(":m", ":other"), *extra_b,
                       "--ledger-b", str(tmp_path / "b.jsonl"),
                       "--criterion-file", str(crit), "--json"])
        assert sa.requests == [] and sb.requests == []
    res = json.loads(capsys.readouterr().out)
    assert rc == 0 and res["exit"] == 0
    assert res["sent"] is False and res["requests"] == 0 and res["claims"] == 3
    assert res["endpoint_hosts"] == {"a": "127.0.0.1", "b": "127.0.0.1"}
    assert FIRST in res["first_prompt"] and "A second claim." not in res["first_prompt"]
    s = res["summary"]
    assert s["disagreed"] is None and s["read"] is None and s["counts_reason"]
    assert not (tmp_path / "a.jsonl").exists() and not (tmp_path / "b.jsonl").exists()


def test_run_dry_run_human_output(tmp_path, files, capsys):
    claims, crit = files
    with StubLLM(answers=["yes"]) as sa, StubLLM(answers=["yes"]) as sb:
        rc = CLI.main(["run", "--claims", str(claims),
                       "--reader-a", "openai_compat:ma", "--base-url-a", sa.url + "/v1",
                       "--ledger-a", str(tmp_path / "a.jsonl"),
                       "--reader-b", "openai_compat:mb", "--base-url-b", sb.url + "/v1",
                       "--ledger-b", str(tmp_path / "b.jsonl"), "--criterion-file", str(crit)])
        assert sa.requests == [] and sb.requests == []
    lines = capsys.readouterr().out.splitlines()
    assert rc == 0
    assert lines[0] == ("dry run: nothing sent. would send 3 claims to 127.0.0.1 "
                        "(openai_compat:ma@127.0.0.1) and to 127.0.0.1 "
                        "(openai_compat:mb@127.0.0.1); add --send to send")
    assert lines[1] == "first claim as it would be sent:"
    assert FIRST in lines


def test_a_dry_run_never_reads_the_key(tmp_path, files, capsys, monkeypatch):
    """No key is needed to see what would be sent; an unset key only matters with --send."""
    monkeypatch.delenv(KEY_ENV, raising=False)
    claims, crit = files
    with StubLLM(answers=["yes"]) as stub:
        rc = CLI.main(["ask", "--claims", str(claims), "--reader", "anthropic:m",
                       "--base-url", stub.url, "--key-env", KEY_ENV,
                       "--ledger", str(tmp_path / "r.jsonl"), "--criterion-file", str(crit)])
        assert stub.requests == []
    assert rc == 0


def test_send_is_what_makes_the_requests(tmp_path, files, capsys):
    """The control: the same command with --send reaches the stub, once per claim."""
    claims, crit = files
    with StubLLM(answers=["yes"]) as stub:
        rc = CLI.main(["ask", "--claims", str(claims), "--reader", "openai_compat:m",
                       "--base-url", stub.url + "/v1", "--ledger", str(tmp_path / "r.jsonl"),
                       "--criterion-file", str(crit), "--send"])
        assert len(stub.requests) == 3
    assert rc == 0


def test_the_library_defaults_to_the_dry_run(tmp_path, files):
    from arcaeon.prove.readers import reader_from_spec
    claims_path, _ = files
    claims = CLI.load_claims(claims_path)
    with StubLLM(answers=["yes"]) as sa, StubLLM(answers=["yes"]) as sb:
        ra = reader_from_spec("openai_compat:ma", base_url=sa.url + "/v1")
        rb = reader_from_spec("openai_compat:mb", base_url=sb.url + "/v1")
        one = CLI.ask(claims, ra, tmp_path / "r.jsonl", criterion_text=SENTENCE)
        two = CLI.run(claims, ra, rb, tmp_path / "a.jsonl", tmp_path / "b.jsonl",
                      criterion_text=SENTENCE)
        assert sa.requests == [] and sb.requests == []
    assert one["sent"] is False and one["requests"] == 0
    assert two["sent"] is False and two["requests"] == 0
