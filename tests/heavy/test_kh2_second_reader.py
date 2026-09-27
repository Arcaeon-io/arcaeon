"""KH2: the second reader, end to end.

One 24-claim fixture (kh2_claims.jsonl) and one frozen sentence
(kh2_criterion.txt) go through the whole second-read path, every step as the
real `arcaeon` command in a subprocess:

  1. three backends against 127.0.0.1 stubs: `second-read ask` through the
     OpenAI-compatible, Anthropic Messages and Gemini readers. A dry run first
     (zero requests), then --send: 24 readings each, the right wire shape, the
     key sent in its header and never written to the ledger.
  2. two models on the same fixture: `second-read run` with a careful stub
     model (OpenAI-compatible) and a hasty one (Gemini) that differs on four
     claims (three flipped, one rambling answer the strict parse files as
     undetermined).
  3. `second-read compare A B --receipt`: 4 disagreed of 24 read, every
     DISAGREED claim carrying both reader ids; `receipt verify` passes.
  4. that receipt inside an evidence pack (`evidence-pack --readings
     --readings-ledger --zip`), then `evidence-pack verify` on the folder and
     on the zip: VERIFIED. An edited count in the pack's copy is BROKEN.

The live test (marked `live`, skipped by default) runs steps 2 to 4 against
the local ollama with two small models, `qwen2.5-coder:3b` and
`qwen2.5-coder:1.5b` (3B or smaller only: a 7B spills to CPU). It talks to
127.0.0.1:11434 and nothing else.

ARCAEON_HOME points into tmp_path for every subprocess. Every stub this file
starts is stopped by its `with` block.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path

import pytest

from arcaeon.record.ledger import Ledger, verify_file
from readings.stub_llm import StubLLM

HERE = Path(__file__).resolve().parent
CLAIMS = HERE / "kh2_claims.jsonl"
CRITERION = HERE / "kh2_criterion.txt"
BUILT_AT = "2026-09-27T12:00:00Z"
KEY_ENV = "KH2_STUB_KEY"
KEY_VALUE = "kh2-stub-key-value-never-in-a-ledger"

#: What the hasty model answers where it parts from the careful one.
HASTY_DIFFERS = {"c03": "No.", "c13": "no", "c17": "No, it names no clock time.",
                 "c20": "Well, that depends on what you count as a time."}

LIVE_MODELS = ("qwen2.5-coder:3b", "qwen2.5-coder:1.5b")

_CLAIM_IN_PROMPT = re.compile(r"Claim:\n(.*?)\n\nAnswer:", re.S)


def _fixture() -> list[dict]:
    return [json.loads(line) for line in CLAIMS.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def _prompt_of(body) -> str:
    """The prompt text, from any of the three request shapes."""
    if "messages" in body:
        return body["messages"][0]["content"]
    return body["contents"][0]["parts"][0]["text"]


def _answers(hasty: bool):
    by_text = {c["claim"]: c for c in _fixture()}

    def answer(_i, body):
        claim = by_text[_CLAIM_IN_PROMPT.search(_prompt_of(body)).group(1)]
        if hasty and claim["claim_id"] in HASTY_DIFFERS:
            return HASTY_DIFFERS[claim["claim_id"]]
        return {"yes": "Yes, it names a time.", "no": "no"}[claim["expect"]]
    return answer


def _env(home: Path) -> dict:
    env = dict(os.environ)
    env["ARCAEON_HOME"] = str(home)
    env[KEY_ENV] = KEY_VALUE
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        env.pop(k, None)
    return env


def _arcaeon(env: dict, *args, timeout: float = 120) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "arcaeon", *map(str, args)], env=env,
                          capture_output=True, text=True, encoding="utf-8", timeout=timeout)


def _json_of(cp: subprocess.CompletedProcess) -> dict:
    assert cp.stdout.strip(), f"no stdout; stderr: {cp.stderr}"
    return json.loads(cp.stdout)


@pytest.fixture()
def home(tmp_path, monkeypatch):
    h = tmp_path / "arcaeon-home"
    h.mkdir()
    monkeypatch.setenv("ARCAEON_HOME", str(h))
    return h


def _source_ledger(tmp_path: Path) -> Path:
    """The agent ledger the pack is built over: four rows, one agent."""
    p = tmp_path / "agent.jsonl"
    lg = Ledger(p)
    for row in ({"ts": "2026-09-27T10:00:00Z", "agent": "kh2-agent", "event": "system_start"},
                {"ts": "2026-09-27T10:05:00Z", "agent": "kh2-agent", "event": "tool_call",
                 "inputs": {"q": "second read of 24 claims"}},
                {"ts": "2026-09-27T10:20:00Z", "agent": "kh2-agent", "event": "decision",
                 "decision": "file the disagreements"},
                {"ts": "2026-09-27T10:30:00Z", "agent": "kh2-agent", "event": "system_stop"}):
        lg.append(row)
    return p


# --- 1. three backends against loopback stubs --------------------------------

BACKENDS = {
    # name: (spec, extra args, request path check, key header, key header value)
    "openai_compat": ("openai_compat:stub-careful", lambda url: ["--base-url", url + "/v1"],
                      lambda p: p == "/v1/chat/completions", "authorization",
                      f"Bearer {KEY_VALUE}"),
    "anthropic": ("anthropic:stub-claude", lambda url: ["--base-url", url],
                  lambda p: p == "/v1/messages", "x-api-key", KEY_VALUE),
    "gemini": ("gemini:stub-gemini", lambda url: ["--base-url", url],
               lambda p: p == "/v1beta/models/stub-gemini:generateContent",
               "x-goog-api-key", KEY_VALUE),
}


@pytest.mark.parametrize("backend", sorted(BACKENDS))
def test_each_backend_reads_all_24_claims_against_a_stub(backend, home, tmp_path):
    spec, extra, path_ok, key_header, key_sent = BACKENDS[backend]
    env = _env(home)
    ledger = tmp_path / f"{backend}.jsonl"
    with StubLLM(answers=_answers(hasty=False)) as stub:
        base = ["second-read", "ask", "--claims", CLAIMS, "--reader", spec, "--ledger", ledger,
                "--criterion-file", CRITERION, "--key-env", KEY_ENV, *extra(stub.url), "--json"]
        dry = _arcaeon(env, *base)
        assert dry.returncode == 0, dry.stderr
        assert _json_of(dry)["requests"] == 0 and not stub.requests and not ledger.exists()
        cp = _arcaeon(env, *base, "--send")
        n_requests = len(stub.requests)
        requests = list(stub.requests)
    assert cp.returncode == 0, cp.stderr
    res = _json_of(cp)
    assert res["counts"] == {"claims": 24, "written": 24, "could_not_look": 0}
    assert n_requests == 24 == res["requests"]
    assert all(path_ok(r["path"]) for r in requests), [r["path"] for r in requests]
    assert all(r["headers"].get(key_header) == key_sent for r in requests)
    raw = ledger.read_bytes()
    assert KEY_VALUE.encode() not in raw
    assert verify_file(ledger).ok is True
    readings = [r for r in Ledger(ledger) if isinstance(r, dict) and r.get("evt") == "reading"]
    assert len(readings) == 24
    assert {r["reader"]["id"] for r in readings} == {res["reader"]["id"]}
    assert res["reader"]["endpoint_host"] == "127.0.0.1"
    got = {r["claim_id"]: r["reading"] for r in readings}
    assert got == {c["claim_id"]: c["expect"] for c in _fixture()}


# --- 2 to 4. two models, compare, receipt, pack ------------------------------

def _compare_receipt_pack(env: dict, tmp_path: Path, ledger_a: Path, ledger_b: Path,
                          id_a: str, id_b: str) -> dict:
    """compare --receipt, receipt verify, pack, pack verify (folder and zip).
    Returns what the steps showed, for the caller's own asserts."""
    receipt = tmp_path / "second_read.receipt.json"
    cp = _arcaeon(env, "second-read", "compare", ledger_a, ledger_b, "--receipt", receipt,
                  "--json")
    cmp = _json_of(cp)
    assert cp.returncode == cmp["exit"] == 0, cp.stdout
    assert cmp["verdict"] == "COMPARED"
    human = _arcaeon(env, "second-read", "compare", ledger_a, ledger_b)
    assert human.returncode == 0, human.stderr
    s = cmp["summary"]
    assert human.stdout.splitlines()[0] == (f"compared 24 claims: {s['disagreed']} disagreed "
                                            f"of {s['read']} read")
    for c in cmp["claims"]:
        if c["status"] == "DISAGREED":
            assert (c["a"]["reader_id"], c["b"]["reader_id"]) == (id_a, id_b), c
    assert "independent" not in json.dumps(cmp)

    rv = _arcaeon(env, "receipt", "verify", receipt)
    assert rv.returncode == 0, rv.stdout + rv.stderr

    receipt_ledger = Path(cmp["receipt"]["ledger"])
    pack = tmp_path / "pack"
    built = _arcaeon(env, "evidence-pack", "--ledger", _source_ledger(tmp_path), "--out", pack,
                     "--agent", "kh2-agent", "--readings", receipt,
                     "--readings-ledger", receipt_ledger, "--zip", "--built-at", BUILT_AT,
                     "--json")
    b = _json_of(built)
    assert built.returncode == b["exit"] == 0, built.stdout
    assert b["verdict"] == "VERIFIED" and b["readings"]["ok"] is True
    assert b["readings"]["ledger_status"] == "consistent"
    assert (pack / "readings_receipt.json").read_bytes() == receipt.read_bytes()

    verified = {}
    for target in (pack, Path(b["zip"])):
        vp = _arcaeon(env, "evidence-pack", "verify", target, "--json")
        v = _json_of(vp)
        assert vp.returncode == v["exit"] == 0, vp.stdout
        assert v["verdict"] == "VERIFIED"
        step = next(c for c in v["checks"] if c["check"] == "second-read receipt")
        assert step["receipt_verify"]["verdict"] == "VERIFIED", step
        verified[target.name] = v
    readme = (pack / "README.md").read_text(encoding="utf-8")
    assert "## The second read" in readme and "receipt verify: passes" in readme

    # An edited count in the pack's copy of the receipt does not verify.
    p = pack / "readings_receipt.json"
    rc = json.loads(p.read_text(encoding="utf-8"))
    rc["checks"][0]["summary"]["disagreed"] = 0
    p.write_text(json.dumps(rc, indent=2), encoding="utf-8")
    tampered = _arcaeon(env, "evidence-pack", "verify", pack, "--json")
    t = _json_of(tampered)
    assert tampered.returncode == t["exit"] == 1 and t["verdict"] == "BROKEN", tampered.stdout
    assert "readings_receipt.json" in t["finding"]
    return {"compare": cmp, "human": human.stdout, "built": b, "verified": verified,
            "readme": readme}


def test_two_models_one_fixture_compare_receipt_pack(home, tmp_path):
    env = _env(home)
    la, lb = tmp_path / "careful.jsonl", tmp_path / "hasty.jsonl"
    with StubLLM(answers=_answers(hasty=False)) as a, StubLLM(answers=_answers(hasty=True)) as b:
        cp = _arcaeon(env, "second-read", "run", "--claims", CLAIMS,
                      "--criterion-file", CRITERION, "--send", "--json",
                      "--reader-a", "openai_compat:stub-careful", "--ledger-a", la,
                      "--base-url-a", a.url + "/v1",
                      "--reader-b", "gemini:stub-hasty", "--ledger-b", lb,
                      "--base-url-b", b.url, "--key-env-b", KEY_ENV)
        requests = len(a.requests) + len(b.requests)
    run = _json_of(cp)
    assert cp.returncode == run["exit"] == 0, cp.stdout
    assert requests == 48 == run["requests"]
    assert run["summary"]["disagreed"] == 4 and run["summary"]["read"] == 24
    assert run["summary"]["not_yet_informative"] is False
    id_a, id_b = run["readers"]["a"]["id"], run["readers"]["b"]["id"]
    assert id_a != id_b

    seen = _compare_receipt_pack(env, tmp_path, la, lb, id_a, id_b)
    cmp = seen["compare"]
    assert cmp["independence"] == "distinct_provider_self_asserted"
    disagreed = {c["claim_id"]: (c["a"]["reading"], c["b"]["reading"])
                 for c in cmp["claims"] if c["status"] == "DISAGREED"}
    assert disagreed == {"c03": ("yes", "no"), "c13": ("yes", "no"), "c17": ("yes", "no"),
                         "c20": ("no", "undetermined")}
    assert seen["human"].splitlines()[0] == "compared 24 claims: 4 disagreed of 24 read"
    assert KEY_VALUE.encode() not in lb.read_bytes()


# --- live: the local ollama, two small models (skipped by default) -----------

@pytest.fixture()
def live_ollama():
    try:
        with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=5) as resp:
            names = {m.get("name") for m in json.load(resp).get("models", [])}
    except (OSError, ValueError):
        pytest.skip("live test: ollama is not answering on 127.0.0.1:11434")
    missing = [m for m in LIVE_MODELS if m not in names]
    if missing:
        pytest.skip(f"live test: not pulled in the local ollama: {', '.join(missing)}")


@pytest.mark.live
def test_live_two_local_models_compare_receipt_pack(live_ollama, home, tmp_path):
    env = _env(home)
    la, lb = tmp_path / "ollama-3b.jsonl", tmp_path / "ollama-1.5b.jsonl"
    cp = _arcaeon(env, "second-read", "run", "--claims", CLAIMS, "--criterion-file", CRITERION,
                  "--send", "--json", "--timeout", "120",
                  "--reader-a", f"ollama:{LIVE_MODELS[0]}", "--ledger-a", la,
                  "--reader-b", f"ollama:{LIVE_MODELS[1]}", "--ledger-b", lb, timeout=1800)
    run = _json_of(cp)
    assert cp.returncode == run["exit"] == 0, cp.stdout + cp.stderr
    assert run["could_not_look"] == []
    s = run["summary"]
    assert s["read"] == 24 and 0 <= s["disagreed"] <= 24
    assert s["not_yet_informative"] is False
    id_a, id_b = run["readers"]["a"]["id"], run["readers"]["b"]["id"]
    assert id_a == f"ollama:{LIVE_MODELS[0]}@127.0.0.1"
    assert id_b == f"ollama:{LIVE_MODELS[1]}@127.0.0.1"
    for led in (la, lb):
        assert verify_file(led).ok is True

    seen = _compare_receipt_pack(env, tmp_path, la, lb, id_a, id_b)
    cmp = seen["compare"]
    assert cmp["independence"] == "same_provider"
    fixture = {c["claim_id"]: c["expect"] for c in _fixture()}
    print()
    print(seen["human"].rstrip())
    for side, led in (("a", la), ("b", lb)):
        got = {r["claim_id"]: r["reading"] for r in Ledger(led)
               if isinstance(r, dict) and r.get("evt") == "reading"}
        match = sum(got[k] == v for k, v in fixture.items())
        print(f"reader {side} {run['readers'][side]['id']}: {match} of 24 match the fixture's "
              f"expected reading")
    print(f"pack verify: folder {seen['verified']['pack']['verdict']}, zip "
          f"{seen['verified']['pack.zip']['verdict']}")
