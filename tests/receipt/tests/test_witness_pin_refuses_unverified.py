"""The hosted witness pin must never be minted over a ledger that does not verify.

Found 2026-09-19 (internal queue task 156): `_witness_pin`'s hosted branch
POSTed `{rows, chain}` from `ledger.head()` straight to the witness API. On a
corrupt ledger, arcaeon-ledger 0.7.5's `head()` returns chain="genesis", rows=0
without raising, so the hosted path would have published a genesis pin over a
damaged log: the one artifact a stranger is supposed to be able to trust.

The check here must not depend on which arcaeon-ledger is installed: newer
versions put the verdict on Head, older ones do not.
"""
import json

import pytest

from arcaeon.record.ledger import Ledger
from arcaeon.record.receipt import core


class _Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, req, timeout=None):
        self.calls.append(req)

        class _Resp:
            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):
                return False

            def read(self_inner):
                return json.dumps({"pin": {"seq": 1}, "history": "https://example.org/h"}).encode()

        return _Resp()


@pytest.fixture
def hosted(monkeypatch):
    monkeypatch.setenv("ARCAEON_WITNESS_URL", "https://witness.example.org")
    monkeypatch.setenv("ARCAEON_WITNESS_KEY", "test-key")
    rec = _Recorder()
    monkeypatch.setattr(core.urllib.request, "urlopen", rec)
    return rec


def test_control_a_healthy_ledger_is_pinned(tmp_path, hosted):
    """Must-pass arm: if this fails, the refusal test below proves nothing."""
    p = tmp_path / "ok.jsonl"
    led = Ledger(str(p))
    led.append({"a": 1})
    out = core._witness_pin(led, p, "demo-ns")
    assert out["status"] == "pinned"
    assert len(hosted.calls) == 1
    assert out["rows"] == 1


def test_a_corrupt_ledger_is_never_posted_to_the_witness(tmp_path, hosted):
    p = tmp_path / "bad.jsonl"
    p.write_text("{this is not a ledger row\n", encoding="utf-8")
    out = core._witness_pin(Ledger(str(p)), p, "demo-ns")
    assert hosted.calls == [], "a pin request left the machine for a ledger that does not verify"
    assert out["status"] == "pin_refused"
    assert out["kind"] == "hosted"
    assert "unparseable" in out["error"]
    assert out["independence"].startswith("none")


def test_a_ledger_corrupted_after_real_rows_is_never_posted(tmp_path, hosted):
    p = tmp_path / "mixed.jsonl"
    led = Ledger(str(p))
    led.append({"a": 1})
    led.append({"a": 2})
    with open(p, "a", encoding="utf-8") as fh:
        fh.write("{torn row\n")
    out = core._witness_pin(Ledger(str(p)), p, "demo-ns")
    assert hosted.calls == []
    assert out["status"] == "pin_refused"
