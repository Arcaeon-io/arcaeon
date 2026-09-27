"""K043: seal a readings comparison as a receipt (local, free).

`--receipt OUT` issues the comparison through arcaeon.record.receipt.core,
carrying both ledgers' heads. `arcaeon receipt verify OUT` passes; editing any
count fails with the body-digest reason. No witness, no anchor, no network.
"""
from __future__ import annotations

import json

import pytest

from arcaeon import cli as ARC
from arcaeon.prove import readings as R
from arcaeon.prove import readings_cli as CLI
from arcaeon.prove import readings_compare as C
from arcaeon.record.ledger import Ledger
from arcaeon.record.receipt.core import load_receipt, verify_receipt

SENTENCE = "Does the claim state the dispatch time?"


def _ledger(path, reader_id, provider, readings):
    sha = R.freeze_criterion(path, SENTENCE)["criterion_sha256"]
    reader = {"id": reader_id, "provider": provider, "model": "m", "endpoint_host": None}
    for cid, word in readings.items():
        R.write_reading(path, R.build_reading(
            claim_id=cid, claim_text=f"claim {cid}", criterion_sha256=sha, reader=reader,
            reading=word, near_match_id=f"n-{cid}", prompt_sha256=None))
    return path


@pytest.fixture
def pair(tmp_path):
    a = _ledger(tmp_path / "a.jsonl", "reader-a", "p1",
                {"c1": "yes", "c2": "yes", "c3": "no", "c4": "yes", "c5": "undetermined"})
    b = _ledger(tmp_path / "b.jsonl", "reader-b", "p2",
                {"c1": "yes", "c2": "no", "c3": "no", "c4": "no", "c5": "undetermined"})
    return a, b


def _verify_cli(path, capsys):
    rc = ARC.main(["receipt", "verify", str(path)])
    return rc, capsys.readouterr().out


def test_receipt_verifies_and_carries_both_heads(pair, tmp_path, capsys):
    a, b = pair
    out = tmp_path / "cmp.receipt.json"
    rc = CLI.main(["compare", str(a), str(b), "--receipt", str(out), "--json"])
    res = json.loads(capsys.readouterr().out)
    assert rc == 0 and res["verdict"] == "COMPARED"
    assert res["receipt"]["path"] == str(out) and out.exists()
    rc2, text = _verify_cli(out, capsys)
    assert rc2 == 0, text
    v = json.loads(text)
    assert v["ok"] is True and v["body_digest_ok"] is True
    receipt = load_receipt(out)
    assert receipt["kind"] == C.RECEIPT_KIND
    heads = receipt["subject"]["ledgers"]
    for side, path in (("a", a), ("b", b)):
        h = Ledger(path).head()
        assert heads[side]["rows"] == h.rows and heads[side]["chain"] == h.chain
        assert heads[side]["chain_ok"] is True
    check = receipt["checks"][0]
    assert check["summary"]["disagreed"] == 2 and check["summary"]["read"] == 5
    dis = [c for c in check["claims"] if c["status"] == "DISAGREED"]
    assert [c["claim_id"] for c in dis] == ["c2", "c4"]
    for c in dis:
        assert c["a"]["reader_id"] == "reader-a" and c["b"]["reader_id"] == "reader-b"
        assert c["a"]["near_match_id"] == f"n-{c['claim_id']}"
    assert receipt["witness"] == {"status": "skipped"} and receipt["anchor"] == {"status": "skipped"}
    assert receipt["scope"]["proves"] and receipt["scope"]["does_not_prove"]
    # the receipt row is chained beside OUT, and verifies against it
    led = C.receipt_ledger_for(out)
    assert res["receipt"]["ledger"] == str(led)
    assert verify_receipt(receipt, ledger_path=led)["ledger"]["status"] == "consistent"


@pytest.mark.parametrize("field", ["disagreed", "read", "agreed", "missing", "could_not_look"])
def test_editing_any_count_fails_on_the_body_digest(pair, tmp_path, capsys, field):
    a, b = pair
    out = tmp_path / "cmp.receipt.json"
    assert CLI.main(["compare", str(a), str(b), "--receipt", str(out)]) == 0
    capsys.readouterr()
    receipt = json.loads(out.read_text(encoding="utf-8"))
    receipt["checks"][0]["summary"][field] += 1
    out.write_text(json.dumps(receipt, indent=1), encoding="utf-8")
    rc, text = _verify_cli(out, capsys)
    v = json.loads(text)
    assert rc != 0 and v["ok"] is False and v["body_digest_ok"] is False
    assert any("body digest mismatch" in n for n in v["notes"])


def test_editing_a_head_or_a_status_fails_too(pair, tmp_path, capsys):
    a, b = pair
    out = tmp_path / "cmp.receipt.json"
    assert CLI.main(["compare", str(a), str(b), "--receipt", str(out)]) == 0
    capsys.readouterr()
    base = json.loads(out.read_text(encoding="utf-8"))
    for edit in (lambda r: r["subject"]["ledgers"]["a"].__setitem__("rows", 99),
                 lambda r: r["checks"][0]["claims"][1].__setitem__("status", "AGREED")):
        receipt = json.loads(json.dumps(base))
        edit(receipt)
        assert verify_receipt(receipt)["body_digest_ok"] is False


def test_a_could_not_look_compare_is_receipted_with_null_counts(tmp_path, capsys):
    a = _ledger(tmp_path / "a.jsonl", "reader-a", "p1", {"c1": "yes"})
    out = tmp_path / "cmp.receipt.json"
    rc = CLI.main(["compare", str(a), str(tmp_path / "absent.jsonl"), "--receipt", str(out), "--json"])
    res = json.loads(capsys.readouterr().out)
    assert rc == 3 and res["verdict"] == "COULD NOT LOOK"
    check = load_receipt(out)["checks"][0]
    assert check["verdict"] == "COULD NOT LOOK" and check["exit"] == 3
    assert check["summary"]["disagreed"] is None and check["summary"]["read"] is None
    assert check["summary"]["counts_reason"]
    assert _verify_cli(out, capsys)[0] == 0


def test_run_takes_receipt_too(tmp_path, capsys):
    from readings.stub_llm import StubLLM
    claims = tmp_path / "claims.jsonl"
    claims.write_text("".join(json.dumps({"claim_id": f"c{i}", "claim": f"claim {i}"}) + "\n"
                              for i in range(1, 4)), encoding="utf-8")
    crit = tmp_path / "crit.txt"
    crit.write_text(SENTENCE, encoding="utf-8")
    out = tmp_path / "run.receipt.json"
    with StubLLM(answers=["yes"]) as sa, StubLLM(answers=["no"]) as sb:
        rc = CLI.main(["run", "--claims", str(claims),
                       "--reader-a", "openai_compat:ma", "--base-url-a", sa.url + "/v1",
                       "--ledger-a", str(tmp_path / "a.jsonl"),
                       "--reader-b", "openai_compat:mb", "--base-url-b", sb.url + "/v1",
                       "--ledger-b", str(tmp_path / "b.jsonl"),
                       "--criterion-file", str(crit), "--send", "--receipt", str(out)])
    text = capsys.readouterr().out
    assert rc == 0 and f"receipt written: {out}" in text
    assert load_receipt(out)["checks"][0]["summary"]["disagreed"] == 3
    assert _verify_cli(out, capsys)[0] == 0


def test_no_receipt_words_claim_truth(pair, tmp_path, capsys):
    a, b = pair
    out = tmp_path / "cmp.receipt.json"
    CLI.main(["compare", str(a), str(b), "--receipt", str(out)])
    capsys.readouterr()
    text = out.read_text(encoding="utf-8").lower()
    assert "independent" not in text and "tamper-proof" not in text
    for s in C.RECEIPT_SCOPE["proves"]:
        assert "true" not in s.lower() and "correct" not in s.lower()
