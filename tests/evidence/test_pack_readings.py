"""K067: `evidence-pack --readings RECEIPT`, a second-read comparison receipt.

The receipt's bytes are copied to readings_receipt.json (its ledger, with
--readings-ledger, to readings_receipt.ledger.jsonl). `receipt verify` runs
on the copy at build and again on every pack verify, so an edited count is
BROKEN with the body-digest reason even when every pack hash is fixed.

The receipt here is issued straight through arcaeon.record.receipt.core,
shaped as a comparison of two readers' ledgers (both heads, the counts): the
same core call `second-read compare --receipt` issues through.
"""
import hashlib
import json
from pathlib import Path

import pytest

from arcaeon import verdict as V
from arcaeon.prove import evidence_pack_cli
from arcaeon.prove.evidence_pack import (READINGS_LEDGER, READINGS_RECEIPT, PackUsageError,
                                         build_pack)
from arcaeon.prove.evidence_pack_verify import verify_pack
from arcaeon.record.receipt.core import build_receipt, save_receipt


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _receipt(tmp_path) -> tuple[Path, Path]:
    led = tmp_path / "receipts.jsonl"
    rc = build_receipt(
        "second_read_compare",
        {"a": {"ledger": "reader-a.jsonl", "rows": 5, "chain": "a" * 32},
         "b": {"ledger": "reader-b.jsonl", "rows": 5, "chain": "b" * 32}},
        [{"name": "compare", "read": 5, "agreed": 3, "disagreed": 2,
          "not_yet_informative": True}],
        {"proves": ["the two ledgers' heads and the compare counts at issue"],
         "does_not_prove": ["that either reading is true"]},
        ledger_path=led, namespace="second-read", witness=False, anchor=False,
        issued_at="2026-09-27T12:00:00Z")
    out = save_receipt(rc, tmp_path / "compare.receipt.json")
    return out, led


def _m(out):
    return json.loads((out / "manifest.json").read_text(encoding="utf-8"))


def _rehash(out, *names):
    m = _m(out)
    for n in names:
        m["files"][n] = _sha((out / n).read_bytes())
    (out / "manifest.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
    (out / "manifest.sha256").write_bytes(
        f"{_sha((out / 'manifest.json').read_bytes())}  manifest.json\n".encode("ascii"))


def test_receipt_with_its_ledger_verifies(ledger, tmp_path):
    rc, led = _receipt(tmp_path)
    out = tmp_path / "pack"
    res = build_pack(ledger, out, readings=rc, readings_ledger=led)
    assert res["verdict"] == V.VERIFIED and res["exit"] == 0, res
    assert (out / READINGS_RECEIPT).read_bytes() == rc.read_bytes()
    assert (out / READINGS_LEDGER).read_bytes() == led.read_bytes()
    m = _m(out)
    assert m["readings"]["ok"] is True and m["readings"]["kind"] == "second_read_compare"
    assert m["readings"]["ledger_status"] == "consistent"
    for n in (READINGS_RECEIPT, READINGS_LEDGER):
        assert m["files"][n] == _sha((out / n).read_bytes())
    assert "## The second read" in (out / "README.md").read_text(encoding="utf-8")
    v = verify_pack(out)
    assert v["exit"] == 0, v
    step = next(c for c in v["checks"] if c["check"] == "second-read receipt")
    assert step["receipt_verify"]["verdict"] == V.VERIFIED
    assert step["ledger_status"] == "consistent"


def test_edited_count_is_broken_with_the_body_digest_reason(ledger, tmp_path):
    rc, led = _receipt(tmp_path)
    out = tmp_path / "pack"
    build_pack(ledger, out, readings=rc, readings_ledger=led)
    p = out / READINGS_RECEIPT
    p.write_bytes(p.read_bytes().replace(b'"disagreed": 2', b'"disagreed": 0', 1))
    v = verify_pack(out)
    assert v["verdict"] == V.BROKEN and READINGS_RECEIPT in v["finding"]
    _rehash(out, READINGS_RECEIPT)
    v = verify_pack(out)
    assert v["verdict"] == V.BROKEN and v["exit"] == 1
    assert "readings_receipt.json fails receipt verify" in v["finding"]
    assert "body digest mismatch" in v["finding"]


def test_edited_receipt_ledger_is_broken(ledger, tmp_path):
    rc, led = _receipt(tmp_path)
    out = tmp_path / "pack"
    build_pack(ledger, out, readings=rc, readings_ledger=led)
    p = out / READINGS_LEDGER
    p.write_bytes(p.read_bytes().replace(b'"checks":1', b'"checks":2', 1)
                  .replace(b'"checks": 1', b'"checks": 2', 1))
    assert p.read_bytes() != led.read_bytes()
    _rehash(out, READINGS_LEDGER)
    v = verify_pack(out)
    assert v["exit"] == 1 and "fails receipt verify" in v["finding"]


def test_without_its_ledger_the_tie_is_not_checked_and_says_so(ledger, tmp_path):
    rc, _ = _receipt(tmp_path)
    out = tmp_path / "pack"
    res = build_pack(ledger, out, readings=rc)
    assert res["exit"] == 0
    m = _m(out)
    assert m["readings"]["ledger"] is None
    assert m["readings"]["ledger_status"] == "not_checked"
    assert "ledger row was not" in m["readings"]["ledger_note"]
    assert not (out / READINGS_LEDGER).exists()
    assert verify_pack(out)["exit"] == 0


def test_a_failing_receipt_builds_broken(ledger, tmp_path):
    rc, led = _receipt(tmp_path)
    body = json.loads(rc.read_text(encoding="utf-8"))
    body["checks"][0]["agreed"] = 5
    rc.write_text(json.dumps(body), encoding="utf-8")
    out = tmp_path / "pack"
    res = build_pack(ledger, out, readings=rc, readings_ledger=led)
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    assert "body digest mismatch" in res["finding"]
    assert verify_pack(out)["exit"] == 1


def test_missing_receipt_is_could_not_look(ledger, tmp_path):
    out = tmp_path / "pack"
    res = build_pack(ledger, out, readings=tmp_path / "nope.json")
    assert res["exit"] == 3 and res["reason_word"] == "missing"
    assert verify_pack(out)["exit"] == 3
    with pytest.raises(PackUsageError):
        build_pack(ledger, tmp_path / "p2", readings_ledger=tmp_path / "x.jsonl")


def test_unreadable_receipt_is_could_not_look(ledger, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"a": 1, "a": 2}', encoding="utf-8")
    out = tmp_path / "pack"
    res = build_pack(ledger, out, readings=bad)
    assert res["exit"] == 3 and res["reason_word"] == "unreadable"


def test_cli_flags(ledger, tmp_path, capsys):
    rc, led = _receipt(tmp_path)
    out = tmp_path / "pack"
    code = evidence_pack_cli.main(["--ledger", str(ledger), "--out", str(out),
                                   "--readings", str(rc), "--readings-ledger", str(led),
                                   "--json"])
    res = json.loads(capsys.readouterr().out)
    assert code == 0 and res["readings"]["ok"] is True
