"""AER-1 (foreign format, issuer zambo.dev) through `receipt verify`.

The fixture is SYNTHETIC: no real AER-1 receipt is on disk and nothing is
downloaded. It is built from the field names in our 9/28 hand check (row
result_sha256, served output_hash, both sha256 hex of the base64-decoded
canonical bytes the issuer's API serves at zambo.dev/api/receipt/<id>).
"""
from __future__ import annotations

import hashlib
import json

import pytest

from arcaeon import verdict as V
from arcaeon.record.receipt import cli
from arcaeon.record.receipt.foreign import aer1

BYTES = b'{"call":"synthetic","output":"hello"}'
DIGEST = hashlib.sha256(BYTES).hexdigest()


def _row(rid="00000000-0000-4000-8000-000000000001", digest=DIGEST, **extra):
    return {"receipt_url": f"https://zambo.dev/r/{rid}", "source": "synthetic",
            "result_sha256": digest, "output_hash": digest, **extra}


def test_detect_true_for_aer1():
    assert aer1.detect(_row())


@pytest.mark.parametrize("obj", [
    {}, [], "x", {"result_sha256": DIGEST},
    {"output_hash": DIGEST},
    _row(receipt_version="arcaeon-receipt/0.1"),
])
def test_detect_false(obj):
    assert not aer1.detect(obj)


def test_verified():
    v = aer1.verify(_row(), BYTES)
    assert v.word == V.VERIFIED and "result_sha256 and output_hash" in v.reason


def test_broken_names_the_field():
    v = aer1.verify(_row(), BYTES + b" ")
    assert v.word == V.BROKEN and "result_sha256" in v.reason
    row = _row()
    row["output_hash"] = "0" * 64
    v = aer1.verify(row, BYTES)
    assert v.word == V.BROKEN and "output_hash" in v.reason and "result_sha256" not in v.reason


def test_could_not_look_names_issuer_api():
    v = aer1.verify(_row(), None)
    assert v.word == V.COULD_NOT_LOOK
    assert "zambo.dev/api/receipt/00000000-0000-4000-8000-000000000001" in v.reason
    assert "fetches nothing" in v.reason


def _run(tmp_path, capsys, text, byte_files=(), prog="arcaeon-receipt"):
    p = tmp_path / "in.json"
    p.write_text(text, encoding="utf-8")
    argv = ["verify", str(p)]
    for i, b in enumerate(byte_files):
        bp = tmp_path / f"b{i}.bin"
        bp.write_bytes(b)
        argv += ["--canonical-bytes", str(bp)]
    rc = cli.main(argv, prog=prog)
    return rc, capsys.readouterr().out.splitlines()


@pytest.mark.parametrize("given,word,code", [
    ([BYTES], V.VERIFIED, 0), ([b"other"], V.BROKEN, 2), ([], V.COULD_NOT_LOOK, 4)])
def test_cli_line_and_exit(tmp_path, capsys, given, word, code):
    rc, out = _run(tmp_path, capsys, json.dumps(_row()), given)
    assert rc == code
    assert out == [out[0]] and out[0].startswith(
        f"AER-1 (foreign format, issuer zambo.dev): {word} -- ")


@pytest.mark.parametrize("given,code", [([BYTES], 0), ([b"other"], 1), ([], 3)])
def test_front_door_exit(tmp_path, capsys, given, code):
    from arcaeon.cli import main as arcaeon_main
    p = tmp_path / "in.json"
    p.write_text(json.dumps(_row()), encoding="utf-8")
    argv = ["receipt", "verify", str(p)]
    for i, b in enumerate(given):
        bp = tmp_path / f"b{i}.bin"
        bp.write_bytes(b)
        argv += ["--canonical-bytes", str(bp)]
    assert arcaeon_main(argv) == code


def test_jsonl_two_receipts_one_line_each(tmp_path, capsys):
    other = b"second"
    rows = [_row(), _row("00000000-0000-4000-8000-000000000002",
                         hashlib.sha256(other).hexdigest())]
    text = "\n".join(json.dumps(r) for r in rows) + "\n"
    rc, out = _run(tmp_path, capsys, text)
    assert rc == 4 and len(out) == 2
    assert all(ln.startswith("AER-1 (foreign format, issuer zambo.dev): COULD NOT LOOK")
               for ln in out)
    assert "000000000002" in out[1]
    rc, out = _run(tmp_path, capsys, text, [BYTES, other])
    assert rc == 0 and len(out) == 2 and all(" VERIFIED -- " in ln for ln in out)
    rc, out = _run(tmp_path, capsys, text, [BYTES, b"tampered"])
    assert rc == 2 and [" BROKEN -- " in ln for ln in out] == [False, True]


def test_bytes_count_mismatch_is_usage_error(tmp_path, capsys):
    text = json.dumps(_row()) + "\n" + json.dumps(_row()) + "\n"
    rc, out = _run(tmp_path, capsys, text, [BYTES])
    assert rc == 1 and out == []
