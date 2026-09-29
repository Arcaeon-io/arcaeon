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


# --- AER-1 -03 Section 8 workflow receipts (SYNTHETIC; construction assumed) ---

def _h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _root(digests):
    """Our own helper: leaves in listed order, sha256(left || right) over raw
    digests, odd last node paired with itself."""
    level = [bytes.fromhex(d) for d in digests]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def _workflow(step_bytes, root=None):
    steps = [{"receipt_id": f"step-{i + 1}", "result_sha256": _h(b), "output_hash": _h(b)}
             for i, b in enumerate(step_bytes)]
    return {"receipt_id": "wf-1", "spec_revision": "-03", "goal": "synthetic",
            "output_hash": _h(b"workflow output"), "steps": steps,
            "merkle_root": root or _root([s["result_sha256"] for s in steps])}


TWO = [b'{"step":1}', b'{"step":2}']
THREE = TWO + [b'{"step":3}']


def test_workflow_detected():
    assert aer1.detect_workflow(_workflow(TWO)) and aer1.detect(_workflow(TWO))
    assert not aer1.detect_workflow(_row())
    assert not aer1.detect_workflow({"merkle_root": "00", "steps": "x"})


@pytest.mark.parametrize("parts", [TWO, THREE], ids=["two", "three"])
def test_workflow_verified(parts):
    v = aer1.verify_workflow(_workflow(parts), list(parts))
    assert v.word == V.VERIFIED and f"all {len(parts)} step digests" in v.reason


def test_workflow_step_altered_is_broken_naming_step():
    wf = _workflow(THREE)
    wf["steps"][1]["result_sha256"] = _h(b"altered")
    v = aer1.verify_workflow(wf, list(THREE))
    assert v.word == V.BROKEN and "step 2 (step-2)" in v.reason


def test_workflow_root_other_construction_could_not_look():
    # e.g. sha256 over the concatenated hex strings: a different construction.
    other = _h("".join(_h(b) for b in THREE).encode())
    v = aer1.verify_workflow(_workflow(THREE, root=other), list(THREE))
    assert v.word == V.COULD_NOT_LOOK
    assert "merkle construction unconfirmed against AER-1 -03 section 8" in v.reason


def test_workflow_no_bytes_could_not_look():
    assert aer1.verify_workflow(_workflow(TWO), None).word == V.COULD_NOT_LOOK


def test_workflow_cli_one_bytes_file_per_step(tmp_path, capsys):
    rc, out = _run(tmp_path, capsys, json.dumps(_workflow(THREE)), THREE)
    assert rc == 0 and len(out) == 1 and " VERIFIED -- " in out[0]
    rc, out = _run(tmp_path, capsys, json.dumps(_workflow(THREE)), TWO)
    assert rc == 1 and out == []
