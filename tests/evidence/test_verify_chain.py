"""K057: verify step 2 reruns the chain on records.jsonl and compares its head."""
import hashlib
import json

import pytest

from arcaeon import verdict as V
from arcaeon.prove import evidence_pack_cli
from arcaeon.prove.evidence_pack import build_pack
from arcaeon.prove.evidence_pack_verify import verify_pack


@pytest.fixture
def pack(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out)
    return out


def _manifest(out):
    return json.loads((out / "manifest.json").read_text(encoding="utf-8"))


def _write_manifest(out, m):
    """The attacker who rewrites the manifest fixes manifest.sha256 too."""
    (out / "manifest.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
    h = hashlib.sha256((out / "manifest.json").read_bytes()).hexdigest()
    (out / "manifest.sha256").write_bytes(f"{h}  manifest.json".encode("ascii") + bytes([10]))


def _edit_and_hide(out, old, new):
    """Change one word in records.jsonl, then fix its manifest hash to hide it."""
    rec = out / "records.jsonl"
    raw = rec.read_bytes()
    assert raw.count(old) == 1
    rec.write_bytes(raw.replace(old, new))
    m = _manifest(out)
    m["files"]["records.jsonl"] = hashlib.sha256(rec.read_bytes()).hexdigest()
    _write_manifest(out, m)


def _step(res):
    return next(c for c in res["checks"] if c["check"] == "records chain and head")


def test_untouched_chain_and_head_verify(pack):
    res = verify_pack(pack)
    assert res["verdict"] == V.VERIFIED and res["exit"] == 0
    st = _step(res)
    assert st["verdict"] == V.VERIFIED
    assert st["chain"] == _manifest(pack)["chain_head"]["chain"]


def test_hidden_word_change_is_broken_at_that_row(pack):
    _edit_and_hide(pack, b"escalate", b"approve")  # row 3 of the ledger
    res = verify_pack(pack)
    assert res["checks"][0]["verdict"] == V.VERIFIED  # the hash was fixed to hide it
    st = _step(res)
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    assert st["verdict"] == V.BROKEN
    assert st["break_line"] == 3
    assert "line 3" in st["finding"] and "line 3" in res["finding"]


def test_hidden_change_via_cli_exit_1(pack, capsys):
    _edit_and_hide(pack, b"lookup", b"looked")  # row 2
    rc = evidence_pack_cli.main(["verify", str(pack)])
    assert rc == 1
    out = capsys.readouterr().out
    assert out.startswith("BROKEN") and "line 2" in out


def test_head_mismatch_with_manifest_is_broken(pack):
    m = _manifest(pack)
    m["chain_head"]["chain"] = "0" * 64
    _write_manifest(pack, m)
    res = verify_pack(pack)
    assert res["verdict"] == V.BROKEN
    assert "chain_head" in _step(res)["finding"]


def test_truncated_records_with_hash_fixed_is_broken(pack):
    rec = pack / "records.jsonl"
    lines = rec.read_bytes().splitlines(keepends=True)
    rec.write_bytes(b"".join(lines[:-1]))
    m = _manifest(pack)
    m["files"]["records.jsonl"] = hashlib.sha256(rec.read_bytes()).hexdigest()
    _write_manifest(pack, m)
    res = verify_pack(pack)
    assert res["verdict"] == V.BROKEN
    assert "rows 3" in _step(res)["finding"]


def test_no_chain_head_in_manifest_is_could_not_look(pack):
    m = _manifest(pack)
    del m["chain_head"]
    _write_manifest(pack, m)
    res = verify_pack(pack)
    assert res["verdict"] == V.COULD_NOT_LOOK and res["exit"] == 3
    assert _step(res)["reason_word"] == "unreadable"
