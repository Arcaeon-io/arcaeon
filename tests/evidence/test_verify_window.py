"""K058: verify step 3, every window row is byte-equal to its records.jsonl line."""
import hashlib
import json

import pytest

from arcaeon import verdict as V
from arcaeon.prove import evidence_pack_cli
from arcaeon.prove.evidence_pack import build_pack
from arcaeon.prove.evidence_pack_verify import verify_pack

CHECK = "window rows equal their records lines"


@pytest.fixture
def pack(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a")  # ledger lines 1 and 3
    return out


def _manifest(out):
    return json.loads((out / "manifest.json").read_text(encoding="utf-8"))


def _write_manifest(out, m):
    (out / "manifest.json").write_text(json.dumps(m, indent=2), encoding="utf-8")


def _fix_hash(out, name):
    m = _manifest(out)
    m["files"][name] = hashlib.sha256((out / name).read_bytes()).hexdigest()
    _write_manifest(out, m)


def _step(res):
    return next(c for c in res["checks"] if c["check"] == CHECK)


def test_untouched_window_verifies(pack):
    res = verify_pack(pack)
    assert res["verdict"] == V.VERIFIED and res["exit"] == 0
    st = _step(res)
    assert st["verdict"] == V.VERIFIED and st["rows_checked"] == 2


def test_edited_window_row_with_hash_fixed_is_broken_naming_the_line(pack):
    win = pack / "window.jsonl"
    raw = win.read_bytes()
    assert raw.count(b"escalate") == 1  # the row from ledger line 3
    win.write_bytes(raw.replace(b"escalate", b"approve"))
    _fix_hash(pack, "window.jsonl")
    res = verify_pack(pack)
    assert res["checks"][0]["verdict"] == V.VERIFIED  # the hash was fixed to hide it
    assert res["checks"][1]["verdict"] == V.VERIFIED  # records.jsonl is untouched
    st = _step(res)
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    assert st["verdict"] == V.BROKEN and st["differ_lines"] == [3]
    assert "line 3" in st["finding"] and "line 3" in res["finding"]


def test_edited_window_row_via_cli_exit_1(pack, capsys):
    win = pack / "window.jsonl"
    win.write_bytes(win.read_bytes().replace(b"system_start", b"system_begin"))
    _fix_hash(pack, "window.jsonl")
    rc = evidence_pack_cli.main(["verify", str(pack)])
    assert rc == 1
    out = capsys.readouterr().out
    assert out.startswith("BROKEN") and "line 1" in out


def test_renumbered_row_is_broken(pack):
    win = pack / "window.jsonl"
    rows = [json.loads(l) for l in win.read_text(encoding="utf-8").splitlines()]
    rows[0]["line"] = 2  # the raw text is line 1's, not line 2's
    win.write_bytes("".join(json.dumps(r) + "\n" for r in rows).encode("utf-8"))
    _fix_hash(pack, "window.jsonl")
    res = verify_pack(pack)
    assert res["verdict"] == V.BROKEN
    assert 2 in _step(res)["differ_lines"]


def test_dropped_window_row_disagrees_with_manifest(pack):
    win = pack / "window.jsonl"
    lines = win.read_bytes().splitlines(keepends=True)
    win.write_bytes(lines[0])
    _fix_hash(pack, "window.jsonl")
    res = verify_pack(pack)
    assert res["verdict"] == V.BROKEN
    assert "the manifest lists [1, 3]" in _step(res)["finding"]


def test_missing_window_is_broken(pack):
    (pack / "window.jsonl").unlink()
    res = verify_pack(pack)
    st = _step(res)
    assert st["verdict"] == V.COULD_NOT_LOOK and st["reason_word"] == "missing"
    # OA1: the manifest lists window.jsonl, so the pack is BROKEN naming it
    assert res["exit"] == 1 and "window.jsonl" in res["finding"]


def test_crlf_records_still_match(ledger, tmp_path):
    ledger.write_bytes(ledger.read_bytes().replace(b"\n", b"\r\n"))
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-b")
    st = _step(verify_pack(out))
    assert st["verdict"] == V.VERIFIED and st["rows_checked"] == 2


def test_window_compares_raw_bytes_not_json_meaning(pack):
    """Same JSON meaning, different bytes (one space added): BROKEN, not equal."""
    win = pack / "window.jsonl"
    rows = [json.loads(l) for l in win.read_text(encoding="utf-8").splitlines()]
    assert json.loads(rows[1]["raw"]) == json.loads(rows[1]["raw"].replace(":", ": ", 1))
    rows[1]["raw"] = rows[1]["raw"].replace(":", ": ", 1)
    win.write_bytes("".join(json.dumps(r) + "\n" for r in rows).encode("utf-8"))
    _fix_hash(pack, "window.jsonl")
    st = _step(verify_pack(pack))
    assert st["verdict"] == V.BROKEN and st["differ_lines"] == [3]


def test_tail_cut_with_head_rewritten_is_broken_by_the_window(ledger, tmp_path):
    """Cut the last record, fix every hash and rewrite chain_head to the cut
    head: the chain step is fooled, the window still names line 4."""
    from arcaeon.record.ledger import Ledger
    out = tmp_path / "pack"
    build_pack(ledger, out)  # every row, lines 1 to 4
    rec = out / "records.jsonl"
    rec.write_bytes(b"".join(rec.read_bytes().splitlines(keepends=True)[:3]))
    head = Ledger(rec).head()
    m = _manifest(out)
    m["chain_head"].update({"chain": head.chain, "rows": head.rows})
    m["pins"] = []
    m["files"]["records.jsonl"] = hashlib.sha256(rec.read_bytes()).hexdigest()
    _write_manifest(out, m)
    res = verify_pack(out)
    chain = next(c for c in res["checks"] if c["check"] == "records chain and head")
    assert chain["verdict"] == V.VERIFIED  # the rewrite fooled step 2
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    assert _step(res)["differ_lines"] == [4]
