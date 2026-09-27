"""K051: `arcaeon evidence-pack` wraps export_bundle; records.jsonl is the ledger, byte for byte."""
import json

import pytest

from arcaeon import verdict as V
from arcaeon.prove import evidence_pack_cli
from arcaeon.prove.evidence_pack import PackUsageError, build_pack


def test_records_byte_equal_to_ledger(ledger, tmp_path):
    out = tmp_path / "pack"
    res = build_pack(ledger, out)
    assert (out / "records.jsonl").read_bytes() == ledger.read_bytes()
    assert res["verdict"] == V.VERIFIED and res["exit"] == 0
    for name in ("records.jsonl", "integrity.json", "ARTICLE_12_SUMMARY.md"):
        assert (out / name).is_file()


def test_crlf_ledger_copied_verbatim(ledger, tmp_path):
    raw = ledger.read_bytes().replace(b"\n", b"\r\n")
    crlf = tmp_path / "crlf.jsonl"
    crlf.write_bytes(raw)
    out = tmp_path / "pack"
    build_pack(crlf, out)
    assert (out / "records.jsonl").read_bytes() == raw


def test_cli_builds_and_exits_zero(ledger, tmp_path, capsys):
    out = tmp_path / "pack"
    rc = evidence_pack_cli.main(["--ledger", str(ledger), "--out", str(out), "--json"])
    assert rc == 0
    res = json.loads(capsys.readouterr().out)
    assert res["verdict"] == V.VERIFIED and res["exit"] == 0
    assert (out / "records.jsonl").read_bytes() == ledger.read_bytes()


def test_non_empty_out_is_usage(ledger, tmp_path):
    out = tmp_path / "pack"
    out.mkdir()
    (out / "old.txt").write_text("x")
    with pytest.raises(PackUsageError):
        build_pack(ledger, out)
    assert evidence_pack_cli.main(["--ledger", str(ledger), "--out", str(out)]) == 2


def test_missing_ledger_is_could_not_look(tmp_path):
    res = build_pack(tmp_path / "nope.jsonl", tmp_path / "pack")
    assert res["verdict"] == V.COULD_NOT_LOOK and res["exit"] == 3
    assert res["reason_word"] == "missing"


def test_broken_ledger_is_broken(ledger, tmp_path):
    lines = ledger.read_bytes().split(b"\n")
    lines[1] = lines[1].replace(b"lookup", b"lookuq")
    ledger.write_bytes(b"\n".join(lines))
    res = build_pack(ledger, tmp_path / "pack")
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
