"""K056: `evidence-pack verify` step 1 rehashes every file the manifest lists."""
import json

import pytest

from arcaeon import verdict as V
from arcaeon.prove import evidence_pack_cli
from arcaeon.prove.evidence_pack import build_pack
from arcaeon.prove.evidence_pack_verify import verify_pack


@pytest.fixture
def pack(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a")
    return out


def _flip_one_byte(p):
    b = bytearray(p.read_bytes())
    i = b.index(b"agent-a")
    b[i] = ord("A")
    p.write_bytes(bytes(b))


def test_untouched_pack_verifies(pack):
    res = verify_pack(pack)
    assert res["verdict"] == V.VERIFIED and res["exit"] == 0
    step = res["checks"][0]
    assert step["check"] == "file hashes" and step["verdict"] == V.VERIFIED
    assert step["changed"] == [] and step["missing"] == [] and step["unlisted"] == []
    assert step["files_checked"] >= 6


def test_one_changed_byte_in_window_is_broken_naming_it(pack):
    _flip_one_byte(pack / "window.jsonl")
    res = verify_pack(pack)
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    assert res["checks"][0]["changed"] == ["window.jsonl"]
    assert "window.jsonl" in res["finding"]


def test_cli_one_changed_byte_exit_1(pack, capsys):
    _flip_one_byte(pack / "window.jsonl")
    rc = evidence_pack_cli.main(["verify", str(pack)])
    assert rc == 1
    out = capsys.readouterr().out
    assert out.startswith("BROKEN") and "window.jsonl" in out


def test_cli_json(pack, capsys):
    rc = evidence_pack_cli.main(["verify", str(pack), "--json"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == V.VERIFIED


def test_unlisted_file_is_broken(pack):
    (pack / "extra.txt").write_text("slipped in", encoding="utf-8")
    res = verify_pack(pack)
    assert res["verdict"] == V.BROKEN
    assert res["checks"][0]["unlisted"] == ["extra.txt"]


@pytest.mark.parametrize("name", ["could_not_look.json", "README.md", "records.jsonl"])
def test_listed_file_gone_is_broken_naming_it(pack, name, capsys):
    """OA1: the manifest names the file, so its absence is tampering."""
    (pack / name).unlink()
    res = verify_pack(pack)
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    assert res["checks"][0]["missing"] == [name]
    assert f"listed in the manifest and missing from the pack: {name}" in res["finding"]
    assert evidence_pack_cli.main(["verify", str(pack)]) == 1
    assert name in capsys.readouterr().out


def test_deleting_cnl_file_does_not_hide_manifest_incomplete(pack):
    """OA1 (the audit's R1): drop `checks`, delete could_not_look.json, unlist it
    and reseal manifest.sha256; the pack stays BROKEN "manifest incomplete"."""
    import hashlib
    m = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
    del m["checks"]
    del m["files"]["could_not_look.json"]
    (pack / "could_not_look.json").unlink()
    raw = json.dumps(m, indent=2).encode("utf-8")
    (pack / "manifest.json").write_bytes(raw)
    (pack / "manifest.sha256").write_text(
        f"{hashlib.sha256(raw).hexdigest()}  manifest.json\n", encoding="utf-8")
    res = verify_pack(pack)
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    assert "manifest incomplete" in res["finding"]


def test_no_manifest_or_no_pack_is_could_not_look(pack, tmp_path):
    assert verify_pack(tmp_path / "nowhere")["exit"] == 3
    (pack / "manifest.json").unlink()
    res = verify_pack(pack)
    assert res["verdict"] == V.COULD_NOT_LOOK and res["reason_word"] == "missing"
    (pack / "manifest.json").write_text("[1, 2]", encoding="utf-8")
    assert verify_pack(pack)["reason_word"] == "unreadable"


def test_missing_ledger_message_names_no_folder(tmp_path, capsys):
    rc = evidence_pack_cli.main(["--ledger", str(tmp_path / "nope.jsonl"),
                                 "--out", str(tmp_path / "pack")])
    assert rc == 3
    out = capsys.readouterr().out
    assert "None" not in out
    assert out.startswith("COULD NOT LOOK: no evidence pack written (missing:")


def test_nested_unlisted_file_is_broken(pack):
    """A file planted in a subfolder is in the pack; nothing vouches for it."""
    (pack / "extra" / "deeper").mkdir(parents=True)
    (pack / "extra" / "deeper" / "forged.jsonl").write_text("{}\n", encoding="utf-8")
    res = verify_pack(pack)
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    assert res["checks"][0]["unlisted"] == ["extra/deeper/forged.jsonl"]
    assert "extra/deeper/forged.jsonl" in res["finding"]


def test_nested_file_named_like_a_listed_one_is_still_unlisted(pack):
    (pack / "sub").mkdir()
    (pack / "sub" / "records.jsonl").write_bytes((pack / "records.jsonl").read_bytes())
    res = verify_pack(pack)
    assert res["verdict"] == V.BROKEN
    assert res["checks"][0]["unlisted"] == ["sub/records.jsonl"]
