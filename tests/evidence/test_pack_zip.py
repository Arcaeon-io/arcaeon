"""K068: `evidence-pack --zip`, deterministic.

Sorted entries, fixed times, stored: two builds of the same input at the
same stated build time are byte-identical, and `evidence-pack verify`
accepts the zip, catching a changed byte inside it as it would in a folder.
"""
import hashlib
import json
import zipfile

import pytest

from arcaeon import verdict as V
from arcaeon.prove import evidence_pack_cli, evidence_pack_verify
from arcaeon.prove.evidence_pack import ZIP_DATE_TIME, PackUsageError, build_pack
from arcaeon.prove.evidence_pack_verify import verify_pack

STAMP = "2026-09-27T12:00:00Z"


def _sha(p) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_two_builds_compare_equal_by_sha256(ledger, tmp_path):
    a = build_pack(ledger, tmp_path / "a", built_at=STAMP, zip_out=True,
                   formats=("aat",))
    b = build_pack(ledger, tmp_path / "b", built_at=STAMP, zip_out=True,
                   formats=("aat",))
    za, zb = tmp_path / "a.zip", tmp_path / "b.zip"
    assert a["zip"] == str(za) and b["zip"] == str(zb)
    assert _sha(za) == _sha(zb) == a["zip_sha256"] == b["zip_sha256"]
    with zipfile.ZipFile(za) as zf:
        infos = zf.infolist()
    names = [i.filename for i in infos]
    assert names == sorted(names) == a["files"]
    assert all(i.date_time == ZIP_DATE_TIME and i.compress_type == zipfile.ZIP_STORED
               for i in infos)
    m = json.loads((tmp_path / "a" / "manifest.json").read_text(encoding="utf-8"))
    assert m["built_at"] == STAMP
    assert m["audit_export"]["generated_at"] == STAMP
    assert f"**Generated:** {STAMP}" in (tmp_path / "a" / "ARTICLE_12_SUMMARY.md").read_text(
        encoding="utf-8")


def test_verify_accepts_the_zip(ledger, tmp_path):
    build_pack(ledger, tmp_path / "a", built_at=STAMP, zip_out=True)
    v = verify_pack(tmp_path / "a.zip")
    assert v["verdict"] == V.VERIFIED and v["exit"] == 0, v
    assert v["pack"] == str(tmp_path / "a.zip")
    assert v["zip"]["sha256"] == _sha(tmp_path / "a.zip")


def _rezip(src, dst, edit):
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dst, "w") as zout:
        for i in zin.infolist():
            name, data = edit(i.filename, zin.read(i))
            if name is not None:
                zout.writestr(name, data)


def test_changed_byte_inside_the_zip_is_broken_naming_the_file(ledger, tmp_path):
    build_pack(ledger, tmp_path / "a", built_at=STAMP, zip_out=True)
    bad = tmp_path / "bad.zip"

    def edit(name, data):
        if name == "window.jsonl":
            data = data.replace(b"escalate", b"escalatE", 1)
        return name, data
    _rezip(tmp_path / "a.zip", bad, edit)
    v = verify_pack(bad)
    assert v["verdict"] == V.BROKEN and v["exit"] == 1
    assert "window.jsonl" in v["finding"]


def test_missing_entry_in_the_zip_is_broken_naming_it(ledger, tmp_path):
    build_pack(ledger, tmp_path / "a", built_at=STAMP, zip_out=True)
    bad = tmp_path / "bad.zip"
    _rezip(tmp_path / "a.zip", bad,
           lambda n, d: (None, d) if n == "could_not_look.json" else (n, d))
    v = verify_pack(bad)
    assert v["exit"] == 1 and v["verdict"] == V.BROKEN  # OA1
    assert "could_not_look.json" in v["finding"]


@pytest.mark.parametrize("entry", ["../evil.txt", "sub/extra.txt", "/abs.txt"])
def test_an_entry_outside_the_top_level_is_broken(ledger, tmp_path, entry):
    build_pack(ledger, tmp_path / "a", built_at=STAMP, zip_out=True)
    bad = tmp_path / "bad.zip"
    with zipfile.ZipFile(tmp_path / "a.zip") as zin, zipfile.ZipFile(bad, "w") as zout:
        for i in zin.infolist():
            zout.writestr(i.filename, zin.read(i))
        zout.writestr(entry, b"planted")
    v = verify_pack(bad)
    assert v["verdict"] == V.BROKEN and v["exit"] == 1
    assert "not a plain top-level file" in v["finding"]
    assert not (tmp_path / "evil.txt").exists()


def test_a_file_that_is_not_a_zip_is_could_not_look(tmp_path):
    p = tmp_path / "pack.zip"
    p.write_bytes(b"not a zip")
    v = verify_pack(p)
    assert v["exit"] == 3 and v["reason_word"] == "unreadable"


def test_zip_never_writes_over_an_older_zip(ledger, tmp_path):
    (tmp_path / "a.zip").write_bytes(b"older")
    with pytest.raises(PackUsageError):
        build_pack(ledger, tmp_path / "a", zip_out=True)
    assert (tmp_path / "a.zip").read_bytes() == b"older"
    with pytest.raises(PackUsageError):
        build_pack(ledger, tmp_path / "b", built_at="yesterday")


def test_cli_zip_with_source_date_epoch(ledger, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1790510400")   # 2026-09-27T12:00:00Z
    for d in ("c", "d"):
        rc = evidence_pack_cli.main(["--ledger", str(ledger), "--out", str(tmp_path / d),
                                     "--zip"])
        assert rc == 0
    out = capsys.readouterr().out
    assert "zip: " in out
    assert _sha(tmp_path / "c.zip") == _sha(tmp_path / "d.zip")
    m = json.loads((tmp_path / "c" / "manifest.json").read_text(encoding="utf-8"))
    assert m["built_at"] == STAMP
    assert evidence_pack_verify.main([str(tmp_path / "c.zip")]) == 0
