"""The second reader: every claim an evidence pack makes, recomputed from its bytes.

    pytest tests/evidence/test_second_reader.py

The pack is the one the 2026-09-29 second reader demo handed a language model:
the four-row, two-agent fixture ledger (conftest.ROWS), every row in the
window, one head pinned to a local pin file in namespace `acme`, system id
`sys-a`, provider `Demo Provider`. The tampered copy is the demo's: one byte
in records.jsonl row 2 (`lookup` to `lookuq`) and one in README.md (`folder`
to `fo1der`), manifest.json untouched. The model called that copy's chain
head VERIFIED by reading the stored `chain` field; here it is MISMATCH.
"""
from __future__ import annotations

import json
import shutil

import pytest

from arcaeon import verdict as V
from arcaeon.prove import evidence_pack_verify
from arcaeon.prove.evidence_pack import build_pack
from arcaeon.prove.evidence_pack_verify import verify_pack
from arcaeon.prove.second_reader import (ALG_CHAIN, ALG_SHA256, COULD_NOT_LOOK, MISMATCH,
                                         ROW_WORDS, VERIFIED, Report, second_reader)
from arcaeon.record.ledger import Ledger
from arcaeon.record.ledger.witness import WitnessStore, publish_head

NS = "acme"
DEMO_README_SHA = "a890bf5290db02c5102e3283e30e6f685976d2e407f5f1113e2cc6cd01788f9b"
DEMO_RECORDS_SHA = "fb3bb4cb9fee51fb94909c3cd39cfde310ebd4b4b834e39fb0e89dad4759280d"
DEMO_HEAD = "bac3de455350a046f6e21ade25d45e0e"
TAMPERED_README_SHA = "98cd18567db1cc8a0fb04004ee8b8724c2d7939b3776b3c2d70da8ec7eef8c2a"
TAMPERED_RECORDS_SHA = "923bc4cc9bf614325fa1f85ee5db34d95daacaded2aee8969e7253b29895ac9f"


@pytest.fixture
def pins(ledger, tmp_path):
    p = tmp_path / "witness.jsonl"
    publish_head(WitnessStore(p), NS, Ledger(ledger))
    return p


@pytest.fixture
def pack(ledger, pins, tmp_path):
    out = tmp_path / "pack"
    res = build_pack(ledger, out, witness=str(pins), witness_namespace=NS,
                     system_id="sys-a", provider="Demo Provider", zip_out=True)
    assert res["verdict"] == V.VERIFIED, res
    return out


@pytest.fixture
def tampered(pack, tmp_path):
    out = tmp_path / "tampered"
    shutil.copytree(pack, out)
    for name, a, b in (("records.jsonl", b"lookup", b"lookuq"),
                       ("README.md", b"folder", b"fo1der")):
        raw = (out / name).read_bytes()
        assert raw.count(a) == 1, name
        (out / name).write_bytes(raw.replace(a, b))
    return out


def _by(rep, kind):
    return [r for r in rep.rows if r.kind == kind]


def _file(rep, name):
    return next(r for r in rep.rows if r.where == f"manifest.json files[{name}]")


def _head(rep):
    return next(r for r in rep.rows if r.where == "manifest.json chain_head.chain")


def test_the_fixture_is_the_demo_pack(pack):
    """Same bytes the demo recorded: README.md, records.jsonl and the head."""
    rep = second_reader(pack)
    assert _file(rep, "README.md").recomputed == DEMO_README_SHA
    assert _file(rep, "records.jsonl").recomputed == DEMO_RECORDS_SHA
    assert _head(rep).recomputed == DEMO_HEAD


def test_untampered_without_witness_every_row_verified_but_the_pins(pack):
    rep = second_reader(pack)
    pin_rows = _by(rep, "pin")
    assert len(pin_rows) == 1
    assert all(r.verdict == COULD_NOT_LOOK for r in pin_rows)
    assert "--witness" in pin_rows[0].how
    assert all(r.verdict == VERIFIED for r in rep.rows if r.kind != "pin"), \
        [(r.n, r.claim, r.verdict) for r in rep.rows if r.verdict != VERIFIED]
    assert rep.verdict == V.COULD_NOT_LOOK and rep.exit == 3
    assert rep.pack_verify["verdict"] == verify_pack(pack)["verdict"] == V.COULD_NOT_LOOK
    assert rep.counts == {VERIFIED: len(rep.rows) - 1, MISMATCH: 0, COULD_NOT_LOOK: 1}


def test_untampered_with_witness_every_row_verified(pack, pins):
    rep = second_reader(pack, witness=pins)
    assert [r.verdict for r in rep.rows] == [VERIFIED] * len(rep.rows)
    assert _by(rep, "pin")[0].recomputed == {"namespace": NS, "rows": 4, "chain": DEMO_HEAD}
    assert rep.verdict == V.VERIFIED and rep.exit == 0
    assert rep.witness == str(pins)


def test_every_row_shows_both_values_and_names_its_algorithm(pack, pins):
    rep = second_reader(pack, witness=pins)
    assert len(rep.rows) >= 20
    for r in rep.rows:
        assert r.verdict in ROW_WORDS and r.algorithm and r.how and r.where
        assert r.recomputed is not None and r.claimed is not None, r
    assert {r.algorithm for r in _by(rep, "file")} >= {ALG_SHA256}
    assert _head(rep).algorithm == ALG_CHAIN
    # every file the manifest lists has its own row
    listed = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))["files"]
    assert {r.where for r in _by(rep, "file")} >= {f"manifest.json files[{n}]" for n in listed}


def test_tampered_copy_mismatch_on_exactly_the_two_files_and_the_head(tampered, pins):
    for witness in (None, pins):
        rep = second_reader(tampered, witness=witness)
        bad_files = sorted(r.where for r in _by(rep, "file") if r.verdict == MISMATCH)
        assert bad_files == ["manifest.json files[README.md]",
                             "manifest.json files[records.jsonl]"], bad_files
        assert _file(rep, "README.md").recomputed == TAMPERED_README_SHA
        assert _file(rep, "records.jsonl").recomputed == TAMPERED_RECORDS_SHA
        assert _file(rep, "README.md").claimed == DEMO_README_SHA
        head = _head(rep)
        # the stored `chain` of the last row still reads bac3de...: the model's
        # mistake. Recomputed from the rows' content, the head differs.
        assert head.verdict == MISMATCH and head.claimed == DEMO_HEAD
        assert head.recomputed != DEMO_HEAD and len(head.recomputed) == 32
        assert "line 2" in head.how
        assert rep.verdict == V.BROKEN and rep.exit == 1
        assert rep.pack_verify["verdict"] == V.BROKEN


def test_untouched_rows_of_the_tampered_copy_still_verify(tampered):
    """The tamper moved no count, period or tally: those rows stay VERIFIED."""
    rep = second_reader(tampered)
    for key in ("record_count", "period_covered", "event_counts"):
        r = next(x for x in rep.rows if x.where == f"manifest.json audit_export.{key}")
        assert r.verdict == VERIFIED, r


def test_json_round_trips(pack, pins, tampered, tmp_path):
    for p, w in ((pack, None), (pack, pins), (tampered, None)):
        rep = second_reader(p, witness=w)
        again = Report.from_dict(json.loads(rep.to_json()))
        assert again == rep
        assert again.to_dict() == rep.to_dict()


def test_markdown_is_one_table_with_every_row(pack):
    rep = second_reader(pack)
    md = rep.to_markdown()
    table = [x for x in md.splitlines() if x.startswith("|")]
    assert table[0].startswith("| # | Claim | Where the pack makes it | Claimed | Recomputed "
                               "| Verdict | Algorithm | How |")
    assert len(table) == 2 + len(rep.rows)
    assert f"`{DEMO_README_SHA}`" in md


def test_zip_reads_the_same_as_the_folder(pack, pins, tmp_path):
    z = pack.parent / "pack.zip"
    assert z.is_file()
    a, b = second_reader(pack, witness=pins), second_reader(z, witness=pins)
    assert [(r.claim, r.claimed, r.recomputed, r.verdict) for r in a.rows] == \
        [(r.claim, r.claimed, r.recomputed, r.verdict) for r in b.rows]
    assert b.verdict == V.VERIFIED and b.pack == str(z)


def test_a_zip_edited_after_zip_wrote_it_is_broken_on_the_changed_rows(pack, pins, tmp_path):
    """The demo tamper, made inside the .zip: each entry rewritten in the same
    order with a fresh CRC, so the zip is sound and verify's "pack zip" check
    passes. The reader must recompute from the entry bytes, not trust the
    manifest's stored digests or the stored `chain` field."""
    import zipfile
    clean, z = pack.parent / "pack.zip", tmp_path / "tampered.zip"
    edits = {"records.jsonl": (b"lookup", b"lookuq"), "README.md": (b"folder", b"fo1der")}
    with zipfile.ZipFile(clean) as src, zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as dst:
        for info in src.infolist():
            raw = src.read(info)
            if info.filename in edits:
                a, b = edits[info.filename]
                assert raw.count(a) == 1, info.filename
                raw = raw.replace(a, b)
            dst.writestr(info, raw)
    for witness in (None, pins):
        rep = second_reader(z, witness=witness)
        assert rep.rows, rep.pack_verify
        assert not any(c.get("check") == "pack zip"
                       for c in verify_pack(z, witness=witness).get("checks") or [])
        bad_files = sorted(r.where for r in _by(rep, "file") if r.verdict == MISMATCH)
        assert bad_files == ["manifest.json files[README.md]",
                             "manifest.json files[records.jsonl]"], bad_files
        assert _file(rep, "README.md").recomputed == TAMPERED_README_SHA
        assert _file(rep, "records.jsonl").recomputed == TAMPERED_RECORDS_SHA
        head = _head(rep)
        assert head.verdict == MISMATCH and head.claimed == DEMO_HEAD
        assert head.recomputed != DEMO_HEAD
        assert rep.verdict == V.BROKEN and rep.exit == 1 and rep.verdict != V.VERIFIED
        assert rep.pack_verify["verdict"] == V.BROKEN and rep.pack == str(z)


def test_a_listed_file_that_is_gone_is_could_not_look_on_its_row_and_broken(pack):
    (pack / "window.jsonl").unlink()
    rep = second_reader(pack)
    row = _file(rep, "window.jsonl")
    assert row.verdict == COULD_NOT_LOOK and row.recomputed is None
    # pack verify calls a missing listed file BROKEN (OA1): never less here
    assert rep.pack_verify["verdict"] == V.BROKEN and rep.verdict == V.BROKEN


def test_a_planted_file_is_a_mismatch(pack):
    (pack / "extra.txt").write_text("nothing vouches for me", encoding="utf-8")
    rep = second_reader(pack)
    row = next(r for r in rep.rows if r.claim.startswith("the pack holds no file"))
    assert row.verdict == MISMATCH and row.recomputed == ["extra.txt"]
    assert rep.verdict == V.BROKEN


def test_no_pack_at_all_is_could_not_look(tmp_path):
    rep = second_reader(tmp_path / "nowhere")
    assert rep.rows == [] and rep.verdict == V.COULD_NOT_LOOK and rep.exit == 3


def _not_a_zip(pack, tmp_path, kind):
    """A pack.zip that is not a zip: zero bytes, or the first 100 bytes of a real one."""
    z = tmp_path / kind / "pack.zip"
    z.parent.mkdir()
    z.write_bytes(b"" if kind == "empty" else (pack.parent / "pack.zip").read_bytes()[:100])
    return z


@pytest.mark.parametrize("kind", ["empty", "truncated"])
def test_a_pack_zip_that_is_not_a_zip_is_could_not_look(pack, tmp_path, kind):
    """zipfile.ZipFile raises BadZipFile on both; verify turns that into a
    COULD NOT LOOK "pack zip" check (unreadable), and the reader, given no
    folder to read, has no rows and says the same."""
    z = _not_a_zip(pack, tmp_path, kind)
    plain = verify_pack(z)
    assert plain["verdict"] == V.COULD_NOT_LOOK and plain["exit"] == 3
    assert [c.get("check") for c in plain["checks"]] == ["pack zip"]
    rep = second_reader(z)
    assert rep.rows == [] and rep.verdict == V.COULD_NOT_LOOK
    assert rep.exit == plain["exit"] == 3 and rep.pack == str(z)
    assert rep.pack_verify["verdict"] == V.COULD_NOT_LOOK
    assert "could not be read as a zip" in rep.pack_verify.get("reason", "")


@pytest.mark.parametrize("kind", ["empty", "truncated"])
def test_cli_a_pack_zip_that_is_not_a_zip_exits_as_plain_verify(pack, tmp_path, kind, capsys):
    z = _not_a_zip(pack, tmp_path, kind)
    plain = evidence_pack_verify.main([str(z)])
    capsys.readouterr()
    code = evidence_pack_verify.main([str(z), "--second-reader"])
    out, err = capsys.readouterr()
    assert code == plain == 3
    assert "COULD NOT LOOK: second reader" in out
    assert "Traceback" not in err and "Traceback" not in out
    from arcaeon.prove import evidence_pack_cli
    assert evidence_pack_cli.main(["verify", str(z), "--second-reader"]) == 3
    out, err = capsys.readouterr()
    assert "COULD NOT LOOK: second reader" in out and "Traceback" not in err


def _bad_witness(pack, tmp_path, capsys, witness):
    """A --witness path the reader cannot use: the pin row is COULD NOT LOOK
    and names the file, every other row is as the no-witness run has it, exit
    3, no traceback, through the library, verify's main and the verb."""
    plain = second_reader(pack)
    rep = second_reader(pack, witness=witness)
    pin_rows = _by(rep, "pin")
    assert len(pin_rows) == 1
    pin = pin_rows[0]
    assert pin.verdict == COULD_NOT_LOOK and pin.recomputed is None
    assert str(witness) in pin.how, pin.how
    assert rep.witness is not None and rep.witness == str(witness)
    others = [r.to_dict() for r in rep.rows if r.kind != "pin"]
    assert others == [r.to_dict() for r in plain.rows if r.kind != "pin"]
    assert rep.verdict == V.COULD_NOT_LOOK and rep.exit == 3
    capsys.readouterr()
    code = evidence_pack_verify.main([str(pack), "--second-reader", "--witness", str(witness)])
    out, err = capsys.readouterr()
    assert code == 3
    assert "COULD NOT LOOK: second reader" in out and str(witness) in out
    assert "Traceback" not in err and "Traceback" not in out
    from arcaeon.prove import evidence_pack_cli
    code = evidence_pack_cli.main(["verify", str(pack), "--second-reader",
                                   "--witness", str(witness)])
    out, err = capsys.readouterr()
    assert code == 3
    assert "COULD NOT LOOK: second reader" in out and "Traceback" not in err
    assert "Traceback" not in out


def test_a_witness_path_that_does_not_exist_is_could_not_look(pack, tmp_path, capsys):
    _bad_witness(pack, tmp_path, capsys, tmp_path / "no-such-pins.jsonl")


def test_a_witness_path_that_is_a_directory_is_could_not_look(pack, tmp_path, capsys):
    d = tmp_path / "pins-dir"
    d.mkdir()
    _bad_witness(pack, tmp_path, capsys, d)


def test_a_witness_file_that_is_not_json_is_could_not_look(pack, tmp_path, capsys):
    f = tmp_path / "pins.txt"
    f.write_text("this is not a pin file\n{not json either\n", encoding="utf-8")
    _bad_witness(pack, tmp_path, capsys, f)


# --- the CLI ----------------------------------------------------------------

def test_cli_prints_the_table_and_writes_json_and_markdown(pack, pins, tmp_path, capsys):
    j, m = tmp_path / "out" / "r.json", tmp_path / "out" / "r.md"
    j.parent.mkdir()
    code = evidence_pack_verify.main([str(pack), "--second-reader", "--witness", str(pins),
                                      "--json", str(j), "--markdown", str(m)])
    out = capsys.readouterr().out
    assert code == 0
    assert out.splitlines()[0].split()[:6] == ["#", "Claim", "Where", "Claimed",
                                               "Recomputed", "Verdict"]
    assert DEMO_README_SHA in out and out.rstrip().splitlines()[-1].startswith("VERIFIED:")
    rep = Report.from_dict(json.loads(j.read_text(encoding="utf-8")))
    assert rep == second_reader(pack, witness=pins)
    assert m.read_text(encoding="utf-8") == rep.to_markdown()


def test_cli_exit_codes_follow_pack_verify(pack, tampered, capsys):
    assert evidence_pack_verify.main([str(pack), "--second-reader"]) == 3
    assert evidence_pack_verify.main([str(tampered), "--second-reader"]) == 1
    out = capsys.readouterr().out
    assert "MISMATCH" in out and "BROKEN: second reader" in out
    # without the flag, verify prints as it always has
    assert evidence_pack_verify.main([str(pack)]) == 3
    assert capsys.readouterr().out.startswith("COULD NOT LOOK: evidence pack")


def test_cli_through_the_verb(pack, capsys):
    from arcaeon.prove import evidence_pack_cli
    assert evidence_pack_cli.main(["verify", str(pack), "--second-reader"]) == 3
    assert "COULD NOT LOOK: second reader" in capsys.readouterr().out


def test_cli_unwritable_json_path_is_bad_usage(pack, tmp_path, capsys):
    code = evidence_pack_verify.main([str(pack), "--second-reader", "--json",
                                      str(tmp_path / "no" / "such" / "dir" / "r.json")])
    assert code == V.EXIT_USAGE
    assert "could not write" in capsys.readouterr().err


# --- page one's bearer twin (pack schema 2) ----------------------------------

def test_bearer_twin_sentences_are_recomputed(pack):
    """A schema 2 pack's README.json lists each sentence's sha256 and class;
    the reader rehashes the line without its bracket and reads the bracket.
    Written by hand here: main builds schema 1 packs, which have no twin."""
    import hashlib
    line_text = "The records are the rows below."
    readme = pack / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8") + line_text + " [bytes]\n",
                      encoding="utf-8", newline="\n")
    n = len(readme.read_text(encoding="utf-8").split("\n")) - 1
    twin = {"bearer_schema": 1, "page": "README.md", "sentences": [
        {"id": "s.ok", "line": n, "class": "bytes",
         "sha256": hashlib.sha256(line_text.encode()).hexdigest()},
        {"id": "s.bad", "line": n, "class": "asserted", "sha256": "0" * 64}]}
    (pack / "README.json").write_text(json.dumps(twin), encoding="utf-8")
    rows = [r for r in second_reader(pack).rows if r.kind == "sentence"]
    assert [(r.where, r.verdict) for r in rows] == [
        ("README.json sentences[s.ok]", VERIFIED),
        ("README.json sentences[s.ok].class", VERIFIED),
        ("README.json sentences[s.bad]", MISMATCH),
        ("README.json sentences[s.bad].class", MISMATCH)]
