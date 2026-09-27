"""K064: `evidence-pack --format aat` inside the pack, checked on verify.

The pack gains aat.jsonl and aat_gaps.json, both listed in the manifest.
Verify recomputes the AAT chain from records.jsonl: one changed byte in
either file is BROKEN naming it, with or without its manifest hash fixed.
"""
import hashlib
import json

import pytest

from arcaeon import verdict as V
from arcaeon.prove import evidence_pack_cli
from arcaeon.prove.aat_export import WHICH_CHAIN, chain_records
from arcaeon.prove.evidence_pack import PackUsageError, build_pack
from arcaeon.prove.evidence_pack_verify import verify_pack

CHECK = "aat export"


def _step(res):
    return next(c for c in res["checks"] if c["check"] == CHECK)


def _m(out):
    return json.loads((out / "manifest.json").read_text(encoding="utf-8"))


def _seal(out, m, *fixed):
    for name in fixed:
        m["files"][name] = hashlib.sha256((out / name).read_bytes()).hexdigest()
    (out / "manifest.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
    h = hashlib.sha256((out / "manifest.json").read_bytes()).hexdigest()
    (out / "manifest.sha256").write_bytes(f"{h}  manifest.json\n".encode("ascii"))


@pytest.fixture
def pack(ledger, tmp_path):
    out = tmp_path / "pack"
    res = build_pack(ledger, out, agent="agent-a", formats=("aat",))
    assert res["exit"] == 0
    return out


def test_aat_files_in_pack_and_manifest(pack):
    m = _m(pack)
    for name in ("aat.jsonl", "aat_gaps.json"):
        assert (pack / name).is_file()
        assert m["files"][name] == hashlib.sha256((pack / name).read_bytes()).hexdigest()
    assert m["aat"]["file"] == "aat.jsonl" and m["aat"]["records"] == 4
    assert m["aat"]["which_chain"] == WHICH_CHAIN
    assert len(m["aat"]["head"]) == 64


def test_untouched_pack_verifies_and_recomputes_the_chain(pack):
    res = verify_pack(pack)
    assert res["verdict"] == V.VERIFIED and res["exit"] == 0
    step = _step(res)
    assert step["verdict"] == V.VERIFIED and step["head"] == _m(pack)["aat"]["head"]


@pytest.mark.parametrize("name", ["aat.jsonl", "aat_gaps.json"])
def test_one_changed_byte_is_broken_naming_the_file(pack, name):
    p = pack / name
    raw = bytearray(p.read_bytes())
    i = raw.index(b"a", 20)
    raw[i] = ord("b")
    p.write_bytes(bytes(raw))
    res = verify_pack(pack)
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    assert name in res["finding"]


@pytest.mark.parametrize("name", ["aat.jsonl", "aat_gaps.json"])
def test_changed_byte_with_hash_fixed_is_broken_by_recompute(pack, name):
    p = pack / name
    raw = p.read_bytes()
    new = raw.replace(b"agent-a", b"agent-z", 1)
    assert new != raw
    p.write_bytes(new)
    _seal(pack, _m(pack), name)
    res = verify_pack(pack)
    assert res["checks"][0]["verdict"] == V.VERIFIED  # the hash hides it
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    assert _step(res)["verdict"] == V.BROKEN and name in _step(res)["finding"]


def test_rechained_rewrite_with_head_fixed_is_broken(pack):
    """Edit a record, rechain the whole file, fix hash and head: still BROKEN."""
    p = pack / "aat.jsonl"
    recs = [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines()]
    recs[1]["action_type"] = "decision"
    lines, head, _ = chain_records(recs)
    p.write_bytes(b"".join(b + b"\n" for b in lines))
    m = _m(pack)
    m["aat"]["head"] = head
    _seal(pack, m, "aat.jsonl")
    res = verify_pack(pack)
    assert res["verdict"] == V.BROKEN
    assert "aat.jsonl differs from the export recomputed from records.jsonl, first at " \
           "line 2" in _step(res)["finding"]


def test_deleted_aat_file_never_exits_0(pack):
    (pack / "aat.jsonl").unlink()
    res = verify_pack(pack)
    # OA1: the manifest lists it, so its absence is BROKEN naming it
    assert res["exit"] == 1 and res["verdict"] == V.BROKEN
    assert "aat.jsonl" in res["finding"]


def test_pack_without_aat_has_nothing_to_check(ledger, tmp_path):
    out = tmp_path / "plain"
    build_pack(ledger, out, agent="agent-a")
    assert not (out / "aat.jsonl").exists() and "aat" not in _m(out)
    res = verify_pack(out)
    assert res["exit"] == 0 and "without --format aat" in _step(res)["note"]


def test_unknown_format_is_usage(ledger, tmp_path):
    with pytest.raises(PackUsageError):
        build_pack(ledger, tmp_path / "x", formats=("csv",))


def test_cli_format_aat(ledger, tmp_path):
    out = tmp_path / "cli"
    assert evidence_pack_cli.main(["--ledger", str(ledger), "--out", str(out),
                                   "--agent", "agent-a", "--format", "aat"]) == 0
    assert (out / "aat.jsonl").is_file()
    assert evidence_pack_cli.main(["verify", str(out)]) == 0
    with pytest.raises(SystemExit):
        evidence_pack_cli.main(["--ledger", str(ledger), "--out", str(tmp_path / "y"),
                                "--format", "csv"])
