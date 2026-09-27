"""K065: `evidence-pack --deal ID`, the deal pack folded in (roadmap N3).

The ledgers are the ones docs/DEAL.md's worked example builds: every
`$ arcaeon deal` step line in its console blocks (dispute and pack lines
skipped, the pack does that part) is run in order in an empty folder,
giving buyer.jsonl and seller.jsonl with d-demo1 (MATCHED) and d-demo2
(ALTERED).
"""
import hashlib
import json
import re
import shlex
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import evidence_pack_cli
from arcaeon.prove.evidence_pack import DEAL_FILES, PackUsageError, build_pack
from arcaeon.prove.evidence_pack_verify import verify_pack

ROOT = Path(__file__).resolve().parents[2]


def _worked_example_steps():
    text = (ROOT / "docs" / "DEAL.md").read_text(encoding="utf-8")
    steps = []
    for block in re.findall(r"```console\n(.*?)```", text, flags=re.S):
        for line in block.splitlines():
            if line.startswith("$ arcaeon deal ") and line.split()[3] not in ("dispute",
                                                                             "pack"):
                steps.append(line[2:])
    return steps


@pytest.fixture
def tapes(tmp_path, monkeypatch, capsys):
    work = tmp_path / "deals"
    work.mkdir()
    monkeypatch.chdir(work)
    steps = _worked_example_steps()
    assert len(steps) >= 10
    for cmd in steps:
        assert cli.main(shlex.split(cmd)[1:]) == 0, cmd
    capsys.readouterr()
    return work / "buyer.jsonl", work / "seller.jsonl"


def _m(out):
    return json.loads((out / "manifest.json").read_text(encoding="utf-8"))


def test_matched_deal_folds_in_and_verifies(tapes, tmp_path):
    buyer, seller = tapes
    out = tmp_path / "p1"
    res = build_pack(buyer, out, deal="d-demo1", deal_seller=seller)
    assert res["verdict"] == V.VERIFIED and res["exit"] == 0
    m = _m(out)
    assert m["deal"]["id"] == "d-demo1" and m["deal"]["verdict"] == V.MATCHED
    assert m["deal"]["files"] == list(DEAL_FILES)
    assert m["deal"]["pack_ledger_is"] == "buyer"
    for name in DEAL_FILES:
        assert m["files"][name] == hashlib.sha256((out / name).read_bytes()).hexdigest()
    assert (out / "timeline.md").read_text(encoding="utf-8").splitlines()[0] == V.MATCHED
    check = next(c for c in m["checks"] if c["check"] == "deal d-demo1 dispute")
    assert check["verdict"] == V.VERIFIED and check["dispute_verdict"] == V.MATCHED
    readme = (out / "README.md").read_text(encoding="utf-8")
    assert "## The deal" in readme and "MATCHED 2 of 2 compared steps" in readme
    assert verify_pack(out)["exit"] == 0


def test_altered_deal_is_broken_and_stays_broken(tapes, tmp_path):
    buyer, seller = tapes
    out = tmp_path / "p2"
    res = build_pack(seller, out, deal="d-demo2", deal_buyer=buyer)
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    assert res["finding"].startswith("deal d-demo2: ALTERED at commit#1")
    m = _m(out)
    assert m["deal"]["verdict"] == V.ALTERED and m["deal"]["pack_ledger_is"] == "seller"
    assert m["counts"]["broken"] == 1
    readme = (out / "README.md").read_text(encoding="utf-8")
    assert "The two tapes of deal d-demo2 do not agree" in readme
    assert "The records chain does not check out" not in readme
    v = verify_pack(out)
    assert v["verdict"] == V.BROKEN and v["exit"] == 1


@pytest.mark.parametrize("name", DEAL_FILES)
def test_one_changed_byte_in_a_deal_file_is_broken_naming_it(tapes, tmp_path, name):
    buyer, seller = tapes
    out = tmp_path / "p3"
    build_pack(buyer, out, deal="d-demo1", deal_seller=seller)
    p = out / name
    raw = bytearray(p.read_bytes())
    i = raw.index(b"d")
    raw[i] = ord("e")
    p.write_bytes(bytes(raw))
    res = verify_pack(out)
    assert res["verdict"] == V.BROKEN and name in res["finding"]


def test_unknown_deal_never_exits_0(tapes, tmp_path):
    buyer, seller = tapes
    out = tmp_path / "p4"
    res = build_pack(buyer, out, deal="d-nope", deal_seller=seller)
    assert res["exit"] == 3 and res["verdict"] == V.COULD_NOT_LOOK
    entries = json.loads((out / "could_not_look.json").read_text(encoding="utf-8"))
    assert any(e["check"] == "deal d-nope dispute" for e in entries)
    assert verify_pack(out)["exit"] == 3


def test_usage(tapes, tmp_path):
    buyer, seller = tapes
    with pytest.raises(PackUsageError):
        build_pack(buyer, tmp_path / "u1", deal="d-demo1")  # no other side
    with pytest.raises(PackUsageError):
        build_pack(buyer, tmp_path / "u2", deal_seller=seller)  # no --deal
    assert not (tmp_path / "u1").exists() and not (tmp_path / "u2").exists()


def test_cli_deal(tapes, tmp_path):
    buyer, seller = tapes
    out = tmp_path / "cli"
    assert evidence_pack_cli.main(["--ledger", str(buyer), "--out", str(out),
                                   "--deal", "d-demo1", "--seller", str(seller)]) == 0
    assert evidence_pack_cli.main(["--ledger", str(buyer), "--out", str(tmp_path / "c2"),
                                   "--deal", "d-demo2", "--seller", str(seller)]) == 1
    assert evidence_pack_cli.main(["--ledger", str(buyer), "--out", str(tmp_path / "c3"),
                                   "--deal", "d-demo1"]) == 2


def test_r3_deal_timeline_is_prose_hash_only(tapes, tmp_path):
    """K06xR3: timeline.md is prose verify cannot re-derive, so the manifest
    labels it hash-only and verify reports it so."""
    buyer, seller = tapes
    out = tmp_path / "p3"
    build_pack(buyer, out, deal="d-demo1", deal_seller=seller)
    assert _m(out)["prose"] == {"timeline.md": "not re-derived, hash only"}
    res = verify_pack(out)
    assert res["exit"] == 0, res.get("finding")
    assert res["prose_not_rederived"] == {"timeline.md": "not re-derived, hash only"}
