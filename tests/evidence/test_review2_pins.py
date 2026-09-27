"""K06xR2 (review 2 on lane D), run as ONE combined edit.

A pack whose tail was cut and whose pins were stripped from the manifest,
integrity.json and witness.json (rows and hashes fixed) verified "not
witnessed" even though the pin file passed with --witness holds a pin past
the cut. Verify now searches the pin file for this ledger.
"""
import hashlib
import json

import pytest

from arcaeon import verdict as V
from arcaeon.prove.evidence_pack import build_pack
from arcaeon.prove.evidence_pack_verify import verify_pack
from arcaeon.record.ledger import Ledger
from arcaeon.record.ledger.witness import WitnessStore, publish_head


NS = "acme-ledger"


def _m(out):
    return json.loads((out / "manifest.json").read_text(encoding="utf-8"))


def _seal(out, m, *fixed):
    """The full attacker: rehash the named files, rewrite the manifest, and
    recompute manifest.sha256 so no hash anywhere gives the edit away."""
    for name in fixed:
        m["files"][name] = hashlib.sha256((out / name).read_bytes()).hexdigest()
    (out / "manifest.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
    h = hashlib.sha256((out / "manifest.json").read_bytes()).hexdigest()
    (out / "manifest.sha256").write_bytes(f"{h}  manifest.json\n".encode("ascii"))


def _hide_empty_window(out):
    (out / "could_not_look.json").write_text("[]\n", encoding="utf-8")
    m = _m(out)
    m["counts"]["could_not_look"] = 0
    del m["checks"]
    _seal(out, m, "could_not_look.json")


@pytest.fixture
def pins(ledger, tmp_path):
    p = tmp_path / "pins.jsonl"
    publish_head(WitnessStore(p), NS, Ledger(ledger))
    return p


# ---- K06xR2 ------------------------------------------------------------

def _cut_and_strip(ledger, tmp_path, keep):
    """Cut the ledger to `keep` rows and build a fresh, self-consistent pack
    with no witness: pins gone from manifest, integrity.json and witness.json,
    every row count and hash agreeing with the cut records."""
    cut = tmp_path / "cut.jsonl"
    cut.write_bytes(b"".join(ledger.read_bytes().splitlines(keepends=True)[:keep]))
    out = tmp_path / "cutpack"
    build_pack(cut, out, agent="agent-a")
    m = _m(out)
    assert m["pins"] == [] and m["chain_head"]["rows"] == keep
    assert verify_pack(out)["exit"] == 0  # clean without the witness
    return out


def test_r2_pin_beyond_head_with_namespace_is_broken(ledger, pins, tmp_path):
    out = _cut_and_strip(ledger, tmp_path, keep=2)
    res = verify_pack(out, witness=pins, namespace=NS)
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    assert "pin beyond head" in res["finding"]


def test_r2_pin_beyond_head_found_without_namespace(ledger, tmp_path):
    """A pin file with an earlier pin the cut records still match ties the
    ledger to its namespace; the later pin past the cut is then BROKEN."""
    lines = ledger.read_bytes().splitlines(keepends=True)
    lg_path = tmp_path / "grow.jsonl"
    lg_path.write_bytes(b"".join(lines[:2]))
    pins = tmp_path / "pins.jsonl"
    publish_head(WitnessStore(pins), NS, Ledger(lg_path))
    lg_path.write_bytes(b"".join(lines))
    publish_head(WitnessStore(pins), NS, Ledger(lg_path))
    out = _cut_and_strip(lg_path, tmp_path, keep=2)
    res = verify_pack(out, witness=pins)
    assert res["verdict"] == V.BROKEN and "pin beyond head" in res["finding"]


def test_r2_untied_pins_are_exit_3_never_0(ledger, pins, tmp_path):
    out = _cut_and_strip(ledger, tmp_path, keep=2)
    res = verify_pack(out, witness=pins)
    assert res["exit"] == 3 and res["reason_word"] == "name_not_found"


def test_r2_pack_claiming_to_predate_the_pin_is_exit_3(ledger, pins, tmp_path):
    out = _cut_and_strip(ledger, tmp_path, keep=2)
    m = _m(out)
    # after the cut records (a build time before them is BROKEN, K06xR3) and
    # before the pin was taken
    m["built_at"] = "2026-09-02T00:00:00Z"
    _seal(out, m)
    res = verify_pack(out, witness=pins, namespace=NS)
    assert res["exit"] == 3 and res["reason_word"] == "bounded"


def test_r2_honest_unpinned_pack_with_empty_pin_file_still_verifies(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a")
    empty = tmp_path / "none.jsonl"
    empty.write_bytes(b"")
    assert verify_pack(out, witness=empty)["exit"] == 0


def test_r2_matching_pin_at_head_verifies(ledger, pins, tmp_path):
    """Built without a witness from the same, uncut ledger: the pin matches."""
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a")
    res = verify_pack(out, witness=pins)
    assert res["exit"] == 0, res.get("finding")
