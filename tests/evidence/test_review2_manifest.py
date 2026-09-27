"""K06xR1 (review 2 on lane D), run as ONE combined edit.

An empty-window pack whose could_not_look.json is emptied (hash fixed),
counts.could_not_look set to 0 and `checks` deleted, manifest.sha256 fixed
too, used to verify VERIFIED because the window step saw [] equal to [] and
the cross-check only ran when `checks` was a list. Verify now re-derives the
build's findings from the pack and never takes the manifest's counts for it.
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


# ---- K06xR1 ------------------------------------------------------------

def test_r1_combined_attack_unpinned_is_never_0(ledger, tmp_path):
    out = tmp_path / "pack"
    assert build_pack(ledger, out, agent="nobody")["exit"] == 3
    _hide_empty_window(out)
    res = verify_pack(out)
    assert res["exit"] != 0 and res["verdict"] != V.VERIFIED
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    assert "manifest incomplete" in res["finding"]


def test_r1_combined_attack_pinned_is_never_0(ledger, pins, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="nobody", witness=str(pins), witness_namespace=NS)
    assert _m(out)["pins"]  # a pinned pack
    _hide_empty_window(out)
    res = verify_pack(out, witness=pins)
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    assert "manifest incomplete" in res["finding"]


@pytest.mark.parametrize("pinned", [False, True])
def test_r1_consistent_rewrite_of_checks_still_broken(ledger, pins, tmp_path, pinned):
    """Keep `checks`, but rewrite it so it agrees with the emptied file."""
    out = tmp_path / "pack"
    kw = {"witness": str(pins), "witness_namespace": NS} if pinned else {}
    build_pack(ledger, out, agent="nobody", **kw)
    (out / "could_not_look.json").write_text("[]\n", encoding="utf-8")
    m = _m(out)
    for c in m["checks"]:
        if c["verdict"] == V.COULD_NOT_LOOK:
            c["verdict"] = V.VERIFIED
            for k in ("looked_for", "where", "reason_word", "reason"):
                c.pop(k, None)
    m["counts"] = {"verified": len(m["checks"]), "broken": 0, "could_not_look": 0}
    m["verdict"], m["exit"] = V.VERIFIED, 0
    _seal(out, m, "could_not_look.json")
    res = verify_pack(out, witness=pins if pinned else None)
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    assert "the window is empty and could_not_look.json does not say so" in res["finding"]


def test_r1_counts_missing_is_broken_manifest_incomplete(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a")
    m = _m(out)
    del m["counts"]
    _seal(out, m)
    res = verify_pack(out)
    assert res["verdict"] == V.BROKEN and "manifest incomplete" in res["finding"]


def test_r1_manifest_edit_alone_is_broken_by_its_sidecar(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a")
    assert verify_pack(out)["exit"] == 0
    m = _m(out)
    m["operator_at_t"] = "KNOWN"
    (out / "manifest.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
    res = verify_pack(out)
    assert res["verdict"] == V.BROKEN and "manifest.sha256" in res["finding"]


def test_r1_sidecar_deleted_is_exit_3_missing(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a")
    (out / "manifest.sha256").unlink()
    res = verify_pack(out)
    assert res["exit"] == 3 and res["reason_word"] == "missing"
    assert res["looked_for"] == "manifest.sha256"


def test_r1_window_reselected_from_records(ledger, tmp_path):
    """A window.jsonl trimmed to one row, with manifest lines to match, is BROKEN."""
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a")
    first = (out / "window.jsonl").read_bytes().split(b"\n")[0] + b"\n"
    (out / "window.jsonl").write_bytes(first)
    m = _m(out)
    m["window"]["lines"] = [1]
    m["window"]["rows"] = 1
    _seal(out, m, "window.jsonl")
    res = verify_pack(out)
    assert res["verdict"] == V.BROKEN
    assert "selecting the window again" in res["finding"]
