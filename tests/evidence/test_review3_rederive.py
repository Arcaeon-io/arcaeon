"""K06xR3 (review 3 on lane D): the pin binds only records.jsonl.

A holder could edit the manifest, recompute manifest.sha256, and get
VERIFIED even with --witness on a pinned pack. The reviewer proved four edits
passed: witness.independence set to "independent", operator_at_t set to a
firm's name, built_at moved back to 2020, and a sentence "certified by an
independent witness" added to ARTICLE_12_SUMMARY.md and README.md with their
manifest hashes updated. Verify now re-derives every one of these from the
records and the pin, and never takes the manifest's word for it. Each edit
is run on a pinned pack verified with --witness AND on an unpinned pack.
"""
import hashlib
import json

import pytest

from arcaeon import verdict as V
from arcaeon.prove.evidence_pack import PROSE_HASH_ONLY, PackUsageError, build_pack
from arcaeon.prove.evidence_pack_verify import verify_pack
from arcaeon.record.ledger import Ledger
from arcaeon.record.ledger.witness import WitnessStore, publish_head

NS = "acme-ledger"
CLAIM = "\n\nThis pack is certified by an independent witness.\n"


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


@pytest.fixture
def pins(ledger, tmp_path):
    p = tmp_path / "pins.jsonl"
    publish_head(WitnessStore(p), NS, Ledger(ledger))
    return p


@pytest.fixture(params=["unpinned", "pinned"])
def pack(request, ledger, pins, tmp_path):
    """(pack folder, verify kwargs): an honest pack that verifies exit 0."""
    out = tmp_path / "pack"
    if request.param == "pinned":
        build_pack(ledger, out, agent="agent-a", witness=str(pins), witness_namespace=NS)
        kw = {"witness": pins}
        assert _m(out)["pins"]
    else:
        build_pack(ledger, out, agent="agent-a")
        kw = {}
    res = verify_pack(out, **kw)
    assert res["exit"] == 0, res.get("finding")
    return out, kw


def _broken(res, *words):
    assert res["verdict"] == V.BROKEN and res["exit"] == 1, res
    for w in words:
        assert w in res["finding"], res["finding"]


# ---- the four edits the reviewer listed ------------------------------------

def test_r3_independence_set_independent_is_broken(pack):
    out, kw = pack
    m = _m(out)
    m["witness"]["independence"] = "independent"
    _seal(out, m)
    _broken(verify_pack(out, **kw), "independence overclaimed")


def test_r3_operator_set_to_a_firm_is_broken(pack):
    out, kw = pack
    m = _m(out)
    m["operator_at_t"] = "Acme Custody Services LLC"
    _seal(out, m)
    _broken(verify_pack(out, **kw), "operator overclaimed")


def test_r3_built_at_moved_to_2020_is_broken(pack):
    out, kw = pack
    m = _m(out)
    m["built_at"] = "2020-01-01T00:00:00Z"
    _seal(out, m)
    _broken(verify_pack(out, **kw), "before the newest record")


def test_r3_sentence_added_to_summary_is_broken(pack):
    out, kw = pack
    p = out / "ARTICLE_12_SUMMARY.md"
    p.write_bytes(p.read_bytes() + CLAIM.encode("utf-8"))
    _seal(out, _m(out), "ARTICLE_12_SUMMARY.md")
    _broken(verify_pack(out, **kw), "summary drift")


def test_r3_sentence_added_to_readme_is_broken(pack):
    out, kw = pack
    p = out / "README.md"
    p.write_bytes(p.read_bytes() + CLAIM.encode("utf-8"))
    _seal(out, _m(out), "README.md")
    _broken(verify_pack(out, **kw), "readme drift")


def test_r3_all_four_edits_together_are_broken(pack):
    out, kw = pack
    for name in ("ARTICLE_12_SUMMARY.md", "README.md"):
        p = out / name
        p.write_bytes(p.read_bytes() + CLAIM.encode("utf-8"))
    m = _m(out)
    m["witness"]["independence"] = "independent"
    m["operator_at_t"] = "Acme Custody Services LLC"
    m["built_at"] = "2020-01-01T00:00:00Z"
    _seal(out, m, "ARTICLE_12_SUMMARY.md", "README.md")
    _broken(verify_pack(out, **kw), "independence overclaimed", "operator overclaimed",
            "before the newest record", "summary drift", "readme drift")


# ---- the same claims, moved to the files beside the manifest ----------------

def test_r3_integrity_independence_edit_is_broken(pack):
    out, kw = pack
    p = out / "integrity.json"
    i = json.loads(p.read_text(encoding="utf-8"))
    i["witness"]["independence"] = "independent"
    p.write_text(json.dumps(i, indent=2), encoding="utf-8")
    _seal(out, _m(out), "integrity.json")
    _broken(verify_pack(out, **kw), "independence overclaimed")


def test_r3_readme_bullet_reworded_is_broken(pack):
    out, kw = pack
    p = out / "README.md"
    text = p.read_bytes().decode("utf-8")
    assert '- Not "independent witness".' in text
    p.write_bytes(text.replace('- Not "independent witness".',
                               '- An "independent witness".').encode("utf-8"))
    _seal(out, _m(out), "README.md")
    _broken(verify_pack(out, **kw), "readme drift")


def test_r3_manifest_verdict_rewritten_is_broken(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a")
    m = _m(out)
    m["verdict"], m["exit"] = V.BROKEN, 1
    _seal(out, m)
    res = verify_pack(out)
    assert res["exit"] == 1 and "re-derived from the records and the checks" in \
        res["finding"]


# ---- built_at against a listed pin, and the pin binding ----------------------

def test_r3_built_before_listed_pin_receipt_is_exit_3_bounded(ledger, pins, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a", witness=str(pins), witness_namespace=NS)
    m = _m(out)
    m["pins"][0]["received_at"] = "2099-01-01T00:00:00Z"
    _seal(out, m)
    res = verify_pack(out, witness=pins)
    assert res["exit"] == 3 and res["reason_word"] == "bounded"


def test_r3_chain_head_below_the_pin_is_broken(ledger, pins, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a", witness=str(pins), witness_namespace=NS)
    m = _m(out)
    m["pins"][0]["rows"] = m["chain_head"]["rows"] + 1
    _seal(out, m)
    res = verify_pack(out, witness=pins)
    assert res["exit"] == 1 and "is not the head pinned" in res["finding"]


# ---- honest shapes stay clean ------------------------------------------------

def test_r3_self_declared_remote_witness_reads_self_asserted(ledger, tmp_path):
    class Hosted:
        def __init__(self):
            h = Ledger(ledger).head()
            self.pin = {"namespace": NS, "rows": h.rows, "chain": h.chain,
                        "as_of": "2026-09-27T00:00:00Z", "commit": "abc"}

        def latest(self, namespace):
            return dict(self.pin) if namespace == NS else None

        def witness_descriptor(self):
            return {"kind": "remote_url", "identifier": "https://w.example.invalid",
                    "independence": "externally_verifiable"}

    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a", witness=Hosted(), witness_namespace=NS)
    w = _m(out)["witness"]
    assert (w["independence"], w["independence_source"]) == (
        "self_asserted", "conservative_default")
    st = next(c for c in verify_pack(out)["checks"]
              if c["check"] == "re-derived fields and prose")
    assert st["verdict"] == V.VERIFIED, st.get("finding")


def test_r3_prose_group_required(ledger, tmp_path):
    """A .md file the pack cannot re-derive must be labelled hash-only."""
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a")
    (out / "NOTES.md").write_bytes(b"Certified by an independent witness.\n")
    _seal(out, _m(out), "NOTES.md")
    _broken(verify_pack(out), "prose not labelled")
    m = _m(out)
    m["prose"] = {"NOTES.md": PROSE_HASH_ONLY}
    _seal(out, m)
    res = verify_pack(out)
    assert res["exit"] == 0, res.get("finding")
    assert res["prose_not_rederived"] == {"NOTES.md": "not re-derived, hash only"}


def test_r3_build_refuses_built_at_before_records(ledger, tmp_path):
    with pytest.raises(PackUsageError, match="before the ledger's newest record"):
        build_pack(ledger, tmp_path / "pack", built_at="2020-01-01T00:00:00Z")


def test_r3_build_refuses_namespace_without_witness(ledger, tmp_path):
    with pytest.raises(PackUsageError, match="only read with --witness"):
        build_pack(ledger, tmp_path / "pack", witness_namespace=NS)
