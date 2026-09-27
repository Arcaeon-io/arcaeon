"""K054: could_not_look.json lists every COULD NOT LOOK; present and [] when none."""
import hashlib
import json

from arcaeon import verdict as V
from arcaeon.prove.evidence_pack import build_pack
from arcaeon.record.ledger import Ledger
from arcaeon.record.ledger.witness import WitnessStore, publish_head

KEYS = {"looked_for", "where", "reason_word", "reason"}


def _cnl(out):
    return json.loads((out / "could_not_look.json").read_text(encoding="utf-8"))


def _manifest(out):
    return json.loads((out / "manifest.json").read_text(encoding="utf-8"))


def test_present_and_empty_list_when_none(ledger, tmp_path):
    out = tmp_path / "pack"
    res = build_pack(ledger, out, agent="agent-a")
    assert res["verdict"] == V.VERIFIED
    assert (out / "could_not_look.json").is_file()
    assert _cnl(out) == []
    assert "could_not_look.json" in res["files"]


def test_hashed_in_the_manifest(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="nobody")
    m = _manifest(out)
    raw = (out / "could_not_look.json").read_bytes()
    assert m["files"]["could_not_look.json"] == hashlib.sha256(raw).hexdigest()


def test_empty_window_entry(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-c")
    entries = _cnl(out)
    assert len(entries) == 1
    e = entries[0]
    assert KEYS <= set(e)
    assert e["reason_word"] == "empty"
    assert e["where"] == "records.jsonl"
    assert "agent-c" in e["looked_for"]
    assert e["reason"]


def test_unplaced_rows_are_listed(tmp_path):
    p = tmp_path / "l.jsonl"
    lg = Ledger(p)
    lg.append({"ts": "2026-09-01T10:00:00Z", "agent": "a", "event": "x"})
    lg.append({"ts": "yesterday", "agent": "a", "event": "y"})
    out = tmp_path / "pack"
    build_pack(p, out, agent="a", since="2026-01-01")
    entries = _cnl(out)
    assert [e["reason_word"] for e in entries] == ["unreadable"]
    assert "[2]" in entries[0]["looked_for"]


def test_witness_name_not_found_entry(ledger, tmp_path):
    store = tmp_path / "witness.jsonl"
    publish_head(WitnessStore(store), "acme", Ledger(ledger))
    out = tmp_path / "pack"
    res = build_pack(ledger, out, witness=str(store), witness_namespace="acmx")
    assert res["verdict"] == V.COULD_NOT_LOOK and res["exit"] == 3
    entries = _cnl(out)
    assert len(entries) == 1
    e = entries[0]
    assert KEYS <= set(e)
    assert e["reason_word"] == "name_not_found"
    assert "acmx" in e["looked_for"]
    for e in entries:
        assert e["reason_word"] in V.REASON_WORDS


def test_entries_equal_manifest_count(ledger, tmp_path):
    for i, agent in enumerate(("agent-a", "nobody")):
        out = tmp_path / f"pack{i}"
        build_pack(ledger, out, agent=agent)
        assert len(_cnl(out)) == _manifest(out)["counts"]["could_not_look"]
