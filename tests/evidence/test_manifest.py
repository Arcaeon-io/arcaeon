"""K053: manifest.json hashes every other file and carries the honest fields."""
import hashlib
import json

from arcaeon import __version__
from arcaeon import verdict as V
from arcaeon.prove.evidence_pack import build_pack
from arcaeon.record.ledger import Ledger
from arcaeon.record.ledger.witness import WitnessStore, publish_head


def _manifest(out):
    return json.loads((out / "manifest.json").read_text(encoding="utf-8"))


def _all_keys(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _all_keys(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _all_keys(v)


def test_every_other_file_is_hashed(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a")
    m = _manifest(out)
    on_disk = sorted(p.name for p in out.iterdir() if p.is_file()
                     and p.name not in ("manifest.json", "manifest.sha256"))
    assert sorted(m["files"]) == on_disk
    # the manifest's own hash sits beside it, not inside it (review 2)
    want = hashlib.sha256((out / "manifest.json").read_bytes()).hexdigest()
    assert (out / "manifest.sha256").read_bytes() == f"{want}  manifest.json".encode() + b"\n"
    assert "manifest.json" not in m["files"]
    for name in ("records.jsonl", "window.jsonl", "integrity.json", "ARTICLE_12_SUMMARY.md"):
        assert m["files"][name] == hashlib.sha256((out / name).read_bytes()).hexdigest()


def test_chain_head_and_window_rows(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-b")
    m = _manifest(out)
    head = Ledger(ledger).head()
    assert m["chain_head"]["chain"] == head.chain
    assert m["chain_head"]["rows"] == 4
    assert m["window"]["first_line"] == 2 and m["window"]["last_line"] == 4
    assert m["window"]["lines"] == [2, 4]


def test_honest_fields(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out)
    m = _manifest(out)
    assert m["operator_at_t"] == "UNKNOWN"
    assert m["tool"] == f"arcaeon/{__version__}"
    for k in ("kind", "identifier", "independence", "independence_source"):
        assert k in m["witness"]
    assert m["pins"] == []
    assert m["counts"] == {"verified": 2, "broken": 0, "could_not_look": 0}


def test_local_witness_pin_reference_is_self_asserted(ledger, tmp_path):
    store_path = tmp_path / "witness.jsonl"
    publish_head(WitnessStore(store_path), "acme", Ledger(ledger))
    out = tmp_path / "pack"
    res = build_pack(ledger, out, witness=str(store_path), witness_namespace="acme")
    m = _manifest(out)
    assert res["verdict"] == V.VERIFIED
    assert m["witness"]["kind"] == "local_file"
    assert m["witness"]["independence"] == "self_asserted"
    assert m["witness"]["independence_source"]
    assert len(m["pins"]) == 1
    pin = m["pins"][0]
    assert pin["namespace"] == "acme" and pin["rows"] == 4
    assert pin["chain"] == Ledger(ledger).head().chain
    assert "witness.json" in m["files"]


def test_counts_side_by_side_on_empty_window(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="nobody")
    m = _manifest(out)
    assert m["counts"] == {"verified": 1, "broken": 0, "could_not_look": 1}
    assert m["verdict"] == V.COULD_NOT_LOOK and m["exit"] == 3


def test_counts_on_broken(ledger, tmp_path):
    lines = ledger.read_bytes().split(b"\n")
    lines[2] = lines[2].replace(b"escalate", b"escalatf")
    ledger.write_bytes(b"\n".join(lines))
    out = tmp_path / "pack"
    build_pack(ledger, out)
    m = _manifest(out)
    assert m["counts"]["broken"] == 1
    assert m["chain_head"]["ok"] is False


def test_no_rate_or_percent_key(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a")
    keys = set(_all_keys(_manifest(out)))
    for k in keys:
        low = k.lower()
        assert low not in ("rate", "percent", "pct", "ratio")
        assert not low.endswith(("_rate", "_percent", "_pct", "_ratio"))
