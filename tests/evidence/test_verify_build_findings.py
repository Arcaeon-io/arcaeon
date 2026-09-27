"""K059R: verify reads the build's own COULD NOT LOOKs; they never exit 0.

An untouched pack whose build reached COULD NOT LOOK (empty window, rows whose
time could not be read, a witness that could not be reached) verifies exit 3
with the reasons. could_not_look.json must agree with the manifest's counts:
emptied with its hash fixed is BROKEN "counts mismatch".
"""
import hashlib
import json

from arcaeon import verdict as V
from arcaeon.prove import evidence_pack_cli
from arcaeon.prove.evidence_pack import build_pack
from arcaeon.prove.evidence_pack_verify import verify_pack
from arcaeon.record.ledger import Ledger

CHECK = "build-time findings"


def _step(res):
    return next(c for c in res["checks"] if c["check"] == CHECK)


def _fix_hash(out, name):
    m = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    m["files"][name] = hashlib.sha256((out / name).read_bytes()).hexdigest()
    (out / "manifest.json").write_text(json.dumps(m, indent=2), encoding="utf-8")


def test_clean_build_verifies_exit_0(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a")
    res = verify_pack(out)
    assert res["verdict"] == V.VERIFIED and res["exit"] == 0
    assert _step(res)["verdict"] == V.VERIFIED and _step(res)["entries"] == []


def test_untouched_empty_window_pack_is_exit_3_never_0(ledger, tmp_path):
    out = tmp_path / "pack"
    assert build_pack(ledger, out, agent="nobody")["exit"] == 3
    res = verify_pack(out)
    assert res["checks"][0]["verdict"] == V.VERIFIED  # nothing was touched
    assert res["verdict"] == V.COULD_NOT_LOOK and res["exit"] == 3
    assert res["reason_word"] == "empty"
    assert [r["reason_word"] for r in res["could_not_look"]] == ["empty"]


def test_untouched_unplaced_rows_pack_is_exit_3(tmp_path):
    p = tmp_path / "l.jsonl"
    lg = Ledger(p)
    lg.append({"ts": "2026-09-01T10:00:00Z", "agent": "a", "event": "x"})
    lg.append({"ts": "yesterday", "agent": "a", "event": "y"})
    out = tmp_path / "pack"
    build_pack(p, out, agent="a", since="2026-01-01")
    res = verify_pack(out)
    assert res["exit"] == 3 and res["verdict"] == V.COULD_NOT_LOOK
    assert res["reason_word"] == "unreadable"
    assert "[2]" in res["looked_for"]


def test_untouched_witness_unreachable_pack_is_exit_3(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, witness=str(tmp_path / "no_pins.jsonl"),
               witness_namespace="ns-a")
    res = verify_pack(out)
    assert res["exit"] == 3 and res["verdict"] == V.COULD_NOT_LOOK
    assert "ns-a" in _step(res)["looked_for"]


def test_emptied_cnl_file_with_hash_fixed_is_broken_counts_mismatch(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="nobody")
    (out / "could_not_look.json").write_text("[]\n", encoding="utf-8")
    _fix_hash(out, "could_not_look.json")
    res = verify_pack(out)
    assert res["checks"][0]["verdict"] == V.VERIFIED  # the hash hides it
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    assert "counts mismatch" in _step(res)["finding"]
    assert "counts mismatch" in res["finding"]


def test_counts_rewritten_to_zero_is_broken(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="nobody")
    m = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    m["counts"]["could_not_look"] = 0
    (out / "manifest.json").write_text(json.dumps(m), encoding="utf-8")
    res = verify_pack(out)
    assert res["verdict"] == V.BROKEN and "counts mismatch" in res["finding"]


def test_cli_prints_every_reason_and_exits_3(ledger, tmp_path, capsys):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="nobody")
    rc = evidence_pack_cli.main(["verify", str(out)])
    assert rc == 3
    text = capsys.readouterr().out
    assert text.startswith("COULD NOT LOOK")
    assert "[empty]" in text
