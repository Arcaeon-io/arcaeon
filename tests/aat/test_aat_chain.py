"""K062: the AAT chain, SHA-256 over RFC 8785 JCS, recomputed independently.

The independent recomputation below does not import arcaeon.prove.jcs: for
records whose keys are ASCII and whose values are strings, integers and null,
JCS equals json.dumps with sorted keys and no whitespace, so the test hashes
that and compares.
"""
import hashlib
import json

from arcaeon.prove.aat_export import chain_records, export_aat, verify_aat_bytes
from arcaeon.record.ledger import Ledger


def _independent_jcs(rec):
    return json.dumps(rec, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _three_row_ledger(tmp_path):
    p = tmp_path / "three.jsonl"
    lg = Ledger(p)
    for i, (agent, ev) in enumerate([("desk-a", "decision"), ("desk-b", "tool_call"),
                                     ("desk-a", "decision")], start=1):
        lg.append({"agent": agent, "event": ev, "tool": f"t{i}", "status": "ok",
                   "seq": i, "inputs": {"n": i}})
    return p


def test_three_record_chain_recomputed_independently(tmp_path):
    ledger = _three_row_ledger(tmp_path)
    out = tmp_path / "aat.jsonl"
    res = export_aat(ledger, out)
    assert res["exit"] == 0 and res["records"] == 3
    lines = out.read_bytes().split(b"\n")
    assert lines[-1] == b"" and len(lines) == 4
    recs = [json.loads(l) for l in lines[:3]]
    assert recs[0]["prev_hash"] is None
    prev = None
    for rec, line in zip(recs, lines):
        assert rec["prev_hash"] == prev
        assert _independent_jcs(rec) == line  # each line is its own JCS form
        prev = hashlib.sha256(_independent_jcs(rec)).hexdigest()
        assert len(prev) == 64
    assert res["aat_chain"]["head"] == prev
    assert recs[1]["prev_hash"] == hashlib.sha256(lines[0]).hexdigest()
    # our original chain rides beside the AAT chain, unchanged
    src = [json.loads(l) for l in ledger.read_text(encoding="utf-8").splitlines()]
    assert [r["chain"] for r in recs] == [s["chain"] for s in src]
    assert verify_aat_bytes(out.read_bytes()) == {"ok": True, "records": 3, "head": prev}


def test_one_changed_byte_breaks_the_aat_chain(tmp_path):
    ledger = _three_row_ledger(tmp_path)
    out = tmp_path / "aat.jsonl"
    export_aat(ledger, out)
    raw = out.read_bytes()
    bad = raw.replace(b'"tool_name":"t1"', b'"tool_name":"t9"')
    assert bad != raw
    v = verify_aat_bytes(bad)
    assert v["ok"] is False and v["line"] == 2  # line 1 still parses; line 2's link breaks


def test_non_jcs_line_is_caught(tmp_path):
    ledger = _three_row_ledger(tmp_path)
    out = tmp_path / "aat.jsonl"
    export_aat(ledger, out)
    first, rest = out.read_bytes().split(b"\n", 1)
    spaced = json.dumps(json.loads(first), sort_keys=True).encode("utf-8")
    v = verify_aat_bytes(spaced + b"\n" + rest)
    assert v["ok"] is False and v["line"] == 1


def test_unexact_value_refused_and_listed_not_rounded():
    recs = [{"sequence_number": 2 ** 60, "source_line": 1, "timestamp": "t"},
            {"sequence_number": 2, "source_line": 2,
             "action_detail": {"tool_name": "x" + chr(0xDC00)}}]
    lines, head, refused = chain_records(recs)
    assert "sequence_number" not in recs[0] and recs[0]["timestamp"] == "t"
    assert "action_detail" not in recs[1]
    assert [(r["source_line"], r["field"]) for r in refused] == \
        [(1, "sequence_number"), (2, "action_detail")]
    assert json.loads(lines[1])["prev_hash"] == hashlib.sha256(lines[0]).hexdigest()
    assert head == hashlib.sha256(lines[1]).hexdigest()


def test_empty_chain():
    assert chain_records([]) == ([], None, [])
    assert verify_aat_bytes(b"") == {"ok": True, "records": 0, "head": None}
