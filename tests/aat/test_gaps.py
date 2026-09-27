"""K063: aat_gaps.json and the which-chain line.

Every field the export leaves out is one COULD NOT LOOK entry with
reason_word "bounded"; the export's header says the AAT chain proves the
export was not altered after export and that the original chain is `chain`.
"""
import json

import pytest

from arcaeon import verdict as V
from arcaeon.prove.aat_export import (EMITTED_WHEN_HELD, NEVER_EMITTED, WHICH_CHAIN,
                                      AatUsageError, build_gaps, chain_records,
                                      export_aat, gaps_path)
from arcaeon.record.ledger import Ledger


@pytest.fixture
def ledger(tmp_path):
    p = tmp_path / "l.jsonl"
    lg = Ledger(p)
    lg.append({"ts": "2026-09-01T10:00:00Z", "agent": "desk-a", "event": "decision",
               "inputs": {"q": 1}})
    lg.append({"ts": "2026-09-01T11:00:00Z", "event": "reference_check"})
    return p


@pytest.fixture
def exported(ledger, tmp_path):
    out = tmp_path / "aat.jsonl"
    res = export_aat(ledger, out)
    return res, json.loads(gaps_path(out).read_text(encoding="utf-8")), out


def _by_field(gaps):
    return {g["looked_for"]: g for g in gaps}


def test_sidecar_named_beside_the_export(exported, tmp_path):
    res, _, out = exported
    assert gaps_path(out) == tmp_path / "aat_gaps.json"
    assert res["gaps_file"] == str(tmp_path / "aat_gaps.json")
    assert res["exit"] == 0 and res["verdict"] == V.VERIFIED


def test_every_entry_is_could_not_look_bounded(exported):
    res, side, _ = exported
    gaps = side["gaps"]
    assert gaps and res["gaps"] == len(gaps)
    for g in gaps:
        assert set(g) >= {"looked_for", "where", "reason_word", "reason"}
        assert g["reason_word"] == "bounded"
        assert g["reason"].startswith("left out")
        assert "verdict" not in g  # a scope entry, not a check result


def test_never_emitted_fields_each_listed(exported):
    _, side, _ = exported
    by = _by_field(side["gaps"])
    for f in NEVER_EMITTED + ("external_timestamp",):
        assert by[f"AAT field {f}"]["where"] == "every record"


def test_per_row_omissions_name_their_lines(exported, ledger):
    _, side, out = exported
    by = _by_field(side["gaps"])
    recs = [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines()]
    for f in EMITTED_WHEN_HELD:
        missing = [r["source_line"] for r in recs if f not in r]
        if missing:
            assert by[f"AAT field {f}"]["lines"] == missing
        else:
            assert f"AAT field {f}" not in by
    # line 2 has no agent: named, never guessed
    assert by["AAT field agent_id"]["lines"] == [2]
    assert by["AAT field agent_id"]["where"] == "ledger line 2"
    assert "timestamp" not in [g["looked_for"].split()[-1] for g in side["gaps"]
                               if g["where"] != "every record"]


def test_which_chain_header(exported):
    res, side, _ = exported
    for text in (res["which_chain"], side["which_chain"]):
        assert text == WHICH_CHAIN
        assert "proves the export was not altered after export" in text
        assert "original chain is the `chain` field" in text
    assert side["aat_chain"]["head"] == res["aat_chain"]["head"]
    assert "not AAT-conformant" in side["scope"]


def test_refused_value_and_skipped_line_listed():
    recs = [{"source_line": 1, "sequence_number": 2 ** 60}]
    _, _, refused = chain_records(recs)
    gaps = build_gaps(recs, refused, skipped=[4])
    by = _by_field(gaps)
    seq = by["AAT field sequence_number"]
    assert seq["lines"] == [1] and "JCS cannot write it exactly" in seq["reason"]
    assert [g["looked_for"] for g in gaps].count("AAT field sequence_number") == 1
    assert by["an AAT record"]["lines"] == [4]


def test_existing_sidecar_is_never_overwritten(ledger, tmp_path):
    (tmp_path / "aat_gaps.json").write_text("{}", encoding="utf-8")
    with pytest.raises(AatUsageError):
        export_aat(ledger, tmp_path / "aat.jsonl")
    assert not (tmp_path / "aat.jsonl").exists()
