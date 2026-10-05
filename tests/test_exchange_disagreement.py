# SPDX-License-Identifier: MIT
"""L3-RECON: the four disagreement classes in `arcaeon exchange pair`
(missing, mismatched, late, retracted) and the dispute packet read from the
PAIR (`arcaeon exchange packet`).

Every key here is a throwaway seed written to tmp_path; no network."""
from __future__ import annotations

import base64
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import dispute_packet as P
from arcaeon.prove import exchange_log as X

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

T0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
ZERO = {"missing": 0, "mismatched": 0, "late": 0, "retracted": 0, "withdrawn": 0}


def _key(tmp_path: Path, name: str) -> tuple[Path, str]:
    from arcaeon.prove.vet import receipts as R
    seed = secrets.token_bytes(32)
    p = tmp_path / f"{name}.key"
    p.write_text(base64.b64encode(seed).decode("ascii") + "\n", encoding="ascii")
    return p, R.did_key(R.public_key_from_seed(seed))


@pytest.fixture
def p(tmp_path):
    ka, da = _key(tmp_path, "a")
    kb, db = _key(tmp_path, "b")
    f = tmp_path / "deliverable.csv"
    f.write_bytes(b"id,grade\n1,A\n")
    return {"ka": ka, "da": da, "kb": kb, "db": db, "file": f,
            "la": tmp_path / "a.jsonl", "lb": tmp_path / "b.jsonl", "tmp": tmp_path}


def _react(p, side, reaction=V.VERIFIED, ex="ex-1", file=None, at=T0, **kw):
    other = "b" if side == "a" else "a"
    return X.react(p["l" + side], key_file=p["k" + side], exchange_id=ex,
                   counterparty=kw.pop("counterparty", p["d" + other]),
                   file=file or p["file"], reaction=reaction, at=at, **kw)


def _ex(r, eid="ex-1"):
    return next(e for e in r["exchanges"] if e["exchange_id"] == eid)


# --- 1. the four classes ----------------------------------------------------------------

def test_the_words_and_the_default_window():
    assert X.DISAGREEMENTS == ("missing", "mismatched", "late", "retracted", "withdrawn")
    assert X.DEFAULT_LATE_AFTER == 86400
    assert "DISAGREEMENTS" in X.__all__ and "classify" in X.__all__


def test_agreeing_exchange_carries_no_class(p):
    _react(p, "a")
    _react(p, "b", at=T0 + timedelta(hours=3))
    r = X.pair(p["la"], p["lb"])
    ex = _ex(r)
    assert ex["status"] == "clean"
    assert ex["disagreement"] is None and ex["disagreement_reason"] is None
    assert r["disagreements"] == ZERO and r["late_after"] == 86400


def test_missing_class(p):
    _react(p, "a")
    _react(p, "a", ex="ex-2")
    _react(p, "b")
    r = X.pair(p["la"], p["lb"])
    ex = _ex(r, "ex-2")
    assert ex["status"] == "missing"                 # status unchanged
    assert ex["disagreement"] == "missing"
    assert "b" in ex["disagreement_reason"] and "no record" in ex["disagreement_reason"]
    assert r["disagreements"] == {**ZERO, "missing": 1}


def test_mismatched_names_the_field(p):
    other = p["tmp"] / "other.csv"
    other.write_bytes(b"id,grade\n1,B\n")
    _react(p, "a")
    _react(p, "b", file=other)
    ex = _ex(X.pair(p["la"], p["lb"]))
    assert ex["status"] == "mismatch"
    assert ex["disagreement"] == "mismatched"
    assert "file_sha256" in ex["disagreement_reason"]


def test_mismatched_reaction(p):
    _react(p, "a")
    _react(p, "b", V.BROKEN)
    r = X.pair(p["la"], p["lb"])
    ex = _ex(r)
    assert ex["disagreement"] == "mismatched" and "reaction" in ex["disagreement_reason"]
    assert r["disagreements"]["mismatched"] == 1


def test_late_past_the_window(p):
    _react(p, "a")
    _react(p, "b", at=T0 + timedelta(days=2, hours=1))
    r = X.pair(p["la"], p["lb"])
    ex = _ex(r)
    assert ex["status"] == "clean"                   # the status is not moved
    assert ex["disagreement"] == "late"
    assert "b" in ex["disagreement_reason"] and "86400" in ex["disagreement_reason"]
    assert r["disagreements"] == {**ZERO, "late": 1}


def test_late_window_is_a_parameter(p):
    _react(p, "a")
    _react(p, "b", at=T0 + timedelta(seconds=61))
    assert _ex(X.pair(p["la"], p["lb"]))["disagreement"] is None
    r = X.pair(p["la"], p["lb"], late_after=60)
    assert _ex(r)["disagreement"] == "late" and r["late_after"] == 60
    assert _ex(X.pair(p["la"], p["lb"], late_after=61))["disagreement"] is None


def test_late_also_reads_an_agreed_non_verified(p):
    _react(p, "a", V.COULD_NOT_LOOK)
    _react(p, "b", V.COULD_NOT_LOOK, at=T0 + timedelta(days=3))
    ex = _ex(X.pair(p["la"], p["lb"]))
    assert ex["status"] == "not_verified" and ex["disagreement"] == "late"


def test_a_mismatch_is_never_late(p):
    _react(p, "a")
    _react(p, "b", V.BROKEN, at=T0 + timedelta(days=3))
    assert _ex(X.pair(p["la"], p["lb"]))["disagreement"] == "mismatched"


def test_retracted_class(p):
    _react(p, "a")
    old = _react(p, "b", V.BROKEN)
    _react(p, "b", V.VERIFIED, supersedes=old["row_digest"], at=T0 + timedelta(minutes=5))
    r = X.pair(p["la"], p["lb"])
    ex = _ex(r)
    assert ex["status"] == "clean" and ex["retracted"] == ["b"]
    assert ex["disagreement"] == "retracted"
    assert "b" in ex["disagreement_reason"] and "BROKEN" in ex["disagreement_reason"]
    assert r["disagreements"] == {**ZERO, "retracted": 1}


def test_retracted_and_late_reads_retracted(p):
    _react(p, "a")
    old = _react(p, "b", V.BROKEN)
    _react(p, "b", V.VERIFIED, supersedes=old["row_digest"], at=T0 + timedelta(days=4))
    assert _ex(X.pair(p["la"], p["lb"]))["disagreement"] == "retracted"


def test_mismatched_wins_over_retracted(p):
    _react(p, "a")
    old = _react(p, "b", V.BROKEN)
    _react(p, "b", V.COULD_NOT_LOOK, supersedes=old["row_digest"])
    ex = _ex(X.pair(p["la"], p["lb"]))
    assert ex["retracted"] == ["b"] and ex["disagreement"] == "mismatched"


def test_broken_exchange_carries_no_class(p):
    _react(p, "a")
    _react(p, "b")
    text = p["la"].read_text(encoding="utf-8")
    p["la"].write_text(text.replace('"VERIFIED"', '"BROKEN"', 1), encoding="utf-8")
    r = X.pair(p["la"], p["lb"])
    assert r["verdict"] == V.BROKEN
    for ex in r["exchanges"]:
        assert ex["status"] == "broken" and ex["disagreement"] is None


def test_pair_exchange_output_is_unchanged_for_the_tally(p):
    """The tally calls pair_exchange; the class is added by pair() only, so
    sealed tally output stays byte-identical."""
    _react(p, "a")
    _react(p, "b", V.BROKEN)
    sa, sb = X.read_side(p["la"], None, "a"), X.read_side(p["lb"], None, "b")
    ex = X.pair_exchange("ex-1", X.latest_heads(sa)["ex-1"], X.latest_heads(sb)["ex-1"],
                         sa["owner"], sb["owner"], [], [])
    assert "disagreement" not in ex and "disagreement_reason" not in ex


def test_could_not_look_pair_has_zero_counts(p):
    r = X.pair(p["la"], p["lb"])
    assert r["verdict"] == V.COULD_NOT_LOOK and r["disagreements"] == ZERO


def test_bad_late_window_is_refused():
    for bad in (-1, True, 1.5, "60"):
        with pytest.raises(ValueError):
            X.classify({"status": "clean", "differs": [], "retracted": []}, None, None,
                       late_after=bad)


def test_text_summary_line_carries_the_class_counts(p):
    _react(p, "a")
    _react(p, "b", at=T0 + timedelta(days=2))
    _react(p, "a", ex="ex-2")
    first = X._render(X.pair(p["la"], p["lb"])).splitlines()[0]
    assert "1 missing, 0 mismatched, 1 late, 0 retracted" in first
    text = X._render(X.pair(p["la"], p["lb"]))
    assert "ex-1: clean [late:" in text and "ex-2: missing [missing:" in text


def test_cli_late_after_and_json(p, capsys):
    _react(p, "a")
    _react(p, "b", at=T0 + timedelta(seconds=90))
    args = ["exchange", "pair", str(p["la"]), str(p["lb"]), "--json"]
    assert cli.main(args) == 0
    assert json.loads(capsys.readouterr().out)["disagreements"]["late"] == 0
    assert cli.main(args + ["--late-after", "60"]) == 0
    r = json.loads(capsys.readouterr().out)
    assert r["late_after"] == 60 and r["disagreements"]["late"] == 1
    for bad in ("-5", "soon", "1.5"):
        assert cli.main(args + ["--late-after", bad]) == V.EXIT_USAGE
    capsys.readouterr()


def test_strict_does_not_mark_late_or_retracted(p, capsys):
    _react(p, "a")
    old = _react(p, "b", V.BROKEN)
    _react(p, "b", V.VERIFIED, supersedes=old["row_digest"])
    _react(p, "a", ex="ex-2")
    _react(p, "b", ex="ex-2", at=T0 + timedelta(days=5))
    r = X.pair(p["la"], p["lb"])
    assert r["disagreements"] == {**ZERO, "late": 1, "retracted": 1}
    assert cli.main(["exchange", "pair", str(p["la"]), str(p["lb"]), "--strict"]) == 0
    capsys.readouterr()


# --- 2. the dispute packet read from the pair -----------------------------------------------

def test_pair_packet_shows_both_sides_and_the_class(p):
    _react(p, "a")
    _react(p, "b", V.BROKEN, disputed="the grades column is empty")
    pk = P.from_pair(p["la"], p["lb"], "ex-1")
    assert pk["kind"] == P.PAIR_KIND == "arcaeon.dispute.pair_packet/v1"
    assert pk["exchange_id"] == "ex-1"
    assert pk["disagreement"] == "mismatched" and pk["differs"] == ["reaction"]
    assert pk["status"] == "mismatch" and pk["pair_verdict"] == V.VERIFIED
    assert pk["sides"]["a"]["record"]["reaction"] == V.VERIFIED
    assert pk["sides"]["b"]["record"]["reaction"] == V.BROKEN
    assert pk["sides"]["a"]["owner"] == p["da"] and pk["sides"]["b"]["owner"] == p["db"]
    assert pk["sides"]["a"]["log"] == "a.jsonl"
    assert [c["side"] for c in pk["claims"]] == ["b"]
    assert pk["limits"] == list(X.DOES_NOT_PROVE_ITEMS)
    assert any("both logs" in t for t in pk["packet_limits"])


def test_pair_packet_carries_no_absolute_path(p):
    _react(p, "a")
    _react(p, "b", V.BROKEN)
    pk = P.from_pair(p["la"], p["lb"], "ex-1")
    js, md = P.render_json(pk), P.render_markdown(pk)
    for text in (js, md):
        assert str(p["tmp"]) not in text and str(p["tmp"]).replace("\\", "/") not in text
        assert str(p["tmp"]).replace("\\", "\\\\") not in text


def test_pair_packet_markdown(p):
    _react(p, "a")
    _react(p, "b", at=T0 + timedelta(days=3))
    md = P.render_markdown(P.from_pair(p["la"], p["lb"], "ex-1"))
    assert md.startswith("# Dispute packet: an exchange read from both logs")
    for s in P.PAIR_SECTIONS:
        assert f"## {s}" in md, s
    assert "**late**" in md and "2026-10-01T12:00:00Z" in md and "2026-10-04T12:00:00Z" in md


def test_pair_packet_missing_side(p):
    _react(p, "a")
    _react(p, "b", ex="ex-0")
    pk = P.from_pair(p["la"], p["lb"], "ex-1")
    assert pk["disagreement"] == "missing" and pk["sides"]["b"]["record"] is None
    assert "no record" in P.render_markdown(pk)


def test_pair_packet_refuses_an_agreeing_exchange(p):
    _react(p, "a")
    _react(p, "b")
    with pytest.raises(P.NothingToDispute):
        P.from_pair(p["la"], p["lb"], "ex-1")


def test_pair_packet_unknown_exchange_and_unreadable_log(p):
    _react(p, "a")
    _react(p, "b")
    with pytest.raises(P.PacketError) as e:
        P.from_pair(p["la"], p["lb"], "ex-404")
    assert not isinstance(e.value, P.NothingToDispute)
    with pytest.raises(P.PacketError):
        P.from_pair(p["la"], p["tmp"] / "nope.jsonl", "ex-1")


def test_pair_packet_renders_a_broken_record(p):
    _react(p, "a")
    _react(p, "b")
    text = p["la"].read_text(encoding="utf-8")
    p["la"].write_text(text.replace('"VERIFIED"', '"BROKEN"', 1), encoding="utf-8")
    pk = P.from_pair(p["la"], p["lb"], "ex-1")
    assert pk["pair_verdict"] == V.BROKEN and pk["status"] == "broken"
    assert pk["disagreement"] is None and pk["sides"]["a"]["broken_rows"]


def test_cli_exchange_packet(p, capsys):
    _react(p, "a")
    _react(p, "b", V.BROKEN)
    base = ["exchange", "packet", str(p["la"]), str(p["lb"])]
    assert cli.main(base + ["--exchange", "ex-1", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["disagreement"] == "mismatched"
    assert cli.main(base + ["--exchange", "ex-1"]) == 0
    assert "mismatched" in capsys.readouterr().out
    out = p["tmp"] / "pk"
    assert cli.main(base + ["--exchange", "ex-1", "--out", str(out)]) == 0
    assert (out / "dispute-packet.md").is_file() and (out / "dispute-packet.json").is_file()
    capsys.readouterr()
    assert cli.main(base) == V.EXIT_USAGE                                  # no --exchange
    assert cli.main(base + ["--exchange", "ex-404"]) == V.EXIT_COULD_NOT_LOOK
    assert cli.main(base + ["--exchange", "ex-1", "--late-after", "x"]) == V.EXIT_USAGE
    capsys.readouterr()


def test_cli_exchange_packet_nothing_to_dispute(p, capsys):
    _react(p, "a")
    _react(p, "b")
    assert cli.main(["exchange", "packet", str(p["la"]), str(p["lb"]),
                     "--exchange", "ex-1"]) == V.EXIT_USAGE
    assert "nothing to dispute" in capsys.readouterr().err.lower()


# --- 4. docs ---------------------------------------------------------------------------

def test_exchange_doc_names_the_classes_packet_and_tool():
    doc = (Path(__file__).resolve().parents[1] / "docs" / "EXCHANGE.md").read_text(
        encoding="utf-8")
    assert "## Disagreement classes" in doc
    for w in ("`missing`", "`mismatched`", "`late`", "`retracted`", "--late-after",
              "86400", "arcaeon exchange packet", "exchange_pair_reconcile"):
        assert w in doc, w
    sec = doc.split("## Disagreement classes", 1)[1]
    assert "cannot prove" in sec.split("\n## ", 1)[0]
