# SPDX-License-Identifier: MIT
"""The WITHDRAW row (exchange.withdraw): a party takes its own reaction back
entirely. Append-only, signed by the same party, read as its own word
("withdrawn") in `arcaeon exchange pair` and in the tally.

Every key here is a throwaway seed written to tmp_path; no network."""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import dispute_packet as P
from arcaeon.prove import exchange_log as X
from arcaeon.prove import tally as T
from arcaeon.record.ledger import Ledger
from arcaeon.record.row import canon_json

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

T0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
NOW = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)


def _key(tmp: Path, name: str, b: int) -> tuple[Path, bytes, str]:
    from arcaeon.prove.vet import receipts as R
    seed = bytes([b]) * 32
    p = tmp / f"{name}.key"
    p.write_text(base64.b64encode(seed).decode("ascii") + "\n", encoding="ascii")
    return p, seed, R.did_key(R.public_key_from_seed(seed))


@pytest.fixture
def p(tmp_path):
    out = {"tmp": tmp_path}
    for n, b in (("a", 1), ("b", 2), ("c", 3)):
        out["k" + n], out["s" + n], out["d" + n] = _key(tmp_path, n, b)
        out["l" + n] = tmp_path / f"{n}.jsonl"
    f = tmp_path / "deliverable.csv"
    f.write_bytes(b"id,grade\n1,A\n")
    out["file"] = f
    return out


def _react(p, side, reaction=V.VERIFIED, ex="ex-1", at=T0, other=None, **kw):
    other = other or ("b" if side == "a" else "a")
    return X.react(p["l" + side], key_file=p["k" + side], exchange_id=ex,
                   counterparty=p["d" + other], file=p["file"], reaction=reaction, at=at, **kw)


def _withdraw(p, side, digest, at=T0 + timedelta(hours=1), **kw):
    return X.withdraw(p["l" + side], key_file=p["k" + side], row=digest, at=at, **kw)


def _ex(r, eid="ex-1"):
    return next(e for e in r["exchanges"] if e["exchange_id"] == eid)


def _append(log: Path, row: dict) -> None:
    Ledger(log).append(dict(row))


# --- 1. the row ------------------------------------------------------------------------

def test_the_kind_and_the_word():
    assert X.WITHDRAW_KIND == "exchange.withdraw"
    assert X.WITHDRAW_SIGNED == ("kind", "v", "exchange_id", "withdraws", "reason", "at",
                                 "signer")
    assert X.DISAGREEMENTS[-1] == "withdrawn"
    for name in ("WITHDRAW_KIND", "build_withdraw", "check_withdraw", "withdraw"):
        assert name in X.__all__


def test_withdraw_appends_and_the_original_row_stays(p):
    first = _react(p, "a")
    before = p["la"].read_bytes()
    out = _withdraw(p, "a", first["row_digest"], reason="sent the wrong file id")
    assert p["la"].read_bytes().startswith(before)          # append-only
    row = out["row"]
    assert row["kind"] == X.WITHDRAW_KIND and row["withdraws"] == first["row_digest"]
    assert row["exchange_id"] == "ex-1" and row["signer"] == p["da"]
    assert row["reason"] == "sent the wrong file id"
    assert X.check_withdraw(row) is None
    assert out["row_digest"].startswith("sha256:json-c14n:v1:")
    lines = [json.loads(x) for x in p["la"].read_text(encoding="utf-8").splitlines() if x]
    assert [x["kind"] for x in lines] == [X.KIND, X.WITHDRAW_KIND]


def test_pair_reads_withdrawn_as_its_own_word(p):
    _react(p, "b")
    first = _react(p, "a")
    _withdraw(p, "a", first["row_digest"])
    r = X.pair(p["la"], p["lb"])
    assert r["verdict"] == V.VERIFIED
    ex = _ex(r)
    assert ex["status"] == "missing"                 # a has no current reaction
    assert ex["withdrawn"] == ["a"] and ex["retracted"] == []
    assert ex["disagreement"] == "withdrawn"
    assert "withdrew" in ex["disagreement_reason"]
    assert r["disagreements"]["withdrawn"] == 1 and r["disagreements"]["missing"] == 0
    assert r["withdrawn"] == 1
    assert r["logs"]["a"]["withdraw_rows"] == 1
    text = X._render(r)
    assert "ex-1: missing [withdrawn:" in text
    assert text.splitlines()[0].endswith("0 retracted, 1 withdrawn")


def test_a_withdraw_signed_by_the_other_party_is_broken(p):
    first = _react(p, "a")
    _react(p, "b")
    forged = X.build_withdraw(seed=p["sb"], exchange_id="ex-1", withdraws=first["row_digest"],
                              at=T0 + timedelta(hours=1))
    _append(p["la"], forged)
    r = X.pair(p["la"], p["lb"])
    assert r["verdict"] == V.BROKEN
    assert _ex(r)["status"] == "broken"
    assert "not by the key that owns this log" in r["logs"]["a"]["broken_rows"][0]["finding"]


def test_a_withdraw_signed_by_a_stranger_is_broken(p):
    first = _react(p, "a")
    _react(p, "b")
    _append(p["la"], X.build_withdraw(seed=p["sc"], exchange_id="ex-1",
                                      withdraws=first["row_digest"]))
    assert X.pair(p["la"], p["lb"])["verdict"] == V.BROKEN


def test_a_withdraw_of_the_other_partys_row_is_broken_and_refused(p):
    _react(p, "a")
    theirs = _react(p, "b")
    with pytest.raises(X.ExchangeError):
        _withdraw(p, "a", theirs["row_digest"])
    _append(p["la"], X.build_withdraw(seed=p["sa"], exchange_id="ex-1",
                                      withdraws=theirs["row_digest"]))
    r = X.pair(p["la"], p["lb"])
    assert r["verdict"] == V.BROKEN
    assert "not an earlier reaction in this log" in r["logs"]["a"]["broken_rows"][0]["finding"]


def test_a_withdraw_of_a_withdraw_is_refused_and_broken(p):
    first = _react(p, "a")
    _react(p, "b")
    w = _withdraw(p, "a", first["row_digest"])
    with pytest.raises(X.ExchangeError):
        _withdraw(p, "a", w["row_digest"])
    _append(p["la"], X.build_withdraw(seed=p["sa"], exchange_id="ex-1",
                                      withdraws=w["row_digest"]))
    r = X.pair(p["la"], p["lb"])
    assert r["verdict"] == V.BROKEN
    assert "withdraw row" in r["logs"]["a"]["broken_rows"][0]["finding"]


def test_a_withdrawn_reaction_is_not_reinstated_by_supersedes(p):
    first = _react(p, "a")
    _react(p, "b")
    _withdraw(p, "a", first["row_digest"])
    with pytest.raises(X.ExchangeError):
        _react(p, "a", supersedes=first["row_digest"], at=T0 + timedelta(hours=2))
    from arcaeon.prove.envelope import _load_seed
    row = X.build_row(seed=_load_seed(p["ka"]), exchange_id="ex-1", counterparty=p["db"],
                      file_sha256=first["row"]["file_sha256"], reaction=V.VERIFIED,
                      supersedes=first["row_digest"], at=T0 + timedelta(hours=2))
    _append(p["la"], row)
    r = X.pair(p["la"], p["lb"])
    assert r["verdict"] == V.BROKEN
    assert "withdrawn" in r["logs"]["a"]["broken_rows"][0]["finding"]


def test_twice_withdrawn_and_superseded_targets_are_broken(p):
    first = _react(p, "a")
    second = _react(p, "a", V.BROKEN, supersedes=first["row_digest"], at=T0 + timedelta(1))
    _react(p, "b")
    with pytest.raises(X.ExchangeError):                     # name the current row
        _withdraw(p, "a", first["row_digest"])
    _withdraw(p, "a", second["row_digest"], at=T0 + timedelta(2))
    with pytest.raises(X.ExchangeError):
        _withdraw(p, "a", second["row_digest"], at=T0 + timedelta(3))
    _append(p["la"], X.build_withdraw(seed=p["sa"], exchange_id="ex-1",
                                      withdraws=second["row_digest"]))
    r = X.pair(p["la"], p["lb"])
    assert r["verdict"] == V.BROKEN
    assert "already withdrawn" in r["logs"]["a"]["broken_rows"][0]["finding"]


def test_a_new_reaction_after_a_withdraw_is_a_new_row_with_a_mark(p):
    first = _react(p, "a")
    _react(p, "b")
    _withdraw(p, "a", first["row_digest"])
    _react(p, "a", at=T0 + timedelta(hours=2))
    r = X.pair(p["la"], p["lb"])
    ex = _ex(r)
    assert ex["status"] == "clean" and ex["a"]["withdrawn"] == 1
    assert ex["withdrawn"] == ["a"] and ex["disagreement"] == "withdrawn"


# --- 2. precedence ------------------------------------------------------------------------

def test_missing_wins_over_withdrawn(p):
    first = _react(p, "a")
    _react(p, "a", ex="ex-2")
    _react(p, "b", ex="ex-2")
    _withdraw(p, "a", first["row_digest"])
    ex = _ex(X.pair(p["la"], p["lb"]))
    assert ex["disagreement"] == "missing" and ex["withdrawn"] == ["a"]
    assert "log b has no record" in ex["disagreement_reason"]


def test_mismatched_wins_over_a_withdrawn_mark(p):
    first = _react(p, "a")
    _react(p, "b", V.BROKEN)
    _withdraw(p, "a", first["row_digest"])
    _react(p, "a", at=T0 + timedelta(hours=2))
    assert _ex(X.pair(p["la"], p["lb"]))["disagreement"] == "mismatched"


def test_withdrawn_wins_over_retracted_and_late(p):
    old = _react(p, "b", V.BROKEN)
    _react(p, "b", supersedes=old["row_digest"], at=T0 + timedelta(days=3))
    first = _react(p, "a")
    _withdraw(p, "a", first["row_digest"])
    ex = _ex(X.pair(p["la"], p["lb"]))
    assert ex["retracted"] == ["b"] and ex["withdrawn"] == ["a"]
    assert ex["disagreement"] == "withdrawn"


def test_both_sides_withdrawn(p):
    fa, fb = _react(p, "a"), _react(p, "b")
    _withdraw(p, "a", fa["row_digest"])
    _withdraw(p, "b", fb["row_digest"])
    ex = _ex(X.pair(p["la"], p["lb"]))
    assert ex["withdrawn"] == ["a", "b"] and ex["disagreement"] == "withdrawn"


def test_strict_marks_a_withdrawn_exchange_with_no_current_row(p, capsys):
    first = _react(p, "a")
    _react(p, "b")
    _withdraw(p, "a", first["row_digest"])
    args = ["exchange", "pair", str(p["la"]), str(p["lb"])]
    assert cli.main(args) == 0
    assert cli.main(args + ["--strict"]) == V.EXIT_BAD
    capsys.readouterr()


# --- 3. CLI, packet ----------------------------------------------------------------------

def test_cli_withdraw(p, capsys):
    first = _react(p, "a")
    args = ["exchange", "withdraw", "--row", first["row_digest"], "--key", str(p["ka"]),
            "--log", str(p["la"])]
    assert cli.main(args + ["--reason", "wrong exchange"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True and out["row"]["kind"] == X.WITHDRAW_KIND
    assert cli.main(args) == V.EXIT_USAGE                    # already withdrawn
    assert "nothing was written" in capsys.readouterr().err
    assert cli.main(["exchange", "withdraw", "--key", str(p["ka"])]) == V.EXIT_USAGE
    capsys.readouterr()


def test_packet_for_a_withdrawn_exchange(p):
    first = _react(p, "a")
    _react(p, "b")
    _withdraw(p, "a", first["row_digest"])
    pk = P.from_pair(p["la"], p["lb"], "ex-1")
    assert pk["disagreement"] == "withdrawn" and pk["sides"]["a"]["withdrawn"] is True
    assert "withdrew" in P.render_markdown(pk)


# --- 4. the tally ------------------------------------------------------------------------

def _tally_scene(p, monkeypatch):
    monkeypatch.chdir(p["tmp"])

    def rx(me, other, ex, word=V.VERIFIED, days=1.0, **kw):
        return X.react(f"{me}.jsonl", key_file=f"{me}.key", exchange_id=ex,
                       counterparty=p["d" + other], file="deliverable.csv", reaction=word,
                       at=NOW - timedelta(days=days), **kw)
    return rx


def test_tally_counts_a_withdrawal_not_a_reaction(p, monkeypatch):
    rx = _tally_scene(p, monkeypatch)
    rx("b", "a", "e1")
    first = rx("a", "b", "e1")
    X.withdraw("a.jsonl", key_file="a.key", row=first["row_digest"],
               at=NOW - timedelta(hours=12))
    rx("a", "b", "e2"); rx("b", "a", "e2")
    r = T.build(["a.jsonl", "b.jsonl"], now=NOW)
    assert r["verdict"] == V.VERIFIED
    a = next(i for i in r["ids"] if i["id"] == p["da"])
    b = next(i for i in r["ids"] if i["id"] == p["db"])
    wa, wb = a["windows"]["all"], b["windows"]["all"]
    assert wa["said"]["total"] == 1                          # e2 only
    assert wa["withdrawn"] == {"said": 1, "received": 0}
    assert wb["withdrawn"] == {"said": 0, "received": 1}
    assert wb["received"]["total"] == 1
    assert wb["paired"]["missing"] == 1                      # b's e1 has no answer now
    assert "withdrawn" in r["definitions"]
    text = T.render(r)
    assert "withdrawn said" in text and "withdrawn received" in text


def test_tally_without_withdraw_rows_is_byte_identical(p, monkeypatch):
    """Golden digests taken at d964ec4 (before the withdraw row existed) over
    this exact scene: sealed tally snapshots depend on these bytes."""
    rx = _tally_scene(p, monkeypatch)
    rx("a", "b", "e1"); rx("b", "a", "e1")
    old = rx("a", "b", "e2", V.BROKEN, 3)
    rx("a", "b", "e2", V.VERIFIED, 2, supersedes=old["row_digest"])
    rx("b", "a", "e2", V.VERIFIED, 2)
    rx("a", "c", "e3", V.COULD_NOT_LOOK, 40)
    rx("c", "a", "e3", V.VERIFIED, 39, disputed="the grade column is empty")
    rx("b", "c", "e4")
    r = T.build(["a.jsonl", "b.jsonl", "c.jsonl"], now=NOW)
    assert "withdrawn" not in json.dumps(r)
    assert hashlib.sha256(canon_json(r)).hexdigest() == \
        "0e07c2b764ca94c6a75a295dd708fbe407d1930d428c44a4cd9907e8104f1627"
    assert hashlib.sha256(T.render(r).encode("utf-8")).hexdigest() == \
        "ae7260495ad1ab909a12b92efa5d91f44b3505c09b296f69074f5bfb387ea69b"


def test_tally_fork_check_sees_a_withdraw(p, monkeypatch):
    """A copy of a chain taken before a withdraw and the chain after it are
    one history (an exact prefix), not a fork: the longer one is read."""
    rx = _tally_scene(p, monkeypatch)
    rx("b", "a", "e1")
    first = rx("a", "b", "e1")
    (p["tmp"] / "a-old.jsonl").write_bytes((p["tmp"] / "a.jsonl").read_bytes())
    X.withdraw("a.jsonl", key_file="a.key", row=first["row_digest"],
               at=NOW - timedelta(hours=12))
    for order in (["a-old.jsonl", "a.jsonl", "b.jsonl"], ["a.jsonl", "a-old.jsonl", "b.jsonl"]):
        r = T.build(order, now=NOW)
        a = next(i for i in r["ids"] if i["id"] == p["da"])
        assert r["verdict"] == V.VERIFIED
        assert a["windows"]["all"]["withdrawn"]["said"] == 1, order


# --- 5. docs -------------------------------------------------------------------------------

def test_exchange_doc_names_the_withdraw_row():
    doc = (Path(__file__).resolve().parents[1] / "docs" / "EXCHANGE.md").read_text(
        encoding="utf-8")
    assert "## Withdraw" in doc
    sec = doc.split("## Withdraw", 1)[1].split("\n## ", 1)[0]
    for w in ("exchange.withdraw", "arcaeon exchange withdraw", "`withdrawn`", "precedence",
              "BROKEN", "cannot prove"):
        assert w in sec, w
