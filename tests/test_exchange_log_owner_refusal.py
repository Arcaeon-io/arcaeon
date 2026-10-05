# SPDX-License-Identifier: MIT
"""A08: a named owner (--owner-a / --owner-b) closes trust on first use.

When the caller names a log's owner and the log's first row that verifies is
signed by another key, the whole log is refused (BROKEN): no row of it is
read and no exchange is lined up from it. Without a named owner the first
good row's signer is the owner, exactly as before.

Every key here is a throwaway seed written to tmp_path; no network."""
from __future__ import annotations

import base64
import json
import secrets
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import exchange_log as X
from arcaeon.record.ledger import Ledger

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")


def _key(tmp_path: Path, name: str):
    from arcaeon.prove.vet import receipts as R
    seed = secrets.token_bytes(32)
    p = tmp_path / f"{name}.key"
    p.write_text(base64.b64encode(seed).decode("ascii") + "\n", encoding="ascii")
    return p, R.did_key(R.public_key_from_seed(seed)), seed


@pytest.fixture
def p(tmp_path):
    ka, da, sa = _key(tmp_path, "a")
    kb, db, sb = _key(tmp_path, "b")
    kc, dc, sc = _key(tmp_path, "c")
    f = tmp_path / "deliverable.csv"
    f.write_bytes(b"id,grade\n1,A\n")
    return {"ka": ka, "da": da, "kb": kb, "db": db, "dc": dc, "sc": sc, "file": f,
            "la": tmp_path / "a.jsonl", "lb": tmp_path / "b.jsonl"}


def _react(p, side, ex="ex-1"):
    other = "b" if side == "a" else "a"
    return X.react(p["l" + side], key_file=p["k" + side], exchange_id=ex,
                   counterparty=p["d" + other], file=p["file"], reaction=V.VERIFIED)


def test_named_owner_differs_from_first_good_row_refuses_the_log(p):
    _react(p, "a")
    _react(p, "b")
    r = X.pair(p["la"], p["lb"], owner_a=p["dc"])
    assert r["verdict"] == V.BROKEN
    side = r["logs"]["a"]
    assert side["owner_from"] == "named" and side["owner"] == p["dc"]
    assert side["owner_refused"] == {"named": p["dc"], "first_row": p["da"]}
    assert "refused" in side["reason"] and p["da"] in side["reason"]
    assert r["exchanges"] == [] and sum(r["counts"].values()) == 0
    assert "refused" in r["reason"]
    json.dumps(r)


def test_stranger_first_row_then_owner_rows_still_refused(p):
    # Someone else's good row heads the log; the named owner's rows come after.
    row = X.build_row(seed=p["sc"], exchange_id="ex-0", counterparty=p["db"],
                      file_sha256="0" * 64, reaction=V.VERIFIED)
    Ledger(p["la"]).append(dict(row))
    seed_a = base64.b64decode(p["ka"].read_text(encoding="ascii").strip())
    Ledger(p["la"]).append(dict(X.build_row(seed=seed_a, exchange_id="ex-1",
                                            counterparty=p["db"], file_sha256="1" * 64,
                                            reaction=V.VERIFIED)))
    _react(p, "b")
    r = X.pair(p["la"], p["lb"], owner_a=p["da"])
    assert r["verdict"] == V.BROKEN
    assert r["logs"]["a"]["owner_refused"] == {"named": p["da"], "first_row": p["dc"]}
    assert r["exchanges"] == []


def test_named_owner_that_matches_is_not_refused(p):
    _react(p, "a")
    _react(p, "b")
    r = X.pair(p["la"], p["lb"], owner_a=p["da"], owner_b=p["db"])
    assert r["verdict"] == V.VERIFIED, r["reason"]
    assert r["logs"]["a"]["owner_refused"] is None
    assert r["exchanges"][0]["status"] == "clean"


def test_without_owner_trust_on_first_use_is_unchanged(p):
    row = X.build_row(seed=p["sc"], exchange_id="ex-1", counterparty=p["db"],
                      file_sha256="0" * 64, reaction=V.VERIFIED)
    Ledger(p["la"]).append(dict(row))
    _react(p, "b")
    r = X.pair(p["la"], p["lb"])
    side = r["logs"]["a"]
    assert side["owner"] == p["dc"] and side["owner_from"] == "first_row"
    assert side["owner_refused"] is None
    assert r["verdict"] == V.VERIFIED, r["reason"]
    assert len(r["exchanges"]) == 1


def test_cli_owner_refusal_exits_1_and_says_why(p, capsys):
    _react(p, "a")
    _react(p, "b")
    args = ["exchange", "pair", str(p["la"]), str(p["lb"])]
    assert cli.main(args) == V.EXIT_GOOD
    capsys.readouterr()
    assert cli.main(args + ["--owner-a", p["dc"]]) == V.EXIT_BAD
    out = capsys.readouterr().out
    assert "refused" in out and p["da"] in out
    assert cli.main(args + ["--owner-a", p["dc"], "--json"]) == V.EXIT_BAD
    r = json.loads(capsys.readouterr().out)
    assert r["logs"]["a"]["owner_refused"]["first_row"] == p["da"]
