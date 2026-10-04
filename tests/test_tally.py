# SPDX-License-Identifier: MIT
"""D058 / TE-43 + TE-44: the tally as facts, no score.

Every key here is a throwaway seed written to tmp_path; no network."""
from __future__ import annotations

import base64
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import exchange_log as X
from arcaeon.prove import tally as T
from arcaeon.record.ledger import Ledger

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

NOW = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)
NOW_S = "2026-10-04T12:00:00Z"


class Party:
    def __init__(self, tmp: Path, name: str):
        from arcaeon.prove.vet import receipts as R
        self.seed = secrets.token_bytes(32)
        self.key = tmp / f"{name}.key"
        self.key.write_text(base64.b64encode(self.seed).decode("ascii") + "\n", encoding="ascii")
        self.did = R.did_key(R.public_key_from_seed(self.seed))
        self.log = tmp / f"{name}.jsonl"


@pytest.fixture
def w(tmp_path):
    f = tmp_path / "deliverable.csv"
    f.write_bytes(b"id,grade\n1,A\n")
    return {"tmp": tmp_path, "file": f, **{n: Party(tmp_path, n) for n in "abcdn"}}


def react(w, me: Party, other: Party | str, ex: str, reaction=V.VERIFIED, days_ago=1.0, **kw):
    cp = other if isinstance(other, str) else other.did
    return X.react(me.log, key_file=me.key, exchange_id=ex, counterparty=cp, file=w["file"],
                   reaction=reaction, at=NOW - timedelta(days=days_ago), **kw)


def both(w, p, q, ex, days_ago=1.0, rp=V.VERIFIED, rq=V.VERIFIED):
    react(w, p, q, ex, rp, days_ago)
    react(w, q, p, ex, rq, days_ago)


def tally(*parties, **kw):
    kw.setdefault("now", NOW)
    return T.build([p.log if isinstance(p, Party) else p for p in parties], **kw)


def by_id(r, did):
    hits = [i for i in r["ids"] if i["id"] == did]
    assert len(hits) == 1, [i["id"] for i in r["ids"]]
    return hits[0]


def _keys(o):
    if isinstance(o, dict):
        for k, v in o.items():
            yield k
            yield from _keys(v)
    elif isinstance(o, list):
        for v in o:
            yield from _keys(v)


def _values(o):
    if isinstance(o, dict):
        for v in o.values():
            yield from _values(v)
    elif isinstance(o, list):
        for v in o:
            yield from _values(v)
    else:
        yield o


# --- the facts ----------------------------------------------------------------------------

def test_happy_tally_counts_in_columns(w):
    a, b = w["a"], w["b"]
    both(w, a, b, "ex-1")
    both(w, a, b, "ex-2", rq=V.BROKEN)
    r = tally(a, b)
    assert r["verdict"] == V.VERIFIED, r["reason"]
    ia = by_id(r, a.did)
    al = ia["windows"]["all"]
    assert al["said"]["share_verified"] == "2 of 2"
    assert al["received"]["share_verified"] == "1 of 2" and al["received"][V.BROKEN] == 1
    assert al["paired"]["clean"] == 1 and al["paired"]["mismatch"] == 1
    assert al["paired"]["share_clean"] == "1 of 2"
    assert al["disagreements"] == 1 and al["exchanges"] == 2
    assert al["counterparties_with_records"] == 1
    assert ia["flags"][0] == "BROKEN"          # b said BROKEN about an exchange with a
    assert set(ia["windows"]) == {"30d", "all"}


def test_no_score_weight_or_rank_anywhere(w):
    both(w, w["a"], w["b"], "ex-1")
    r = tally(w["a"], w["b"])
    for k in _keys(r):
        assert not re.search(r"score|weight|rank", k, re.I), k
    for v in _values(r):
        assert not isinstance(v, float), v   # never a bare rate
    for i in r["ids"]:
        for b in i["windows"].values():
            for blk, key in (("said", "share_verified"), ("received", "share_verified"),
                             ("paired", "share_clean")):
                assert re.fullmatch(r"\d+ of \d+", b[blk][key])


def test_sentence_in_json_and_text(w, capsys):
    both(w, w["a"], w["b"], "ex-1")
    r = tally(w["a"], w["b"])
    assert r["sentence"] == "clean means unchanged and labeled, never true"
    assert "clean means unchanged and labeled, never true" in json.dumps(r)
    assert "clean means unchanged and labeled, never true" in T.render(r)
    for extra in ([], ["--json"]):
        rc = cli.main(["tally", "build", str(w["a"].log), str(w["b"].log), "--now", NOW_S,
                       *extra])
        assert rc == 0
        assert "clean means unchanged and labeled, never true" in capsys.readouterr().out
    # even a COULD NOT LOOK tally carries it
    r = T.build([w["tmp"] / "nope.jsonl"], now=NOW)
    assert r["verdict"] == V.COULD_NOT_LOOK and r["sentence"] == T.SENTENCE
    assert T.SENTENCE in T.render(r)


def test_text_shows_counts_beside_share_and_windows_side_by_side(w):
    both(w, w["a"], w["b"], "ex-1")
    both(w, w["a"], w["b"], "ex-old", days_ago=60)
    out = T.render(tally(w["a"], w["b"]))
    header = [ln for ln in out.splitlines() if ln.strip().startswith("30d")]
    assert header and header[0].split() == ["30d", "all"]
    line = next(ln for ln in out.splitlines() if ln.strip().startswith("said VERIFIED"))
    assert re.search(r"1 of 1\s+2 of 2$", line), line
    assert "%" not in out


# --- the window and the unrated threshold ----------------------------------------------------

def test_window_boundary_inclusive(w):
    a, b = w["a"], w["b"]
    both(w, a, b, "edge", days_ago=30)                        # exactly now - 30d: in
    both(w, a, b, "past", days_ago=30 + 1 / 86400)            # one second earlier: out
    r = tally(a, b)
    ia = by_id(r, a.did)
    assert ia["windows"]["30d"]["said"]["total"] == 1
    assert ia["windows"]["30d"]["exchanges"] == 1
    assert ia["windows"]["all"]["said"]["total"] == 2
    assert r["windows"][0] == {"name": "30d", "from": "2026-09-04T12:00:00Z", "to": NOW_S}


def test_custom_window(w):
    both(w, w["a"], w["b"], "ex-1", days_ago=3)
    r = tally(w["a"], w["b"], window="2d")
    ia = by_id(r, w["a"].did)
    assert ia["windows"]["2d"]["said"]["total"] == 0 and ia["windows"]["all"]["said"]["total"] == 1
    with pytest.raises(T.TallyError):
        tally(w["a"], window="30x")


def test_future_rows_are_in_no_window(w):
    both(w, w["a"], w["b"], "ex-f", days_ago=-2)
    ia = by_id(tally(w["a"], w["b"]), w["a"].did)
    assert ia["windows"]["all"]["said"]["total"] == 0
    assert any("after now" in f for f in ia["findings"])


def test_unrated_under_ten_exchanges(w):
    a, b = w["a"], w["b"]
    for n in range(9):
        both(w, a, b, f"ex-{n}", days_ago=20)
    ia = by_id(tally(a, b), a.did)
    assert ia["unrated"] and "unrated" in ia["flags"]
    assert any("9 exchanges" in x for x in ia["unrated_because"])
    both(w, a, b, "ex-9", days_ago=20)
    ia = by_id(tally(a, b), a.did)
    assert not ia["unrated"] and "unrated" not in ia["flags"], ia["unrated_because"]
    assert ia["windows"]["all"]["said"]["share_verified"] == "10 of 10"


def test_unrated_under_fourteen_days(w):
    a, b = w["a"], w["b"]
    for n in range(10):
        both(w, a, b, f"ex-{n}", days_ago=13.9)
    ia = by_id(tally(a, b), a.did)
    assert ia["unrated"] and ia["age_days"] == 13
    assert any("13 days old" in x for x in ia["unrated_because"])
    ia = by_id(tally(a, b, now=NOW + timedelta(days=1)), a.did)
    assert ia["age_days"] == 14 and not ia["unrated"]


def test_unpaired_rows_do_not_count_toward_rating(w):
    """Ten rows naming keys with no chain among the inputs: said counts them,
    nothing pairs, the ID stays unrated."""
    a = w["a"]
    for n in range(10):
        react(w, a, Party(w["tmp"], f"ghost{n}"), f"ex-{n}", days_ago=20)
    ia = by_id(tally(a), a.did)
    assert ia["windows"]["all"]["said"]["share_verified"] == "10 of 10"
    assert ia["windows"]["all"]["exchanges"] == 0
    assert ia["windows"]["all"]["counterparties_with_records"] == 0
    assert ia["unrated"]


# --- gaming rules ---------------------------------------------------------------------------

def test_gaming_a_self_trade_naming_own_key_is_excluded(w):
    a = w["a"]
    row = X.build_row(seed=a.seed, exchange_id="self-1", counterparty=a.did,
                      file_sha256="0" * 64, reaction=V.VERIFIED, at=NOW - timedelta(days=1))
    Ledger(a.log).append(dict(row))
    ia = by_id(tally(a), a.did)
    assert ia["windows"]["all"]["said"]["total"] == 0
    assert ia["excluded"] and "own key" in ia["excluded"][0]["reason"]
    assert ia["windows"]["all"]["excluded"] == 1


def test_gaming_a_declared_group_is_excluded_both_sides(w):
    a, b, c = w["a"], w["b"], w["c"]
    both(w, a, b, "pump-1")
    both(w, a, c, "real-1")
    g = w["tmp"] / "groups.json"
    g.write_text(json.dumps({"groups": [{"name": "acme", "members": [a.did, b.did]}]}))
    r = tally(a, b, c, groups=g)
    assert r["verdict"] == V.VERIFIED
    ia, ib = by_id(r, a.did), by_id(r, b.did)
    assert ia["windows"]["all"]["said"]["total"] == 1
    assert ia["windows"]["all"]["exchanges"] == 1
    assert ia["windows"]["all"]["counterparties_with_records"] == 1
    assert ib["windows"]["all"]["said"]["total"] == 0
    reasons = {e["reason"] for e in ia["excluded"]}
    assert any("declared group 'acme'" in x for x in reasons)
    assert any(e["exchange_id"] == "pump-1" for e in ib["excluded"])
    # without the group the same trade counts
    ia = by_id(tally(a, b, c), a.did)
    assert ia["windows"]["all"]["exchanges"] == 2


def test_gaming_b_broken_flag_first_and_broken_ids_first(w):
    a, b, c = w["a"], w["b"], w["c"]
    both(w, a, c, "ex-1")
    both(w, b, c, "ex-2", rq=V.BROKEN)       # c says BROKEN about the exchange with b
    react(w, a, c, "ex-3", disputed="late")
    r = tally(a, b, c)
    assert r["ids"][0]["id"] == b.did
    ib = by_id(r, b.did)
    assert ib["flags"][0] == "BROKEN"
    assert ib["windows"]["30d"]["flags"][0] == "BROKEN"
    ia = by_id(r, a.did)
    assert ia["flags"][0] == "DISPUTED" and "BROKEN" not in ia["flags"]
    out = T.render(r)
    assert out.index(b.did + "  BROKEN") < out.index(a.did + "  DISPUTED")


def test_broken_chain_flags_the_owner_and_the_tally(w):
    a, b = w["a"], w["b"]
    both(w, a, b, "ex-1")
    both(w, a, b, "ex-2")
    lines = a.log.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[0])
    row["reaction"] = V.BROKEN                     # edit a signed field in place
    lines[0] = json.dumps(row)
    a.log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    r = tally(a, b)
    assert r["verdict"] == V.BROKEN
    ia = by_id(r, a.did)
    assert ia["flags"][0] == "BROKEN" and ia["record_broken"]
    ib = by_id(r, b.did)                 # its pair with a holds the broken row
    assert ib["flags"][0] == "BROKEN" and ib["record_broken"] == []
    assert ib["windows"]["all"]["paired"]["broken"] == 1
    assert {i["id"] for i in r["ids"][:2]} == {a.did, b.did}
    assert cli.main(["tally", "build", str(a.log), str(b.log), "--now", NOW_S]) == 1


def test_gaming_c_windows_side_by_side(w):
    a, b = w["a"], w["b"]
    both(w, a, b, "old", days_ago=90, rq=V.BROKEN)
    both(w, a, b, "new", days_ago=2)
    ia = by_id(tally(a, b), a.did)
    assert ia["windows"]["30d"]["flags"] == []
    assert ia["windows"]["all"]["flags"] == ["BROKEN"]
    assert ia["flags"][0] == "BROKEN"       # an old break is not forgotten


def _alias_file(w, old_p: Party, new_p: Party, **mut) -> Path:
    e = T.sign_alias(old_p.seed, new_p.seed, NOW - timedelta(days=1))
    e.update(mut)
    p = w["tmp"] / "aliases.json"
    p.write_text(json.dumps({"aliases": [e]}))
    return p


def test_gaming_d_alias_inherits_history(w):
    a, n, b = w["a"], w["n"], w["b"]
    for k in range(10):
        both(w, a, b, f"old-{k}", days_ago=60, rq=V.BROKEN if k == 0 else V.VERIFIED)
    both(w, n, b, "new-1", days_ago=1)
    r = tally(a, n, b, aliases=_alias_file(w, a, n))
    assert r["aliases"][0]["applied"] is True
    assert [i["id"] for i in r["ids"]].count(a.did) == 1
    assert n.did not in [i["id"] for i in r["ids"]]
    ia = by_id(r, a.did)
    assert ia["keys"] == sorted([a.did, n.did])
    assert ia["windows"]["all"]["exchanges"] == 11
    assert ia["flags"][0] == "BROKEN" and not ia["unrated"]


def test_gaming_d_fresh_key_without_alias_is_new_and_unrated(w):
    a, n, b = w["a"], w["n"], w["b"]
    for k in range(10):
        both(w, a, b, f"old-{k}", days_ago=60, rq=V.BROKEN if k == 0 else V.VERIFIED)
    both(w, n, b, "new-1", days_ago=1)
    r = tally(a, n, b)
    i_n = by_id(r, n.did)
    assert i_n["unrated"] and "BROKEN" not in i_n["flags"] and i_n["age_days"] == 1
    assert any("fresh key" in x for x in r["limits"])


def test_alias_with_a_bad_signature_is_broken_and_not_applied(w):
    a, n, c = w["a"], w["n"], w["c"]
    both(w, a, c, "ex-1")
    both(w, n, c, "ex-2")
    bad = _alias_file(w, a, n, new=c.did)        # retarget after signing
    r = tally(a, n, c, aliases=bad)
    assert r["verdict"] == V.BROKEN
    assert r["aliases"][0]["applied"] is False and "BROKEN" in r["aliases"][0]["finding"]
    assert {i["id"] for i in r["ids"]} == {a.did, n.did, c.did}


def test_alias_needs_both_signatures(w):
    a, n = w["a"], w["n"]
    both(w, a, w["b"], "ex-1")
    p = _alias_file(w, a, n)
    e = json.loads(p.read_text())["aliases"][0]
    del e["sig_new"]
    p.write_text(json.dumps([e]))
    r = tally(a, aliases=p)
    assert r["aliases"][0]["applied"] is False
    assert r["aliases"][0]["finding"].startswith(V.COULD_NOT_LOOK)


def test_alias_cli_prints_a_signed_entry(w, capsys):
    rc = cli.main(["tally", "alias", "--old-key", str(w["a"].key), "--new-key", str(w["n"].key),
                   "--at", NOW_S])
    assert rc == 0
    e = json.loads(capsys.readouterr().out)
    assert e["old"] == w["a"].did and e["new"] == w["n"].did
    assert T.check_alias(e) == (None, None)


# --- filters ----------------------------------------------------------------------------------

def test_checked_only_drops_could_not_look(w):
    a, b = w["a"], w["b"]
    both(w, a, b, "ex-1")
    both(w, a, b, "ex-2", rp=V.COULD_NOT_LOOK, rq=V.COULD_NOT_LOOK)
    ia = by_id(tally(a, b, checked_only=True), a.did)
    assert ia["windows"]["all"]["said"]["share_verified"] == "1 of 1"
    assert ia["windows"]["all"]["paired"]["total"] == 1
    assert ia["filtered_out"] == {"said": 1, "received": 1, "paired": 1}


def test_settled_only_drops_disputed_and_unpaired(w):
    a, b = w["a"], w["b"]
    both(w, a, b, "ex-1")
    react(w, a, b, "ex-2")                                 # b never answered
    react(w, a, b, "ex-3")
    react(w, b, a, "ex-3", disputed="wrong file")
    react(w, a, w["c"], "ex-4")                            # c has no chain here
    r = tally(a, b, settled_only=True)
    assert r["filters"]["settled_only"] is True
    ia = by_id(r, a.did)
    assert ia["windows"]["all"]["said"]["total"] == 1
    assert ia["windows"]["all"]["paired"]["total"] == 1
    assert ia["filtered_out"]["said"] == 3


# --- hostile input ------------------------------------------------------------------------------

@pytest.mark.parametrize("body", [b"", b"\xff\xfe garbage", b"not json\n", b"[1,2,3]\n",
                                  b'{"kind":"exchange.reaction"}\n', b"{" * 5000])
def test_hostile_chain_is_could_not_look_or_broken(w, body):
    bad = w["tmp"] / "bad.jsonl"
    bad.write_bytes(body)
    both(w, w["a"], w["b"], "ex-1")
    r = tally(w["a"], w["b"], bad)
    assert r["verdict"] in (V.COULD_NOT_LOOK, V.BROKEN)
    assert r["sentence"] == T.SENTENCE
    json.dumps(r)
    T.render(r)


def test_forged_row_in_a_chain_is_broken(w):
    a, b, c = w["a"], w["b"], w["c"]
    both(w, a, b, "ex-1")
    row = X.build_row(seed=c.seed, exchange_id="ex-9", counterparty=b.did,
                      file_sha256="0" * 64, reaction=V.VERIFIED, at=NOW)
    Ledger(a.log).append(dict(row))                       # c's row in a's chain
    r = tally(a, b)
    assert r["verdict"] == V.BROKEN
    assert by_id(r, a.did)["flags"][0] == "BROKEN"


def test_missing_chain_and_bad_side_files(w, capsys):
    both(w, w["a"], w["b"], "ex-1")
    r = tally(w["a"], w["tmp"] / "gone.jsonl")
    assert r["verdict"] == V.COULD_NOT_LOOK and r["ids"]
    g = w["tmp"] / "g.json"
    g.write_text("{not json")
    r = tally(w["a"], w["b"], groups=g)
    assert r["verdict"] == V.COULD_NOT_LOOK and r["ids"] == []
    g.write_text(json.dumps({"groups": [["did:key:nope", w["a"].did]]}))
    assert tally(w["a"], groups=g)["verdict"] == V.COULD_NOT_LOOK
    assert tally(w["a"], aliases=w["tmp"] / "none.json")["verdict"] == V.COULD_NOT_LOOK
    assert T.build([], now=NOW)["verdict"] == V.COULD_NOT_LOOK
    assert cli.main(["tally", "build", str(w["tmp"] / "gone.jsonl"), "--now", NOW_S]) == 3
    assert cli.main(["tally", "build", "--now", "yesterday", str(w["a"].log)]) == 2
    assert cli.main(["tally", "build"]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_build_is_importable_with_paths():
    from arcaeon.prove.tally import build  # noqa: F401  D059 stacks on this
    assert T.KIND == "arcaeon.tally/v1"
