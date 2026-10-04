# SPDX-License-Identifier: MIT
"""D059 / TE-47: the tally and the exchange logs sealed as a chain of their own.

Every key here is a throwaway seed written to tmp_path; no network, no live pin."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import exchange_log as X
from arcaeon.prove import tally_chain as TC
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
        self.log = tmp / "logs" / f"{name}.jsonl"


@pytest.fixture
def w(tmp_path):
    (tmp_path / "logs").mkdir()
    f = tmp_path / "deliverable.csv"
    f.write_bytes(b"id,grade\n1,A\n")
    a, b = Party(tmp_path, "a"), Party(tmp_path, "b")
    w = {"tmp": tmp_path, "file": f, "a": a, "b": b, "log": tmp_path / "chain" / "TALLY.jsonl"}
    both(w, "ex-1", days_ago=2)
    both(w, "ex-2", days_ago=1)
    return w


def react(w, me, other, ex, reaction=V.VERIFIED, days_ago=1.0):
    return X.react(me.log, key_file=me.key, exchange_id=ex, counterparty=other.did,
                   file=w["file"], reaction=reaction, at=NOW - timedelta(days=days_ago))


def both(w, ex, days_ago=1.0):
    react(w, w["a"], w["b"], ex, days_ago=days_ago)
    react(w, w["b"], w["a"], ex, days_ago=days_ago)


def seal(w, at=None, **kw):
    kw.setdefault("now", NOW)
    return TC.seal([w["a"].log, w["b"].log], log=w["log"], at=at, **kw)


def inputs(w):
    return [w["a"].log, w["b"].log]


def rows(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def rewrite(path: Path, rs: list[dict]) -> None:
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rs),
                    encoding="utf-8")


# --- seal and verify ------------------------------------------------------------------------

def test_seal_then_verify(w):
    out = seal(w)
    row = out["row"]
    assert row["kind"] == "tally.snapshot" and row["v"] == 1
    assert row["tally_verdict"] == V.VERIFIED
    assert [i["name"] for i in row["inputs"]] == ["a.jsonl", "b.jsonl"]
    for i, p in zip(row["inputs"], inputs(w)):
        assert i["sha256"] == hashlib.sha256(p.read_bytes()).hexdigest()
        assert i["chain_tip"] == rows(p)[-1]["chain"] and i["rows"] == 2
    assert row["tally_sha256"] == hashlib.sha256(
        json.dumps(out["tally"], sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False).encode()).hexdigest()
    r = TC.verify(w["log"])
    assert r["verdict"] == V.VERIFIED, r["reason"]
    assert "inputs not checked" in r["reason"]
    r = TC.verify(w["log"], inputs=inputs(w))
    assert r["verdict"] == V.VERIFIED, r["reason"]
    assert r["snapshots"][0]["tally_rebuilt"] == V.VERIFIED


def test_no_absolute_paths_in_sealed_rows(w):
    out_file = w["tmp"] / "tally.json"
    seal(w, groups=None, out=out_file)
    both(w, "ex-3")
    seal(w)
    text = w["log"].read_text(encoding="utf-8")
    tally_text = out_file.read_text(encoding="utf-8")
    for t in (text, tally_text):
        for form in {str(w["tmp"]), str(w["tmp"]).replace("\\", "/"),
                     str(w["tmp"].resolve()), str(w["tmp"].resolve()).replace("\\", "/")}:
            assert form not in t
        assert "logs/" not in t and "logs\\\\" not in t   # no parent folder survives
    for row in rows(w["log"]):
        assert TC._absolute_strings(row) == []
        for i in row["inputs"]:
            assert i["name"] == Path(i["name"]).name
    t = json.loads(tally_text)
    assert [c["log"] for c in t["chains"]] == ["a.jsonl", "b.jsonl"]
    assert all(set(i["chains"]) <= {"a.jsonl", "b.jsonl"} for i in t["ids"])
    assert TC._absolute_strings(t) == []


def test_could_not_look_tally_seals_names_not_paths(w):
    odd = w["tmp"] / "logs" / "notes.jsonl"
    odd.write_text("hello\n", encoding="utf-8")
    out = TC.seal([w["a"].log, odd], log=w["log"], now=NOW, out=w["tmp"] / "t.json")
    assert out["row"]["tally_verdict"] == V.COULD_NOT_LOOK
    t = out["tally"]
    assert t["chains"][1]["where"] == "notes.jsonl"
    text = w["log"].read_text(encoding="utf-8") + (w["tmp"] / "t.json").read_text(encoding="utf-8")
    assert str(w["tmp"]) not in text and str(w["tmp"]).replace("\\", "/") not in text
    assert TC.verify(w["log"], inputs=[w["a"].log, odd])["verdict"] == V.VERIFIED


def test_edit_a_tally_row_is_broken(w):
    seal(w)
    seal(w)
    rs = rows(w["log"])
    rs[0]["tally_verdict"] = V.BROKEN
    rewrite(w["log"], rs)
    r = TC.verify(w["log"])
    assert r["verdict"] == V.BROKEN and "does not verify" in r["reason"]


def test_backdated_at_is_broken(w):
    seal(w, at=NOW)
    first = rows(w["log"])[0]
    forged = {k: v for k, v in first.items() if k != "chain"}
    forged.update(at="2026-10-01T00:00:00Z", ts="2026-10-04T13:00:00Z")
    Ledger(w["log"]).append(forged)          # a well-chained row: only the order catches it
    r = TC.verify(w["log"])
    assert r["chain"]["ok"] is True
    assert r["verdict"] == V.BROKEN and "BACKDATED" in r["reason"]


def test_reordered_ledger_ts_is_broken(w):
    seal(w, at=NOW)
    seal(w, at=NOW + timedelta(hours=1))
    rs = rows(w["log"])
    w["log"].unlink()
    for row in reversed(rs):                 # re-minted in swapped order: the chain holds
        Ledger(w["log"]).append({k: v for k, v in row.items() if k != "chain"})
    r = TC.verify(w["log"])
    assert r["chain"]["ok"] is True
    assert r["verdict"] == V.BROKEN and "REORDERED" in r["reason"]


def test_same_second_is_not_backdating(w):
    seal(w, at=NOW)
    seal(w, at=NOW)
    assert TC.verify(w["log"])["verdict"] == V.VERIFIED


def test_edit_an_input_row_after_sealing_is_broken(w):
    seal(w)
    p = w["a"].log
    text = p.read_text(encoding="utf-8")
    p.write_text(text.replace('"ex-1"', '"ex-9"', 1), encoding="utf-8")
    r = TC.verify(w["log"], inputs=inputs(w))
    assert r["verdict"] == V.BROKEN
    assert "a.jsonl" in r["reason"] and "edited" in r["reason"]


def test_truncated_input_is_broken(w):
    seal(w)
    p = w["b"].log
    p.write_text(p.read_text(encoding="utf-8").splitlines()[0] + "\n", encoding="utf-8")
    r = TC.verify(w["log"], inputs=inputs(w))
    assert r["verdict"] == V.BROKEN and "TRUNCATED" in r["reason"]


def test_append_to_input_after_seal_keeps_old_snapshot_verified(w):
    seal(w)
    both(w, "ex-3", days_ago=0.5)
    r = TC.verify(w["log"], inputs=inputs(w))
    assert r["verdict"] == V.VERIFIED, r["reason"]
    assert any("appended since" in i["reason"] for i in r["snapshots"][0]["inputs"])
    seal(w)                                  # a later snapshot reads the longer logs
    r = TC.verify(w["log"], inputs=inputs(w))
    assert r["verdict"] == V.VERIFIED, r["reason"]
    assert [s["inputs"][0]["rows"] for s in r["snapshots"]] == [2, 3]


def test_missing_input_is_could_not_look(w):
    seal(w)
    r = TC.verify(w["log"], inputs=[w["a"].log])
    assert r["verdict"] == V.COULD_NOT_LOOK and "b.jsonl was not given" in r["reason"]
    assert r["reason_word"] == "missing"
    w["b"].log.unlink()
    r = TC.verify(w["log"], inputs=inputs(w))
    assert r["verdict"] == V.COULD_NOT_LOOK and "b.jsonl" in r["reason"]


def test_missing_tally_chain_is_could_not_look(w):
    r = TC.verify(w["tmp"] / "nope.jsonl")
    assert r["verdict"] == V.COULD_NOT_LOOK and r["reason_word"] == "missing"


def test_seal_refuses_unreadable_or_duplicate_inputs(w, capsys):
    gone = w["tmp"] / "gone.jsonl"
    assert cli.main(["tally", "seal", str(w["a"].log), str(gone), "--log", str(w["log"]),
                     "--now", NOW_S]) == 3
    assert not w["log"].exists()
    other = w["tmp"] / "a.jsonl"
    other.write_bytes(w["b"].log.read_bytes())
    assert cli.main(["tally", "seal", str(w["a"].log), str(other), "--log", str(w["log"]),
                     "--now", NOW_S]) == 2
    assert "share the file name" in capsys.readouterr().err
    assert not w["log"].exists()


def test_a_broken_tally_is_sealed_with_its_verdict(w):
    p = w["a"].log
    rs = rows(p)
    rs[0]["reaction"] = V.BROKEN               # breaks the chain and the signature
    rewrite(p, rs)
    out = seal(w)
    assert out["row"]["tally_verdict"] == V.BROKEN
    assert TC.verify(w["log"], inputs=inputs(w))["verdict"] == V.VERIFIED


def test_groups_file_must_match_to_rebuild(w):
    g = w["tmp"] / "groups.json"
    g.write_text(json.dumps({"groups": [{"name": "x", "members": [w["a"].did, w["b"].did]}]}),
                 encoding="utf-8")
    out = seal(w, groups=g)
    assert out["row"]["options"]["groups"]["name"] == "groups.json"
    r = TC.verify(w["log"], inputs=inputs(w))
    assert r["verdict"] == V.VERIFIED and "groups" in r["snapshots"][0]["note"]
    assert TC.verify(w["log"], inputs=inputs(w), groups=g)["snapshots"][0]["tally_rebuilt"] \
        == V.VERIFIED
    g.write_text(json.dumps({"groups": []}), encoding="utf-8")
    assert TC.verify(w["log"], inputs=inputs(w), groups=g)["verdict"] == V.BROKEN


# --- the pin statement (dry run only) ---------------------------------------------------------

def test_pin_without_dry_run_is_refused(w, capsys):
    seal(w)
    out = w["tmp"] / "S.json"
    assert cli.main(["tally", "pin", "--log", str(w["log"]), "--out", str(out)]) == 2
    err = capsys.readouterr().err
    assert "--dry-run is the only mode" in err and "operator's scheduled task" in err
    assert not out.exists()


def test_pin_dry_run_prints_and_writes_only_out(w, capsys):
    seal(w)
    before = sorted(p.name for p in w["tmp"].rglob("*"))
    out = w["tmp"] / "S.json"
    assert cli.main(["tally", "pin", "--log", str(w["log"]), "--dry-run", "--out", str(out)]) == 0
    printed = capsys.readouterr().out.strip()
    assert out.read_text(encoding="utf-8") == printed
    after = sorted(p.name for p in w["tmp"].rglob("*"))
    assert sorted(set(after) - set(before)) == ["S.json"]
    st = json.loads(printed)
    assert st["tip"] == rows(w["log"])[-1]["chain"] and st["rows"] == 1
    assert cli.main(["tally", "pin", "--log", str(w["log"]), "--dry-run", "--out", str(out)]) == 2


def test_pin_refuses_a_broken_or_empty_chain(w):
    seal(w)
    seal(w)
    rs = rows(w["log"])
    rs[0]["tally_verdict"] = V.BROKEN
    rewrite(w["log"], rs)
    assert cli.main(["tally", "pin", "--log", str(w["log"]), "--dry-run"]) == 1
    empty = w["tmp"] / "empty.jsonl"
    empty.write_bytes(b"")
    assert cli.main(["tally", "pin", "--log", str(empty), "--dry-run"]) == 3
    assert cli.main(["tally", "pin", "--log", str(w["tmp"] / "no.jsonl"), "--dry-run"]) == 3


def test_statement_verifies_and_mismatch_is_broken(w):
    seal(w)
    st = TC.pin_statement(w["log"])
    s = w["tmp"] / "S.json"
    s.write_text(TC.statement_canonical(st), encoding="utf-8")
    r = TC.verify(w["log"], statement=s)
    assert r["verdict"] == V.VERIFIED and r["statement"]["verdict"] == V.VERIFIED
    seal(w)                                  # the chain grows: the old statement is a prefix
    r = TC.verify(w["log"], statement=s)
    assert r["verdict"] == V.VERIFIED and "not covered" in r["statement"]["reason"]
    for k, v in (("tip", "0" * 32), ("chain_values_sha256", "1" * 64),
                 ("file_sha256", "2" * 64), ("rows", 9)):
        bad = dict(st, **{k: v})
        s.write_text(TC.statement_canonical(bad), encoding="utf-8")
        r = TC.verify(w["log"], statement=s)
        assert r["verdict"] == V.BROKEN, (k, r["reason"])
        assert r["statement"]["verdict"] == V.BROKEN


def test_statement_from_another_chain_is_broken(w, tmp_path):
    seal(w)
    other = tmp_path / "other.jsonl"
    Ledger(other).append({"kind": "tally.snapshot", "x": 1})
    s = tmp_path / "S.json"
    s.write_text(TC.statement_canonical(TC.pin_statement(other)), encoding="utf-8")
    assert TC.verify(w["log"], statement=s)["verdict"] == V.BROKEN


# --- the statement shape, against the witness builder ---------------------------------------

#: A two-row chain written by Ledger.append, and the statement the canon witness
#: builder (bridge/witness/seal_chain.py build_pin_statement_v2 +
#: statement_canonical, commit 25a88340 of the operator's witness repository)
#: produced over exactly these bytes with chain "arcaeon-tally", prev null and
#: stated_at "2026-10-04T12:10:00+00:00". docs/TALLY.md cites the same source.
REF_ROWS = (
    '{"kind": "tally.snapshot", "n": 1, "ts": "2026-10-04T12:00:00Z", '
    '"chain": "291787300258eaeac7d61a5b3927da93"}\n'
    '{"kind": "tally.snapshot", "n": 2, "ts": "2026-10-04T12:05:00Z", '
    '"chain": "701298ec0d2a62a71e5ba087f2f9d0ef"}\n')
REF_STATEMENT = (
    '{"chain":"arcaeon-tally","chain_values_sha256":'
    '"51408d88b499c4a32b1b47685ab197671d2bb3c1f461876ef7a69412a792f29a","file_sha256":'
    '"8632172ab60f2054bad49ced1fb33cded61eed6a22818005f1fd7fcc82b1f7cb","file_sha256_of":"lf",'
    '"prev_pin_sha256":null,"rows":2,"stated_at":"2026-10-04T12:10:00+00:00",'
    '"tip":"701298ec0d2a62a71e5ba087f2f9d0ef","v":2}')
REF_SHA256 = "ade4065cbdaf86093f7fd7f45edc0a66b301ff408243a268bfe5f88efa33d499"
REF_FIELDS = ("chain", "chain_values_sha256", "file_sha256", "file_sha256_of",
              "prev_pin_sha256", "rows", "stated_at", "tip", "v")


@pytest.mark.parametrize("eol", [b"\n", b"\r\n"])
def test_statement_matches_the_witness_builder_byte_for_byte(tmp_path, eol):
    p = tmp_path / "ref.jsonl"
    p.write_bytes(REF_ROWS.encode("utf-8").replace(b"\n", eol))
    st = TC.pin_statement(p, stated_at="2026-10-04T12:10:00+00:00")
    assert tuple(st) == REF_FIELDS == TC.PIN_STATEMENT_FIELDS
    assert tuple(json.loads(REF_STATEMENT)) == REF_FIELDS
    assert TC.statement_canonical(st) == REF_STATEMENT
    assert TC.statement_sha256(st) == REF_SHA256
    s = tmp_path / "S.json"
    s.write_text(REF_STATEMENT, encoding="utf-8")
    assert TC._check_statement(s, TC._lf(p.read_bytes()), TC._lines(TC._lf(p.read_bytes())),
                               TC._chain_values(TC._lines(TC._lf(p.read_bytes()))))["verdict"] \
        == V.VERIFIED


def test_default_stated_at_has_the_builders_format(w):
    seal(w)
    st = TC.pin_statement(w["log"])
    assert datetime.fromisoformat(st["stated_at"]).utcoffset() == timedelta(0)
    assert st["stated_at"].endswith("+00:00") and len(st["stated_at"]) == 25


# --- hostile files ----------------------------------------------------------------------------

HOSTILE = {
    "binary.jsonl": b"\xff\xfe\x00garbage\x80",
    "notjson.jsonl": b"not json at all\n",
    "array.jsonl": b"[1, 2, 3]\n\"x\"\n",
    "nochain.jsonl": b'{"kind": "tally.snapshot"}\n',
    "deep.jsonl": b"[" * 5000 + b"]" * 5000 + b"\n",
    "blank.jsonl": b"\n\n  \n",
    "nan.jsonl": b'{"kind": NaN, "chain": "00"}\n',
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_hostile_tally_chain_no_traceback(w, name, capsys):
    p = w["tmp"] / name
    p.write_bytes(HOSTILE[name])
    for argv in (["tally", "verify", "--log", str(p)],
                 ["tally", "verify", "--log", str(p), "--inputs", str(w["a"].log),
                  "--statement", str(p), "--json"],
                 ["tally", "pin", "--log", str(p), "--dry-run"]):
        rc = cli.main(argv)
        cap = capsys.readouterr()
        assert rc in (1, 3), (argv, rc, cap.err)
        assert "Traceback" not in cap.err + cap.out


def test_hostile_statement_inputs_and_directories(w, capsys):
    seal(w)
    s = w["tmp"] / "S.json"
    for blob in (b"\xff", b"[]", b"{}", b'{"v": 2}', b"1e999", b"[" * 5000):
        s.write_bytes(blob)
        r = TC.verify(w["log"], statement=s)
        assert r["verdict"] == V.COULD_NOT_LOOK, (blob, r["reason"])
    r = TC.verify(w["log"], inputs=[w["tmp"] / "logs" / "a.jsonl", w["tmp"]])
    assert r["verdict"] == V.COULD_NOT_LOOK
    r = TC.verify(w["tmp"])                   # a directory for the chain
    assert r["verdict"] == V.COULD_NOT_LOOK
    big = w["tmp"] / "big.jsonl"
    big.write_bytes(w["log"].read_bytes())
    old = TC.MAX_LOG_BYTES
    try:
        TC.MAX_LOG_BYTES = 10
        assert TC.verify(big)["verdict"] == V.COULD_NOT_LOOK
    finally:
        TC.MAX_LOG_BYTES = old
    assert cli.main(["tally", "verify", "--log", str(w["log"]), "--inputs"]) == 2
    assert cli.main(["tally", "verify", str(w["log"])]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_foreign_row_in_tally_chain_is_broken(w):
    seal(w)
    Ledger(w["log"]).append({"kind": "deal.offer", "x": 1})
    r = TC.verify(w["log"])
    assert r["verdict"] == V.BROKEN and "snapshots only" in r["reason"]


# --- the CLI round trip ----------------------------------------------------------------------

def test_cli_round_trip(w, capsys):
    log, out, s = w["log"], w["tmp"] / "tally.json", w["tmp"] / "S.json"
    assert cli.main(["tally", "seal", str(w["a"].log), str(w["b"].log), "--log", str(log),
                     "--out", str(out), "--now", NOW_S]) == 0
    text = capsys.readouterr().out
    assert "sealed row" in text and "wash trade" in text
    assert cli.main(["tally", "pin", "--log", str(log), "--dry-run", "--out", str(s)]) == 0
    capsys.readouterr()
    assert cli.main(["tally", "verify", "--log", str(log), "--inputs", str(w["a"].log),
                     str(w["b"].log), "--statement", str(s)]) == 0
    text = capsys.readouterr().out
    assert text.startswith("VERIFIED:") and "statement S.json: VERIFIED" in text
    w["a"].log.write_text(w["a"].log.read_text(encoding="utf-8").replace("ex-2", "ex-8"),
                          encoding="utf-8")
    assert cli.main(["tally", "verify", "--log", str(log), "--inputs", str(w["a"].log),
                     str(w["b"].log), "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["verdict"] == V.BROKEN
