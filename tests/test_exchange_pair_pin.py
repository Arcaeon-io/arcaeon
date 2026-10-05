# SPDX-License-Identifier: MIT
"""`arcaeon exchange pair --pin FILE`: a v2 pin statement over the pair result,
built by the tally chain's statement builder. Dry run only: it writes the
statement file and says what would be pinned; it never contacts a witness,
never touches a witness_pins file, and opens no socket.

Every key here is a throwaway seed written to tmp_path; no network."""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import shutil
import socket
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import exchange_log as X
from arcaeon.prove import tally_chain as TC
from arcaeon.record.row import canon_json

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

T0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
STATED = "2026-10-05T10:00:00+00:00"


def _key(tmp: Path, name: str, b: int) -> tuple[Path, str]:
    from arcaeon.prove.vet import receipts as R
    seed = bytes([b]) * 32
    p = tmp / f"{name}.key"
    p.write_text(base64.b64encode(seed).decode("ascii") + "\n", encoding="ascii")
    return p, R.did_key(R.public_key_from_seed(seed))


@pytest.fixture
def p(tmp_path):
    out = {"tmp": tmp_path}
    for n, b in (("a", 1), ("b", 2)):
        out["k" + n], out["d" + n] = _key(tmp_path, n, b)
        out["l" + n] = tmp_path / f"{n}.jsonl"
    f = tmp_path / "deliverable.csv"
    f.write_bytes(b"id,grade\n1,A\n")
    out["file"] = f
    return out


def _react(p, side, reaction=V.VERIFIED, ex="ex-1"):
    other = "b" if side == "a" else "a"
    return X.react(p["l" + side], key_file=p["k" + side], exchange_id=ex,
                   counterparty=p["d" + other], file=p["file"], reaction=reaction, at=T0)


def _pin(p, **kw):
    r = X.pair(p["la"], p["lb"])
    return X.pair_pin_statement(r, p["la"], p["lb"], stated_at=STATED, **kw)


@pytest.fixture
def no_network(monkeypatch):
    def refuse(*a, **kw):
        raise AssertionError("network call attempted")
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    monkeypatch.setattr(http.client.HTTPConnection, "request", refuse)


def test_the_statement_is_the_v2_pin_statement(p):
    _react(p, "a")
    _react(p, "b")
    out = _pin(p)
    st = out["statement"]
    assert tuple(sorted(st)) == TC.PIN_STATEMENT_FIELDS
    assert TC._statement_problem(st) is None
    assert st["chain"] == X.PAIR_PIN_CHAIN == "arcaeon-exchange-pair"
    assert st["v"] == 2 and st["rows"] == 1 and st["file_sha256_of"] == "lf"
    assert st["stated_at"] == STATED and st["prev_pin_sha256"] is None
    assert out["statement_sha256"] == TC.statement_sha256(st)


def test_the_statement_commits_to_the_pair_result_by_names_only(p):
    _react(p, "a")
    _react(p, "b")
    r = X.pair(p["la"], p["lb"])
    body = X.pair_snapshot(r, p["la"], p["lb"])
    assert str(p["tmp"]).encode("utf-8") not in body
    assert str(p["tmp"]).replace("\\", "/").encode("utf-8") not in body
    st = X.pair_pin_statement(r, p["la"], p["lb"], stated_at=STATED)["statement"]
    assert st["tip"] == hashlib.sha256(body).hexdigest()
    assert st["file_sha256"] == hashlib.sha256(body + b"\n").hexdigest()
    assert st["chain_values_sha256"] == hashlib.sha256((st["tip"] + "\n").encode()).hexdigest()
    assert json.loads(body)["kind"] == X.PAIR_KIND
    assert body == canon_json(json.loads(body))


def test_the_digest_is_stable_for_the_same_pair_result(p, tmp_path_factory):
    _react(p, "a")
    _react(p, "b")
    one, two = _pin(p), _pin(p)
    assert one["statement_sha256"] == two["statement_sha256"]
    elsewhere = tmp_path_factory.mktemp("copy")             # same names, another folder
    for n in ("a.jsonl", "b.jsonl"):
        shutil.copyfile(p["tmp"] / n, elsewhere / n)
    r = X.pair(elsewhere / "a.jsonl", elsewhere / "b.jsonl")
    there = X.pair_pin_statement(r, elsewhere / "a.jsonl", elsewhere / "b.jsonl",
                                 stated_at=STATED)
    assert there["statement_sha256"] == one["statement_sha256"]


def test_the_digest_changes_when_the_pair_result_changes(p):
    _react(p, "a")
    _react(p, "b")
    before = _pin(p)
    _react(p, "a", ex="ex-2")
    after = _pin(p)
    assert after["pair_sha256"] != before["pair_sha256"]
    assert after["statement_sha256"] != before["statement_sha256"]
    chained = _pin(p, prev_pin_sha256=before["statement_sha256"])
    assert chained["statement"]["prev_pin_sha256"] == before["statement_sha256"]
    assert chained["statement_sha256"] != after["statement_sha256"]


def test_bad_options_are_refused(p):
    _react(p, "a")
    _react(p, "b")
    r = X.pair(p["la"], p["lb"])
    for kw in ({"prev_pin_sha256": "abc"}, {"stated_at": "yesterday"}):
        with pytest.raises(X.ExchangeError):
            X.pair_pin_statement(r, p["la"], p["lb"], **kw)
    cnl = X.pair(p["la"], p["tmp"] / "nope.jsonl")
    with pytest.raises(X.ExchangeError):
        X.pair_pin_statement(cnl, p["la"], p["tmp"] / "nope.jsonl", stated_at=STATED)


def test_cli_pin_is_a_dry_run_with_no_network(p, capsys, no_network):
    _react(p, "a")
    _react(p, "b")
    before = sorted(x.name for x in p["tmp"].iterdir())
    out = p["tmp"] / "pair.statement.json"
    args = ["exchange", "pair", str(p["la"]), str(p["lb"]), "--json", "--pin", str(out),
            "--stated-at", STATED]
    assert cli.main(args) == 0
    cap = capsys.readouterr()
    r = json.loads(cap.out)                                   # stdout is still the pair JSON
    assert r["verdict"] == V.VERIFIED
    want = X.pair_pin_statement(X.pair(p["la"], p["lb"]), p["la"], p["lb"], stated_at=STATED)
    assert out.read_bytes() == TC.statement_canonical(want["statement"]).encode("utf-8")
    assert want["statement_sha256"] in cap.err and "dry run" in cap.err
    assert "no witness was contacted" in cap.err
    after = sorted(x.name for x in p["tmp"].iterdir())
    assert after == sorted(before + [out.name])               # nothing else written
    assert not any("witness_pins" in n for n in after)
    assert cli.main(args) == V.EXIT_USAGE                     # never overwritten
    assert "never overwritten" in capsys.readouterr().err


def test_cli_pin_text_mode_and_bad_flags(p, capsys, no_network):
    _react(p, "a")
    _react(p, "b")
    out = p["tmp"] / "s.json"
    base = ["exchange", "pair", str(p["la"]), str(p["lb"]), "--pin", str(out)]
    assert cli.main(base + ["--stated-at", "soon"]) == V.EXIT_USAGE
    assert cli.main(base + ["--prev-pin-sha256", "zz"]) == V.EXIT_USAGE
    assert cli.main(["exchange", "pair", str(p["la"]), str(p["lb"]), "--stated-at",
                     STATED]) == V.EXIT_USAGE                 # needs --pin
    assert not out.exists()
    assert cli.main(base) == 0                                # stated_at defaults to now
    assert TC._statement_problem(json.loads(out.read_text(encoding="utf-8"))) is None
    capsys.readouterr()


def test_cli_pin_refuses_a_pair_that_could_not_look(p, capsys, no_network):
    _react(p, "a")
    out = p["tmp"] / "s.json"
    code = cli.main(["exchange", "pair", str(p["la"]), str(p["tmp"] / "nope.jsonl"),
                     "--pin", str(out), "--stated-at", STATED])
    assert code == V.EXIT_COULD_NOT_LOOK and not out.exists()
    assert "no statement" in capsys.readouterr().err


def test_cli_pin_over_a_broken_pair_keeps_the_exit(p, capsys, no_network):
    _react(p, "a")
    _react(p, "b")
    with p["lb"].open("a", encoding="utf-8") as fh:
        fh.write('{"kind": "exchange.reaction", "v": 1, "chain": "00"}\n')
    out = p["tmp"] / "s.json"
    code = cli.main(["exchange", "pair", str(p["la"]), str(p["lb"]), "--pin", str(out),
                     "--stated-at", STATED])
    assert code == V.EXIT_BAD and out.exists()
    capsys.readouterr()


def test_exchange_doc_names_the_pair_pin():
    doc = (Path(__file__).resolve().parents[1] / "docs" / "EXCHANGE.md").read_text(
        encoding="utf-8")
    assert "## Pinning a pair result" in doc
    sec = doc.split("## Pinning a pair result", 1)[1].split("\n## ", 1)[0]
    for w in ("--pin", "--stated-at", "--prev-pin-sha256", "dry run", "arcaeon-exchange-pair",
              "witness", "cannot prove"):
        assert w in sec, w
