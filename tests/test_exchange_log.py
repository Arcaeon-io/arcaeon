# SPDX-License-Identifier: MIT
"""D057 / TE-42: signed exchange reactions and the pair reader.

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
from arcaeon.record.ledger import Ledger, verify_file

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")


def _key(tmp_path: Path, name: str) -> tuple[Path, str]:
    from arcaeon.prove.vet import receipts as R
    seed = secrets.token_bytes(32)
    p = tmp_path / f"{name}.key"
    p.write_text(base64.b64encode(seed).decode("ascii") + "\n", encoding="ascii")
    return p, R.did_key(R.public_key_from_seed(seed))


@pytest.fixture
def parties(tmp_path):
    ka, da = _key(tmp_path, "a")
    kb, db = _key(tmp_path, "b")
    f = tmp_path / "deliverable.csv"
    f.write_bytes(b"id,grade\n1,A\n")
    return {"ka": ka, "da": da, "kb": kb, "db": db, "file": f,
            "la": tmp_path / "a.jsonl", "lb": tmp_path / "b.jsonl", "tmp": tmp_path}


def _react(p, side, reaction=V.VERIFIED, ex="ex-1", file=None, **kw):
    other = "b" if side == "a" else "a"
    return X.react(p["l" + side], key_file=p["k" + side], exchange_id=ex,
                   counterparty=kw.pop("counterparty", p["d" + other]),
                   file=file or p["file"], reaction=reaction, **kw)


def _only(r):
    assert len(r["exchanges"]) == 1, r["exchanges"]
    return r["exchanges"][0]


# --- the happy pair and the marks -----------------------------------------------------

def test_happy_pair_is_clean(parties):
    out = _react(parties, "a")
    _react(parties, "b")
    assert out["row"]["kind"] == "exchange.reaction"
    assert out["row"]["signer"] == parties["da"]
    assert out["row_digest"].startswith("sha256:json-c14n:v1:")
    assert verify_file(parties["la"], strict=True).ok is True
    r = X.pair(parties["la"], parties["lb"])
    assert r["verdict"] == V.VERIFIED, r["reason"]
    ex = _only(r)
    assert ex["status"] == "clean" and ex["differs"] == []
    assert r["counts"]["clean"] == 1 and r["claims"] == []
    assert r["logs"]["a"]["owner"] == parties["da"]
    assert r["logs"]["a"]["owner_from"] == "first_row"


def test_mismatch_reaction_is_named(parties):
    _react(parties, "a")
    _react(parties, "b", V.BROKEN)
    r = X.pair(parties["la"], parties["lb"])
    ex = _only(r)
    assert r["verdict"] == V.VERIFIED          # the record is sound; the pair is the mark
    assert ex["status"] == "mismatch" and ex["differs"] == ["reaction"]
    assert "a said VERIFIED, b said BROKEN" in ex["findings"][0]


def test_mismatch_sha_is_named(parties):
    other = parties["tmp"] / "other.csv"
    other.write_bytes(b"id,grade\n1,B\n")
    _react(parties, "a")
    _react(parties, "b", file=other)
    ex = _only(X.pair(parties["la"], parties["lb"]))
    assert ex["status"] == "mismatch" and ex["differs"] == ["file_sha256"]


def test_missing_side(parties):
    _react(parties, "a", ex="ex-1")
    _react(parties, "a", ex="ex-2")
    _react(parties, "b", ex="ex-1")
    r = X.pair(parties["la"], parties["lb"])
    st = {e["exchange_id"]: e["status"] for e in r["exchanges"]}
    assert st == {"ex-1": "clean", "ex-2": "missing"}
    assert "no reaction from b" in r["exchanges"][1]["findings"]


def test_agreed_non_verified_is_not_clean(parties):
    _react(parties, "a", V.COULD_NOT_LOOK)
    _react(parties, "b", V.COULD_NOT_LOOK)
    assert _only(X.pair(parties["la"], parties["lb"]))["status"] == "not_verified"


def test_counterparty_mismatch(parties):
    _, stranger = _key(parties["tmp"], "c")
    _react(parties, "a", counterparty=stranger)
    _react(parties, "b")
    ex = _only(X.pair(parties["la"], parties["lb"]))
    assert ex["status"] == "mismatch" and ex["differs"] == ["counterparty"]
    assert stranger in ex["findings"][0]


def test_disputed_is_a_claim_not_a_verdict(parties):
    _react(parties, "a")
    _react(parties, "b", disputed="the rows arrived after the deadline")
    r = X.pair(parties["la"], parties["lb"])
    ex = _only(r)
    assert ex["status"] == "clean"             # both said VERIFIED about the same bytes
    assert all(s not in ("DISPUTED", "disputed") for s in X.STATUSES)
    [c] = r["claims"]
    assert c["claim"] == "DISPUTED" and c["side"] == "b" and c["current"] is True
    assert c["reason"] == "the rows arrived after the deadline"
    assert c["signer"] == parties["db"]


def test_disputed_needs_a_reason(parties):
    with pytest.raises(X.ExchangeError):
        _react(parties, "a", disputed="  ")


# --- forgery, edits, supersede ------------------------------------------------------------

def test_forged_row_signed_with_the_wrong_key_is_broken(parties):
    _react(parties, "a")
    _react(parties, "b")
    kc, dc = _key(parties["tmp"], "mallory")
    seed = base64.b64decode(kc.read_text(encoding="ascii").strip())
    forged = X.build_row(seed=seed, exchange_id="ex-1", counterparty=parties["db"],
                         file_sha256="0" * 64, reaction=V.BROKEN)
    Ledger(parties["la"]).append(forged)       # chain intact: only the signer is wrong
    assert verify_file(parties["la"], strict=True).ok is True
    r = X.pair(parties["la"], parties["lb"])
    assert r["verdict"] == V.BROKEN
    [br] = r["logs"]["a"]["broken_rows"]
    assert "not by the key that owns this log" in br["finding"]
    assert _only(r)["status"] == "broken"      # never silently dropped


def test_row_with_a_bad_signature_is_broken(parties):
    _react(parties, "a")
    _react(parties, "b")
    good = json.loads(parties["la"].read_text(encoding="utf-8").splitlines()[0])
    for k in ("ts", "chain"):
        good.pop(k)
    good["reaction"] = V.BROKEN                # re-chained, but the signature no longer covers it
    Ledger(parties["la"]).append(good)
    r = X.pair(parties["la"], parties["lb"])
    assert r["verdict"] == V.BROKEN
    assert "does not verify" in r["logs"]["a"]["broken_rows"][0]["finding"]


def test_row_edited_in_place_breaks_the_chain(parties):
    _react(parties, "a")
    _react(parties, "b")
    text = parties["la"].read_text(encoding="utf-8")
    parties["la"].write_text(text.replace('"VERIFIED"', '"BROKEN"'), encoding="utf-8")
    assert verify_file(parties["la"], strict=True).ok is False
    r = X.pair(parties["la"], parties["lb"])
    assert r["verdict"] == V.BROKEN
    assert r["logs"]["a"]["chain"]["ok"] is False
    assert "chain does not verify" in r["reason"]


def test_extra_field_outside_the_signature_is_broken(parties):
    out = _react(parties, "a")
    _react(parties, "b")
    row = dict(out["row"], note="added later")
    Ledger(parties["la"]).append(row)
    r = X.pair(parties["la"], parties["lb"])
    assert r["verdict"] == V.BROKEN
    assert "outside the signature" in r["logs"]["a"]["broken_rows"][0]["finding"]


def test_supersede_resolves_to_the_latest(parties):
    first = _react(parties, "a", V.BROKEN)
    second = _react(parties, "a", V.COULD_NOT_LOOK, supersedes=first["row_digest"])
    _react(parties, "a", V.VERIFIED, supersedes=second["row_digest"])
    _react(parties, "b")
    r = X.pair(parties["la"], parties["lb"])
    assert r["verdict"] == V.VERIFIED, r["reason"]
    ex = _only(r)
    assert ex["status"] == "clean" and ex["a"]["line"] == 3
    assert "note" not in ex["a"]
    assert verify_file(parties["la"], strict=True).ok is True   # a new row, nothing edited


def test_superseded_dispute_is_listed_not_current(parties):
    first = _react(parties, "b", V.BROKEN, disputed="wrong file")
    _react(parties, "b", supersedes=first["row_digest"])
    _react(parties, "a")
    r = X.pair(parties["la"], parties["lb"])
    assert _only(r)["status"] == "clean"
    [c] = r["claims"]
    assert c["current"] is False


def test_supersede_refused_on_write_when_the_target_is_absent(parties):
    with pytest.raises(X.ExchangeError, match="no row with that digest"):
        _react(parties, "a", supersedes="sha256:json-c14n:v1:" + "a" * 64)


def test_dangling_supersede_in_the_log_is_broken(parties):
    seed = base64.b64decode(parties["ka"].read_text(encoding="ascii").strip())
    row = X.build_row(seed=seed, exchange_id="ex-1", counterparty=parties["db"],
                      file_sha256="1" * 64, reaction=V.VERIFIED,
                      supersedes="sha256:json-c14n:v1:" + "b" * 64)
    Ledger(parties["la"]).append(row)
    _react(parties, "b")
    r = X.pair(parties["la"], parties["lb"])
    assert r["verdict"] == V.BROKEN
    assert "not earlier in this log" in r["logs"]["a"]["broken_rows"][0]["finding"]


def test_two_unsuperseded_rows_read_the_last_and_say_so(parties):
    _react(parties, "a", V.BROKEN)
    _react(parties, "a", V.VERIFIED)
    _react(parties, "b")
    ex = _only(X.pair(parties["la"], parties["lb"]))
    assert ex["status"] == "clean" and "not superseded" in ex["a"]["note"]


def test_one_log_per_key_on_write(parties):
    _react(parties, "a")
    with pytest.raises(X.ExchangeError, match="belongs to"):
        X.react(parties["la"], key_file=parties["kb"], exchange_id="ex-2",
                counterparty=parties["da"], file=parties["file"], reaction=V.VERIFIED)


def test_named_owner_overrides_first_row(parties):
    _react(parties, "a")
    _react(parties, "b")
    r = X.pair(parties["la"], parties["lb"], owner_a=parties["db"])
    assert r["verdict"] == V.BROKEN
    assert r["logs"]["a"]["owner_from"] == "named"


def test_same_log_twice_is_broken(parties):
    _react(parties, "a")
    r = X.pair(parties["la"], parties["la"])
    assert r["verdict"] == V.BROKEN and "one key" in r["reason"]


def test_signing_encoding_is_pae_over_c14n(parties):
    from arcaeon.prove.envelope import pae
    from arcaeon.record.row import canon_json
    row = _react(parties, "a")["row"]
    body = {k: row[k] for k in X.SIGNED_FIELDS}
    assert X.signing_bytes(row) == pae(X.SIG_PAYLOAD_TYPE, canon_json(body))
    assert set(row) == set(X.SIGNED_FIELDS) | {"sig"}
    assert X.check_row(row) is None


# --- hostile input ------------------------------------------------------------------------

@pytest.mark.parametrize("content", [
    None,                                   # missing
    b"",                                    # empty
    b"\xff\xfe\x00garbage\x00",             # not UTF-8
    b"[1,2,3]\n",                           # not rows
    b"{\"a\": 1}\n{\"b\": 2}\n",            # rows, but not a chained ledger
    b"[" * 200000 + b"\n",                  # nests too deep
    b"\"just a string\"\n",
], ids=["missing", "empty", "not-utf8", "array", "unchained", "deep", "scalar"])
def test_hostile_logs_could_not_look(parties, content):
    _react(parties, "b")
    bad = parties["tmp"] / "hostile.jsonl"
    if content is not None:
        bad.write_bytes(content)
    r = X.pair(bad, parties["lb"])
    assert r["verdict"] == V.COULD_NOT_LOOK, r
    assert r["reason_word"] in V.REASON_WORDS
    json.dumps(r)


def test_directory_as_log_could_not_look(parties):
    _react(parties, "b")
    r = X.pair(parties["tmp"], parties["lb"])
    assert r["verdict"] == V.COULD_NOT_LOOK


def test_hostile_reaction_row_fields_are_broken_not_a_crash(parties):
    _react(parties, "b")
    for junk in ({"kind": X.KIND}, {**{k: [] for k in X.SIGNED_FIELDS}, "kind": X.KIND, "sig": 7},
                 {"kind": X.KIND, "exchange_id": {"x": 1}, "reaction": None}):
        Ledger(parties["la"]).append(junk)
    r = X.pair(parties["la"], parties["lb"])
    assert r["verdict"] == V.BROKEN
    assert len(r["logs"]["a"]["broken_rows"]) == 3
    json.dumps(r)


# --- CLI --------------------------------------------------------------------------------

def test_cli_react_and_pair(parties, capsys):
    p = parties
    rc = cli.main(["exchange", "react", "--exchange", "ex-9", "--counterparty", p["db"],
                   "--file", str(p["file"]), "--reaction", "COULD NOT LOOK",
                   "--key", str(p["ka"]), "--log", str(p["la"])])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["row"]["reaction"] == V.COULD_NOT_LOOK
    rc = cli.main(["exchange", "react", "--exchange", "ex-9", "--counterparty", p["da"],
                   "--file", str(p["file"]), "--reaction", "VERIFIED",
                   "--disputed", "late", "--key", str(p["kb"]), "--log", str(p["lb"])])
    assert rc == 0
    capsys.readouterr()
    rc = cli.main(["exchange", "pair", str(p["la"]), str(p["lb"]), "--json"])
    r = json.loads(capsys.readouterr().out)
    assert rc == 0 and r["verdict"] == V.VERIFIED
    assert r["exchanges"][0]["status"] == "mismatch" and len(r["claims"]) == 1
    rc = cli.main(["exchange", "pair", str(p["la"]), str(p["lb"])])
    text = capsys.readouterr().out
    assert rc == 0 and "ex-9: mismatch" in text and "claim DISPUTED by b" in text


def test_cli_exit_codes(parties, capsys):
    p = parties
    assert cli.main(["exchange", "react", "--exchange", "x"]) == V.EXIT_USAGE
    assert cli.main(["exchange", "react", "--exchange", "x", "--counterparty", p["db"],
                     "--file", str(p["tmp"] / "nope"), "--reaction", "VERIFIED",
                     "--key", str(p["ka"]), "--log", str(p["la"])]) == V.EXIT_COULD_NOT_LOOK
    assert cli.main(["exchange", "react", "--exchange", "x", "--counterparty", p["db"],
                     "--file", str(p["file"]), "--reaction", "DISPUTED",
                     "--key", str(p["ka"]), "--log", str(p["la"])]) == V.EXIT_USAGE
    assert not p["la"].exists()
    assert cli.main(["exchange", "pair", str(p["la"])]) == V.EXIT_USAGE
    assert cli.main(["exchange", "pair", str(p["la"]), str(p["lb"])]) == V.EXIT_COULD_NOT_LOOK
    assert cli.main(["exchange", "pair", "a", "b", "--owner-a", "bob"]) == V.EXIT_USAGE
    _react(p, "a")
    _react(p, "b")
    text = p["la"].read_text(encoding="utf-8")
    p["la"].write_text(text.replace("ex-1", "ex-2"), encoding="utf-8")
    assert cli.main(["exchange", "pair", str(p["la"]), str(p["lb"])]) == V.EXIT_BAD
    assert cli.main(["exchange", "--help"]) == 0


# --- D071: the arcaeon.io account id form, pair --strict, public helpers ------------------

ACCT = "acct:dealer-7@arcaeon.io"


@pytest.mark.parametrize("good", [ACCT, "acct:a@arcaeon.io", "acct:bot-1.owner@arcaeon.io"])
def test_account_id_form_is_accepted(good):
    assert X.is_account_id(good) and X.is_counterparty_id(good)
    assert not X.is_did(good)


@pytest.mark.parametrize("bad", ["dealer-7@arcaeon.io", "acct:Dealer@arcaeon.io",
                                 "acct:dealer@arcaeon.com", "acct:@arcaeon.io",
                                 "acct:-x@arcaeon.io", "acct:a..b@arcaeon.io",
                                 "acct:" + "a" * 65 + "@arcaeon.io", "https://arcaeon.io/x",
                                 "acct:x@arcaeon.io\n", "did:key:zNOPE", 7, None])
def test_malformed_ids_are_not_counterparties(bad):
    assert not X.is_counterparty_id(bad)


def test_react_stores_the_account_id_as_given(parties):
    out = _react(parties, "a", counterparty=ACCT)
    assert out["row"]["counterparty"] == ACCT
    assert X.check_row(out["row"]) is None
    rows = [r for r in Ledger(parties["la"]) if r.get("kind") == X.KIND]
    assert rows[0]["counterparty"] == ACCT


def test_react_refuses_a_malformed_counterparty_with_a_clear_error(parties):
    with pytest.raises(X.ExchangeError) as e:
        _react(parties, "a", counterparty="acct:Dealer 7@arcaeon.io")
    msg = str(e.value)
    assert "--counterparty" in msg and "did:key" in msg and "acct:NAME@arcaeon.io" in msg
    assert not parties["la"].exists()


def test_cli_react_malformed_counterparty_exit_2(parties, capsys):
    p = parties
    rc = cli.main(["exchange", "react", "--exchange", "x", "--counterparty", "dealer@arcaeon",
                   "--file", str(p["file"]), "--reaction", "VERIFIED",
                   "--key", str(p["ka"]), "--log", str(p["la"])])
    assert rc == V.EXIT_USAGE
    assert "acct:NAME@arcaeon.io" in capsys.readouterr().err
    assert not p["la"].exists()


def test_did_key_counterparty_unchanged(parties):
    out = _react(parties, "a")
    assert out["row"]["counterparty"] == parties["db"] and X.is_did(parties["db"])
    _react(parties, "b")
    assert _only(X.pair(parties["la"], parties["lb"]))["status"] == "clean"


def test_pair_treats_account_and_did_as_distinct(parties):
    _react(parties, "a", counterparty=ACCT)
    _react(parties, "b")
    r = X.pair(parties["la"], parties["lb"])
    assert r["verdict"] == V.VERIFIED, r["reason"]
    ex = _only(r)
    assert ex["status"] == "mismatch" and ex["differs"] == ["counterparty"]
    assert any(ACCT in f and "not checked here" in f for f in ex["findings"])


def test_pair_strict_exits_1_on_mismatch_and_missing(parties, capsys):
    p = parties
    _react(p, "a", ex="ex-1")
    _react(p, "b", V.BROKEN, ex="ex-1")
    args = ["exchange", "pair", str(p["la"]), str(p["lb"])]
    assert cli.main(args) == V.EXIT_GOOD
    assert cli.main(args + ["--strict"]) == V.EXIT_BAD
    assert "--strict" in capsys.readouterr().err


def test_pair_strict_missing_and_clean(parties, capsys):
    p = parties
    _react(p, "a", ex="ex-1")
    _react(p, "b", ex="ex-1")
    args = ["exchange", "pair", str(p["la"]), str(p["lb"]), "--strict"]
    assert cli.main(args) == V.EXIT_GOOD
    assert cli.main(args[:-1]) == V.EXIT_GOOD
    _react(p, "a", ex="ex-2")
    assert cli.main(args[:-1]) == V.EXIT_GOOD
    assert cli.main(args) == V.EXIT_BAD
    assert cli.main(args + ["--json"]) == V.EXIT_BAD
    capsys.readouterr()


def test_pair_strict_keeps_could_not_look_and_broken_codes(parties, capsys):
    p = parties
    args = ["exchange", "pair", str(p["la"]), str(p["lb"]), "--strict"]
    assert cli.main(args) == V.EXIT_COULD_NOT_LOOK
    _react(p, "a")
    _react(p, "b")
    text = p["la"].read_text(encoding="utf-8")
    p["la"].write_text(text.replace("ex-1", "ex-2"), encoding="utf-8")
    assert cli.main(args) == V.EXIT_BAD
    capsys.readouterr()


def test_tally_modules_import_no_private_names_from_exchange_log():
    import ast
    import arcaeon.prove.tally as T
    import arcaeon.prove.tally_chain as TC
    for mod in (T, TC):
        tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))
        aliases = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "arcaeon.prove.exchange_log":
                bad = [a.name for a in node.names if a.name.startswith("_")]
                assert not bad, (mod.__name__, bad)
            if isinstance(node, ast.ImportFrom) and node.module == "arcaeon.prove":
                aliases |= {a.asname or a.name for a in node.names if a.name == "exchange_log"}
            if isinstance(node, ast.Import):
                aliases |= {a.asname or a.name for a in node.names
                            if a.name == "arcaeon.prove.exchange_log"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                    and node.value.id in aliases:
                assert not node.attr.startswith("_"), (mod.__name__, node.attr)


def test_promoted_helpers_are_public():
    for name in ("is_did", "is_account_id", "is_counterparty_id", "text_ok", "read_side",
                 "latest_heads", "pair_exchange"):
        assert callable(getattr(X, name)) and name in X.__all__


# --- D077: retracted BROKEN (F7), the account binding row (lead call) --------------------

def test_f7_retracted_broken_leaves_a_mark_in_pair(parties):
    p = parties
    _react(p, "a")
    old = _react(p, "b", V.BROKEN)
    _react(p, "b", V.VERIFIED, supersedes=old["row_digest"])
    r = X.pair(p["la"], p["lb"])
    ex = _only(r)
    assert ex["status"] == "clean"                 # the current rows agree
    assert ex["retracted"] == ["b"]                # but the BROKEN b wrote is not gone
    assert ex["b"]["retracted"] == 1
    assert any("retracted" in f and "BROKEN" in f for f in ex["findings"])
    assert r["retracted"] == 1
    assert "retracted" in X._render(r)


def test_f7_broken_superseded_by_broken_is_not_a_retraction(parties):
    p = parties
    _react(p, "a", V.BROKEN)
    old = _react(p, "b", V.BROKEN)
    _react(p, "b", V.BROKEN, supersedes=old["row_digest"], disputed="still wrong")
    ex = _only(X.pair(p["la"], p["lb"]))
    assert ex["retracted"] == [] and ex["b"].get("retracted", 0) == 0


def _seed(p, side):
    return base64.b64decode(p["k" + side].read_text(encoding="ascii").strip())


def test_bind_writes_a_signed_binding_row(parties):
    p = parties
    out = X.bind(p["lb"], key_file=p["kb"], account=ACCT)
    row = out["row"]
    assert row["kind"] == X.BIND_KIND and row["account"] == ACCT and row["signer"] == p["db"]
    assert X.check_binding(row) is None
    assert verify_file(p["lb"], strict=True).ok is True
    with pytest.raises(X.ExchangeError):
        X.bind(p["lb"], key_file=p["kb"], account="acct:Bad@arcaeon.io")
    with pytest.raises(X.ExchangeError):
        X.bind(p["lb"], key_file=p["ka"], account=ACCT)      # one log per key


def test_account_pairs_clean_only_through_a_binding_row(parties):
    p = parties
    _react(p, "a", counterparty=ACCT)
    _react(p, "b")
    ex = _only(X.pair(p["la"], p["lb"]))
    assert ex["status"] == "mismatch"                        # no binding: as before
    assert any(ACCT in f and V.COULD_NOT_LOOK in f for f in ex["findings"])
    X.bind(p["lb"], key_file=p["kb"], account=ACCT)
    r = X.pair(p["la"], p["lb"])
    assert r["verdict"] == V.VERIFIED, r["reason"]
    assert _only(r)["status"] == "clean"
    assert r["logs"]["b"]["accounts"] == [ACCT]


def test_forged_binding_signed_by_another_key_is_broken(parties):
    p = parties
    _react(p, "a", counterparty=ACCT)
    _react(p, "b")
    forged = X.build_binding(seed=_seed(p, "a"), account=ACCT)   # a's key, in b's log
    Ledger(p["lb"]).append(dict(forged))
    r = X.pair(p["la"], p["lb"])
    assert r["verdict"] == V.BROKEN
    assert r["logs"]["b"]["accounts"] == []
    assert _only(r)["status"] != "clean"


def test_binding_with_an_edited_account_is_broken(parties):
    p = parties
    row = X.build_binding(seed=_seed(p, "b"), account=ACCT)
    row["account"] = "acct:someone-else@arcaeon.io"
    assert X.check_binding(row) is not None
    _react(p, "b")
    Ledger(p["lb"]).append(dict(row))
    assert X.pair(p["la"], p["lb"])["verdict"] in (V.BROKEN, V.COULD_NOT_LOOK)


def test_account_bound_by_both_logs_does_not_resolve(parties):
    p = parties
    _react(p, "a", counterparty=ACCT)
    _react(p, "b")
    X.bind(p["lb"], key_file=p["kb"], account=ACCT)
    X.bind(p["la"], key_file=p["ka"], account=ACCT)
    ex = _only(X.pair(p["la"], p["lb"]))
    assert ex["status"] == "mismatch"
    assert any("more than one log binds" in f for f in ex["findings"])


def test_cli_bind(parties, capsys):
    p = parties
    rc = cli.main(["exchange", "bind", "--account", ACCT, "--key", str(p["kb"]),
                   "--log", str(p["lb"])])
    assert rc == V.EXIT_GOOD
    assert json.loads(capsys.readouterr().out)["row"]["account"] == ACCT
    assert cli.main(["exchange", "bind", "--account", "nope", "--key", str(p["kb"]),
                     "--log", str(p["lb"])]) == V.EXIT_USAGE
    assert cli.main(["exchange", "bind", "--key", str(p["kb"])]) == V.EXIT_USAGE
    assert "Traceback" not in capsys.readouterr().err
