# SPDX-License-Identifier: MIT
"""L3-02 (D077 gap): the exchange binding row held to the account service.

`exchange bind` writes the key holder's own claim; with an account service
given (`accounts=` / `--accounts FILE` plus the server key it trusts), the
tally and `exchange pair` ask the L3-01 stub whether that key held that
account at the binding row's time and at its newest reaction row (R2). Without
one, nothing changes.

Every key here is a throwaway seed made in the test; no network."""
from __future__ import annotations

import base64
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

from arcaeon import verdict as V  # noqa: E402
from arcaeon.prove import account_id as A  # noqa: E402
from arcaeon.prove import envelope as E  # noqa: E402
from arcaeon.prove import exchange_log as X  # noqa: E402
from arcaeon.prove import tally as T  # noqa: E402
from arcaeon.record.ledger import Ledger  # noqa: E402

NOW = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)
OWNER = "acct:owner-a@arcaeon.io"
OTHER = "acct:owner-b@arcaeon.io"
ACCT = "acct:bot1.owner-a@arcaeon.io"
SESSION = {"kind": "owner_session", "owner": OWNER}


class Party:
    def __init__(self, tmp: Path, name: str):
        from arcaeon.prove.vet import receipts as R
        self.seed = secrets.token_bytes(32)
        self.key = tmp / f"{name}.key"
        self.key.write_text(base64.b64encode(self.seed).decode("ascii") + "\n", encoding="ascii")
        self.did = R.did_key(R.public_key_from_seed(self.seed))
        self.log = tmp / f"{name}.jsonl"


class Server:
    def __init__(self):
        from arcaeon.prove.vet import receipts as R
        self.seed = secrets.token_bytes(32)
        self.did = R.did_key(R.public_key_from_seed(self.seed))


@pytest.fixture
def w(tmp_path):
    f = tmp_path / "deliverable.csv"
    f.write_bytes(b"id,grade\n1,A\n")
    return {"tmp": tmp_path, "file": f, "srv": Server(), "store": A.new_store(),
            **{n: Party(tmp_path, n) for n in "ab"}}


def _issue(w, p: Party, at, owner=OWNER, agent="bot1"):
    acct = A.agent_account(agent, owner)
    proof = A.possession_proof(p.seed, acct, at=at)
    A.issue(w["store"], {"kind": "owner_session", "owner": owner}, agent=agent, proof=proof,
            server_seed=w["srv"].seed, at=at)
    return proof


def _exchange(w, bind_at=NOW - timedelta(days=3), account=ACCT):
    a, b = w["a"], w["b"]
    X.bind(a.log, key_file=a.key, account=account, at=bind_at)
    X.react(a.log, key_file=a.key, exchange_id="ex-1", counterparty=b.did, file=w["file"],
            reaction=V.VERIFIED, at=NOW - timedelta(days=1))
    X.react(b.log, key_file=b.key, exchange_id="ex-1", counterparty=account, file=w["file"],
            reaction=V.VERIFIED, at=NOW - timedelta(days=1))


def _tally(w, **kw):
    kw.setdefault("now", NOW)
    if "accounts" in kw:
        kw.setdefault("account_keys", [w["srv"].did])
    return T.build([w["a"].log, w["b"].log], **kw)


def _pair(w, **kw):
    if "accounts" in kw:
        kw.setdefault("account_keys", [w["srv"].did])
    return X.pair(w["a"].log, w["b"].log, **kw)


def _ib(r, did):
    return [i for i in r["ids"] if i["id"] == did][0]["windows"]["all"]


def _svc(r):
    return {b["account"]: b for b in r["account_service"]["bindings"]}


# --- confirmed: VERIFIED pairing ---------------------------------------------------

def test_confirmed_binding_is_a_verified_pairing(w):
    _issue(w, w["a"], NOW - timedelta(days=5))
    _exchange(w)
    r = _tally(w, accounts=w["store"])
    assert r["verdict"] == V.VERIFIED, r["reason"]
    (b,) = r["bindings"]
    assert b["applied"] is True and b["finding"] is None
    assert b["account_service"]["verdict"] == V.VERIFIED
    assert b["account_service"]["at"] == "2026-10-01T12:00:00Z"
    assert _ib(r, w["b"].did)["said"]["total"] == 1
    assert _ib(r, w["a"].did)["paired"]["clean"] == 1
    assert r["account_service"]["consulted"] is True
    assert not any("record is not consulted" in x for x in r["limits"])
    assert "account service VERIFIED" in T.render(r)
    p = _pair(w, accounts=w["store"])
    assert p["verdict"] == V.VERIFIED, p["reason"]
    assert p["counts"]["clean"] == 1
    assert _svc(p)[ACCT]["verdict"] == V.VERIFIED


def test_the_possession_proof_itself_as_the_log_row_is_verified(w):
    """The proof is signed a moment before the server issues; the service
    vouches for that very row, so it is read at the issue time."""
    a = w["a"]
    proof = A.possession_proof(a.seed, ACCT, at=NOW - timedelta(days=5))
    A.issue(w["store"], SESSION, agent="bot1", proof=proof, server_seed=w["srv"].seed,
            at=NOW - timedelta(days=5) + timedelta(minutes=2))
    Ledger(a.log).append(dict(proof))
    _exchange_no_bind(w)
    r = _tally(w, accounts=w["store"])
    assert r["bindings"][0]["account_service"]["verdict"] == V.VERIFIED, r["bindings"]
    assert r["bindings"][0]["applied"] is True


def _exchange_no_bind(w, account=ACCT):
    a, b = w["a"], w["b"]
    X.react(a.log, key_file=a.key, exchange_id="ex-1", counterparty=b.did, file=w["file"],
            reaction=V.VERIFIED, at=NOW - timedelta(days=1))
    X.react(b.log, key_file=b.key, exchange_id="ex-1", counterparty=account, file=w["file"],
            reaction=V.VERIFIED, at=NOW - timedelta(days=1))


# --- BROKEN: revoked before the row, another owner, a forged service row -----------

def test_revoked_before_the_row_is_broken(w):
    _issue(w, w["a"], NOW - timedelta(days=5))
    A.revoke(w["store"], SESSION, ACCT, server_seed=w["srv"].seed, at=NOW - timedelta(days=4))
    _exchange(w)
    r = _tally(w, accounts=w["store"])
    assert r["verdict"] == V.BROKEN
    (b,) = r["bindings"]
    assert b["applied"] is False and b["finding"].startswith(V.BROKEN)
    assert "revoked" in b["account_service"]["reason"]
    assert "revoked" in r["reason"]
    assert _ib(r, w["b"].did)["said_unpaired"]["total"] == 1
    assert "BROKEN" in _ib(r, w["a"].did)["flags"]
    p = _pair(w, accounts=w["store"])
    assert p["verdict"] == V.BROKEN and "revoked" in p["reason"]
    assert p["counts"]["mismatch"] == 1


def test_revoked_after_the_newest_reaction_stays_verified_with_the_revocation_shown(w):
    _issue(w, w["a"], NOW - timedelta(days=5))
    A.revoke(w["store"], SESSION, ACCT, server_seed=w["srv"].seed, at=NOW - timedelta(hours=12))
    _exchange(w)
    r = _tally(w, accounts=w["store"])
    b = r["bindings"][0]
    assert b["applied"] is True and b["account_service"]["verdict"] == V.VERIFIED
    assert "revoked later" in b["account_service"]["reason"]
    assert b["account_service"]["at"] == "2026-10-01T12:00:00Z"
    assert b["account_service"]["through"] == "2026-10-03T12:00:00Z"
    assert _pair(w, accounts=w["store"])["counts"]["clean"] == 1


# --- R2: the key's own reaction rows are held to the service too (the stolen key) ---

def test_reaction_after_the_revoke_unpairs_and_names_the_reaction(w):
    """Issue, bind, revoke, then the key reacts AFTER the revoke: the binding
    row alone checks, the reaction does not; the pairing is dropped, BROKEN."""
    _issue(w, w["a"], NOW - timedelta(days=5))
    A.revoke(w["store"], SESSION, ACCT, server_seed=w["srv"].seed, at=NOW - timedelta(days=2))
    _exchange(w)
    r = _tally(w, accounts=w["store"])
    assert r["verdict"] == V.BROKEN
    (b,) = r["bindings"]
    svc = b["account_service"]
    assert b["applied"] is False and svc["verdict"] == V.BROKEN
    assert b["finding"].startswith(f"{V.BROKEN}: account service: ")
    assert "reaction row" in svc["reason"] and "ex-1" in svc["reason"]
    assert "2026-10-03T12:00:00Z" in svc["reason"] and "revoked" in svc["reason"]
    assert svc["at"] == "2026-10-03T12:00:00Z"
    assert _ib(r, w["b"].did)["said_unpaired"]["total"] == 1
    p = _pair(w, accounts=w["store"])
    assert p["verdict"] == V.BROKEN and "reaction row" in p["reason"]
    assert p["counts"]["mismatch"] == 1
    note = _cp_note(p)
    assert f"account service {V.BROKEN}: " in note and "reaction row" in note, note


def test_reaction_after_a_rotation_unpairs_the_old_key(w):
    _issue(w, w["a"], NOW - timedelta(days=5))
    new = Party(w["tmp"], "c")
    A.rotate(w["store"], SESSION, ACCT, proof=A.possession_proof(new.seed, ACCT,
                                                                 at=NOW - timedelta(days=2)),
             server_seed=w["srv"].seed, at=NOW - timedelta(days=2))
    _exchange(w)
    b = _tally(w, accounts=w["store"])["bindings"][0]
    assert b["applied"] is False and b["account_service"]["verdict"] == V.BROKEN
    assert "rotated out" in b["account_service"]["reason"]
    assert "reaction row" in b["account_service"]["reason"]


def test_consult_binding_takes_the_reaction_rows(w):
    _issue(w, w["a"], NOW - timedelta(days=5))
    A.revoke(w["store"], SESSION, ACCT, server_seed=w["srv"].seed, at=NOW - timedelta(days=2))
    _exchange(w)
    svc, _ = A.load_service(w["store"], [w["srv"].did])
    binds = A.log_binding_rows(w["a"].log, w["a"].did)[ACCT]
    reacts = A.log_reaction_rows(w["a"].log, w["a"].did)
    assert [x["exchange_id"] for x in reacts] == ["ex-1"]
    assert A.consult_binding(svc, w["a"].did, ACCT, binds)["verdict"] == V.VERIFIED
    res = A.consult_binding(svc, w["a"].did, ACCT, binds, reacts)
    assert res["verdict"] == V.BROKEN and res["at"] == "2026-10-03T12:00:00Z"


def test_key_bound_under_a_different_owner_is_broken(w):
    _issue(w, w["a"], NOW - timedelta(days=5), owner=OTHER)     # acct:bot1.owner-b
    _exchange(w)                                                # the log claims owner-a
    r = _tally(w, accounts=w["store"])
    assert r["verdict"] == V.BROKEN
    b = r["bindings"][0]
    assert b["applied"] is False
    assert "different owner" in b["account_service"]["reason"]
    assert "acct:bot1.owner-b@arcaeon.io" in b["account_service"]["reason"]
    assert _pair(w, accounts=w["store"])["verdict"] == V.BROKEN


def test_key_bound_to_a_different_account_same_owner_is_broken(w):
    _issue(w, w["a"], NOW - timedelta(days=5), agent="bot2")
    _exchange(w)
    b = _tally(w, accounts=w["store"])["bindings"][0]
    assert b["account_service"]["verdict"] == V.BROKEN
    assert "different account" in b["account_service"]["reason"]


def test_forged_service_row_bad_server_signature_is_broken(w):
    _issue(w, w["a"], NOW - timedelta(days=5))
    row = w["store"]["accounts"][ACCT]["rows"][0]
    row["at"] = "2026-09-20T12:00:00Z"                          # a signed field changed
    _exchange(w)
    r = _tally(w, accounts=w["store"])
    assert r["verdict"] == V.BROKEN
    b = r["bindings"][0]
    assert b["applied"] is False and "signature does not verify" in b["account_service"]["reason"]


def test_service_row_signed_by_a_key_not_trusted_is_broken(w):
    _issue(w, w["a"], NOW - timedelta(days=5))
    _exchange(w)
    r = _tally(w, accounts=w["store"], account_keys=[Server().did])
    assert r["bindings"][0]["account_service"]["verdict"] == V.BROKEN


# --- COULD NOT LOOK: the service has no record -------------------------------------

def test_unknown_key_with_service_is_could_not_look(w):
    _exchange(w)                                    # nothing issued in the store
    r = _tally(w, accounts=w["store"])
    assert r["verdict"] == V.VERIFIED              # the record reads; the pairing does not
    b = r["bindings"][0]
    assert b["applied"] is False and b["finding"].startswith(V.COULD_NOT_LOOK)
    assert b["account_service"]["verdict"] == V.COULD_NOT_LOOK
    assert "no record" in b["account_service"]["reason"]
    assert _ib(r, w["b"].did)["said_unpaired"]["total"] == 1
    p = _pair(w, accounts=w["store"])
    assert p["verdict"] == V.VERIFIED
    assert _svc(p)[ACCT]["verdict"] == V.COULD_NOT_LOOK
    assert p["counts"]["mismatch"] == 1


def test_service_without_a_trusted_key_is_could_not_look(w):
    _issue(w, w["a"], NOW - timedelta(days=5))
    _exchange(w)
    b = _tally(w, accounts=w["store"], account_keys=[])["bindings"][0]
    assert b["account_service"]["verdict"] == V.COULD_NOT_LOOK and b["applied"] is False


def test_unreadable_accounts_file_makes_the_tally_could_not_look(w):
    _exchange(w)
    bad = w["tmp"] / "accounts.json"
    bad.write_text("{not json", encoding="utf-8")
    r = _tally(w, accounts=bad)
    assert r["verdict"] == V.COULD_NOT_LOOK and "accounts" in r["reason"]
    assert _tally(w, accounts=w["tmp"] / "gone.json")["verdict"] == V.COULD_NOT_LOOK
    assert _pair(w, accounts=bad)["verdict"] == V.COULD_NOT_LOOK


# --- no service: today's behavior, unchanged ---------------------------------------

def test_no_service_is_unchanged(w):
    _issue(w, w["a"], NOW - timedelta(days=5))
    A.revoke(w["store"], SESSION, ACCT, server_seed=w["srv"].seed, at=NOW - timedelta(days=4))
    _exchange(w)
    plain = T.build([w["a"].log, w["b"].log], now=NOW)
    again = T.build([w["a"].log, w["b"].log], now=NOW, accounts=None)
    assert json.dumps(plain, sort_keys=True) == json.dumps(again, sort_keys=True)
    assert "account_service" not in plain
    assert plain["verdict"] == V.VERIFIED
    assert plain["bindings"] == [{"account": ACCT, "key": w["a"].did, "applied": True,
                                  "finding": None}]
    assert any("arcaeon.io's record is not consulted" in x for x in plain["limits"])
    p = X.pair(w["a"].log, w["b"].log)
    assert p["verdict"] == V.VERIFIED and p["counts"]["clean"] == 1
    assert p["account_service"]["consulted"] is False
    assert "account service not consulted" in p["account_service"]["reason"]
    assert "account service not consulted" in X._render(p)


# --- hostile input -------------------------------------------------------------------

def test_oversized_did_key_is_refused_without_decode(w, monkeypatch):
    svc, why = A.load_service(w["store"], [w["srv"].did])
    assert why is None

    real = E._pubkey_from_did

    def boom(did):
        if isinstance(did, str) and len(did) > 100:
            raise AssertionError("decoded an oversized did:key")
        return real(did)
    monkeypatch.setattr(E, "_pubkey_from_did", boom)
    huge = "did:key:z" + "6Mk" * 40000
    res = A.consult_binding(svc, huge, ACCT, [])
    assert res["verdict"] == V.COULD_NOT_LOOK and "length" in res["reason"]
    svc2, why = A.load_service({"statements": [{"did": huge, "rows": []}]}, [w["srv"].did])
    assert why is None
    assert A.consult_binding(svc2, huge, ACCT, [])["verdict"] == V.COULD_NOT_LOOK
    _, why = A.load_service(w["store"], [huge])
    assert why and "did:key" in why


def test_statements_file_form_is_read(w):
    _issue(w, w["a"], NOW - timedelta(days=5))
    _exchange(w)
    f = w["tmp"] / "statements.json"
    f.write_text(json.dumps({"statements": [A.binding_statement(w["store"], w["a"].did)]}),
                 encoding="utf-8")
    r = _tally(w, accounts=f)
    assert r["bindings"][0]["account_service"]["verdict"] == V.VERIFIED


# --- CLI ------------------------------------------------------------------------------

def test_cli_tally_and_pair_take_accounts(w, capsys):
    _issue(w, w["a"], NOW - timedelta(days=5))
    A.revoke(w["store"], SESSION, ACCT, server_seed=w["srv"].seed, at=NOW - timedelta(days=4))
    _exchange(w)
    f = w["tmp"] / "accounts.json"
    A.save_store(w["store"], f)
    logs = [str(w["a"].log), str(w["b"].log)]
    base = ["--accounts", str(f), "--account-key", w["srv"].did]
    assert T.main(["build", *logs, "--now", "2026-10-04T12:00:00Z"]) == V.EXIT_GOOD
    assert T.main(["build", *logs, "--now", "2026-10-04T12:00:00Z", *base]) == V.EXIT_BAD
    assert X.main(["pair", *logs]) == V.EXIT_GOOD
    assert X.main(["pair", *logs, *base]) == V.EXIT_BAD
    capsys.readouterr()
    assert T.main(["build", *logs, "--accounts", str(f)]) == V.EXIT_USAGE
    assert X.main(["pair", *logs, "--account-key", w["srv"].did]) == V.EXIT_USAGE
    assert "--accounts FILE" in T.USAGE and "--accounts FILE" in X.USAGE


# --- doc claims: the FILE, the flags, the unchanged default ---------------------------

def _file_cases(w, monkeypatch):
    """Missing, oversized and non-JSON accounts files, each read as COULD NOT LOOK."""
    gone = w["tmp"] / "gone.json"
    big = w["tmp"] / "big.json"
    A.save_store(w["store"], big)
    bad = w["tmp"] / "bad.json"
    bad.write_bytes(b"\xff\xfe not json")
    monkeypatch.setattr(A, "MAX_STORE_BYTES", big.stat().st_size - 1)
    return {"missing": gone, "oversized": big, "not JSON": bad}


@pytest.mark.parametrize("verb", ["tally", "pair"])
def test_missing_oversized_or_non_json_file_is_could_not_look(w, monkeypatch, verb):
    _issue(w, w["a"], NOW - timedelta(days=5))
    _exchange(w)
    for label, f in _file_cases(w, monkeypatch).items():
        r = _tally(w, accounts=f) if verb == "tally" else _pair(w, accounts=f)
        assert r["verdict"] == V.COULD_NOT_LOOK, (label, r["reason"])
        assert "accounts file" in r["reason"], (label, r["reason"])
    rep = _tally(w, accounts=_file_cases(w, monkeypatch)["oversized"])
    assert "over" in rep["reason"]


def test_cli_missing_accounts_file_exits_could_not_look(w, capsys):
    _exchange(w)
    logs = [str(w["a"].log), str(w["b"].log)]
    base = ["--accounts", str(w["tmp"] / "gone.json"), "--account-key", w["srv"].did]
    assert T.main(["build", *logs, "--now", "2026-10-04T12:00:00Z", *base]) \
        == V.EXIT_COULD_NOT_LOOK
    assert X.main(["pair", *logs, *base]) == V.EXIT_COULD_NOT_LOOK


def test_cli_accounts_without_account_key_is_usage_for_both_verbs(w, capsys):
    _exchange(w)
    f = w["tmp"] / "accounts.json"
    A.save_store(w["store"], f)
    logs = [str(w["a"].log), str(w["b"].log)]
    for argv in (["build", *logs, "--accounts", str(f)],
                 ["build", *logs, "--account-key", w["srv"].did]):
        assert T.main(argv) == V.EXIT_USAGE
    for argv in (["pair", *logs, "--accounts", str(f)],
                 ["pair", *logs, "--account-key", w["srv"].did]):
        assert X.main(argv) == V.EXIT_USAGE
    err = capsys.readouterr().err
    assert "--accounts and --account-key go together" in err


def test_cli_account_key_repeats_and_confirms_in_json(w, capsys):
    _issue(w, w["a"], NOW - timedelta(days=5))
    _exchange(w)
    f = w["tmp"] / "accounts.json"
    A.save_store(w["store"], f)
    logs = [str(w["a"].log), str(w["b"].log)]
    keys = ["--account-key", Server().did, "--account-key", w["srv"].did]
    capsys.readouterr()
    assert T.main(["build", *logs, "--now", "2026-10-04T12:00:00Z", "--json",
                   "--accounts", str(f), *keys]) == V.EXIT_GOOD
    r = json.loads(capsys.readouterr().out)
    assert r["bindings"][0]["account_service"]["verdict"] == V.VERIFIED
    assert len(r["account_service"]["server_keys"]) == 2
    assert X.main(["pair", *logs, "--json", "--accounts", str(f), *keys]) == V.EXIT_GOOD
    p = json.loads(capsys.readouterr().out)
    assert p["counts"]["clean"] == 1 and _svc(p)[ACCT]["verdict"] == V.VERIFIED


def test_cli_without_accounts_output_is_unchanged(w, capsys):
    """No --accounts: the tally carries no account_service block and renders the
    binding exactly as before; a revoked record in a store nobody passed changes nothing."""
    _issue(w, w["a"], NOW - timedelta(days=5))
    A.revoke(w["store"], SESSION, ACCT, server_seed=w["srv"].seed, at=NOW - timedelta(days=4))
    _exchange(w)
    logs = [str(w["a"].log), str(w["b"].log)]
    capsys.readouterr()
    assert T.main(["build", *logs, "--now", "2026-10-04T12:00:00Z", "--json"]) == V.EXIT_GOOD
    out = capsys.readouterr().out
    assert out == json.dumps(T.build(logs, now=NOW), indent=1, ensure_ascii=False) + "\n"
    assert "account_service" not in json.loads(out)
    assert T.main(["build", *logs, "--now", "2026-10-04T12:00:00Z"]) == V.EXIT_GOOD
    text = capsys.readouterr().out
    assert f"binding {ACCT} -> {w['a'].did}: applied (signed binding row)\n" in text
    assert "account service" not in text


def test_pair_render_names_a_broken_binding(w):
    _issue(w, w["a"], NOW - timedelta(days=5))
    A.revoke(w["store"], SESSION, ACCT, server_seed=w["srv"].seed, at=NOW - timedelta(days=4))
    _exchange(w)
    p = _pair(w, accounts=w["store"])
    assert p["verdict"] == V.BROKEN
    assert _svc(p)[ACCT]["verdict"] == V.BROKEN
    assert f"account service BROKEN {ACCT} -> {w['a'].did}" in X._render(p)


def test_tally_seal_does_not_take_accounts(w, capsys):
    _exchange(w)
    f = w["tmp"] / "accounts.json"
    A.save_store(w["store"], f)
    rc = T.main(["seal", str(w["a"].log), "--log", str(w["tmp"] / "tc.jsonl"),
                 "--accounts", str(f), "--account-key", w["srv"].did])
    assert rc == V.EXIT_USAGE
    assert not (w["tmp"] / "tc.jsonl").exists()


# --- L3-02b: a dropped pairing's note names the service's word and reason ----------

def _cp_note(p):
    (ex,) = p["exchanges"]
    return [f for f in ex["findings"] if f.startswith("counterparty: b names")][0]


def test_dropped_could_not_look_note_names_the_service_word_and_reason(w):
    _exchange(w)                                    # a binding row, no service record
    p = _pair(w, accounts=w["store"])
    assert p["verdict"] == V.VERIFIED and p["counts"]["mismatch"] == 1
    note = _cp_note(p)
    assert "holds no signed binding row" not in note, note
    assert f"log a binds {ACCT} by a signed binding row" in note, note
    assert f"account service {V.COULD_NOT_LOOK}: " in note, note
    assert "the account service has no record for this key" in note, note
    assert note in X._render(p)


def test_dropped_broken_note_names_the_service_word_and_reason(w):
    _issue(w, w["a"], NOW - timedelta(days=5))
    A.revoke(w["store"], SESSION, ACCT, server_seed=w["srv"].seed, at=NOW - timedelta(days=4))
    _exchange(w)
    p = _pair(w, accounts=w["store"])
    assert p["verdict"] == V.BROKEN
    note = _cp_note(p)
    assert "holds no signed binding row" not in note, note
    assert f"account service {V.BROKEN}: " in note and "revoked" in note, note


def test_no_binding_row_with_service_keeps_the_holds_no_row_note(w):
    _exchange_no_bind(w)
    p = _pair(w, accounts=w["store"])
    assert p["verdict"] == V.VERIFIED
    note = _cp_note(p)
    assert f"log a holds no signed binding row for {ACCT}" in note, note
    assert "account service" not in note, note
    assert p["account_service"]["consulted"] is True
    assert p["account_service"]["bindings"] == []


def test_without_service_the_exchange_notes_are_unchanged(w):
    _exchange_no_bind(w)
    p = X.pair(w["a"].log, w["b"].log)
    assert f"log a holds no signed binding row for {ACCT}: which key it binds is not " \
           f"checked here ({V.COULD_NOT_LOOK})" in _cp_note(p)
    assert p["account_service"] == A.service_report(None)


# --- R3: two agents of one owner trading are self-trades (TE-44a) ---------------------

ACCT2 = "acct:bot2.owner-a@arcaeon.io"


def _sibling_trade(w, owner_b=OWNER):
    """owner-a's bot1 (key a) and bot2 (key b) bind and react to each other."""
    a, b = w["a"], w["b"]
    _issue(w, a, NOW - timedelta(days=5))
    _issue(w, b, NOW - timedelta(days=5), owner=owner_b, agent="bot2")
    acct_b = A.agent_account("bot2", owner_b)
    X.bind(a.log, key_file=a.key, account=ACCT, at=NOW - timedelta(days=3))
    X.bind(b.log, key_file=b.key, account=acct_b, at=NOW - timedelta(days=3))
    X.react(a.log, key_file=a.key, exchange_id="ex-1", counterparty=acct_b, file=w["file"],
            reaction=V.VERIFIED, at=NOW - timedelta(days=1))
    X.react(b.log, key_file=b.key, exchange_id="ex-1", counterparty=ACCT, file=w["file"],
            reaction=V.VERIFIED, at=NOW - timedelta(days=1))


def test_consult_carries_the_owner(w):
    _issue(w, w["a"], NOW - timedelta(days=5))
    _exchange(w)
    svc, _ = A.load_service(w["store"], [w["srv"].did])
    res = A.consult_pairings(svc, [(ACCT, w["a"].did, [w["a"].log])])
    assert res[0]["verdict"] == V.VERIFIED and res[0]["owner"] == OWNER


def test_two_agents_of_one_owner_trading_are_self_trades(w):
    _sibling_trade(w)
    r = _tally(w, accounts=w["store"])
    assert r["verdict"] == V.VERIFIED, r["reason"]
    assert all(b["applied"] for b in r["bindings"])
    for k in (w["a"].did, w["b"].did):
        win = _ib(r, k)
        assert win["excluded"] == 2, win          # said and received, as for any self-trade
        assert win["paired"]["clean"] == 0 and win["exchanges"] == 0, win
    ex = [i for i in r["ids"] if i["id"] == w["a"].did][0]["excluded"]
    assert ex and all(OWNER in e["reason"] and "self-trade" in e["reason"] for e in ex), ex
    assert "account service" in ex[0]["reason"]
    assert any("agent accounts of one owner" in x for x in r["limits"])


def test_agents_of_two_owners_still_count(w):
    _sibling_trade(w, owner_b=OTHER)
    r = _tally(w, accounts=w["store"])
    assert _ib(r, w["a"].did)["excluded"] == 0
    assert _ib(r, w["a"].did)["paired"]["clean"] == 1


def test_sibling_trade_without_accounts_is_unchanged(w):
    """No --accounts: the owner is never read; the tally is what it was."""
    _sibling_trade(w)
    r = T.build([w["a"].log, w["b"].log], now=NOW)
    assert _ib(r, w["a"].did)["excluded"] == 0
    assert _ib(r, w["a"].did)["paired"]["clean"] == 1
    assert "account_service" not in r
    assert not any("agent accounts of one owner" in x for x in r["limits"])
