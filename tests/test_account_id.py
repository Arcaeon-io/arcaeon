# SPDX-License-Identifier: MIT
"""account-as-ID stub (TE-41 machine path): arcaeon.prove.account_id.

Keys here are generated inside the test and thrown away; no real key, no network.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

from arcaeon import verdict as V  # noqa: E402
from arcaeon.prove import account_id as A  # noqa: E402
from arcaeon.prove import envelope as E  # noqa: E402
from arcaeon.prove.vet import receipts as R  # noqa: E402

T0 = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)
OWNER = "acct:owner-a@arcaeon.io"
OTHER_OWNER = "acct:owner-b@arcaeon.io"
SESSION = {"kind": "owner_session", "owner": OWNER}
OWNER_KEY = {"kind": "owner_api_key", "owner": OWNER}


def _key():
    seed = os.urandom(32)
    return seed, R.did_key(R.public_key_from_seed(seed))


@pytest.fixture
def server():
    return _key()


@pytest.fixture
def store():
    return A.new_store()


def _issue(store, server, name="bot1", caller=SESSION, at=T0, owner=OWNER):
    seed, did = _key()
    acct = A.agent_account(name, owner)
    proof = A.possession_proof(seed, acct, at=at)
    row = A.issue(store, caller, agent=name, proof=proof, server_seed=server[0], at=at)
    return seed, did, acct, row


def _verify(store, did, server, **kw):
    return A.verify_binding(A.binding_statement(store, did), did, server_keys=[server[1]], **kw)


# --- issue -------------------------------------------------------------------------

def test_issue_under_owner_binds_account_owner_and_key(store, server):
    _, did, acct, row = _issue(store, server)
    assert acct == "acct:bot1.owner-a@arcaeon.io"
    assert row["kind"] == A.BIND_KIND and row["event"] == "issue"
    assert (row["account"], row["owner"], row["key"]) == (acct, OWNER, did)
    assert row["signer"] == server[1] and row["prev"] is None
    rep = _verify(store, did, server, now=T0 + timedelta(hours=1))
    assert rep["verdict"] == V.VERIFIED, rep
    assert rep["owner"] == OWNER and rep["account"] == acct
    agents = A.list_agents(store, SESSION)
    assert [(a["account"], a["key"], a["status"]) for a in agents] == [(acct, did, "active")]


def test_owner_api_key_can_issue_too(store, server):
    _, did, _, _ = _issue(store, server, caller=OWNER_KEY)
    assert _verify(store, did, server, now=T0)["verdict"] == V.VERIFIED


def test_server_never_holds_the_agent_private_key(store, server):
    seed, _, _, _ = _issue(store, server)
    blob = json.dumps(store)
    assert E._b64(seed) not in blob and seed.hex() not in blob


# --- auth --------------------------------------------------------------------------

@pytest.mark.parametrize("caller", [
    {"kind": "agent_key", "owner": OWNER},
    {"kind": "agent_key", "agent": "acct:bot1.owner-a@arcaeon.io"},
    {"kind": "anonymous"},
    {},
    None,
])
def test_agent_or_anyone_else_cannot_issue(store, server, caller):
    with pytest.raises(A.AccountError) as ei:
        _issue(store, server, caller=caller)
    assert ei.value.status in (401, 403)
    assert A.list_agents(store, SESSION) == []


def test_a_proof_made_for_another_owner_is_refused(store, server):
    seed, _ = _key()
    proof = A.possession_proof(seed, A.agent_account("bot1", OTHER_OWNER), at=T0)
    with pytest.raises(A.AccountError) as ei:
        A.issue(store, SESSION, agent="bot1", proof=proof, server_seed=server[0], at=T0)
    assert ei.value.status == 400


def test_a_proof_with_a_bad_signature_is_refused(store, server):
    seed, _ = _key()
    proof = A.possession_proof(seed, A.agent_account("bot1", OWNER), at=T0)
    proof["at"] = "2026-10-05T12:00:01Z"
    with pytest.raises(A.AccountError) as ei:
        A.issue(store, SESSION, agent="bot1", proof=proof, server_seed=server[0], at=T0)
    assert ei.value.status == 400


def test_only_the_owner_sees_or_revokes_its_agents(store, server):
    _, _, acct, _ = _issue(store, server)
    other = {"kind": "owner_session", "owner": OTHER_OWNER}
    assert A.list_agents(store, other) == []
    with pytest.raises(A.AccountError) as ei:
        A.revoke(store, other, acct, server_seed=server[0], at=T0 + timedelta(hours=1))
    assert ei.value.status == 404


# --- revoke ------------------------------------------------------------------------

def test_revoked_key_is_broken_after_t_and_stays_before_t(store, server):
    _, did, acct, _ = _issue(store, server)
    t_rev = T0 + timedelta(days=1)
    A.revoke(store, SESSION, acct, server_seed=server[0], at=t_rev, reason="key lost")
    after = _verify(store, did, server, at=t_rev + timedelta(minutes=1), now=t_rev + timedelta(days=1))
    assert after["verdict"] == V.BROKEN
    assert after["revoked_at"] == "2026-10-06T12:00:00Z"
    before = _verify(store, did, server, at=t_rev - timedelta(hours=1), now=t_rev + timedelta(days=1))
    assert before["verdict"] == V.VERIFIED
    assert before["revoked_at"] == "2026-10-06T12:00:00Z"   # shown, not hidden
    now_only = _verify(store, did, server, now=t_rev + timedelta(days=1))
    assert now_only["verdict"] == V.BROKEN
    assert A.list_agents(store, SESSION)[0]["status"] == "revoked"


def test_a_time_before_the_key_was_bound_cannot_be_looked_at(store, server):
    _, did, _, _ = _issue(store, server)
    rep = _verify(store, did, server, at=T0 - timedelta(days=1), now=T0)
    assert rep["verdict"] == V.COULD_NOT_LOOK


def test_revoking_twice_is_refused(store, server):
    _, _, acct, _ = _issue(store, server)
    A.revoke(store, SESSION, acct, server_seed=server[0], at=T0 + timedelta(hours=1))
    with pytest.raises(A.AccountError) as ei:
        A.revoke(store, SESSION, acct, server_seed=server[0], at=T0 + timedelta(hours=2))
    assert ei.value.status == 409


# --- rotate ------------------------------------------------------------------------

def test_rotation_keeps_owner_and_links_history(store, server):
    _, old_did, acct, first = _issue(store, server)
    t_rot = T0 + timedelta(days=2)
    new_seed, new_did = _key()
    proof = A.possession_proof(new_seed, acct, at=t_rot)
    row = A.rotate(store, SESSION, acct, proof=proof, server_seed=server[0], at=t_rot)
    assert row["event"] == "rotate" and row["owner"] == OWNER and row["key"] == new_did
    assert row["prev"] == A.row_digest(first)
    stmt = A.binding_statement(store, new_did)
    assert [r["event"] for r in stmt["rows"]] == ["issue", "rotate"]
    assert stmt["account"] == acct and stmt["owner"] == OWNER
    assert _verify(store, new_did, server, now=t_rot)["verdict"] == V.VERIFIED
    # the old key is retired at the rotation time
    old_after = _verify(store, old_did, server, at=t_rot + timedelta(seconds=1), now=t_rot)
    assert old_after["verdict"] == V.BROKEN
    old_before = _verify(store, old_did, server, at=t_rot - timedelta(hours=1), now=t_rot)
    assert old_before["verdict"] == V.VERIFIED
    # the same account, one record
    agents = A.list_agents(store, SESSION)
    assert len(agents) == 1 and agents[0]["key"] == new_did
    assert agents[0]["history"] == 2


def test_history_cannot_be_reset_by_reissuing_the_name(store, server):
    _, _, acct, _ = _issue(store, server)
    A.revoke(store, SESSION, acct, server_seed=server[0], at=T0 + timedelta(hours=1))
    with pytest.raises(A.AccountError) as ei:
        _issue(store, server, at=T0 + timedelta(hours=2))
    assert ei.value.status == 409


def test_rotation_after_revoke_recovers_the_account(store, server):
    _, _, acct, _ = _issue(store, server)
    A.revoke(store, SESSION, acct, server_seed=server[0], at=T0 + timedelta(hours=1))
    seed, did = _key()
    t = T0 + timedelta(hours=2)
    A.rotate(store, SESSION, acct, proof=A.possession_proof(seed, acct, at=t),
             server_seed=server[0], at=t)
    stmt = A.binding_statement(store, did)
    assert [r["event"] for r in stmt["rows"]] == ["issue", "revoke", "rotate"]
    assert _verify(store, did, server, now=t)["verdict"] == V.VERIFIED


def test_a_key_is_never_bound_twice(store, server):
    seed, did, acct, _ = _issue(store, server)
    t = T0 + timedelta(hours=1)
    with pytest.raises(A.AccountError) as ei:
        A.rotate(store, SESSION, acct, proof=A.possession_proof(seed, acct, at=t),
                 server_seed=server[0], at=t)
    assert ei.value.status == 409


# --- duplicate issue: idempotent on an exact repeat, refused otherwise ---------------

def test_exact_repeat_issue_is_idempotent(store, server):
    seed, did = _key()
    acct = A.agent_account("bot1", OWNER)
    proof = A.possession_proof(seed, acct, at=T0)
    first = A.issue(store, SESSION, agent="bot1", proof=proof, server_seed=server[0], at=T0)
    again = A.issue(store, SESSION, agent="bot1", proof=proof, server_seed=server[0],
                    at=T0 + timedelta(minutes=5))
    assert again == first
    assert len(A.binding_statement(store, did)["rows"]) == 1


def test_same_name_other_key_is_refused(store, server):
    _issue(store, server)
    with pytest.raises(A.AccountError) as ei:
        _issue(store, server)
    assert ei.value.status == 409


def test_per_owner_cap_counts_revoked_accounts(store, server):
    for i in range(2):
        _, _, acct, _ = _issue(store, server, name=f"bot{i}")
    A.revoke(store, SESSION, acct, server_seed=server[0], at=T0 + timedelta(hours=1))
    seed, _ = _key()
    proof = A.possession_proof(seed, A.agent_account("bot9", OWNER), at=T0)
    with pytest.raises(A.AccountError) as ei:
        A.issue(store, SESSION, agent="bot9", proof=proof, server_seed=server[0], at=T0,
                max_agents=2)
    assert ei.value.status == 429


def test_control_cluster_is_the_owner(store, server):
    _, d1, a1, _ = _issue(store, server, name="bot1")
    _, d2, a2, _ = _issue(store, server, name="bot2")
    assert A.control_cluster(store, d1) == A.control_cluster(store, a2) == OWNER
    assert A.control_cluster(store, "did:key:z" + "1" * 47) is None


# --- verify paths --------------------------------------------------------------------

def test_forged_binding_signature_is_broken(store, server):
    _, did, _, _ = _issue(store, server)
    stmt = A.binding_statement(store, did)
    stmt["rows"][0]["owner"] = OTHER_OWNER
    stmt["owner"] = OTHER_OWNER
    rep = A.verify_binding(stmt, did, server_keys=[server[1]], now=T0)
    assert rep["verdict"] == V.BROKEN


def test_binding_signed_by_an_untrusted_key_is_broken(store):
    fake = _key()
    _, did, _, _ = _issue(store, fake)
    rep = A.verify_binding(A.binding_statement(store, did), did,
                           server_keys=[_key()[1]], now=T0)
    assert rep["verdict"] == V.BROKEN


def test_no_trusted_server_key_named_cannot_look(store, server):
    _, did, _, _ = _issue(store, server)
    rep = A.verify_binding(A.binding_statement(store, did), did, server_keys=[], now=T0)
    assert rep["verdict"] == V.COULD_NOT_LOOK


def test_altered_agent_proof_is_broken(store, server):
    _, did, _, _ = _issue(store, server)
    stmt = A.binding_statement(store, did)
    stmt["rows"][0]["agent_proof"]["at"] = "2026-10-05T11:00:00Z"
    rep = A.verify_binding(stmt, did, server_keys=[server[1]], now=T0)
    assert rep["verdict"] == V.BROKEN


def test_a_dropped_row_breaks_the_history_link(store, server):
    _, _, acct, _ = _issue(store, server)
    A.revoke(store, SESSION, acct, server_seed=server[0], at=T0 + timedelta(hours=1))
    seed, did = _key()
    t = T0 + timedelta(hours=2)
    A.rotate(store, SESSION, acct, proof=A.possession_proof(seed, acct, at=t),
             server_seed=server[0], at=t)
    stmt = A.binding_statement(store, did)
    del stmt["rows"][1]
    assert A.verify_binding(stmt, did, server_keys=[server[1]], now=t)["verdict"] == V.BROKEN


def test_unknown_key_could_not_look(store, server):
    _issue(store, server)
    _, stranger = _key()
    assert A.binding_statement(store, stranger) is None
    rep = A.verify_binding(None, stranger, server_keys=[server[1]], now=T0)
    assert rep["verdict"] == V.COULD_NOT_LOOK
    assert rep["reason"]


def test_statement_for_another_key_cannot_look(store, server):
    _, did, _, _ = _issue(store, server)
    _, stranger = _key()
    rep = A.verify_binding(A.binding_statement(store, did), stranger,
                           server_keys=[server[1]], now=T0)
    assert rep["verdict"] == V.COULD_NOT_LOOK


def test_oversized_did_key_is_rejected_without_decode(store, server, monkeypatch):
    _, did, _, _ = _issue(store, server)
    stmt = A.binding_statement(store, did)

    def _no_decode(_s):
        raise AssertionError("base58 decode reached on an oversized did:key")
    monkeypatch.setattr(E, "_b58decode", _no_decode)
    huge = "did:key:z" + "1" * 200_000
    started = time.monotonic()
    rep = A.verify_binding(stmt, huge, server_keys=[server[1]], now=T0)
    assert rep["verdict"] == V.COULD_NOT_LOOK
    assert A.binding_statement(store, huge) is None
    assert A.control_cluster(store, huge) is None
    seed, _ = _key()
    proof = A.possession_proof(seed, A.agent_account("bot2", OWNER), at=T0)
    proof["signer"] = huge
    with pytest.raises(A.AccountError) as ei:
        A.issue(store, SESSION, agent="bot2", proof=proof, server_seed=server[0], at=T0)
    assert ei.value.status == 400
    assert time.monotonic() - started < 2.0


def test_verify_never_raises_on_hostile_input(server):
    for stmt in ({}, [], "x", {"rows": "x"}, {"rows": [None]}, {"rows": [{"kind": 1}]}):
        rep = A.verify_binding(stmt, "did:key:z6Mk", server_keys=[server[1]], now=T0)
        assert rep["verdict"] in (V.COULD_NOT_LOOK, V.BROKEN)


# --- external identity ---------------------------------------------------------------

def _receipt(**over):
    rec = {"issuer_family": "entra", "iss": "https://sts.example.test/tenant-1/",
           "sub": "agent-object-1", "facets": ["11"], "key_jkt": None,
           "jwt_sha256": "a" * 64, "jwk_sha256": "b" * 64,
           "binding_strength": "possession-sig", "checked_at": "2026-10-05T12:30:00Z"}
    rec.update(over)
    return rec


def test_attach_external_identity_records_a_receipt_not_a_token(store, server):
    _, did, acct, _ = _issue(store, server)
    t = T0 + timedelta(hours=1)
    row = A.attach_external(store, SESSION, acct, receipt=_receipt(), server_seed=server[0], at=t)
    assert row["event"] == "external" and row["external"]["iss"].startswith("https://")
    rep = _verify(store, did, server, now=t)
    assert rep["verdict"] == V.VERIFIED
    assert rep["external"][0]["issuer_family"] == "entra"


@pytest.mark.parametrize("bad", [
    {"id_token": "eyJ.x.y"}, {"access_token": "eyJ.x.y"}, {"jwt": "eyJ.x.y"},
    {"token": "eyJ.x.y"}, {"jwt_sha256": "eyJhbGciOi.x.y"}, {"issuer_family": "myspace"},
    {"binding_strength": "trust-me"},
])
def test_attach_external_refuses_raw_tokens_and_bad_fields(store, server, bad):
    _, _, acct, _ = _issue(store, server)
    with pytest.raises(A.AccountError) as ei:
        A.attach_external(store, SESSION, acct, receipt=_receipt(**bad),
                          server_seed=server[0], at=T0 + timedelta(hours=1))
    assert ei.value.status == 400
    assert "eyJ" not in json.dumps(store)


def test_agent_cannot_attach_external_identity(store, server):
    _, _, acct, _ = _issue(store, server)
    with pytest.raises(A.AccountError) as ei:
        A.attach_external(store, {"kind": "agent_key", "agent": acct}, acct,
                          receipt=_receipt(), server_seed=server[0], at=T0)
    assert ei.value.status == 403


# --- store and handler -----------------------------------------------------------------

def test_json_file_store_round_trips(store, server, tmp_path):
    _, did, _, _ = _issue(store, server)
    path = tmp_path / "accounts.json"
    A.save_store(store, path)
    again = A.load_store(path)
    assert A.binding_statement(again, did) == A.binding_statement(store, did)
    assert A.load_store(tmp_path / "missing.json") == A.new_store()


def test_handler_routes(store, server):
    seed, did = _key()
    acct = A.agent_account("bot1", OWNER)
    body = {"agent": "bot1", "proof": A.possession_proof(seed, acct, at=T0)}
    st, out = A.handle(store, {"kind": "agent_key", "agent": acct}, "POST", "/v1/agents",
                       body, server_seed=server[0], now=T0)
    assert st == 403 and "error" in out
    st, out = A.handle(store, SESSION, "POST", "/v1/agents", body, server_seed=server[0], now=T0)
    assert st == 201 and out["binding"]["key"] == did
    st, out = A.handle(store, None, "GET", f"/v1/keys/{did}/binding", None,
                       server_seed=server[0], now=T0)
    assert st == 200 and out["account"] == acct
    st, out = A.handle(store, SESSION, "GET", "/v1/agents", None, server_seed=server[0], now=T0)
    assert st == 200 and out["agents"][0]["account"] == acct
    st, _ = A.handle(store, None, "GET", f"/v1/keys/{_key()[1]}/binding", None,
                     server_seed=server[0], now=T0)
    assert st == 404
    st, out = A.handle(store, SESSION, "POST", f"/v1/agents/{acct}/revoke", {"reason": "x"},
                       server_seed=server[0], now=T0 + timedelta(hours=1))
    assert st == 200 and out["binding"]["event"] == "revoke"
    st, _ = A.handle(store, SESSION, "DELETE", "/v1/agents", None, server_seed=server[0], now=T0)
    assert st == 405 or st == 404
