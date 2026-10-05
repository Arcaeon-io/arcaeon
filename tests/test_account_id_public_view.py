# SPDX-License-Identifier: MIT
"""account_id server rules from stack review 2 (2026-10-05): R4 (no row dated
before the previous one), R10 (the public binding view does not carry an IdP
`sub`), R11 (a replayed statement says when it was fetched).

Keys are throwaway seeds made in the test; identities are fake; no network."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

from arcaeon import verdict as V  # noqa: E402
from arcaeon.prove import account_id as A  # noqa: E402
from arcaeon.prove.vet import receipts as R  # noqa: E402

T5 = datetime(2026, 10, 5, 12, 0, 5, tzinfo=timezone.utc)
T3 = datetime(2026, 10, 5, 12, 0, 3, tzinfo=timezone.utc)
OWNER = "acct:owner-a@arcaeon.io"
SESSION = {"kind": "owner_session", "owner": OWNER}


def _key():
    seed = os.urandom(32)
    return seed, R.did_key(R.public_key_from_seed(seed))


@pytest.fixture
def server():
    return _key()


@pytest.fixture
def store():
    return A.new_store()


def _issue(store, server, at=T5, name="bot1"):
    seed, did = _key()
    acct = A.agent_account(name, OWNER)
    A.issue(store, SESSION, agent=name, proof=A.possession_proof(seed, acct, at=at),
            server_seed=server[0], at=at)
    return did, acct


def _verify(store, did, server, **kw):
    return A.verify_binding(A.binding_statement(store, did), did, server_keys=[server[1]], **kw)


def _receipt(**over):
    rec = {"issuer_family": "okta", "iss": "https://idp.example.com/oauth2/default",
           "sub": "agent-one@example.com", "facets": ["svc"], "key_jkt": None,
           "jwt_sha256": "a" * 64, "jwk_sha256": "b" * 64,
           "binding_strength": "possession-sig", "checked_at": "2026-10-05T12:30:00Z"}
    rec.update(over)
    return rec


# --- R10: the public view carries no IdP sub; the owner view does ------------------

def _attached(store, server):
    did, acct = _issue(store, server, at=T5)
    A.attach_external(store, SESSION, acct, receipt=_receipt(), server_seed=server[0],
                      at=T5 + timedelta(hours=1))
    return did, acct


def test_public_binding_view_carries_iss_and_a_salted_sub_hash_only(store, server):
    did, _ = _attached(store, server)
    st, out = A.handle(store, None, "GET", f"/v1/keys/{did}/binding", None,
                       server_seed=server[0])
    assert st == 200
    blob = json.dumps(out)
    assert "agent-one@example.com" not in blob and "agent-one" not in blob
    ext = [r["external"] for r in out["rows"] if r["event"] == "external"][0]
    assert "sub" not in ext and "sub_salt" not in ext
    assert ext["iss"] == "https://idp.example.com/oauth2/default"
    assert len(ext["sub_sha256"]) == 64
    # a plain sha256 of the sub is not what is published (it could be guessed back)
    assert ext["sub_sha256"] != hashlib.sha256(b"agent-one@example.com").hexdigest()
    rep = A.verify_binding(out, did, server_keys=[server[1]], now=T5 + timedelta(hours=2))
    assert rep["verdict"] == V.VERIFIED, rep
    assert "agent-one@example.com" not in json.dumps(rep)


def test_owner_view_carries_the_full_receipt_that_opens_the_public_hash(store, server):
    did, acct = _attached(store, server)
    st, out = A.handle(store, SESSION, "GET", f"/v1/agents/{acct}/binding", None,
                       server_seed=server[0])
    assert st == 200, out
    full = out["receipts"]
    assert len(full) == 1 and full[0]["receipt"]["sub"] == "agent-one@example.com"
    row = out["rows"][full[0]["row"]]
    salt = bytes.fromhex(full[0]["sub_salt"])
    assert hashlib.sha256(salt + b"agent-one@example.com").hexdigest() == \
        row["external"]["sub_sha256"]
    # the owner view is the same signed history the public one is
    assert A.verify_binding(out, did, server_keys=[server[1]],
                            now=T5 + timedelta(hours=2))["verdict"] == V.VERIFIED


def test_owner_view_needs_the_owner(store, server):
    _, acct = _attached(store, server)
    for caller, want in ((None, 401), ({"kind": "agent_key", "agent": acct}, 403),
                         ({"kind": "owner_session", "owner": "acct:owner-b@arcaeon.io"}, 404)):
        st, out = A.handle(store, caller, "GET", f"/v1/agents/{acct}/binding", None,
                           server_seed=server[0])
        assert st == want and "agent-one" not in json.dumps(out)


def test_two_accounts_with_one_sub_are_not_linkable_publicly(store, server):
    _, a1 = _issue(store, server, name="bot1")
    d2, a2 = _issue(store, server, name="bot2")
    for a in (a1, a2):
        A.attach_external(store, SESSION, a, receipt=_receipt(), server_seed=server[0],
                          at=T5 + timedelta(hours=1))
    hashes = {[r for r in rec["rows"] if r["event"] == "external"][0]["external"]["sub_sha256"]
              for rec in store["accounts"].values()}
    assert len(hashes) == 2
