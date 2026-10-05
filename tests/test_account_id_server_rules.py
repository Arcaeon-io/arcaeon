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


# --- R4: a server op never writes a row dated before the previous row ---------------

def _ops(store, server, acct):
    seed, _ = _key()
    return {
        "revoke": lambda: A.revoke(store, SESSION, acct, server_seed=server[0], at=T3),
        "rotate": lambda: A.rotate(store, SESSION, acct,
                                   proof=A.possession_proof(seed, acct, at=T3),
                                   server_seed=server[0], at=T3),
        "external": lambda: A.attach_external(store, SESSION, acct, receipt=_receipt(),
                                              server_seed=server[0], at=T3),
    }


@pytest.mark.parametrize("op", ["revoke", "rotate", "external"])
def test_backdated_op_is_refused_409_and_store_is_untouched(store, server, op):
    did, acct = _issue(store, server, at=T5)
    before = copy.deepcopy(store)
    with pytest.raises(A.AccountError) as ei:
        _ops(store, server, acct)[op]()
    assert ei.value.status == 409
    assert "before" in str(ei.value)
    assert store == before
    # the history still verifies: nothing BROKEN was written
    assert _verify(store, did, server, now=T5 + timedelta(hours=1))["verdict"] == V.VERIFIED


def test_review_repro_issue_then_earlier_revoke_does_not_break_the_account(store, server):
    did, acct = _issue(store, server, at=T5)
    st, out = A.handle(store, SESSION, "POST", f"/v1/agents/{acct}/revoke", {},
                       server_seed=server[0], now=T3)
    assert st == 409 and "error" in out
    for t in (T5, T5 + timedelta(days=1)):
        assert _verify(store, did, server, at=t, now=t)["verdict"] == V.VERIFIED


@pytest.mark.parametrize("op", ["revoke", "rotate", "external"])
def test_same_second_op_is_allowed_as_verify_allows_it(store, server, op):
    did, acct = _issue(store, server, at=T3)
    _ops(store, server, acct)[op]()
    stmt = A.binding_statement(store, did)
    rep = A.verify_binding(stmt, did, server_keys=[server[1]], at=T3, now=T3)
    assert "dated before" not in (rep["reason"] or "")
    assert not rep["findings"]
