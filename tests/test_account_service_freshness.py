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


# --- R11: a replayed statement says when it was fetched ----------------------------

def test_file_service_records_mtime_as_fetched_at_and_reports_as_of(store, server, tmp_path):
    did, _ = _issue(store, server)
    f = tmp_path / "statements.json"
    f.write_text(json.dumps({"statements": [A.binding_statement(store, did)]}), encoding="utf-8")
    mt = datetime(2026, 10, 1, 8, 0, 0, tzinfo=timezone.utc).timestamp()
    os.utime(f, (mt, mt))
    svc, why = A.load_service(f, [server[1]])
    assert why is None
    assert svc["fetched_at"] == "2026-10-01T08:00:00Z"
    rep = A.service_report(svc, [])
    assert rep["fetched_at"] == "2026-10-01T08:00:00Z"
    assert "as of 2026-10-01T08:00:00Z" in rep["reason"]
    assert "revocation after" in rep["reason"]


def test_explicit_fetched_at_field_is_used_when_older_than_mtime(store, server, tmp_path):
    did, _ = _issue(store, server)
    f = tmp_path / "statements.json"
    f.write_text(json.dumps({"fetched_at": "2026-09-30T07:00:00Z",
                             "statements": [A.binding_statement(store, did)]}),
                 encoding="utf-8")
    svc, why = A.load_service(f, [server[1]])
    assert why is None and svc["fetched_at"] == "2026-09-30T07:00:00Z"
    svc2, _ = A.load_service({"fetched_at": "2026-09-30T07:00:00Z",
                              "statements": [A.binding_statement(store, did)]}, [server[1]])
    assert "as of 2026-09-30T07:00:00Z" in A.service_report(svc2, [])["reason"]


def test_bad_fetched_at_is_refused(store, server):
    _, why = A.load_service({"fetched_at": "yesterday", "statements": []}, [server[1]])
    assert why and "fetched_at" in why


def test_in_memory_statements_without_a_time_say_unknown(store, server):
    did, _ = _issue(store, server)
    svc, _ = A.load_service([A.binding_statement(store, did)], [server[1]])
    assert svc["fetched_at"] is None
    assert "as of an unknown time" in A.service_report(svc, [])["reason"]
