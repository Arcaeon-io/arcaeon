# SPDX-License-Identifier: MIT
"""Register of named operators: revocation rows (L3-03, TE-41), arcaeon.prove.register.

Keys here are TEST-ONLY: generated inside the test from os.urandom and thrown
away. No real key, no network, no file outside tmp.
"""
from __future__ import annotations

import copy
import os
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

from arcaeon import verdict as V  # noqa: E402
from arcaeon.prove import register as G  # noqa: E402
from arcaeon.prove.vet import receipts as R  # noqa: E402

T0 = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)
MEMBER = "acct:operator-a@arcaeon.io"
OTHER = "acct:operator-b@arcaeon.io"
S = timedelta(seconds=1)
D = timedelta(days=1)


def _key():
    seed = os.urandom(32)
    return seed, R.did_key(R.public_key_from_seed(seed))


@pytest.fixture
def op():
    """The TEST-ONLY register operator key."""
    return _key()


def _reg(op, member=MEMBER, at=T0):
    reg = G.new_register()
    _, did = _key()
    G.add(reg, op[0], member=member, what="key", value=did, at=at)
    return reg, did, G.thing_digest("key", did)


def _read(reg, op, digest, sealed, member=MEMBER, **kw):
    return G.reading_at(reg, member, digest, sealed, operator_keys=[op[1]], **kw)


# --- the rows -------------------------------------------------------------------------

def test_add_and_revoke_rows_carry_the_designed_fields(op):
    reg, did, dg = _reg(op)
    row = G.revoke(reg, op[0], member=MEMBER, what="key", digest=dg, reason="retired",
                   at=T0 + D)
    assert row["kind"] == G.ROW_KIND and row["v"] == 1
    assert row["event"] == "revoke" and row["member"] == MEMBER and row["what"] == "key"
    assert row["digest"] == dg and row["at"] == "2026-10-06T12:00:00Z"
    assert row["reason"] == "retired" and row["compromised_since"] is None
    assert row["prev"] == G.row_digest(reg[0]) and row["signer"] == op[1]
    assert isinstance(row["sig"], str) and row["value"] is None
    assert reg[0]["prev"] is None and reg[0]["value"] == did
    assert G.check_register(reg, operator_keys=[op[1]])["verdict"] == V.VERIFIED


def test_reasons_are_a_fixed_set():
    assert G.REASONS == ("key_compromise", "retired", "superseded", "operator_request")
    assert G.WHATS == ("key", "chain", "witness_endpoint")


def test_signing_reuses_the_account_id_scheme(op):
    """One scheme: PAE + json-c14n over the signed fields, Ed25519, base64."""
    from arcaeon.prove import account_id as A
    reg, _, _ = _reg(op)
    assert A.verify_fields(reg[0], G.SIGNED, G.PAYLOAD_TYPE)
    assert not A.verify_fields(reg[0], G.SIGNED, A.PAYLOAD_TYPE)   # domain separated
    assert G.row_digest(reg[0]) == A.fields_digest(reg[0], G.SIGNED)


# --- schema refusals (writer side) ---------------------------------------------------------

@pytest.mark.parametrize("kw, why", [
    ({"reason": "lost"}, "reason"),
    ({"reason": "key_compromise"}, "compromised_since"),
    ({"reason": "retired", "compromised_since": T0}, "compromised_since"),
    ({"reason": "key_compromise", "compromised_since": T0 + 2 * D}, "after"),
    ({"reason": "retired", "what": "certificate"}, "what"),
    ({"reason": "retired", "member": "operator-a"}, "member"),
    ({"reason": "retired", "digest": "abc"}, "digest"),
])
def test_revoke_schema_refusals(op, kw, why):
    reg, _, dg = _reg(op)
    args = {"member": MEMBER, "what": "key", "digest": dg, "at": T0 + D}
    args.update(kw)
    before = copy.deepcopy(reg)
    with pytest.raises(G.RegisterError, match=why):
        G.revoke(reg, op[0], **args)
    assert reg == before


@pytest.mark.parametrize("what, value", [
    ("key", "not-a-did"),
    ("key", "did:key:z" + "1" * 400),
    ("witness_endpoint", "http://witness.example/"),
    ("chain", "two\nlines"),
    ("chain", ""),
])
def test_add_schema_refusals(op, what, value):
    reg = G.new_register()
    with pytest.raises(G.RegisterError):
        G.add(reg, op[0], member=MEMBER, what=what, value=value, at=T0)
    assert reg == []


def test_key_compromise_is_for_keys_only(op):
    reg = G.new_register()
    G.add(reg, op[0], member=MEMBER, what="chain", value="operator-a-main", at=T0)
    dg = G.thing_digest("chain", "operator-a-main")
    with pytest.raises(G.RegisterError, match="key"):
        G.revoke(reg, op[0], member=MEMBER, what="chain", digest=dg,
                 reason="key_compromise", compromised_since=T0, at=T0 + D)


def test_revoke_of_unknown_or_already_revoked_thing_refused(op):
    reg, _, dg = _reg(op)
    with pytest.raises(G.RegisterError, match="not in the register"):
        G.revoke(reg, op[0], member=MEMBER, what="key", digest="sha256:json-c14n:v1:" + "0" * 64,
                 reason="retired", at=T0 + D)
    with pytest.raises(G.RegisterError, match="not in the register"):
        G.revoke(reg, op[0], member=OTHER, what="key", digest=dg, reason="retired", at=T0 + D)
    G.revoke(reg, op[0], member=MEMBER, what="key", digest=dg, reason="retired", at=T0 + D)
    with pytest.raises(G.RegisterError, match="already revoked"):
        G.revoke(reg, op[0], member=MEMBER, what="key", digest=dg, reason="superseded",
                 at=T0 + 2 * D)


def test_row_dated_before_the_last_row_refused(op):
    reg, _, dg = _reg(op)
    with pytest.raises(G.RegisterError, match="before"):
        G.revoke(reg, op[0], member=MEMBER, what="key", digest=dg, reason="retired",
                 at=T0 - S)


def test_reader_refuses_a_row_outside_the_schema_even_when_signed(op):
    reg, _, dg = _reg(op)
    G.revoke(reg, op[0], member=MEMBER, what="key", digest=dg, reason="retired", at=T0 + D)
    bad = copy.deepcopy(reg)
    bad[1]["reason"] = "felt_like_it"
    G.sign_row(bad[1], op[0])                      # the operator itself signs junk
    rep = G.check_register(bad, operator_keys=[op[1]])
    assert rep["verdict"] == V.BROKEN and "reason" in rep["reason"]
    extra = copy.deepcopy(reg)
    extra[1]["note"] = "x"
    assert G.check_register(extra, operator_keys=[op[1]])["verdict"] == V.BROKEN


# --- signature tamper -----------------------------------------------------------------

def test_signature_tamper_reads_the_register_broken(op):
    reg, _, dg = _reg(op)
    G.revoke(reg, op[0], member=MEMBER, what="key", digest=dg, reason="retired", at=T0 + D)
    bad = copy.deepcopy(reg)
    bad[1]["at"] = "2026-10-09T12:00:00Z"           # push the retirement later, unsigned
    rep = G.check_register(bad, operator_keys=[op[1]])
    assert rep["verdict"] == V.BROKEN and "signature" in rep["reason"]
    r = _read(bad, op, dg, T0 + 2 * D)
    assert r["verdict"] == V.BROKEN and "register" in r["reason"]


def test_rows_by_a_key_not_named_read_broken_and_no_key_named_could_not_look(op):
    reg, _, dg = _reg(op)
    other = _key()
    assert G.check_register(reg, operator_keys=[other[1]])["verdict"] == V.BROKEN
    assert G.check_register(reg, operator_keys=[])["verdict"] == V.COULD_NOT_LOOK
    assert G.reading_at(reg, MEMBER, dg, T0 + D)["verdict"] == V.COULD_NOT_LOOK


# --- chain break ----------------------------------------------------------------------

def _three(op):
    reg, did, dg = _reg(op)
    _, did2 = _key()
    G.add(reg, op[0], member=MEMBER, what="key", value=did2, at=T0 + S)
    G.revoke(reg, op[0], member=MEMBER, what="key", digest=dg, reason="key_compromise",
             compromised_since=T0 + S, at=T0 + D)
    return reg, dg


def test_dropping_a_row_breaks_the_chain(op):
    reg, dg = _three(op)
    assert G.check_register(reg, operator_keys=[op[1]])["verdict"] == V.VERIFIED
    dropped = [reg[0], reg[2]]
    rep = G.check_register(dropped, operator_keys=[op[1]])
    assert rep["verdict"] == V.BROKEN and "prev" in rep["reason"]
    # dropping the revocation tail is the stale-copy case, not a break: it still checks
    assert G.check_register(reg[:2], operator_keys=[op[1]])["verdict"] == V.VERIFIED


def test_a_prev_pointing_elsewhere_breaks_even_when_resigned(op):
    reg, dg = _three(op)
    bad = copy.deepcopy(reg)
    bad[2]["prev"] = G.row_digest(bad[0])
    G.sign_row(bad[2], op[0])
    rep = G.check_register(bad, operator_keys=[op[1]])
    assert rep["verdict"] == V.BROKEN and "prev" in rep["reason"]
    assert _read(bad, op, dg, T0)["verdict"] == V.BROKEN


def test_reordered_rows_break(op):
    reg, _ = _three(op)
    assert G.check_register([reg[1], reg[0], reg[2]],
                            operator_keys=[op[1]])["verdict"] == V.BROKEN


def test_first_row_with_a_prev_breaks(op):
    reg, _ = _three(op)
    assert G.check_register(reg[1:], operator_keys=[op[1]])["verdict"] == V.BROKEN


def test_a_resigned_row_dated_backwards_breaks(op):
    reg, _ = _three(op)
    bad = copy.deepcopy(reg)
    bad[2]["at"] = "2026-10-01T00:00:00Z"
    bad[2]["compromised_since"] = "2026-10-01T00:00:00Z"
    G.sign_row(bad[2], op[0])
    assert G.check_register(bad, operator_keys=[op[1]])["verdict"] == V.BROKEN


# --- compromise backdating ---------------------------------------------------------------

def test_compromise_reads_broken_from_compromised_since_before_at(op):
    reg, _, dg = _reg(op)
    G.revoke(reg, op[0], member=MEMBER, what="key", digest=dg, reason="key_compromise",
             compromised_since=T0 + 3 * D, at=T0 + 10 * D)
    before = _read(reg, op, dg, T0 + 3 * D - S)
    assert before["verdict"] == V.VERIFIED
    assert before["revocation"]["reason"] == "key_compromise"
    assert before["revocation"]["compromised_since"] == "2026-10-08T12:00:00Z"
    for t in (T0 + 3 * D, T0 + 5 * D, T0 + 10 * D, T0 + 20 * D):
        r = _read(reg, op, dg, t)
        assert r["verdict"] == V.BROKEN, t
        assert "compromise" in r["reason"]


def test_retirement_does_not_backdate(op):
    reg, _, dg = _reg(op)
    G.revoke(reg, op[0], member=MEMBER, what="key", digest=dg, reason="retired",
             at=T0 + 10 * D)
    assert _read(reg, op, dg, T0 + 5 * D)["verdict"] == V.VERIFIED


def test_compromise_since_may_equal_at(op):
    reg, _, dg = _reg(op)
    G.revoke(reg, op[0], member=MEMBER, what="key", digest=dg, reason="key_compromise",
             compromised_since=T0 + D, at=T0 + D)
    assert _read(reg, op, dg, T0 + D - S)["verdict"] == V.VERIFIED
    assert _read(reg, op, dg, T0 + D)["verdict"] == V.BROKEN


# --- retirement boundary (same second) ------------------------------------------------------

@pytest.mark.parametrize("reason", ["retired", "superseded", "operator_request"])
def test_retirement_boundary_same_second(op, reason):
    reg, _, dg = _reg(op)
    at = T0 + D
    G.revoke(reg, op[0], member=MEMBER, what="key", digest=dg, reason=reason, at=at)
    one_before = _read(reg, op, dg, at - S)
    assert one_before["verdict"] == V.VERIFIED
    assert one_before["revocation"]["at"] == "2026-10-06T12:00:00Z"
    assert "revoked" in one_before["reason"]          # shown beside the VERIFIED
    same = _read(reg, op, dg, at)
    assert same["verdict"] == V.BROKEN and reason in same["reason"]
    assert _read(reg, op, dg, at + S)["verdict"] == V.BROKEN


def test_sub_second_seal_in_the_revocation_second_reads_broken(op):
    reg, _, dg = _reg(op)
    G.revoke(reg, op[0], member=MEMBER, what="key", digest=dg, reason="retired", at=T0 + D)
    r = _read(reg, op, dg, T0 + D + timedelta(milliseconds=400))
    assert r["verdict"] == V.BROKEN


def test_a_seal_with_no_revocation_reads_verified_as_of_the_fetch(op):
    reg, _, dg = _reg(op)
    r = _read(reg, op, dg, T0 + D, fetched_at=T0 + 2 * D)
    assert r["verdict"] == V.VERIFIED and r["revocation"] is None
    assert r["as_of"] == "2026-10-07T12:00:00Z"
    assert "as of 2026-10-07T12:00:00Z" in r["reason"]
    assert "unknown time" in _read(reg, op, dg, T0 + D)["reason"]


def test_a_stale_copy_does_not_see_a_later_revocation(op):
    reg, _, dg = _reg(op)
    stale = copy.deepcopy(reg)
    G.revoke(reg, op[0], member=MEMBER, what="key", digest=dg, reason="key_compromise",
             compromised_since=T0 + S, at=T0 + D)
    old = _read(stale, op, dg, T0 + 2 * S, fetched_at=T0 + S)
    assert old["verdict"] == V.VERIFIED and "not seen" in old["reason"]
    assert _read(reg, op, dg, T0 + 2 * S, fetched_at=T0 + 2 * D)["verdict"] == V.BROKEN


def test_seal_before_the_thing_was_added_could_not_look(op):
    reg, _, dg = _reg(op)
    r = _read(reg, op, dg, T0 - S)
    assert r["verdict"] == V.COULD_NOT_LOOK and "before" in r["reason"]


# --- unknown member / key --------------------------------------------------------------

def test_unknown_member_could_not_look(op):
    reg, _, dg = _reg(op)
    r = _read(reg, op, dg, T0 + D, member="acct:nobody@arcaeon.io")
    assert r["verdict"] == V.COULD_NOT_LOOK and "member" in r["reason"]


def test_unknown_key_could_not_look(op):
    reg, _, _ = _reg(op)
    _, did = _key()
    r = _read(reg, op, G.thing_digest("key", did), T0 + D)
    assert r["verdict"] == V.COULD_NOT_LOOK


def test_key_registered_to_another_member_reads_broken(op):
    reg, _, dg = _reg(op)
    _, did2 = _key()
    G.add(reg, op[0], member=OTHER, what="key", value=did2, at=T0)
    r = _read(reg, op, dg, T0 + D, member=OTHER)
    assert r["verdict"] == V.BROKEN and MEMBER in r["reason"]


@pytest.mark.parametrize("rows", [None, [], "x", [1, 2], [{"kind": "x"}]])
def test_hostile_registers_never_raise(op, rows):
    r = G.reading_at(rows, MEMBER, "sha256:json-c14n:v1:" + "0" * 64, T0,
                     operator_keys=[op[1]])
    assert r["verdict"] in (V.BROKEN, V.COULD_NOT_LOOK)


def test_bad_sealed_at_could_not_look(op):
    reg, _, dg = _reg(op)
    assert _read(reg, op, dg, "yesterday")["verdict"] == V.COULD_NOT_LOOK
    assert _read(reg, op, dg, "2026-10-06T12:00:00Z")["verdict"] == V.VERIFIED


# --- a revoked thing is never re-added ------------------------------------------------------

def test_add_after_revoke_refused(op):
    reg, did, dg = _reg(op)
    G.revoke(reg, op[0], member=MEMBER, what="key", digest=dg, reason="retired", at=T0 + D)
    n = len(reg)
    with pytest.raises(G.RegisterError, match="never"):
        G.add(reg, op[0], member=MEMBER, what="key", value=did, at=T0 + 2 * D)
    with pytest.raises(G.RegisterError, match="never"):
        G.add(reg, op[0], member=OTHER, what="key", value=did, at=T0 + 2 * D)
    assert len(reg) == n


def test_add_twice_refused(op):
    reg, did, _ = _reg(op)
    with pytest.raises(G.RegisterError, match="already"):
        G.add(reg, op[0], member=MEMBER, what="key", value=did, at=T0 + D)


def test_a_signed_re_add_reads_the_register_broken(op):
    """Even the operator's own key cannot re-add a revoked thing unseen."""
    reg, did, dg = _reg(op)
    G.revoke(reg, op[0], member=MEMBER, what="key", digest=dg, reason="key_compromise",
             compromised_since=T0, at=T0 + D)
    forged = copy.deepcopy(reg)
    row = {k: None for k in G.SIGNED}
    row.update(kind=G.ROW_KIND, v=1, event="add", member=MEMBER, what="key", value=did,
               digest=dg, at="2026-10-07T12:00:00Z", prev=G.row_digest(forged[-1]))
    forged.append(G.sign_row(row, op[0]))
    rep = G.check_register(forged, operator_keys=[op[1]])
    assert rep["verdict"] == V.BROKEN and "never" in rep["reason"]
    assert _read(forged, op, dg, T0 + 2 * D)["verdict"] == V.BROKEN


def test_add_row_digest_must_match_its_value(op):
    reg, _, _ = _reg(op)
    bad = copy.deepcopy(reg)
    _, other = _key()
    bad[0]["value"] = other
    G.sign_row(bad[0], op[0])
    assert G.check_register(bad, operator_keys=[op[1]])["verdict"] == V.BROKEN


def test_witness_endpoint_and_chain_revocation_read_the_same_way(op):
    reg = G.new_register()
    G.add(reg, op[0], member=MEMBER, what="witness_endpoint",
          value="https://witness.example/v1", at=T0)
    dg = G.thing_digest("witness_endpoint", "https://witness.example/v1")
    G.revoke(reg, op[0], member=MEMBER, what="witness_endpoint", digest=dg,
             reason="superseded", at=T0 + D)
    assert _read(reg, op, dg, T0 + D - S)["verdict"] == V.VERIFIED
    r = _read(reg, op, dg, T0 + D)
    assert r["verdict"] == V.BROKEN and r["what"] == "witness_endpoint"
