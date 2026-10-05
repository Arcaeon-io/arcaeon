# SPDX-License-Identifier: MIT
"""arcaeon.prove.register: the register of named operators, revocation rows (TE-41, L3-03).

A design stub, not a service: no server route, no publishing, no network, no
real keys. The design is docs/design/REGISTER_REVOCATION.md.

The register is one append-only, hash-linked list of rows signed by the
register operator's key. A row ADDS a thing to a member (an operator's key, a
chain name or a witness endpoint) or REVOKES one. A row is never deleted or
edited, and a thing once added is never added again, under any member.

    new_register()                                             -> []
    thing_digest(what, value)                                  -> digest
    add(register, operator_seed, member=, what=, value=, at=)  -> row
    revoke(register, operator_seed, member=, what=, digest=, reason=, at=,
           compromised_since=)                                 -> row
    check_register(rows, operator_keys=[DID])                  -> report
    reading_at(rows, member, digest, sealed_at, operator_keys=[DID],
               fetched_at=)                                    -> report

THE ROW (kind "register.row", v 1). Every field below is signed, null where an
event does not use it; `sig` is outside:

  {"kind", "v", "event", "member", "what", "value", "digest", "at", "reason",
   "compromised_since", "prev", "signer"} + "sig"

The signing and chaining scheme is account_id's (fields_digest, sign_fields,
verify_fields): PAE + json-c14n over the signed fields, Ed25519, base64, with
this module's own payload type so an account.binding signature never passes
as a register row.

READING (reading_at), never raises:
  VERIFIED        the register checks, the thing was added to that member at
                  or before sealed_at, and it was not revoked by then. A later
                  revocation is shown beside the VERIFIED.
  BROKEN          the register itself does not check (a signature, a prev
                  link, a row out of place, a signer you did not name); or the
                  thing is named under another member; or sealed_at is at or
                  after the revocation (retired / superseded /
                  operator_request: at or after `at`; key_compromise: at or
                  after `compromised_since`, which may precede `at`).
  COULD NOT LOOK  no register, no operator key named, no Ed25519 backend, an
                  unknown member, an unknown thing, sealed_at before the thing
                  was added, or a sealed_at that is not a UTC time.
"""
from __future__ import annotations

import copy
import re
from datetime import datetime, timezone
from typing import Any

from arcaeon import verdict as V
from arcaeon.prove import account_id as A
from arcaeon.prove import envelope as _env
from arcaeon.prove import exchange_log as X
from arcaeon.record.row import digest_json

__all__ = ["ROW_KIND", "PAYLOAD_TYPE", "ROW_VERSION", "SIGNED", "EVENTS", "WHATS", "REASONS",
           "MAX_REGISTER_ROWS", "RegisterError", "new_register", "thing_digest", "add",
           "revoke", "sign_row", "row_digest", "check_register", "reading_at"]

ROW_KIND = "register.row"
PAYLOAD_TYPE = "application/vnd.arcaeon.register.row.v1+json"
ROW_VERSION = 1
SIGNED = ("kind", "v", "event", "member", "what", "value", "digest", "at", "reason",
          "compromised_since", "prev", "signer")
EVENTS = ("add", "revoke")
#: What a register entry can hold and so what a revoke row can revoke.
WHATS = ("key", "chain", "witness_endpoint")
#: The only reason words a revoke row may carry.
REASONS = ("key_compromise", "retired", "superseded", "operator_request")
MAX_REGISTER_ROWS = 200_000
_DIGEST = re.compile(r"sha256:json-c14n:v1:[0-9a-f]{64}")

PROVES = ("the register operator's key signed, in one unbroken append-only list, that this "
          "member held this key, chain or witness endpoint from one time, and when (and "
          "why) it stopped")
DOES_NOT_PROVE = ("that a seal time written by the signer is true, that the copy read is "
                  "the newest one, that compromised_since is the real start of a "
                  "compromise, or that the register operator itself is honest")


class RegisterError(ValueError):
    """A refusal on the writer side; nothing was appended."""


def new_register() -> list:
    """An empty register: a list of rows, oldest first."""
    return []


def thing_digest(what: str, value: str) -> str:
    """The digest a row names a thing by: digest_json({"what", "value"})."""
    return digest_json({"what": what, "value": value})


def row_digest(row: dict) -> str:
    """What the next row's `prev` names (account_id.fields_digest)."""
    return A.fields_digest(row, SIGNED)


def sign_row(row: dict, operator_seed: bytes) -> dict:
    """Sign `row` in place with the register operator's 32-byte Ed25519 seed."""
    if not isinstance(operator_seed, (bytes, bytearray)) or len(operator_seed) != 32:
        raise RegisterError("the register operator key is not a 32-byte Ed25519 seed")
    return A.sign_fields(row, operator_seed, SIGNED, PAYLOAD_TYPE)


# --- the rules, shared by the writer and the reader ----------------------------------------

def _value_problem(what: str, value: Any) -> str | None:
    if what == "key":
        if not A._did_shape_ok(value) or A._pub(value) is None:
            return "a key value is not an Ed25519 did:key (the length is checked before any decode)"
    elif what == "chain":
        if not _env._text_ok(value, 128):
            return "a chain value is not one line of text (at most 128 chars)"
    elif what == "witness_endpoint":
        if not (_env._text_ok(value, 512) and value.startswith("https://") and " " not in value):
            return "a witness_endpoint value is not an https URL"
    return None


def _row_problem(row: Any, i: int, prev_row: Any, things: dict) -> str | None:
    """Why row i is out of place, or None. `things` is {digest: entry} so far."""
    if not isinstance(row, dict):
        return f"row {i} is not an object"
    if set(row) != set(SIGNED) | {"sig"}:
        return f"row {i} does not carry exactly the signed fields and sig"
    if row["kind"] != ROW_KIND or row["v"] != ROW_VERSION or isinstance(row["v"], bool):
        return f"row {i} is not a {ROW_KIND} v{ROW_VERSION} row"
    if row["event"] not in EVENTS:
        return f"row {i} event {row['event']!r} is not one of {', '.join(EVENTS)}"
    if not (isinstance(row["member"], str) and X.ACCOUNT_ID_RE.fullmatch(row["member"])):
        return f"row {i} member is not an {X.ACCOUNT_ID_FORM} account"
    if row["what"] not in WHATS:
        return f"row {i} what {row['what']!r} is not one of {', '.join(WHATS)}"
    at = A._parse(row["at"])
    if at is None:
        return f"row {i} at is not a UTC time (YYYY-MM-DDTHH:MM:SSZ)"
    if not (isinstance(row["digest"], str) and _DIGEST.fullmatch(row["digest"])):
        return f"row {i} digest is not a sha256:json-c14n:v1 digest"
    if prev_row is None:
        if row["prev"] is not None:
            return "the first row names a previous row (prev is not null)"
    else:
        if row["prev"] != row_digest(prev_row):
            return f"row {i} prev does not name row {i - 1} (a row was dropped, moved or changed)"
        if at < A._parse(prev_row["at"]):
            return f"row {i} is dated before the row it follows"
    seen = things.get(row["digest"])
    if row["event"] == "add":
        if row["reason"] is not None or row["compromised_since"] is not None:
            return f"row {i} is an add and carries a reason or compromised_since"
        why = _value_problem(row["what"], row["value"])
        if why:
            return f"row {i}: {why}"
        if row["digest"] != thing_digest(row["what"], row["value"]):
            return f"row {i} digest is not the digest of its what and value"
        if seen is not None:
            if seen["revoked"] is not None:
                return (f"row {i} adds a thing revoked at {seen['revoked']['at']}: a revoked "
                        f"thing is never re-added")
            return f"row {i} adds a thing that is already in the register"
        return None
    # revoke
    if row["value"] is not None:
        return f"row {i} is a revoke and carries a value (it names the thing by digest)"
    if seen is None or seen["member"] != row["member"] or seen["what"] != row["what"]:
        return f"row {i}: the revoke names a thing not in the register under this member"
    if seen["revoked"] is not None:
        return f"row {i}: this thing is already revoked (at {seen['revoked']['at']})"
    if row["reason"] not in REASONS:
        return f"row {i} reason {row['reason']!r} is not one of {', '.join(REASONS)}"
    cs = row["compromised_since"]
    if row["reason"] == "key_compromise":
        if row["what"] != "key":
            return f"row {i}: key_compromise is for a key; a {row['what']} is retired or superseded"
        if cs is None:
            return f"row {i}: a key_compromise revoke needs compromised_since"
        t = A._parse(cs)
        if t is None:
            return f"row {i} compromised_since is not a UTC time"
        if t > at:
            return f"row {i} compromised_since is after the revoke's at"
    elif cs is not None:
        return f"row {i}: compromised_since is only for a key_compromise revoke"
    return None


def _note(row: dict, things: dict) -> None:
    if row["event"] == "add":
        things[row["digest"]] = {"member": row["member"], "what": row["what"],
                                 "value": row["value"], "added_at": row["at"], "revoked": None}
    else:
        things[row["digest"]]["revoked"] = row


def _walk(rows: list, verify: bool) -> tuple[str | None, dict, set]:
    """(problem or None, things, signers) over rows in order."""
    things: dict = {}
    signers: set = set()
    for i, row in enumerate(rows):
        why = _row_problem(row, i, rows[i - 1] if i else None, things)
        if why:
            return why, things, signers
        if verify and not A.verify_fields(row, SIGNED, PAYLOAD_TYPE):
            return (f"row {i} signature does not verify (a field or the signature was "
                    f"changed)"), things, signers
        signers.add(row["signer"])
        _note(row, things)
    return None, things, signers


# --- the writer --------------------------------------------------------------------------

def _stamp(t: Any, name: str) -> str:
    if isinstance(t, str):
        if A._parse(t) is None:
            raise RegisterError(f"{name} is not a UTC time (YYYY-MM-DDTHH:MM:SSZ)")
        return t
    if not isinstance(t, datetime) or t.tzinfo is None:
        raise RegisterError(f"{name} is not an aware datetime or a UTC time string")
    return A._utc(A._when(t))


def _append(register: list, operator_seed: bytes, row: dict) -> dict:
    if not isinstance(register, list):
        raise RegisterError("the register is not a list of rows")
    why, things, _ = _walk(register, verify=False)
    if why:
        raise RegisterError(f"the register does not check before this row: {why}")
    row["prev"] = row_digest(register[-1]) if register else None
    sign_row(row, operator_seed)
    why = _row_problem(row, len(register), register[-1] if register else None, things)
    if why:
        raise RegisterError(re.sub(r"^row \d+:? ", "", why))
    register.append(row)
    return copy.deepcopy(row)


def _blank(event: str, member: Any, what: Any, at: Any) -> dict:
    row = {k: None for k in SIGNED}
    row.update(kind=ROW_KIND, v=ROW_VERSION, event=event, member=member, what=what,
               at=_stamp(datetime.now(timezone.utc) if at is None else at, "at"))
    return row


def add(register: list, operator_seed: bytes, *, member: str, what: str, value: str,
        at: Any = None) -> dict:
    """Add a key, chain or witness endpoint to a member. Refused (RegisterError,
    nothing appended) when the thing was ever added before, by anyone: a revoked
    thing is never re-added."""
    row = _blank("add", member, what, at)
    row["value"] = value
    if what in WHATS:
        why = _value_problem(what, value)
        if why:
            raise RegisterError(why)
        row["digest"] = thing_digest(what, value)
    return _append(register, operator_seed, row)


def revoke(register: list, operator_seed: bytes, *, member: str, what: str, digest: str,
           reason: str, at: Any = None, compromised_since: Any = None) -> dict:
    """Revoke a member's thing at `at`, for one of REASONS. A key_compromise
    revoke names compromised_since (at or before `at`): seals from then on read
    BROKEN. The row is appended; nothing earlier is touched."""
    row = _blank("revoke", member, what, at)
    row.update(digest=digest, reason=reason,
               compromised_since=(None if compromised_since is None
                                  else _stamp(compromised_since, "compromised_since")))
    return _append(register, operator_seed, row)


# --- the reader --------------------------------------------------------------------------

def check_register(rows: Any, *, operator_keys: Any = ()) -> dict:
    """VERIFIED / BROKEN / COULD NOT LOOK for the register itself: every row in
    its place, linked, and signed by an operator key you named. Never raises."""
    rep = {"verdict": None, "reason": None, "rows": 0, "head": None, "signers": []}

    def done(word, why):
        rep["verdict"], rep["reason"] = word, why
        return rep
    try:
        if not isinstance(rows, list) or not rows:
            return done(V.COULD_NOT_LOOK, "no register rows to read")
        if len(rows) > MAX_REGISTER_ROWS:
            return done(V.COULD_NOT_LOOK, f"the register is over {MAX_REGISTER_ROWS} rows; not read")
        try:
            A._receipts()._require_backend()
        except Exception:  # noqa: BLE001
            return done(V.COULD_NOT_LOOK, "this install cannot check Ed25519: "
                                          "pip install 'arcaeon[sign]'")
        rep["rows"] = len(rows)
        why, _, signers = _walk(rows, verify=True)
        if why:
            return done(V.BROKEN, why)
        rep["signers"] = sorted(signers)
        rep["head"] = row_digest(rows[-1])
        keys = [operator_keys] if isinstance(operator_keys, str) else list(operator_keys or ())
        trusted = {k for k in keys if A._did_shape_ok(k)}
        if not trusted:
            return done(V.COULD_NOT_LOOK, f"signed by {', '.join(rep['signers'])}; name the "
                                          f"register operator key you trust (operator_keys)")
        if not signers <= trusted:
            return done(V.BROKEN, f"signed by {', '.join(sorted(signers - trusted))}, not by "
                                  f"an operator key you named")
        return done(V.VERIFIED, f"{len(rows)} rows, linked and signed by the operator key "
                                f"you named; head {rep['head']}")
    except Exception as e:  # noqa: BLE001  hostile input is an answer, not a crash
        return done(V.COULD_NOT_LOOK, f"the register could not be read ({type(e).__name__})")


def _instant(t: Any) -> datetime | None:
    if isinstance(t, str):
        return A._parse(t)
    if isinstance(t, datetime) and t.tzinfo is not None:
        return t.astimezone(timezone.utc)
    return None


def reading_at(register_rows: Any, member: Any, key_digest: Any, sealed_at: Any, *,
               operator_keys: Any = (), fetched_at: Any = None) -> dict:
    """Was `key_digest` (a key, chain or witness endpoint, by thing_digest) good
    for `member` at `sealed_at`, by this copy of the register? Never raises.

    `fetched_at` is when this copy was fetched (a datetime or UTC string; None
    = unknown). A copy is as fresh as its fetch: a revocation written after it
    is not seen, so a VERIFIED says "as of" that time."""
    fetched = _instant(fetched_at)
    as_of = A._utc(fetched) if fetched else None
    rep = {"verdict": None, "reason": None, "member": member, "digest": key_digest,
           "what": None, "added_at": None, "revocation": None, "as_of": as_of,
           "register": None}

    def done(word, why):
        rep["verdict"], rep["reason"] = word, why
        return rep
    try:
        chk = check_register(register_rows, operator_keys=operator_keys)
        rep["register"] = {k: chk[k] for k in ("verdict", "reason", "rows", "head")}
        if chk["verdict"] == V.BROKEN:
            return done(V.BROKEN, f"the register itself is BROKEN: {chk['reason']}")
        if chk["verdict"] != V.VERIFIED:
            return done(V.COULD_NOT_LOOK, f"the register could not be checked: {chk['reason']}")
        t = _instant(sealed_at)
        if t is None:
            return done(V.COULD_NOT_LOOK, "sealed_at is not a UTC time (YYYY-MM-DDTHH:MM:SSZ "
                                          "or an aware datetime)")
        _, things, _ = _walk(register_rows, verify=False)
        members = {e["member"] for e in things.values()}
        if member not in members:
            return done(V.COULD_NOT_LOOK, f"the register has no member {member}")
        entry = things.get(key_digest)
        if entry is None:
            return done(V.COULD_NOT_LOOK, f"the register names no such key, chain or witness "
                                          f"endpoint under member {member}")
        rep["what"], rep["added_at"] = entry["what"], entry["added_at"]
        if entry["member"] != member:
            return done(V.BROKEN, f"the register names this {entry['what']} under "
                                  f"{entry['member']}, not {member}")
        if t < A._parse(entry["added_at"]):
            return done(V.COULD_NOT_LOOK, f"sealed_at is before the {entry['what']} was added "
                                          f"({entry['added_at']}); the member did not hold it then")
        rv = entry["revoked"]
        fresh = (f"as of {as_of}" if as_of else "as of an unknown time") + \
            " (a copy is as fresh as its fetch; a revocation after then is not seen)"
        if rv is None:
            return done(V.VERIFIED, f"{entry['what']} registered to {member} from "
                                    f"{entry['added_at']}; no revocation in this copy, {fresh}")
        rep["revocation"] = {"at": rv["at"], "reason": rv["reason"],
                             "compromised_since": rv["compromised_since"],
                             "row": row_digest(rv)}
        if rv["reason"] == "key_compromise":
            since = rv["compromised_since"]
            if t >= A._parse(since):
                return done(V.BROKEN, f"the key was revoked for key_compromise at {rv['at']}, "
                                      f"compromised since {since}; anything sealed from "
                                      f"{since} on is not the member's")
            return done(V.VERIFIED, f"key registered to {member} from {entry['added_at']}; "
                                    f"revoked later for key_compromise at {rv['at']} "
                                    f"(compromised since {since}), after this seal; {fresh}")
        if t >= A._parse(rv["at"]):
            return done(V.BROKEN, f"the {entry['what']} was revoked ({rv['reason']}) at "
                                  f"{rv['at']}; anything sealed from then on is not the member's")
        return done(V.VERIFIED, f"{entry['what']} registered to {member} from "
                                f"{entry['added_at']}; revoked later ({rv['reason']}) at "
                                f"{rv['at']}, after this seal; {fresh}")
    except Exception as e:  # noqa: BLE001  hostile input is an answer, not a crash
        return done(V.COULD_NOT_LOOK, f"the register could not be read ({type(e).__name__})")
