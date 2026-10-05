# SPDX-License-Identifier: MIT
"""arcaeon.prove.exchange_log: signed reactions after an exchange, and the pair reader (TE-42).

    arcaeon exchange react --exchange ID --counterparty ID --file F
                           --reaction {VERIFIED,BROKEN,"COULD NOT LOOK"}
                           [--disputed REASON] [--supersedes ROWDIGEST]
                           --key SEEDFILE [--log PATH]
    arcaeon exchange bind --account acct:NAME@arcaeon.io --key SEEDFILE [--log PATH]
    arcaeon exchange withdraw --row ROWDIGEST --key SEEDFILE [--reason TEXT] [--log PATH]
    arcaeon exchange pair A.jsonl B.jsonl [--owner-a DID] [--owner-b DID] [--json]
                          [--strict] [--late-after SECONDS]
                          [--pin FILE [--stated-at T] [--prev-pin-sha256 HEX]]
    arcaeon exchange packet A.jsonl B.jsonl --exchange ID [--json] [--out DIR]

After an exchange each party writes ONE row under its own account key into its
own hash-chained log (arcaeon.record.ledger.Ledger.append, the same writer the
deal and gate rows use). The pair reader reads both logs and lines the rows up.

THE ROW (kind "exchange.reaction", v 1). Every field below is signed:

  {"kind": "exchange.reaction", "v": 1,
   "exchange_id": TEXT,
   "counterparty": did:key (the other party's account key) or an arcaeon.io
                   account id, acct:NAME@arcaeon.io (ACCOUNT_ID_RE, stored as given),
   "file_sha256": 64 hex, "reaction": "VERIFIED" | "BROKEN" | "COULD NOT LOOK",
   "disputed": bool, "reason": TEXT or null (present exactly when disputed),
   "supersedes": "sha256:json-c14n:v1:<hex>" or null, "at": UTC time,
   "signer": did:key}
  + "sig": base64 Ed25519 signature, and the ledger's own "ts" and "chain".

THE SIGNATURE ENCODING. Ed25519 over the DSSE v1 pre-authentication encoding
(envelope.pae) of the json-c14n v1 bytes (arcaeon.record.row.canon_json:
sorted keys, "," and ":" separators, UTF-8, no NaN) of the eleven signed fields
above, with payload type SIG_PAYLOAD_TYPE. `sig`, `ts` and `chain` are not
signed; any other key in the row is a field outside the signature and the row
reads BROKEN.

THE ROW DIGEST, what `supersedes` points at: digest_json(the eleven signed
fields) = "sha256:json-c14n:v1:" + sha256(those same canonical bytes).

The reaction vocabulary is the verifier's three words. DISPUTED is not a
fourth word: it is a signed CLAIM with a reason, listed apart from the
verdicts. A hash proves what a party said and when, not what the other meant.

Rows are append-only. A change is a new row whose `supersedes` names the old
row's digest; the pair reader reads the latest non-superseded row per party.
Editing a row in place breaks the chain (and, for a signed field, the signature).

THE COUNTERPARTY ID (TE-41: the ID is the arcaeon.io account; the account binds
the did:key). Two forms are accepted, and this module is the one place the
account form is defined: an Ed25519 did:key, or acct:NAME@arcaeon.io (the
RFC 7565 acct: URI under the arcaeon.io host; NAME is 1 to 64 characters of
dot-separated labels, each lower-case a-z, 0-9 and "-", not starting or ending
with "-"). Nothing here resolves an account over the network. A row that
names an account is compared as text: the pair reader and the tally treat
acct:... and did:key:... as two distinct IDs, because no row records which
key an account binds, unless the log holds a binding row (below).

THE BINDING ROW (kind "exchange.binding", v 1; D077). acct:NAME@arcaeon.io is
the confirmed account form. An account id pairs ONLY through a signed binding
row in the bound key's own log: {"kind", "v", "account", "at", "signer"} +
"sig", Ed25519 by `signer` over PAE(BIND_PAYLOAD_TYPE, canon_json(those five
fields)), signer = the log's owner. A binding signed by any other key, or
with a field changed, is a BROKEN row. With a valid binding, a row naming the
account is read as naming that log's key; without one (or when both logs bind
the same account) that side is COULD NOT LOOK, and the pair finding says so.
The binding is the key holder's own claim: whether arcaeon.io agrees that the
account is theirs is not checked here, unless pair() is given an account
service (accounts=, L3-02: arcaeon.prove.account_id.consult_binding).

A row that said BROKEN and was later superseded by a row with another word is
RETRACTED: the current row is read, and the retraction stays visible as a mark
(`retracted` on the head, in the pair and in the tally). Never erased.

THE WITHDRAW ROW (kind "exchange.withdraw", v 1). A party takes its own
reaction back entirely: {"kind", "v", "exchange_id", "withdraws" (the
reaction row's digest), "reason" (TEXT or null), "at", "signer"} + "sig",
Ed25519 by `signer` over PAE(WITHDRAW_PAYLOAD_TYPE, canon_json(those seven
fields)). Append-only: the withdrawn row stays. It must be signed by the
log's owner and name the current (not superseded, not already withdrawn)
reaction row earlier in the same log, for the same exchange; anything else
(signed by the other party or a stranger, naming the other party's row, a
superseded row, a withdraw row) is a BROKEN row. A withdrawal is final: a
row that supersedes a withdrawn reaction or a withdraw row is BROKEN; a new
reaction is a new row (supersedes null). The pair reader and the tally read
it as its own word, `withdrawn`, apart from retracted and superseded.

THE DISAGREEMENT CLASSES (L3-RECON). On top of the status, pair() gives each
exchange that disagrees one word from DISAGREEMENTS (missing, mismatched,
withdrawn, retracted, late, read in that precedence) and a one-sentence
reason; see classify() and docs/EXCHANGE.md. There is no separate retraction
row: the retraction is the one above (a BROKEN superseded by another word).

Never raises from pair(): an unreadable or hostile log is COULD NOT LOOK.
The spec and its limits: docs/EXCHANGE.md.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arcaeon import verdict as V
from arcaeon.record.row import canon_json, digest_json, file_pin, loads_strict

__all__ = ["KIND", "ROW_VERSION", "SIG_PAYLOAD_TYPE", "REACTIONS", "SIGNED_FIELDS",
           "BIND_KIND", "BIND_PAYLOAD_TYPE", "BIND_SIGNED", "build_binding", "check_binding",
           "bind", "WITHDRAW_KIND", "WITHDRAW_PAYLOAD_TYPE", "WITHDRAW_SIGNED",
           "build_withdraw", "check_withdraw", "withdraw_digest", "withdraw", "withdrawn_rows",
           "PAIR_KIND", "STATUSES", "DISAGREEMENTS", "DEFAULT_LATE_AFTER",
           "DOES_NOT_PROVE_ITEMS", "classify", "ACCOUNT_ID_RE", "ACCOUNT_ID_FORM", "ExchangeError",
           "text_ok", "is_did", "is_account_id", "is_counterparty_id", "signed_fields",
           "signing_bytes", "row_digest", "build_row", "react", "check_row", "read_side",
           "latest_heads", "pair_exchange", "pair", "PAIR_PIN_CHAIN", "pair_snapshot",
           "pair_pin_statement", "main"]

KIND = "exchange.reaction"
ROW_VERSION = 1
SIG_PAYLOAD_TYPE = "application/vnd.arcaeon.exchange.reaction.v1+json"
PAIR_KIND = "arcaeon.exchange.pair/v1"
REACTIONS = (V.VERIFIED, V.BROKEN, V.COULD_NOT_LOOK)
SIGNED_FIELDS = ("kind", "v", "exchange_id", "counterparty", "file_sha256", "reaction",
                 "disputed", "reason", "supersedes", "at", "signer")
BIND_KIND = "exchange.binding"
BIND_PAYLOAD_TYPE = "application/vnd.arcaeon.exchange.binding.v1+json"
BIND_SIGNED = ("kind", "v", "account", "at", "signer")
WITHDRAW_KIND = "exchange.withdraw"
WITHDRAW_PAYLOAD_TYPE = "application/vnd.arcaeon.exchange.withdraw.v1+json"
WITHDRAW_SIGNED = ("kind", "v", "exchange_id", "withdraws", "reason", "at", "signer")
#: Keys a row may carry outside the signature: the signature and the ledger's stamps.
UNSIGNED_FIELDS = ("sig", "ts", "chain")
#: A log bigger than this is not read.
MAX_LOG_BYTES = 64 << 20
DEFAULT_LOG = "exchange.jsonl"

STATUSES = ("clean", "mismatch", "not_verified", "missing", "broken")

#: The disagreement classes (L3-RECON), in the order they are counted and
#: printed. Precedence (an exchange that fits more than one carries the first)
#: is missing, mismatched, withdrawn, retracted, late: see classify(). Read by
#: pair() on top of the status; pair_exchange (which the tally calls) does not
#: carry them. `withdrawn` was added last so the earlier four keep their order.
DISAGREEMENTS = ("missing", "mismatched", "late", "retracted", "withdrawn")
#: --late-after default, in seconds: one day. `at` is each signer's own clock
#: and a reaction is often written by a scheduled job after delivery, so a day
#: separates "answered in the same cycle" from "answered after the fact"
#: without marking clock drift or a nightly batch as late.
DEFAULT_LATE_AFTER = 86400

PROVES = ("each row was written by the key that owns its log, in the order the chain "
          "records, and says what that party said about which bytes and when")
DOES_NOT_PROVE = ("that the file is true or safe (two clean rows mean both parties said "
                  "VERIFIED about the same bytes), that the parties did not collude (two "
                  "colluding parties write two clean rows), what either party meant, that "
                  "a key belongs to who it claims, or that a log was not truncated (pin "
                  "its head outside your control)")
#: The same limits as items, for a page that lists them (the pair dispute packet).
DOES_NOT_PROVE_ITEMS = (
    "That the file is true or safe: two clean rows mean both parties said VERIFIED about "
    "the same bytes, not that the bytes say anything true.",
    "That the parties did not collude: two parties who agree to lie write two clean rows.",
    "What either party meant: a DISPUTED reason is the disputer's sentence.",
    "Who holds a key: a did:key is a key, not a person or a company.",
    "That a log was not truncated or re-minted: pin each log's head outside your control.",
    "The at time: it is the writer's clock, signed, not witnessed. A late class is read "
    "from those two clocks.",
)

#: The arcaeon.io account id form (TE-41), the one definition. See the module doc.
ACCOUNT_ID_FORM = "acct:NAME@arcaeon.io"
_LABEL = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
ACCOUNT_ID_RE = re.compile(rf"acct:(?P<name>{_LABEL}(?:\.{_LABEL})*)@arcaeon\.io")
ACCOUNT_NAME_MAX = 64
_COUNTERPARTY_FORMS = f"an Ed25519 did:key or an arcaeon.io account id ({ACCOUNT_ID_FORM})"

_HEX64 = re.compile(r"[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:json-c14n:v1:[0-9a-f]{64}")
_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"


class ExchangeError(ValueError):
    """`react` refused: a field is missing or malformed, the file or key could
    not be used, or the supersedes target is not in the log. Nothing was written."""


# --- the row ------------------------------------------------------------------------

def text_ok(v: Any, limit: int = 256) -> bool:
    return (isinstance(v, str) and 0 < len(v.strip()) and len(v) <= limit
            and not any(ord(c) < 0x20 or ord(c) == 0x7f for c in v))


def is_account_id(v: Any) -> bool:
    """True for an arcaeon.io account id, acct:NAME@arcaeon.io (ACCOUNT_ID_RE).
    Text only: nothing is resolved, nothing is fetched."""
    if not isinstance(v, str):
        return False
    m = ACCOUNT_ID_RE.fullmatch(v)
    return bool(m) and len(m.group("name")) <= ACCOUNT_NAME_MAX


def is_counterparty_id(v: Any) -> bool:
    """True for either accepted counterparty form: did:key or account id."""
    return is_did(v) or is_account_id(v)


def is_did(v: Any) -> bool:
    from arcaeon.prove.envelope import _pubkey_from_did
    try:
        _pubkey_from_did(v)
        return True
    except (ValueError, TypeError):
        return False


def signed_fields(row: dict) -> dict:
    """The eleven signed fields of a row (KeyError if one is absent)."""
    return {k: row[k] for k in SIGNED_FIELDS}


def signing_bytes(row: dict) -> bytes:
    """What the signature covers: PAE(SIG_PAYLOAD_TYPE, canon_json(signed fields))."""
    from arcaeon.prove.envelope import pae
    return pae(SIG_PAYLOAD_TYPE, canon_json(signed_fields(row)))


def row_digest(row: dict) -> str:
    """The digest `supersedes` points at: digest_json(signed fields)."""
    return digest_json(signed_fields(row))


def _parse_at(text: Any) -> bool:
    if not isinstance(text, str):
        return False
    try:
        datetime.strptime(text, _TS_FMT)
        return True
    except ValueError:
        return False


def _shape_problem(row: dict) -> str | None:
    """Why a row is not a well-formed exchange.reaction row, or None."""
    keys = set(row)
    missing = [k for k in SIGNED_FIELDS + ("sig",) if k not in keys]
    if missing:
        return f"missing field(s) {', '.join(missing)}"
    extra = sorted(keys - set(SIGNED_FIELDS) - set(UNSIGNED_FIELDS))
    if extra:
        return f"fields outside the signature: {', '.join(extra)}"
    if row["v"] != ROW_VERSION or isinstance(row["v"], bool):
        return f"unknown row version {row['v']!r}"
    if not text_ok(row["exchange_id"]):
        return "exchange_id is not one line of text (at most 256 characters)"
    if not is_counterparty_id(row["counterparty"]):
        return f"counterparty is not {_COUNTERPARTY_FORMS}"
    if not (isinstance(row["file_sha256"], str) and _HEX64.fullmatch(row["file_sha256"])):
        return "file_sha256 is not 64 lower-case hex"
    if row["reaction"] not in REACTIONS:
        return f"reaction {row['reaction']!r} is not VERIFIED, BROKEN or COULD NOT LOOK"
    if not isinstance(row["disputed"], bool):
        return "disputed is not true or false"
    if row["disputed"] and not text_ok(row["reason"], 1024):
        return "a disputed row carries no reason (one line, at most 1024 characters)"
    if not row["disputed"] and row["reason"] is not None:
        return "reason given on a row that is not disputed"
    if row["supersedes"] is not None and not (isinstance(row["supersedes"], str)
                                              and _DIGEST.fullmatch(row["supersedes"])):
        return "supersedes is not sha256:json-c14n:v1:<64 hex>"
    if not _parse_at(row["at"]):
        return "at is not a UTC time (YYYY-MM-DDTHH:MM:SSZ)"
    if not is_did(row["signer"]):
        return "signer is not an Ed25519 did:key"
    if not isinstance(row["sig"], str):
        return "sig is not a base64 string"
    return None


def check_row(row: dict) -> str | None:
    """None when the row is well formed and its signature verifies under its
    own `signer`; else the reason it is BROKEN. Needs the Ed25519 backend
    (raises if absent: the caller decides that is COULD NOT LOOK)."""
    if not isinstance(row, dict):
        return "not a JSON object"
    bad = _shape_problem(row)
    if bad:
        return bad
    from arcaeon.prove.envelope import _pubkey_from_did
    from arcaeon.prove.vet import receipts as R
    try:
        sig = base64.b64decode(row["sig"], validate=True)
    except (binascii.Error, ValueError):
        return "sig is not base64"
    try:
        message = signing_bytes(row)
    except ValueError as e:
        return f"the signed fields cannot be canonicalized ({e})"
    if not R._verify_bytes(_pubkey_from_did(row["signer"]), message, sig):
        return (f"the signature by {row['signer']} does not verify over the signed fields "
                f"(a field or the signature was changed)")
    return None


def build_row(*, seed: bytes, exchange_id: str, counterparty: str, file_sha256: str,
              reaction: str, disputed: str | None = None, supersedes: str | None = None,
              at: datetime | None = None) -> dict:
    """A signed exchange.reaction row (not yet chained). ExchangeError on a bad field."""
    if not text_ok(exchange_id):
        raise ExchangeError("--exchange must be one line of text, at most 256 characters")
    if not is_counterparty_id(counterparty):
        raise ExchangeError(f"--counterparty {counterparty!r} is not {_COUNTERPARTY_FORMS}: "
                            f"give the other party's did:key (the pair reader matches it "
                            f"against their log's key) or their account id")
    if reaction not in REACTIONS:
        raise ExchangeError(f"--reaction must be VERIFIED, BROKEN or COULD NOT LOOK, "
                            f"got {reaction!r}")
    if not (isinstance(file_sha256, str) and _HEX64.fullmatch(file_sha256)):
        raise ExchangeError("file_sha256 must be 64 lower-case hex")
    if disputed is not None and not text_ok(disputed, 1024):
        raise ExchangeError("--disputed needs a reason: one line, at most 1024 characters")
    if supersedes is not None and not _DIGEST.fullmatch(str(supersedes)):
        raise ExchangeError("--supersedes must be a row digest, sha256:json-c14n:v1:<64 hex>")
    try:
        from arcaeon.prove.vet import receipts as R
        pub = R.public_key_from_seed(seed)
    except Exception as e:  # noqa: BLE001  ReceiptsUnavailable: no backend
        raise ExchangeError(f"signing needs an Ed25519 backend: pip install 'arcaeon[sign]' "
                            f"({type(e).__name__})") from None
    when = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    row = {"kind": KIND, "v": ROW_VERSION, "exchange_id": exchange_id,
           "counterparty": counterparty, "file_sha256": file_sha256, "reaction": reaction,
           "disputed": disputed is not None, "reason": disputed, "supersedes": supersedes,
           "at": when.strftime(_TS_FMT), "signer": R.did_key(pub)}
    row["sig"] = base64.b64encode(R._sign_bytes(seed, signing_bytes(row))).decode("ascii")
    return row


def _bind_bytes(row: dict) -> bytes:
    from arcaeon.prove.envelope import pae
    return pae(BIND_PAYLOAD_TYPE, canon_json({k: row[k] for k in BIND_SIGNED}))


def build_binding(*, seed: bytes, account: str, at: datetime | None = None) -> dict:
    """A signed exchange.binding row: the seed's did:key binds `account`."""
    if not is_account_id(account):
        raise ExchangeError(f"--account {account!r} is not an arcaeon.io account id "
                            f"({ACCOUNT_ID_FORM})")
    try:
        from arcaeon.prove.vet import receipts as R
        pub = R.public_key_from_seed(seed)
    except Exception as e:  # noqa: BLE001  ReceiptsUnavailable: no backend
        raise ExchangeError(f"signing needs an Ed25519 backend: pip install 'arcaeon[sign]' "
                            f"({type(e).__name__})") from None
    when = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    row = {"kind": BIND_KIND, "v": ROW_VERSION, "account": account,
           "at": when.strftime(_TS_FMT), "signer": R.did_key(pub)}
    row["sig"] = base64.b64encode(R._sign_bytes(seed, _bind_bytes(row))).decode("ascii")
    return row


def check_binding(row: Any) -> str | None:
    """None when a binding row is well formed (kind exchange.binding, v 1) and
    signed by its `signer`; else why it is BROKEN. A row of another kind is
    BROKEN here, before any signature work. (Whether the signer owns the log is
    the reader's check.)"""
    if not isinstance(row, dict):
        return "not a JSON object"
    keys = set(row)
    missing = [k for k in BIND_SIGNED + ("sig",) if k not in keys]
    if missing:
        return f"binding row missing field(s) {', '.join(missing)}"
    extra = sorted(keys - set(BIND_SIGNED) - set(UNSIGNED_FIELDS))
    if extra:
        return f"binding row has fields outside the signature: {', '.join(extra)}"
    if row["kind"] != BIND_KIND:        # R12: a row of any other kind is not a binding
        return f"binding row kind is not {BIND_KIND}"
    if row["v"] != ROW_VERSION or isinstance(row["v"], bool):
        return f"unknown binding row version {row['v']!r}"
    if not is_account_id(row["account"]):
        return f"binding row account is not {ACCOUNT_ID_FORM}"
    if not _parse_at(row["at"]):
        return "binding row at is not a UTC time"
    if not is_did(row["signer"]) or not isinstance(row["sig"], str):
        return "binding row signer is not an Ed25519 did:key or sig is not text"
    from arcaeon.prove.envelope import _pubkey_from_did
    from arcaeon.prove.vet import receipts as R
    try:
        sig = base64.b64decode(row["sig"], validate=True)
    except (binascii.Error, ValueError):
        return "binding row sig is not base64"
    if not R._verify_bytes(_pubkey_from_did(row["signer"]), _bind_bytes(row), sig):
        return (f"the binding signature by {row['signer']} does not verify (a field or the "
                f"signature was changed)")
    return None


def bind(log: str | Path, *, key_file: str | Path, account: str,
         at: datetime | None = None) -> dict:
    """Append a signed binding row (this key binds `account`) to the key's own log."""
    from arcaeon.prove.envelope import SealError, _load_seed
    from arcaeon.record.ledger import Ledger
    try:
        seed = _load_seed(key_file)
    except SealError as e:
        raise ExchangeError(str(e)) from None
    row = build_binding(seed=seed, account=account, at=at)
    log = Path(log)
    owners = [r.get("signer") for r in _own_rows(log) if isinstance(r.get("signer"), str)]
    if owners and owners[0] != row["signer"]:
        raise ExchangeError(f"this log belongs to {owners[0]}; the key given is "
                            f"{row['signer']}. A binding goes in the bound key's own log")
    chain = Ledger(log).append(dict(row))
    return {"log": str(log), "row": row, "chain": chain}


def _withdraw_bytes(row: dict) -> bytes:
    from arcaeon.prove.envelope import pae
    return pae(WITHDRAW_PAYLOAD_TYPE, canon_json({k: row[k] for k in WITHDRAW_SIGNED}))


def withdraw_digest(row: dict) -> str:
    """The digest of a withdraw row: digest_json(its seven signed fields)."""
    return digest_json({k: row[k] for k in WITHDRAW_SIGNED})


def build_withdraw(*, seed: bytes, exchange_id: str, withdraws: str,
                   reason: str | None = None, at: datetime | None = None) -> dict:
    """A signed exchange.withdraw row (not yet chained): the seed's did:key takes
    back the reaction row whose digest is `withdraws`. ExchangeError on a bad field.
    Whether that row is the signer's own current reaction is the log's check."""
    if not text_ok(exchange_id):
        raise ExchangeError("exchange_id must be one line of text, at most 256 characters")
    if not (isinstance(withdraws, str) and _DIGEST.fullmatch(withdraws)):
        raise ExchangeError("--row must be a row digest, sha256:json-c14n:v1:<64 hex>")
    if reason is not None and not text_ok(reason, 1024):
        raise ExchangeError("--reason must be one line, at most 1024 characters")
    try:
        from arcaeon.prove.vet import receipts as R
        pub = R.public_key_from_seed(seed)
    except Exception as e:  # noqa: BLE001  ReceiptsUnavailable: no backend
        raise ExchangeError(f"signing needs an Ed25519 backend: pip install 'arcaeon[sign]' "
                            f"({type(e).__name__})") from None
    when = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    row = {"kind": WITHDRAW_KIND, "v": ROW_VERSION, "exchange_id": exchange_id,
           "withdraws": withdraws, "reason": reason, "at": when.strftime(_TS_FMT),
           "signer": R.did_key(pub)}
    row["sig"] = base64.b64encode(R._sign_bytes(seed, _withdraw_bytes(row))).decode("ascii")
    return row


def check_withdraw(row: Any) -> str | None:
    """None when a withdraw row is well formed (kind exchange.withdraw, v 1) and
    signed by its `signer`; else why it is BROKEN. (Whether the signer owns the
    log, and what the row names, are the reader's checks.)"""
    if not isinstance(row, dict):
        return "not a JSON object"
    keys = set(row)
    missing = [k for k in WITHDRAW_SIGNED + ("sig",) if k not in keys]
    if missing:
        return f"withdraw row missing field(s) {', '.join(missing)}"
    extra = sorted(keys - set(WITHDRAW_SIGNED) - set(UNSIGNED_FIELDS))
    if extra:
        return f"withdraw row has fields outside the signature: {', '.join(extra)}"
    if row["kind"] != WITHDRAW_KIND:
        return f"withdraw row kind is not {WITHDRAW_KIND}"
    if row["v"] != ROW_VERSION or isinstance(row["v"], bool):
        return f"unknown withdraw row version {row['v']!r}"
    if not text_ok(row["exchange_id"]):
        return "withdraw row exchange_id is not one line of text (at most 256 characters)"
    if not (isinstance(row["withdraws"], str) and _DIGEST.fullmatch(row["withdraws"])):
        return "withdraw row withdraws is not sha256:json-c14n:v1:<64 hex>"
    if row["reason"] is not None and not text_ok(row["reason"], 1024):
        return "withdraw row reason is neither null nor one line (at most 1024 characters)"
    if not _parse_at(row["at"]):
        return "withdraw row at is not a UTC time"
    if not is_did(row["signer"]) or not isinstance(row["sig"], str):
        return "withdraw row signer is not an Ed25519 did:key or sig is not text"
    from arcaeon.prove.envelope import _pubkey_from_did
    from arcaeon.prove.vet import receipts as R
    try:
        sig = base64.b64decode(row["sig"], validate=True)
    except (binascii.Error, ValueError):
        return "withdraw row sig is not base64"
    try:
        message = _withdraw_bytes(row)
    except ValueError as e:
        return f"the withdraw row's signed fields cannot be canonicalized ({e})"
    if not R._verify_bytes(_pubkey_from_did(row["signer"]), message, sig):
        return (f"the withdraw signature by {row['signer']} does not verify (a field or the "
                f"signature was changed)")
    return None


def _log_state(existing: list[dict]) -> tuple[dict, set, dict, set]:
    """(reaction digest -> row, withdraw-row digests, withdrawn reaction digest ->
    withdraw row, superseded digests) of a log's rows, read loosely (write side)."""
    reactions: dict[str, dict] = {}
    wdig: set[str] = set()
    withdrawn: dict[str, dict] = {}
    superseded: set[str] = set()
    for r in existing:
        try:
            if r.get("kind") == KIND:
                reactions[row_digest(r)] = r
                if r.get("supersedes"):
                    superseded.add(r["supersedes"])
            elif r.get("kind") == WITHDRAW_KIND:
                wdig.add(withdraw_digest(r))
                withdrawn.setdefault(r["withdraws"], r)
        except (KeyError, ValueError, TypeError):
            continue
    return reactions, wdig, withdrawn, superseded


def withdraw(log: str | Path, *, key_file: str | Path, row: str, reason: str | None = None,
             at: datetime | None = None) -> dict:
    """Append one signed withdraw row to `log`: the key's own current reaction
    row `row` (a row digest) is taken back entirely. The withdrawn row stays.
    Returns {row, row_digest, chain, log}; ExchangeError on any refusal, before
    writing (the row is not this log's reaction, is superseded, is already
    withdrawn, or is itself a withdraw row; the log belongs to another key)."""
    from arcaeon.prove.envelope import SealError, _load_seed
    from arcaeon.record.ledger import Ledger
    try:
        seed = _load_seed(key_file)
    except SealError as e:
        raise ExchangeError(str(e)) from None
    if not (isinstance(row, str) and _DIGEST.fullmatch(row)):
        raise ExchangeError("--row must be a row digest, sha256:json-c14n:v1:<64 hex>")
    log = Path(log)
    existing = _own_rows(log)
    reactions, wdig, withdrawn, superseded = _log_state(existing)
    if row in wdig:
        raise ExchangeError(f"--row {row} is a withdraw row: a withdrawal is not taken back; "
                            f"a new reaction is a new row")
    target = reactions.get(row)
    if target is None:
        raise ExchangeError(f"--row {row}: no reaction row with that digest in {log} (a party "
                            f"withdraws only its own reaction, from its own log)")
    if row in withdrawn:
        raise ExchangeError(f"--row {row} is already withdrawn")
    if row in superseded:
        raise ExchangeError(f"--row {row} is superseded: a withdraw names the current reaction")
    w = build_withdraw(seed=seed, exchange_id=target["exchange_id"], withdraws=row,
                       reason=reason, at=at)
    owners = [r.get("signer") for r in existing if isinstance(r.get("signer"), str)]
    if owners and owners[0] != w["signer"]:
        raise ExchangeError(f"this log belongs to {owners[0]}; the key given is "
                            f"{w['signer']}. A party withdraws only its own reaction")
    if target.get("signer") != w["signer"]:
        raise ExchangeError(f"--row {row} is signed by {target.get('signer')}, not by the key "
                            f"given: a party withdraws only its own reaction")
    chain = Ledger(log).append(dict(w))
    return {"log": str(log), "row": w, "row_digest": withdraw_digest(w), "chain": chain}


def _own_rows(path: Path) -> list[dict]:
    """The reaction, binding and withdraw rows already in a log, parsed loosely (write side)."""
    from arcaeon.record.ledger import Ledger
    return [r for r in Ledger(path) if isinstance(r, dict)
            and r.get("kind") in (KIND, BIND_KIND, WITHDRAW_KIND)]


def react(log: str | Path, *, key_file: str | Path, exchange_id: str, counterparty: str,
          file: str | Path, reaction: str, disputed: str | None = None,
          supersedes: str | None = None, at: datetime | None = None) -> dict:
    """Append one signed reaction row to `log` through Ledger.append and return
    {row, row_digest, chain, log}. ExchangeError on any refusal, before writing."""
    from arcaeon.prove.envelope import SealError, _load_seed
    from arcaeon.record.ledger import Ledger
    try:
        seed = _load_seed(key_file)
    except SealError as e:
        raise ExchangeError(str(e)) from None
    pin = file_pin(file)
    if "sha256" not in pin:
        raise ExchangeError(f"cannot read the file ({pin.get('error')})")
    row = build_row(seed=seed, exchange_id=exchange_id, counterparty=counterparty,
                    file_sha256=pin["sha256"], reaction=reaction, disputed=disputed,
                    supersedes=supersedes, at=at)
    log = Path(log)
    existing = _own_rows(log)
    owners = [r.get("signer") for r in existing if isinstance(r.get("signer"), str)]
    if owners and owners[0] != row["signer"]:
        raise ExchangeError(f"this log belongs to {owners[0]}; the key given is "
                            f"{row['signer']}. One log per account key")
    if row["signer"] == counterparty:
        raise ExchangeError("--counterparty is your own key: a pair needs two parties")
    if supersedes is not None:
        _, wdig, withdrawn, _ = _log_state(existing)
        if supersedes in wdig or supersedes in withdrawn:
            raise ExchangeError(f"--supersedes {supersedes} names a withdrawn reaction or a "
                                f"withdraw row: a withdrawal is not re-instated; a new reaction "
                                f"is a new row (no --supersedes)")
        target = None
        for r in existing:
            try:
                if r.get("kind") == KIND and row_digest(r) == supersedes:
                    target = r
            except (KeyError, ValueError, TypeError):
                continue
        if target is None:
            raise ExchangeError(f"--supersedes {supersedes}: no row with that digest in {log}")
        if target.get("exchange_id") != exchange_id:
            raise ExchangeError(f"--supersedes names a row for exchange "
                                f"{target.get('exchange_id')!r}, not {exchange_id!r}")
    chain = Ledger(log).append(dict(row))
    return {"log": str(log), "row": row, "row_digest": row_digest(row), "chain": chain}


# --- the pair reader ------------------------------------------------------------------

def _cnl_log(side: dict, looked_for: str, where, word: str, reason: str) -> dict:
    side.update({"verdict": V.COULD_NOT_LOOK, "reason": reason,
                 **V.could_not_look(looked_for, str(where), word, reason)})
    return side


def read_side(path: Path, owner: str | None, name: str) -> dict:
    """Read and check one log. The side dict carries verdict, chain, owner,
    rows (valid, in chain order, with line and digest) and broken_rows."""
    from arcaeon.record.ledger import verify_file
    side: dict[str, Any] = {"log": str(path), "verdict": None, "reason": None,
                            "owner": owner, "owner_from": "named" if owner else None,
                            "chain": None, "reaction_rows": 0, "binding_rows": 0,
                            "withdraw_rows": 0,
                            "broken_rows": [], "accounts": [], "owner_refused": None,
                            "_rows": [], "_seq": []}
    looked = f"log {name} (an exchange reactions log)"
    try:
        if not path.exists():
            return _cnl_log(side, looked, path, "missing", f"{path.name} is not there")
        if not path.is_file():
            return _cnl_log(side, looked, path, "unreadable", f"{path.name} is not a file")
        if path.stat().st_size > MAX_LOG_BYTES:
            return _cnl_log(side, looked, path, "unreadable",
                            f"{path.name} is over {MAX_LOG_BYTES} bytes; not read")
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return _cnl_log(side, looked, path, "unreadable",
                        f"{path.name} cannot be read as UTF-8 text ({type(e).__name__})")
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    parsed: list[tuple[int, Any]] = []
    for i, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            parsed.append((i, loads_strict(raw)))
        except ValueError:
            parsed.append((i, None))
    if not parsed:
        return _cnl_log(side, looked, path, "empty", f"{path.name} holds no rows")
    if not any(isinstance(o, dict) and isinstance(o.get("chain"), str) for _, o in parsed):
        return _cnl_log(side, looked, path, "unreadable",
                        f"{path.name} is not a hash-chained ledger (no row carries a chain)")
    res = verify_file(path, strict=True)
    side["chain"] = {"ok": res.ok, "rows": res.rows, "breaks": res.breaks,
                     "first_break": res.first_break}
    cand = [(i, o) for i, o in parsed
            if isinstance(o, dict) and o.get("kind") in (KIND, BIND_KIND, WITHDRAW_KIND)]
    side["reaction_rows"] = sum(1 for _, o in cand if o["kind"] == KIND)
    side["binding_rows"] = sum(1 for _, o in cand if o["kind"] == BIND_KIND)
    side["withdraw_rows"] = sum(1 for _, o in cand if o["kind"] == WITHDRAW_KIND)
    checked = []
    check = {KIND: check_row, BIND_KIND: check_binding, WITHDRAW_KIND: check_withdraw}
    for i, o in cand:
        checked.append((i, o, check[o["kind"]](o)))
    first = next((o["signer"] for _, o, p in checked if p is None), None)
    if side["owner"] is None:
        side["owner"] = first
        side["owner_from"] = "first_row" if first else None
    elif first is not None and first != side["owner"]:
        # A08: the caller named the owner, so trust on first use is closed. A log
        # whose first good row is another key's is not the named owner's log:
        # refused whole (BROKEN), no row of it read, no exchange lined up from it.
        side["owner_refused"] = {"named": side["owner"], "first_row": first}
        side["verdict"] = V.BROKEN
        side["reason"] = (f"refused: the first row that verifies is signed by {first}, not by "
                          f"the named owner {side['owner']}; this is not that key's log, and "
                          f"no row of it is read")
        return side
    seen: dict[str, dict] = {}
    wseen: dict[str, int] = {}          # withdraw row digest -> its line
    withdrawn: dict[str, int] = {}      # withdrawn reaction digest -> the withdraw's line
    superseded: set[str] = set()
    accounts: set[str] = set()
    prefix = {BIND_KIND: "binding row ", WITHDRAW_KIND: "withdraw row "}
    for i, o, problem in checked:
        if problem is None and o["signer"] != side["owner"]:
            problem = (f"{prefix.get(o['kind'], '')}signed by "
                       f"{o['signer']}, not by the key that owns this log ({side['owner']})")
        if o["kind"] == BIND_KIND:
            if problem is None:
                accounts.add(o["account"])
            else:
                side["broken_rows"].append({"line": i, "exchange_id": None, "finding": problem})
            continue
        if o["kind"] == WITHDRAW_KIND:
            if problem is None:
                problem = _withdraw_problem(o, seen, wseen, withdrawn, superseded)
            if problem is not None:
                eid = o.get("exchange_id") if isinstance(o.get("exchange_id"), str) else None
                side["broken_rows"].append({"line": i, "exchange_id": eid, "finding": problem})
                continue
            d = withdraw_digest(o)
            wseen[d] = i
            withdrawn[o["withdraws"]] = i
            seen[o["withdraws"]]["withdrawn_by"] = {"line": i, "at": o["at"], "row_digest": d,
                                                    "reason": o["reason"]}
            side["_seq"].append(d)
            continue
        if problem is None and o["supersedes"] is not None:
            tgt = seen.get(o["supersedes"])
            if o["supersedes"] in wseen:
                problem = ("supersedes a withdraw row: a withdrawal is not re-instated; a new "
                           "reaction is a new row (supersedes null)")
            elif o["supersedes"] in withdrawn:
                problem = (f"supersedes a withdrawn reaction (withdrawn at line "
                           f"{withdrawn[o['supersedes']]}): a withdrawn reaction is not "
                           f"re-instated; a new reaction is a new row (supersedes null)")
            elif tgt is None:
                problem = "supersedes a row that is not earlier in this log"
            elif tgt["exchange_id"] != o["exchange_id"]:
                problem = (f"supersedes a row for another exchange "
                           f"({tgt['exchange_id']!r})")
        if problem is not None:
            eid = o.get("exchange_id") if isinstance(o.get("exchange_id"), str) else None
            side["broken_rows"].append({"line": i, "exchange_id": eid, "finding": problem})
            continue
        d = row_digest(o)
        r = {**signed_fields(o), "line": i, "row_digest": d}
        seen[d] = r
        if o["supersedes"] is not None:
            superseded.add(o["supersedes"])
        side["_rows"].append(r)
        side["_seq"].append(d)
    side["accounts"] = sorted(accounts)
    findings = []
    if res.ok is False:
        findings.append(f"the chain does not verify ({res.first_break})")
    if side["broken_rows"]:
        findings.append(f"{len(side['broken_rows'])} reaction row(s) BROKEN "
                        f"(first: line {side['broken_rows'][0]['line']}: "
                        f"{side['broken_rows'][0]['finding']})")
    side["verdict"] = V.BROKEN if findings else V.VERIFIED
    side["reason"] = "; ".join(findings) if findings else "the chain verifies and every reaction row's signature checks under the log's key"
    return side


def _withdraw_problem(o: dict, seen: dict, wseen: dict, withdrawn: dict,
                      superseded: set) -> str | None:
    """Why a signed withdraw row (by the log's owner) does not hold, read in chain
    order against the rows before it; None when it holds."""
    t = o["withdraws"]
    if t in wseen:
        return (f"withdraws a withdraw row (line {wseen[t]}): a withdrawal is not taken back; "
                f"a new reaction is a new row")
    tgt = seen.get(t)
    if tgt is None:
        return ("withdraws a row that is not an earlier reaction in this log (a party "
                "withdraws only its own reaction)")
    if tgt["exchange_id"] != o["exchange_id"]:
        return f"withdraws a row for another exchange ({tgt['exchange_id']!r})"
    if tgt["signer"] != o["signer"]:
        return f"withdraws a row signed by {tgt['signer']}, not by the withdrawing key"
    if t in withdrawn:
        return f"withdraws a reaction already withdrawn (line {withdrawn[t]})"
    if t in superseded:
        return "withdraws a superseded row: a withdraw names the current reaction"
    return None


def withdrawn_rows(side: dict) -> dict[str, list[dict]]:
    """exchange_id -> this log's withdrawn reaction rows (each carries
    `withdrawn_by`: the withdraw row's line, at, digest and reason)."""
    out: dict[str, list[dict]] = {}
    for r in side["_rows"]:
        if r.get("withdrawn_by"):
            out.setdefault(r["exchange_id"], []).append(r)
    return out


def latest_heads(side: dict) -> dict[str, dict]:
    """exchange_id -> the latest non-superseded, non-withdrawn row (with notes on
    forks). A head that is not BROKEN, for an exchange where this log said BROKEN
    in a row now superseded, carries `retracted` (how many such rows) and
    `retracted_at` (the latest one's `at`): the retraction is a mark, never
    erased (F7). A head written after this log withdrew an earlier reaction for
    the exchange carries `withdrawn` and `withdrawn_at` the same way. A withdrawn
    row is never a head (withdrawn_rows lists it)."""
    rows = side["_rows"]
    superseded = {r["supersedes"] for r in rows if r["supersedes"]}
    by_ex: dict[str, list[dict]] = {}
    gone: dict[str, list[dict]] = {}
    wd: dict[str, list[dict]] = {}
    for r in rows:
        if r.get("withdrawn_by"):
            wd.setdefault(r["exchange_id"], []).append(r)
        elif r["row_digest"] not in superseded:
            by_ex.setdefault(r["exchange_id"], []).append(r)
        elif r["reaction"] == V.BROKEN:
            gone.setdefault(r["exchange_id"], []).append(r)
    out = {}
    for eid, heads in by_ex.items():
        head = dict(heads[-1])
        if head["reaction"] != V.BROKEN and gone.get(eid):
            head["retracted"] = len(gone[eid])
            head["retracted_at"] = max(g["at"] for g in gone[eid])
        if wd.get(eid):
            head["withdrawn"] = len(wd[eid])
            head["withdrawn_at"] = max(w["withdrawn_by"]["at"] for w in wd[eid])
        if len(heads) > 1:
            head["note"] = (f"{len(heads)} rows for this exchange are not superseded "
                            f"(lines {', '.join(str(h['line']) for h in heads)}); the last "
                            f"in chain order is read")
        out[eid] = head
    return out


def _account_note(acct: str, other: str, shared, dropped=None) -> str:
    x = (dropped or {}).get(other, {}).get(acct)
    if x is not None:
        return (f"; log {other} binds {acct} by a signed binding row, but the account "
                f"service {x['verdict']}: {x['reason']}; the pairing is dropped, so which "
                f"key it binds is not resolved")
    if acct in shared:
        return (f"; more than one log binds {acct}, so it is not resolved to any key: "
                f"which key it binds is not checked here ({V.COULD_NOT_LOOK})")
    return (f"; log {other} holds no signed binding row for {acct}: which key it binds is "
            f"not checked here ({V.COULD_NOT_LOOK})")


def _summary(r: dict | None) -> dict | None:
    if r is None:
        return None
    keep = ("reaction", "file_sha256", "counterparty", "signer", "at", "disputed", "reason",
            "supersedes", "line", "row_digest", "note", "retracted", "retracted_at",
            "withdrawn", "withdrawn_at")
    return {k: r[k] for k in keep if k in r}


def pair_exchange(eid: str, a: dict | None, b: dict | None, own_a, own_b,
                   broken_a: list, broken_b: list, ids_a=None, ids_b=None,
                   shared=(), dropped=None, withdrawn_a=None, withdrawn_b=None) -> dict:
    """Line one exchange up. ids_a / ids_b: the IDs that name each party (its key,
    plus accounts its log binds by a valid binding row); default its key only.
    shared: accounts both logs bind (resolved to neither). dropped: {log name:
    {account: account service answer}} for bindings the service did not confirm.
    withdrawn_a / withdrawn_b: that side's withdrawn rows for this exchange
    (withdrawn_rows); a side with no current row and a withdrawn one reads
    status missing and is listed under `withdrawn`."""
    ids_a = {own_a} if ids_a is None else set(ids_a)
    ids_b = {own_b} if ids_b is None else set(ids_b)
    ex: dict[str, Any] = {"exchange_id": eid, "status": None, "differs": [],
                          "a": _summary(a), "b": _summary(b), "retracted": [],
                          "withdrawn": [], "findings": []}
    for nm, row in (("a", a), ("b", b)):
        if row and row.get("retracted"):
            ex["retracted"].append(nm)
            ex["findings"].append(f"{nm} retracted an earlier BROKEN ({row['retracted']} "
                                  f"row(s), latest at {row['retracted_at']}); its current row "
                                  f"says {row['reaction']}")
    for nm, row, wl in (("a", a, withdrawn_a), ("b", b, withdrawn_b)):
        if row and row.get("withdrawn"):
            ex["withdrawn"].append(nm)
            ex["findings"].append(f"{nm} withdrew an earlier reaction ({row['withdrawn']} "
                                  f"row(s), latest withdraw at {row['withdrawn_at']}); its "
                                  f"current row, written after, says {row['reaction']}")
        elif row is None and wl:
            w = wl[-1]
            ex["withdrawn"].append(nm)
            ex["findings"].append(f"{nm} withdrew its reaction (line {w['line']}, which said "
                                  f"{w['reaction']}; withdraw row line "
                                  f"{w['withdrawn_by']['line']} at {w['withdrawn_by']['at']}); "
                                  f"it has no current reaction")
    if broken_a or broken_b:
        ex["status"] = "broken"
        for nm, bl in (("a", broken_a), ("b", broken_b)):
            for br in bl:
                ex["findings"].append(f"log {nm} line {br['line']}: {br['finding']}")
        return ex
    if a is None or b is None:
        ex["status"] = "missing"
        ex["findings"].append(f"no reaction from {'a' if a is None else 'b'}")
        return ex
    if a["reaction"] != b["reaction"]:
        ex["differs"].append("reaction")
        ex["findings"].append(f"reaction: a said {a['reaction']}, b said {b['reaction']}")
    if a["file_sha256"] != b["file_sha256"]:
        ex["differs"].append("file_sha256")
        ex["findings"].append(f"file_sha256: a reacted to {a['file_sha256']}, "
                              f"b to {b['file_sha256']}")
    if a["counterparty"] not in ids_b or b["counterparty"] not in ids_a:
        ex["differs"].append("counterparty")
        for nm, row, other, own, ids in (("a", a, "b", own_b, ids_b),
                                         ("b", b, "a", own_a, ids_a)):
            if row["counterparty"] not in ids:
                cp = row["counterparty"]
                ex["findings"].append(f"counterparty: {nm} names {cp}, log {other} is owned "
                                      f"by {own}" + (_account_note(cp, other, shared, dropped)
                                                     if is_account_id(cp) else ""))
    if ex["differs"]:
        ex["status"] = "mismatch"
    elif a["reaction"] != V.VERIFIED:
        ex["status"] = "not_verified"
        ex["findings"].append(f"both said {a['reaction']}: agreed, not clean")
    else:
        ex["status"] = "clean"
    return ex


def _late_window(late_after: Any) -> int:
    if isinstance(late_after, bool) or not isinstance(late_after, int) or late_after < 0:
        raise ValueError(f"late_after must be a whole number of seconds, 0 or more "
                         f"(got {late_after!r})")
    return late_after


def _when(row: dict | None) -> datetime | None:
    try:
        return datetime.strptime(row["at"], _TS_FMT).replace(tzinfo=timezone.utc)
    except (TypeError, KeyError, ValueError):
        return None


def _short(field: str, v: Any) -> str:
    s = str(v)
    return s[:12] + "..." if field == "file_sha256" and len(s) > 12 else s


def classify(ex: dict, a: dict | None, b: dict | None, *,
             late_after: int = DEFAULT_LATE_AFTER) -> tuple[str | None, str | None, str | None]:
    """The disagreement class of one lined-up exchange (pair_exchange's dict and
    the two head rows): (word, one-sentence reason, note). word is one of
    DISAGREEMENTS, or None when the two sides agree, or when the status is
    broken (a record that does not check is not read for a disagreement).
    Precedence: missing, mismatched, withdrawn, retracted, late. missing,
    mismatched and a withdrawal with no current row say the current records do
    not reconcile; withdrawn (as a mark), retracted and late are read on
    current records that agree. A withdrawn reaction is a record taken back,
    not a record that never was, so it is not missing. note is set when the
    late class could not be read (no comparable `at` on both rows).
    ValueError on a bad late_after."""
    late_after = _late_window(late_after)
    status = ex.get("status")
    if status == "broken":
        return None, None, None
    wd = list(ex.get("withdrawn") or [])
    if status == "missing" or a is None or b is None:
        absent = [nm for nm, row in (("a", a), ("b", b)) if row is None and nm not in wd]
        if absent:
            gone = absent[0]
            has, row = ("b", b) if gone == "a" else ("a", a)
            said = (f" (its row says {row['reaction']} at {row['at']})" if row else
                    " (it withdrew its reaction)" if has in wd else "")
            return ("missing", f"log {gone} has no record of this exchange; log {has} "
                               f"does{said}.", None)
        who = " and ".join(wd)
        other = next(((nm, row) for nm, row in (("a", a), ("b", b)) if row), None)
        tail = (f"; log {other[0]}'s current row says {other[1]['reaction']}" if other
                else "")
        return ("withdrawn", f"log {who} withdrew its reaction to this exchange by a signed "
                             f"withdraw row and has no current one{tail}; the withdrawn row "
                             f"stays in the log.", None)
    differs = list(ex.get("differs") or [])
    if differs:
        parts = []
        for f in differs:
            if f == "counterparty":
                parts.append("counterparty (each side names a party the other log is not)")
            else:
                parts.append(f"{f} (a {_short(f, a.get(f))}, b {_short(f, b.get(f))})")
        what = "this field differs" if len(parts) == 1 else "these fields differ"
        return "mismatched", f"both logs have it, but {what}: {'; '.join(parts)}.", None
    if wd:
        who = " and ".join(wd)
        return ("withdrawn", f"log {who} withdrew an earlier reaction for this exchange and "
                             f"wrote a new one (the current rows agree on {a['reaction']}); "
                             f"the withdrawn row stays in the log.", None)
    if ex.get("retracted"):
        who = " and ".join(ex["retracted"])
        return ("retracted", f"log {who} retracted an earlier BROKEN for this exchange "
                             f"(superseded; the current rows agree on {a['reaction']}); the "
                             f"retracted row stays in the log.", None)
    ta, tb = _when(a), _when(b)
    if ta is None or tb is None:
        return None, None, ("late not read: the two rows carry no comparable at time, so "
                            "this exchange cannot be late")
    gap = int(abs((tb - ta).total_seconds()))
    if gap > late_after:
        late, early = (("b", b), ("a", a)) if tb > ta else (("a", a), ("b", b))
        return ("late", f"both agree on {a['reaction']}, but log {late[0]}'s record time "
                        f"({late[1]['at']}) trails log {early[0]}'s ({early[1]['at']}) by "
                        f"{gap} s, past the {late_after} s window.", None)
    return None, None, None


def _hold_to_accounts(r: dict, svc: dict, sa: dict, sb: dict, acc_a: set, acc_b: set,
                      broken: list, dropped: dict) -> tuple[set, set]:
    """L3-02: an account a log binds pairs only if the account service confirms it."""
    from arcaeon.prove import account_id as A
    res = A.consult_pairings(svc, [(acct, s["owner"], [s["log"]])
                                   for s, accs in ((sa, acc_a), (sb, acc_b)) for acct in sorted(accs)])
    r["account_service"] = A.service_report(svc, res)
    keep = {(x["account"], x["key"]) for x in res if x["verdict"] == V.VERIFIED}
    for nm, s, accs in (("a", sa, acc_a), ("b", sb, acc_b)):
        dropped[nm] = {x["account"]: x for x in res if x["verdict"] != V.VERIFIED
                       and x["account"] in accs and x["key"] == s["owner"]}
    broken += [f"binding {x['account']} -> {x['key']}: {x['reason']}" for x in res
               if x["verdict"] == V.BROKEN]
    return ({a for a in acc_a if (a, sa["owner"]) in keep},
            {a for a in acc_b if (a, sb["owner"]) in keep})


def pair(log_a: str | Path, log_b: str | Path, *, owner_a: str | None = None,
         owner_b: str | None = None, accounts: Any = None, account_keys: Any = (),
         late_after: int = DEFAULT_LATE_AFTER) -> dict:
    """Read two parties' reaction logs and line their rows up by exchange_id.

    verdict: BROKEN if either chain fails, any reaction row is BROKEN (bad
    shape, bad signature, a signer that is not the log's owner, a dangling
    supersedes) or both logs are owned by one key; else COULD NOT LOOK if a
    log could not be read (missing, empty, not a chained ledger, hostile) or
    signatures cannot be checked; else VERIFIED. The verdict is about the
    record. Per exchange, `status` is clean / mismatch / not_verified /
    missing / broken; DISPUTED rows are listed under `claims`, never as a
    status. accounts / account_keys: hold each account binding to the account
    service (account_id.load_service); without them `account_service` says it
    was not consulted. Each exchange also carries `disagreement` (one of
    DISAGREEMENTS, or None) and `disagreement_reason`; `disagreements` counts
    them and `late_after` is the window used. Never raises on what it reads;
    a late_after that is not a whole number of seconds >= 0 is a ValueError
    (the caller's bug, before anything is read)."""
    late_after = _late_window(late_after)
    r: dict[str, Any] = {"kind": PAIR_KIND, "verdict": None, "reason": None,
                         "logs": {}, "exchanges": [], "claims": [], "retracted": 0,
                         "withdrawn": 0, "counts": {s: 0 for s in STATUSES}, "findings": [],
                         "disagreements": {w: 0 for w in DISAGREEMENTS},
                         "late_after": late_after,
                         "proves": PROVES, "does_not_prove": DOES_NOT_PROVE}
    try:
        from arcaeon.prove import account_id as A
        r["account_service"] = A.service_report(None)
        svc = None
        if accounts is not None:
            svc, why = A.load_service(accounts, account_keys)
            if why:
                r.update({"verdict": V.COULD_NOT_LOOK, "reason": why,
                          **V.could_not_look("the accounts file", str(accounts), "unreadable", why)})
                return r
        return _pair(r, Path(log_a), Path(log_b), owner_a, owner_b, svc, late_after)
    except Exception as e:  # noqa: BLE001  never a traceback, never a green
        r.update({"verdict": V.COULD_NOT_LOOK, "exchanges": [], "claims": [], "retracted": 0,
                  "withdrawn": 0, "counts": {s: 0 for s in STATUSES},
                  "disagreements": {w: 0 for w in DISAGREEMENTS},
                  "reason": f"the check could not finish ({type(e).__name__})",
                  **V.could_not_look("a finished pair check", f"{log_a}, {log_b}",
                                     "unreadable",
                                     f"the check could not finish ({type(e).__name__})")})
        for side in r["logs"].values():
            side.pop("_rows", None)
            side.pop("_seq", None)
        return r


def _pair(r: dict, pa: Path, pb: Path, owner_a, owner_b, svc=None,
          late_after: int = DEFAULT_LATE_AFTER) -> dict:
    for nm, own in (("a", owner_a), ("b", owner_b)):
        if own is not None and not is_did(own):
            r.update({"verdict": V.COULD_NOT_LOOK,
                      **V.could_not_look(f"the owner key of log {nm}", f"--owner-{nm}",
                                         "unreadable", f"--owner-{nm} is not an Ed25519 did:key")})
            return r
    try:
        from arcaeon.prove.vet import receipts as R
        R._require_backend()
    except Exception:  # noqa: BLE001
        reason = "this install cannot check Ed25519 signatures: pip install 'arcaeon[sign]'"
        r.update({"verdict": V.COULD_NOT_LOOK,
                  **V.could_not_look("an Ed25519 backend", "this install", "missing", reason)})
        return r
    sa = read_side(pa, owner_a, "a")
    sb = read_side(pb, owner_b, "b")
    r["logs"] = {"a": sa, "b": sb}
    broken = [f"log {nm}: {s['reason']}" for nm, s in (("a", sa), ("b", sb))
              if s["verdict"] == V.BROKEN]
    cnl = [(nm, s) for nm, s in (("a", sa), ("b", sb)) if s["verdict"] == V.COULD_NOT_LOOK]
    same = (pa.resolve() == pb.resolve()) or (sa["owner"] and sa["owner"] == sb["owner"])
    if same and not cnl:
        broken.append(f"both logs are owned by one key ({sa['owner']}): a pair needs two "
                      f"parties")
    refused = any(s.get("owner_refused") for s in (sa, sb))
    if not cnl and not refused:
        ha, hb = latest_heads(sa), latest_heads(sb)
        wa, wb = withdrawn_rows(sa), withdrawn_rows(sb)
        ba: dict[str, list] = {}
        bb: dict[str, list] = {}
        for src, dst in ((sa["broken_rows"], ba), (sb["broken_rows"], bb)):
            for br in src:
                if br["exchange_id"] is not None:
                    dst.setdefault(br["exchange_id"], []).append(br)
        acc_a, acc_b = set(sa["accounts"]), set(sb["accounts"])
        shared = acc_a & acc_b
        dropped: dict[str, dict] = {}
        if svc is not None:
            acc_a, acc_b = _hold_to_accounts(r, svc, sa, sb, acc_a - shared, acc_b - shared,
                                             broken, dropped)
        ids_a, ids_b = {sa["owner"]} | (acc_a - shared), {sb["owner"]} | (acc_b - shared)
        ids = sorted(set(ha) | set(hb) | set(ba) | set(bb) | set(wa) | set(wb))
        for eid in ids:
            ex = pair_exchange(eid, ha.get(eid), hb.get(eid), sa["owner"], sb["owner"],
                                ba.get(eid, []), bb.get(eid, []), ids_a, ids_b, shared,
                                dropped, wa.get(eid), wb.get(eid))
            word, why, note = classify(ex, ha.get(eid), hb.get(eid), late_after=late_after)
            ex["disagreement"], ex["disagreement_reason"] = word, why
            if note:
                ex["findings"].append(note)
            if word:
                r["disagreements"][word] += 1
            r["exchanges"].append(ex)
            r["counts"][ex["status"]] += 1
            r["retracted"] += len(ex["retracted"])
            r["withdrawn"] += len(ex["withdrawn"])
        for nm, s in (("a", sa), ("b", sb)):
            heads = {h["row_digest"] for h in (ha if nm == "a" else hb).values()}
            for row in s["_rows"]:
                if row["disputed"]:
                    r["claims"].append({"claim": "DISPUTED", "exchange_id": row["exchange_id"],
                                        "side": nm, "signer": row["signer"],
                                        "reason": row["reason"], "at": row["at"],
                                        "reaction": row["reaction"], "line": row["line"],
                                        "row_digest": row["row_digest"],
                                        "current": row["row_digest"] in heads,
                                        **({"withdrawn": True} if row.get("withdrawn_by")
                                           else {})})
    for s in (sa, sb):
        s.pop("_rows", None)
        s.pop("_seq", None)
    r["findings"] = broken + [f"log {nm}: {s['reason']}" for nm, s in cnl]
    if broken:
        r["verdict"] = V.BROKEN
        r["reason"] = "; ".join(broken)
    elif cnl:
        nm, s = cnl[0]
        r.update({k: s[k] for k in ("looked_for", "where", "reason_word")})
        r["verdict"] = V.COULD_NOT_LOOK
        r["reason"] = "; ".join(f"log {n}: {x['reason']}" for n, x in cnl)
    else:
        r["verdict"] = V.VERIFIED
        c = r["counts"]
        r["reason"] = (f"both chains verify and every reaction row checks under its log's key; "
                       f"{c['clean']} clean, {c['mismatch']} mismatch, {c['not_verified']} "
                       f"not verified, {c['missing']} missing, {len(r['claims'])} DISPUTED "
                       f"claim(s), {r['retracted']} retracted BROKEN"
                       + (f", {r['withdrawn']} withdrawn" if r["withdrawn"] else ""))
    return r


# --- the pair pin statement (dry run only) ---------------------------------------------

#: The `chain` of a pair result's pin statement.
PAIR_PIN_CHAIN = "arcaeon-exchange-pair"
_STATED_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:Z|\+00:00)")


def _stated_at(v: Any) -> str | None:
    """None, or a UTC time in the statement's +00:00 form; ExchangeError otherwise."""
    if v is None:
        return None
    if not isinstance(v, str) or not _STATED_AT.fullmatch(v):
        raise ExchangeError(f"--stated-at must be a UTC time, YYYY-MM-DDTHH:MM:SSZ or "
                            f"+00:00 (got {v!r})")
    try:
        datetime.strptime(v[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        raise ExchangeError(f"--stated-at {v!r} is not a real time") from None
    return v[:19] + "+00:00"


def _prev_pin(v: Any) -> str | None:
    if v is not None and not (isinstance(v, str) and _HEX64.fullmatch(v)):
        raise ExchangeError("--prev-pin-sha256 must be 64 lower-case hex")
    return v


def pair_snapshot(r: dict, log_a: str | Path, log_b: str | Path) -> bytes:
    """The bytes a pair pin commits to: the json-c14n v1 bytes of pair()'s result
    with every spelling of the two log paths replaced by the file's name
    (tally_chain.relativize), so the same logs read from another folder give
    the same bytes. ExchangeError when the result cannot be canonicalized."""
    from arcaeon.prove.tally_chain import relativize
    try:
        return canon_json(relativize(r, [Path(log_a), Path(log_b)]))
    except (ValueError, TypeError) as e:
        raise ExchangeError(f"the pair result cannot be canonicalized ({type(e).__name__}); "
                            f"no statement over it") from None


def pair_pin_statement(r: dict, log_a: str | Path, log_b: str | Path, *,
                       prev_pin_sha256: str | None = None,
                       stated_at: str | None = None) -> dict:
    """The v2 pin statement over one pair result, built by the tally chain's
    builder (tally_chain.statement_v2): chain PAIR_PIN_CHAIN, one row whose
    chain value is sha256(pair_snapshot), file_sha256 over pair_snapshot plus
    one LF. Returns {statement, statement_sha256, pair_sha256}. Builds only:
    nothing is written, sent or pinned. ExchangeError when the pair is COULD
    NOT LOOK (nothing was read to commit to) or an option is malformed."""
    from arcaeon.prove import tally_chain as TC
    prev_pin_sha256, stated_at = _prev_pin(prev_pin_sha256), _stated_at(stated_at)
    if r.get("verdict") not in (V.VERIFIED, V.BROKEN):
        raise ExchangeError(f"the pair reads {r.get('verdict')}: nothing was read to commit "
                            f"to; no statement over it")
    body = pair_snapshot(r, log_a, log_b)
    tip = hashlib.sha256(body).hexdigest()
    st = TC.statement_v2(PAIR_PIN_CHAIN, [tip], body + b"\n",
                         prev_pin_sha256=prev_pin_sha256, stated_at=stated_at)
    return {"statement": st, "statement_sha256": TC.statement_sha256(st), "pair_sha256": tip}


def _write_pin(r: dict, pa: str, pb: str, o: dict) -> int | None:
    """--pin: write the statement file (never overwritten) and say what would be
    pinned, on stderr (stdout stays the pair output). None when written; else
    the exit code to return."""
    from arcaeon.prove.tally_chain import statement_canonical
    try:
        pin = pair_pin_statement(r, pa, pb, prev_pin_sha256=o.get("--prev-pin-sha256"),
                                 stated_at=o.get("--stated-at"))
    except ExchangeError as e:
        print(f"arcaeon exchange pair --pin: {e}; no statement written", file=sys.stderr)
        return V.exit_for(r["verdict"]) if r.get("verdict") == V.COULD_NOT_LOOK \
            else V.EXIT_USAGE
    text = statement_canonical(pin["statement"])
    name = Path(o["--pin"]).name
    try:
        with open(o["--pin"], "xb") as fh:
            fh.write(text.encode("utf-8"))
    except FileExistsError:
        print(f"arcaeon exchange pair --pin: {name} exists; a statement file is never "
              f"overwritten", file=sys.stderr)
        return V.EXIT_USAGE
    except OSError as e:
        print(f"arcaeon exchange pair --pin: cannot write {name} ({type(e).__name__})",
              file=sys.stderr)
        return V.EXIT_USAGE
    print(f"dry run: wrote the pin statement {name}, sha256 {pin['statement_sha256']}, over "
          f"the pair result (pair_sha256 {pin['pair_sha256']}, chain {PAIR_PIN_CHAIN}); "
          f"nothing was pinned and no witness was contacted. Would pin: {text}",
          file=sys.stderr)
    return None


# --- CLI --------------------------------------------------------------------------------

USAGE = """usage: arcaeon exchange react --exchange ID --counterparty ID --file PATH
                              --reaction {VERIFIED,BROKEN,"COULD NOT LOOK"}
                              --key SEEDFILE [--disputed REASON]
                              [--supersedes ROWDIGEST] [--log PATH]
       arcaeon exchange bind --account acct:NAME@arcaeon.io --key SEEDFILE
                              [--log PATH]
       arcaeon exchange withdraw --row ROWDIGEST --key SEEDFILE
                              [--reason TEXT] [--log PATH]
       arcaeon exchange pair A.jsonl B.jsonl [--owner-a DID] [--owner-b DID]
                              [--json] [--strict]
                              [--accounts FILE --account-key DID...]
                              [--late-after SECONDS]
                              [--pin FILE [--stated-at T]
                              [--prev-pin-sha256 HEX]]
       arcaeon exchange packet A.jsonl B.jsonl --exchange ID
                              [--owner-a DID] [--owner-b DID]
                              [--late-after SECONDS] [--json] [--out DIR]"""

HELP = USAGE + """

react appends one signed row (kind exchange.reaction) to your own hash-chained
log (--log, default exchange.jsonl): the exchange id, the other party's ID
(their did:key, or their arcaeon.io account id acct:NAME@arcaeon.io, stored
as given and never looked up), the file's sha256, your reaction in the verifier's three words, the
UTC time and your did:key, signed with Ed25519 by --key (a 32-byte seed,
base64, one line; needs arcaeon[sign]). --disputed REASON adds a signed
DISPUTED claim with a reason; it is a claim, never a verdict. A change is a
new row: --supersedes names the old row's digest. Rows are never edited.

pair reads two logs, verifies each chain and every row's signature against
the log's key (--owner-a / --owner-b, else the first row's signer; a named
owner that is not the signer of the log's first good row refuses that log,
BROKEN, and no exchange is lined up), takes the
latest non-superseded row per party per exchange and reports each exchange:
clean (both VERIFIED, same sha256, each names the other), mismatch (names the
field), not_verified (both said the same other word), missing (one side
absent), broken (a row for it is BROKEN). DISPUTED claims are listed apart.
A BROKEN later superseded by another word is listed as retracted, never
erased.

withdraw appends one signed row (kind exchange.withdraw) to your own log: it
takes your current reaction row --row (its digest) back entirely. The
withdrawn row stays; the withdraw row is signed by the same key. It cannot be
withdrawn or superseded; to react again, write a new row (no --supersedes).
A withdraw signed by any other key, or naming a row that is not this log's
current reaction, is a BROKEN row. pair lists it as withdrawn.

Each exchange that disagrees also carries one class word, with a one-sentence
reason (precedence in this order): missing (one log has no record of it),
mismatched (both have it, a field differs; the reason names it), withdrawn (a
side took its reaction back by a withdraw row; status missing when it has no
current row), retracted (a side superseded an earlier BROKEN for it), late (both agree, but one row's
`at` trails the other's by more than --late-after SECONDS, default 86400: one
day). An agreeing exchange carries none; a broken one carries none (its record
does not check). The counts are under `disagreements` and on the first line.

pair --pin FILE writes a v2 pin statement over the pair result (the tally
chain's statement builder; chain arcaeon-exchange-pair, one row: the sha256
of the result's json-c14n bytes with log paths replaced by file names) to
FILE, never overwriting one, and prints what would be pinned on stderr. A
dry run only: no witness is contacted, nothing is sent. --stated-at T fixes
the statement's time (default now), --prev-pin-sha256 HEX chains it to an
earlier one. A pair that is COULD NOT LOOK gets no statement.

packet reads both logs (the same reader as pair) and writes one exchange's
dispute packet: both sides' rows, the status, the class word and the field
that differs, DISPUTED claims, and the limits. File names only. Markdown by
default, --json for the JSON, --out DIR writes dispute-packet.md and .json.
Exit 0 written, 2 bad usage or nothing to dispute (the exchange agrees), 3
COULD NOT LOOK (a log cannot be read, or the exchange is in neither log).

bind appends one signed row (kind exchange.binding) to the key's own log:
this did:key binds the account id acct:NAME@arcaeon.io. An account id pairs
ONLY through such a row in the other party's log, signed by that log's key; a
binding signed by any other key is a BROKEN row. Without one (or when both
logs bind the same account) a row naming the account reads mismatch on
counterparty, and which key it binds is COULD NOT LOOK here. The binding is
the key holder's claim; arcaeon.io's own record is not consulted unless pair
gets --accounts FILE (an account store or binding statements) and
--account-key DID (the binding key you trust; repeatable): then each binding
is held to the account service at the row's time and at the newest reaction
row the key signed. Confirmed pairs; revoked or rotated out by either time, or
another owner, is BROKEN; no record is COULD NOT LOOK (both unpaired).

Exit codes: react 0 written, 2 refused or bad usage, 3 the file is not there.
bind 0 written, 2 refused or bad usage. withdraw 0 written, 2 refused or bad
usage.
pair 0 VERIFIED (both logs check; read the statuses), 1 BROKEN, 3 COULD NOT
LOOK, 2 bad usage. pair --strict: also 1 when both logs check but any
exchange is mismatch or missing (not_verified stays 0; 3 and 2 unchanged).
late and retracted are not marks under --strict: both sides agree on the
current record. A withdrawal with no current row is status missing, so
--strict marks it; a withdrawal followed by a new agreeing row is not marked. Spec and limits: docs/EXCHANGE.md."""


class _Usage(Exception):
    pass


_REACT_SPEC = {"--exchange": "value", "--counterparty": "value", "--file": "value",
               "--reaction": "value", "--disputed": "value", "--supersedes": "value",
               "--key": "value", "--log": "value"}
_BIND_SPEC = {"--account": "value", "--key": "value", "--log": "value"}
_WITHDRAW_SPEC = {"--row": "value", "--key": "value", "--reason": "value", "--log": "value"}
_PAIR_SPEC = {"--owner-a": "value", "--owner-b": "value", "--json": "bool",
              "--strict": "bool", "--accounts": "value", "--account-key": "list",
              "--late-after": "value", "--pin": "value", "--stated-at": "value",
              "--prev-pin-sha256": "value"}
_PACKET_SPEC = {"--exchange": "value", "--owner-a": "value", "--owner-b": "value",
                "--late-after": "value", "--json": "bool", "--out": "value"}


def _late_flag(o: dict) -> int:
    v = o.get("--late-after")
    if v is None:
        return DEFAULT_LATE_AFTER
    if not re.fullmatch(r"[0-9]{1,12}", v):
        raise _Usage(f"--late-after must be a whole number of seconds, 0 or more (got {v!r})")
    return int(v)


def _react_cli(argv: list[str]) -> int:
    from arcaeon.prove.envelope import _parse, _Usage as _EUsage
    try:
        pos, o = _parse(argv, _REACT_SPEC)
    except _EUsage as e:
        raise _Usage(str(e)) from None
    if pos:
        raise _Usage(f"react takes no positional argument (got {pos[0]!r})")
    need = [k for k in ("--exchange", "--counterparty", "--file", "--reaction", "--key")
            if k not in o]
    if need:
        raise _Usage("react needs " + ", ".join(need))
    target = Path(o["--file"])
    if not target.is_file():
        why = "it does not exist" if not target.exists() else "it is not a regular file"
        cnl = V.could_not_look("the file reacted to", o["--file"],
                               "missing" if not target.exists() else "unreadable",
                               f"cannot react to {o['--file']}: {why}")
        print(json.dumps({"ok": False, "verdict": V.COULD_NOT_LOOK, **cnl}, indent=1))
        print(f"{V.COULD_NOT_LOOK}: cannot react to {o['--file']}: {why}; nothing was written",
              file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK
    try:
        out = react(o.get("--log", DEFAULT_LOG), key_file=o["--key"],
                    exchange_id=o["--exchange"], counterparty=o["--counterparty"],
                    file=target, reaction=o["--reaction"], disputed=o.get("--disputed"),
                    supersedes=o.get("--supersedes"))
    except ExchangeError as e:
        print(f"arcaeon exchange react: {e}; nothing was written", file=sys.stderr)
        return V.EXIT_USAGE
    print(json.dumps({"ok": True, **out}, indent=1, ensure_ascii=True))
    return V.EXIT_GOOD


def _bind_cli(argv: list[str]) -> int:
    from arcaeon.prove.envelope import _parse, _Usage as _EUsage
    try:
        pos, o = _parse(argv, _BIND_SPEC)
    except _EUsage as e:
        raise _Usage(str(e)) from None
    if pos:
        raise _Usage(f"bind takes no positional argument (got {pos[0]!r})")
    need = [k for k in ("--account", "--key") if k not in o]
    if need:
        raise _Usage("bind needs " + ", ".join(need))
    try:
        out = bind(o.get("--log", DEFAULT_LOG), key_file=o["--key"], account=o["--account"])
    except ExchangeError as e:
        print(f"arcaeon exchange bind: {e}; nothing was written", file=sys.stderr)
        return V.EXIT_USAGE
    print(json.dumps({"ok": True, **out}, indent=1, ensure_ascii=True))
    return V.EXIT_GOOD


def _withdraw_cli(argv: list[str]) -> int:
    from arcaeon.prove.envelope import _parse, _Usage as _EUsage
    try:
        pos, o = _parse(argv, _WITHDRAW_SPEC)
    except _EUsage as e:
        raise _Usage(str(e)) from None
    if pos:
        raise _Usage(f"withdraw takes no positional argument (got {pos[0]!r})")
    need = [k for k in ("--row", "--key") if k not in o]
    if need:
        raise _Usage("withdraw needs " + ", ".join(need))
    try:
        out = withdraw(o.get("--log", DEFAULT_LOG), key_file=o["--key"], row=o["--row"],
                       reason=o.get("--reason"))
    except ExchangeError as e:
        print(f"arcaeon exchange withdraw: {e}; nothing was written", file=sys.stderr)
        return V.EXIT_USAGE
    print(json.dumps({"ok": True, **out}, indent=1, ensure_ascii=True))
    return V.EXIT_GOOD


def _render(r: dict) -> str:
    d = r.get("disagreements") or {}
    first = f"{r['verdict']}: {r['reason']}"
    if r.get("verdict") == V.VERIFIED and d:
        first += "; disagreements: " + ", ".join(f"{d.get(w, 0)} {w}" for w in DISAGREEMENTS)
    lines = [first]
    for nm, s in r.get("logs", {}).items():
        lines.append(f"log {nm}: {s.get('verdict')} {s.get('log')} owner {s.get('owner')} "
                     f"({s.get('owner_from')})"
                     + (f" binds {', '.join(s['accounts'])}" if s.get("accounts") else ""))
        for br in s.get("broken_rows", []):
            lines.append(f"  BROKEN row line {br['line']}: {br['finding']}")
    for ex in r.get("exchanges", []):
        tail = "; ".join(ex["findings"])
        cls = (f" [{ex['disagreement']}: {ex['disagreement_reason']}]"
               if ex.get("disagreement") else "")
        lines.append(f"{ex['exchange_id']}: {ex['status']}{cls}" + (f" ({tail})" if tail else ""))
    for c in r.get("claims", []):
        lines.append(f"claim DISPUTED by {c['side']} on {c['exchange_id']} at {c['at']}"
                     f"{'' if c['current'] else ' (withdrawn)' if c.get('withdrawn') else ' (superseded)'}"
                     f": {c['reason']}")
    svc = r.get("account_service") or {}
    if svc.get("consulted"):
        lines.append(f"account service: {svc['reason']}")
    for b in svc.get("bindings", []):
        lines.append(f"account service {b['verdict']} {b['account']} -> {b['key']}: {b['reason']}")
    if svc and not svc.get("consulted") and any(s.get("accounts") for s in r.get("logs", {}).values()):
        lines.append(svc["reason"])
    return "\n".join(lines)


def _pair_cli(argv: list[str]) -> int:
    from arcaeon.prove.envelope import _parse, _Usage as _EUsage
    try:
        pos, o = _parse(argv, _PAIR_SPEC)
    except _EUsage as e:
        raise _Usage(str(e)) from None
    if len(pos) != 2:
        raise _Usage("pair takes two logs: A.jsonl B.jsonl")
    for flag in ("--owner-a", "--owner-b"):
        if flag in o and not is_did(o[flag]):
            raise _Usage(f"{flag} must be an Ed25519 did:key")
    if ("--accounts" in o) != ("--account-key" in o):
        raise _Usage("--accounts and --account-key go together")
    late_after = _late_flag(o)
    for flag in ("--stated-at", "--prev-pin-sha256"):
        if flag in o and "--pin" not in o:
            raise _Usage(f"{flag} goes with --pin FILE")
    try:
        _stated_at(o.get("--stated-at"))
        _prev_pin(o.get("--prev-pin-sha256"))
    except ExchangeError as e:
        raise _Usage(str(e)) from None
    r = pair(pos[0], pos[1], owner_a=o.get("--owner-a"), owner_b=o.get("--owner-b"),
             accounts=o.get("--accounts"), account_keys=o.get("--account-key", ()),
             late_after=late_after)
    if o.get("--json"):
        print(json.dumps(r, indent=1, ensure_ascii=True))     # F11: a lone surrogate prints
    else:
        print(_render(r).encode("utf-8", "backslashreplace").decode("utf-8"))
    code = V.exit_for(r["verdict"])
    if "--pin" in o:
        refused = _write_pin(r, pos[0], pos[1], o)
        if refused is not None:
            return refused
    marks = r["counts"]["mismatch"] + r["counts"]["missing"]
    if o.get("--strict") and code == V.EXIT_GOOD and marks:
        print(f"arcaeon exchange pair --strict: {r['counts']['mismatch']} mismatch, "
              f"{r['counts']['missing']} missing; exit {V.EXIT_BAD}", file=sys.stderr)
        return V.EXIT_BAD
    return code


def _packet_cli(argv: list[str]) -> int:
    from arcaeon.prove import dispute_packet as P
    from arcaeon.prove.envelope import _parse, _Usage as _EUsage
    try:
        pos, o = _parse(argv, _PACKET_SPEC)
    except _EUsage as e:
        raise _Usage(str(e)) from None
    if len(pos) != 2:
        raise _Usage("packet takes two logs: A.jsonl B.jsonl")
    if not o.get("--exchange"):
        raise _Usage("packet needs --exchange ID")
    for flag in ("--owner-a", "--owner-b"):
        if flag in o and not is_did(o[flag]):
            raise _Usage(f"{flag} must be an Ed25519 did:key")
    late_after = _late_flag(o)
    try:
        p = P.from_pair(pos[0], pos[1], o["--exchange"], owner_a=o.get("--owner-a"),
                        owner_b=o.get("--owner-b"), late_after=late_after)
    except P.NothingToDispute as e:
        print(f"arcaeon exchange packet: {e}", file=sys.stderr)
        return V.EXIT_USAGE
    except P.PacketError as e:
        print(f"arcaeon exchange packet: {V.COULD_NOT_LOOK}: {e}", file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK
    md, js = P.render_markdown(p), P.render_json(p)
    if o.get("--out"):
        out = Path(o["--out"])
        out.mkdir(parents=True, exist_ok=True)
        for name, text in (("dispute-packet.md", md), ("dispute-packet.json", js)):
            (out / name).write_text(text, encoding="utf-8", newline="\n")
            print(out / name)
    else:
        text = js if o.get("--json") else md
        sys.stdout.write(text.encode("utf-8", "backslashreplace").decode("utf-8"))
    return V.EXIT_GOOD


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help") or any(a in ("-h", "--help") for a in argv):
        print(HELP)
        return V.EXIT_GOOD if argv else V.EXIT_USAGE
    sub, rest = argv[0], argv[1:]
    try:
        if sub == "react":
            return _react_cli(rest)
        if sub == "pair":
            return _pair_cli(rest)
        if sub == "bind":
            return _bind_cli(rest)
        if sub == "packet":
            return _packet_cli(rest)
        if sub == "withdraw":
            return _withdraw_cli(rest)
        raise _Usage(f"unknown subcommand {sub!r} (react, bind, withdraw, pair or packet)")
    except _Usage as e:
        print(f"arcaeon exchange: {e}\n{USAGE}", file=sys.stderr)
        return V.EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
