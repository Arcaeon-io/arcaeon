# SPDX-License-Identifier: MIT
"""arcaeon.prove.account_id: account-as-ID, a reference stub (TE-41 machine path).

The ID is the arcaeon.io account. A human owner (signed up on the site; that
step is out of scope here) issues machine keys for its agents by an API call;
an agent never signs itself up and never issues a key. The design, with the
endpoints, the auth model and the limits, is docs/ACCOUNT_ID_API.md.

    issue(store, caller, agent=NAME, proof=ROW, server_seed=SEED)  -> binding row
    rotate(store, caller, ACCOUNT, proof=ROW, server_seed=SEED)    -> binding row
    revoke(store, caller, ACCOUNT, server_seed=SEED, reason=TEXT)  -> binding row
    attach_external(store, caller, ACCOUNT, receipt=DICT, server_seed=SEED)
    list_agents(store, caller)                                     -> [summary]
    binding_statement(store, DID)                                  -> statement | None
    verify_binding(statement, DID, server_keys=[DID], at=, now=)   -> report
    load_service(STORE|STATEMENTS|PATH, server_keys=[DID])         -> (service, why)
    consult_binding(service, DID, ACCOUNT, [exchange.binding rows]) -> report

THE EXCHANGE PAIRING (L3-02, D077). `arcaeon exchange pair` and `arcaeon
tally build` pair an account id only through the key's own exchange.binding
row. Given an account service (--accounts FILE, --account-key DID), each such
pairing is held to it at the binding row's time AND at the newest reaction
row the key signed in the logs read (R2): confirmed at both is VERIFIED (the
pairing stands, for every reaction row from the binding row's time through
that newest one); revoked or rotated out by either time, bound to another owner or
account, or a service row that does not verify is BROKEN (the pairing is
dropped, the report reads BROKEN); no record, or no trusted key, is COULD NOT
LOOK (the pairing is dropped). Without one, nothing changes.

KEYS ARE MADE ON THE AGENT'S SIDE. The agent generates its own Ed25519 seed
and signs a possession proof: an `exchange.binding` row (docs/EXCHANGE.md)
naming its account, acct:AGENT.OWNER@arcaeon.io. The server checks that
proof and signs an `account.binding` row over it. The server never sees or
holds an agent private key.

THE ROW (kind "account.binding", v 1). Every field below is signed, null
where an event does not use it:

  {"kind", "v", "event", "account", "owner", "key", "prev", "at", "signer",
   "agent_proof", "external", "reason"} + "sig"

  event        issue | rotate | revoke | external
  prev         null on the first row, else the digest of the account's
               previous row: one hash-linked history per account (TE-44d:
               a new key inherits the record; the history cannot be reset)
  signer       the server's binding key (a did:key the verifier names)
  sig          Ed25519 by signer over PAE(PAYLOAD_TYPE, canon_json(signed))

VERIFY answers in the usual three words and never raises:
  VERIFIED        every row is signed by a server key you named, the history
                  links, the agent proofs check, and the key was bound to the
                  account at the time asked about.
  BROKEN          a signature, a link or a proof does not check; or the key
                  was revoked or rotated out at or before the time asked about.
  COULD NOT LOOK  no statement, a statement about another key, a key that is
                  not an Ed25519 did:key (length checked before any decode),
                  no trusted server key named, or a time before the binding.

stdlib only, plus the [sign] extra's Ed25519 backend that envelope.py and
exchange_log.py already use. No network, no CLI verb, no real keys.
"""
from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from arcaeon import verdict as V
from arcaeon.prove import envelope as _env
from arcaeon.prove import exchange_log as X
from arcaeon.record.row import canon_json, digest_json

__all__ = ["BIND_KIND", "PAYLOAD_TYPE", "STATEMENT_TYPE", "ROW_VERSION", "SIGNED", "EVENTS",
           "OWNER_CALLERS", "ISSUER_FAMILIES", "BINDING_STRENGTHS", "RECEIPT_FIELDS",
           "MAX_AGENTS_PER_OWNER", "PROOF_MAX_AGE", "AccountError", "new_store",
           "load_store", "save_store", "agent_account", "possession_proof", "jwk_thumbprint",
           "row_digest", "issue", "rotate", "revoke", "attach_external", "list_agents",
           "binding_statement", "control_cluster", "verify_binding", "handle",
           "NOT_CONSULTED", "load_service", "consult_binding", "log_binding_rows",
           "log_reaction_rows", "consult_pairings", "service_report"]

BIND_KIND = "account.binding"
PAYLOAD_TYPE = "application/vnd.arcaeon.account.binding.v1+json"
STATEMENT_TYPE = "https://arcaeon.io/account-binding-statement/v1"
ROW_VERSION = 1
SIGNED = ("kind", "v", "event", "account", "owner", "key", "prev", "at", "signer",
          "agent_proof", "external", "reason")
EVENTS = ("issue", "rotate", "revoke", "external")
#: Who may issue, rotate, revoke and attach: the owner, by its site session or
#: an owner API key. An agent key is never on this list.
OWNER_CALLERS = ("owner_session", "owner_api_key")
ISSUER_FAMILIES = ("entra", "okta", "aws-sts", "spiffe", "sigstore")
#: Strongest first: the IdP signed our key's thumbprint (cnf), the IdP carried
#: it as a tag, or only the agent's own possession signature tied them.
BINDING_STRENGTHS = ("idp-cnf", "idp-tag", "possession-sig")
RECEIPT_FIELDS = ("issuer_family", "iss", "sub", "facets", "key_jkt", "jwt_sha256",
                  "jwk_sha256", "binding_strength", "checked_at")
#: Accounts one owner may hold, revoked ones included (a revoke does not free a
#: slot, or churn would reset the count). A stub default, not a price.
MAX_AGENTS_PER_OWNER = 100
#: A possession proof older than this (or this far in the future) is refused.
PROOF_MAX_AGE = timedelta(minutes=15)
MAX_STORE_BYTES = 64 << 20
_MAX_PATH = 512
_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_B64URL = re.compile(r"[A-Za-z0-9_-]{43}")

PROVES = ("the arcaeon.io binding key signed that this did:key was bound to this agent "
          "account, under this owner, from one time to another, and the agent's own key "
          "signed that it holds the key")
DOES_NOT_PROVE = ("that the owner is who the account name suggests, that the agent behaves, "
                  "that a seal time inside an envelope is true (the signer writes it), or "
                  "that an external identity is still alive now")


class AccountError(ValueError):
    """A refusal, with the HTTP status the thin handler answers with."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


# --- small pieces ----------------------------------------------------------------------

def _utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(_TS_FMT)


def _when(at: datetime | None) -> datetime:
    return (at or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)


def _parse(ts: Any) -> datetime | None:
    if not isinstance(ts, str):
        return None
    try:
        return datetime.strptime(ts, _TS_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _did_shape_ok(did: Any) -> bool:
    """The cheap check, before any decode: a hostile length never reaches base58."""
    return (isinstance(did, str) and len(did) == _env.DID_KEY_ED25519_LEN
            and did.startswith("did:key:z"))


def _pub(did: Any) -> bytes | None:
    if not _did_shape_ok(did):
        return None
    try:
        return _env._pubkey_from_did(did)
    except (ValueError, TypeError):
        return None


def _receipts():
    from arcaeon.prove.vet import receipts as R
    return R


def jwk_thumbprint(did: str) -> str | None:
    """RFC 7638 SHA-256 thumbprint of the did:key's Ed25519 key as an OKP JWK
    (the `jkt` an IdP puts in `cnf`), base64url without padding; None if not a key."""
    pub = _pub(did)
    if pub is None:
        return None
    x = base64.urlsafe_b64encode(pub).rstrip(b"=").decode("ascii")
    jwk = json.dumps({"crv": "Ed25519", "kty": "OKP", "x": x}, separators=(",", ":"),
                     sort_keys=True).encode("ascii")
    return base64.urlsafe_b64encode(hashlib.sha256(jwk).digest()).rstrip(b"=").decode("ascii")


def row_digest(row: dict) -> str:
    """What the next row's `prev` names: digest_json of the signed fields plus sig."""
    return digest_json({k: row.get(k) for k in SIGNED + ("sig",)})


def _signing_bytes(row: dict) -> bytes:
    return _env.pae(PAYLOAD_TYPE, canon_json({k: row[k] for k in SIGNED}))


def _sign_row(row: dict, server_seed: bytes) -> dict:
    if not isinstance(server_seed, (bytes, bytearray)) or len(server_seed) != 32:
        raise AccountError(500, "the server binding key is not a 32-byte Ed25519 seed")
    R = _receipts()
    row["signer"] = R.did_key(R.public_key_from_seed(bytes(server_seed)))
    row["sig"] = base64.b64encode(R._sign_bytes(bytes(server_seed),
                                                _signing_bytes(row))).decode("ascii")
    return row


# --- the store (in memory, optionally a JSON file) ----------------------------------------

def new_store() -> dict:
    """An empty store: accounts by id (owner + hash-linked rows), keys by did."""
    return {"version": 1, "accounts": {}, "keys": {}}


def load_store(path: str | Path) -> dict:
    p = Path(path)
    if not p.exists():
        return new_store()
    if p.stat().st_size > MAX_STORE_BYTES:
        raise AccountError(500, "the store file is over the size cap")
    data = json.loads(p.read_text(encoding="utf-8"))
    if not (isinstance(data, dict) and isinstance(data.get("accounts"), dict)
            and isinstance(data.get("keys"), dict)):
        raise AccountError(500, "the store file is not an account store")
    return data


def save_store(store: dict, path: str | Path) -> None:
    p = Path(path)
    tmp = p.with_name(p.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps(store, indent=1, sort_keys=True) + "\n")
    os.replace(tmp, p)


# --- names and auth --------------------------------------------------------------------

def _owner_name(owner: Any) -> str:
    m = X.ACCOUNT_ID_RE.fullmatch(owner) if isinstance(owner, str) else None
    if not m or "." in m.group("name"):
        raise AccountError(400, f"the owner is not a single-label {X.ACCOUNT_ID_FORM}")
    return m.group("name")


def agent_account(agent: Any, owner: str) -> str:
    """acct:AGENT.OWNER@arcaeon.io: the agent's account id, under its owner."""
    name = _owner_name(owner)
    if not isinstance(agent, str) or not _LABEL.fullmatch(agent):
        raise AccountError(400, "the agent name is not one label (a-z, 0-9, '-')")
    full = f"{agent}.{name}"
    if len(full) > X.ACCOUNT_NAME_MAX:
        raise AccountError(400, f"the agent account name is over {X.ACCOUNT_NAME_MAX} chars")
    return f"acct:{full}@arcaeon.io"


def _caller_owner(caller: Any) -> str:
    if isinstance(caller, dict) and caller.get("kind") == "agent_key":
        raise AccountError(403, "an agent key cannot issue, rotate, revoke or attach: "
                                "its human owner does, by session or owner API key")
    if not isinstance(caller, dict) or caller.get("kind") not in OWNER_CALLERS:
        raise AccountError(401, "no owner session or owner API key")
    _owner_name(caller.get("owner"))
    return caller["owner"]


def _owned(store: dict, owner: str, account: Any) -> dict:
    rec = store["accounts"].get(account) if isinstance(account, str) else None
    if rec is None or rec.get("owner") != owner:
        raise AccountError(404, "no such agent account under this owner")
    return rec


def _check_proof(proof: Any, account: str, now: datetime) -> str:
    """The agent's possession proof (an exchange.binding row): its did, or refuse."""
    if not isinstance(proof, dict):
        raise AccountError(400, "the possession proof is not a JSON object")
    if not _did_shape_ok(proof.get("signer")):
        raise AccountError(400, "the proof signer is not an Ed25519 did:key "
                                "(length checked before decoding)")
    problem = X.check_binding(proof)
    if problem:
        raise AccountError(400, f"the possession proof does not check: {problem}")
    if proof["account"] != account:
        raise AccountError(400, f"the possession proof names {proof['account']}, not {account}")
    t = _parse(proof["at"])
    if t is None or abs(now - t) > PROOF_MAX_AGE:
        raise AccountError(400, "the possession proof is stale or dated in the future")
    return proof["signer"]


def possession_proof(seed: bytes, account: str, at: datetime | None = None) -> dict:
    """AGENT SIDE: the agent signs, with its own seed, that its key binds `account`.
    The seed never leaves the agent; only the returned row is sent."""
    try:
        return X.build_binding(seed=seed, account=account, at=at)
    except X.ExchangeError as e:
        raise AccountError(400, str(e)) from None


# --- account state ---------------------------------------------------------------------

def _windows(rows: list) -> list:
    """[(did, bound_at, retired_at | None, retired_by | None)] in order."""
    out: list = []
    for r in rows:
        if r["event"] in ("issue", "rotate"):
            if out and out[-1][2] is None:
                out[-1] = (out[-1][0], out[-1][1], r["at"], "rotate")
            out.append((r["key"], r["at"], None, None))
        elif r["event"] == "revoke" and out and out[-1][2] is None:
            out[-1] = (out[-1][0], out[-1][1], r["at"], "revoke")
    return out


def _active_key(rec: dict) -> str | None:
    w = _windows(rec["rows"])
    return w[-1][0] if w and w[-1][2] is None else None


def _append(store: dict, account: str, owner: str, row: dict) -> dict:
    rec = store["accounts"].setdefault(account, {"owner": owner, "rows": []})
    rec["rows"].append(row)
    if row["event"] in ("issue", "rotate"):
        store["keys"][row["key"]] = account
    return copy.deepcopy(row)


def _row(event: str, account: str, owner: str, key: str | None, prev: str | None,
         at: datetime, **extra) -> dict:
    row = {"kind": BIND_KIND, "v": ROW_VERSION, "event": event, "account": account,
           "owner": owner, "key": key, "prev": prev, "at": _utc(at), "signer": None,
           "agent_proof": None, "external": None, "reason": None}
    row.update(extra)
    return row


# --- the operations --------------------------------------------------------------------

def issue(store: dict, caller: Any, *, agent: str, proof: Any, server_seed: bytes,
          at: datetime | None = None, max_agents: int = MAX_AGENTS_PER_OWNER) -> dict:
    """Bind the agent's key to acct:AGENT.OWNER@arcaeon.io. An exact repeat
    (same account, same key, still active) returns the existing row and writes
    nothing; the same name with another key, or a key bound anywhere before, is
    refused (409): a new key on an existing account is `rotate`."""
    owner = _caller_owner(caller)
    account = agent_account(agent, owner)
    now = _when(at)
    if not isinstance(proof, dict) or not _did_shape_ok(proof.get("signer")):
        _check_proof(proof, account, now)          # raises the precise 400
    did = proof["signer"]
    rec = store["accounts"].get(account)
    if rec is not None:
        if rec["owner"] == owner and _active_key(rec) == did and \
                store["keys"].get(did) == account:
            bound = [r for r in rec["rows"] if r["key"] == did and r["event"] in ("issue", "rotate")]
            if bound and bound[-1]["agent_proof"] == proof:
                return copy.deepcopy(bound[-1])
        raise AccountError(409, f"{account} already exists; a new key on it is a rotate "
                                f"(its history cannot be reset)")
    _check_proof(proof, account, now)
    if did in store["keys"]:
        raise AccountError(409, "this key is already bound to an account; a key is bound once")
    held = sum(1 for r in store["accounts"].values() if r.get("owner") == owner)
    if held >= max_agents:
        raise AccountError(429, f"this owner holds {held} agent accounts, the cap is "
                                f"{max_agents} (revoked accounts count)")
    row = _sign_row(_row("issue", account, owner, did, None, now,
                         agent_proof=copy.deepcopy(proof)), server_seed)
    return _append(store, account, owner, row)


def rotate(store: dict, caller: Any, account: str, *, proof: Any, server_seed: bytes,
           at: datetime | None = None) -> dict:
    """A new agent key on the same account: the old key (if still active) is
    retired at this row's time, the owner and the whole history carry over."""
    owner = _caller_owner(caller)
    rec = _owned(store, owner, account)
    now = _when(at)
    did = _check_proof(proof, account, now)
    if did in store["keys"]:
        raise AccountError(409, "this key is already bound to an account; a key is bound once")
    row = _sign_row(_row("rotate", account, owner, did, row_digest(rec["rows"][-1]), now,
                         agent_proof=copy.deepcopy(proof)), server_seed)
    return _append(store, account, owner, row)


def revoke(store: dict, caller: Any, account: str, *, server_seed: bytes,
           at: datetime | None = None, reason: str | None = None) -> dict:
    """Revoke the account's active key at this time. The account and its
    history stay; envelopes the key sealed after this time read BROKEN."""
    owner = _caller_owner(caller)
    rec = _owned(store, owner, account)
    key = _active_key(rec)
    if key is None:
        raise AccountError(409, f"{account} has no active key to revoke")
    if reason is not None and not _env._text_ok(reason, 256):
        raise AccountError(400, "reason is not one line of text (at most 256 chars)")
    row = _sign_row(_row("revoke", account, owner, key, row_digest(rec["rows"][-1]),
                         _when(at), reason=reason), server_seed)
    return _append(store, account, owner, row)


def _check_receipt(receipt: Any) -> dict:
    if not isinstance(receipt, dict):
        raise AccountError(400, "the receipt is not a JSON object")
    extra = sorted(set(receipt) - set(RECEIPT_FIELDS))
    if extra:
        raise AccountError(400, f"the receipt carries field(s) outside the receipt shape "
                                f"({len(extra)}); a raw IdP token is never stored, send "
                                f"its sha256 as jwt_sha256")
    missing = [k for k in RECEIPT_FIELDS if k not in receipt]
    if missing:
        raise AccountError(400, f"the receipt is missing {', '.join(missing)}")
    r = receipt
    if r["issuer_family"] not in ISSUER_FAMILIES:
        raise AccountError(400, f"issuer_family is not one of {', '.join(ISSUER_FAMILIES)}")
    if r["binding_strength"] not in BINDING_STRENGTHS:
        raise AccountError(400, f"binding_strength is not one of {', '.join(BINDING_STRENGTHS)}")
    for k in ("jwt_sha256", "jwk_sha256"):
        if not (isinstance(r[k], str) and _HEX64.fullmatch(r[k])):
            raise AccountError(400, f"{k} is not 64 lower-case hex digits")
    if not (_env._text_ok(r["iss"], 512) and r["iss"].startswith("https://")):
        raise AccountError(400, "iss is not an https issuer")
    if not _env._text_ok(r["sub"], 256):
        raise AccountError(400, "sub is not one line of text")
    if not (isinstance(r["facets"], list) and len(r["facets"]) <= 16
            and all(_env._text_ok(f, 32) for f in r["facets"])):
        raise AccountError(400, "facets is not a short list of short text")
    if r["key_jkt"] is not None and not (isinstance(r["key_jkt"], str)
                                         and _B64URL.fullmatch(r["key_jkt"])):
        raise AccountError(400, "key_jkt is not a base64url SHA-256 thumbprint")
    if r["binding_strength"] != "possession-sig" and r["key_jkt"] is None:
        raise AccountError(400, "an idp-cnf or idp-tag binding needs key_jkt")
    if _parse(r["checked_at"]) is None:
        raise AccountError(400, "checked_at is not a UTC time")
    return copy.deepcopy(r)


def attach_external(store: dict, caller: Any, account: str, *, receipt: Any,
                    server_seed: bytes, at: datetime | None = None) -> dict:
    """Record an outside identity (Entra / Okta / AWS STS / SPIFFE / Sigstore)
    as a BOUND receipt on the account, never a rival ID. The IdP token was
    checked upstream; only its hash and the checked claims arrive here."""
    owner = _caller_owner(caller)
    rec = _owned(store, owner, account)
    clean = _check_receipt(receipt)
    key = _active_key(rec)
    if key is None:
        raise AccountError(409, f"{account} has no active key to bind an identity to")
    if clean["key_jkt"] is not None and clean["key_jkt"] != jwk_thumbprint(key):
        raise AccountError(400, "key_jkt is not the thumbprint of the account's active key")
    row = _sign_row(_row("external", account, owner, key, row_digest(rec["rows"][-1]),
                         _when(at), external=clean), server_seed)
    return _append(store, account, owner, row)


def list_agents(store: dict, caller: Any) -> list:
    """The caller-owner's agent accounts, one summary each."""
    owner = _caller_owner(caller)
    out = []
    for account, rec in sorted(store["accounts"].items()):
        if rec.get("owner") != owner:
            continue
        w = _windows(rec["rows"])
        last = w[-1] if w else (None, None, None, None)
        out.append({"account": account, "owner": owner, "key": last[0],
                    "status": "active" if last[0] and last[2] is None else "revoked",
                    "bound_at": last[1], "revoked_at": last[2], "history": len(rec["rows"])})
    return out


def binding_statement(store: dict, did: Any) -> dict | None:
    """PUBLIC: the account history that binds `did`, or None. Anyone may fetch it."""
    if not _did_shape_ok(did):
        return None
    account = store["keys"].get(did)
    rec = store["accounts"].get(account) if account else None
    if rec is None:
        return None
    return {"type": STATEMENT_TYPE, "did": did, "account": account, "owner": rec["owner"],
            "rows": copy.deepcopy(rec["rows"])}


def control_cluster(store: dict, ident: Any) -> str | None:
    """The minimum control cluster for Sybil counting: the owner account. A
    tally counts exchanges between two IDs of one cluster as self-trades."""
    if isinstance(ident, str) and ident.startswith("did:"):
        if not _did_shape_ok(ident):
            return None
        ident = store["keys"].get(ident)
    rec = store["accounts"].get(ident) if isinstance(ident, str) else None
    return rec.get("owner") if rec else None


# --- verify ----------------------------------------------------------------------------

def _row_problem(row: Any, i: int, prev_row: Any, account: str | None, owner: str | None,
                 current: str | None) -> str | None:
    if not isinstance(row, dict):
        return f"row {i} is not an object"
    if set(row) != set(SIGNED) | {"sig"}:
        return f"row {i} does not carry exactly the signed fields and sig"
    if row["kind"] != BIND_KIND or row["v"] != ROW_VERSION or isinstance(row["v"], bool):
        return f"row {i} is not an {BIND_KIND} v{ROW_VERSION} row"
    if row["event"] not in EVENTS or (i == 0) != (row["event"] == "issue"):
        return f"row {i} event {row['event']!r} is out of place"
    if _parse(row["at"]) is None:
        return f"row {i} at is not a UTC time"
    if prev_row is None:
        if row["prev"] is not None:
            return "the first row names a previous row"
    else:
        if row["prev"] != row_digest(prev_row):
            return f"row {i} prev does not name row {i - 1} (a row was dropped, moved or changed)"
        if _parse(row["at"]) < _parse(prev_row["at"]):
            return f"row {i} is dated before row {i - 1}"
    if account is not None and (row["account"] != account or row["owner"] != owner):
        return f"row {i} names another account or owner"
    if row["event"] in ("issue", "rotate"):
        proof = row["agent_proof"]
        if not isinstance(proof, dict) or not _did_shape_ok(proof.get("signer")):
            return f"row {i} agent proof is missing or its signer is not a did:key"
        why = X.check_binding(proof)
        if why:
            return f"row {i} agent proof does not check: {why}"
        if proof["signer"] != row["key"] or proof["account"] != row["account"]:
            return f"row {i} agent proof is for another key or account"
    elif row["event"] in ("revoke", "external"):
        if row["key"] != current:
            return f"row {i} {row['event']} names a key that is not the active one"
        if row["event"] == "external":
            ext = row["external"]
            if not isinstance(ext, dict) or (ext.get("key_jkt") is not None
                                             and ext.get("key_jkt") != jwk_thumbprint(row["key"])):
                return f"row {i} external receipt key_jkt is not the bound key's thumbprint"
    return None


def verify_binding(statement: Any, did: Any, *, server_keys: Any = (),
                   at: datetime | None = None, now: datetime | None = None) -> dict:
    """VERIFIED / BROKEN / COULD NOT LOOK for "this did:key was bound to its
    account at `at` (default: now)". Never raises."""
    rep = {"verdict": None, "reason": None, "did": did if _did_shape_ok(did) else None,
           "account": None, "owner": None, "bound_at": None, "retired_at": None,
           "revoked_at": None, "retired_by": None, "external": [], "findings": []}

    def done(word, reason):
        rep["verdict"], rep["reason"] = word, reason
        return rep
    try:
        if _pub(did) is None:
            return done(V.COULD_NOT_LOOK, "the key is not an Ed25519 did:key (the length is "
                                          "checked before any decode)")
        if not isinstance(statement, dict) or not isinstance(statement.get("rows"), list) \
                or not statement["rows"]:
            return done(V.COULD_NOT_LOOK, "no binding statement for this key")
        rows = statement["rows"]
        R = _receipts()
        try:
            R._require_backend()
        except Exception:  # noqa: BLE001
            return done(V.COULD_NOT_LOOK, "this install cannot check Ed25519: "
                                          "pip install 'arcaeon[sign]'")
        account = owner = current = None
        signers = set()
        for i, row in enumerate(rows):
            why = _row_problem(row, i, rows[i - 1] if i else None, account, owner, current)
            if why:
                rep["findings"].append(why)
                return done(V.BROKEN, why)
            pub = _pub(row["signer"])
            try:
                sig = base64.b64decode(row["sig"], validate=True) if isinstance(row["sig"], str) else b""
            except (binascii.Error, ValueError):
                sig = b""
            if pub is None or not R._verify_bytes(pub, _signing_bytes(row), sig):
                return done(V.BROKEN, f"row {i} binding signature does not verify (a field or "
                                      f"the signature was changed)")
            signers.add(row["signer"])
            account, owner = row["account"], row["owner"]
            if row["event"] in ("issue", "rotate"):
                current = row["key"]
            elif row["event"] == "revoke":
                current = None
            else:
                rep["external"].append(copy.deepcopy(row["external"]))
        rep["account"], rep["owner"] = account, owner
        if statement.get("account", account) != account or statement.get("owner", owner) != owner:
            return done(V.BROKEN, "the statement's account or owner is not what its rows say")
        trusted = {k for k in (server_keys or ()) if _did_shape_ok(k)}
        if not trusted:
            return done(V.COULD_NOT_LOOK, f"signed by {', '.join(sorted(signers))}; name the "
                                          f"arcaeon.io binding key you trust (server_keys)")
        if not signers <= trusted:
            return done(V.BROKEN, f"signed by {', '.join(sorted(signers - trusted))}, not by "
                                  f"a binding key you named")
        win = [w for w in _windows(rows) if w[0] == did]
        if not win:
            return done(V.COULD_NOT_LOOK, "this statement does not bind that key")
        key, bound_at, retired_at, retired_by = win[-1]
        rep.update(bound_at=bound_at, retired_at=retired_at, retired_by=retired_by,
                   revoked_at=retired_at)
        when = _when(at if at is not None else now)
        if when < _parse(bound_at):
            return done(V.COULD_NOT_LOOK, f"the time asked about is before the key was bound "
                                          f"({bound_at}); the account did not hold it then")
        if retired_at is not None and when >= _parse(retired_at):
            return done(V.BROKEN, f"the key was {'revoked' if retired_by == 'revoke' else 'rotated out'} "
                                  f"at {retired_at}; anything it signed from then on is not the account's")
        note = (f"; it was {'revoked' if retired_by == 'revoke' else 'rotated out'} later, at "
                f"{retired_at}") if retired_at else ""
        return done(V.VERIFIED, f"bound to {account} under {owner} from {bound_at}{note}")
    except Exception as e:  # noqa: BLE001  hostile input is an answer, not a crash
        return done(V.COULD_NOT_LOOK, f"the statement could not be read ({type(e).__name__})")


# --- the exchange pairing, held to the account service (L3-02, D077) ---------------------

#: What a report says when no account service was given (today's behavior).
NOT_CONSULTED = ("account service not consulted: a binding row is the key holder's own "
                 "claim (pass --accounts FILE and --account-key DID to hold it to the "
                 "account service)")
_AMBIGUOUS = object()


def load_service(src: Any, server_keys: Any = ()) -> tuple[dict | None, str | None]:
    """(service, None) or (None, why). `src` is an account store (new_store /
    save_store shape), {"statements": [binding statement, ...]} (what GET
    /v1/keys/{did}/binding answers), a list of statements, or a path to one
    as JSON. `server_keys` are the binding keys the reader trusts; they are
    never taken from the file. Never raises."""
    name = "the account service"
    try:
        if isinstance(src, (dict, list)):
            data = src
        else:
            from arcaeon.record.row import loads_strict
            p = Path(src)
            name = f"accounts file {p.name}"
            if not p.is_file():
                return None, f"{name} is not there"
            if p.stat().st_size > MAX_STORE_BYTES:
                return None, f"{name} is over {MAX_STORE_BYTES} bytes; not read"
            data = loads_strict(p.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, TypeError) as e:
        return None, f"{name} is not JSON ({type(e).__name__})"
    keys = [server_keys] if isinstance(server_keys, str) else list(server_keys or ())
    if any(_pub(k) is None for k in keys):
        return None, ("an --account-key is not an Ed25519 did:key (the length is checked "
                      "before any decode)")
    if isinstance(data, dict) and isinstance(data.get("accounts"), dict) \
            and isinstance(data.get("keys"), dict):
        def lookup(did, store=data):
            return binding_statement(store, did)
    else:
        items = data.get("statements") if isinstance(data, dict) else data
        if not isinstance(items, list):
            return None, f"{name} is not an account store or a list of binding statements"
        index: dict = {}
        for st in items:
            did = st.get("did") if isinstance(st, dict) else None
            if _did_shape_ok(did):
                index[did] = _AMBIGUOUS if did in index else st

        def lookup(did, index=index):
            return index.get(did) if _did_shape_ok(did) else None
    return {"source": name, "lookup": lookup, "server_keys": sorted(set(keys))}, None


def _other_account(claimed: str, rep: dict) -> str:
    m = X.ACCOUNT_ID_RE.fullmatch(claimed)
    o = X.ACCOUNT_ID_RE.fullmatch(rep["owner"] or "")
    if m and o and (claimed == rep["owner"]
                    or m.group("name").split(".")[-1] != o.group("name")):
        return (f"the account service binds this key to {rep['account']} under "
                f"{rep['owner']}: a different owner than {claimed}")
    return (f"the account service binds this key to {rep['account']}, not {claimed}: a "
            f"different account")


def _newest_reaction(reactions: Any) -> tuple[datetime | None, Any]:
    newest, eid = None, None
    for row in reactions or ():
        t = _parse(row.get("at")) if isinstance(row, dict) else None
        if t is not None and (newest is None or t > newest):
            newest, eid = t, row.get("exchange_id")
    return newest, eid


def consult_binding(service: dict, did: Any, account: Any, rows: Any,
                    reactions: Any = ()) -> dict:
    """Does the account service confirm that `did` held `account` at each
    exchange.binding row's time, and still held it at the newest reaction row
    the key signed (`reactions`, R2)? {verdict, reason, account, key, at,
    through}. BROKEN when a binding row is not confirmed for a BROKEN reason
    (revoked or rotated out by then, another owner or account, a service row
    that does not verify), or the key was revoked or rotated out at or before
    its newest reaction row; COULD NOT LOOK when the service has no record or
    cannot be trusted. A row the service wraps as its agent_proof is read at
    the issue time. `through` (on VERIFIED) is the latest time the pairing was
    held at: the newest binding row or reaction row. Never raises."""
    out = {"verdict": None, "reason": None, "account": account,
           "key": did if _did_shape_ok(did) else None, "at": None, "through": None}

    def done(word, why, at=None):
        out.update(verdict=word, reason=why, at=at)
        return out
    try:
        if _pub(did) is None:
            return done(V.COULD_NOT_LOOK, "the key is not an Ed25519 did:key (the length is "
                                          "checked before any decode)")
        st = service["lookup"](did)
        if st is _AMBIGUOUS:
            return done(V.COULD_NOT_LOOK, "the account service holds two statements for this key")
        if st is None:
            return done(V.COULD_NOT_LOOK, "the account service has no record for this key")
        vouched = {}
        signed = X.BIND_SIGNED + ("sig",)
        for sr in st.get("rows") or ():
            ap = sr.get("agent_proof") if isinstance(sr, dict) else None
            if isinstance(ap, dict) and sr.get("event") in ("issue", "rotate") \
                    and sr.get("key") == did and _parse(sr.get("at")):
                vouched[canon_json({k: ap.get(k) for k in signed})] = _parse(sr["at"])
        seen = []
        for row in rows or ():
            t = _parse(row.get("at")) if isinstance(row, dict) else None
            if t is None:
                continue
            own = {k: row.get(k) for k in signed}
            t = max(t, vouched.get(canon_json(own), t))
            rep = verify_binding(st, did, server_keys=service["server_keys"], at=t)
            word, why = rep["verdict"], rep["reason"]
            if word == V.VERIFIED and rep["account"] != account:
                word, why = V.BROKEN, _other_account(account, rep)
            seen.append((word, why, _utc(t)))
        if not seen:
            return done(V.COULD_NOT_LOOK, "no dated binding row to hold to the account service")
        for word in (V.BROKEN, V.COULD_NOT_LOOK):
            hits = [s for s in seen if s[0] == word]
            if hits:
                return done(*hits[0])
        # R2: every binding row checks; the key must also still hold the
        # account at the newest reaction row it signed (a revoked or rotated
        # out key that goes on reacting is not the account's).
        newest, eid = _newest_reaction(reactions)
        if newest is not None and newest > max(_parse(s[2]) for s in seen):
            rep = verify_binding(st, did, server_keys=service["server_keys"], at=newest)
            if rep["verdict"] != V.VERIFIED:
                return done(rep["verdict"], f"the reaction row the key signed at "
                                            f"{_utc(newest)} (exchange {eid}) is not "
                                            f"confirmed: {rep['reason']}", _utc(newest))
        last = max(_parse(s[2]) for s in seen)
        out["through"] = _utc(max(newest, last) if newest is not None else last)
        return done(*seen[0])
    except Exception as e:  # noqa: BLE001  hostile input is an answer, not a crash
        return done(V.COULD_NOT_LOOK, f"the account service record could not be read "
                                      f"({type(e).__name__})")
    return done(V.COULD_NOT_LOOK, "nothing to check")


def _log_objects(path: Any, kind: str, owner: Any) -> list:
    """The rows of `kind` in one exchange log signed by `owner`; [] when the log
    cannot be read (the log reader has already said so). Signatures are the
    caller's check."""
    from arcaeon.record.row import loads_strict
    try:
        p = Path(path)
        if p.stat().st_size > X.MAX_LOG_BYTES:
            return []
        text = p.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError, TypeError, ValueError):
        return []
    out = []
    for raw in text.splitlines():
        try:
            o = loads_strict(raw) if raw.strip() else None
        except ValueError:
            continue
        if isinstance(o, dict) and o.get("kind") == kind and o.get("signer") == owner:
            out.append(o)
    return out


def log_binding_rows(path: Any, owner: Any) -> dict:
    """{account: [exchange.binding row, ...]}: the rows in one exchange log that
    check under their signature and are signed by the log's owner. {} when the
    log cannot be read (the log reader has already said so)."""
    out: dict = {}
    for o in _log_objects(path, X.BIND_KIND, owner):
        if X.check_binding(o) is None:
            out.setdefault(o["account"], []).append(o)
    return out


def log_reaction_rows(path: Any, owner: Any) -> list:
    """[exchange.reaction row, ...]: the reaction rows in one exchange log that
    check under their signature and are signed by the log's owner (R2: what the
    key went on signing after its binding row). [] when the log cannot be read."""
    out = []
    for o in _log_objects(path, X.KIND, owner):
        try:
            if X.check_row(o) is None:
                out.append(o)
        except Exception:  # noqa: BLE001  no backend: the consult says COULD NOT LOOK
            continue
    return out


def consult_pairings(service: dict, pairs: Any) -> list:
    """For each (account, key, [log paths]) an exchange reader paired through a
    binding row: consult_binding over that key's binding rows for the account
    and the reaction rows the key signed in those logs."""
    res = []
    for account, key, logs in pairs:
        rows = [r for lg in logs for r in log_binding_rows(lg, key).get(account, [])]
        reacts = [r for lg in logs for r in log_reaction_rows(lg, key)]
        res.append(consult_binding(service, key, account, rows, reacts))
    return res


def service_report(service: dict | None, results: Any = ()) -> dict:
    """The `account_service` block a report carries."""
    if service is None:
        return {"consulted": False, "reason": NOT_CONSULTED, "bindings": []}
    return {"consulted": True, "source": service["source"],
            "server_keys": list(service["server_keys"]), "bindings": list(results),
            "reason": (f"each binding row was held to {service['source']}, read with the "
                       f"binding key(s) named")}


# --- the thin handler ------------------------------------------------------------------

def handle(store: dict, caller: Any, method: str, path: str, body: Any, *,
           server_seed: bytes, now: datetime | None = None) -> tuple[int, dict]:
    """A transport-free router: (status, JSON body). The caller is whatever the
    site's auth layer established (owner session, owner API key, agent key or
    none); this stub does not check sessions itself."""
    try:
        if not isinstance(path, str) or len(path) > _MAX_PATH:
            raise AccountError(414, "path too long")
        parts = path.strip("/").split("/")
        body = body if isinstance(body, dict) else {}
        if parts[:2] == ["v1", "keys"] and len(parts) == 4 and parts[3] == "binding":
            if method != "GET":
                raise AccountError(405, "GET only")
            st = binding_statement(store, parts[2])
            if st is None:
                raise AccountError(404, "no binding for this key")
            return 200, st
        if parts == ["v1", "agents"]:
            if method == "GET":
                return 200, {"agents": list_agents(store, caller)}
            if method == "POST":
                before = sum(len(r["rows"]) for r in store["accounts"].values())
                row = issue(store, caller, agent=body.get("agent"), proof=body.get("proof"),
                            server_seed=server_seed, at=now)
                after = sum(len(r["rows"]) for r in store["accounts"].values())
                return (201 if after > before else 200), {"binding": row}
            raise AccountError(405, "GET or POST only")
        if parts[:2] == ["v1", "agents"] and len(parts) == 4:
            if method != "POST":
                raise AccountError(405, "POST only")
            acct, op = parts[2], parts[3]
            if op == "revoke":
                return 200, {"binding": revoke(store, caller, acct, server_seed=server_seed,
                                               at=now, reason=body.get("reason"))}
            if op == "rotate":
                return 200, {"binding": rotate(store, caller, acct, proof=body.get("proof"),
                                               server_seed=server_seed, at=now)}
            if op == "external":
                return 201, {"binding": attach_external(store, caller, acct,
                                                        receipt=body.get("receipt"),
                                                        server_seed=server_seed, at=now)}
        raise AccountError(404, "no such route")
    except AccountError as e:
        return e.status, {"error": str(e)}
