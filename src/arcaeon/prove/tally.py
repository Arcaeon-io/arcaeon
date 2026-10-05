# SPDX-License-Identifier: MIT
"""arcaeon.prove.tally: the tally as facts, no score (TE-43 + TE-44).

    arcaeon tally build CHAIN.jsonl... [--json] [--settled-only] [--checked-only]
                        [--window 30d] [--groups FILE] [--aliases FILE] [--now T]
    arcaeon tally alias --old-key SEEDFILE --new-key SEEDFILE [--at T]
    arcaeon tally seal|pin|verify ...   (the tally chain: arcaeon.prove.tally_chain)
    arcaeon tally html TALLY.json [--out FILE]   (the page: arcaeon.prove.tally_html)

Reads exchange reaction chains (docs/EXCHANGE.md, one per account key) and
prints, per ID, facts in columns for a recent window and for all time, side
by side. There is no score, no weight and no ranking: anything that counts
more can be bought. The library is `build(paths, ...)`; it returns a dict of
kind arcaeon.tally/v1 and does not raise on hostile input (COULD NOT LOOK or
BROKEN instead). Bad options (a window or time that does not parse) raise
TallyError before anything is read.

Every output carries SENTENCE. The spec and its limits: docs/TALLY.md.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from arcaeon import verdict as V
from arcaeon.prove import exchange_log as X
from arcaeon.record.row import canon_json, loads_strict

__all__ = ["KIND", "SENTENCE", "ALIAS_KIND", "ALIAS_PAYLOAD_TYPE", "UNRATED_UNDER_EXCHANGES",
           "UNRATED_UNDER_DAYS", "DEFAULT_WINDOW", "TallyError", "parse_window", "parse_now",
           "sign_alias", "check_alias", "build", "render", "main"]

KIND = "arcaeon.tally/v1"
SENTENCE = "clean means unchanged and labeled, never true"
ALIAS_KIND = "arcaeon.tally.alias/v1"
ALIAS_PAYLOAD_TYPE = "application/vnd.arcaeon.tally.alias.v1+json"
ALIAS_SIGNED = ("kind", "old", "new", "at")
UNRATED_UNDER_EXCHANGES = 10
UNRATED_UNDER_DAYS = 14
DEFAULT_WINDOW = "30d"
WORDS = (V.VERIFIED, V.COULD_NOT_LOOK, V.BROKEN)
MAX_SIDE_FILE = 4 << 20
_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
_WINDOW = re.compile(r"([1-9][0-9]{0,4})([dh])")

DEFINITIONS = {
    "said": "the words this ID wrote in its own chain, its latest non-superseded reaction "
            "per exchange, counted ONLY when the counterparty pairs: a chain the counterparty "
            "owns is among the inputs and holds a current row for the same exchange",
    "said_unpaired": "the same words for every other exchange (a counterparty with no chain "
                     "here, an account id with no binding row, or no answering row); shown "
                     "apart, never folded into said or its share",
    "retracted": "BROKEN rows later superseded by another word: `said`, by this ID; "
                 "`received`, by a counterparty about an exchange with it. Dated by the "
                 "retracted row; counted before filters",
    "from_broken_chain": "rows from a chain that reads BROKEN, about this ID: `received` "
                         "words and `paired` exchanges they would have made. They credit and "
                         "flag nothing; they are counted here, before filters",
    "received": "the words counterparties wrote about exchanges with this ID: their latest "
                "reaction per exchange, read only from chains among the inputs that do not "
                "read BROKEN (those are in from_broken_chain)",
    "paired": "exchanges where both parties' chains are among the inputs, lined up by "
              "exchange_id as `arcaeon exchange pair` does: clean, mismatch, missing, "
              "not_verified, broken",
    "exchanges": "distinct paired exchanges (counterparty has its own chain among the inputs) "
                 "where both sides hold a current row; a side that never answered is in "
                 "paired.missing only. Self-trades excluded; the unrated threshold counts these",
    "counterparties_with_records": "distinct other IDs in paired exchanges: a counterparty "
                                   "counts only if a chain it owns is among the inputs",
    "disagreements": "paired exchanges whose status is mismatch or missing",
    "broken": "findings that make the BROKEN flag: this ID's chain does not verify or holds "
              "a BROKEN row (dated in every window), a counterparty whose chain does not "
              "read BROKEN said BROKEN about an exchange with it, or a paired exchange is "
              "broken",
    "checked": "a reaction that is VERIFIED or BROKEN (someone looked); COULD NOT LOOK is not "
               "checked. --checked-only drops unchecked rows and any pair holding one",
    "settled": "an exchange with a current row from both parties (both chains among the "
               "inputs) and neither row DISPUTED. --settled-only drops every other row",
    "age": "from this ID's earliest signed `at` (any of its keys) to now; the writer's clock",
}

PROVES = ("each counted row was written by the key that owns its chain, and the counts are "
          "what those rows say, read the same way by anyone holding the same chains")
DOES_NOT_PROVE = ("that any file was true, that an ID is honest or a person, that two IDs "
                  "are not one owner (only declared groups and shared keys are caught), that "
                  "a chain was not truncated or re-minted, or that `at` times are real (they "
                  "are the writer's clock)")
LIMITS = (
    "no score, no weight, no ranking: anything that counts more can be bought",
    "self-trades are caught only when the two sides share a key, are one ID by a signed "
    "alias, or are in one declared group; two strangers' keys run by one owner look like "
    "two parties",
    "a fresh key with no alias cannot be stopped; it is shown as a new, unrated ID",
    "an alias needs both keys' signatures, so an ID with a bad record will not sign one: "
    "the alias carries history forward only when the holder chooses to",
    "a counterparty named by arcaeon.io account id (acct:NAME@arcaeon.io) resolves to a key "
    "ONLY through a signed binding row in that key's own chain among the inputs; without "
    "one, or when two chains bind it, the binding is COULD NOT LOOK and the row is unpaired. "
    "A binding is the key holder's claim: arcaeon.io's record is not consulted",
    "`at` is signed but not witnessed: an owner can backdate rows to look older; pin chain "
    "heads outside your control",
)


class TallyError(ValueError):
    """A bad option (window, time, key file). Nothing was read."""


# --- options -----------------------------------------------------------------------------

def parse_window(text: str) -> timedelta:
    """'30d' or '12h' (1 to 99999), else TallyError."""
    m = _WINDOW.fullmatch(str(text).strip())
    if not m:
        raise TallyError(f"--window {text!r} is not a span like 30d or 12h")
    n = int(m.group(1))
    return timedelta(days=n) if m.group(2) == "d" else timedelta(hours=n)


def parse_now(text: Any) -> datetime:
    """A datetime with a zone, or 'YYYY-MM-DDTHH:MM:SSZ', as UTC."""
    if isinstance(text, datetime):
        if text.tzinfo is None:
            raise TallyError("--now needs a zone")
        return text.astimezone(timezone.utc).replace(microsecond=0)
    try:
        return datetime.strptime(str(text), _TS_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        raise TallyError(f"--now {text!r} is not a UTC time YYYY-MM-DDTHH:MM:SSZ") from None


def _at(text: Any) -> datetime | None:
    try:
        return datetime.strptime(text, _TS_FMT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _ts(dt: datetime | None) -> str | None:
    return dt.strftime(_TS_FMT) if dt else None


# --- aliases: a new key inherits an old ID, signed by both keys --------------------------

def _alias_bytes(entry: dict) -> bytes:
    from arcaeon.prove.envelope import pae
    return pae(ALIAS_PAYLOAD_TYPE, canon_json({k: entry[k] for k in ALIAS_SIGNED}))


def sign_alias(old_seed: bytes, new_seed: bytes, at: datetime | None = None) -> dict:
    """An alias entry: `new` inherits the record of `old`. Both keys sign the
    same bytes (sig_old, sig_new), so neither a key's history nor a key can be
    claimed without its holder."""
    from arcaeon.prove.vet import receipts as R
    old = R.did_key(R.public_key_from_seed(old_seed))
    new = R.did_key(R.public_key_from_seed(new_seed))
    if old == new:
        raise TallyError("the old key and the new key are the same key")
    e = {"kind": ALIAS_KIND, "old": old, "new": new,
         "at": _ts((at or datetime.now(timezone.utc)).astimezone(timezone.utc))}
    msg = _alias_bytes(e)
    e["sig_old"] = base64.b64encode(R._sign_bytes(old_seed, msg)).decode("ascii")
    e["sig_new"] = base64.b64encode(R._sign_bytes(new_seed, msg)).decode("ascii")
    return e


def check_alias(entry: Any) -> tuple[str | None, str | None]:
    """(None, None) when both signatures verify; else (word, why): word is
    COULD NOT LOOK for a malformed entry, BROKEN for a signature that fails."""
    from arcaeon.prove.envelope import _pubkey_from_did
    from arcaeon.prove.vet import receipts as R
    if not isinstance(entry, dict):
        return V.COULD_NOT_LOOK, "not a JSON object"
    want = set(ALIAS_SIGNED) | {"sig_old", "sig_new"}
    if set(entry) != want:
        return V.COULD_NOT_LOOK, f"fields must be exactly {', '.join(sorted(want))}"
    if entry["kind"] != ALIAS_KIND:
        return V.COULD_NOT_LOOK, f"kind is not {ALIAS_KIND}"
    if not (X.is_did(entry["old"]) and X.is_did(entry["new"])):
        return V.COULD_NOT_LOOK, "old and new must be Ed25519 did:key"
    if entry["old"] == entry["new"]:
        return V.COULD_NOT_LOOK, "old and new are the same key"
    if _at(entry["at"]) is None:
        return V.COULD_NOT_LOOK, "at is not a UTC time"
    msg = _alias_bytes(entry)
    for side in ("old", "new"):
        try:
            sig = base64.b64decode(str(entry[f"sig_{side}"]), validate=True)
        except (binascii.Error, ValueError):
            return V.BROKEN, f"sig_{side} is not base64"
        if not R._verify_bytes(_pubkey_from_did(entry[side]), msg, sig):
            return V.BROKEN, f"sig_{side} does not verify under the {side} key"
    return None, None


# --- side files (groups, aliases) ----------------------------------------------------------

def _load_side(src: Any, what: str) -> tuple[Any, str | None]:
    """(parsed JSON, None) or (None, why). `src` is a path or already-parsed JSON."""
    if src is None:
        return None, None
    if isinstance(src, (dict, list)):
        return src, None
    p = Path(src)
    try:
        if not p.is_file():
            return None, f"{what} file {p.name} is not there"
        if p.stat().st_size > MAX_SIDE_FILE:
            return None, f"{what} file {p.name} is over {MAX_SIDE_FILE} bytes; not read"
        return loads_strict(p.read_bytes().decode("utf-8")), None
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return None, f"{what} file {p.name} is not JSON ({type(e).__name__})"


def _groups(obj: Any) -> tuple[list[dict], str | None]:
    """[{name, members}] or (_, why). Shape: {"groups": [...]} or a list; each
    group a list of did:key or {"name": TEXT, "members": [did:key, ...]}."""
    if obj is None:
        return [], None
    items = obj.get("groups") if isinstance(obj, dict) else obj
    if not isinstance(items, list):
        return [], "groups file holds no list of groups"
    out = []
    for n, g in enumerate(items, 1):
        name, members = f"group {n}", g
        if isinstance(g, dict):
            name, members = g.get("name", name), g.get("members")
        if not X.text_ok(name) or not isinstance(members, list) or len(members) < 2 \
                or not all(X.is_did(m) for m in members):
            return [], f"group {n} is not a name and two or more Ed25519 did:key members"
        out.append({"name": name, "members": sorted(set(members))})
    return out, None


# --- build ---------------------------------------------------------------------------------

def _skeleton(now: datetime, span: timedelta, window: str, settled: bool, checked: bool) -> dict:
    return {"kind": KIND, "sentence": SENTENCE, "verdict": None, "reason": None,
            "now": _ts(now),
            "windows": [{"name": window, "from": _ts(now - span), "to": _ts(now)},
                        {"name": "all", "from": None, "to": _ts(now)}],
            "order": "IDs with a BROKEN flag first, then by key text; this is not a ranking",
            "thresholds": {"unrated_under_exchanges": UNRATED_UNDER_EXCHANGES,
                           "unrated_under_days": UNRATED_UNDER_DAYS},
            "filters": {"settled_only": settled, "checked_only": checked},
            "definitions": DEFINITIONS, "chains": [], "aliases": [], "bindings": [],
            "groups": [],
            "ids": [], "findings": [], "proves": PROVES, "does_not_prove": DOES_NOT_PROVE,
            "limits": list(LIMITS)}


def build(paths, *, window: str = DEFAULT_WINDOW, settled_only: bool = False,
          checked_only: bool = False, groups: Any = None, aliases: Any = None,
          now: Any = None, accounts: Any = None, account_keys: Any = ()) -> dict:
    """The tally of exchange reaction chains as facts per ID (kind arcaeon.tally/v1).
    accounts / account_keys: hold each account binding to the account service
    (arcaeon.prove.account_id.load_service); None leaves the tally as it was.

    verdict: BROKEN if a chain does not verify or holds a BROKEN row, or an
    alias entry's signature fails; else COULD NOT LOOK if a chain, the groups
    file, the aliases file or an alias entry (malformed) could not be read, or
    no chain was given; else
    VERIFIED. The verdict is about the record, never about an ID. Raises
    TallyError only for a bad window or now."""
    span = parse_window(window)
    when = parse_now(now) if now is not None else \
        datetime.now(timezone.utc).replace(microsecond=0)
    r = _skeleton(when, span, str(window).strip(), bool(settled_only), bool(checked_only))
    svc = None
    if accounts is not None:
        from arcaeon.prove import account_id as A
        svc, why = A.load_service(accounts, account_keys)
        if why:
            return _cnl(r, "the accounts file", str(accounts), "unreadable", why)
    try:
        return _build(r, [Path(p) for p in paths], when, span, groups, aliases,
                      bool(settled_only), bool(checked_only), svc)
    except Exception as e:  # noqa: BLE001  never a traceback, never a green
        why = f"the tally could not finish ({type(e).__name__})"
        r.update({"verdict": V.COULD_NOT_LOOK, "ids": [], "reason": why,
                  **V.could_not_look("a finished tally", "the chains given", "unreadable", why)})
        return r


def _cnl(r: dict, looked_for: str, where: str, word: str, why: str) -> dict:
    r.update({"verdict": V.COULD_NOT_LOOK, "ids": [], "reason": why,
              **V.could_not_look(looked_for, where, word, why)})
    return r


def _hold_to_accounts(r: dict, svc: dict, acct_key: dict, record_broken: dict,
                      broken_top: list) -> dict:
    """L3-02: an applied binding stands only if the account service confirms it.
    Returns {key: owner account} for each binding that stands (R3, TE-44a)."""
    from arcaeon.prove import account_id as A
    logs: dict[str, list[str]] = {}
    for c in r["chains"]:
        if c.get("owner") and c.get("verdict") in (V.VERIFIED, V.BROKEN):
            logs.setdefault(c["owner"], []).append(c["log"])
    res = A.consult_pairings(svc, [(a, k, logs.get(k, [])) for a, k in sorted(acct_key.items())])
    by = {x["account"]: x for x in res}
    for b in r["bindings"]:
        x = by.get(b["account"]) if b["applied"] else None
        if x is None:
            continue
        b["account_service"] = {k: x[k] for k in ("verdict", "reason", "at", "through")}
        if x["verdict"] != V.VERIFIED:
            b["applied"], b["finding"] = False, f"{x['verdict']}: account service: {x['reason']}"
            acct_key.pop(b["account"], None)
        if x["verdict"] == V.BROKEN:
            why = f"binding {b['account']} -> {b['key']}: {x['reason']}"
            broken_top.append(why)
            record_broken.setdefault(b["key"], []).append(why)
    r["account_service"] = A.service_report(svc, res)
    r["limits"] = [s.replace("arcaeon.io's record is not consulted", "the account service "
                             "named in account_service was consulted")
                    .replace("or are in one declared group;", "are in one declared group, or "
                             "are both bound (confirmed by the account service) to agent "
                             "accounts of one owner;") for s in r["limits"]]
    return {x["key"]: x["owner"] for x in res if x["verdict"] == V.VERIFIED and x.get("owner")
            and acct_key.get(x["account"]) == x["key"]}


def _build(r: dict, paths: list[Path], now: datetime, span: timedelta, groups_src,
           aliases_src, settled_only: bool, checked_only: bool, svc=None) -> dict:
    try:
        from arcaeon.prove.vet import receipts as R
        R._require_backend()
    except Exception:  # noqa: BLE001
        return _cnl(r, "an Ed25519 backend", "this install", "missing",
                    "this install cannot check Ed25519 signatures: pip install 'arcaeon[sign]'")
    if not paths:
        return _cnl(r, "an exchange reactions chain", "the arguments", "empty",
                    "no chain was given")
    gobj, why = _load_side(groups_src, "groups")
    if why:
        return _cnl(r, "the groups file", str(groups_src), "unreadable", why)
    glist, why = _groups(gobj)
    if why:
        return _cnl(r, "the groups file", str(groups_src), "unreadable", why)
    r["groups"] = glist
    aobj, why = _load_side(aliases_src, "aliases")
    if why:
        return _cnl(r, "the aliases file", str(aliases_src), "unreadable", why)
    entries = []
    if aobj is not None:
        entries = aobj.get("aliases") if isinstance(aobj, dict) else aobj
        if not isinstance(entries, list):
            return _cnl(r, "the aliases file", str(aliases_src), "unreadable",
                        "aliases file holds no list of aliases")
    broken_top: list[str] = []
    alias: dict[str, str] = {}
    cnl_aliases: list[str] = []
    for n, e in enumerate(entries, 1):
        word, why = check_alias(e)
        if word == V.COULD_NOT_LOOK:    # malformed: unreadable, like a bad aliases file
            cnl_aliases.append(f"alias {n}: {why}")
        old =e.get("old") if isinstance(e, dict) else None
        new = e.get("new") if isinstance(e, dict) else None
        rec = {"old": old, "new": new, "applied": False, "how": "signed by the old and new keys",
               "finding": None}
        if word is None and new in alias:
            word, why = V.COULD_NOT_LOOK, f"{new} already aliased to {alias[new]}; not applied"
        if word is None:
            k = old                     # the applied map has no loop, so this ends
            while k != new and k in alias:
                k = alias[k]
            if k == new:
                word, why = V.COULD_NOT_LOOK, "this alias closes a loop; not applied"
        if word is None:
            alias[new] = old
            rec["applied"] = True
        else:
            rec["finding"] = f"{word}: {why}"
            if word == V.BROKEN:
                broken_top.append(f"alias {n}: {why}")
        r["aliases"].append(rec)

    def canon(k: str) -> str:
        while k in alias:
            k = alias[k]
        return k

    # read every chain
    rows_by_key: dict[str, list[dict]] = {}
    broken_rows_by_key: dict[str, list[dict]] = {}
    chains_by_key: dict[str, list[tuple[str, list, list]]] = {}
    record_broken: dict[str, list[str]] = {}
    bound: dict[str, set[str]] = {}
    cnl_chains: list[str] = []
    seen_paths: set[str] = set()
    for i, p in enumerate(paths, 1):
        try:
            where = str(p.resolve())
        except (OSError, RuntimeError, ValueError):
            where = str(p)
        if where in seen_paths:
            r["chains"].append({"log": str(p), "verdict": None,
                                "reason": "the same file was given twice; read once"})
            continue
        seen_paths.add(where)
        side = X.read_side(p, None, f"#{i}")
        rows = side.pop("_rows", [])
        own = side.get("owner")
        entry = {k: side.get(k) for k in ("log", "verdict", "reason", "owner", "owner_from",
                                          "reaction_rows", "broken_rows", "chain")}
        entry["id"] = canon(own) if own else None
        for k in ("looked_for", "where", "reason_word"):
            if k in side:
                entry[k] = side[k]
        r["chains"].append(entry)
        if side["verdict"] == V.COULD_NOT_LOOK:
            cnl_chains.append(f"{p.name}: {side['reason']}")
            continue
        if side["verdict"] == V.BROKEN:
            broken_top.append(f"{p.name}: {side['reason']}")
            if own is None:
                continue
            record_broken.setdefault(own, []).append(f"chain {p.name}: {side['reason']}")
        if own is None:
            continue
        for acct in side.get("accounts", []):
            bound.setdefault(acct, set()).add(own)
        chains_by_key.setdefault(own, []).append((p.name, rows, side["broken_rows"]))

    # R3-2: one key, more than one chain. Concatenating them let argument order
    # pick the head (a BROKEN or a VERIFIED). A copy, or an earlier prefix, of
    # one chain is one history: read the longest once. Chains that diverge are
    # a fork: BROKEN for that key, which then credits nothing (F10).
    for own, chs in chains_by_key.items():
        chs = sorted(chs, key=lambda c: -len(c[1]))
        longest = [x["row_digest"] for x in chs[0][1]]
        diverge = [c[0] for c in chs[1:]
                   if [x["row_digest"] for x in c[1]] != longest[:len(c[1])]]
        if diverge:
            names = ", ".join(sorted(c[0] for c in chs))
            why = (f"fork: key {own} owns {len(chs)} chains among the inputs ({names}) that "
                   f"diverge; which reaction is current cannot be read from them")
            broken_top.append(why)
            record_broken.setdefault(own, []).append(why)
            rows_by_key[own] = [x for c in chs for x in c[1]]
            broken_rows_by_key[own] = [x for c in chs for x in c[2]]
        else:
            rows_by_key[own] = list(chs[0][1])
            broken_rows_by_key[own] = list(chs[0][2])

    owners = set(rows_by_key)
    broken_owners = set(record_broken) | {k for k, v in broken_rows_by_key.items() if v}
    heads = {k: X.latest_heads({"_rows": v}) for k, v in rows_by_key.items()}
    acct_key: dict[str, str] = {}
    for acct in sorted(bound):
        keys = sorted(bound[acct])
        if len(keys) == 1:
            acct_key[acct] = keys[0]
            r["bindings"].append({"account": acct, "key": keys[0], "applied": True,
                                  "finding": None})
            continue
        for k in keys:
            r["bindings"].append({"account": acct, "key": k, "applied": False, "finding":
                                  f"{V.COULD_NOT_LOOK}: {len(keys)} chains among the inputs "
                                  f"bind {acct}; not resolved"})
    owner_of: dict[str, str] = {}
    if svc is not None:
        owner_of = _hold_to_accounts(r, svc, acct_key, record_broken, broken_top)
    shared = {a for a, ks in bound.items() if len(ks) > 1}
    ids_of: dict[str, set[str]] = {k: {k} for k in owners}
    for acct, k in acct_key.items():
        ids_of[k].add(acct)

    def resolve(cp: str) -> str:
        return acct_key.get(cp, cp)
    group_of: dict[str, set[str]] = {}
    for g in glist:
        for m in g["members"]:
            group_of.setdefault(canon(m), set()).add(g["name"])

    def exclusion(a: str, b: str) -> str | None:
        if a == b:
            return "self-trade: the row names its own key as the counterparty"
        ca, cb = canon(a), canon(b)
        if ca == cb:
            return "self-trade: both keys are one ID (a signed alias)"
        shared = sorted(group_of.get(ca, set()) & group_of.get(cb, set()))
        if shared:
            return f"self-trade: both IDs are in the declared group {shared[0]!r}"
        if owner_of.get(a) and owner_of.get(a) == owner_of.get(b):
            return (f"self-trade: both keys are agents of one owner, {owner_of[a]} "
                    f"(account service)")
        return None

    ids: dict[str, dict] = {}

    def acc(i: str) -> dict:
        return ids.setdefault(i, {"keys": set(), "chains": [], "events": [], "excluded": [],
                                  "claims": [], "record_broken": [], "filtered_out":
                                  {"said": 0, "received": 0, "paired": 0}, "first": None,
                                  "future": 0})

    for c in r["chains"]:
        if c.get("id") and c.get("owner") in owners | set(record_broken):
            a = acc(c["id"])
            a["chains"].append(c["log"])
            a["keys"].add(c["owner"])
    for k, fs in record_broken.items():
        acc(canon(k))["record_broken"].extend(fs)
    for k, bl in broken_rows_by_key.items():
        for br in bl:
            acc(canon(k))["record_broken"].append(f"row line {br['line']}: {br['finding']}")

    def pair_key(a: str, b: str, eid: str) -> tuple[str, str, str]:
        return (a, b, eid) if a < b else (b, a, eid)

    def settled(a: str, b: str, eid: str) -> bool:
        if a not in owners or b not in owners:
            return False
        ha, hb = heads[a].get(eid), heads[b].get(eid)
        return bool(ha and hb and not ha["disputed"] and not hb["disputed"])

    # said and received, from heads
    pairs: set[tuple[str, str, str]] = set()
    for k in sorted(owners):
        me = acc(canon(k))
        for row in rows_by_key[k]:
            t = _at(row["at"])
            if t and t > now:
                me["future"] += 1
            elif t and (me["first"] is None or t < me["first"]):
                me["first"] = t
        for eid, h in sorted(heads[k].items()):
            cp, t = resolve(h["counterparty"]), _at(h["at"])
            why = exclusion(k, cp)
            if why:
                me["excluded"].append({"exchange_id": eid, "counterparty": cp, "side": "said",
                                       "at": h["at"], "reason": why})
                if cp in owners and cp != k:
                    acc(canon(cp))["excluded"].append(
                        {"exchange_id": eid, "counterparty": k, "side": "received",
                         "at": h["at"], "reason": why})
                continue
            here = cp in owners
            if here:
                pairs.add(pair_key(k, cp, eid))
            answered = here and eid in heads[cp]
            credit = here and k not in broken_owners
            if h.get("retracted"):
                rt = _at(h["retracted_at"])
                me["events"].append({"t": rt, "type": "retracted_said"})
                if credit:
                    acc(canon(cp))["events"].append({"t": rt, "type": "retracted_received"})
            if here and not credit:
                acc(canon(cp))["events"].append({"t": t, "type": "broken_received"})
            drop = (checked_only and h["reaction"] == V.COULD_NOT_LOOK) or \
                (settled_only and not settled(k, cp, eid))
            if drop:
                me["filtered_out"]["said"] += 1
                if credit:
                    acc(canon(cp))["filtered_out"]["received"] += 1
                continue
            me["events"].append({"t": t, "type": "said" if answered else "said_unpaired",
                                 "word": h["reaction"]})
            if credit:
                acc(canon(cp))["events"].append({"t": t, "type": "received",
                                                 "word": h["reaction"]})

    # paired outcomes
    for a, b, eid in sorted(pairs):
        ha, hb = heads[a].get(eid), heads[b].get(eid)
        ba = [x for x in broken_rows_by_key.get(a, []) if x["exchange_id"] == eid]
        bb = [x for x in broken_rows_by_key.get(b, []) if x["exchange_id"] == eid]
        ex = X.pair_exchange(eid, ha, hb, a, b, ba, bb, ids_of[a], ids_of[b], shared)
        times = [t for t in (_at(h["at"]) if h else None for h in (ha, hb)) if t]
        t = max(times) if times else None
        present = [h for h in (ha, hb) if h]
        drop = (checked_only and any(h["reaction"] == V.COULD_NOT_LOOK for h in present)) or \
            (settled_only and not settled(a, b, eid))
        for me_k, other in ((a, b), (b, a)):
            me = acc(canon(me_k))
            if other in broken_owners:          # F10: marked, never credited
                me["events"].append({"t": t, "type": "broken_paired"})
                continue
            if drop:
                me["filtered_out"]["paired"] += 1
                continue
            me["events"].append({"t": t, "type": "paired", "status": ex["status"],
                                 "eid": eid, "other": canon(other),
                                 "answered": bool(ha and hb)})

    # DISPUTED claims, by and about
    for k in sorted(owners):
        cur = {h["row_digest"] for h in heads[k].values()}
        for row in rows_by_key[k]:
            if not row["disputed"]:
                continue
            cp = resolve(row["counterparty"])
            c = {"claim": "DISPUTED", "exchange_id": row["exchange_id"], "signer": k,
                 "counterparty": row["counterparty"], "reason": row["reason"], "at": row["at"],
                 "reaction": row["reaction"], "row_digest": row["row_digest"],
                 "current": row["row_digest"] in cur, "counted": exclusion(k, cp) is None,
                 "from_broken_chain": k in broken_owners}
            acc(canon(k))["claims"].append({**c, "role": "by"})
            if canon(cp) in ids and canon(cp) != canon(k):
                about = {**c, "role": "about"}
                if k in broken_owners:
                    about["counted"] = False
                acc(canon(cp))["claims"].append(about)

    windows = [(r["windows"][0]["name"], now - span), ("all", None)]
    out = []
    for i, a in ids.items():
        blocks = {name: _window(a, start, now) for name, start in windows}
        exchanges = blocks["all"]["exchanges"]
        age = (now - a["first"]).days if a["first"] else None
        because = []
        if exchanges < UNRATED_UNDER_EXCHANGES:
            because.append(f"{exchanges} exchanges, under {UNRATED_UNDER_EXCHANGES}")
        if age is None:
            because.append("no dated row")
        elif age < UNRATED_UNDER_DAYS:
            because.append(f"{age} days old, under {UNRATED_UNDER_DAYS}")
        flags = list(blocks["all"]["flags"]) + (["unrated"] if because else [])
        findings = []
        if a["future"]:
            findings.append(f"{a['future']} row(s) dated after now: in no window")
        out.append({"id": i, "flags": flags, "keys": sorted(a["keys"]),
                    "chains": a["chains"], "unrated": bool(because),
                    "unrated_because": because, "first_row_at": _ts(a["first"]),
                    "age_days": age, "windows": blocks,
                    "record_broken": a["record_broken"], "claims": a["claims"],
                    "excluded": a["excluded"], "filtered_out": a["filtered_out"],
                    "findings": findings})
    out.sort(key=lambda x: (0 if "BROKEN" in x["flags"] else 1, x["id"]))
    r["ids"] = out

    if broken_top:
        r["verdict"], r["reason"] = V.BROKEN, "; ".join(broken_top)
    elif cnl_chains or cnl_aliases:
        looked = "every chain given" if cnl_chains else "every alias entry given"
        where = "the chains given" if cnl_chains else (
            str(aliases_src) if isinstance(aliases_src, (str, Path)) else "the aliases given")
        r.update({k: v for k, v in V.could_not_look(
            looked, where, "unreadable", "; ".join(cnl_chains + cnl_aliases)).items()})
        r["verdict"] = V.COULD_NOT_LOOK
    else:
        r["verdict"] = V.VERIFIED
        r["reason"] = (f"{len(r['chains'])} chain(s) verify and every reaction row checks "
                       f"under its chain's key; {len(out)} ID(s)")
    r["findings"] = broken_top + cnl_chains + cnl_aliases
    return r


def _of(n: int, total: int) -> str:
    return f"{n} of {total}"


def _window(a: dict, start: datetime | None, now: datetime) -> dict:
    said = {w: 0 for w in WORDS}
    unpaired = {w: 0 for w in WORDS}
    recv = {w: 0 for w in WORDS}
    retracted = {"said": 0, "received": 0}
    from_broken = {"received": 0, "paired": 0}
    paired = {s: 0 for s in X.STATUSES}
    exchanges, others = set(), set()
    broken = len(a["record_broken"])
    for ev in a["events"]:
        t = ev["t"]
        if t is None or t > now or (start is not None and t < start):
            continue
        if ev["type"] == "said":
            said[ev["word"]] += 1
        elif ev["type"] == "said_unpaired":
            unpaired[ev["word"]] += 1
        elif ev["type"].startswith("retracted_"):
            retracted[ev["type"][len("retracted_"):]] += 1
        elif ev["type"].startswith("broken_"):
            from_broken[ev["type"][len("broken_"):]] += 1
        elif ev["type"] == "received":
            recv[ev["word"]] += 1
            broken += ev["word"] == V.BROKEN
        else:
            paired[ev["status"]] += 1
            if ev["answered"]:                  # A02: a side that never answered
                exchanges.add((ev["eid"], ev["other"]))   # is in paired.missing only
            others.add(ev["other"])
            broken += ev["status"] == "broken"

    def inwin(at: Any) -> bool:
        t = _at(at)
        return bool(t and t <= now and (start is None or t >= start))

    disputes = sum(1 for c in a["claims"] if c["counted"] and c["current"] and inwin(c["at"]))
    excluded = sum(1 for e in a["excluded"] if inwin(e["at"]))
    flags = (["BROKEN"] if broken else []) + (["DISPUTED"] if disputes else [])
    st, sr, sp = sum(said.values()), sum(recv.values()), sum(paired.values())
    return {"flags": flags, "broken": broken,
            "said": {**said, "total": st, "share_verified": _of(said[V.VERIFIED], st)},
            "said_unpaired": {**unpaired, "total": sum(unpaired.values())},
            "received": {**recv, "total": sr, "share_verified": _of(recv[V.VERIFIED], sr)},
            "paired": {**paired, "total": sp, "share_clean": _of(paired["clean"], sp)},
            "exchanges": len(exchanges), "counterparties_with_records": len(others),
            "disagreements": paired["mismatch"] + paired["missing"],
            "disputed": disputes, "excluded": excluded, "retracted": retracted,
            "from_broken_chain": from_broken}


# --- text ------------------------------------------------------------------------------------

_ROWS = (
    ("flags", lambda b: " ".join(b["flags"]) or "-"),
    ("broken", lambda b: str(b["broken"])),
    ("said VERIFIED", lambda b: b["said"]["share_verified"]),
    ("said COULD NOT LOOK", lambda b: str(b["said"][V.COULD_NOT_LOOK])),
    ("said BROKEN", lambda b: str(b["said"][V.BROKEN])),
    ("said unpaired VERIFIED", lambda b: str(b["said_unpaired"][V.VERIFIED])),
    ("said unpaired total", lambda b: str(b["said_unpaired"]["total"])),
    ("received VERIFIED", lambda b: b["received"]["share_verified"]),
    ("received COULD NOT LOOK", lambda b: str(b["received"][V.COULD_NOT_LOOK])),
    ("received BROKEN", lambda b: str(b["received"][V.BROKEN])),
    ("paired clean", lambda b: b["paired"]["share_clean"]),
    ("paired mismatch", lambda b: str(b["paired"]["mismatch"])),
    ("paired missing", lambda b: str(b["paired"]["missing"])),
    ("paired not_verified", lambda b: str(b["paired"]["not_verified"])),
    ("paired broken", lambda b: str(b["paired"]["broken"])),
    ("exchanges", lambda b: str(b["exchanges"])),
    ("counterparties with records", lambda b: str(b["counterparties_with_records"])),
    ("disagreements", lambda b: str(b["disagreements"])),
    ("DISPUTED claims (current)", lambda b: str(b["disputed"])),
    ("excluded self-trades", lambda b: str(b["excluded"])),
    ("retracted BROKEN said", lambda b: str(b["retracted"]["said"])),
    ("retracted BROKEN received", lambda b: str(b["retracted"]["received"])),
    ("from broken chain received", lambda b: str(b["from_broken_chain"]["received"])),
    ("from broken chain paired", lambda b: str(b["from_broken_chain"]["paired"])),
)


def render(r: dict) -> str:
    lines = [SENTENCE, f"tally {r['verdict']}: {r['reason']}", f"now {r['now']}; {r['order']}"]
    for c in r["chains"]:
        lines.append(f"chain {c.get('log')}: {c.get('verdict') or 'skipped'}"
                     + (f" owner {c['owner']}" if c.get("owner") else "")
                     + (f" ({c['reason']})" if c.get("verdict") != V.VERIFIED else ""))
    svc = r.get("account_service") or {}
    if svc.get("consulted"):
        lines.append(f"account service: {svc['reason']}")
    for b in r.get("bindings", []):
        lines.append(f"binding {b['account']} -> {b['key']}: "
                     + ((f"applied (signed binding row"
                         + (f"; account service {b['account_service']['verdict']}: "
                            f"{b['account_service']['reason']}" if "account_service" in b else "")
                         + ")") if b["applied"] else b["finding"]))
    for a in r["aliases"]:
        lines.append(f"alias {a['new']} -> {a['old']}: "
                     + ("applied (signed by both keys)" if a["applied"] else a["finding"]))
    names = [w["name"] for w in r["windows"]]
    for i in r["ids"]:
        lines.append("")
        lines.append(f"{i['id']}  {' '.join(i['flags']) or '-'}")
        if i["unrated"]:
            lines.append(f"  unrated: {'; '.join(i['unrated_because'])}")
        if len(i["keys"]) > 1 or i["keys"] != [i["id"]]:
            lines.append(f"  keys: {', '.join(i['keys'])}")
        lines.append(f"  first row {i['first_row_at'] or '-'}, age "
                     f"{'-' if i['age_days'] is None else i['age_days']} days")
        lines.append(f"  {'':28}" + "".join(f"  {n:>16}" for n in names))
        for label, fn in _ROWS:
            lines.append(f"  {label:28}"
                         + "".join(f"  {fn(i['windows'][n]):>16}" for n in names))
        for f in i["record_broken"]:
            lines.append(f"  BROKEN record: {f}")
        for c in i["claims"]:
            if c.get("from_broken_chain") and c["role"] == "about":
                tag = " (from a BROKEN chain, not counted)"
            else:
                tag = "" if c["counted"] else " (self-trade, not counted)"
            lines.append(f"  DISPUTED {c['role']} {c['signer']} on {c['exchange_id']} at "
                         f"{c['at']}{'' if c['current'] else ' (superseded)'}{tag}: "
                         f"{c['reason']}")
        for e in i["excluded"]:
            lines.append(f"  excluded {e['exchange_id']} ({e['side']}, {e['counterparty']}): "
                         f"{e['reason']}")
        fo = i["filtered_out"]
        if any(fo.values()):
            lines.append(f"  filtered out: {fo['said']} said, {fo['received']} received, "
                         f"{fo['paired']} paired")
        for f in i["findings"]:
            lines.append(f"  note: {f}")
    lines += ["", "no score, no weight, no ranking: anything that counts more can be bought",
              SENTENCE]
    return "\n".join(lines)


# --- CLI ---------------------------------------------------------------------------------------

USAGE = """usage: arcaeon tally build CHAIN.jsonl... [--json] [--settled-only]
                           [--checked-only] [--window 30d] [--groups FILE]
                           [--aliases FILE] [--now T]
                           [--accounts FILE --account-key DID...]
       arcaeon tally alias --old-key SEEDFILE --new-key SEEDFILE [--at T]
       arcaeon tally seal CHAIN.jsonl... --log TALLY_CHAIN.jsonl [--out FILE]
                          [--json] [build options]
       arcaeon tally pin --log TALLY_CHAIN.jsonl --dry-run [--out S.json]
                         [--chain-id ID] [--prev-pin-sha256 HEX]
       arcaeon tally verify --log TALLY_CHAIN.jsonl [--inputs CHAIN.jsonl...]
                            [--statement S.json] [--groups FILE]
                            [--aliases FILE] [--json]
       arcaeon tally html TALLY.json [--out FILE]
       arcaeon tally scitt-export S.json --key SEEDFILE --out FILE.scitt
                                 [--proof INCLUSION.json --ts-key SEEDFILE]
                                 [--iss ID] [--ts-iss ID]
       arcaeon tally scitt-verify FILE.scitt [--receipt FILE] [--ts-pub KEY]
                                 [--issuer-pub KEY] [--statement S.json]
                                 [--json]"""

HELP = USAGE + """

build reads exchange reaction chains (arcaeon exchange react, one per account
key) and prints, per ID, facts in columns for --window (default 30d) and for
all time side by side: words the ID said, words counterparties said about it,
paired outcomes (clean, mismatch, missing, not_verified, broken), exchanges,
counterparties with their own records, disagreements, DISPUTED claims, account
age. Every share is printed with its count ("9 of 10"). No score, no weight,
no ranking. An ID with any broken record or BROKEN reaction about it shows
BROKEN first; under 10 exchanges or 14 days it is unrated. Self-trades (one
key, one ID by alias, one --groups group, or with --accounts two agents of one
owner) are listed and not counted.
--accounts FILE (an account store or binding statements, docs/ACCOUNT_ID_API.md)
with --account-key DID (the binding key you trust; repeatable) holds each
account binding to the account service at the binding row's time and at the
newest reaction row the key signed: confirmed pairs, revoked or rotated out by
either time, or another owner, is BROKEN, no record is COULD NOT LOOK (both
unpaired). Without it the binding is the key holder's claim, not consulted.

alias prints an alias entry for --aliases: the new key inherits the old key's
record. Both keys sign it. A fresh key with no alias is a new, unrated ID.

seal runs build, replaces every local path with the file's name, and appends
one tally.snapshot row to the tally chain (--log): the tally's sha256 and,
per exchange log read, its name, sha256 and chain tip. --out writes the
sealed tally JSON. pin --dry-run prints the pin statement for the tally
chain's tip; --dry-run is the only mode, the live pin is the operator's
scheduled task. verify checks the tally chain, that no row is backdated, and
with --inputs that every snapshot's logs still hold the sealed rows (rows
appended since are fine), with --statement that it commits to this chain.
Un-editable, not un-gameable: a wash trade is sealed as a wash trade.

scitt-export writes the pin statement as a SCITT-shaped Signed Statement
(COSE_Sign1, RFC 9995 hash envelope); with --proof and --ts-key it adds an
RFC 9942-shaped receipt (vds 1, RFC 9162 inclusion proof) under 394. Offline:
nothing is sent. scitt-verify checks one: a bad signature or proof is BROKEN,
an unknown vds or no --ts-pub is COULD NOT LOOK. Not a conformance claim: the
leaf preimage rule is open (docs/design/SCITT_RECEIPTS.md).

html reads a tally JSON (build --json, seal --out) and writes one static
page: inline CSS, no script, nothing fetched. One row per ID per window in
the tally's order, the same fact columns as build, the sentence on every
row, the verdict and unrated as text. No score, rank or colour. --out never
overwrites; without it the page goes to stdout.

clean means unchanged and labeled, never true.

Exit codes: build 0 VERIFIED (every chain reads), 1 BROKEN (a chain, a row
or an alias signature), 3 COULD NOT LOOK, 2 bad usage; alias 0 printed, 2
refused; seal 0 written, 3 an input cannot be read, 2 refused; pin 0
printed, 1 the chain does not verify, 3 missing or empty, 2 refused (no
--dry-run); verify 0 VERIFIED, 1 BROKEN, 3 COULD NOT LOOK, 2 bad usage;
html 0 written, 3 the input is not a tally, 2 bad usage or --out exists.
Spec and limits: docs/TALLY.md."""


class _Usage(Exception):
    pass


_BUILD_SPEC = {"--json": "bool", "--settled-only": "bool", "--checked-only": "bool",
               "--window": "value", "--groups": "value", "--aliases": "value", "--now": "value",
               "--accounts": "value", "--account-key": "list"}
_ALIAS_SPEC = {"--old-key": "value", "--new-key": "value", "--at": "value"}


def _parse(argv, spec):
    from arcaeon.prove.envelope import _parse as p, _Usage as EU
    try:
        return p(argv, spec)
    except EU as e:
        raise _Usage(str(e)) from None


def _build_cli(argv: list[str]) -> int:
    pos, o = _parse(argv, _BUILD_SPEC)
    if not pos:
        raise _Usage("build takes one or more chains")
    if ("--accounts" in o) != ("--account-key" in o):
        raise _Usage("--accounts and --account-key go together")
    try:
        r = build(pos, window=o.get("--window", DEFAULT_WINDOW),
                  settled_only=bool(o.get("--settled-only")),
                  checked_only=bool(o.get("--checked-only")), groups=o.get("--groups"),
                  aliases=o.get("--aliases"), now=o.get("--now"),
                  accounts=o.get("--accounts"), account_keys=o.get("--account-key", ()))
    except TallyError as e:
        raise _Usage(str(e)) from None
    print(json.dumps(r, indent=1, ensure_ascii=False) if o.get("--json") else render(r))
    return V.exit_for(r["verdict"])


def _alias_cli(argv: list[str]) -> int:
    from arcaeon.prove.envelope import SealError, _load_seed
    pos, o = _parse(argv, _ALIAS_SPEC)
    if pos:
        raise _Usage(f"alias takes no positional argument (got {pos[0]!r})")
    if "--old-key" not in o or "--new-key" not in o:
        raise _Usage("alias needs --old-key and --new-key")
    try:
        at = parse_now(o["--at"]) if "--at" in o else None
        e = sign_alias(_load_seed(o["--old-key"]), _load_seed(o["--new-key"]), at)
    except (SealError, TallyError) as ex:
        print(f"arcaeon tally alias: {ex}; nothing printed", file=sys.stderr)
        return V.EXIT_USAGE
    except Exception as ex:  # noqa: BLE001  no backend
        print(f"arcaeon tally alias: signing needs arcaeon[sign] ({type(ex).__name__})",
              file=sys.stderr)
        return V.EXIT_USAGE
    print(json.dumps(e, indent=1))
    return V.EXIT_GOOD


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help") or any(a in ("-h", "--help") for a in argv):
        print(HELP)
        return V.EXIT_GOOD if argv else V.EXIT_USAGE
    sub, rest = argv[0], argv[1:]
    try:
        if sub == "build":
            return _build_cli(rest)
        if sub == "alias":
            return _alias_cli(rest)
        if sub == "html":
            from arcaeon.prove import tally_html
            return tally_html.html_cli(rest)
        if sub in ("scitt-export", "scitt-verify"):
            from arcaeon.prove import tally_chain as TC
            from arcaeon.remote import scitt
            try:
                return (scitt.export_cli if sub == "scitt-export" else scitt.verify_cli)(rest)
            except TC.Usage as e:
                raise _Usage(str(e)) from None
        if sub in ("seal", "pin", "verify"):
            from arcaeon.prove import tally_chain as TC
            try:
                return {"seal": TC.seal_cli, "pin": TC.pin_cli, "verify": TC.verify_cli}[sub](rest)
            except TC.Usage as e:
                raise _Usage(str(e)) from None
        raise _Usage(f"unknown subcommand {sub!r} (build, alias, seal, pin, verify, html, scitt-export or scitt-verify)")
    except _Usage as e:
        print(f"arcaeon tally: {e}\n{USAGE}", file=sys.stderr)
        return V.EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
