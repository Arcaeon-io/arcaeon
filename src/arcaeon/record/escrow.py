# SPDX-License-Identifier: MIT
"""arcaeon.record.escrow: a release rule over deal rows. MOCK RAIL ONLY.

    from arcaeon.record import escrow
    from arcaeon.record.deal import Deal
    buyer = Deal("buyer.jsonl", "buyer", "d-demo1")
    buyer.mandate(merchant="acme-tools", cap="1.00", currency="USD",
                  recourse="escrow_challenge_window")
    crit = {"seller": "acme-tools", "url": "https://tool.example/v1/answer",
            "response_status": 200}
    escrow.hold("buyer.jsonl", "buyer", "d-demo1", amount="0.30", currency="USD",
                criteria_digest=escrow.criteria_digest(crit),
                recourse="escrow_challenge_window", timeout_at="2026-10-03T00:00:00Z")
    s = escrow.settle("buyer.jsonl", "buyer", "d-demo1", receipt="call.receipt.json",
                      receipt_ledger="seller-calls.jsonl", criteria=crit)
    s.state   # "RELEASED", "REFUNDED" or "HELD"

WHAT THIS IS NOT
----------------
This module never moves money, never holds money and never talks to a payment
rail. Every hold, release and refund is a row on the writer's own deal ledger
with `rail: "mock"` and a `mock_reference` minted here; nothing was authorized,
captured or returned anywhere. It ships the RULE (when a hold may be released),
never the vault. A real rail adapter, and who holds the funds, is a separate
decision outside this package.

THE RULE, as a state machine over one hold per deal on one ledger:

    (no hold)  hold(...)                         -> HELD      writes deal.hold
    HELD       look MATCHED                      -> RELEASED  writes deal.release
    HELD       look ALTERED                      -> REFUNDED  writes deal.refund (cause ALTERED)
    HELD       look MISSING                      -> REFUNDED  writes deal.refund (cause MISSING)
    HELD       look COULD NOT LOOK, before timeout_at
                                                 -> HELD      writes deal.look
    HELD       look COULD NOT LOOK, at or after timeout_at
                                                 -> REFUNDED  writes deal.refund (cause timeout)
    RELEASED / REFUNDED   anything               -> unchanged, writes nothing

`timeout_at` is declared at hold time and is in the hold row's shared body, so
neither side can move it afterwards without the hold's digest changing.

THE LOOK. `look()` answers in the four deal words, never another:
  MATCHED         the counterpart's call receipt recomputes to its body digest,
                  its row is on the counterpart's ledger at the place it says
                  and that ledger's chain holds, nothing attached contradicts
                  it, the call reports no upstream error, the criteria
                  presented recompute to the digest the hold froze, and every
                  criteria field equals the receipt's.
  ALTERED         the receipt's body no longer matches its digest (a one-byte
                  edit is enough), its ledger chain is broken or does not end
                  where it says, a key appears twice, an attachment contradicts
                  it, or a criteria field differs from what the receipt records.
  MISSING         the receipt's row is not on the counterpart's ledger, or the
                  call it records produced nothing (upstream_error).
  COULD NOT LOOK  no receipt, no ledger, not a call receipt, unreadable, no
                  criteria, criteria that do not recompute to the held digest,
                  or a criteria key that names nothing a call receipt records.
As in `dispute()`, a defect found is a fact even when another part could not
be looked at: ALTERED / MISSING win over COULD NOT LOOK.

The only writer of a release row is `_release`, and it refuses anything but a
Look whose verdict is MATCHED and which `look()` itself marked verified.

RECOURSE (N05). A hold carries a recourse tier and must not be `no_recourse`.
On the buyer's tape the hold refuses unless a mandate row recorded the same
tier before the first commit or hold. `dispute()` checks the same thing across
both tapes. A tier records what was asked for; it is never a promise.

WHAT A RELEASE DOES NOT PROVE: the receipt is delivery evidence, not quality
evidence (receipt/call.py's own scope). The side that runs `settle` chooses
which receipt and criteria to present; both sides can run it, and `dispute()`
names it ALTERED when one tape releases a hold the other refunds.

Stdlib only. `look()` never raises: that is an answer too.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arcaeon import verdict as _v
from arcaeon.record.deal import (ESCROW_STEPS, PARTIES, RECOURSE, Deal, Finding, _amount,
                                 _parse_time, deal_rows, recourse_before_work)
from arcaeon.record.row import digest_json

__all__ = ["HELD", "RELEASED", "REFUNDED", "STATES", "ESCROW_RECOURSE", "CRITERIA_KEYS",
           "RAIL", "TRANSITIONS", "Look", "Settlement", "criteria_digest", "hold", "look",
           "settle", "state", "check_rows", "LIMITS", "main"]

#: State names, not verdict words: where a hold stands.
HELD, RELEASED, REFUNDED = "HELD", "RELEASED", "REFUNDED"
STATES = (HELD, RELEASED, REFUNDED)
#: The tiers a hold may carry. `no_recourse` means pay outright: no hold.
ESCROW_RECOURSE = tuple(t for t in RECOURSE if t != "no_recourse")
RAIL = "mock"
TIMEOUT = "timeout"
#: Criteria keys a call receipt can answer: subject fields, then check fields.
_SUBJECT_KEYS = ("seller", "endpoint")
_CHECK_KEYS = ("method", "url", "response_status", "response_digest", "request_digest")
CRITERIA_KEYS = _SUBJECT_KEYS + _CHECK_KEYS
_CALL_KIND = "receipted-call"

#: (state, look verdict, past timeout_at) -> next state. The one table.
TRANSITIONS = {
    (HELD, _v.MATCHED, False): RELEASED, (HELD, _v.MATCHED, True): RELEASED,
    (HELD, _v.ALTERED, False): REFUNDED, (HELD, _v.ALTERED, True): REFUNDED,
    (HELD, _v.MISSING, False): REFUNDED, (HELD, _v.MISSING, True): REFUNDED,
    (HELD, _v.COULD_NOT_LOOK, False): HELD, (HELD, _v.COULD_NOT_LOOK, True): REFUNDED,
}

LIMITS = [
    "Mock rail: no money was held, released or refunded by this record; each row "
    "states what the rule decided, with a mock reference.",
    "A call receipt is delivery evidence, not quality evidence: a release says the "
    "named call happened as recorded, not that its answer was right.",
    "The side running the rule chooses which receipt and criteria to present; when "
    "the two sides settle one hold differently, dispute() says so.",
    "A recourse tier records what the buyer asked for before work began; it is not "
    "a promise that anything will be paid back.",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def criteria_digest(criteria: dict) -> str:
    """The digest a hold freezes. `criteria` is a non-empty dict whose keys are
    all CRITERIA_KEYS; anything else is refused here, before the hold."""
    if not isinstance(criteria, dict) or not criteria:
        raise ValueError("criteria must be a non-empty object")
    unknown = sorted(set(criteria) - set(CRITERIA_KEYS))
    if unknown:
        raise ValueError(f"criteria keys {unknown} name nothing a call receipt records; "
                         f"use {', '.join(CRITERIA_KEYS)}")
    return digest_json(criteria)


def _mock_reference(action: str, basis: str) -> str:
    return f"mock-{action}-" + hashlib.sha256(f"{action}:{basis}".encode()).hexdigest()[:16]


# -- reading a ledger's hold ----------------------------------------------------

def _escrow_rows(ledger, deal_id: str) -> dict:
    by = {s: [] for s in ESCROW_STEPS}
    for r in deal_rows(ledger, deal_id):
        step = str(r.get("kind", ""))[5:]
        if step in by:
            by[step].append(r)
    return by


def _state_of(by: dict) -> str | None:
    if not by["hold"]:
        return None
    if by["release"] and by["refund"]:
        raise ValueError("this ledger settles the hold both ways (a release and a refund row)")
    if by["release"]:
        return RELEASED
    if by["refund"]:
        return REFUNDED
    return HELD


def state(ledger, deal_id: str) -> str | None:
    """Where the hold for `deal_id` on this ledger stands: HELD, RELEASED,
    REFUNDED, or None when the ledger holds no hold row for the deal."""
    return _state_of(_escrow_rows(ledger, deal_id))


# -- hold -------------------------------------------------------------------------

def hold(ledger, party: str, deal_id: str, *, amount: str, currency: str,
         criteria_digest: str, recourse: str, timeout_at: str,
         ts: str | None = None) -> dict:
    """Write the HELD row. One hold per deal per ledger. `timeout_at` is when a
    hold nobody could look at is refunded; it is frozen in the row's shared
    body. Mock rail: nothing is held anywhere."""
    if party not in PARTIES:
        raise ValueError(f"party must be one of {PARTIES}, got {party!r}")
    amt = _amount(amount)
    if amt is None or amt <= 0:
        raise ValueError(f"amount must be a positive amount, got {amount!r}")
    if not isinstance(currency, str) or not currency:
        raise ValueError("currency is required")
    if not isinstance(criteria_digest, str) or not criteria_digest.startswith("sha256:"):
        raise ValueError("criteria_digest must be a digest (escrow.criteria_digest(criteria))")
    if recourse not in ESCROW_RECOURSE:
        raise ValueError(f"a hold's recourse must be one of {ESCROW_RECOURSE}, got {recourse!r}"
                         + ("; no_recourse means pay outright, with no hold"
                            if recourse == "no_recourse" else ""))
    if _parse_time(timeout_at) is None:
        raise ValueError(f"timeout_at must be a readable time, got {timeout_at!r}")
    d = Deal(ledger, party, deal_id)
    rows = d.rows()
    if any(r.get("kind") == "deal.hold" for r in rows):
        raise ValueError(f"deal {deal_id} already has a hold on this ledger; one hold per deal")
    if party == "buyer":
        B = {s: [] for s in ("mandate", "commit", "hold")}
        for n, r in enumerate(rows, start=1):
            step = str(r.get("kind", ""))[5:]
            if step in B:
                B[step].append((n, r))
        tier, _ = recourse_before_work(B)
        if tier is None:
            raise ValueError("no mandate row on this tape recorded a recourse tier before work "
                             "began; record it with mandate(recourse=...) first")
        if tier != recourse:
            raise ValueError(f"the mandate recorded recourse {tier!r}; this hold says {recourse!r}")
    shared = {"amount": str(amount), "currency": currency, "criteria_digest": criteria_digest,
              "recourse": recourse, "timeout_at": timeout_at, "rail": RAIL}
    private = {"mock_reference": _mock_reference("hold", f"{deal_id}:{digest_json(shared)}"),
               "rail_note": "mock rail: nothing was held"}
    return d._write("hold", shared, private, ts)


# -- look -------------------------------------------------------------------------

@dataclass
class Look:
    """What one look at a counterpart's call receipt found. `verified` is True
    only when `look()` itself reached MATCHED; nothing else sets it."""
    verdict: str
    reason: str
    receipt_body_digest: str | None = None
    findings: list = field(default_factory=list)
    could_not_look: list = field(default_factory=list)
    looked_for: str | None = None
    where: str | None = None
    reason_word: str | None = None
    verified: bool = False

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "reason": self.reason,
                "receipt_body_digest": self.receipt_body_digest,
                "findings": list(self.findings), "could_not_look": list(self.could_not_look),
                "looked_for": self.looked_for, "where": self.where,
                "reason_word": self.reason_word, "verified": self.verified}


def _read_receipt(receipt) -> tuple[dict | None, str | None, list, list]:
    """(receipt, source_text, findings, cnl). Never raises."""
    from arcaeon.record.row import DuplicateKeyError, loads_strict
    if receipt is None:
        return None, None, [], [("no receipt was presented", "the counterpart's call receipt",
                                 "(none given)", "missing")]
    if isinstance(receipt, dict):
        return receipt, None, [], []
    p = Path(receipt)
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, None, [], [(f"receipt not found: {p}", "the counterpart's call receipt",
                                 str(p), "missing")]
    except (OSError, UnicodeDecodeError) as e:
        return None, None, [], [(f"receipt unreadable: {type(e).__name__}",
                                 "the counterpart's call receipt", str(p), "unreadable")]
    try:
        obj = loads_strict(text)
    except DuplicateKeyError as e:
        return None, text, [(_v.ALTERED, f"the receipt file carries a key twice ({e}); it "
                                         f"means different things to different JSON readers")], []
    except (ValueError, RecursionError) as e:
        return None, text, [], [(f"receipt is not readable JSON: {str(e)[:120]}",
                                 "the counterpart's call receipt", str(p), "unreadable")]
    if not isinstance(obj, dict):
        return None, text, [], [("receipt is not a JSON object", "the counterpart's call receipt",
                                 str(p), "unreadable")]
    return obj, text, [], []


def look(receipt, *, receipt_ledger=None, criteria: dict | None = None,
         held_criteria_digest: str | None = None) -> Look:
    """Look at the counterpart's call receipt against the held criteria.
    `receipt` is a receipt dict or a path to one; `receipt_ledger` the
    counterpart's ledger its row sits in. Never raises."""
    try:
        return _look(receipt, receipt_ledger, criteria, held_criteria_digest)
    except Exception as e:  # the fence: an answer, not a crash
        why = f"the look could not finish: {type(e).__name__} [internal_error]"
        return Look(_v.COULD_NOT_LOOK, why, could_not_look=[why], looked_for="a verdict",
                    where="the receipt", reason_word="unreadable")


def _look(receipt, receipt_ledger, criteria, held) -> Look:
    from arcaeon.record.receipt.core import (ATTACH_INCONSISTENT, ATTACH_MISMATCH,
                                             verify_receipt)
    rc, text, found, cnl = _read_receipt(receipt)
    body_digest = rc.get("body_digest") if isinstance(rc, dict) else None
    if rc is not None:
        is_call = rc.get("kind") == _CALL_KIND
        if not is_call:
            cnl.append((f"the receipt is of kind {rc.get('kind')!r}, not a {_CALL_KIND} receipt",
                        f"a {_CALL_KIND} receipt", "the receipt's kind", "name_not_found"))
        led = None
        if receipt_ledger is None:
            cnl.append(("no counterpart ledger was presented, so the receipt's row could not "
                        "be found in the counterpart's sequence", "the counterpart's ledger",
                        "(none given)", "missing"))
        elif not Path(receipt_ledger).is_file():
            cnl.append((f"counterpart ledger not found: {receipt_ledger}",
                        "the counterpart's ledger", str(receipt_ledger), "missing"))
        else:
            led = receipt_ledger
        res = verify_receipt(rc, ledger_path=led, source_text=text)
        if not res.get("body_digest_ok"):
            found.append((_v.ALTERED, "the receipt's body does not recompute to its body_digest: "
                                      "a body field was changed after issue"))
        if res.get("duplicate_keys"):
            found.append((_v.ALTERED, f"the receipt file is ambiguous: {res['duplicate_keys']}"))
        status = res.get("ledger", {}).get("status")
        if status == "chain_broken":
            found.append((_v.ALTERED, "the counterpart's ledger chain does not verify"))
        elif status == "head_mismatch":
            found.append((_v.ALTERED, "the receipt's ledger position does not match the "
                                      "counterpart's ledger"))
        elif status == "row_not_found":
            found.append((_v.MISSING, "the receipt's row is not on the counterpart's ledger"))
        if res.get("witness", {}).get("verdict") == ATTACH_INCONSISTENT:
            found.append((_v.ALTERED, "the receipt's witness block contradicts it"))
        if res.get("attestation_signature", {}).get("verdict") == ATTACH_MISMATCH:
            found.append((_v.ALTERED, "an attached signature is not over this receipt"))
        checks = rc.get("checks") if isinstance(rc.get("checks"), list) else []
        check = checks[0] if len(checks) == 1 and isinstance(checks[0], dict) else None
        subject = rc.get("subject") if isinstance(rc.get("subject"), dict) else {}
        if not is_call:
            check = None                           # another kind's fields are not a call's
        elif check is None:
            cnl.append(("the receipt does not carry exactly one call check", "one call check",
                        "the receipt's checks", "unreadable"))
        elif check.get("upstream_error"):
            found.append((_v.MISSING, "the call the receipt records produced nothing "
                                      "(upstream_error)"))
        # the criteria: frozen at hold time, presented now
        if criteria is None:
            cnl.append(("no criteria were presented", "the criteria the hold froze",
                        "(none given)", "missing"))
        elif not isinstance(criteria, dict) or not criteria:
            cnl.append(("the criteria presented are not a non-empty object",
                        "the criteria the hold froze", "the criteria", "unreadable"))
        elif held is None or digest_json(criteria) != held:
            cnl.append(("the criteria presented do not recompute to the digest the hold froze; "
                        "the criteria fixed at hold time were not presented",
                        "the criteria the hold froze", "the hold row's criteria_digest",
                        "name_not_found"))
        else:
            unknown = sorted(set(criteria) - set(CRITERIA_KEYS))
            if unknown:
                cnl.append((f"criteria keys {unknown} name nothing a call receipt records",
                            "a criteria key a call receipt records", "the criteria",
                            "name_not_found"))
            elif check is not None:
                for k, want in criteria.items():
                    have = subject.get(k) if k in _SUBJECT_KEYS else check.get(k)
                    if have != want:
                        found.append((_v.ALTERED, f"criteria {k} is {want!r}; the receipt "
                                                  f"records {have!r}"))
    if found:
        word = _v.ALTERED if any(w == _v.ALTERED for w, _ in found) else _v.MISSING
        first = next(r for w, r in found if w == word)
        return Look(word, first, body_digest, findings=[f"{w}: {r}" for w, r in found],
                    could_not_look=[c[0] for c in cnl])
    if cnl:
        reason, looked_for, where, rw = cnl[0]
        return Look(_v.COULD_NOT_LOOK, reason, body_digest, could_not_look=[c[0] for c in cnl],
                    looked_for=looked_for, where=where, reason_word=rw)
    return Look(_v.MATCHED, "the receipt recomputes, its row is on the counterpart's verified "
                            "ledger, and every criteria field equals what it records",
                body_digest, verified=True)


# -- settle -----------------------------------------------------------------------

@dataclass
class Settlement:
    state: str
    look: Look | None = None
    row: dict | None = None
    note: str = ""

    def to_dict(self) -> dict:
        return {"state": self.state, "look": self.look.to_dict() if self.look else None,
                "row": self.row, "note": self.note, "limits": list(LIMITS)}


def _outcome_shared(h: dict, lk: Look) -> dict:
    hs = h["shared"]
    return {"hold_digest": h["step_digest"], "verdict": lk.verdict,
            "receipt_body_digest": lk.receipt_body_digest, "amount": hs.get("amount"),
            "currency": hs.get("currency"), "rail": RAIL}


def _release(d: Deal, h: dict, lk: Look, ts: str | None) -> dict:
    """The one writer of a release row. Refuses anything look() did not verify."""
    if not isinstance(lk, Look) or lk.verdict != _v.MATCHED or lk.verified is not True:
        raise ValueError("a release needs a receipt look() verified as MATCHED")
    shared = _outcome_shared(h, lk)
    shared["criteria_digest"] = h["shared"].get("criteria_digest")
    return d._write("release", shared,
                    {"mock_reference": _mock_reference("release", h["step_digest"]),
                     "rail_note": "mock rail: nothing was released", "reason": lk.reason}, ts)


def _refund(d: Deal, h: dict, lk: Look, cause: str, ts: str | None) -> dict:
    shared = _outcome_shared(h, lk)
    shared["cause"] = cause
    return d._write("refund", shared,
                    {"mock_reference": _mock_reference("refund", h["step_digest"]),
                     "rail_note": "mock rail: nothing was refunded", "reason": lk.reason}, ts)


def settle(ledger, party: str, deal_id: str, *, receipt=None, receipt_ledger=None,
           criteria: dict | None = None, now: str | None = None,
           ts: str | None = None) -> Settlement:
    """Run the rule once for the hold on this ledger and write the row it
    decides (see TRANSITIONS). `now` is the time the timeout is judged at
    (default: this machine's clock); it also becomes the row's ts unless `ts`
    is given. A settled hold writes nothing."""
    d = Deal(ledger, party, deal_id)
    by = _escrow_rows(d.ledger, deal_id)
    st = _state_of(by)
    if st is None:
        raise ValueError(f"no hold row for deal {deal_id} on this ledger")
    if st != HELD:
        return Settlement(st, note=f"the hold is already {st}; nothing written")
    h = by["hold"][0]
    lk = look(receipt, receipt_ledger=receipt_ledger, criteria=criteria,
              held_criteria_digest=h["shared"].get("criteria_digest"))
    when = now or _now_iso()
    at, limit = _parse_time(when), _parse_time(h["shared"].get("timeout_at"))
    if at is None:
        raise ValueError(f"now must be a readable time, got {now!r}")
    past = limit is not None and at >= limit
    nxt = TRANSITIONS[(HELD, lk.verdict, past)]
    ts = ts or when
    if nxt == RELEASED:
        return Settlement(RELEASED, lk, _release(d, h, lk, ts))
    if nxt == REFUNDED:
        cause = lk.verdict if lk.verdict in (_v.ALTERED, _v.MISSING) else TIMEOUT
        return Settlement(REFUNDED, lk, _refund(d, h, lk, cause, ts))
    row = d._write("look", {"hold_digest": h["step_digest"], "verdict": lk.verdict,
                            "receipt_body_digest": lk.receipt_body_digest},
                   {"reason": lk.reason, "reason_word": lk.reason_word,
                    "timeout_at": h["shared"].get("timeout_at")}, ts)
    return Settlement(HELD, lk, row, note=f"still held until {h['shared'].get('timeout_at')}")


# -- what dispute() checks on escrow rows --------------------------------------------

def check_rows(by: dict, findings: list) -> None:
    """Called by deal.dispute() when escrow rows are on either tape. `by` is
    party -> step -> [(row number, row)], rows already self-consistent.
    Release and refund rows must name a hold on their own tape and its amount;
    a release must carry MATCHED; a refund ALTERED, MISSING or a timeout at or
    after the hold's timeout_at; one tape settles a hold one way; and the two
    tapes must not settle it opposite ways."""
    for p in PARTIES:
        holds = {r.get("step_digest"): r for _, r in by[p]["hold"]}
        for step in ("release", "refund"):
            for k, (n, r) in enumerate(by[p][step], start=1):
                at, sh = f"{step}#{k}", r["shared"]
                h = holds.get(sh.get("hold_digest"))
                if h is None:
                    findings.append(Finding(_v.MISSING, at, p,
                                            f"{p} tape row {n}: the {step} names hold "
                                            f"{sh.get('hold_digest')}, and no hold row on this "
                                            f"tape carries it", index_side=p))
                    continue
                if (sh.get("amount"), sh.get("currency")) != (h["shared"].get("amount"),
                                                               h["shared"].get("currency")):
                    findings.append(Finding(_v.ALTERED, at, p,
                                            f"{p} tape row {n}: the {step} amount differs from "
                                            f"the hold's", index_side=p))
                if step == "release" and sh.get("verdict") != _v.MATCHED:
                    findings.append(Finding(_v.ALTERED, at, p,
                                            f"{p} tape row {n}: a release carries verdict "
                                            f"{sh.get('verdict')!r}; only a receipt looked at "
                                            f"and found matching releases a hold", index_side=p))
                if step == "refund":
                    cause = sh.get("cause")
                    if cause == TIMEOUT:
                        t, lim = _parse_time(r.get("ts")), _parse_time(h["shared"].get("timeout_at"))
                        if t is None or lim is None or t < lim:
                            findings.append(Finding(_v.ALTERED, at, p,
                                                    f"{p} tape row {n}: a refund for timeout "
                                                    f"written at {r.get('ts')}, before the hold's "
                                                    f"timeout_at {h['shared'].get('timeout_at')}",
                                                    index_side=p))
                    elif cause not in (_v.ALTERED, _v.MISSING) or sh.get("verdict") != cause:
                        findings.append(Finding(_v.ALTERED, at, p,
                                                f"{p} tape row {n}: a refund with cause "
                                                f"{cause!r} and verdict {sh.get('verdict')!r}",
                                                index_side=p))
        if by[p]["release"] and by[p]["refund"]:
            findings.append(Finding(_v.ALTERED, "refund#1", p,
                                    f"the {p} tape both releases and refunds the hold",
                                    index_side=p))
    B, S = by["buyer"], by["seller"]
    if (B["release"] and S["refund"]) or (B["refund"] and S["release"]):
        rel = "buyer" if B["release"] else "seller"
        ref = "seller" if rel == "buyer" else "buyer"
        findings.append(Finding(_v.ALTERED, "release#1", None,
                                f"the {rel} tape releases the hold and the {ref} tape refunds it",
                                index_side=rel))


# -- the CLI ----------------------------------------------------------------------

USAGE = """usage: arcaeon escrow <hold|settle|state> ...

A release rule over deal rows, MOCK RAIL ONLY: no money is held, released or
refunded; each step is a deal row stating what the rule decided.
  hold    <ledger> --deal ID --party buyer|seller --amount A --currency C
          (--criteria FILE | --criteria-digest D)
          --recourse escrow_challenge_window|high --timeout-at T
  settle  <ledger> --deal ID --party buyer|seller --receipt FILE
          --receipt-ledger FILE --criteria FILE [--now T] [--json]
  state   <ledger> --deal ID

settle: MATCHED releases; ALTERED or MISSING refunds; COULD NOT LOOK stays
held until the timeout recorded at hold time, then refunds.
settle exits with its look's word: 0 MATCHED, 1 ALTERED or MISSING,
3 COULD NOT LOOK; 0 for a hold already settled; 2 bad usage.
state exits 0, or 3 when the ledger holds no hold for the deal."""


def _parser(cmd: str):
    import argparse
    ap = argparse.ArgumentParser(prog=f"arcaeon escrow {cmd}")
    ap.add_argument("ledger")
    ap.add_argument("--deal", required=True)
    if cmd in ("hold", "settle"):
        ap.add_argument("--party", required=True, choices=PARTIES)
    if cmd == "hold":
        ap.add_argument("--amount", required=True)
        ap.add_argument("--currency", required=True)
        g = ap.add_mutually_exclusive_group(required=True)
        g.add_argument("--criteria")
        g.add_argument("--criteria-digest")
        ap.add_argument("--recourse", required=True, choices=ESCROW_RECOURSE)
        ap.add_argument("--timeout-at", required=True)
    elif cmd == "settle":
        ap.add_argument("--receipt", required=True)
        ap.add_argument("--receipt-ledger", required=True)
        ap.add_argument("--criteria", required=True)
        ap.add_argument("--now")
        ap.add_argument("--json", action="store_true")
    return ap


def _load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv: list[str]) -> int:
    argv, _legacy = _v.pop_legacy_flag(argv)       # new verb: no legacy codes to keep
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return _v.EXIT_GOOD if argv else _v.EXIT_USAGE
    cmd, rest = argv[0], argv[1:]
    if cmd not in ("hold", "settle", "state"):
        print(f"arcaeon escrow: unknown step {cmd!r}\n\n{USAGE}")
        return _v.EXIT_USAGE
    try:
        a = _parser(cmd).parse_args(rest)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else _v.EXIT_USAGE
    try:
        if cmd == "hold":
            cd = a.criteria_digest or criteria_digest(_load_json(a.criteria))
            row = hold(a.ledger, a.party, a.deal, amount=a.amount, currency=a.currency,
                       criteria_digest=cd, recourse=a.recourse, timeout_at=a.timeout_at)
            print(json.dumps({"deal": a.deal, "state": HELD, "row": row}, ensure_ascii=False))
            return _v.EXIT_GOOD
        if cmd == "state":
            if not Path(a.ledger).is_file():
                print(f"{_v.COULD_NOT_LOOK}: ledger not found: {a.ledger}")
                return _v.EXIT_COULD_NOT_LOOK
            st = state(a.ledger, a.deal)
            if st is None:
                print(f"{_v.COULD_NOT_LOOK}: {a.ledger} holds no hold row for deal {a.deal}")
                return _v.EXIT_COULD_NOT_LOOK
            print(st)
            return _v.EXIT_GOOD
        try:
            crit = _load_json(a.criteria)
        except (OSError, ValueError):
            crit = None                            # the look says COULD NOT LOOK
        s = settle(a.ledger, a.party, a.deal, receipt=a.receipt,
                   receipt_ledger=a.receipt_ledger, criteria=crit, now=a.now)
    except (ValueError, OSError) as e:
        print(f"arcaeon escrow {cmd}: {e}")
        return _v.EXIT_USAGE
    if a.json:
        print(json.dumps(s.to_dict(), indent=1, ensure_ascii=False))
    else:
        print(s.state if s.look is None else f"{s.state}: {s.look.verdict}: {s.look.reason}")
        if s.note:
            print(f"  {s.note}")
        print("  mock rail: no money moved")
    return _v.EXIT_GOOD if s.look is None else _v.exit_for(s.look.verdict)
