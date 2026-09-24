# SPDX-License-Identifier: MIT
"""arcaeon.record.deal: a witnessed transaction, recorded by both sides.

    from arcaeon.record.deal import Deal, dispute, pack
    buyer = Deal("buyer.jsonl", "buyer", "d-demo1")
    buyer.mandate(merchant="acme-store", cap="60.00", currency="USD",
                  not_before="2026-01-01T00:00:00Z", not_after="2099-12-31T00:00:00Z")
    buyer.commit(items=[{"sku": "pens-12", "qty": 2, "unit_price": "9.50"}],
                 total="19.00", currency="USD", seller="acme-store", ship_to="1 Main St")
    ...
    report = dispute("d-demo1", "buyer.jsonl", "seller.jsonl")

WHAT IT ANSWERS
---------------
Card networks settle one question: was this the cardholder's card. An agent
buying for a person raises three more that nobody records in a form both sides
can check later: did the person authorize this agent to do this (the mandate),
did the agent and the merchant agree on the same terms (the commit), and when
did each step happen relative to the others (the cancel-before-ship fight).
Each side keeps a hash-chained ledger of the same steps; `dispute()` lines the
two up and answers in the words every Arcaeon check uses: MATCHED, MISSING,
ALTERED or COULD NOT LOOK (arcaeon.verdict, one exit table).

THE ROWS. One `Ledger.append` per step, row format unchanged, no new reserved
keys. Every deal row carries `kind` = "deal.<step>", `deal` (the deal id),
`party` ("buyer" / "seller"), `shared` (the fields both sides must agree on) and
`step_digest` = digest_json(shared). Private fields sit beside `shared`, never
in it, and are never compared.

  mandate  buyer only. shared = {mandate_digest}. The mandate body (merchant,
           cap, currency, window, may / may_not) is private; `sealed` keeps only
           the digest in the row and the body in a sidecar file.
  commit   both. shared = {terms, mandate_digest}. The buyer's row also records
           `inside_mandate` (true / false / null = could not check) + reason.
  pay      both. shared = {rail, reference, amount, currency}.
  ship     seller; the buyer may mirror. shared = {carrier, tracking, at}.
           `after_cancel` records whether this tape already held a cancel row.
  deliver  either. shared = {at, proof}.
  cancel   buyer; the seller may mirror. shared = {reason}.
  dispute  either. shared = {claim, text}. Never compared: a claim is one side's.

Two-sided steps (commit, pay) must be on both tapes. A mirrored step (ship,
deliver, cancel) held by one side only is not a finding; `position` says which
tape lacks it. Once both sides record a mirrored step, they are compared.

WHAT IT DOES NOT DO
-------------------
It never moves money, holds money, or talks to a payment rail: `pay` records a
reference the rail already issued. It enforces no window: it records when rows
exist and pins bound those times; the merchant's policy decides a refund. The
`may` / `may_not` lists are recorded, not interpreted. It adds no verdict word.

REUSED, NOT COPIED. Pins load through `arcaeon.prove.reconcile.load_pins` and are
checked by reconcile's own pin check; unreadable lines are found by reconcile's
`_cannot_read`; the no-pin limit is reconcile's own sentence.

Stdlib only. Never raises from `dispute()`: that is an answer too.
"""
from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from arcaeon import verdict as _v
from arcaeon.record.ledger import Ledger, verify_file
from arcaeon.record.row import digest_json
from arcaeon.record.row import loads as _loads
# Reconcile's helpers, reused rather than copied. `_Tape`, `_cannot_read` and
# `_check_pin` are private to reconcile; they are imported here on purpose so
# the deal lane reads lines and checks pins with the very code reconcile uses,
# and a fix there lands here too.
from arcaeon.prove.reconcile import LIMITS as _RECONCILE_LIMITS
from arcaeon.prove.reconcile import Finding, load_pins
from arcaeon.prove.reconcile import _cannot_read, _check_pin, _Tape

__all__ = ["STEPS", "PARTIES", "CLAIMS", "Deal", "DealReport", "Finding", "dispute",
           "pack", "check_mandate", "deal_rows", "LIMITS"]

STEPS = ("mandate", "commit", "pay", "ship", "deliver", "cancel", "dispute")
PARTIES = ("buyer", "seller")
CLAIMS = ("not_authorized", "terms_altered", "not_shipped", "not_delivered",
          "cancelled_before_ship", "other")
BOTH_SIDES = ("commit", "pay")                 # must be on both tapes
MIRRORED = ("ship", "deliver", "cancel")       # compared once both sides record it
_ORDER = {s: i for i, s in enumerate(STEPS)}

#: What a deal verdict does not prove. The first three are reconcile's LIMITS in
#: deal words; the fourth is reconcile's no-pin sentence, verbatim.
LIMITS = [
    "MATCHED means the buyer's and the seller's tapes agree; a buyer side and a "
    "seller side run by one party who wants a lie can write two agreeing tapes.",
    "A step neither side recorded leaves no row on either tape; the deal lane "
    "records what each side wrote, not what happened in the world.",
    "Digests compare content (canonical JSON), not bytes: a meaning-preserving "
    "re-serialization in transit is MATCHED by design.",
    _RECONCILE_LIMITS[3],
    "Times are each writer's own ledger ts; only a witness pin bounds when a row "
    "existed. The deal lane moves no money and enforces no window.",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(s: Any) -> datetime | None:
    if not isinstance(s, str) or not s:
        return None
    try:
        t = datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith("Z") else s)
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _amount(s: Any) -> Decimal | None:
    if isinstance(s, bool) or not isinstance(s, (str, int)):
        return None
    try:
        d = Decimal(str(s))
    except InvalidOperation:
        return None
    return d if d.is_finite() else None


def check_mandate(mandate: dict, terms: dict, at: str) -> tuple[bool | None, str]:
    """Is a commit with these `terms`, made at `at`, inside `mandate`?

    (True, reason) inside; (False, reason) outside, naming the first rule it
    breaks; (None, reason) when a field cannot be read to check."""
    if terms.get("seller") != mandate.get("merchant"):
        return False, (f"seller {terms.get('seller')!r} is not the mandate's merchant "
                       f"{mandate.get('merchant')!r}")
    if terms.get("currency") != mandate.get("currency"):
        return False, (f"currency {terms.get('currency')!r} is not the mandate's "
                       f"{mandate.get('currency')!r}")
    total, cap = _amount(terms.get("total")), _amount(mandate.get("cap"))
    if total is None or cap is None:
        return None, "total or cap is not a readable amount"
    if total > cap:
        return False, f"total {terms.get('total')} is over the mandate's cap {mandate.get('cap')}"
    when = _parse_time(at)
    nb, na = _parse_time(mandate.get("not_before")), _parse_time(mandate.get("not_after"))
    if when is None:
        return None, f"commit time {at!r} is not a readable time"
    if mandate.get("not_before") and nb is None or mandate.get("not_after") and na is None:
        return None, "the mandate's window is not a readable time"
    if nb and when < nb:
        return False, f"commit at {at} is before the mandate's not_before {mandate['not_before']}"
    if na and when > na:
        return False, f"commit at {at} is after the mandate's not_after {mandate['not_after']}"
    return True, "seller, currency, cap and window are inside the mandate"


# -- writing -------------------------------------------------------------------

class Deal:
    """One party's side of one deal, written to that party's ledger.

    Every step writer appends exactly one row and returns it (with `ts` and
    `chain`). No step edits an earlier row. The record never refuses to
    record: a commit outside the mandate is written with `inside_mandate: false`.
    """

    def __init__(self, ledger: str | Path | Ledger, party: str, deal_id: str | None = None):
        if party not in PARTIES:
            raise ValueError(f"party must be one of {PARTIES}, got {party!r}")
        if deal_id is not None and (not isinstance(deal_id, str) or not deal_id.strip()):
            raise ValueError("deal id must be a non-empty string")
        self.ledger = ledger if isinstance(ledger, Ledger) else Ledger(ledger)
        self.party = party
        self.id = deal_id or "d-" + secrets.token_hex(6)
        self._sealed: dict[str, dict] = {}     # mandate_digest -> body, this process only

    def rows(self) -> list[dict]:
        """This deal's rows on this ledger, in file order."""
        return deal_rows(self.ledger, self.id)

    def _write(self, step: str, shared: dict, private: dict | None = None,
               ts: str | None = None, keep_null: tuple = ()) -> dict:
        row = {"kind": f"deal.{step}", "deal": self.id, "party": self.party,
               "step_digest": digest_json(shared), "shared": shared}
        for k, v in (private or {}).items():
            if v is not None or k in keep_null:
                row[k] = v
        row["ts"] = ts or _now_iso()
        row["chain"] = self.ledger.append(row)
        return row

    # mandate ---------------------------------------------------------------
    def mandate(self, *, merchant: str, cap: str, currency: str, not_before: str | None = None,
                not_after: str | None = None, may: list | None = None,
                may_not: list | None = None, sealed: str | Path | None = None,
                ts: str | None = None) -> dict:
        """Buyer only. `cap` is a string amount in `currency`. With `sealed`,
        the body goes to that sidecar file and the row keeps only its digest."""
        if self.party != "buyer":
            raise ValueError("only the buyer writes a mandate; the seller never holds one")
        body = {"merchant": merchant, "cap": str(cap), "currency": currency,
                "not_before": not_before, "not_after": not_after,
                "may": list(may or []), "may_not": list(may_not or [])}
        md = digest_json(body)
        scope = (f"{merchant}, up to {cap} {currency}"
                 + (f", from {not_before}" if not_before else "")
                 + (f", until {not_after}" if not_after else ""))
        private: dict = {"mandate_digest": md, "scope": scope}
        if sealed is not None:
            Path(sealed).write_text(json.dumps({"deal": self.id, "mandate_digest": md,
                                                "mandate": body}, indent=1), encoding="utf-8")
            private["sealed"] = True
            self._sealed[md] = body
        else:
            private["mandate"] = body
        return self._write("mandate", {"mandate_digest": md}, private, ts)

    def _mandate_body(self, row: dict, disclosed: dict | None) -> dict | None:
        if isinstance(row.get("mandate"), dict):
            return row["mandate"]
        md = row.get("mandate_digest")
        for body in (disclosed, self._sealed.get(md)):
            if isinstance(body, dict) and digest_json(body) == md:
                return body
        return None

    # commit ----------------------------------------------------------------
    def commit(self, *, items: list, total: str, currency: str, seller: str,
               ship_to: Any = None, ship_to_digest: str | None = None,
               buyer_ref: str | None = None, mandate_digest: str | None = None,
               note: str | None = None, mandate: dict | None = None,
               ts: str | None = None) -> dict:
        """Both sides. The buyer's commit cites the buyer's latest mandate row
        for this deal (or `mandate_digest`); the seller copies `mandate_digest`
        from the buyer's commit message. `ship_to` is digested, never stored.
        `mandate` discloses a sealed mandate's body so the buyer's check can run."""
        if ship_to_digest is None and ship_to is not None:
            ship_to_digest = digest_json(ship_to)
        terms = {"items": [dict(i) for i in items], "total": str(total), "currency": currency,
                 "ship_to_digest": ship_to_digest, "seller": seller, "buyer_ref": buyer_ref}
        private: dict = {"note": note}
        ts = ts or _now_iso()
        if self.party == "buyer":
            mandates = [r for r in self.rows() if r.get("kind") == "deal.mandate"]
            if mandate_digest is not None:
                cited = next((r for r in reversed(mandates)
                              if r.get("mandate_digest") == mandate_digest), None)
            else:
                cited = mandates[-1] if mandates else None
                mandate_digest = cited.get("mandate_digest") if cited else None
            if cited is None:
                inside, why = False, ("no mandate row for this deal on the buyer tape"
                                      if mandate_digest is None else
                                      "the cited mandate_digest is on no mandate row of this tape")
            else:
                body = self._mandate_body(cited, mandate)
                if body is None:
                    inside, why = None, "the mandate is sealed and its body was not disclosed"
                else:
                    inside, why = check_mandate(body, terms, ts)
            private.update(inside_mandate=inside, mandate_reason=why)
        shared = {"terms": terms, "mandate_digest": mandate_digest}
        # inside_mandate null (could not check) is kept in the row, not dropped
        return self._write("commit", shared, private, ts, keep_null=("inside_mandate",))

    # the rest ----------------------------------------------------------------
    def pay(self, *, rail: str, reference: str, amount: str, currency: str,
            ts: str | None = None) -> dict:
        """Both sides. Records a reference the rail already issued; moves nothing."""
        return self._write("pay", {"rail": rail, "reference": reference,
                                   "amount": str(amount), "currency": currency}, None, ts)

    def ship(self, *, carrier: str, tracking: str, at: str | None = None,
             ts: str | None = None) -> dict:
        """Seller (the buyer may mirror, copying carrier, tracking and `at`).
        `at` is the carrier's time as given, never defaulted to this writer's
        clock (the row's `ts` is that). `after_cancel` says whether this tape
        already held a cancel row for the deal."""
        after = any(r.get("kind") == "deal.cancel" for r in self.rows())
        return self._write("ship", {"carrier": carrier, "tracking": tracking,
                                    "at": at}, {"after_cancel": after}, ts)

    def deliver(self, *, proof: str, at: str | None = None, ts: str | None = None) -> dict:
        """Either side. `proof` is a digest or a carrier event id; `at` as given."""
        return self._write("deliver", {"at": at, "proof": proof}, None, ts)

    def cancel(self, *, reason: str, ts: str | None = None) -> dict:
        """Buyer (the seller may mirror)."""
        return self._write("cancel", {"reason": reason}, None, ts)

    def raise_dispute(self, claim: str, text: str = "", *, ts: str | None = None) -> dict:
        """Either side: record a dispute claim (one of CLAIMS). This writes the
        claim; the module-level `dispute()` is the verdict over both tapes."""
        if claim not in CLAIMS:
            raise ValueError(f"claim must be one of {CLAIMS}, got {claim!r}")
        return self._write("dispute", {"claim": claim, "text": text}, None, ts)


def deal_rows(ledger: str | Path | Ledger, deal_id: str) -> list[dict]:
    """Every row of `deal_id` on one ledger, in file order."""
    lg = ledger if isinstance(ledger, Ledger) else Ledger(ledger)
    return [r for r in lg if isinstance(r, dict) and str(r.get("kind", "")).startswith("deal.")
            and r.get("deal") == deal_id]


# -- the verdict -------------------------------------------------------------------

@dataclass
class DealReport:
    """Mirrors `arcaeon.prove.reconcile.Reconciliation`, plus `timeline` and
    `position`. `at` is a step and its ordinal ("commit#1"), or "row#N" for a
    pin finding. `position` states what the rows show and never a verdict word."""
    verdict: str
    deal: str = ""
    at: str | None = None
    side: str | None = None
    reason: str = ""
    matched: int = 0
    counts: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    could_not_look: list = field(default_factory=list)
    pins_checked: list = field(default_factory=list)
    limits: list = field(default_factory=lambda: list(LIMITS))
    timeline: list = field(default_factory=list)
    position: list = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        return _v.exit_for(self.verdict)

    @property
    def summary(self) -> str:
        if self.verdict == _v.MATCHED:
            return f"MATCHED {self.matched} of {self.matched} compared steps"
        if self.verdict == _v.COULD_NOT_LOOK:
            return f"COULD NOT LOOK: {self.reason}"
        where = f" at {self.at}" if self.at is not None else ""
        who = f" ({self.side} tape)" if self.side else ""
        return f"{self.verdict}{where}{who}: {self.reason}"

    def __bool__(self) -> bool:
        return self.verdict == _v.MATCHED

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "summary": self.summary, "deal": self.deal,
                "at": self.at, "side": self.side, "reason": self.reason,
                "matched": self.matched, "counts": self.counts,
                "findings": [f.to_dict() for f in self.findings],
                "could_not_look": list(self.could_not_look),
                "pins_checked": list(self.pins_checked), "limits": list(self.limits),
                "timeline": list(self.timeline), "position": list(self.position),
                "exit_code": self.exit_code}


def _load_side(party: str, path: str | Path, deal_id: str, cnl: list,
               findings: list) -> tuple[_Tape, list]:
    """Read one tape. Returns reconcile's `_Tape` (every row, for the pin check)
    and this deal's rows as (row number, row). Trouble goes into `cnl`."""
    label = f"{party} tape"
    t = _Tape(label=label, path=Path(path), side=party)
    try:
        t.path.stat()
    except FileNotFoundError:
        t.cnl = f"{label} not found: {t.path}"
    except OSError as e:
        t.cnl = f"{label} unreadable: {e}"
    if t.cnl is None and t.path.is_dir():
        t.cnl = f"{label} is a directory, not a ledger: {t.path}"
    if t.cnl:
        cnl.append(t.cnl)
        return t, []
    try:
        lines = t.path.read_text(encoding="utf-8", errors="replace").split("\n")
    except OSError as e:
        t.cnl = f"{label} unreadable: {e}"
        cnl.append(t.cnl)
        return t, []
    t.cnl = _cannot_read(label, lines)
    if t.cnl:
        cnl.append(t.cnl)
        return t, []
    res = verify_file(t.path)
    if res.ok is False:
        t.broken = True
        t.cnl = (f"{label} does not verify ({res.first_break or 'chain broken'}); "
                 f"a tape edited after it was written cannot be read as a deal record")
        cnl.append(t.cnl)
        return t, []
    if res.ok is None and res.verified_scope not in ("empty", "bounded_prechain_skipped"):
        t.cnl = f"{label} verifies only within scope ({res.verified_scope}): {res.declared}"
        cnl.append(t.cnl)
        return t, []
    mine = []
    for raw in lines:                       # counted exactly as chain_at / verify_file count
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = _loads(raw)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        t.rows.append(row)
        if not str(row.get("kind", "")).startswith("deal.") or row.get("deal") != deal_id:
            continue
        n = len(t.rows)
        step = row["kind"][5:]
        if step not in STEPS:
            t.cnl = f"{label} row {n} is a deal row of unknown step {step!r}"
        elif row.get("party") != party:
            t.cnl = f"{label} row {n} is written as party {row.get('party')!r}, not {party}"
        elif "chain" not in row:
            t.cnl = f"{label} row {n} is a deal row with no chain (outside the verified chain)"
        if t.cnl:
            cnl.append(t.cnl)
            return t, []
        mine.append((n, row))
    return t, mine


def _shared_of(row: dict) -> Any:
    return row.get("shared")


def _self_consistent(party: str, step: str, k: int, n: int, row: dict, findings: list) -> bool:
    shared = _shared_of(row)
    try:
        ok = isinstance(shared, dict) and digest_json(shared) == row.get("step_digest")
    except ValueError:
        ok = False
    if not ok:
        findings.append(Finding(_v.ALTERED, f"{step}#{k}", party,
                                f"{party} tape row {n}: the step_digest does not match the "
                                f"shared body the row carries", index_side=party))
    return ok


def _diff(a: Any, b: Any, prefix: str = "") -> list[str]:
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for key in sorted(set(a) | set(b)):
            p = f"{prefix}{key}"
            if key not in a or key not in b:
                out.append(p)
            elif a[key] != b[key]:
                out.extend(_diff(a[key], b[key], p + "."))
        return out
    return [prefix.rstrip(".") or "(body)"] if a != b else []


def _compare(step: str, B: list, S: list, findings: list) -> int:
    """Pair the i-th buyer row of a step with the i-th seller row. Returns matched."""
    matched = 0
    for k in range(max(len(B), len(S))):
        at = f"{step}#{k + 1}"
        if k >= len(B) or k >= len(S):
            short = "buyer" if k >= len(B) else "seller"
            longer = "seller" if short == "buyer" else "buyer"
            findings.append(Finding(_v.MISSING, at, short,
                                    f"{step} #{k + 1} is on the {longer} tape and not on the "
                                    f"{short} tape", index_side=longer))
            continue
        (nb, rb), (ns, rs) = B[k], S[k]
        if rb.get("step_digest") == rs.get("step_digest"):
            matched += 1
            continue
        keys = _diff(_shared_of(rb), _shared_of(rs))
        lead = "mandate_digest mismatch; " if "mandate_digest" in keys else ""
        findings.append(Finding(_v.ALTERED, at, None,
                                f"{lead}{step} #{k + 1} differs between the tapes in "
                                f"{', '.join(keys) or 'its shared body'} (buyer row {nb}, "
                                f"seller row {ns})", index_side="buyer"))
    return matched


def _load_pin_file(path: str | Path) -> list[dict]:
    """reconcile's `load_pins`, plus the two shapes a deal pin file also takes:
    a `{"buyer": pin, "seller": pin}` pair, and a witness store's JSONL (one pin
    per line, what `arcaeon pin --witness` appends to)."""
    try:
        return load_pins(path)
    except ValueError as first:
        text = Path(path).read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except ValueError:
            data = [json.loads(ln) for ln in text.split("\n") if ln.strip()]
        if isinstance(data, dict) and data and set(data) <= set(PARTIES):
            data = [dict(v, side=k) if isinstance(v, dict) else v for k, v in data.items()]
        if not isinstance(data, list):
            raise first
        for p in data:
            # load_pins' per-pin check is inline in it and not callable alone;
            # the same two rules, restated for the shapes it does not read.
            r = p.get("rows") if isinstance(p, dict) else None
            if not isinstance(p, dict) or not isinstance(r, int) or isinstance(r, bool) or r < 0:
                raise ValueError(f"pin rows is not a non-negative integer: {r!r}")
            if not isinstance(p.get("chain"), str):
                raise ValueError("pin chain is not a string")
        return data


_CALL = re.compile(r"\bcall(s?)\b")


def _check_pins(pins: list, tapes: dict, ns: dict, findings: list, cnl: list,
                checked: list) -> None:
    for pin in pins:
        side = pin.get("side")
        if side in PARTIES:
            targets = [side]
        else:
            by_ns = [p for p in PARTIES if ns.get(p) and pin.get("namespace") == ns[p]]
            if by_ns:
                targets = by_ns
            elif any(ns.values()):
                checked.append({"side": None, "namespace": pin.get("namespace"),
                                "rows": pin.get("rows"), "result": "other_namespace"})
                continue
            else:
                targets = list(PARTIES)        # reconcile's rule: held against both
        for p in targets:
            before = len(findings)
            _check_pin(pin, tapes[p], findings, cnl, checked)
            if checked:
                checked[-1]["as_of"] = pin.get("received_at") or pin.get("as_of")
            for f in findings[before:]:        # reconcile counts calls; a ledger counts rows
                f.at = f"row#{f.at}"
                f.reason = _CALL.sub(lambda m: "row" + m.group(1), f.reason)


def _pin_bound(party: str, n: int, checked: list) -> str | None:
    times = [c["as_of"] for c in checked if c.get("side") == party
             and c.get("result") == "agrees" and isinstance(c.get("rows"), int)
             and c["rows"] >= n and c.get("as_of")]
    return min(times) if times else None


def _minutes(a: str, b: str) -> int | None:
    ta, tb = _parse_time(a), _parse_time(b)
    if ta is None or tb is None:
        return None
    return round((tb - ta).total_seconds() / 60)


def _position(by: dict, timeline: list, checked: list) -> list[str]:
    """Plain sentences from the rows alone. Never a verdict word."""
    out = []
    B, S = by["buyer"], by["seller"]
    for step in STEPS:
        nb, ns_ = len(B[step]), len(S[step])
        if step == "mandate":
            if nb:
                out.append(f"mandate: the buyer tape holds {nb} mandate row(s); the seller "
                           f"never holds one.")
            else:
                out.append("mandate: no mandate row on the buyer tape.")
            continue
        if step == "dispute":
            claims = [f"the {p}'s dispute row claims {r['shared'].get('claim')}"
                      + (f" ({r['shared'].get('text')})" if r["shared"].get("text") else "")
                      for p in PARTIES for _, r in by[p]["dispute"]
                      if isinstance(r.get("shared"), dict)]
            out.append("dispute: " + ("; ".join(claims) + "." if claims
                                      else "no dispute row on either tape."))
            continue
        if not nb and not ns_:
            out.append(f"{step}: no {step} row on either tape.")
        elif nb and ns_:
            same = sum(1 for (_, x), (_, y) in zip(B[step], S[step])
                       if x.get("step_digest") == y.get("step_digest"))
            out.append(f"{step}: {nb} row(s) on the buyer tape, {ns_} on the seller tape; "
                       f"{same} pair(s) carry the same digest.")
        else:
            holder, lacker = ("buyer", "seller") if nb else ("seller", "buyer")
            out.append(f"{step}: {max(nb, ns_)} row(s) on the {holder} tape; {lacker} tape "
                       f"holds no {step} row.")
    for _, r in B["commit"]:
        if "inside_mandate" in r:
            v = r["inside_mandate"]
            word = "true" if v is True else "false" if v is False else "null (not checkable)"
            out.append(f"the buyer's commit row records inside_mandate {word}: "
                       f"{r.get('mandate_reason', '')}.")
    # the cancel-before-ship question, by ledger ts (pins bound it when given)
    cancels = [e for e in timeline if e["step"] == "cancel"]
    ships = [e for e in timeline if e["step"] == "ship"]
    if cancels and ships:
        if (B["cancel"] and S["cancel"]
                and max(e["ts"] for e in cancels) < min(e["ts"] for e in ships)):
            out.append("cancel is on both tapes before any ship row.")
        c0, s0 = cancels[0], ships[0]
        m = _minutes(c0["ts"], s0["ts"])
        if m is not None:
            rel = f"{abs(m)} minutes {'after' if m >= 0 else 'before'}"
            pinned = [f"the {e['party']}'s {e['step']} row existed by {e['pinned']}"
                      for e in (c0, s0) if e.get("pinned")]
            how = "by ledger ts; " + ("pinned: " + ", ".join(pinned) if pinned else "not pinned")
            out.append(f"{s0['party']}'s ship row is {rel} {c0['party']}'s cancel row ({how}).")
        for e in ships:
            if e.get("after_cancel") is True:
                out.append(f"the {e['party']}'s ship row records after_cancel true: that tape "
                           f"already held a cancel row when it shipped.")
        for p in PARTIES:
            if by[p]["ship"] and not by[p]["cancel"]:
                out.append(f"{p} tape holds no cancel row.")
    return out


def dispute(deal_id: str, buyer: str | Path, seller: str | Path, *,
            pins: list[dict] | None = None, pin_path: str | Path | None = None,
            buyer_ns: str | None = None, seller_ns: str | None = None) -> DealReport:
    """The deal verdict over the buyer's and the seller's tapes.

    Precedence is `reconcile()`'s: any MISSING / ALTERED finding is the verdict
    (earliest step first, ALTERED before MISSING at the same step), because a
    defect found is a fact even when another part could not be looked at.
    Otherwise any could-not-look makes it COULD NOT LOOK. Only a comparison of
    at least one shared step, with no finding and nothing unlooked-at, is
    MATCHED. Never raises: anything that escapes is COULD NOT LOOK [internal_error].

    Pins: a pin naming `side` "buyer" / "seller" is checked against that tape;
    else one whose `namespace` equals `buyer_ns` / `seller_ns`; with neither
    namespace given, a pin is held against both tapes (reconcile's rule).
    """
    try:
        return _dispute(deal_id, buyer, seller, pins=pins, pin_path=pin_path,
                        buyer_ns=buyer_ns, seller_ns=seller_ns)
    except Exception as e:  # the fence: an answer, not a crash
        why = f"deal dispute could not finish: {type(e).__name__} [internal_error]"
        return DealReport(verdict=_v.COULD_NOT_LOOK, deal=str(deal_id), reason=why,
                          could_not_look=[why])


def _dispute(deal_id, buyer, seller, *, pins, pin_path, buyer_ns, seller_ns) -> DealReport:
    findings: list = []
    cnl: list = []
    checked: list = []
    tapes, mine = {}, {}
    for party, path in (("buyer", buyer), ("seller", seller)):
        tapes[party], mine[party] = _load_side(party, path, deal_id, cnl, findings)

    by = {p: {s: [] for s in STEPS} for p in PARTIES}
    for p in PARTIES:
        for n, row in mine[p]:
            step = row["kind"][5:]
            k = len(by[p][step]) + 1
            if _self_consistent(p, step, k, n, row, findings):
                by[p][step].append((n, row))

    matched = compared = 0
    readable = all(not tapes[p].cnl for p in PARTIES)
    if readable:
        for step in BOTH_SIDES:
            compared += max(len(by["buyer"][step]), len(by["seller"][step]))
            matched += _compare(step, by["buyer"][step], by["seller"][step], findings)
        for step in MIRRORED:
            if by["buyer"][step] and by["seller"][step]:
                compared += max(len(by["buyer"][step]), len(by["seller"][step]))
                matched += _compare(step, by["buyer"][step], by["seller"][step], findings)
        mandates = {r.get("mandate_digest") for _, r in by["buyer"]["mandate"]}
        for k, (n, r) in enumerate(by["seller"]["commit"], start=1):
            md = r["shared"].get("mandate_digest")
            if mandates and md not in mandates:
                findings.append(Finding(_v.ALTERED, f"commit#{k}", "seller",
                                        f"mandate_digest mismatch: the seller's commit (row {n}) "
                                        f"cites {md}, and no mandate row on the buyer tape "
                                        f"holds it", index_side="seller"))
        if not mine["buyer"] and not mine["seller"]:
            cnl.append(f"neither tape holds a row for deal {deal_id}")
        elif not compared:
            cnl.append(f"no step both sides record is on either tape for deal {deal_id}; "
                       f"there was nothing to compare")

    if pin_path is not None:
        try:
            pins = list(pins or []) + _load_pin_file(pin_path)
        except (OSError, ValueError) as e:
            cnl.append(f"pin unreadable: {e}")
        except RecursionError:
            cnl.append("pin unreadable: nested deeper than the JSON reader goes [nesting_too_deep]")
    _check_pins(pins or [], tapes, {"buyer": buyer_ns, "seller": seller_ns},
                findings, cnl, checked)

    timeline = []
    for p in PARTIES:
        for step in STEPS:
            for k, (n, r) in enumerate(by[p][step], start=1):
                e = {"ts": r.get("ts"), "party": p, "step": step, "ordinal": k, "row": n,
                     "step_digest": r.get("step_digest"), "pinned": _pin_bound(p, n, checked)}
                if step == "ship":
                    e["after_cancel"] = r.get("after_cancel")
                timeline.append(e)
    timeline.sort(key=lambda e: (str(e["ts"]), e["party"], e["row"]))

    def _key(f):
        at = str(f.at)
        step, _, k = at.partition("#")
        return (_ORDER.get(step, len(STEPS)), int(k) if k.isdigit() else 0,
                0 if f.verdict == _v.ALTERED else 1)

    findings.sort(key=_key)
    r = DealReport(verdict=_v.MATCHED, deal=str(deal_id), matched=matched,
                   counts={p: len(mine[p]) for p in PARTIES}, findings=findings,
                   could_not_look=cnl, pins_checked=checked, timeline=timeline,
                   position=_position(by, timeline, checked))
    if findings:
        h = findings[0]
        r.verdict, r.at, r.side, r.reason = h.verdict, h.at, h.side, h.reason
    elif cnl:
        r.verdict, r.reason = _v.COULD_NOT_LOOK, cnl[0]
    else:
        r.reason = f"{matched} compared steps on each tape, same digests"
    return r


# -- the pack ---------------------------------------------------------------------

def pack(deal_id: str, buyer: str | Path, seller: str | Path, out_dir: str | Path | None = None,
         *, pins: list[dict] | None = None, pin_path: str | Path | None = None,
         buyer_ns: str | None = None, seller_ns: str | None = None) -> tuple[DealReport, Path]:
    """Write the evidence pack for a person: verdict.json, timeline.md, and this
    deal's rows from each tape (buyer.deal.jsonl, seller.deal.jsonl). Returns
    (report, directory). Nothing in it claims more than the rows show."""
    report = dispute(deal_id, buyer, seller, pins=pins, pin_path=pin_path,
                     buyer_ns=buyer_ns, seller_ns=seller_ns)
    out = Path(out_dir) if out_dir is not None else Path(f"DEAL-{deal_id}")
    out.mkdir(parents=True, exist_ok=True)
    (out / "verdict.json").write_text(json.dumps(report.to_dict(), indent=1, ensure_ascii=False),
                                      encoding="utf-8")
    for party, path in (("buyer", buyer), ("seller", seller)):
        try:
            rows = deal_rows(path, deal_id)
        except OSError:
            rows = []
        (out / f"{party}.deal.jsonl").write_text(
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    (out / "timeline.md").write_text(_timeline_md(report, buyer, seller, pin_path),
                                     encoding="utf-8")
    return report, out


def _timeline_md(r: DealReport, buyer, seller, pin_path) -> str:
    L = [r.verdict, "", f"# Deal {r.deal}", "", r.summary, "", "## Timeline", "",
         "| ts | party | step | row | step_digest | existed by (pin) |", "|---|---|---|---|---|---|"]
    for e in r.timeline:
        L.append(f"| {e['ts']} | {e['party']} | {e['step']} #{e['ordinal']} | {e['row']} | "
                 f"`{e['step_digest']}` | {e['pinned'] or 'not pinned'} |")
    L += ["", "## What the rows show", ""] + [f"- {s}" for s in r.position]
    if r.findings:
        L += ["", "## Findings", ""] + [f"- {f.verdict} at {f.at}: {f.reason}" for f in r.findings]
    if r.could_not_look:
        L += ["", "## Could not look", ""] + [f"- {c}" for c in r.could_not_look]
    L += ["", "## Pins", ""]
    L += ([f"- {c.get('side')} tape, {c.get('rows')} rows, as of {c.get('as_of')}: "
           f"{c.get('result')}" for c in r.pins_checked] or ["- no pin was checked"])
    L += ["", "## What this does not prove", ""] + [f"- {x}" for x in r.limits]
    pins = f" --pins {pin_path}" if pin_path else ""
    L += ["", "## How to check this yourself", "",
          "buyer.deal.jsonl and seller.deal.jsonl hold only this deal's rows; their chain "
          "values link into the full ledgers, so check against the full ledgers. With both "
          "ledgers (and the pin file, if one was used), run:", "",
          f"    arcaeon deal dispute {r.deal} --buyer {buyer} --seller {seller}{pins}", "",
          "and compare its first line with the first line of this file. This is an evidence "
          "pack a person can hand to whoever decides; it records facts, not a ruling.", ""]
    return "\n".join(L)


# -- the CLI ----------------------------------------------------------------------

USAGE = """usage: arcaeon deal <step> ...

A witnessed transaction: each side records the same steps on its own ledger;
`dispute` lines the two tapes up. Steps:
  mandate   <ledger> --merchant M --cap AMOUNT --currency C [--deal ID] [--not-before T]
            [--not-after T] [--may X]... [--may-not X]... [--sealed SIDECAR]   (buyer only)
  commit    <ledger> --deal ID --party buyer|seller --seller M --item SKU:QTY:PRICE...
            --total AMOUNT --currency C [--ship-to TEXT] [--buyer-ref R]
            [--mandate-digest D] [--mandate-sidecar FILE] [--note N]
  pay       <ledger> --deal ID --party P --rail R --reference REF --amount A --currency C
  ship      <ledger> --deal ID [--party seller] --carrier C --tracking T [--at T]
  deliver   <ledger> --deal ID --party P --proof PROOF [--at T]
  cancel    <ledger> --deal ID [--party buyer] --reason TEXT
  dispute   <deal_id> --buyer B --seller S [--pins FILE] [--buyer-ns NS] [--seller-ns NS]
            [--json] [--remote] [--claim CLAIM --by buyer|seller [--text T]]
  pack      <deal_id> --buyer B --seller S [--pins FILE] [-o DIR]
  show      <ledger> --deal ID

dispute / pack exit 0 MATCHED, 1 MISSING or ALTERED, 3 COULD NOT LOOK, 2 bad usage.
The deal lane is new in 0.9.0: --legacy-exit changes nothing here."""

_STEP_CMDS = ("mandate", "commit", "pay", "ship", "deliver", "cancel")


def _parser(cmd: str):
    import argparse
    ap = argparse.ArgumentParser(prog=f"arcaeon deal {cmd}")
    if cmd in _STEP_CMDS or cmd == "show":
        ap.add_argument("ledger")
        ap.add_argument("--deal", required=cmd != "mandate")
    if cmd in ("commit", "pay", "deliver"):
        ap.add_argument("--party", required=True, choices=PARTIES)
    elif cmd in ("ship", "cancel"):
        ap.add_argument("--party", default="seller" if cmd == "ship" else "buyer",
                        choices=PARTIES)
    if cmd == "mandate":
        ap.add_argument("--merchant", required=True)
        ap.add_argument("--cap", required=True)
        ap.add_argument("--currency", required=True)
        ap.add_argument("--not-before")
        ap.add_argument("--not-after")
        ap.add_argument("--may", action="append", default=[])
        ap.add_argument("--may-not", action="append", default=[])
        ap.add_argument("--sealed", help="write the mandate body here; the row keeps its digest")
    elif cmd == "commit":
        ap.add_argument("--seller", required=True)
        ap.add_argument("--item", action="append", required=True, help="SKU:QTY:UNIT_PRICE")
        ap.add_argument("--total", required=True)
        ap.add_argument("--currency", required=True)
        ap.add_argument("--ship-to")
        ap.add_argument("--buyer-ref")
        ap.add_argument("--mandate-digest")
        ap.add_argument("--mandate-sidecar")
        ap.add_argument("--note")
    elif cmd == "pay":
        for a in ("--rail", "--reference", "--amount", "--currency"):
            ap.add_argument(a, required=True)
    elif cmd == "ship":
        ap.add_argument("--carrier", required=True)
        ap.add_argument("--tracking", required=True)
        ap.add_argument("--at")
    elif cmd == "deliver":
        ap.add_argument("--proof", required=True)
        ap.add_argument("--at")
    elif cmd == "cancel":
        ap.add_argument("--reason", required=True)
    elif cmd in ("dispute", "pack"):
        ap.add_argument("deal_id")
        ap.add_argument("--buyer", required=True)
        ap.add_argument("--seller", required=True)
        ap.add_argument("--pins")
        ap.add_argument("--buyer-ns")
        ap.add_argument("--seller-ns")
        if cmd == "dispute":
            ap.add_argument("--json", action="store_true")
            ap.add_argument("--remote", action="store_true")
            ap.add_argument("--claim", choices=CLAIMS)
            ap.add_argument("--by", choices=PARTIES)
            ap.add_argument("--text", default="")
        else:
            ap.add_argument("-o", "--out")
    return ap


def _item(s: str) -> dict:
    sku, qty, price = s.rsplit(":", 2)
    return {"sku": sku, "qty": int(qty), "unit_price": price}


def main(argv: list[str]) -> int:
    argv, _legacy = _v.pop_legacy_flag(argv)       # new verb: no legacy codes to keep
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return _v.EXIT_GOOD if argv else _v.EXIT_USAGE
    cmd, rest = argv[0], argv[1:]
    if cmd not in (*_STEP_CMDS, "dispute", "pack", "show"):
        print(f"arcaeon deal: unknown step {cmd!r}\n\n{USAGE}")
        return _v.EXIT_USAGE
    try:
        a = _parser(cmd).parse_args(rest)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else _v.EXIT_USAGE
    try:
        if cmd in _STEP_CMDS:
            return _step(cmd, a)
        if cmd == "show":
            problem = _show_problem(Path(a.ledger))
            if problem:
                print(f"{_v.COULD_NOT_LOOK}: {problem}")
                return _v.EXIT_COULD_NOT_LOOK
            rows = deal_rows(a.ledger, a.deal)
            if not rows:
                print(f"{_v.COULD_NOT_LOOK}: {a.ledger} holds no row for deal {a.deal}")
                return _v.EXIT_COULD_NOT_LOOK
            for r in rows:
                print(json.dumps(r, ensure_ascii=False))
            return _v.EXIT_GOOD
    except (ValueError, OSError) as e:
        print(f"arcaeon deal {cmd}: {e}")
        return _v.EXIT_USAGE
    if cmd == "pack":
        r, out = pack(a.deal_id, a.buyer, a.seller, a.out, pin_path=a.pins,
                      buyer_ns=a.buyer_ns, seller_ns=a.seller_ns)
        print(r.summary)
        print(f"pack written to {out}")
        return r.exit_code
    if a.claim:
        if not a.by:
            print("arcaeon deal dispute: --claim needs --by buyer|seller")
            return _v.EXIT_USAGE
        try:
            Deal(a.buyer if a.by == "buyer" else a.seller, a.by, a.deal_id).raise_dispute(
                a.claim, a.text)
        except (ValueError, OSError) as e:
            print(f"arcaeon deal dispute: {e}")
            return _v.EXIT_USAGE
    r = dispute(a.deal_id, a.buyer, a.seller, pin_path=a.pins,
                buyer_ns=a.buyer_ns, seller_ns=a.seller_ns)
    if a.json:
        print(json.dumps(r.to_dict(), indent=1, ensure_ascii=False))
    else:
        print(r.summary)
        for s in r.position:
            print(f"  {s}")
    if a.remote:
        # arcaeon.remote.reconcile_tapes takes an agent tape and a tool tape
        # (arcaeon-tape/1 rows); deal rows are not that profile, so nothing is sent.
        import sys
        print("hosted deal verdict not yet available; local verdict above", file=sys.stderr)
    return r.exit_code


def _show_problem(p: Path) -> str | None:
    """Why `deal show` cannot read `p` as a ledger, or None (qa-fixes item 5:
    a missing, directory or binary path printed nothing and exited 0)."""
    if not p.exists():
        return f"ledger not found: {p}"
    if p.is_dir():
        return f"ledger is a directory, not a ledger: {p}"
    try:
        p.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        return f"ledger is not UTF-8 text (a binary file?): {p}"
    except OSError as e:
        return f"ledger cannot be read ({e.strerror or type(e).__name__}): {p}"
    return None


def _step(cmd: str, a) -> int:
    d = Deal(a.ledger, "buyer" if cmd == "mandate" else a.party, a.deal)
    if cmd == "mandate":
        row = d.mandate(merchant=a.merchant, cap=a.cap, currency=a.currency,
                        not_before=a.not_before, not_after=a.not_after, may=a.may,
                        may_not=a.may_not, sealed=a.sealed)
    elif cmd == "commit":
        disclosed = None
        if a.mandate_sidecar:
            disclosed = json.loads(Path(a.mandate_sidecar).read_text(encoding="utf-8")).get("mandate")
        row = d.commit(items=[_item(s) for s in a.item], total=a.total, currency=a.currency,
                       seller=a.seller, ship_to=a.ship_to, buyer_ref=a.buyer_ref,
                       mandate_digest=a.mandate_digest, note=a.note, mandate=disclosed)
    elif cmd == "pay":
        row = d.pay(rail=a.rail, reference=a.reference, amount=a.amount, currency=a.currency)
    elif cmd == "ship":
        row = d.ship(carrier=a.carrier, tracking=a.tracking, at=a.at)
    elif cmd == "deliver":
        row = d.deliver(proof=a.proof, at=a.at)
    else:
        row = d.cancel(reason=a.reason)
    print(json.dumps({"deal": d.id, "row": row}, ensure_ascii=False))
    return _v.EXIT_GOOD
