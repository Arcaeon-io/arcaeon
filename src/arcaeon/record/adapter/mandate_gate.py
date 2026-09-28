# SPDX-License-Identifier: MIT
"""The mandate gate: is this tool call inside what the agent was allowed to do?

    gate = load("mandate.json")
    verdict, reason = gate.evaluate({"name": "place_order",
                                     "arguments": {"total": "19.00", "currency": "USD"}})
    # verdict is "inside", "outside" or "could_not_look"

Pure and stdlib: `evaluate` reads the call and the mandate and returns an
answer. It writes nothing and blocks nothing. The proxy decides what to do
with the answer (record-only by default; see docs/MANDATE_GATE.md).

A spend is judged by `arcaeon.record.deal.check_mandate`, imported, never
copied: the proxy and the deal lane must never disagree about whether a
purchase was inside the same mandate body.

An optional `spend_cap.total` caps the whole session. The gate keeps the
running total, but only a caller that forwarded a spend adds to it
(`add_spend`): `evaluate` still writes nothing, so asking twice never counts
twice. A spend that would take the total past the cap is outside, rule
`spend_cap.total`, and the proxy writes it as `mandate_cap_exceeded`.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import threading
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

from arcaeon.record.deal import _amount, check_mandate
from arcaeon.record.row import digest_bytes, digest_json

__all__ = ["INSIDE", "OUTSIDE", "COULD_NOT_LOOK", "VERDICTS", "CAP_EXCEEDED_EVT",
           "OUTSIDE_FORWARDED", "BLOCKED", "NEVER_ATTEMPTED", "OUTCOMES",
           "OUTCOME_MEANINGS", "outcome", "MandateGate", "load", "evaluate"]

INSIDE = "inside"
OUTSIDE = "outside"
COULD_NOT_LOOK = "could_not_look"
VERDICTS = (INSIDE, OUTSIDE, COULD_NOT_LOOK)

# What happened to a call, one word per gate row (`outcome`). The verdict says
# what the gate answered; the outcome also says whether the call went through.
OUTSIDE_FORWARDED = "outside_forwarded"
BLOCKED = "blocked"
NEVER_ATTEMPTED = "never_attempted"
OUTCOMES = (INSIDE, OUTSIDE_FORWARDED, BLOCKED, NEVER_ATTEMPTED, COULD_NOT_LOOK)

#: One line per outcome word; `arcaeon mandate explain` prints these.
OUTCOME_MEANINGS = {
    INSIDE: "the gate looked and nothing in the mandate said no; the call went through.",
    OUTSIDE_FORWARDED: "record-only: the gate said no and the call went through anyway.",
    BLOCKED: "enforce: the gate ran and said no, and the call was withheld from the tool.",
    NEVER_ATTEMPTED: "the call never reached the gate's judgment: it was refused before "
                     "the gate, or the mandate file could not be read (`reason` says which).",
    COULD_NOT_LOOK: "the gate ran but something it needed to decide (an amount, a time, "
                    "the call itself) could not be read; never counted as inside.",
}

#: `reason` prefixes on a never_attempted row, naming which of the two it was.
REFUSED_BEFORE_GATE = "refused before the gate: "
GATE_COULD_NOT_RUN = "the gate could not run: "


def outcome(verdict: str, action: str, extra: dict | None = None) -> str:
    """The outcome word for one judged call. `action` is "forwarded" or
    "blocked"; `extra` is the gate's detail dict (its `rule` decides whether
    the gate ran at all)."""
    rule = (extra or {}).get("rule")
    if rule == "mandate_file":
        return NEVER_ATTEMPTED
    if rule == "frame" and action == "blocked":
        return NEVER_ATTEMPTED
    if verdict == INSIDE:
        return INSIDE
    if verdict == OUTSIDE:
        return BLOCKED if action == "blocked" else OUTSIDE_FORWARDED
    return COULD_NOT_LOOK

_AMOUNT_ARGS = ("total", "amount")
_CURRENCY_ARGS = ("currency",)
_MERCHANT_ARGS = ("seller", "merchant")

#: The event a spend past `spend_cap.total` is written as (record-only by default).
CAP_EXCEEDED_EVT = "mandate_cap_exceeded"


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


def _str_list(v: Any, field: str) -> list[str]:
    if v is None:
        return []
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ValueError(f"{field} must be a list of strings")
    return list(v)


def _normalize(obj: Any) -> dict:
    """Mandate file JSON -> the tool-shaped mandate. Raises ValueError on a
    shape the gate cannot read. Accepts the tool shape, a deal-lane mandate
    body, and the deal lane's sealed sidecar (`{"mandate": body, ...}`)."""
    if not isinstance(obj, dict):
        raise ValueError("a mandate is a JSON object")
    if isinstance(obj.get("mandate"), dict) and "mandate_digest" in obj:
        obj = obj["mandate"]                      # deal sealed sidecar
    m: dict = {
        "who": obj.get("who"),
        "allowed_acts": _str_list(obj.get("allowed_acts", obj.get("may")),
                                  "allowed_acts"),
        "forbidden_acts": _str_list(obj.get("forbidden_acts", obj.get("may_not")),
                                    "forbidden_acts"),
        "not_before": obj.get("not_before"),
        "not_after": obj.get("not_after"),
        "spend_cap": None,
    }
    for k in ("not_before", "not_after"):
        if m[k] is not None and _parse_time(m[k]) is None:
            raise ValueError(f"{k} {m[k]!r} is not a readable time")
    cap = obj.get("spend_cap")
    if cap is None and "cap" in obj:              # deal-lane body
        cap = {"amount": obj.get("cap"), "currency": obj.get("currency"),
               "merchant": obj.get("merchant")}
    if cap is not None:
        if not isinstance(cap, dict):
            raise ValueError("spend_cap must be an object")
        total = cap.get("total")
        if total is not None and _amount(total) is None:
            raise ValueError(f"spend_cap.total {total!r} is not a readable amount")
        m["spend_cap"] = {
            "amount": cap.get("amount"),
            "total": total,
            "currency": cap.get("currency"),
            "merchant": cap.get("merchant"),
            "amount_args": _str_list(cap.get("amount_args"), "spend_cap.amount_args")
            or list(_AMOUNT_ARGS),
            "currency_args": _str_list(cap.get("currency_args"), "spend_cap.currency_args")
            or list(_CURRENCY_ARGS),
            "merchant_args": _str_list(cap.get("merchant_args"), "spend_cap.merchant_args")
            or list(_MERCHANT_ARGS),
        }
    return m


class MandateGate:
    """A loaded mandate (or the reason it could not be loaded).

    `status` is "loaded", "missing" or "unreadable". When it is not "loaded",
    every `evaluate` answers could_not_look: a gate that cannot read its
    mandate has not looked, and must never answer inside."""

    def __init__(self, path: str | Path | None, mandate: dict | None = None, *,
                 status: str = "loaded", error: str | None = None,
                 file_sha256: str | None = None, file_digest: str | None = None,
                 body_digest: str | None = None):
        self.path = None if path is None else str(path)
        self.mandate = mandate
        self.status = status
        self.error = error
        self.file_sha256 = file_sha256
        self.file_digest = file_digest
        self.body_digest = body_digest
        #: The session's running spend: the amounts `add_spend` was handed.
        self.spent = Decimal(0)
        self._spent_lock = threading.Lock()

    @property
    def total_cap(self) -> Any:
        """`spend_cap.total` as written in the mandate, or None."""
        return ((self.mandate or {}).get("spend_cap") or {}).get("total")

    def add_spend(self, amount: Any) -> Decimal:
        """Add one forwarded spend to the session total; returns the new total.
        An amount that is not readable adds nothing."""
        d = _amount(amount)
        with self._spent_lock:
            if d is not None:
                self.spent += d
            return self.spent

    @property
    def ok(self) -> bool:
        return self.status == "loaded"

    @property
    def who(self) -> Any:
        return (self.mandate or {}).get("who")

    @classmethod
    def from_dict(cls, obj: dict, path: str | None = None) -> "MandateGate":
        """A gate over an in-memory mandate (tests, library callers)."""
        return cls(path, _normalize(obj), body_digest=digest_json(obj))

    def fingerprint(self) -> dict:
        """The fields `session_begin` carries to pin the mandate in force."""
        return {"mandate": self.path, "mandate_status": self.status,
                "mandate_error": self.error,
                "mandate_file_sha256": self.file_sha256,
                "mandate_file_digest": self.file_digest,
                "mandate_body_digest": self.body_digest,
                "mandate_who": self.who}

    def evaluate(self, tool_call: Any, at: str | None = None) -> tuple[str, str]:
        """(verdict, reason) for one tools/call's params.

        `tool_call` is the JSON-RPC params: {"name": ..., "arguments": {...}}.
        `at` is the call's time (ISO 8601; default now, UTC). `detail()` also
        names the rule that decided."""
        return self.detail(tool_call, at)[:2]

    def detail(self, tool_call: Any, at: str | None = None) -> tuple[str, str, dict]:
        """(verdict, reason, extra): `extra` has `rule`, and on could_not_look
        `looked_for`, `where`, `reason_word` (arcaeon.verdict.REASON_WORDS)."""
        if not self.ok:
            word = "missing" if self.status == "missing" else "unreadable"
            return COULD_NOT_LOOK, f"the mandate could not be read: {self.error}", {
                "rule": "mandate_file", "looked_for": "the mandate",
                "where": self.path or "(no path)", "reason_word": word}
        m = self.mandate or {}
        if not isinstance(tool_call, dict):
            return COULD_NOT_LOOK, "the tools/call params are not an object", {
                "rule": "call", "looked_for": "params", "where": "tools/call",
                "reason_word": "unreadable"}
        name = tool_call.get("name")
        if not isinstance(name, str):
            return COULD_NOT_LOOK, "the tools/call has no readable tool name", {
                "rule": "call", "looked_for": "params.name", "where": "tools/call",
                "reason_word": "name_not_found"}
        for pat in m.get("forbidden_acts") or []:
            if fnmatch.fnmatchcase(name, pat):
                return OUTSIDE, f"tool {name!r} matches forbidden_acts pattern {pat!r}", {
                    "rule": "forbidden_acts"}
        allowed = m.get("allowed_acts") or []
        if allowed and not any(fnmatch.fnmatchcase(name, p) for p in allowed):
            return OUTSIDE, f"tool {name!r} matches no allowed_acts pattern", {
                "rule": "allowed_acts"}
        at = at or _now_iso()
        args = tool_call.get("arguments")
        args = args if isinstance(args, dict) else {}
        cap = m.get("spend_cap")
        amount_key = next((k for k in (cap or {}).get("amount_args", ())
                           if k in args), None) if cap else None
        if cap and amount_key is not None:
            # A spend: the deal lane's own check, on the terms this call carries.
            currency = next((args[k] for k in cap["currency_args"] if k in args), None)
            seller = next((args[k] for k in cap["merchant_args"] if k in args), None)
            per_call = cap.get("amount")
            if per_call is None and cap.get("total") is not None:
                per_call = cap.get("total")      # one call can never spend past the total
            body = {"merchant": cap.get("merchant"), "currency": cap.get("currency"),
                    "cap": per_call, "not_before": m.get("not_before"),
                    "not_after": m.get("not_after")}
            terms = {"seller": seller if cap.get("merchant") is not None else None,
                     "currency": currency if cap.get("currency") is not None else None,
                     "total": args[amount_key]}
            inside, why = check_mandate(body, terms, at)
            spend = _amount(args[amount_key])
            carry = {"spend_amount": str(spend)} if spend is not None else {}
            if inside is True and cap.get("total") is not None:
                total = _amount(cap["total"])
                with self._spent_lock:
                    before = self.spent
                if before + spend > total:
                    return OUTSIDE, (f"spend: {args[amount_key]} would take the session "
                                     f"total from {before} to {before + spend}, over the "
                                     f"mandate's total {cap['total']}"), {
                        "rule": "spend_cap.total", "evt": CAP_EXCEEDED_EVT,
                        "session_spent_before": str(before),
                        "session_total_cap": str(cap["total"]), **carry}
            if inside is True:
                return INSIDE, f"spend: {why}", {"rule": "spend_cap", **carry}
            if inside is False:
                return OUTSIDE, f"spend: {why}", {"rule": "spend_cap", **carry}
            return COULD_NOT_LOOK, f"spend: {why}", {
                "rule": "spend_cap",
                "looked_for": getattr(why, "looked_for", amount_key),
                "where": getattr(why, "where", "arguments"),
                "reason_word": getattr(why, "reason_word", "unreadable")}
        when = _parse_time(at)
        if when is None:
            return COULD_NOT_LOOK, f"call time {at!r} is not a readable time", {
                "rule": "window", "looked_for": "call time", "where": "the proxy clock",
                "reason_word": "unreadable"}
        nb, na = _parse_time(m.get("not_before")), _parse_time(m.get("not_after"))
        if nb and when < nb:
            return OUTSIDE, f"call at {at} is before the mandate's not_before " \
                            f"{m['not_before']}", {"rule": "window"}
        if na and when > na:
            return OUTSIDE, f"call at {at} is after the mandate's not_after " \
                            f"{m['not_after']}", {"rule": "window"}
        return INSIDE, f"tool {name!r} is allowed and the call is inside the window", {
            "rule": "acts"}


def load(path: str | Path | None) -> MandateGate:
    """Load a mandate file. Never raises: a missing or unreadable file comes back
    as a gate whose status says so, and every evaluation through it is
    could_not_look."""
    if path is None or str(path) == "":
        return MandateGate(None, status="missing", error="no mandate path given")
    p = Path(path)
    try:
        data = p.read_bytes()
    except FileNotFoundError:
        return MandateGate(p, status="missing", error=f"no file at {p}")
    except OSError as e:
        return MandateGate(p, status="unreadable", error=f"{type(e).__name__}: {e}")
    sha = hashlib.sha256(data).hexdigest()
    fp = {"file_sha256": sha, "file_digest": digest_bytes(data)}
    try:
        obj = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        return MandateGate(p, status="unreadable",
                           error=f"not JSON: {type(e).__name__}", **fp)
    try:
        mandate = _normalize(obj)
        body = digest_json(obj)
    except ValueError as e:
        return MandateGate(p, status="unreadable", error=str(e), **fp)
    return MandateGate(p, mandate, body_digest=body, **fp)


def evaluate(mandate: MandateGate | dict | str | Path, tool_call: Any,
             at: str | None = None) -> tuple[str, str]:
    """Module-level shortcut: a gate, a mandate dict, or a path."""
    if isinstance(mandate, MandateGate):
        gate = mandate
    elif isinstance(mandate, dict):
        try:
            gate = MandateGate.from_dict(mandate)
        except ValueError as e:
            gate = MandateGate(None, status="unreadable", error=str(e))
    else:
        gate = load(mandate)
    return gate.evaluate(tool_call, at)
