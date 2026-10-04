# SPDX-License-Identifier: MIT
"""arcaeon.prove.x402_ext: the labeled-exchange envelope on an x402 V2 paid
response, and the buyer's check before an escrow rule releases (TE-24).

    from arcaeon.prove import x402_ext as X
    paid = X.attach(settlement_response, envelope)          # seller side
    c = X.check(paid, body_bytes, "buyer-agent-7", "pay",   # buyer side
                signers=["did:key:z6Mk..."], deal="d-7f3a")
    c.release        # True only on VERIFIED with the settlement saying success
    c.decision       # the gate's GateDecision (allow / refuse, the three words)

WHERE IT RIDES. x402 V2 puts a `SettlementResponse` on the paid response
(HTTP: the base64 `PAYMENT-RESPONSE` header; MCP: `_meta["x402/payment-
response"]`; A2A: an entry of `x402.payment.receipts`). Its optional
`extensions` object maps an extension id to `{"info": ..., "schema": ...}`.
This module puts the envelope at

    extensions["labeled-exchange"].info.envelope

and the sidecar object goes there unchanged. docs/X402.md has the sources.

THE CHECK. `check` writes the body bytes and the carried envelope to a
throwaway directory and calls `arcaeon.prove.gate.decide` on them: the one
verifier (envelope.verify) decides; this module never checks a byte itself.
A missing or malformed extension reaches verify as a missing or unreadable
sidecar, so it reads COULD NOT LOOK there, never VERIFIED.

`release` is True only when the action is `pay` or `act`, the gate allowed
it (so the verdict was VERIFIED), and the settlement response says
`"success": true`. BROKEN: no release, and with a deal id the gate's
evidence pack is written (plus the settlement response as received).
COULD NOT LOOK: no release; the hold stays.

THE MOCK RAIL. `MockEscrowRail` is in memory and test-only: nothing is held
or moved, there is no network and no key. A refusal never refunds by itself:
whether money goes back is the human's decision.

Stdlib only. `attach` raises ValueError on a bad argument; `check` raises
only on an action other than `pay` or `act` and otherwise always answers.
"""
from __future__ import annotations

import base64
import binascii
import copy
import json
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from arcaeon import verdict as V
from arcaeon.prove import envelope as E
from arcaeon.prove import gate as G
from arcaeon.record.row import loads_strict

__all__ = ["EXTENSION_KEY", "INFO_FIELD", "SCHEMA", "RELEASE_ACTIONS", "X402Check",
           "MockEscrowRail", "attach", "check", "encode_header", "decode_header",
           "HELD", "RELEASED"]

#: the extension id, kebab-case like the spec's own (`offer-receipt`,
#: `payment-identifier`); the name of the envelope's predicate.
EXTENSION_KEY = "labeled-exchange"
#: the field under `info` that holds the sidecar object. Never `bundle`.
INFO_FIELD = "envelope"
RELEASE_ACTIONS = ("pay", "act")
#: the most a header value or raw JSON response is read (bytes).
MAX_RESPONSE_BYTES = 2 * E.MAX_ENVELOPE_BYTES
BODY_NAME = "paid-response.body"

#: JSON Schema for `info`, as x402 V2 asks every extension to carry. A reader
#: does not check against it: verify does the checking.
SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        INFO_FIELD: {
            "type": "object",
            "properties": {
                "mediaType": {"type": "string", "const": E.MEDIA_TYPE},
                "dsseEnvelope": {
                    "type": "object",
                    "properties": {
                        "payloadType": {"type": "string", "const": E.PAYLOAD_TYPE},
                        "payload": {"type": "string"},
                        "signatures": {"type": "array", "items": {
                            "type": "object",
                            "properties": {"keyid": {"type": "string"},
                                           "sig": {"type": "string"}},
                            "required": ["keyid", "sig"]}},
                    },
                    "required": ["payloadType", "payload", "signatures"],
                    "additionalProperties": False,
                },
            },
            "required": ["mediaType", "dsseEnvelope"],
            "additionalProperties": False,
        },
    },
    "required": [INFO_FIELD],
}

LIMITS = [
    "release means the paid body's bytes are the bytes the key you named sealed, labeled "
    "for you, for this deal when you gave one, and in date; not that they are true or safe",
    "the x402 settlement fields (success, transaction, payer) are read as the seller sent "
    "them; nothing here checks a chain or a facilitator",
    "the mock rail holds and moves nothing; a refusal never refunds by itself",
]

_FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


# --- the wire --------------------------------------------------------------------

def encode_header(obj: dict) -> str:
    """A SettlementResponse as the base64 `PAYMENT-RESPONSE` header value."""
    return base64.b64encode(json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
                            .encode("utf-8")).decode("ascii")


def decode_header(value: str | bytes) -> dict:
    """The SettlementResponse in a header value (base64 JSON) or raw JSON.
    ValueError when it is not one JSON object (duplicate keys included)."""
    raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError(f"over {MAX_RESPONSE_BYTES} bytes; not read")
    text = raw.strip()
    if not text.startswith(b"{"):
        try:
            text = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("neither base64 nor a JSON object") from None
    try:
        obj = loads_strict(text.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        raise ValueError(f"not one JSON object ({type(e).__name__})") from None
    if not isinstance(obj, dict):
        raise ValueError("not a JSON object")
    return obj


# --- seller side -----------------------------------------------------------------

def attach(response: dict, envelope: dict | str | Path, *, replace: bool = False) -> dict:
    """A copy of `response` (a SettlementResponse) with the envelope under
    extensions["labeled-exchange"].info.envelope. `envelope` is the sidecar
    object or its path. ValueError on a bad argument or an extension already
    there (unless `replace`)."""
    if not isinstance(response, dict):
        raise ValueError("response must be a SettlementResponse object")
    if not isinstance(envelope, dict):
        try:
            envelope = loads_strict(Path(envelope).read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, ValueError, TypeError) as e:
            raise ValueError(f"cannot read the envelope ({type(e).__name__})") from None
    if not isinstance(envelope, dict) or envelope.get("mediaType") != E.MEDIA_TYPE:
        raise ValueError(f"envelope must be an arcaeon envelope ({E.MEDIA_TYPE})")
    out = copy.deepcopy(response)
    ext = out.setdefault("extensions", {})
    if not isinstance(ext, dict):
        raise ValueError("response.extensions is not an object")
    if EXTENSION_KEY in ext and not replace:
        raise ValueError(f"response already carries extensions[{EXTENSION_KEY!r}]")
    ext[EXTENSION_KEY] = {"info": {INFO_FIELD: copy.deepcopy(envelope)},
                          "schema": copy.deepcopy(SCHEMA)}
    return out


# --- buyer side ------------------------------------------------------------------

@dataclass
class X402Check:
    """One check of a paid response. `decision` is the gate's GateDecision;
    `release` is what the escrow rule may do; `extension` says what was found
    under the extension key ("present", "missing" or "malformed")."""
    release: bool
    decision: G.GateDecision
    extension: str
    reason: str
    settled: bool
    deal: str | None = None
    evidence: str | None = None
    limits: list = field(default_factory=lambda: list(LIMITS))

    @property
    def verdict(self) -> str:
        return self.decision.verdict

    def to_dict(self) -> dict:
        return {"release": self.release, "verdict": self.verdict,
                "decision": self.decision.to_dict(), "extension": self.extension,
                "reason": self.reason, "settled": self.settled, "deal": self.deal,
                "evidence": self.evidence, "limits": list(self.limits)}


def _extract(response: Any) -> tuple[dict | None, Any, str, str]:
    """(response object, envelope object, extension state, why)."""
    if isinstance(response, (str, bytes, bytearray)):
        try:
            response = decode_header(response)
        except ValueError as e:
            return None, None, "malformed", f"the payment response cannot be read: {e}"
    if not isinstance(response, dict):
        return None, None, "malformed", "the payment response is not a JSON object"
    ext = response.get("extensions")
    if ext is None or (isinstance(ext, dict) and EXTENSION_KEY not in ext):
        return response, None, "missing", (f"the paid response carries no "
                                           f"extensions[{EXTENSION_KEY!r}]")
    if not isinstance(ext, dict):
        return response, None, "malformed", "the response's extensions is not an object"
    entry = ext[EXTENSION_KEY]
    info = entry.get("info") if isinstance(entry, dict) else None
    if not isinstance(info, dict) or INFO_FIELD not in info:
        return response, None, "malformed", (f"extensions[{EXTENSION_KEY!r}] has no "
                                             f"info.{INFO_FIELD}")
    return response, info[INFO_FIELD], "present", ""


def check(response: Any, file_bytes: bytes, audience: str | None, action: str, *,
          signers=(), deal: str | None = None, purpose: str | None = None,
          record_dir: str | Path | None = None, file_name: str | None = None,
          now=None) -> X402Check:
    """Run the gate on a paid response before an escrow rule releases.

    `response` is the SettlementResponse (a dict, the base64 header value, or
    raw JSON); `file_bytes` the paid body; `audience` the buyer's own id;
    `action` "pay" or "act". `signers`, `deal`, `purpose` and `record_dir` go
    to gate.decide unchanged. ValueError on another action; otherwise never
    raises."""
    if action not in RELEASE_ACTIONS:
        raise ValueError(f"action must be one of {RELEASE_ACTIONS}, got {action!r}")
    try:
        obj, env, state, why = _extract(response)
    except Exception as e:  # noqa: BLE001  hostile input: an answer, never a traceback
        obj, env, state, why = None, None, "malformed", f"the response could not be read ({type(e).__name__})"
    name = file_name if isinstance(file_name, str) and _FILE_NAME.fullmatch(file_name) \
        and ".." not in file_name else BODY_NAME
    with tempfile.TemporaryDirectory(prefix="arcaeon-x402-") as tmp:
        body = Path(tmp) / name
        side = Path(tmp) / (name + E.SUFFIX)
        if isinstance(file_bytes, (bytes, bytearray, memoryview)):
            body.write_bytes(bytes(file_bytes))
        else:
            why = (why + "; " if why else "") + "the paid body is not bytes"
        if env is not None:
            try:
                side.write_text(json.dumps(env, ensure_ascii=False, allow_nan=False),
                                encoding="utf-8", newline="\n")
            except Exception as e:  # noqa: BLE001  not JSON-writable: the sidecar stays missing
                state = "malformed"
                why = f"info.{INFO_FIELD} is not JSON ({type(e).__name__})"
        d = G.decide(body, envelope=side, action=action, audience=audience, signers=signers,
                     deal=deal, purpose=purpose, record_dir=record_dir, now=now)
    settled = isinstance(obj, dict) and obj.get("success") is True
    release = bool(d.allowed and d.verdict == V.VERIFIED and settled and state == "present")
    if d.evidence and obj is not None:
        try:
            (Path(d.evidence) / "x402-settlement-response.json").write_text(
                json.dumps(obj, indent=1, ensure_ascii=False, allow_nan=False) + "\n",
                encoding="utf-8", newline="\n")
        except Exception:  # noqa: BLE001  the refusal stands either way
            pass
    if release:
        reason = f"release: {d.reason}"
    elif d.allowed and not settled:
        reason = ("hold: the settlement response does not say success: true, so there is "
                  f"nothing to release. {d.reason}")
    elif d.verdict == V.BROKEN:
        reason = f"do not release: {d.reason}"
    else:
        reason = f"hold: {why + '. ' if why else ''}{d.reason}"
    return X402Check(release=release, decision=d, extension=state, reason=reason,
                     settled=settled, deal=deal, evidence=d.evidence)


# --- the mock rail ---------------------------------------------------------------

HELD, RELEASED = "HELD", "RELEASED"


class MockEscrowRail:
    """In-memory, test-only escrow. MOCK RAIL: nothing is held or moved, no
    network, no keys. A hold is RELEASED only on a check whose `release` is
    True and that was run with this hold's deal id; anything else leaves it
    HELD and logs why. It never refunds: that
    is the human's call, made outside this object."""

    def __init__(self) -> None:
        self.holds: dict[str, dict] = {}
        self.log: list[dict] = []

    def hold(self, deal: str, amount: str, currency: str) -> dict:
        if deal in self.holds:
            raise ValueError(f"deal {deal!r} already has a hold")
        h = {"deal": deal, "amount": str(amount), "currency": str(currency), "state": HELD,
             "evidence": None}
        self.holds[deal] = h
        self.log.append({"deal": deal, "event": "hold", "state": HELD})
        return dict(h)

    def state(self, deal: str) -> str | None:
        h = self.holds.get(deal)
        return h["state"] if h else None

    def settle(self, deal: str, result: X402Check) -> dict:
        h = self.holds.get(deal)
        if h is None:
            self.log.append({"deal": deal, "event": "settle", "state": None,
                             "why": "no hold for this deal"})
            return {"deal": deal, "state": None, "released": False}
        if h["state"] == RELEASED:
            self.log.append({"deal": deal, "event": "settle", "state": RELEASED,
                             "why": "already released; not released twice"})
            return {"deal": deal, "state": RELEASED, "released": False}
        # the check must have held the envelope to this very deal: a release on
        # a check run without --deal could be a replay from another exchange
        ok = isinstance(result, X402Check) and result.release is True and result.deal == deal
        if ok:
            h["state"] = RELEASED
        elif isinstance(result, X402Check) and result.evidence:
            h["evidence"] = result.evidence
        verdict = result.verdict if isinstance(result, X402Check) else None
        self.log.append({"deal": deal, "event": "settle", "state": h["state"],
                         "verdict": verdict,
                         "why": result.reason if isinstance(result, X402Check) else "no check"})
        return {"deal": deal, "state": h["state"], "released": ok, "verdict": verdict}
