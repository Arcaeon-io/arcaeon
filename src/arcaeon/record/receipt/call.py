"""Receipted Call: delivery evidence for a paid agent-to-agent call.

Buyer: a small tool or data seller on an agent-payment marketplace (x402,
Nevermined, AgenticMarket) who wants a "verified delivery" signal a buyer
can check without trusting the seller. The gap is named in a competitor's
own docs: the x402 verifier checks the PAYMENT and explicitly does not
verify the service delivered what it promised.

This receipt records digests of the request, the response and the payment
header (if any), in sequence, with timing. Digests only by default: a
receipt that carried the buyer's query and the seller's answer would be a
data leak with a hash on it. It proves that a specific request produced a
specific response at a time; it does not prove the response was right.
"""
from __future__ import annotations

import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from arcaeon.record.ledger import digest_bytes, digest_json

from .core import build_receipt, render_exhibit

KIND = "receipted-call"

SCOPE = {
    "proves": [
        "A request with the recorded digest was received and a response with the recorded digest "
        "was returned, in that order, with the recorded status and elapsed time.",
        "If a payment header was present, its digest was recorded beside the request it paid for.",
    ],
    "does_not_prove": [
        "That the response was correct, complete, or what the listing promised. This is delivery "
        "evidence, not quality evidence.",
        "That the payment settled on any chain or was for the listed price; the payment header is "
        "digested, not verified. Payment verification belongs to the facilitator.",
        "The content of the request or response: only digests are recorded unless raw_payloads was "
        "explicitly enabled by the seller, and the receipt says which.",
    ],
    "method": "sha256 digests of canonical request / response / payment-header bytes, hash-chained "
              "in arcaeon-ledger, one row per call.",
}


def _digest_any(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (bytes, bytearray)):
        return digest_bytes(bytes(v))
    if isinstance(v, str):
        return digest_bytes(v.encode("utf-8"))
    return digest_json(v)


def _payment_header(headers: Optional[dict]) -> Optional[str]:
    if not headers:
        return None
    for k, v in headers.items():
        if str(k).lower() in ("x-payment", "payment-signature", "x-payment-response", "authorization-payment"):
            return str(v)
    return None


def call_receipt(request: dict, response: dict, *, ledger_path: str | Path,
                 namespace: str = "receipted-call", seller: str = "",
                 elapsed_ms: Optional[int] = None, raw_payloads: bool = False,
                 witness: bool = True, anchor: bool = False,
                 error: Optional[str] = None) -> dict:
    """request: {method, url, headers?, body?}; response: {status, headers?, body?}.
    anchor defaults False here: one OTS stamp per $0.30 call is the wrong
    cadence. Batch-anchor the ledger head instead (the witness pin covers it).
    `error` names a transport-level failure (upstream unreachable); the call
    is still receipted, with the failure on the check, because a paid call
    that produced nothing is exactly the one the buyer will ask about."""
    pay = _payment_header(request.get("headers"))
    check = {"method": request.get("method", "GET"), "url": request.get("url", ""),
             "request_digest": _digest_any(request.get("body")),
             "response_status": response.get("status"),
             "response_digest": _digest_any(response.get("body")),
             "payment_header_digest": _digest_any(pay) if pay is not None else None,
             "elapsed_ms": elapsed_ms}
    if error:
        check["upstream_error"] = str(error)[:300]
    if raw_payloads:
        check["request_body"] = request.get("body")
        check["response_body"] = response.get("body")
    subject = {"seller": seller or "(unnamed)", "endpoint": request.get("url", ""),
               "raw_payloads": raw_payloads}
    return build_receipt(KIND, subject, [check], SCOPE, ledger_path=ledger_path,
                         namespace=namespace, witness=witness, anchor=anchor)


def receipted(fn: Callable[..., Any], *, ledger_path: str | Path, namespace: str = "receipted-call",
              seller: str = "") -> Callable[..., Any]:
    """Wrap a handler(request_dict) -> response_dict so every call is receipted.
    Returns (response, receipt). The seam a proxy or an ASGI middleware will
    call; the foundation ships the seam, not the server."""
    def _wrapped(request: dict):
        t0 = time.perf_counter()
        response = fn(request)
        ms = int((time.perf_counter() - t0) * 1000)
        rc = call_receipt(request, response, ledger_path=ledger_path, namespace=namespace,
                          seller=seller, elapsed_ms=ms)
        return response, rc
    return _wrapped


def _line(c: dict) -> str:
    pay = " paid" if c.get("payment_header_digest") else ""
    return (f"{c.get('method')} {c.get('url')} -> {c.get('response_status')} in {c.get('elapsed_ms')}ms{pay}  "
            f"req={str(c.get('request_digest'))[-16:]} resp={str(c.get('response_digest'))[-16:]}")


def exhibit(receipt: dict) -> str:
    return render_exhibit(receipt, title="RECEIPTED CALL", check_line=_line)


# --------------------------------------------------------------------------
# Receipted Phone Call: a different call, a different buyer.
# --------------------------------------------------------------------------
# Buyer: a dispatch/call-taking operation (or anyone downstream of one) that
# needs to prove a call happened -- who (as opaque ids), when, how long, and
# that a specific transcript is the one bound to it -- without the receipt
# itself becoming a second copy of the call to leak. Raw phone numbers and
# transcript TEXT never enter this receipt; only opaque participant ids and
# a transcript hash do.

PHONE_KIND = "receipted-phone-call"

PHONE_SCOPE = {
    "proves": [
        "A call occurred between the recorded participant ids, starting and ending at the recorded "
        "timestamps and lasting the recorded duration, with the recorded transcript hash.",
    ],
    "does_not_prove": [
        "The truth of anything said in the call.",
        "The real-world identity of the humans behind the participant ids.",
        "That consent to the call, or to its recording, was given.",
    ],
    "method": "Opaque participant ids, ISO-8601 start/end timestamps, and a sha256 digest of the "
              "transcript text are recorded in the digested body; the transcript itself, and any raw "
              "phone number, is never carried by this receipt.",
}

# Deliberately conservative: mostly-digit strings (with the usual phone
# punctuation) are refused as participant ids, so a raw number pasted in by
# mistake is caught at build time rather than silently digested into the
# ledger forever.
_PHONE_LIKE = re.compile(r"^\+?[\d\-.\s()]{7,}$")


def _reject_phone_like(participants: list) -> None:
    for p in participants:
        if _PHONE_LIKE.match(str(p).strip()):
            raise ValueError(f"participant id looks like a raw phone number, not an opaque id: {p!r}")


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))


def phone_call_receipt(participants: list, start_time: str, end_time: str, transcript_hash: str, *,
                       ledger_path: str | Path, namespace: str = "receipted-phone-call",
                       extra: Optional[dict] = None, witness: bool = True,
                       anchor: bool = False) -> dict:
    """participants: opaque ids only (never raw phone numbers -- rejected below).
    start_time/end_time: ISO-8601 UTC strings. transcript_hash: a hex digest the
    caller computed over the transcript text; the text itself is never passed in
    or stored here. duration is derived from start/end, not separately asserted,
    so the two can never disagree."""
    if not participants:
        raise ValueError("participants is required (opaque ids, at least one)")
    _reject_phone_like(participants)
    if not transcript_hash or not str(transcript_hash).strip():
        raise ValueError("transcript_hash is required and must not be the transcript text")
    start_dt, end_dt = _parse_iso(start_time), _parse_iso(end_time)
    if end_dt < start_dt:
        raise ValueError("end_time precedes start_time")
    check = {"participants": list(participants), "start_time": start_time, "end_time": end_time,
             "duration_seconds": (end_dt - start_dt).total_seconds(),
             "transcript_hash": str(transcript_hash)}
    subject = {"participant_count": len(participants)}
    return build_receipt(PHONE_KIND, subject, [check], PHONE_SCOPE, ledger_path=ledger_path,
                         namespace=namespace, extra=extra, witness=witness, anchor=anchor)


def _phone_line(c: dict) -> str:
    return (f"{c.get('start_time')} -> {c.get('end_time')} ({c.get('duration_seconds')}s)  "
            f"participants={','.join(c.get('participants') or [])}  "
            f"transcript={str(c.get('transcript_hash'))[-16:]}")


def phone_exhibit(receipt: dict) -> str:
    return render_exhibit(receipt, title="RECEIPTED PHONE CALL", check_line=_phone_line)
