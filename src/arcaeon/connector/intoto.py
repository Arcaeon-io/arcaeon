# SPDX-License-Identifier: MIT
"""arcaeon.connector.intoto: our row, exported as an in-toto Statement v1.

    {
      "_type": "https://in-toto.io/Statement/v1",
      "subject": [{"name": "...", "digest": {"sha256": "<64 hex>"}}],
      "predicateType": "https://arcaeon.io/connector-verdict/v1",
      "predicate": {...}
    }

SUBJECT is what was checked: the artifact the vendor names (with its sha256) when
it names one, else the vendor payload itself, and `predicate.subject_is` says which.

PREDICATE carries exactly one of two verdict keys, never both:
  relayed=True   `relayed_verdict`: a vendor's verdict, in our words, relayed by us
  relayed=False  `verdict`: our own check (statement_for_check)
plus the chain refs (`chain`: ledger name, the row's chain hash, a pin if given).

The bytes are RFC 8785 (JCS) canonical (arcaeon.prove.jcs), so the same statement
is the same bytes in any language, ready for a DSSE envelope with payloadType
MEDIA_TYPE. This module does NOT sign: no key is made or read here. Wrapping
and signing belong to the envelope.

Stdlib only.
"""
from __future__ import annotations

from typing import Any

from arcaeon.prove.jcs import canonicalize
from arcaeon.record.row import RAW_BYTES_PREFIX, loads_strict

from .core import MAX_DEPTH, MAX_PAYLOAD_BYTES, OUR_WORDS, ROW_KIND, _sha256_hex, _too_deep

__all__ = ["STATEMENT_TYPE", "PREDICATE_TYPE", "MEDIA_TYPE", "StatementError", "export_row",
           "statement_for_check", "statement_bytes", "parse_statement"]

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://arcaeon.io/connector-verdict/v1"
#: DSSE payloadType for an in-toto statement.
MEDIA_TYPE = "application/vnd.in-toto+json"

_ROW_KEYS = ("vendor", "vendor_id", "vendor_word", "mapping", "attestation",
             "vendor_payload_digest", "vendor_payload_bytes", "received_at", "could_not_look")


class StatementError(ValueError):
    """Not a statement this predicate type defines. A reader treats it as COULD NOT LOOK."""


def _chain_refs(row_chain: Any, ledger: Any, pin: Any) -> dict:
    return {"ledger": ledger if isinstance(ledger, str) else None,
            "row_chain": row_chain if isinstance(row_chain, str) else None,
            "pin": pin if isinstance(pin, str) else None}


def _statement(subject: list, predicate: dict) -> dict:
    return {"_type": STATEMENT_TYPE, "subject": subject, "predicateType": PREDICATE_TYPE,
            "predicate": predicate}


def export_row(row: dict, *, row_chain: str | None = None, ledger: str | None = None,
               pin: str | None = None) -> dict:
    """A relayed row -> an in-toto Statement (a dict; statement_bytes() for the bytes).
    `row_chain` defaults to the row's own `chain` (a row read back from the ledger)."""
    if not isinstance(row, dict) or row.get("kind") != ROW_KIND:
        raise StatementError("not a check.verdict.relayed row")
    if row.get("relayed") is not True or row.get("checked_by_us") is not False:
        raise StatementError("the row does not say it is relayed; refusing to export it as ours")
    word = row.get("relayed_verdict")
    if word not in OUR_WORDS:
        raise StatementError(f"relayed_verdict {word!r} is not one of {OUR_WORDS}")
    subj = row.get("subject") if isinstance(row.get("subject"), dict) else {}
    vendor = row.get("vendor") if isinstance(row.get("vendor"), dict) else {}
    if _sha256_hex(subj.get("sha256")):
        subject = [{"name": subj.get("name") or "unnamed",
                    "digest": {"sha256": subj["sha256"]}}]
        subject_is = "checked_artifact"
    else:
        pd = row.get("vendor_payload_digest")
        hexpart = pd[len(RAW_BYTES_PREFIX):] if isinstance(pd, str) and pd.startswith(RAW_BYTES_PREFIX) else None
        if not _sha256_hex(hexpart):
            raise StatementError("the row names neither a checked artifact nor a payload digest")
        subject = [{"name": f"vendor-payload:{vendor.get('name')}/{row.get('vendor_id')}",
                    "digest": {"sha256": hexpart}}]
        subject_is = "vendor_payload"
    predicate = {"relayed": True, "checked_by_us": False, "relayed_verdict": word,
                 "subject_is": subject_is}
    for k in _ROW_KEYS:
        if k in row:
            predicate[k] = row[k]
    predicate["chain"] = _chain_refs(row_chain if row_chain is not None else row.get("chain"),
                                     ledger, pin)
    return _statement(subject, predicate)


def statement_for_check(subject_name: str, sha256_hex: str, verdict: str, *,
                        checked_at: str | None = None, row_chain: str | None = None,
                        ledger: str | None = None, pin: str | None = None,
                        detail: dict | None = None) -> dict:
    """Our OWN check's verdict as a statement (relayed=False, key `verdict`)."""
    if verdict not in OUR_WORDS:
        raise StatementError(f"verdict {verdict!r} is not one of {OUR_WORDS}")
    hx = _sha256_hex(sha256_hex)
    if not hx or not isinstance(subject_name, str) or not subject_name:
        raise StatementError("a subject needs a name and a 64-hex sha256")
    predicate = {"relayed": False, "checked_by_us": True, "verdict": verdict,
                 "subject_is": "checked_artifact", "checked_at": checked_at,
                 "chain": _chain_refs(row_chain, ledger, pin)}
    if detail is not None:
        predicate["detail"] = detail
    return _statement([{"name": subject_name, "digest": {"sha256": hx}}], predicate)


def statement_bytes(stmt: dict) -> bytes:
    """RFC 8785 canonical bytes of a statement."""
    return canonicalize(stmt)


def parse_statement(data: Any) -> dict:
    """Read a statement the way an outside tool would, and refuse anything this
    predicate type does not define. Raises StatementError (never anything else)."""
    if isinstance(data, (bytes, bytearray)):
        if len(data) > MAX_PAYLOAD_BYTES:
            raise StatementError("statement over the size limit")
        try:
            data = bytes(data).decode("utf-8")
        except UnicodeDecodeError:
            raise StatementError("statement is not UTF-8") from None
    if isinstance(data, str):
        if len(data) > MAX_PAYLOAD_BYTES:
            raise StatementError("statement over the size limit")
        try:
            data = loads_strict(data)
        except ValueError as e:
            raise StatementError(f"statement is not one unambiguous JSON value: {type(e).__name__}") from None
    if not isinstance(data, dict):
        raise StatementError("statement is not a JSON object")
    if _too_deep(data, MAX_DEPTH):
        raise StatementError("statement nests too deep")
    if data.get("_type") != STATEMENT_TYPE:
        raise StatementError(f"_type is not {STATEMENT_TYPE}")
    if data.get("predicateType") != PREDICATE_TYPE:
        raise StatementError(f"predicateType is not {PREDICATE_TYPE}")
    subject = data.get("subject")
    if not isinstance(subject, list) or not subject:
        raise StatementError("subject must be a non-empty list")
    for s in subject:
        if not isinstance(s, dict) or not isinstance(s.get("name"), str):
            raise StatementError("every subject needs a name")
        dg = s.get("digest")
        if not isinstance(dg, dict) or not _sha256_hex(dg.get("sha256")):
            raise StatementError("every subject needs digest.sha256 (64 hex)")
    pred = data.get("predicate")
    if not isinstance(pred, dict):
        raise StatementError("predicate must be an object")
    relayed = pred.get("relayed")
    if relayed is True:
        if "verdict" in pred or pred.get("relayed_verdict") not in OUR_WORDS:
            raise StatementError("a relayed predicate carries relayed_verdict (one of our words) "
                                 "and no verdict")
        if pred.get("checked_by_us") is not False:
            raise StatementError("a relayed predicate must say checked_by_us false")
    elif relayed is False:
        if "relayed_verdict" in pred or pred.get("verdict") not in OUR_WORDS:
            raise StatementError("our own predicate carries verdict (one of our words) "
                                 "and no relayed_verdict")
    else:
        raise StatementError("predicate.relayed must be true or false")
    if not isinstance(pred.get("chain"), dict):
        raise StatementError("predicate.chain must be an object")
    return data
