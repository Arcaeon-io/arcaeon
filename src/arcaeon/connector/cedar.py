# SPDX-License-Identifier: MIT
"""arcaeon.connector.cedar: a Cedar authorization decision becomes relayed check
rows on the one adapter base (arcaeon.connector.core.VendorAdapter).

THE FORMATS, as the research note records them (no live capture was read):

    cedar       the cedar-policy library's is_authorized Response, as JSON:
                {"decision": "Allow" | "Deny",
                 "diagnostics": {"reason": [policy id, ...], "errors": [...]}}
    avp         an Amazon Verified Permissions IsAuthorized response:
                {"decision": "ALLOW" | "DENY",
                 "determiningPolicies": [{"policyId": ...}], "errors": [{"errorDescription": ...}]}
                (the AWS docs also show "PolicyId" capitalised; both are read, one per item).
                Empty determiningPolicies on DENY is an implicit deny.
    cloudtrail  one CloudTrail data event for IsAuthorized / BatchIsAuthorized:
                requestParameters {principal, action, resource, policyStoreId},
                responseElements null, additionalEventData {decision} or, for a
                batch, additionalEventData {results: [{request, decision}]},
                requestID, eventID, eventName. It carries NO determiningPolicies and
                NO errors: it says that a decision happened, not which policy made it.

A body is one JSON object of exactly one of these shapes. A JSON array, a Cedar CLI
text line, or an object of no shape or two shapes is one COULD NOT LOOK row.

THE WORD. The decision word (strip + casefold) is read by this table:

    allow  -> VERIFIED   only when the errors list is present and empty
    deny   -> BROKEN     whatever the errors list says

A Deny is the verdict: present and empty, present with errors, not reported
(CloudTrail, or the key is missing), not a list, or a policy list that cannot be
read, it is BROKEN, and `cedar.reason` says which ("Cedar denied", then any of
those notes; a missing errors list adds none). For an Allow, per row:

    errors present (any count)  -> COULD NOT LOOK  Cedar skips a policy that errors, so
                                   the Allow was reached without it
    errors not reported         -> COULD NOT LOOK  the shape has no errors list (CloudTrail,
                                   or the key is missing), so a clean Allow cannot be told
                                   from one reached with policies skipped
    unreadable policy or error lists -> COULD NOT LOOK

COULD NOT LOOK for any decision only when the decision itself cannot be read:
absent, null, not a string, or a word other than Allow / Deny.

The adapter's per-row reading is `cedar.outcome`: allow | deny | errored |
errors_not_reported | unknown_decision | unreadable (errored, errors_not_reported
and unreadable are an Allow's only; a Deny is always `deny`). vendor_word is the
decision exactly as written.

THE ROW. The check.verdict.relayed row of arcaeon.connector.core, plus:

    cedar        shape, item_index, outcome, policy_ids (at most MAX_POLICY_IDS, or None
                 when the shape carries none), policy_ids_total, implicit_deny,
                 errors_reported, errors_count, errors_digest (sha256:jcs:v1 of the errors
                 list; the error text is not copied), event_name, event_id,
                 request_digest (sha256:jcs:v1 of the CloudTrail request; principal,
                 action and resource are not copied), reason (a Deny's reason text,
                 else None)
    policy_ref   {policy_store_id, policy_store_source ("payload" | "caller" | None),
                 policy_ids, version: None, join: COULD NOT LOOK, note}
    signed_by_vendor  False. Always.
    standing          "reported_by_sender". Always.
    input_sha256      hex SHA-256 of the exact bytes given to ingest (None if not bytes)

    vendor_id    the CloudTrail requestID, else None (the responses carry no id)
    subject      {"name": "cedar:request", "sha256": hex of request_digest} for a
                 CloudTrail row, else None
    attestation  always NONE: Cedar and AVP do not sign decisions; a field in the
                 payload that looks like a signature is not read

The last three keys are written by ONE final step (`_seal`) over every row ingest
returns, after which only a clean Allow can be VERIFIED. `ingest` takes no argument
that changes them. `rollup` over these rows is never VERIFIED.

`recheck` says COULD NOT LOOK for these rows (one payload, many rows); re-run
`ingest` with the same bytes to compare. Never raises on what is sent. Stdlib only.
No network, no AWS call: this reads bytes you already hold.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from arcaeon.record.row import loads_strict
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED, could_not_look

from .core import (ATTESTATION_NONE, JCS_DIGEST_PREFIX, AdapterError, Extracted,
                   VendorAdapter, _now_iso, _safe_str, _too_deep, map_word, register, rollup_rows)

__all__ = ["VENDOR", "ADAPTER_VERSION", "TABLE", "SHAPES", "MAX_PAYLOAD_BYTES", "MAX_DEPTH",
           "MAX_ROWS", "MAX_POLICY_IDS", "STANDING", "CedarDecisionAdapter", "CEDAR",
           "ingest", "rollup"]

VENDOR = "cedar"
ADAPTER_VERSION = "1"
#: A body over this is digested, never read.
MAX_PAYLOAD_BYTES = 8 << 20
#: CloudTrail requests nest entities; leave room.
MAX_DEPTH = 64
#: More batch results than this in one body: the rest are not read, and a row says so.
MAX_ROWS = 10000
#: Policy ids copied per row; policy_ids_total says how many there were.
MAX_POLICY_IDS = 64
#: What every row of this adapter is: the sender's report, not a signed one.
STANDING = "reported_by_sender"
SHAPES = ("cedar", "avp", "cloudtrail")

TABLE = {"allow": VERIFIED, "deny": BROKEN}

_WHERE = "Cedar decision"
_POLICY_NOTE = ("the decision names policy ids only; which signed policy text they were "
                "needs the policy set sealed too, and that join is not built, so this row "
                "cannot be tied to a sealed policy")


class CedarDecisionAdapter(VendorAdapter):
    """Cedar / Verified Permissions decisions on the one adapter base. One body, one
    or many rows: read it with `ingest`, not import_verdict (whose `extract` refuses it)."""
    name = VENDOR
    version = ADAPTER_VERSION
    table = TABLE
    max_payload_bytes = MAX_PAYLOAD_BYTES
    max_depth = MAX_DEPTH
    one_row_per_payload = False

    def extract(self, doc: dict) -> Extracted:
        raise AdapterError("a Cedar decision is read with arcaeon.connector.cedar.ingest")


CEDAR = register(CedarDecisionAdapter())

_cnl = CEDAR.mark_could_not_look


def _copy(row: dict) -> dict:
    return json.loads(json.dumps(row))


def _digest(v: Any) -> str | None:
    try:
        return CEDAR.digest(v)
    except Exception:  # noqa: BLE001 - a value JCS refuses has no digest
        return None


class _Bad(Exception):
    """A list in the decision cannot be read; the message is the reason."""


def _cedar_ids(v: Any) -> list:
    if not isinstance(v, list):
        raise _Bad("diagnostics.reason is not a list of policy ids")
    if not all(isinstance(x, str) for x in v):
        raise _Bad("diagnostics.reason holds an id that is not a string")
    return v


def _avp_ids(v: Any) -> list:
    if not isinstance(v, list):
        raise _Bad("determiningPolicies is not a list")
    out = []
    for x in v:
        if not isinstance(x, dict):
            raise _Bad("a determiningPolicies entry is not an object")
        got = [x[k] for k in ("policyId", "PolicyId") if k in x]
        if len(got) != 1 or not isinstance(got[0], str):
            raise _Bad("a determiningPolicies entry has no single string policyId")
        out.append(got[0])
    return out


def _classify(doc: dict) -> list:
    """The shapes the object's keys point at; exactly one is readable."""
    has = {"cedar": "diagnostics" in doc,
           "avp": "determiningPolicies" in doc or "errors" in doc,
           "cloudtrail": "additionalEventData" in doc}
    return [s for s in SHAPES if has[s]]


def _row(base: dict, shape: str, idx: int, where: str) -> dict:
    row = _copy(base)
    row["cedar"] = {"shape": shape, "item_index": idx, "outcome": "unreadable",
                    "policy_ids": None, "policy_ids_total": None, "implicit_deny": None,
                    "errors_reported": False, "errors_count": None, "errors_digest": None,
                    "event_name": None, "event_id": None, "request_digest": None,
                    "reason": None}
    row["policy_ref"] = {"policy_store_id": None, "policy_store_source": None,
                         "policy_ids": None, "version": None, "join": COULD_NOT_LOOK,
                         "note": _POLICY_NOTE}
    return row


def _decide(row: dict, where: str, decision: Any, ids: Any, errors: Any,
            errors_key: bool, bad: str | None) -> dict:
    """Fill the word and the verdict. `ids` is a list or None (shape carries none)."""
    c = row["cedar"]
    ours, rule = map_word(CEDAR, decision)
    row["vendor_word"] = _safe_str(decision)
    row["mapping"] = {"rule": rule}
    row["relayed_verdict"] = ours
    if isinstance(ids, list):
        c["policy_ids"] = [_safe_str(x) for x in ids[:MAX_POLICY_IDS]]
        c["policy_ids_total"] = len(ids)
        row["policy_ref"]["policy_ids"] = list(c["policy_ids"])
    c["errors_reported"] = errors_key and isinstance(errors, list)
    if isinstance(errors, list):
        c["errors_count"] = len(errors)
        c["errors_digest"] = _digest(errors)
    word = decision.strip().casefold() if isinstance(decision, str) else None
    if rule == "table" and isinstance(ids, list):
        c["implicit_deny"] = word == "deny" and not ids
    if rule != "table":
        c["outcome"] = "unknown_decision"
        row["could_not_look"] = could_not_look(
            "a decision word this adapter's table holds (Allow or Deny)", where,
            "name_not_found",
            f"decision {row['vendor_word']!r} is not in the cedar table" if rule == "unknown_word"
            else "the decision is not a word")
    elif word == "deny":
        # The decision IS the verdict: a Deny is BROKEN whatever the lists say.
        # What they say (or that they are missing) goes into the reason only.
        c["outcome"] = "deny"
        notes = []
        if bad:
            notes.append(bad)
        if errors_key and not isinstance(errors, list):
            notes.append("errors is not a list")
        elif errors:
            notes.append(f"{len(errors)} policy evaluation error(s) reported; those "
                         f"policies were skipped")
        c["reason"] = "; ".join(["Cedar denied"] + notes)
    elif bad:
        c["outcome"] = "unreadable"
        _cnl(row, "a readable Cedar decision", where, "unreadable", bad)
    elif errors_key and not isinstance(errors, list):
        c["outcome"] = "unreadable"
        _cnl(row, "an errors list", where, "unreadable", "errors is not a list")
    elif not c["errors_reported"]:
        c["outcome"] = "errors_not_reported"
        _cnl(row, "the list of policy evaluation errors", where, "missing",
             "this decision carries no errors list, so a clean decision cannot be told "
             "from one reached with erroring policies skipped")
    elif errors:
        c["outcome"] = "errored"
        _cnl(row, "a decision reached with no policy errors", where, "unreadable",
             f"{len(errors)} policy evaluation error(s) reported; the decision was reached "
             f"with those policies skipped")
    else:
        c["outcome"] = word
    return row


def _response_row(base: dict, doc: dict, shape: str) -> dict:
    row = _row(base, shape, 0, _WHERE)
    bad, ids, errors, errors_key = None, None, None, False
    try:
        if shape == "cedar":
            diag = doc["diagnostics"]
            if not isinstance(diag, dict):
                raise _Bad("diagnostics is not an object")
            if "reason" not in diag:
                raise _Bad("diagnostics has no reason list")
            ids = _cedar_ids(diag["reason"])
            errors_key, errors = "errors" in diag, diag.get("errors")
        else:
            if "determiningPolicies" not in doc:
                raise _Bad("the response has no determiningPolicies")
            ids = _avp_ids(doc["determiningPolicies"])
            errors_key, errors = "errors" in doc, doc.get("errors")
    except _Bad as e:
        bad = str(e)
        if shape == "cedar" and isinstance(doc.get("diagnostics"), dict):
            errors_key, errors = "errors" in doc["diagnostics"], doc["diagnostics"].get("errors")
        elif shape == "avp":
            errors_key, errors = "errors" in doc, doc.get("errors")
        ids = None
    return _decide(row, _WHERE, doc.get("decision"), ids, errors, errors_key, bad)


def _cloudtrail_rows(base: dict, doc: dict) -> list:
    ad = doc["additionalEventData"]
    rp = doc.get("requestParameters") if isinstance(doc.get("requestParameters"), dict) else {}
    store = _safe_str(rp.get("policyStoreId"))
    top = _row(base, "cloudtrail", 0, _WHERE)
    top["vendor_id"] = _safe_str(doc.get("requestID"))
    top["cedar"]["event_name"] = _safe_str(doc.get("eventName"))
    top["cedar"]["event_id"] = _safe_str(doc.get("eventID"))
    if store:
        top["policy_ref"]["policy_store_id"] = store
        top["policy_ref"]["policy_store_source"] = "payload"
    where = "CloudTrail additionalEventData"
    if not isinstance(ad, dict):
        return [_cnl(top, "additionalEventData.decision", where, "name_not_found",
                     "additionalEventData is not an object")]
    if "decision" in ad and "results" in ad:
        return [_cnl(top, "one decision or one results list", where, "unreadable",
                     "additionalEventData holds both decision and results")]

    def one(i: int, decision: Any, request: Any, w: str) -> dict:
        row = _copy(top)
        row["cedar"]["item_index"] = i
        rd = _digest(request) if request is not None else None
        row["cedar"]["request_digest"] = rd
        if rd:
            row["subject"] = {"name": "cedar:request", "sha256": rd[len(JCS_DIGEST_PREFIX):]}
        return _decide(row, w, decision, None, None, False, None)

    if "decision" in ad:
        return [one(0, ad["decision"], doc.get("requestParameters"), where)]
    if "results" not in ad:
        return [_cnl(top, "additionalEventData.decision or .results", where, "name_not_found",
                     "the event carries no decision")]
    res = ad["results"]
    if not isinstance(res, list):
        return [_cnl(top, "additionalEventData.results[]", where, "name_not_found",
                     f"results is a JSON {type(res).__name__}, not an array")]
    if not res:
        return [_cnl(top, "a batch result", where, "empty", "the batch lists no results")]
    rows = []
    for i, item in enumerate(res):
        if len(rows) >= MAX_ROWS:
            rows.append(_cnl(_copy(top), "every batch result", where, "bounded",
                             f"more than {MAX_ROWS} results; the rest were not read"))
            break
        w = f"{where}.results[{i}]"
        if not isinstance(item, dict):
            row = _copy(top)
            row["cedar"]["item_index"] = i
            rows.append(_cnl(row, "a batch result object", w, "unreadable",
                             "the result is not a JSON object"))
            continue
        rows.append(one(i, item.get("decision"), item.get("request"), w))
    return rows


def _read(raw: Any, at: str) -> list:
    if not isinstance(raw, bytes):
        return [_cnl(CEDAR.base_row(None, at), "Cedar decision bytes", "argument",
                     "unreadable", f"payload is a {type(raw).__name__}, not bytes")]
    base = CEDAR.base_row(raw, at)
    if not raw:
        return [_cnl(base, "a Cedar decision", _WHERE, "empty", "the body is empty")]
    if len(raw) > MAX_PAYLOAD_BYTES:
        return [_cnl(base, "a Cedar decision", _WHERE, "bounded",
                     f"body is {len(raw)} bytes, over the {MAX_PAYLOAD_BYTES}-byte limit; "
                     f"digested, not read")]
    try:
        doc = loads_strict(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        return [_cnl(base, "a Cedar decision JSON object", _WHERE, "unreadable",
                     f"body is not one unambiguous UTF-8 JSON value: {type(e).__name__}")]
    if _too_deep(doc, MAX_DEPTH):
        return [_cnl(base, "a Cedar decision JSON object", _WHERE, "unreadable",
                     f"body nests deeper than {MAX_DEPTH}")]
    if not isinstance(doc, dict):
        return [_cnl(base, "a Cedar decision JSON object", _WHERE, "name_not_found",
                     f"body is a JSON {type(doc).__name__}, not one decision object")]
    found = _classify(doc)
    if len(found) != 1:
        why = ("no Cedar, Verified Permissions or CloudTrail decision shape" if not found
               else f"the body matches more than one shape: {', '.join(found)}")
        return [_cnl(base, "one Cedar decision shape", _WHERE, "name_not_found", why)]
    if found[0] == "cloudtrail":
        return _cloudtrail_rows(base, doc)
    return [_response_row(base, doc, found[0])]


def _apply_store(rows: list, store: str | None) -> None:
    if store is None:
        return
    for r in rows:
        p = r.get("policy_ref")
        if not isinstance(p, dict):
            continue
        if p.get("policy_store_id") is None:
            p["policy_store_id"], p["policy_store_source"] = store, "caller"
        elif p["policy_store_id"] != store:
            _cnl(r, "one policy store id", _WHERE, "unreadable",
                 "the caller's policy_store_id differs from the one in the event")


def _clean_allow(r: dict) -> bool:
    w, c = r.get("vendor_word"), r.get("cedar")
    return (isinstance(w, str) and w.strip().casefold() == "allow"
            and r.get("mapping", {}).get("rule") == "table" and isinstance(c, dict)
            and c.get("outcome") == "allow" and c.get("errors_reported") is True
            and c.get("errors_count") == 0 and "could_not_look" not in r)


def _seal(rows: list, raw: bytes | None) -> list:
    """The one final step: every row is unsigned, reported by the sender, and pinned
    to the exact input bytes. Only a clean Allow can leave VERIFIED; a Deny never can."""
    sha = hashlib.sha256(raw).hexdigest() if isinstance(raw, bytes) else None
    for r in rows:
        r["attestation"] = {"status": ATTESTATION_NONE, "checked_by_us": False, "claimed": None}
        if r.get("relayed_verdict") == VERIFIED and not _clean_allow(r):
            _cnl(r, "a clean Allow", _WHERE, "unreadable",
                 f"only an Allow with an empty errors list can relay as VERIFIED; "
                 f"{r.get('vendor_word')!r} cannot")
        r["signed_by_vendor"] = False
        r["standing"] = STANDING
        r["input_sha256"] = sha
    return rows


def ingest(raw: Any, *, received_at: str | None = None,
           policy_store_id: str | None = None) -> list:
    """A Cedar Response, a Verified Permissions IsAuthorized response, or one
    CloudTrail IsAuthorized / BatchIsAuthorized event, as the bytes you hold -> a
    list of relayed rows (one, or one per batch result). Never raises on the body;
    an unreadable body is one COULD NOT LOOK row. Every row is signed_by_vendor
    False, standing reported_by_sender.

    `policy_store_id`: the store the caller sent the request to (the responses do
    not name it). Recorded as the caller's; a CloudTrail event naming a different
    store makes the row COULD NOT LOOK. Not a string, or empty: ValueError (a caller
    error, not vendor input)."""
    if policy_store_id is not None and (not isinstance(policy_store_id, str)
                                        or not policy_store_id):
        raise ValueError("policy_store_id must be a non-empty string or None")
    at = received_at if isinstance(received_at, str) else _now_iso()
    data = None
    try:
        if isinstance(raw, str):
            raw = raw.encode("utf-8", "surrogatepass")
        if isinstance(raw, bytearray):
            raw = bytes(raw)
        data = raw if isinstance(raw, bytes) else None
        rows = _read(raw, at)
        _apply_store(rows, _safe_str(policy_store_id))
    except Exception as e:  # noqa: BLE001 - never a traceback on what is sent
        rows = [_cnl(CEDAR.base_row(data, at), "a Cedar decision", _WHERE,
                     "unreadable", f"the adapter failed: {type(e).__name__}")]
    return _seal(rows, data)


def rollup(rows: Any) -> dict:
    """The one rollup (core.rollup_rows, docs/CONNECTOR_ADAPTER.md "The rollup"):
    BROKEN when any of this adapter's rows relays BROKEN with the vendor word 'deny';
    otherwise COULD NOT LOOK, with the per-word counts. Never VERIFIED: unsigned
    rows reported by the sender cannot make a VERIFIED by themselves. No bare
    `verdict` key. Rows not from this adapter are not counted. Never raises."""
    return rollup_rows(rows, VENDOR, label='Cedar decision', standing=STANDING,
                       broken_words=('deny',),
                       broken_reason='Cedar reported at least one Deny (relayed, unsigned)')
