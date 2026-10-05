# SPDX-License-Identifier: MIT
"""arcaeon.connector.sentinelone: a SentinelOne alert export becomes relayed check
rows, one per alert, on the one adapter base (arcaeon.connector.core.VendorAdapter).

THE SOURCE. The shape is the Unified Alert Management (UAM) GraphQL alert as
SentinelOne's own public, MIT-licensed client reads it (read for Batch 200 L2-09,
2026-10-05; read only, nothing signed up for, nothing sent):

  https://github.com/Sentinel-One/purple-mcp/blob/main/src/purple_mcp/libs/alerts/models.py
  https://github.com/Sentinel-One/purple-mcp/blob/main/src/purple_mcp/libs/alerts/client.py

Not OCSF: the public OCSF-to-UAM code SentinelOne publishes (Sentinel-One/ai-siem)
is for alerts going IN to SentinelOne, with its own class 99602001, not an
export; and Amazon Security Lake lists SentinelOne as a subscriber only, its doc
behind a sign-in. The Management API threats list has no public reference.

THE FORMAT this reads, any one of:

    {"data": {"alerts": {"edges": [{"node": ALERT, "cursor"}], "pageInfo",
                         "totalCount"}}}                  -> "uam-graphql-alerts"
    {"alerts": {...}} or {"edges": [...]} (the same, unwrapped)
    {"data": {"alert": ALERT}} or {"alert": ALERT}         -> "uam-graphql-alert"
    [ALERT, ...]                                           -> "uam-alert-list"
    ALERT                                                  -> "uam-alert"

    ALERT = {id, externalId, severity, status, name, description, detectedAt,
             firstSeenAt, lastSeenAt, analystVerdict, classification,
             confidenceLevel, dataSources, detectionSource {product, vendor},
             asset {id, name, type}, assignee, noteExists, result, storylineId,
             ticketId}
    status          NEW | IN_PROGRESS | RESOLVED | FALSE_POSITIVE
    analystVerdict  TRUE_POSITIVE_* (14 values) | FALSE_POSITIVE_* (5) | UNDEFINED

Signing: the source shows no signature on an alert or a response. Treated as
unsigned (unconfirmed for any other export path). Every row is
signed_by_vendor False, standing "reported_by_sender", whatever the body claims.

THE WORD. An alert carries no pass or fail of its own, so the adapter writes its
own word (as the OPA and agent-scan adapters do):

    true_positive            analystVerdict TRUE_POSITIVE_*                -> BROKEN
    false_positive           analystVerdict FALSE_POSITIVE_*, or no
                             verdict and status FALSE_POSITIVE             -> COULD NOT LOOK
    no_verdict               verdict null or UNDEFINED, status NEW,
                             IN_PROGRESS, RESOLVED or absent               -> COULD NOT LOOK
    verdict_status_conflict  TRUE_POSITIVE_* with status FALSE_POSITIVE    -> COULD NOT LOOK
    unknown_verdict          a verdict not in the enum, or not a string    -> COULD NOT LOOK
    unknown_status           no verdict and a status not in the enum       -> COULD NOT LOOK

Nothing maps to VERIFIED: an alert export lists what fired, and nothing in it
says a check ran clean. A false positive is the analyst saying the alert was
wrong, not that the thing was scanned and passed. TRUE_POSITIVE_BENIGN is still
BROKEN: the analyst confirmed the detection, and a relayed confirmation is not
ours to downgrade. Mitigation: the source documents no mitigation field on an
alert (`result` is a free string with no documented values), so mitigated or
blocked is not read; `result` is kept verbatim, cut to 256 characters.

THE ROW. The check.verdict.relayed row of arcaeon.connector.core, plus:

    signed_by_vendor   False. Always.
    standing           "reported_by_sender". Always.
    input_sha256       hex SHA-256 of the exact bytes read (None when given no bytes)
    vendor_request_id  the caller's `vendor_request_id`, else None
    at                 the alert's detectedAt (not parsed, not checked), or None
    detection          {format, index, alert_id, external_id, name, severity,
                        status, analyst_verdict, classification, confidence_level,
                        detected_at, asset_id, asset_type, detection_product,
                        detection_vendor, storyline_id, result, ignored_keys}
    vendor_id          the alert id
    subject            {"name": "sentinelone:alert/<id>", "sha256": None}
    attestation        always NONE

Host names, descriptions, assignees and data sources are not copied.
`standing_verdict(rows)` (also `rollup`) is BROKEN when any row relays BROKEN,
otherwise COULD NOT LOOK. Never VERIFIED. `recheck` says COULD NOT LOOK (one body,
many rows); re-run `ingest`. Never raises on what is sent. Stdlib only. No network.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from arcaeon.record.row import loads_strict
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, could_not_look

from .core import (ATTESTATION_NONE, AdapterError, Extracted, VendorAdapter, _now_iso,
                   _safe_str, _too_deep, register)

__all__ = ["VENDOR", "ADAPTER_VERSION", "TABLE", "MAX_PAYLOAD_BYTES", "MAX_DEPTH", "MAX_ROWS",
           "STANDING", "SOURCE_URLS", "TRUE_POSITIVE", "FALSE_POSITIVE", "STATUSES",
           "SentinelOneAdapter", "SENTINELONE", "ingest", "standing_verdict", "rollup"]

VENDOR = "sentinelone"
ADAPTER_VERSION = "1"
#: A body over this is digested, never read.
MAX_PAYLOAD_BYTES = 8 << 20
MAX_DEPTH = 32
#: More alerts than this in one body: the rest are not read, and a row says so.
MAX_ROWS = 10000
STANDING = "reported_by_sender"
SOURCE_URLS = (
    "https://github.com/Sentinel-One/purple-mcp/blob/main/src/purple_mcp/libs/alerts/models.py",
    "https://github.com/Sentinel-One/purple-mcp/blob/main/src/purple_mcp/libs/alerts/client.py",
)

TRUE_POSITIVE = frozenset("TRUE_POSITIVE_" + s for s in (
    "ADVANCED_PERSISTENT_THREAT", "BENIGN", "BENIGN_BUT_SUSPICIOUS", "DATA_EXFILTRATION",
    "DENIAL_OF_SERVICE", "EXPLOITATION_TOOLS", "INSIDER_THREAT", "MALWARE", "PHISHING_ATTACK",
    "POLICY_VIOLATION", "PUA_ADWARE", "RANSOMWARE", "UNAUTHORIZED_ACCESS", "UNDEFINED"))
FALSE_POSITIVE = frozenset("FALSE_POSITIVE_" + s for s in (
    "BENIGN", "BENIGN_BUT_SUSPICIOUS", "SYSTEM_ERROR", "UNDEFINED", "USER_ERROR"))
STATUSES = frozenset(("NEW", "IN_PROGRESS", "RESOLVED", "FALSE_POSITIVE"))

TABLE = {
    "true_positive": BROKEN,
    "false_positive": COULD_NOT_LOOK,
    "no_verdict": COULD_NOT_LOOK,
    "verdict_status_conflict": COULD_NOT_LOOK,
    "unknown_verdict": COULD_NOT_LOOK,
    "unknown_status": COULD_NOT_LOOK,
}

_WHERE = "SentinelOne alert export"
_WHY = {
    "false_positive": ("missing", "the analyst marked the alert a false positive; that says "
                                  "the alert was wrong, not that a check ran clean"),
    "no_verdict": ("missing", "the alert has no analyst verdict yet"),
    "verdict_status_conflict": ("unreadable", "the verdict says true positive and the status "
                                              "says false positive"),
    "unknown_verdict": ("name_not_found", "the analyst verdict is not one this adapter's "
                                          "source documents"),
    "unknown_status": ("name_not_found", "the status is not one this adapter's source "
                                         "documents"),
}
_KNOWN = ("id", "externalId", "severity", "status", "name", "description", "detectedAt",
          "firstSeenAt", "lastSeenAt", "analystVerdict", "classification", "confidenceLevel",
          "dataSources", "detectionSource", "asset", "assignee", "noteExists", "result",
          "storylineId", "ticketId")


class SentinelOneAdapter(VendorAdapter):
    """SentinelOne alert export on the one adapter base. One body, many rows: read
    it with `ingest`, not import_verdict (whose `extract` path refuses it)."""
    name = VENDOR
    version = ADAPTER_VERSION
    table = TABLE
    max_payload_bytes = MAX_PAYLOAD_BYTES
    max_depth = MAX_DEPTH
    one_row_per_payload = False

    def extract(self, doc: dict) -> Extracted:
        raise AdapterError("a SentinelOne alert export is one row per alert; read it with "
                           "arcaeon.connector.sentinelone.ingest")


SENTINELONE = register(SentinelOneAdapter())


def _copy(row: dict) -> dict:
    return json.loads(json.dumps(row))


def _cnl(row: dict, looked_for: str, where: str, reason_word: str, reason: str) -> dict:
    return SENTINELONE.mark_could_not_look(row, looked_for, where, reason_word, reason)


def _base(raw: bytes | None, at: str, req: str | None) -> dict:
    row = SENTINELONE.base_row(raw, at)
    row["input_sha256"] = hashlib.sha256(raw).hexdigest() if raw is not None else None
    row["vendor_request_id"] = req
    row["at"] = None
    row["detection"] = None
    return row


def _word(verdict: Any, status: Any) -> str:
    v = verdict.strip().upper() if isinstance(verdict, str) else verdict
    s = status.strip().upper() if isinstance(status, str) else status
    if v is not None and not isinstance(v, str):
        return "unknown_verdict"
    if v in TRUE_POSITIVE:
        return "verdict_status_conflict" if s == "FALSE_POSITIVE" else "true_positive"
    if v in FALSE_POSITIVE:
        return "false_positive"
    if v is None or v == "UNDEFINED":
        if s == "FALSE_POSITIVE":
            return "false_positive"
        if s is None or s in STATUSES:
            return "no_verdict"
        return "unknown_status"
    return "unknown_verdict"


def _sub(node: dict, key: str, field: str) -> str | None:
    d = node.get(key)
    return _safe_str(d.get(field)) if isinstance(d, dict) else None


def _alert_row(base: dict, i: int, node: Any, fmt: str) -> dict:
    row = _copy(base)
    where = f"{_WHERE} alert[{i}]"
    if not isinstance(node, dict):
        return _cnl(row, "an alert object", where, "unreadable", "the alert is not an object")
    aid = _safe_str(node.get("id"))
    det = {
        "format": fmt, "index": i, "alert_id": aid,
        "external_id": _safe_str(node.get("externalId")), "name": _safe_str(node.get("name")),
        "severity": _safe_str(node.get("severity")), "status": _safe_str(node.get("status")),
        "analyst_verdict": _safe_str(node.get("analystVerdict")),
        "classification": _safe_str(node.get("classification")),
        "confidence_level": _safe_str(node.get("confidenceLevel")),
        "detected_at": _safe_str(node.get("detectedAt")),
        "asset_id": _sub(node, "asset", "id"), "asset_type": _sub(node, "asset", "type"),
        "detection_product": _sub(node, "detectionSource", "product"),
        "detection_vendor": _sub(node, "detectionSource", "vendor"),
        "storyline_id": _safe_str(node.get("storylineId")),
        "result": _safe_str(node.get("result")),
        "ignored_keys": sorted(s for s in (_safe_str(k) for k in node if k not in _KNOWN)
                               if s is not None)[:16],
    }
    row["detection"] = det
    row["at"] = det["detected_at"]
    if not aid:
        return _cnl(row, "the alert id", where, "missing", "the alert has no string id")
    row["vendor_id"] = aid
    row["subject"] = {"name": f"{VENDOR}:alert/{aid}", "sha256": None}
    word = _word(node.get("analystVerdict"), node.get("status"))
    row["vendor_word"] = word
    row["mapping"] = {"rule": "table"}
    row["relayed_verdict"] = TABLE[word]
    if TABLE[word] == COULD_NOT_LOOK:
        _cnl(row, "an alert this adapter can read as a finding", where, *_WHY[word])
    return row


def _nodes(doc: Any) -> tuple[str, list] | None:
    """(format, alerts) or None when the body is not an alert export shape."""
    if isinstance(doc, list):
        return "uam-alert-list", doc
    if not isinstance(doc, dict):
        return None
    d = doc["data"] if isinstance(doc.get("data"), dict) else doc
    conn = d.get("alerts") if isinstance(d.get("alerts"), dict) else d
    if isinstance(conn.get("edges"), list):
        return "uam-graphql-alerts", [e.get("node") if isinstance(e, dict) else e
                                      for e in conn["edges"]]
    if "alert" in d:
        return "uam-graphql-alert", ([] if d["alert"] is None else [d["alert"]])
    if "id" in doc and ("analystVerdict" in doc or "status" in doc):
        return "uam-alert", [doc]
    return None


def _read(raw: Any, at: str, req: str | None) -> list:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogatepass")
    if isinstance(raw, bytearray):
        raw = bytes(raw)
    if not isinstance(raw, bytes):
        return [_cnl(_base(None, at, req), "SentinelOne alert JSON bytes", "argument",
                     "unreadable", f"the body is a {type(raw).__name__}, not bytes")]
    base = _base(raw, at, req)
    if not raw:
        return [_cnl(base, "SentinelOne alert JSON", _WHERE, "empty", "the body is empty")]
    if len(raw) > MAX_PAYLOAD_BYTES:
        return [_cnl(base, "SentinelOne alert JSON", _WHERE, "bounded",
                     f"body is {len(raw)} bytes, over the {MAX_PAYLOAD_BYTES}-byte limit; "
                     f"digested, not read")]
    try:
        doc = loads_strict(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        return [_cnl(base, "SentinelOne alert JSON", _WHERE, "unreadable",
                     f"body is not one unambiguous UTF-8 JSON value: {type(e).__name__}")]
    if _too_deep(doc, MAX_DEPTH):
        return [_cnl(base, "SentinelOne alert JSON", _WHERE, "unreadable",
                     f"body nests deeper than {MAX_DEPTH}")]
    found = _nodes(doc)
    if found is None:
        why = ("the response carries GraphQL errors and no alerts"
               if isinstance(doc, dict) and doc.get("errors") else
               "the JSON is not a SentinelOne alert export shape")
        return [_cnl(base, "a SentinelOne alert list or alert", _WHERE, "name_not_found", why)]
    fmt, nodes = found
    if not nodes:
        return [_cnl(base, "an alert", _WHERE, "empty", "the export lists no alerts")]
    rows = []
    for i, node in enumerate(nodes):
        if i >= MAX_ROWS:
            rows.append(_cnl(_copy(base), "every alert in the export", _WHERE, "bounded",
                             f"more than {MAX_ROWS} alerts; the rest were not read"))
            break
        rows.append(_alert_row(base, i, node, fmt))
    return rows


def _seal(rows: list) -> list:
    """The one final step over every row: this adapter's, unsigned, reported by the
    sender, no attestation. The table holds no VERIFIED, so a VERIFIED here is a bug
    and reads COULD NOT LOOK."""
    for r in rows:
        r["vendor"] = {"name": VENDOR, "adapter_version": ADAPTER_VERSION}
        r["attestation"] = {"status": ATTESTATION_NONE, "checked_by_us": False, "claimed": None}
        for k in ("input_sha256", "vendor_request_id", "at", "detection"):
            r.setdefault(k, None)
        if r.get("relayed_verdict") not in (BROKEN, COULD_NOT_LOOK):
            _cnl(r, "a SentinelOne finding", _WHERE, "unreadable",
                 "a SentinelOne alert row cannot relay VERIFIED")
        r["signed_by_vendor"] = False
        r["standing"] = STANDING
    return rows


def ingest(raw: Any, *, vendor_request_id: Any = None, received_at: str | None = None) -> list:
    """A SentinelOne alert export (the bytes as read) -> a list of relayed rows, one
    per alert. `vendor_request_id`: an id the caller holds from the transport, if
    any. Never raises on the body; an unreadable body is one COULD NOT LOOK row."""
    req = _safe_str(vendor_request_id)
    at = received_at if isinstance(received_at, str) else _now_iso()
    try:
        rows = _read(raw, at, req)
    except Exception as e:  # noqa: BLE001 - never a traceback on what is sent
        rows = [_cnl(_base(None, at, req), "SentinelOne alert JSON", _WHERE, "unreadable",
                     f"the adapter failed: {type(e).__name__}")]
    return _seal(rows)


def standing_verdict(rows: Any) -> dict:
    """What these rows can say on their own. BROKEN when any of this adapter's rows
    relays BROKEN; otherwise COULD NOT LOOK. Never VERIFIED: unsigned rows reported
    by the sender cannot make a VERIFIED, and nothing in an alert export says a
    check ran clean. Never raises."""
    ours = []
    if isinstance(rows, (list, tuple)):
        ours = [r for r in rows if isinstance(r, dict) and isinstance(r.get("vendor"), dict)
                and r["vendor"].get("name") == VENDOR]
    broken = any(r.get("relayed_verdict") == BROKEN for r in ours)
    out = {"relayed_verdict": BROKEN if broken else COULD_NOT_LOOK, "rows": len(ours),
           "signed_by_vendor": False, "standing": STANDING}
    if broken:
        out["reason"] = "SentinelOne relayed at least one true-positive alert (unsigned)"
    else:
        out.update(could_not_look(
            "a check of our own or a signed vendor verdict", "rows",
            "missing" if ours else "empty",
            "SentinelOne alert rows are unsigned and reported by the sender; they cannot "
            "make a VERIFIED" if ours else "no SentinelOne rows were given"))
    return out


#: The same function under the name the reported adapter uses.
rollup = standing_verdict
