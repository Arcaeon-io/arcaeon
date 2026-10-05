# SPDX-License-Identifier: MIT
"""arcaeon.connector.hiddenlayer: HiddenLayer alerts become relayed check rows, one
per alert, on the one adapter base (arcaeon.connector.core.VendorAdapter).

THE FORMAT, as HiddenLayer's public docs show it (read 2026-10-05, no account):

  https://docs.hiddenlayer.ai/docs/integrations/webhook_integrations.md
      ("Data Formats": the four data sources a webhook can deliver)
  https://docs.hiddenlayer.ai/docs/products/runtime/agentic/policy_outcomes.md
      (field meanings and enums for a runtime policy outcome)

  Runtime Security Convictions  {conviction_id, conviction_timestamp,
      detection_category, engine_name, mitre: {Tactic, Technique}, severity,
      source ("aidr"), tactic, technique, sensor_id, tenant_id, requester_id, ...}
      A conviction is "when HiddenLayer has determined that a malicious event, or
      set of malicious events, has taken place".
  Supply Chain Scans  {scan_result_summary: {scan_id, status, severity,
      detection_count, file_count, files_with_detections_count,
      detection_categories, scan_error, start_time, end_time, inventory, signing,
      version, summary: {detection_count, file_count, severity,
      files_with_detections_count, detection_categories, files_failed_to_scan,
      unknown_files}}}
  Runtime Policy Outcomes  {manifest: {event_id, event_at, correlation_id,
      schema_name "com.hiddenlayer.runtime_security.runtime_policy_outcome_v1",
      ...}, policy_id, session_id, interaction_id, evaluation: {action
      (DETECT | REDACT | BLOCK), highest_threat_level (NONE | LOW | MEDIUM | HIGH |
      CRITICAL)}, detections: [{name}]}. Emitted only when a policy takes action.
  Audit Logs  {action, actor_type, occurred_at, ...}: not an alert.

SIGNING. The webhook page documents custom headers (for the receiver's own auth)
and a TLS-verification toggle, and no payload signature, HMAC or signing key. So:
unsigned as far as the public docs show; we found no signing scheme to check
(UNCONFIRMED that none exists). The scan summary's `signing` field is about the
scanned MODEL's signature, not the alert's, and is not read.

THE WORD. HiddenLayer writes no pass/fail word, so the adapter writes its own:

    conviction                       a runtime security conviction      -> BROKEN
    scan_detections                  scan done, detection_count > 0      -> BROKEN
    scan_clean                       scan done, every count says 0
                                     detections, 0 failed, 0 unknown
                                     files, file_count > 0, no error,
                                     no severity                         -> VERIFIED
    scan_incomplete                  done, but any of the above missing,
                                     not a count, or not clean           -> COULD NOT LOOK
    policy_block                     action BLOCK                        -> BROKEN
    policy_detect / policy_redact    DETECT / REDACT with a detection    -> BROKEN
    policy_action_without_detection  DETECT / REDACT, no detection named -> COULD NOT LOOK
    unknown_action                   any other action word               -> COULD NOT LOOK
    unknown_status                   scan status other than "done"       -> COULD NOT LOOK
    unknown_severity                 severity or threat level outside
                                     the documented words                -> COULD NOT LOOK
    not_an_alert                     an audit log, another schema, or no
                                     known shape                         -> COULD NOT LOOK

Known severities (convictions, scans): low, medium, high (the Detections page
names these three). Known threat levels (policy outcomes): the five above.
Anything else, including "critical" on a conviction, reads COULD NOT LOOK.

THE ROW. The check.verdict.relayed row of arcaeon.connector.core, plus:

    signed_by_vendor   False. Always. No argument or payload field sets it.
    standing           "reported_by_sender". Always.
    input_sha256       hex SHA-256 of the exact bytes received (None when not bytes)
    vendor_request_id  the alert's own id (conviction_id, scan_id, manifest.event_id)
    vendor_id          the same
    at                 when HiddenLayer says it happened, as written, or None
    alert              {source, index, id, severity, status, action, threat_level,
                        detection_category, detection_names, detection_count,
                        file_count, files_failed_to_scan, unknown_files,
                        scan_error_present, mitre_technique, engine_name, schema_name}
    subject            {"name": "hiddenlayer:<source>/<id>", "sha256": None}
    attestation        always NONE

Requester ids, tenant, sensor, session and project ids, inventory and model names
are not copied.

`standing_verdict(rows)` (also `rollup`): BROKEN when any of these rows relays
BROKEN, otherwise COULD NOT LOOK. Never VERIFIED: unsigned rows reported by the
sender cannot make a VERIFIED by themselves. `recheck` says COULD NOT LOOK for
these rows; re-run `ingest`. Never raises on what is sent. Stdlib only. No
network: this reads bytes you already hold.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from arcaeon.record.row import loads_strict
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED, could_not_look

from .core import (ATTESTATION_NONE, ROW_KIND, AdapterError, Extracted, VendorAdapter, _now_iso,
                   _safe_str, _too_deep, register)

__all__ = ["VENDOR", "ADAPTER_VERSION", "TABLE", "MAX_PAYLOAD_BYTES", "MAX_DEPTH", "MAX_ROWS",
           "STANDING", "SEVERITIES", "THREAT_LEVELS", "POLICY_SCHEMA", "HiddenLayerAdapter",
           "HIDDENLAYER", "ingest", "standing_verdict", "rollup"]

VENDOR = "hiddenlayer"
ADAPTER_VERSION = "1"
#: A body over this is digested, never read.
MAX_PAYLOAD_BYTES = 8 << 20
MAX_DEPTH = 32
#: More alerts than this in one body: the rest are not read, and a row says so.
MAX_ROWS = 1000
STANDING = "reported_by_sender"
SEVERITIES = ("low", "medium", "high")
THREAT_LEVELS = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
POLICY_SCHEMA = "com.hiddenlayer.runtime_security.runtime_policy_outcome_v1"

TABLE = {
    "conviction": BROKEN,
    "scan_detections": BROKEN,
    "scan_clean": VERIFIED,
    "scan_incomplete": COULD_NOT_LOOK,
    "policy_block": BROKEN,
    "policy_detect": BROKEN,
    "policy_redact": BROKEN,
    "policy_action_without_detection": COULD_NOT_LOOK,
    "unknown_action": COULD_NOT_LOOK,
    "unknown_status": COULD_NOT_LOOK,
    "unknown_severity": COULD_NOT_LOOK,
    "not_an_alert": COULD_NOT_LOOK,
}

_WHERE = "hiddenlayer alert"
_WHY = {
    "scan_incomplete": ("missing", "the scan does not show every file scanned with no detection"),
    "policy_action_without_detection": ("missing", "the policy acted with no detection named "
                                                   "(an always-fire condition)"),
    "unknown_action": ("name_not_found", "the policy action is not DETECT, REDACT or BLOCK"),
    "unknown_status": ("name_not_found", "the scan status is not the documented \"done\""),
    "unknown_severity": ("name_not_found", "the severity is not one of the documented words"),
    "not_an_alert": ("name_not_found", "the body is not a conviction, scan or policy outcome"),
}


class HiddenLayerAdapter(VendorAdapter):
    """HiddenLayer alerts on the one adapter base. Read with `ingest`, not
    import_verdict (whose `extract` refuses it)."""
    name = VENDOR
    version = ADAPTER_VERSION
    table = TABLE
    max_payload_bytes = MAX_PAYLOAD_BYTES
    max_depth = MAX_DEPTH
    one_row_per_payload = False

    def extract(self, doc: dict) -> Extracted:
        raise AdapterError("a HiddenLayer alert is read with arcaeon.connector.hiddenlayer.ingest")


HIDDENLAYER = register(HiddenLayerAdapter())


def _seal(row: dict) -> dict:
    """Applied last to every row this module returns: this adapter's, unsigned,
    reported by the sender. There is no other code path."""
    row["vendor"] = {"name": VENDOR, "adapter_version": ADAPTER_VERSION}
    row["attestation"] = {"status": ATTESTATION_NONE, "checked_by_us": False, "claimed": None}
    row.setdefault("input_sha256", None)
    row.setdefault("vendor_request_id", None)
    row.setdefault("at", None)
    row.setdefault("alert", None)
    row["signed_by_vendor"] = False
    row["standing"] = STANDING
    return row


def _copy(row: dict) -> dict:
    return json.loads(json.dumps(row))


def _cnl(row: dict, looked_for: str, where: str, reason_word: str, reason: str) -> dict:
    return HIDDENLAYER.mark_could_not_look(row, looked_for, where, reason_word, reason)


def _count(v: Any) -> int | None:
    return v if type(v) is int and v >= 0 else None


def _word(v: Any) -> str | None:
    return v.strip().casefold() if isinstance(v, str) else None


def _blank(source: str | None, index: int) -> dict:
    return {"source": source, "index": index, "id": None, "severity": None, "status": None,
            "action": None, "threat_level": None, "detection_category": None,
            "detection_names": None, "detection_count": None, "file_count": None,
            "files_failed_to_scan": None, "unknown_files": None, "scan_error_present": None,
            "mitre_technique": None, "engine_name": None, "schema_name": None}


def _set(row: dict, word: str, where: str, why: str | None = None) -> dict:
    row["vendor_word"] = word
    row["mapping"] = {"rule": "table"}
    row["relayed_verdict"] = TABLE[word]
    a = row.get("alert")
    if isinstance(a, dict) and a.get("source"):
        row["subject"] = {"name": f"{VENDOR}:{a['source']}/{a.get('id') or ''}", "sha256": None}
    if TABLE[word] == COULD_NOT_LOOK:
        rw, reason = _WHY[word]
        row["could_not_look"] = could_not_look("a HiddenLayer alert this adapter can read as "
                                               "pass or fail", where, rw, why or reason)
    return row


def _id(row: dict, a: dict, v: Any) -> None:
    a["id"] = _safe_str(v)
    row["vendor_request_id"] = row["vendor_id"] = a["id"]


def _conviction(row: dict, doc: dict, where: str) -> dict:
    a = row["alert"] = _blank("runtime_security_conviction", row["alert"]["index"])
    _id(row, a, doc.get("conviction_id"))
    a["detection_category"] = _safe_str(doc.get("detection_category"))
    a["engine_name"] = _safe_str(doc.get("engine_name"))
    a["mitre_technique"] = _safe_str(doc.get("technique"))
    t = doc.get("conviction_timestamp")
    row["at"] = t if type(t) is int else _safe_str(t)
    sev = _word(doc.get("severity"))
    if sev not in SEVERITIES:
        return _set(row, "unknown_severity", where)
    a["severity"] = sev
    return _set(row, "conviction", where)


def _scan(row: dict, s: dict, where: str) -> dict:
    a = row["alert"] = _blank("supply_chain_scan", row["alert"]["index"])
    _id(row, a, s.get("scan_id"))
    row["at"] = _safe_str(s.get("end_time"))
    status = _word(s.get("status"))
    a["status"] = _safe_str(s.get("status"))
    if status != "done":
        return _set(row, "unknown_status", where)
    a["status"] = "done"
    inner = s.get("summary")
    inner = inner if isinstance(inner, dict) else None
    n = _count(s.get("detection_count"))
    n_in = _count(inner.get("detection_count")) if inner else None
    a["detection_count"] = n
    a["file_count"] = _count(s.get("file_count"))
    if inner:
        a["files_failed_to_scan"] = _count(inner.get("files_failed_to_scan"))
        a["unknown_files"] = _count(inner.get("unknown_files"))
    a["scan_error_present"] = s.get("scan_error") is not None
    cats = s.get("detection_categories")
    if isinstance(cats, list):
        a["detection_names"] = [x for x in (_safe_str(c) for c in cats[:32]) if x is not None]
    if n is None and n_in is None:
        return _set(row, "scan_incomplete", where, "the scan carries no detection count")
    if (n or 0) > 0 or (n_in or 0) > 0:
        sev = _word(s.get("severity"))
        if sev not in SEVERITIES:
            return _set(row, "unknown_severity", where)
        a["severity"] = sev
        return _set(row, "scan_detections", where)
    # nothing detected: VERIFIED only if every documented count says the scan finished clean
    checks = [
        (n == 0 and n_in == 0, "detection_count is not 0 in both places"),
        (inner is not None and _count(inner.get("files_with_detections_count")) in (0, None)
         and _count(s.get("files_with_detections_count")) == 0,
         "files_with_detections_count is not 0"),
        (a["files_failed_to_scan"] == 0, "files_failed_to_scan is not 0"),
        (a["unknown_files"] == 0, "unknown_files is not 0"),
        (a["file_count"] is not None and a["file_count"] > 0, "no file was scanned"),
        (inner is not None and _count(inner.get("file_count")) == a["file_count"],
         "the two file counts differ"),
        (not a["scan_error_present"], "the scan reports an error"),
        (s.get("severity") is None and (inner is None or inner.get("severity") is None),
         "a severity is set on a scan with no detection"),
    ]
    for ok, why in checks:
        if not ok:
            return _set(row, "scan_incomplete", where, why)
    return _set(row, "scan_clean", where)


def _policy(row: dict, doc: dict, where: str) -> dict:
    a = row["alert"] = _blank("runtime_policy_outcome", row["alert"]["index"])
    m = doc["manifest"]
    _id(row, a, m.get("event_id"))
    row["at"] = _safe_str(m.get("event_at"))
    a["schema_name"] = _safe_str(m.get("schema_name"))
    if "schema_name" in m and m.get("schema_name") != POLICY_SCHEMA:
        return _set(row, "not_an_alert", where, "the manifest names another schema")
    ev = doc.get("evaluation")
    if not isinstance(ev, dict):
        return _set(row, "not_an_alert", where, "the outcome has no evaluation object")
    dets = doc.get("detections")
    names = []
    if isinstance(dets, list):
        names = [x for x in (_safe_str(d.get("name")) for d in dets[:32] if isinstance(d, dict))
                 if x]
    a["detection_names"] = names
    a["detection_count"] = len(names)
    act = ev.get("action")
    act = act.strip().upper() if isinstance(act, str) else None
    a["action"] = act if act in ("DETECT", "REDACT", "BLOCK") else _safe_str(ev.get("action"))
    lvl = ev.get("highest_threat_level")
    lvl = lvl.strip().upper() if isinstance(lvl, str) else None
    a["threat_level"] = lvl if lvl in THREAT_LEVELS else None
    if act not in ("DETECT", "REDACT", "BLOCK"):
        return _set(row, "unknown_action", where)
    if lvl not in THREAT_LEVELS:
        return _set(row, "unknown_severity", where)
    if act == "BLOCK":
        return _set(row, "policy_block", where)
    if not names:
        return _set(row, "policy_action_without_detection", where)
    return _set(row, "policy_detect" if act == "DETECT" else "policy_redact", where)


def _alert_row(base: dict, i: int, doc: Any) -> dict:
    row = _copy(base)
    row["alert"] = _blank(None, i)
    where = f"{_WHERE}[{i}]"
    if not isinstance(doc, dict):
        return _cnl(row, "a HiddenLayer alert object", where, "unreadable",
                    "the entry is not a JSON object")
    if "conviction_id" in doc:
        return _conviction(row, doc, where)
    if isinstance(doc.get("scan_result_summary"), dict):
        return _scan(row, doc["scan_result_summary"], where)
    if isinstance(doc.get("manifest"), dict) and "evaluation" in doc:
        return _policy(row, doc, where)
    return _set(row, "not_an_alert", where,
                "an audit log entry, not an alert" if "actor_type" in doc and "occurred_at" in doc
                else None)


def _read(raw: Any, at: str) -> list:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogatepass")
    if isinstance(raw, bytearray):
        raw = bytes(raw)
    if not isinstance(raw, bytes):
        return [_cnl(HIDDENLAYER.base_row(None, at), "HiddenLayer alert bytes", "argument",
                     "unreadable", f"payload is a {type(raw).__name__}, not bytes")]
    base = HIDDENLAYER.base_row(raw, at)
    base["input_sha256"] = hashlib.sha256(raw).hexdigest()
    if not raw:
        return [_cnl(base, "a HiddenLayer alert", _WHERE, "empty", "the body is empty")]
    if len(raw) > MAX_PAYLOAD_BYTES:
        return [_cnl(base, "a HiddenLayer alert", _WHERE, "bounded",
                     f"body is {len(raw)} bytes, over the {MAX_PAYLOAD_BYTES}-byte limit; "
                     f"digested, not read")]
    try:
        doc = loads_strict(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        return [_cnl(base, "a HiddenLayer alert as JSON", _WHERE, "unreadable",
                     f"body is not one unambiguous UTF-8 JSON value: {type(e).__name__}")]
    if _too_deep(doc, MAX_DEPTH):
        return [_cnl(base, "a HiddenLayer alert as JSON", _WHERE, "unreadable",
                     f"body nests deeper than {MAX_DEPTH}")]
    if isinstance(doc, dict):
        return [_alert_row(base, 0, doc)]
    if not isinstance(doc, list):
        return [_cnl(base, "a HiddenLayer alert object or a list of them", _WHERE,
                     "name_not_found", f"body is a JSON {type(doc).__name__}")]
    if not doc:
        return [_cnl(base, "a HiddenLayer alert", _WHERE, "empty", "the body lists no alerts")]
    rows = []
    for i, entry in enumerate(doc):
        if i >= MAX_ROWS:
            rows.append(_cnl(_copy(base), "every alert in the body", _WHERE, "bounded",
                             f"more than {MAX_ROWS} alerts; the rest were not read"))
            break
        rows.append(_alert_row(base, i, entry))
    return rows


def ingest(raw: Any, *, received_at: str | None = None) -> list:
    """One HiddenLayer alert (a JSON object, as the webhook delivers it) or a JSON
    array of them, as the bytes you hold -> a list of relayed rows, one per alert.
    Never raises on the body; an unreadable body is one COULD NOT LOOK row. Every
    row is signed_by_vendor False, standing reported_by_sender."""
    at = received_at if isinstance(received_at, str) else _now_iso()
    try:
        rows = _read(raw, at)
    except Exception as e:  # noqa: BLE001 - never a traceback on what is sent
        ok = isinstance(raw, (bytes, bytearray))
        base = HIDDENLAYER.base_row(bytes(raw) if ok else None, at)
        base["input_sha256"] = hashlib.sha256(bytes(raw)).hexdigest() if ok else None
        rows = [_cnl(base, "a HiddenLayer alert", _WHERE, "unreadable",
                     f"the adapter failed: {type(e).__name__}")]
    return [_seal(r) for r in rows]


def standing_verdict(rows: Any) -> dict:
    """What these rows can say on their own. BROKEN when any of them relays BROKEN;
    otherwise COULD NOT LOOK, because unsigned rows reported by the sender cannot
    make a VERIFIED by themselves. Never VERIFIED (neither `verdict` nor
    `relayed_verdict`). Rows not from this adapter are not counted. Never raises."""
    counts = {VERIFIED: 0, BROKEN: 0, COULD_NOT_LOOK: 0}
    for r in rows if isinstance(rows, (list, tuple)) else ():
        if (isinstance(r, dict) and r.get("kind") == ROW_KIND and isinstance(r.get("vendor"), dict)
                and r["vendor"].get("name") == VENDOR):
            v = r.get("relayed_verdict")
            counts[v if v in counts else COULD_NOT_LOOK] += 1
    out = {"verdict": COULD_NOT_LOOK, "relayed_verdict": COULD_NOT_LOOK,
           "rows": sum(counts.values()), "counts": counts, "signed_by_vendor": False,
           "standing": STANDING}
    if counts[BROKEN]:
        out["verdict"] = out["relayed_verdict"] = BROKEN
        out["reason"] = "HiddenLayer relayed at least one detection (unsigned, reported by sender)"
        return out
    ours = out["rows"] > 0
    out.update(could_not_look(
        "a check of our own or a signed vendor verdict", "rows", "missing" if ours else "empty",
        "HiddenLayer rows are unsigned and reported by the sender; they cannot make a VERIFIED "
        "by themselves" if ours else "no HiddenLayer rows were given"))
    return out


rollup = standing_verdict
