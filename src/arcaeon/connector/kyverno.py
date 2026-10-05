# SPDX-License-Identifier: MIT
"""arcaeon.connector.kyverno: a Kyverno PolicyReport or ClusterPolicyReport
becomes relayed check rows, one per result, on the one adapter base
(arcaeon.connector.core.VendorAdapter).

THE FORMAT, as the Kyverno policy-reports page and the upstream wg-policy
API doc describe it (no live capture was read for this adapter):

    apiVersion   "wgpolicyk8s.io/v1alpha2" (Kyverno today), "reports.x-k8s.io/v1beta2"
                 (the upstream API doc), "openreports.io/v1alpha1" (alpha, behind a flag)
    kind         "PolicyReport" (namespaced) or "ClusterPolicyReport"
    metadata     name, namespace, uid, resourceVersion (Kubernetes object metadata)
    results[]    policy, rule, result (pass | fail | warn | error | skip), source,
                 scored, timestamp {seconds, nanos}, message, severity
                 (critical | high | medium | low | info), category,
                 properties (map of string to string), resources[] (object refs).
                 Every result field is optional.
    summary      {pass, fail, warn, error, skip} counts

A Kubernetes list body ({"kind": "List", "items": [report, ...]}) is read report by
report. The kyverno CLI's text or table output is not read.

THE WORD. The result word is the verdict word, read by this table:

    pass   -> VERIFIED        the policy rule passed, as Kyverno says
    fail   -> BROKEN          the policy rule failed, as Kyverno says
    warn   -> COULD NOT LOOK  an advisory result, neither pass nor fail
    error  -> COULD NOT LOOK  Kyverno could not evaluate the rule
    skip   -> COULD NOT LOOK  the rule was not applied

A report whose `summary` counts disagree with its own results[] is
self-inconsistent: every row of that report is COULD NOT LOOK (the word Kyverno
wrote is kept in vendor_word).

THE ROW. The check.verdict.relayed row of arcaeon.connector.core, plus:

    kyverno      report {api_version, kind, name, namespace, uid, resource_version},
                 report_index, result_index, policy, rule, source, scored, severity,
                 category, message, timestamp {seconds, nanos}, resources[] (at most
                 MAX_RESOURCES, each {api_version, kind, namespace, name, uid}),
                 resources_total, properties_digest (sha256:jcs:v1, the map itself
                 is not copied), summary_check ("agrees" | "disagrees" | "absent")
    policy_ref   {policy, rule, version: None, join: COULD NOT LOOK, note}: a report
                 names the policy and rule only, so the row cannot be tied to a
                 sealed policy
    signed_by_vendor  False. Always.
    standing          "reported_by_sender". Always.
    input_sha256      hex SHA-256 of the exact bytes given to ingest (None if not bytes)

    vendor_id    the report's metadata.uid
    subject      {"name": "kyverno:<namespace>/<kind>/<name>", "sha256": None} when the
                 result names exactly one resource, else None
    attestation  always NONE: Kyverno does not sign reports; a field in the payload
                 that looks like a signature is not read

The last three keys are written by ONE final step (`_seal`) over every row ingest
returns, after which a row whose word is not `pass` cannot be VERIFIED. `ingest`
takes no argument that changes them. `rollup` over these rows is never VERIFIED.

`recheck` says COULD NOT LOOK for these rows (one payload, many rows); re-run
`ingest` with the same bytes to compare. Never raises on what Kyverno sends.
Stdlib only. No network, no cluster: this reads bytes you already hold.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from arcaeon.record.row import loads_strict
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED, could_not_look

from .core import (ATTESTATION_NONE, AdapterError, Extracted, VendorAdapter,
                   _now_iso, _safe_str, _too_deep, map_word, register, rollup_rows)

__all__ = ["VENDOR", "ADAPTER_VERSION", "TABLE", "API_VERSIONS", "REPORT_KINDS",
           "MAX_PAYLOAD_BYTES", "MAX_DEPTH", "MAX_ROWS", "MAX_RESOURCES", "STANDING",
           "KyvernoReportAdapter", "KYVERNO", "ingest", "rollup"]

VENDOR = "kyverno"
ADAPTER_VERSION = "1"
#: A body over this is digested, never read.
MAX_PAYLOAD_BYTES = 8 << 20
#: Reports nest shallowly; leave room for properties and lists.
MAX_DEPTH = 64
#: More results than this in one body: the rest are not read, and a row says so.
MAX_ROWS = 10000
#: Resources copied per result; resources_total says how many there were.
MAX_RESOURCES = 32
#: What every row of this adapter is: the sender's report, not a signed one.
STANDING = "reported_by_sender"

API_VERSIONS = ("wgpolicyk8s.io/v1alpha2", "reports.x-k8s.io/v1beta2", "openreports.io/v1alpha1")
REPORT_KINDS = ("PolicyReport", "ClusterPolicyReport")
_LIST_KINDS = ("List", "PolicyReportList", "ClusterPolicyReportList")
_WORDS = ("pass", "fail", "warn", "error", "skip")

TABLE = {
    "pass": VERIFIED,
    "fail": BROKEN,
    "warn": COULD_NOT_LOOK,
    "error": COULD_NOT_LOOK,
    "skip": COULD_NOT_LOOK,
}

_WHERE = "Kyverno policy report"
_WHY = {
    "warn": ("missing", "Kyverno reported warn: an advisory result, neither pass nor fail"),
    "error": ("unreadable", "Kyverno reported error: the rule could not be evaluated"),
    "skip": ("missing", "Kyverno reported skip: the rule was not applied"),
}
_POLICY_NOTE = ("the report carries no policy version, resourceVersion or digest of the "
                "policy, only its name and rule, so this row cannot be joined to a sealed policy")


class KyvernoReportAdapter(VendorAdapter):
    """Kyverno policy reports on the one adapter base. One body, many rows: read it
    with `ingest`, not import_verdict (whose `extract` path refuses it)."""
    name = VENDOR
    version = ADAPTER_VERSION
    table = TABLE
    max_payload_bytes = MAX_PAYLOAD_BYTES
    max_depth = MAX_DEPTH
    one_row_per_payload = False

    def extract(self, doc: dict) -> Extracted:
        raise AdapterError("a Kyverno policy report is one row per result; read it with "
                           "arcaeon.connector.kyverno.ingest")


KYVERNO = register(KyvernoReportAdapter())

_cnl = KYVERNO.mark_could_not_look


def _copy(row: dict) -> dict:
    return json.loads(json.dumps(row))


def _int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _digest(v: Any) -> str | None:
    try:
        return KYVERNO.digest(v)
    except Exception:  # noqa: BLE001 - a value JCS refuses has no digest
        return None


def _report_info(rep: dict) -> dict:
    meta = rep.get("metadata") if isinstance(rep.get("metadata"), dict) else {}
    return {"api_version": _safe_str(rep.get("apiVersion")), "kind": _safe_str(rep.get("kind")),
            "name": _safe_str(meta.get("name")), "namespace": _safe_str(meta.get("namespace")),
            "uid": _safe_str(meta.get("uid")),
            "resource_version": _safe_str(meta.get("resourceVersion"))}


def _resource(v: Any) -> dict | None:
    if not isinstance(v, dict):
        return None
    return {"api_version": _safe_str(v.get("apiVersion")), "kind": _safe_str(v.get("kind")),
            "namespace": _safe_str(v.get("namespace")), "name": _safe_str(v.get("name")),
            "uid": _safe_str(v.get("uid"))}


def _timestamp(v: Any) -> dict | None:
    if not isinstance(v, dict):
        return None
    return {"seconds": _int(v.get("seconds")), "nanos": _int(v.get("nanos"))}


def _summary_check(rep: dict, results: list) -> tuple[str, str | None]:
    if "summary" not in rep:
        return "absent", None
    s = rep["summary"]
    seen = {w: 0 for w in _WORDS}
    for r in results:
        if isinstance(r, dict) and isinstance(r.get("result"), str) and r["result"] in seen:
            seen[r["result"]] += 1
    if not isinstance(s, dict):
        return "disagrees", "the report's summary is not an object of counts"
    said = {w: s.get(w, 0) for w in _WORDS}
    if any(_int(v) is None for v in said.values()) or said != seen:
        return "disagrees", (f"the report's summary {json.dumps(said, default=str)[:120]} "
                             f"disagrees with its results[] {json.dumps(seen)}")
    return "agrees", None


def _result_row(base: dict, info: dict, ri: int, j: int, res: Any,
                check: str, why: str | None) -> dict:
    row = _copy(base)
    row["vendor_id"] = info["uid"]
    if not isinstance(res, dict):
        row["kyverno"] = {"report": info, "report_index": ri, "result_index": j,
                          "summary_check": check}
        return _cnl(row, "a policy report result object", f"{_WHERE}[{ri}].results[{j}]",
                    "unreadable", "the result is not a JSON object")
    rs = res.get("resources")
    rlist = rs if isinstance(rs, list) else []
    resources = [_resource(x) for x in rlist[:MAX_RESOURCES]]
    k = {"report": info, "report_index": ri, "result_index": j,
         "policy": _safe_str(res.get("policy")), "rule": _safe_str(res.get("rule")),
         "source": _safe_str(res.get("source")),
         "scored": res.get("scored") if isinstance(res.get("scored"), bool) else None,
         "severity": _safe_str(res.get("severity")), "category": _safe_str(res.get("category")),
         "message": _safe_str(res.get("message")), "timestamp": _timestamp(res.get("timestamp")),
         "resources": resources, "resources_total": len(rs) if isinstance(rs, list) else None,
         "properties_digest": _digest(res["properties"]) if "properties" in res else None,
         "summary_check": check}
    row["kyverno"] = k
    row["policy_ref"] = {"policy": k["policy"], "rule": k["rule"], "version": None,
                         "join": COULD_NOT_LOOK, "note": _POLICY_NOTE}
    word = res.get("result")
    ours, rule = map_word(KYVERNO, word)
    row["vendor_word"] = _safe_str(word)
    row["mapping"] = {"rule": rule}
    row["relayed_verdict"] = ours
    if len(rlist) == 1 and resources[0] and resources[0]["name"]:
        r0 = resources[0]
        row["subject"] = {"name": "kyverno:" + "/".join(
            p for p in (r0["namespace"], r0["kind"], r0["name"]) if p), "sha256": None}
    where = f"{_WHERE}[{ri}].results[{j}]"
    if rule != "table":
        row["could_not_look"] = could_not_look(
            "a result word this adapter's table holds", where, "name_not_found",
            f"result {row['vendor_word']!r} is not in the kyverno table" if rule == "unknown_word"
            else "the result is not a word")
    elif ours == COULD_NOT_LOOK:
        row["could_not_look"] = could_not_look("a pass or fail result", where,
                                               *_WHY[word.strip().casefold()])
    if check == "disagrees":
        _cnl(row, "a report whose summary agrees with its results", where, "unreadable", why)
    return row


def _report_rows(base: dict, ri: int, rep: Any, rows: list) -> bool:
    """Append this report's rows. True when the row cap stopped reading."""
    if not isinstance(rep, dict):
        row = _copy(base)
        row["kyverno"] = {"report_index": ri}
        rows.append(_cnl(row, "a policy report object", f"{_WHERE}[{ri}]", "unreadable",
                         "the item is not a JSON object"))
        return False
    info = _report_info(rep)
    row = _copy(base)
    row["vendor_id"] = info["uid"]
    row["kyverno"] = {"report": info, "report_index": ri}
    if rep.get("kind") not in REPORT_KINDS or rep.get("apiVersion") not in API_VERSIONS:
        rows.append(_cnl(row, f"a PolicyReport or ClusterPolicyReport of {', '.join(API_VERSIONS)}",
                         f"{_WHERE}[{ri}]", "name_not_found",
                         f"kind {info['kind']!r} apiVersion {info['api_version']!r} is not a "
                         f"Kyverno policy report this adapter reads"))
        return False
    results = rep.get("results")
    if results is None:
        rows.append(_cnl(row, "results[]", f"{_WHERE}[{ri}]", "missing", "the report has no results"))
        return False
    if not isinstance(results, list):
        rows.append(_cnl(row, "results[]", f"{_WHERE}[{ri}]", "name_not_found",
                         f"results is a JSON {type(results).__name__}, not an array"))
        return False
    if not results:
        rows.append(_cnl(row, "a policy report result", f"{_WHERE}[{ri}]", "empty",
                         "the report lists no results"))
        return False
    check, why = _summary_check(rep, results)
    for j, res in enumerate(results):
        if len(rows) >= MAX_ROWS:
            rows.append(_cnl(_copy(base), "every result in the body", _WHERE, "bounded",
                             f"more than {MAX_ROWS} results; the rest were not read"))
            return True
        rows.append(_result_row(base, info, ri, j, res, check, why))
    return False


def _read(raw: Any, at: str) -> list:
    if not isinstance(raw, bytes):
        return [_cnl(KYVERNO.base_row(None, at), "Kyverno policy report bytes", "argument",
                     "unreadable", f"payload is a {type(raw).__name__}, not bytes")]
    base = KYVERNO.base_row(raw, at)
    if not raw:
        return [_cnl(base, "a Kyverno policy report", _WHERE, "empty", "the body is empty")]
    if len(raw) > MAX_PAYLOAD_BYTES:
        return [_cnl(base, "a Kyverno policy report", _WHERE, "bounded",
                     f"body is {len(raw)} bytes, over the {MAX_PAYLOAD_BYTES}-byte limit; "
                     f"digested, not read")]
    try:
        doc = loads_strict(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as e:
        return [_cnl(base, "a Kyverno policy report JSON object", _WHERE, "unreadable",
                     f"body is not one unambiguous UTF-8 JSON value: {type(e).__name__}")]
    if _too_deep(doc, MAX_DEPTH):
        return [_cnl(base, "a Kyverno policy report JSON object", _WHERE, "unreadable",
                     f"body nests deeper than {MAX_DEPTH}")]
    if not isinstance(doc, dict):
        return [_cnl(base, "a Kyverno policy report JSON object", _WHERE, "name_not_found",
                     f"body is a JSON {type(doc).__name__}, not a report or a list of reports")]
    rows: list = []
    if doc.get("kind") in _LIST_KINDS:
        items = doc.get("items")
        if not isinstance(items, list):
            return [_cnl(base, "items[] of policy reports", _WHERE, "name_not_found",
                         "the list body has no items array")]
        if not items:
            return [_cnl(base, "a policy report", _WHERE, "empty", "the list holds no reports")]
        for ri, rep in enumerate(items):
            if len(rows) >= MAX_ROWS:
                rows.append(_cnl(_copy(base), "every report in the body", _WHERE, "bounded",
                                 f"more than {MAX_ROWS} rows; the rest were not read"))
                break
            if _report_rows(base, ri, rep, rows):
                break
        return rows
    _report_rows(base, 0, doc, rows)
    return rows


def _seal(rows: list, raw: bytes | None) -> list:
    """The one final step: every row is unsigned, reported by the sender, and pinned
    to the exact input bytes. A row whose word is not `pass` cannot leave VERIFIED."""
    sha = hashlib.sha256(raw).hexdigest() if isinstance(raw, bytes) else None
    for r in rows:
        r["attestation"] = {"status": ATTESTATION_NONE, "checked_by_us": False, "claimed": None}
        w = r.get("vendor_word")
        if r.get("relayed_verdict") == VERIFIED and not (
                isinstance(w, str) and w.strip().casefold() == "pass"
                and r.get("mapping", {}).get("rule") == "table"):
            _cnl(r, "a pass result", _WHERE, "unreadable",
                 f"only a Kyverno pass can relay as VERIFIED; {w!r} cannot")
        r["signed_by_vendor"] = False
        r["standing"] = STANDING
        r["input_sha256"] = sha
    return rows


def ingest(raw: Any, *, received_at: str | None = None) -> list:
    """A Kyverno PolicyReport / ClusterPolicyReport, or a Kubernetes list of them, as
    the bytes you hold -> a list of relayed rows, one per result (plus one per item
    that cannot be read). Never raises on the body; an unreadable body is one COULD
    NOT LOOK row. Every row is signed_by_vendor False, standing reported_by_sender."""
    at = received_at if isinstance(received_at, str) else _now_iso()
    data = None
    try:
        if isinstance(raw, str):
            raw = raw.encode("utf-8", "surrogatepass")
        if isinstance(raw, bytearray):
            raw = bytes(raw)
        data = raw if isinstance(raw, bytes) else None
        rows = _read(raw, at)
    except Exception as e:  # noqa: BLE001 - never a traceback on what Kyverno sends
        rows = [_cnl(KYVERNO.base_row(data, at), "a Kyverno policy report", _WHERE,
                     "unreadable", f"the adapter failed: {type(e).__name__}")]
    return _seal(rows, data)


def rollup(rows: Any) -> dict:
    """The one rollup (core.rollup_rows, docs/CONNECTOR_ADAPTER.md "The rollup"):
    BROKEN when any of this adapter's rows relays BROKEN with the vendor word 'fail';
    otherwise COULD NOT LOOK, with the per-word counts. Never VERIFIED: unsigned
    rows reported by the sender cannot make a VERIFIED by themselves. No bare
    `verdict` key. Rows not from this adapter are not counted. Never raises."""
    return rollup_rows(rows, VENDOR, label='Kyverno policy report', standing=STANDING,
                       broken_words=('fail',),
                       broken_reason='Kyverno reported at least one fail (relayed, unsigned)')
