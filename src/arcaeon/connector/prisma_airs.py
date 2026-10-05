# SPDX-License-Identifier: MIT
"""arcaeon.connector.prisma_airs: Palo Alto Prisma AIRS (AI Runtime Security) scan
results become relayed check rows, one per scan or detection result, on the one
adapter base (arcaeon.connector.core.VendorAdapter).

THE FORMAT, as the Prisma AIRS AI Runtime API pages on pan.dev document it (read
for Batch 200 research R15). Four response shapes are read:

  sync-scan-response   POST /v1/scan/sync/request ->
                       {action, category, profile_id, profile_name,
                        prompt_detected: {dlp, injection, url_cats: bool},
                        response_detected: {dlp, url_cats: bool},
                        report_id, scan_id, tr_id}
  async-scan-ack       POST /v1/scan/async/request -> {received, scan_id, report_id}
                       (no verdict yet)
  scan-results         GET /v1/scan/results -> [{req_id, status, scan_id, result}]
                       where `result` is the sync shape
  threat-scan-report   GET /v1/scan/reports -> [{report_id, scan_id,
                       detection_results: [{data_type, detection_service, verdict,
                                            action, result_detail}]}]

No shape carries a signature. Unverified in R15: the full id format (shown only
as "0000.." and "R0000.."), `status` and report `verdict` values, any category
but "malicious", the reports response's outer wrapping, and the query parameter
names `scan_ids` / `report_ids` (from SDK method names).

THE WORD. Prisma writes `action` (allow or block); the adapter writes its own
word from it, and reads the detection flags and category so an allow that names
a threat is not taken as a pass:

    allow                 action allow, no detection flag true, category (or a
                          report's verdict) not "malicious"                -> VERIFIED
    block                 action block, whatever else the payload says     -> BROKEN
    allow_with_detection  action allow, but a detection flag is true or the
                          category / report verdict is "malicious"         -> COULD NOT LOOK
    detection_unreadable  action allow, a detection map or flag that is not
                          an object of true/false                          -> COULD NOT LOOK
    unknown_action        action missing, not a string, or not allow/block -> COULD NOT LOOK
    pending               an async ack, or a results item with no result   -> COULD NOT LOOK

THE ROW. The check.verdict.relayed row of arcaeon.connector.core, plus:

    signed_by_vendor   False. Always. No argument, flag or payload field sets it
                       (R15: Prisma does not sign its verdicts).
    standing           "reported_by_sender". Always.
    input_sha256       hex SHA-256 of the exact bytes read (None when given no bytes)
    vendor_request_id  the scan_id, else the report_id, as Prisma wrote it; else None
    vendor_id          the same
    ids                {scan_id, report_id, tr_id, req_id}
    refetch            refetch_request() for the scan_id, else the report_id, when
                       one has the documented shape; else None
    finding            {format, index, status, action, category, profile_name,
                        prompt_detected, response_detected (names of flags that are
                        true), data_type, detection_service, report_verdict,
                        detail_digest}
    subject            {"name": "prisma-airs:scan/<vendor_request_id>", "sha256": None}
    attestation        always NONE

`result_detail` is kept by digest only. Prompts and responses are not copied.

RE-FETCH. Prisma is the one vendor of the three that serves a stored result by
id. `refetch_request(id)` returns a description of that request (method, path,
query, id) and nothing else: no host, no key, no network call. A re-fetch is a
second report from the same vendor, not a signature: it can show the vendor
still says the same thing, never that the first report was not forged in
transit by them or by the sender.

`standing_verdict(rows)` is what these rows can say on their own: BROKEN when any
row relays BROKEN, otherwise COULD NOT LOOK. Never VERIFIED (T4). A relayed
BROKEN always stays BROKEN (stack review F12). Never raises on what the vendor
sends. Stdlib only.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from arcaeon.record.row import loads_strict
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED, could_not_look

from .core import (AdapterError, Extracted, VendorAdapter, _now_iso, _safe_str, _too_deep,
                   register)

__all__ = ["VENDOR", "ADAPTER_VERSION", "TABLE", "MAX_PAYLOAD_BYTES", "MAX_DEPTH", "MAX_ROWS",
           "STANDING", "REFETCH_NOTE", "PrismaAirsAdapter", "PRISMA_AIRS", "ingest",
           "refetch_request", "standing_verdict"]

VENDOR = "prisma-airs"
ADAPTER_VERSION = "1"
#: A response over this is digested, never read.
MAX_PAYLOAD_BYTES = 8 << 20
MAX_DEPTH = 64
#: More rows than this from one response: the rest are not read, and a row says so.
MAX_ROWS = 10000
STANDING = "reported_by_sender"
REFETCH_NOTE = ("a re-fetch is a second report from the same vendor, not a signature; "
                "it needs the receiver's own Prisma AIRS key and is never VERIFIED by itself")

TABLE = {
    "allow": VERIFIED,
    "block": BROKEN,
    "allow_with_detection": COULD_NOT_LOOK,
    "detection_unreadable": COULD_NOT_LOOK,
    "unknown_action": COULD_NOT_LOOK,
    "pending": COULD_NOT_LOOK,
}

FORMAT_SYNC = "sync-scan-response"
FORMAT_ACK = "async-scan-ack"
FORMAT_RESULTS = "scan-results"
FORMAT_REPORT = "threat-scan-report"

_WHERE = "Prisma AIRS response"
_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_SCAN_ID = re.compile(_UUID)
_REPORT_ID = re.compile("R" + _UUID)
_MAX_FLAGS = 32
_WHY = {
    "allow_with_detection": ("name_not_found", "Prisma allowed it but names a detection or "
                                               "a malicious category; not read as a pass"),
    "detection_unreadable": ("unreadable", "a detection map or flag is not true/false"),
    "unknown_action": ("name_not_found", "the action is not allow or block"),
    "pending": ("missing", "Prisma has not returned a result for this scan yet"),
}


class PrismaAirsAdapter(VendorAdapter):
    """Prisma AIRS on the one adapter base. One response, many rows: read it with
    `ingest`, not import_verdict (whose `extract` path refuses it)."""
    name = VENDOR
    version = ADAPTER_VERSION
    table = TABLE
    max_payload_bytes = MAX_PAYLOAD_BYTES
    max_depth = MAX_DEPTH
    one_row_per_payload = False

    def extract(self, doc: dict) -> Extracted:
        raise AdapterError("Prisma AIRS responses are read with "
                           "arcaeon.connector.prisma_airs.ingest")


PRISMA_AIRS = register(PrismaAirsAdapter())


def _seal(row: dict) -> dict:
    """The R15 rule, applied last to every row this module returns: unsigned,
    reported by sender, no attestation claim. There is no other code path."""
    row["signed_by_vendor"] = False
    row["standing"] = STANDING
    row["attestation"] = {"status": "NONE", "checked_by_us": False, "claimed": None}
    return row


# ---------------------------------------------------------------- re-fetch

def refetch_request(vendor_id: Any) -> dict:
    """A DESCRIPTION of the documented re-fetch for one id: a scan id (UUID) reads
    `GET /v1/scan/results?scan_ids=<id>`, a report id ("R" + UUID) reads
    `GET /v1/scan/reports?report_ids=<id>`. No host, no credentials, no network
    call: the receiver sends it, with its own key, if it wants a second report.
    Raises ValueError on anything not of those two shapes."""
    if isinstance(vendor_id, str) and _SCAN_ID.fullmatch(vendor_id):
        kind, path, param = "scan_id", "/v1/scan/results", "scan_ids"
    elif isinstance(vendor_id, str) and _REPORT_ID.fullmatch(vendor_id):
        kind, path, param = "report_id", "/v1/scan/reports", "report_ids"
    else:
        raise ValueError("a Prisma AIRS scan id (UUID) or report id (R + UUID) is required")
    return {"method": "GET", "path": path, "query": {param: vendor_id}, "id": vendor_id,
            "id_kind": kind, "network": False, "credentials": None, "note": REFETCH_NOTE}


def _refetch_or_none(*ids: Any) -> dict | None:
    for i in ids:
        try:
            return refetch_request(i)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------- rows

def _base(raw: bytes | None, at: str) -> dict:
    row = PRISMA_AIRS.base_row(raw, at)
    row["input_sha256"] = hashlib.sha256(raw).hexdigest() if raw is not None else None
    row["vendor_request_id"] = None
    row["ids"] = {"scan_id": None, "report_id": None, "tr_id": None, "req_id": None}
    row["refetch"] = None
    row["finding"] = None  # the doc: every row carries `finding`; a refusal row has none
    return _seal(row)


def _copy(base: dict) -> dict:
    return json.loads(json.dumps(base))


def _cnl(row: dict, looked_for: str, where: str, reason_word: str, reason: str) -> dict:
    return _seal(PRISMA_AIRS.mark_could_not_look(row, looked_for, where, reason_word, reason))


def _digest(v: Any) -> str | None:
    try:
        return PRISMA_AIRS.digest(v) if v is not None else None
    except Exception:  # noqa: BLE001 - a value JCS refuses has no digest
        return None


def _id(v: Any) -> str | None:
    s = _safe_str(v)
    return s if s else None


def _flags(v: Any) -> tuple[list, bool]:
    """(names of flags that are true, readable). Absent is readable and empty."""
    if v is None:
        return [], True
    if not isinstance(v, dict):
        return [], False
    ok = all(type(x) is bool for x in v.values())
    names = sorted(_safe_str(k) or "" for k, x in v.items() if x is True)
    return names[:_MAX_FLAGS], ok


def _word(action: Any, detected: bool, readable: bool, malicious: bool) -> str:
    a = action.strip().casefold() if isinstance(action, str) else None
    if a == "block":
        return "block"
    if a != "allow":
        return "unknown_action"
    if not readable:
        return "detection_unreadable"
    if detected or malicious:
        return "allow_with_detection"
    return "allow"


def _row(base: dict, word: str, *, fmt: str, index: int | None, where: str,
         ids: dict, **extra) -> dict:
    row = _copy(base)
    f = {"format": fmt, "index": index, "status": None, "action": None, "category": None,
         "profile_name": None, "prompt_detected": None, "response_detected": None,
         "data_type": None, "detection_service": None, "report_verdict": None,
         "detail_digest": None}
    f.update(extra)
    row["finding"] = f
    row["ids"] = {k: ids.get(k) for k in ("scan_id", "report_id", "tr_id", "req_id")}
    req = ids.get("scan_id") or ids.get("report_id")
    row["vendor_request_id"] = req
    row["vendor_id"] = req
    row["refetch"] = _refetch_or_none(ids.get("scan_id"), ids.get("report_id"))
    if req:
        row["subject"] = {"name": f"{VENDOR}:scan/{req}", "sha256": None}
    row["vendor_word"] = word
    row["mapping"] = {"rule": "table"}
    row["relayed_verdict"] = TABLE[word]
    if TABLE[word] == COULD_NOT_LOOK:
        row["could_not_look"] = could_not_look("a Prisma AIRS result this adapter can read "
                                               "as pass or fail", where, *_WHY[word])
    return _seal(row)


def _ids(*docs: dict, req_id: Any = None) -> dict:
    out = {"scan_id": None, "report_id": None, "tr_id": None,
           "req_id": req_id if type(req_id) is int else _id(req_id)}
    for d in docs:
        for k in ("scan_id", "report_id", "tr_id"):
            if out[k] is None:
                out[k] = _id(d.get(k))
    return out


def _scan_row(base: dict, res: dict, *, fmt: str, index: int | None, where: str,
              ids: dict, status: Any = None) -> dict:
    pd, pok = _flags(res.get("prompt_detected"))
    rd, rok = _flags(res.get("response_detected"))
    cat = res.get("category")
    malicious = isinstance(cat, str) and cat.strip().casefold() == "malicious"
    word = _word(res.get("action"), bool(pd or rd), pok and rok, malicious)
    return _row(base, word, fmt=fmt, index=index, where=where, ids=ids,
                status=_safe_str(status), action=_safe_str(res.get("action")),
                category=_safe_str(cat), profile_name=_safe_str(res.get("profile_name")),
                prompt_detected=pd, response_detected=rd)


class _Full(Exception):
    pass


class _Out:
    def __init__(self, base: dict):
        self.rows: list = []
        self.base = base

    def add(self, row: dict) -> None:
        if len(self.rows) >= MAX_ROWS:
            self.rows.append(_cnl(_copy(self.base), "every result in the response", _WHERE,
                                  "bounded", f"more than {MAX_ROWS} rows; the rest were "
                                             f"not read"))
            raise _Full
        self.rows.append(row)


def _report(out: _Out, rep: dict, where: str) -> None:
    ids = _ids(rep)
    dets = rep.get("detection_results")
    if not isinstance(dets, list) or not dets:
        out.add(_row(out.base, "pending", fmt=FORMAT_REPORT, index=None, where=where, ids=ids))
        return
    for i, d in enumerate(dets):
        w = f"{where}.detection_results[{i}]"
        if not isinstance(d, dict):
            row = _copy(out.base)
            out.add(_cnl(row, "a detection result", w, "unreadable", "not an object"))
            continue
        v = d.get("verdict")
        malicious = isinstance(v, str) and v.strip().casefold() == "malicious"
        word = _word(d.get("action"), False, True, malicious)
        out.add(_row(out.base, word, fmt=FORMAT_REPORT, index=i, where=w, ids=ids,
                     action=_safe_str(d.get("action")), report_verdict=_safe_str(v),
                     data_type=_safe_str(d.get("data_type")),
                     detection_service=_safe_str(d.get("detection_service")),
                     detail_digest=_digest(d.get("result_detail"))))


def _item(out: _Out, it: Any, i: int) -> None:
    where = f"[{i}]"
    if not isinstance(it, dict):
        out.add(_cnl(_copy(out.base), "a scan result or report", where, "unreadable",
                     "not an object"))
    elif "detection_results" in it:
        _report(out, it, where)
    elif "scan_id" in it and ("result" in it or "status" in it):
        res = it.get("result")
        if isinstance(res, dict):
            ids = _ids(it, res, req_id=it.get("req_id"))
            out.add(_scan_row(out.base, res, fmt=FORMAT_RESULTS, index=i, where=where,
                              ids=ids, status=it.get("status")))
        else:
            out.add(_row(out.base, "pending", fmt=FORMAT_RESULTS, index=i, where=where,
                         ids=_ids(it, req_id=it.get("req_id")),
                         status=_safe_str(it.get("status"))))
    else:
        out.add(_cnl(_copy(out.base), "a scan result or report", where, "name_not_found",
                     "the entry is not a Prisma AIRS result or report shape"))


# ---------------------------------------------------------------- entry points

def ingest(raw: Any, *, received_at: str | None = None) -> list:
    """A Prisma AIRS scan response (the bytes as received) -> a list of relayed rows.

    Takes no argument that can change `signed_by_vendor` or `standing`. Never
    raises on the response; unreadable input is one COULD NOT LOOK row."""
    at = received_at if isinstance(received_at, str) else _now_iso()
    try:
        if isinstance(raw, str):
            raw = raw.encode("utf-8", "surrogatepass")
        if not isinstance(raw, (bytes, bytearray)):
            return [_cnl(_base(None, at), "Prisma AIRS JSON bytes", "argument", "unreadable",
                         f"the response is a {type(raw).__name__}, not bytes")]
        raw = bytes(raw)
        base = _base(raw, at)
        if not raw:
            return [_cnl(base, "Prisma AIRS JSON", _WHERE, "empty", "the response is empty")]
        if len(raw) > MAX_PAYLOAD_BYTES:
            return [_cnl(base, "Prisma AIRS JSON", _WHERE, "bounded",
                         f"response is {len(raw)} bytes, over the {MAX_PAYLOAD_BYTES}-byte "
                         f"limit; digested, not read")]
        try:
            doc = loads_strict(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError) as e:
            return [_cnl(base, "Prisma AIRS JSON", _WHERE, "unreadable",
                         f"response is not one unambiguous UTF-8 JSON value: "
                         f"{type(e).__name__}")]
        if _too_deep(doc, MAX_DEPTH):
            return [_cnl(base, "Prisma AIRS JSON", _WHERE, "unreadable",
                         f"response nests deeper than {MAX_DEPTH}")]
        out = _Out(base)
        try:
            if isinstance(doc, dict) and "action" in doc:
                out.add(_scan_row(base, doc, fmt=FORMAT_SYNC, index=None, where=_WHERE,
                                  ids=_ids(doc)))
            elif isinstance(doc, dict) and "detection_results" in doc:
                _report(out, doc, _WHERE)
            elif isinstance(doc, dict) and "received" in doc and (
                    "scan_id" in doc or "report_id" in doc):
                out.add(_row(base, "pending", fmt=FORMAT_ACK, index=None, where=_WHERE,
                             ids=_ids(doc)))
            elif isinstance(doc, list):
                for i, it in enumerate(doc):
                    _item(out, it, i)
            else:
                return [_cnl(base, "a Prisma AIRS scan response, results or report",
                             _WHERE, "name_not_found",
                             "the JSON is not a Prisma AIRS response shape")]
        except _Full:
            pass
        if not out.rows:
            return [_cnl(base, "a scan result", _WHERE, "empty",
                         "the response lists no results")]
        return out.rows
    except Exception as e:  # noqa: BLE001 - never a traceback on what a vendor sends
        return [_cnl(_base(None, at), "Prisma AIRS JSON", _WHERE, "unreadable",
                     f"the adapter failed: {type(e).__name__}")]


def standing_verdict(rows: Any) -> dict:
    """What Prisma AIRS rows can say on their own. BROKEN when any of them relays
    BROKEN (a relayed BROKEN never becomes anything else, whatever else the row
    claims); otherwise COULD NOT LOOK, because an unsigned row reported by sender
    cannot make a VERIFIED by itself, and a re-fetch would only be a second
    report from the same vendor. Never VERIFIED. Never raises."""
    ours = []
    if isinstance(rows, (list, tuple)):
        ours = [r for r in rows if isinstance(r, dict) and isinstance(r.get("vendor"), dict)
                and r["vendor"].get("name") == VENDOR]
    words = [r.get("relayed_verdict") for r in ours]
    if BROKEN in words:
        relayed = BROKEN
    elif ours and all(w == VERIFIED for w in words):
        relayed = VERIFIED
    else:
        relayed = COULD_NOT_LOOK if ours else None
    out = {"verdict": BROKEN if relayed == BROKEN else COULD_NOT_LOOK,
           "relayed_verdict": relayed, "rows": len(ours), "signed_by_vendor": False,
           "standing": STANDING}
    if relayed == BROKEN:
        out["reason"] = "Prisma AIRS relayed BROKEN (block) for at least one scan"
    else:
        out.update(could_not_look(
            "a check of our own or a signed vendor verdict", "rows",
            "missing" if ours else "empty",
            "Prisma AIRS rows are unsigned and reported by sender; they cannot make a "
            "VERIFIED by themselves" if ours else "no Prisma AIRS rows were given"))
    return out
