# SPDX-License-Identifier: MIT
"""arcaeon.connector.lakera_guard: a Lakera Guard API v2 screening response
(`POST /v2/guard`) becomes relayed check rows on the one adapter base
(arcaeon.connector.core.VendorAdapter): one row for the response, plus one per
detector that says it detected something and one per payload match span.

THE FORMAT, as the Lakera API v2 reference documents it (read for Batch 200
research R15):

    {"flagged": bool, "action": "..",
     "payload":   [{start, end, text, detector_type, labels: [..], message_id}],
     "breakdown": [{project_id, policy_id, detector_id, detector_type, detected,
                    result, message_id}],
     "tools":     {flagged, breakdown: [{.., detected, result, tool_id}]},
     "dev_info":  {git_revision, git_timestamp, model_version, version},
     "metadata":  {"request_uuid": ".."}}

`payload` and `breakdown` come back only when the request asked for them;
`tools` (the screening of the request's tool definitions) only when the request
sent tools. `flagged` is always false in Detect mode; only an Enforce-mode
policy flags. The caller declares the mode (`policy_mode`), as the Snyk adapter
makes the caller declare a score cut-off. The API reference (re-read
2026-10-05, tests/fixtures/lakera_guard/vendor_public/) documents `action` as
the project's mode, `enforce` or `detect`: a not-flagged response whose
`action` names the other mode than the one declared is
`not_flagged_mode_conflict`, COULD NOT LOOK. `action` alone never sets the mode.
v2 has no `categories` field: `detector_type` is the category. The response
is not signed.

`/v2/guard/results` returns `results[]` and makes no flagging decision; it is a
re-scan, not a lookup, and is read as `results_not_screening`.

THE WORD. Lakera writes a boolean, not a verdict word, so the adapter writes its own:

    flagged                      `flagged` is true                          -> BROKEN
    detector_detected            a breakdown entry with `detected` true     -> BROKEN
    payload_match                a payload match span                       -> BROKEN
    not_flagged                  `flagged` false, nothing detected, nothing
                                 unreadable, caller declared "enforce"      -> VERIFIED
    not_flagged_detect_mode      `flagged` false, caller declared "detect"  -> COULD NOT LOOK
    not_flagged_mode_undeclared  `flagged` false, no mode declared          -> COULD NOT LOOK
    not_flagged_unsettled        `flagged` false, but a detector hit, a
                                 match span or an unreadable entry          -> COULD NOT LOOK
    tools_flagged                `tools.flagged` is true                    -> BROKEN
    tool_detector_detected       a tools.breakdown entry, `detected` true   -> BROKEN
    not_flagged_mode_conflict    `flagged` false, `action` is the other mode -> COULD NOT LOOK
    tools_unreadable             a `tools` block or entry we cannot read    -> COULD NOT LOOK
    flagged_unreadable           `flagged` missing or not a boolean         -> COULD NOT LOOK
    detector_unreadable          a breakdown entry that is not an object,
                                 or whose `detected` is not a boolean       -> COULD NOT LOOK
    payload_unreadable           a payload entry that is not an object      -> COULD NOT LOOK
    results_not_screening        the /v2/guard/results shape                -> COULD NOT LOOK

"not flagged" relays VERIFIED for its one row only when the caller declares
Enforce mode and nothing else in the response points the other way; a VERIFIED
relayed row is still never our own VERIFIED (see standing_verdict).

THE ROW. The check.verdict.relayed row of arcaeon.connector.core, plus:

    signed_by_vendor          False. Always. No argument, flag or payload field sets it
                              (R15: Lakera Guard does not sign its responses).
    standing                  "reported_by_sender". Always.
    input_sha256              hex SHA-256 of the exact response bytes read (None when
                              given no bytes)
    request_sha256            hex SHA-256 of the request body the caller sent, if given
    vendor_request_id         `metadata.request_uuid` from the response, else the
                              caller's `vendor_request_id`, else None
    vendor_request_id_source  "response" | "caller" | None
    ids                       {"request_uuid": .., "caller": ..}
    finding                   {part ("response" | "breakdown" | "payload"), index,
                              flagged, action, policy_mode, detectors_reported,
                              detectors_detected, payload_matches, model_version,
                              vendor_version, project_id, policy_id, detector_id,
                              detector_type, detected, result, message_id, labels,
                              start, end, text_digest}
    vendor_id                 the same as vendor_request_id
    attestation               always NONE

Match text is kept by digest only (it quotes the screened content, which may be
personal data). Messages are never in the response and nothing is copied from
the request.

`standing_verdict(rows)` is what these rows can say on their own: BROKEN when any
row relays BROKEN, otherwise COULD NOT LOOK. Never VERIFIED: an unsigned vendor
row is reported by sender and cannot make a VERIFIED by itself (T4). A relayed
BROKEN always stays BROKEN (stack review F12).

Never raises on what the vendor sends. Stdlib only. No network: this reads a
response you already hold; it never calls Lakera.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from arcaeon.record.row import loads_strict
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED, could_not_look

from .core import (AdapterError, Extracted, VendorAdapter, _now_iso, _safe_str, _too_deep,
                   register, rollup_rows)

__all__ = ["VENDOR", "ADAPTER_VERSION", "TABLE", "MAX_PAYLOAD_BYTES", "MAX_DEPTH", "MAX_ROWS",
           "POLICY_MODES", "STANDING", "LakeraGuardAdapter", "LAKERA_GUARD", "ingest",
           "standing_verdict"]

VENDOR = "lakera-guard"
ADAPTER_VERSION = "2"
#: A response over this is digested, never read.
MAX_PAYLOAD_BYTES = 8 << 20
MAX_DEPTH = 64
#: More rows than this from one response: the rest are not read, and a row says so.
MAX_ROWS = 10000
#: What the caller can declare about the Lakera policy that screened the request.
POLICY_MODES = ("enforce", "detect")
STANDING = "reported_by_sender"

TABLE = {
    "flagged": BROKEN,
    "detector_detected": BROKEN,
    "payload_match": BROKEN,
    "tools_flagged": BROKEN,
    "tool_detector_detected": BROKEN,
    "not_flagged": VERIFIED,
    "not_flagged_detect_mode": COULD_NOT_LOOK,
    "not_flagged_mode_undeclared": COULD_NOT_LOOK,
    "not_flagged_unsettled": COULD_NOT_LOOK,
    "not_flagged_mode_conflict": COULD_NOT_LOOK,
    "tools_unreadable": COULD_NOT_LOOK,
    "flagged_unreadable": COULD_NOT_LOOK,
    "detector_unreadable": COULD_NOT_LOOK,
    "payload_unreadable": COULD_NOT_LOOK,
    "results_not_screening": COULD_NOT_LOOK,
}

_WHERE = "Lakera Guard response"
_WHY = {
    "not_flagged_detect_mode": ("missing", "flagged is always false in Detect mode, so "
                                           "not flagged says nothing"),
    "not_flagged_mode_undeclared": ("name_not_found", "no policy_mode was declared; flagged is "
                                                      "always false in Detect mode"),
    "not_flagged_unsettled": ("missing", "flagged is false but a detector, a match span or an "
                                         "unreadable entry points the other way"),
    "not_flagged_mode_conflict": ("unreadable", "the response's action names another policy "
                                                "mode than the one the caller declared"),
    "tools_unreadable": ("unreadable", "the tools block is not an object with a boolean flagged "
                                       "and a list of breakdown objects with a boolean detected"),
    "flagged_unreadable": ("unreadable", "flagged is missing or not a boolean"),
    "detector_unreadable": ("unreadable", "the breakdown entry is not an object with a "
                                          "boolean detected"),
    "payload_unreadable": ("unreadable", "the payload entry is not an object"),
    "results_not_screening": ("name_not_found", "a /v2/guard/results body makes no flagging "
                                                "decision; it is a re-scan, not a screening"),
}
_FINDING_KEYS = ("part", "index", "flagged", "action", "policy_mode", "detectors_reported",
                 "detectors_detected", "payload_matches", "model_version", "vendor_version",
                 "project_id", "policy_id", "detector_id", "detector_type", "detected",
                 "result", "message_id", "labels", "start", "end", "text_digest", "tool_id")


class LakeraGuardAdapter(VendorAdapter):
    """Lakera Guard v2 on the one adapter base. One response, many rows: read it
    with `ingest`, not import_verdict (whose `extract` path refuses it)."""
    name = VENDOR
    version = ADAPTER_VERSION
    table = TABLE
    max_payload_bytes = MAX_PAYLOAD_BYTES
    max_depth = MAX_DEPTH
    one_row_per_payload = False

    def extract(self, doc: dict) -> Extracted:
        raise AdapterError("a Lakera Guard response is one row per detection; read it with "
                           "arcaeon.connector.lakera_guard.ingest")


LAKERA_GUARD = register(LakeraGuardAdapter())


def _seal(row: dict) -> dict:
    """The R15 rule, applied last to every row this module returns: unsigned,
    reported by sender, no attestation claim. There is no other code path."""
    row["signed_by_vendor"] = False
    row["standing"] = STANDING
    row["attestation"] = {"status": "NONE", "checked_by_us": False, "claimed": None}
    return row


def _set_id(row: dict, uuid: str | None, caller: str | None) -> None:
    rid = uuid or caller
    row["vendor_request_id"] = rid
    row["vendor_id"] = rid
    row["vendor_request_id_source"] = "response" if uuid else ("caller" if caller else None)
    row["ids"] = {"request_uuid": uuid, "caller": caller}


def _base(raw: bytes | None, at: str, caller: str | None, req_sha: str | None) -> dict:
    row = LAKERA_GUARD.base_row(raw, at)
    row["input_sha256"] = hashlib.sha256(raw).hexdigest() if raw is not None else None
    row["request_sha256"] = req_sha
    if req_sha is not None:
        row["subject"] = {"name": f"{VENDOR}:screened-request", "sha256": req_sha}
    _set_id(row, None, caller)
    row["finding"] = None  # the doc: every row carries `finding`; a refusal row has none
    return _seal(row)


def _copy(base: dict) -> dict:
    return json.loads(json.dumps(base))


def _cnl(row: dict, looked_for: str, where: str, reason_word: str, reason: str) -> dict:
    return _seal(LAKERA_GUARD.mark_could_not_look(row, looked_for, where, reason_word, reason))


def _digest(v: Any) -> str | None:
    try:
        return LAKERA_GUARD.digest(v) if v is not None else None
    except Exception:  # noqa: BLE001 - a value JCS refuses has no digest
        return None


def _int(v: Any) -> int | None:
    return v if type(v) is int else None


def _labels(v: Any) -> list | None:
    if not isinstance(v, list):
        return None
    return [_safe_str(x) for x in v[:16] if isinstance(x, str)]


def _row(base: dict, word: str, where: str, **extra) -> dict:
    row = _copy(base)
    f = dict.fromkeys(_FINDING_KEYS)
    f.update(extra)
    row["finding"] = f
    row["vendor_word"] = word
    row["mapping"] = {"rule": "table"}
    row["relayed_verdict"] = TABLE[word]
    if TABLE[word] == COULD_NOT_LOOK:
        row["could_not_look"] = could_not_look("a Lakera Guard result this adapter can read "
                                               "as pass or fail", where, *_WHY[word])
    return _seal(row)


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


def _breakdown_rows(base: dict, bd: Any) -> tuple[list, int, int, bool]:
    """(rows, reported, detected, any unreadable) for the breakdown list."""
    if bd is None:
        return [], 0, 0, False
    if not isinstance(bd, list):
        return [_row(base, "detector_unreadable", "breakdown", part="breakdown")], 0, 0, True
    rows, detected, bad = [], 0, False
    for i, d in enumerate(bd):
        w = f"breakdown[{i}]"
        if not isinstance(d, dict) or type(d.get("detected")) is not bool:
            rows.append(_row(base, "detector_unreadable", w, part="breakdown", index=i))
            bad = True
            continue
        if not d["detected"]:
            continue
        detected += 1
        rows.append(_row(base, "detector_detected", w, part="breakdown", index=i,
                         project_id=_safe_str(d.get("project_id")),
                         policy_id=_safe_str(d.get("policy_id")),
                         detector_id=_safe_str(d.get("detector_id")),
                         detector_type=_safe_str(d.get("detector_type")), detected=True,
                         result=_safe_str(d.get("result")),
                         message_id=_int(d.get("message_id"))))
    return rows, len(bd), detected, bad


def _payload_rows(base: dict, pl: Any) -> tuple[list, int, bool]:
    """(rows, matches, any unreadable) for the payload list."""
    if pl is None:
        return [], 0, False
    if not isinstance(pl, list):
        return [_row(base, "payload_unreadable", "payload", part="payload")], 0, True
    rows, n, bad = [], 0, False
    for i, m in enumerate(pl):
        w = f"payload[{i}]"
        if not isinstance(m, dict):
            rows.append(_row(base, "payload_unreadable", w, part="payload", index=i))
            bad = True
            continue
        n += 1
        rows.append(_row(base, "payload_match", w, part="payload", index=i,
                         detector_type=_safe_str(m.get("detector_type")),
                         labels=_labels(m.get("labels")), message_id=_int(m.get("message_id")),
                         start=_int(m.get("start")), end=_int(m.get("end")),
                         text_digest=_digest(_safe_str(m.get("text")))))
    return rows, n, bad


def _tools_rows(base: dict, tl: Any) -> tuple[list, bool]:
    """(rows, anything pointing away from a pass) for the `tools` block: the
    screening of the request's tool definitions, which the API reference lists
    beside the message-level flagged/breakdown (read 2026-10-05)."""
    if tl is None:
        return [], False
    if not isinstance(tl, dict) or ("flagged" in tl and type(tl["flagged"]) is not bool):
        return [_row(base, "tools_unreadable", "tools", part="tools")], True
    rows, hit = [], False
    if tl.get("flagged") is True:
        rows.append(_row(base, "tools_flagged", "tools", part="tools", flagged=True))
        hit = True
    bd = tl.get("breakdown")
    if bd is not None and not isinstance(bd, list):
        return rows + [_row(base, "tools_unreadable", "tools.breakdown", part="tools")], True
    for i, d in enumerate(bd or []):
        w = f"tools.breakdown[{i}]"
        if not isinstance(d, dict) or type(d.get("detected")) is not bool:
            rows.append(_row(base, "tools_unreadable", w, part="tools_breakdown", index=i))
            hit = True
            continue
        if d["detected"]:
            hit = True
            rows.append(_row(base, "tool_detector_detected", w, part="tools_breakdown", index=i,
                             project_id=_safe_str(d.get("project_id")),
                             policy_id=_safe_str(d.get("policy_id")),
                             detector_id=_safe_str(d.get("detector_id")),
                             detector_type=_safe_str(d.get("detector_type")), detected=True,
                             result=_safe_str(d.get("result")), tool_id=_int(d.get("tool_id"))))
    return rows, hit


def _response_word(flagged: Any, mode: str | None, unsettled: bool,
                   action: Any = None) -> str:
    if type(flagged) is not bool:
        return "flagged_unreadable"
    if flagged:
        return "flagged"
    if unsettled:
        return "not_flagged_unsettled"
    if mode is not None and action in POLICY_MODES and action != mode:
        return "not_flagged_mode_conflict"
    if mode == "enforce":
        return "not_flagged"
    return "not_flagged_detect_mode" if mode == "detect" else "not_flagged_mode_undeclared"


def _screening(doc: dict, out: _Out, mode: str | None) -> None:
    base = out.base
    d_rows, reported, detected, d_bad = _breakdown_rows(base, doc.get("breakdown"))
    p_rows, matches, p_bad = _payload_rows(base, doc.get("payload"))
    t_rows, t_hit = _tools_rows(base, doc.get("tools"))
    unsettled = bool(detected or matches or d_bad or p_bad or t_hit)
    dev = doc.get("dev_info") if isinstance(doc.get("dev_info"), dict) else {}
    word = _response_word(doc.get("flagged"), mode, unsettled, doc.get("action"))
    flagged = doc.get("flagged") if type(doc.get("flagged")) is bool else None
    out.add(_row(base, word, _WHERE, part="response", flagged=flagged,
                 action=_safe_str(doc.get("action")), policy_mode=mode,
                 detectors_reported=reported, detectors_detected=detected,
                 payload_matches=matches, model_version=_safe_str(dev.get("model_version")),
                 vendor_version=_safe_str(dev.get("version"))))
    for r in d_rows + p_rows + t_rows:
        out.add(r)


# ---------------------------------------------------------------- entry points

def _mode(v: Any) -> str | None:
    if v is None:
        return None
    if not isinstance(v, str) or v not in POLICY_MODES:
        raise ValueError(f"policy_mode must be one of {POLICY_MODES}, or None")
    return v


def _request_sha(v: Any) -> str | None:
    if v is None:
        return None
    if isinstance(v, str):
        v = v.encode("utf-8", "surrogatepass")
    if not isinstance(v, (bytes, bytearray)):
        raise ValueError("request_body must be the bytes (or str) sent to Lakera, or None")
    return hashlib.sha256(bytes(v)).hexdigest()


def _uuid(doc: Any) -> str | None:
    md = doc.get("metadata") if isinstance(doc, dict) else None
    u = md.get("request_uuid") if isinstance(md, dict) else None
    return _safe_str(u) or None


def ingest(raw: Any, *, policy_mode: Any = None, vendor_request_id: Any = None,
           request_body: Any = None, received_at: str | None = None) -> list:
    """A Lakera Guard v2 screening response (the bytes as read) -> a list of relayed rows.

    `policy_mode`: "enforce" or "detect", what the caller knows of the Lakera
    policy that screened the request; None (the default) leaves "not flagged"
    COULD NOT LOOK. Any other value raises ValueError (a caller error).
    `vendor_request_id`: an id the caller holds, used when the response carries
    no `metadata.request_uuid`. `request_body`: the bytes sent to Lakera, kept
    as `request_sha256` only. Never raises on the response; an unreadable
    response is one COULD NOT LOOK row."""
    mode = _mode(policy_mode)
    req_sha = _request_sha(request_body)
    caller = _safe_str(vendor_request_id)
    at = received_at if isinstance(received_at, str) else _now_iso()
    try:
        if isinstance(raw, str):
            raw = raw.encode("utf-8", "surrogatepass")
        if not isinstance(raw, (bytes, bytearray)):
            return [_cnl(_base(None, at, caller, req_sha), "Lakera Guard JSON bytes",
                         "argument", "unreadable",
                         f"response is a {type(raw).__name__}, not bytes")]
        raw = bytes(raw)
        base = _base(raw, at, caller, req_sha)
        if not raw:
            return [_cnl(base, "Lakera Guard JSON", _WHERE, "empty", "the response is empty")]
        if len(raw) > MAX_PAYLOAD_BYTES:
            return [_cnl(base, "Lakera Guard JSON", _WHERE, "bounded",
                         f"response is {len(raw)} bytes, over the {MAX_PAYLOAD_BYTES}-byte "
                         f"limit; digested, not read")]
        try:
            doc = loads_strict(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError) as e:
            return [_cnl(base, "Lakera Guard JSON", _WHERE, "unreadable",
                         f"response is not one unambiguous UTF-8 JSON value: "
                         f"{type(e).__name__}")]
        if _too_deep(doc, MAX_DEPTH):
            return [_cnl(base, "Lakera Guard JSON", _WHERE, "unreadable",
                         f"response nests deeper than {MAX_DEPTH}")]
        _set_id(base, _uuid(doc), caller)
        _seal(base)
        if isinstance(doc, dict) and "flagged" in doc:
            out = _Out(base)
            try:
                _screening(doc, out, mode)
            except _Full:
                pass
            return out.rows
        if isinstance(doc, dict) and isinstance(doc.get("results"), list):
            return [_row(base, "results_not_screening", _WHERE, part="response",
                         policy_mode=mode)]
        return [_cnl(base, "a Lakera Guard screening response (flagged)", _WHERE,
                     "name_not_found", "the JSON is not a Lakera Guard response shape")]
    except Exception as e:  # noqa: BLE001 - never a traceback on what a vendor sends
        return [_cnl(_base(None, at, caller, req_sha), "Lakera Guard JSON", _WHERE,
                     "unreadable", f"the adapter failed: {type(e).__name__}")]


def standing_verdict(rows: Any) -> dict:
    """The one rollup (core.rollup_rows, docs/CONNECTOR_ADAPTER.md "The rollup"):
    BROKEN when any of this adapter's rows relays BROKEN;
    otherwise COULD NOT LOOK, with the per-word counts. Never VERIFIED: unsigned
    rows reported by the sender cannot make a VERIFIED by themselves. No bare
    `verdict` key. Rows not from this adapter are not counted. Never raises."""
    return rollup_rows(rows, VENDOR, label='Lakera Guard', standing=STANDING,
                       broken_reason='Lakera Guard relayed BROKEN for at least one result (unsigned)')
