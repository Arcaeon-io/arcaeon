# SPDX-License-Identifier: MIT
"""arcaeon.connector.snyk_agent_scan: Snyk agent-scan (formerly Invariant mcp-scan)
`--json` output becomes relayed check rows, one per finding, plus one per clean
or unreadable target, on the one adapter base (arcaeon.connector.core.VendorAdapter).

THE FORMAT, as the snyk/agent-scan repository documents it (docs/json-output.md,
models/api/v20260710.py, docs/issue-codes.md; read for Batch 200 research R15):

  v0.6+  {"scan_path_responses": [{client, path, error,
            server_risks: [{name, entities, risk_indexes: {risk: {score 0..1000,
                            evidence, affected_tools}}, error}],
            skill_risks:  [{name, files, risk_indexes: {risk: {score, evidence,
                            locations}}, error}]}]}
  v0.5.x {"<path>": {client, path, error, servers: [{name, config_path, server,
            signature, error}], issues: [{code, message, reference:
            [server_index, entity_index], extra_data}], labels}}

In v0.5 a server's `signature` is its tool catalog, not a cryptographic signature.
Neither shape carries a request or scan id, and neither is signed.

THE WORD. agent-scan writes no per-finding verdict word, so the adapter writes its
own (as the OPA and mcp-scan adapters do):

    no_findings                 target analysed, nothing points at it    -> VERIFIED
    issue_error                 a v0.5 E* code                           -> BROKEN
    issue_warning               a v0.5 W* code                           -> BROKEN
    risk_at_or_over_threshold   a v0.6 score >= broken_at_score          -> BROKEN
    scan_failure                a v0.5 X* code (the scan itself failed)  -> COULD NOT LOOK
    unknown_code                a v0.5 code not shaped [EWX]ddd          -> COULD NOT LOOK
    risk_below_threshold        a v0.6 score < broken_at_score           -> COULD NOT LOOK
    risk_no_threshold           a v0.6 score, no broken_at_score given   -> COULD NOT LOOK
    risk_unscored               a v0.6 risk with no 0..1000 number score -> COULD NOT LOOK
    error                       a path or target error                   -> COULD NOT LOOK
    not_analyzed                listed but never analysed                -> COULD NOT LOOK

A v0.6 score is a number from 0 to 1000, not pass or fail, and agent-scan
documents no cut-off; so the caller declares one (`broken_at_score`), as the OPA
adapter makes the caller declare polarity. A low score is not a pass.

THE ROW. The check.verdict.relayed row of arcaeon.connector.core, plus:

    signed_by_vendor   False. Always. No argument, flag or payload field sets it
                       (R15: agent-scan does not sign its output).
    standing           "reported_by_sender". Always.
    input_sha256       hex SHA-256 of the exact bytes read (None when given no bytes)
    vendor_request_id  the caller's `vendor_request_id` (a transport id it holds),
                       else None; the JSON carries none and nothing in it is read as one
    finding            {format, scan_path, client, target_kind ("path" | "server" |
                       "skill"), target_name, target_index, code, severity ("error" |
                       "warning" | "failure" | None), reference, risk, score, threshold,
                       affected_tools, evidence_digest}
    vendor_id          the same as vendor_request_id
    subject            {"name": "snyk-agent-scan:<client>/<target>", "sha256": None}
    attestation        always NONE

Evidence text is kept by digest only (it can quote tool descriptions). Messages,
server commands, configs and file lists are not copied.

`standing_verdict(rows)` is what these rows can say on their own: BROKEN when any
row relays BROKEN, otherwise COULD NOT LOOK. Never VERIFIED: an unsigned vendor
row is reported by sender and cannot make a VERIFIED by itself (T4). A relayed
BROKEN always stays BROKEN (stack review F12).

Not arcaeon.prove.mcp_scan: that adapter writes one row per TOOL and pins tool
definitions for verify_tool_called; this one writes one row per FINDING. Nothing
is shared beyond connector.core. Never raises on what the scanner sends. Stdlib
only. No network: this reads output you already hold.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any

from arcaeon.record.row import loads_strict
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED, could_not_look

from .core import (AdapterError, Extracted, VendorAdapter, _now_iso, _safe_str, _too_deep,
                   register)

__all__ = ["VENDOR", "ADAPTER_VERSION", "TABLE", "MAX_PAYLOAD_BYTES", "MAX_DEPTH", "MAX_ROWS",
           "SCORE_MAX", "STANDING", "SnykAgentScanAdapter", "SNYK_AGENT_SCAN", "ingest",
           "standing_verdict"]

VENDOR = "snyk-agent-scan"
ADAPTER_VERSION = "1"
#: Output over this is digested, never read.
MAX_PAYLOAD_BYTES = 8 << 20
MAX_DEPTH = 64
#: More rows than this from one output: the rest are not read, and a row says so.
MAX_ROWS = 10000
#: v0.6 risk scores run 0 to 1000.
SCORE_MAX = 1000
STANDING = "reported_by_sender"

TABLE = {
    "no_findings": VERIFIED,
    "issue_error": BROKEN,
    "issue_warning": BROKEN,
    "risk_at_or_over_threshold": BROKEN,
    "scan_failure": COULD_NOT_LOOK,
    "unknown_code": COULD_NOT_LOOK,
    "risk_below_threshold": COULD_NOT_LOOK,
    "risk_no_threshold": COULD_NOT_LOOK,
    "risk_unscored": COULD_NOT_LOOK,
    "error": COULD_NOT_LOOK,
    "not_analyzed": COULD_NOT_LOOK,
}

FORMAT_V05 = "v0.5-path-keyed"
FORMAT_V06 = "v0.6-scan-response"

_WHERE = "agent-scan output"
_SEVERITY = {"E": ("issue_error", "error"), "W": ("issue_warning", "warning"),
             "X": ("scan_failure", "failure")}
_CODE = re.compile(r"[EWX][0-9]{3}")
_WHY = {
    "scan_failure": ("unreadable", "agent-scan reported that its own scan failed (X code)"),
    "unknown_code": ("name_not_found", "the issue code is not an E, W or X code"),
    "risk_below_threshold": ("missing", "the score is under broken_at_score; a low score "
                                        "is not a pass"),
    "risk_no_threshold": ("name_not_found", "no broken_at_score was declared, so a 0..1000 "
                                            "score cannot be read as pass or fail"),
    "risk_unscored": ("unreadable", "the risk has no number score from 0 to 1000"),
    "error": ("missing", "agent-scan reported an error for this path or target"),
    "not_analyzed": ("missing", "the target was listed but never analysed"),
}


class SnykAgentScanAdapter(VendorAdapter):
    """Snyk agent-scan on the one adapter base. One output, many rows: read it with
    `ingest`, not import_verdict (whose `extract` path refuses it)."""
    name = VENDOR
    version = ADAPTER_VERSION
    table = TABLE
    max_payload_bytes = MAX_PAYLOAD_BYTES
    max_depth = MAX_DEPTH
    one_row_per_payload = False

    def extract(self, doc: dict) -> Extracted:
        raise AdapterError("agent-scan output is one row per finding; read it with "
                           "arcaeon.connector.snyk_agent_scan.ingest")


SNYK_AGENT_SCAN = register(SnykAgentScanAdapter())


def _seal(row: dict) -> dict:
    """The R15 rule, applied last to every row this module returns: unsigned,
    reported by sender, no attestation claim. There is no other code path."""
    row["signed_by_vendor"] = False
    row["standing"] = STANDING
    row["attestation"] = {"status": "NONE", "checked_by_us": False, "claimed": None}
    return row


def _base(raw: bytes | None, at: str, req_id: str | None) -> dict:
    row = SNYK_AGENT_SCAN.base_row(raw, at)
    row["input_sha256"] = hashlib.sha256(raw).hexdigest() if raw is not None else None
    row["vendor_request_id"] = req_id
    row["vendor_id"] = req_id
    row["finding"] = None  # the doc: every row carries `finding`; a refusal row has none
    return _seal(row)


def _copy(base: dict) -> dict:
    return json.loads(json.dumps(base))


def _cnl(row: dict, looked_for: str, where: str, reason_word: str, reason: str) -> dict:
    return _seal(SNYK_AGENT_SCAN.mark_could_not_look(row, looked_for, where, reason_word,
                                                     reason))


def _digest(v: Any) -> str | None:
    try:
        return SNYK_AGENT_SCAN.digest(v) if v is not None else None
    except Exception:  # noqa: BLE001 - a value JCS refuses has no digest
        return None


def _ints(v: Any) -> list | None:
    if not isinstance(v, list):
        return None
    return [x for x in v[:64] if type(x) is int]


def _score(v: Any) -> int | float | None:
    if type(v) not in (int, float) or (isinstance(v, float) and not math.isfinite(v)):
        return None
    return v if 0 <= v <= SCORE_MAX else None


def _row(base: dict, word: str, *, fmt: str, scan_path: Any, client: Any, kind: str,
         name: Any, index: int | None, where: str, **extra) -> dict:
    row = _copy(base)
    f = {"format": fmt, "scan_path": _safe_str(scan_path), "client": _safe_str(client),
         "target_kind": kind, "target_name": _safe_str(name), "target_index": index,
         "code": None, "severity": None, "reference": None, "risk": None, "score": None,
         "threshold": None, "affected_tools": None, "evidence_digest": None}
    f.update(extra)
    row["finding"] = f
    row["vendor_word"] = word
    row["mapping"] = {"rule": "table"}
    row["relayed_verdict"] = TABLE[word]
    if f["client"] or f["target_name"]:
        row["subject"] = {"name": f"{VENDOR}:{f['client'] or ''}/{f['target_name'] or ''}",
                          "sha256": None}
    if TABLE[word] == COULD_NOT_LOOK:
        row["could_not_look"] = could_not_look("an agent-scan finding this adapter can read "
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
            self.rows.append(_cnl(_copy(self.base), "every finding in the output", _WHERE,
                                  "bounded", f"more than {MAX_ROWS} rows; the rest were "
                                             f"not read"))
            raise _Full
        self.rows.append(row)


# ---------------------------------------------------------------- v0.6

def _risk_row(base, rname, rv, threshold, **ctx) -> dict:
    score = _score(rv.get("score")) if isinstance(rv, dict) else None
    if score is None:
        word = "risk_unscored"
    elif threshold is None:
        word = "risk_no_threshold"
    else:
        word = "risk_at_or_over_threshold" if score >= threshold else "risk_below_threshold"
    rv = rv if isinstance(rv, dict) else {}
    return _row(base, word, risk=_safe_str(rname), score=score, threshold=threshold,
                affected_tools=_ints(rv.get("affected_tools")),
                evidence_digest=_digest(_safe_str(rv.get("evidence"))), **ctx)


def _v06(doc: dict, out: _Out, threshold) -> None:
    base = out.base
    for pi, spr in enumerate(doc["scan_path_responses"]):
        where = f"scan_path_responses[{pi}]"
        if not isinstance(spr, dict):
            out.add(_cnl(_copy(base), "a scan path response", where, "unreadable",
                         "not an object"))
            continue
        path, client = spr.get("path"), spr.get("client")
        groups = [("server", spr.get("server_risks")), ("skill", spr.get("skill_risks"))]
        if not isinstance(groups[0][1], list) and not isinstance(groups[1][1], list):
            word = "error" if spr.get("error") is not None else "not_analyzed"
            out.add(_row(base, word, fmt=FORMAT_V06, scan_path=path, client=client,
                         kind="path", name=None, index=None, where=where))
            continue
        for kind, items in groups:
            if not isinstance(items, list):
                continue
            for i, t in enumerate(items):
                w = f"{where}.{kind}_risks[{i}]"
                if not isinstance(t, dict):
                    out.add(_cnl(_copy(base), f"a {kind} risk entry", w, "unreadable",
                                 "not an object"))
                    continue
                ctx = dict(fmt=FORMAT_V06, scan_path=path, client=client, kind=kind,
                           name=t.get("name"), index=i, where=w)
                risks = t.get("risk_indexes")
                failed = t.get("error") is not None or spr.get("error") is not None
                if failed:
                    out.add(_row(base, "error", **ctx))
                if not isinstance(risks, dict):
                    if not failed:
                        out.add(_row(base, "not_analyzed", **ctx))
                    continue
                if not risks and not failed:
                    out.add(_row(base, "no_findings", **ctx))
                for rname, rv in risks.items():
                    out.add(_risk_row(base, rname, rv, threshold, **ctx))


# ---------------------------------------------------------------- v0.5

def _ref(issue: dict) -> tuple[Any, Any]:
    ref = issue.get("reference")
    if ref is None:
        return None, None
    ok = lambda x: type(x) is int and x >= 0  # noqa: E731 - not bool, not negative
    if isinstance(ref, list) and len(ref) == 2 and ok(ref[0]) and (ref[1] is None or ok(ref[1])):
        return ref[0], ref[1]
    return "bad", "bad"


def _issue_row(base, issue: dict, **ctx) -> dict:
    code = issue.get("code")
    if isinstance(code, str) and _CODE.fullmatch(code):
        word, sev = _SEVERITY[code[0]]
    else:
        word, sev = "unknown_code", None
    s, e = _ref(issue)
    ref = [s, e] if s not in (None, "bad") else None
    return _row(base, word, code=_safe_str(code), severity=sev, reference=ref, **ctx)


def _v05(doc: dict, out: _Out) -> None:
    base = out.base
    for path, res in doc.items():
        where = f"result[{_safe_str(path)!r}]"
        client = res.get("client")
        servers = res.get("servers")
        analysed = isinstance(res.get("issues"), list)
        issues = [i for i in res.get("issues")] if analysed else []
        path_failed = res.get("error") is not None
        if not isinstance(servers, list):
            word = "error" if path_failed else "not_analyzed"
            out.add(_row(base, word, fmt=FORMAT_V05, scan_path=path, client=client,
                         kind="path", name=None, index=None, where=where))
            servers = []
        wide = [i for i in issues if not isinstance(i, dict) or _ref(i)[0] in (None, "bad")]
        for si, srv in enumerate(servers):
            w = f"{where}.servers[{si}]"
            if not isinstance(srv, dict):
                out.add(_cnl(_copy(base), "a server entry", w, "unreadable", "not an object"))
                continue
            ctx = dict(fmt=FORMAT_V05, scan_path=path, client=client, kind="server",
                       name=srv.get("name"), index=si, where=w)
            mine = [i for i in issues if isinstance(i, dict) and _ref(i)[0] == si]
            failed = srv.get("error") is not None or path_failed
            if failed:
                out.add(_row(base, "error", **ctx))
            elif not analysed:
                out.add(_row(base, "not_analyzed", **ctx))
            elif not mine and not wide:
                out.add(_row(base, "no_findings", **ctx))
            for issue in mine:
                out.add(_issue_row(base, issue, **ctx))
        for issue in wide:
            ctx = dict(fmt=FORMAT_V05, scan_path=path, client=client, kind="path", name=None,
                       index=None, where=where)
            if not isinstance(issue, dict):
                out.add(_cnl(_copy(base), "an issue entry", where, "unreadable",
                             "not an object"))
                continue
            out.add(_issue_row(base, issue, **ctx))


# ---------------------------------------------------------------- entry points

def _threshold(v: Any) -> int | None:
    if v is None:
        return None
    if type(v) is not int or not 0 <= v <= SCORE_MAX:
        raise ValueError(f"broken_at_score must be an int from 0 to {SCORE_MAX}, or None")
    return v


def ingest(raw: Any, *, broken_at_score: Any = None, vendor_request_id: Any = None,
           received_at: str | None = None) -> list:
    """agent-scan `--json` output (the bytes as read) -> a list of relayed rows.

    `broken_at_score`: the v0.6 score (0..1000) at or over which a risk reads
    BROKEN; None (the default) leaves every scored risk COULD NOT LOOK. A value
    outside 0..1000 raises ValueError (a caller error, not scanner input).
    `vendor_request_id`: an id the caller holds from the transport, if any.
    Never raises on the output; unreadable output is one COULD NOT LOOK row."""
    threshold = _threshold(broken_at_score)
    req = _safe_str(vendor_request_id)
    at = received_at if isinstance(received_at, str) else _now_iso()
    try:
        if isinstance(raw, str):
            raw = raw.encode("utf-8", "surrogatepass")
        if not isinstance(raw, (bytes, bytearray)):
            return [_cnl(_base(None, at, req), "agent-scan JSON bytes", "argument",
                         "unreadable", f"output is a {type(raw).__name__}, not bytes")]
        raw = bytes(raw)
        base = _base(raw, at, req)
        if not raw:
            return [_cnl(base, "agent-scan JSON", _WHERE, "empty", "the output is empty")]
        if len(raw) > MAX_PAYLOAD_BYTES:
            return [_cnl(base, "agent-scan JSON", _WHERE, "bounded",
                         f"output is {len(raw)} bytes, over the {MAX_PAYLOAD_BYTES}-byte "
                         f"limit; digested, not read")]
        try:
            doc = loads_strict(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError) as e:
            return [_cnl(base, "agent-scan JSON", _WHERE, "unreadable",
                         f"output is not one unambiguous UTF-8 JSON value: {type(e).__name__}")]
        if _too_deep(doc, MAX_DEPTH):
            return [_cnl(base, "agent-scan JSON", _WHERE, "unreadable",
                         f"output nests deeper than {MAX_DEPTH}")]
        out = _Out(base)
        try:
            if isinstance(doc, dict) and isinstance(doc.get("scan_path_responses"), list):
                _v06(doc, out, threshold)
            elif isinstance(doc, dict) and doc and all(
                    isinstance(v, dict) and "path" in v and "servers" in v
                    for v in doc.values()):
                _v05(doc, out)
            else:
                return [_cnl(base, "an agent-scan result (scan_path_responses or "
                                   "path-keyed)", _WHERE, "name_not_found",
                             "the JSON is not an agent-scan output shape")]
        except _Full:
            pass
        if not out.rows:
            return [_cnl(base, "a scanned target", _WHERE, "empty",
                         "the output lists no scanned targets")]
        return out.rows
    except Exception as e:  # noqa: BLE001 - never a traceback on what a scanner sends
        return [_cnl(_base(None, at, req), "agent-scan JSON", _WHERE, "unreadable",
                     f"the adapter failed: {type(e).__name__}")]


def standing_verdict(rows: Any) -> dict:
    """What agent-scan rows can say on their own. BROKEN when any of them relays
    BROKEN (a relayed BROKEN never becomes anything else, whatever else the row
    claims); otherwise COULD NOT LOOK, because an unsigned row reported by sender
    cannot make a VERIFIED by itself. Never VERIFIED. Never raises."""
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
        out["reason"] = "agent-scan relayed BROKEN for at least one target"
    else:
        out.update(could_not_look(
            "a check of our own or a signed vendor verdict", "rows",
            "missing" if ours else "empty",
            "agent-scan rows are unsigned and reported by sender; they cannot make a "
            "VERIFIED by themselves" if ours else "no agent-scan rows were given"))
    return out
