# SPDX-License-Identifier: MIT
"""arcaeon.connector.opa: an Open Policy Agent decision-log POST body becomes
relayed check rows, one per decision event, on the one adapter base
(arcaeon.connector.core.VendorAdapter).

THE FORMAT, as OPA documents it (Decision Logs page, "Decision Log Service API",
https://www.openpolicyagent.org/docs/latest/management-decision-logs/, read
2026-10-04): OPA's decision-log plugin POSTs to `/logs` (or the configured
resource) with `Content-Encoding: gzip`, `Content-Type: application/json`, and a
body that is a gzip-compressed JSON ARRAY. Each element is one event:

    labels            object   identifies the OPA instance (id, version, ...)
    decision_id       string   unique per decision
    trace_id, span_id string   W3C trace context
    bundles           object   {bundle name: {"revision": string}}
    path              string   the policy decision path, e.g. "http/example/authz/allow";
                               receivers should tolerate a leading slash
    query             string   an ad-hoc Rego query (Query API) instead of a path
    input             any      the input to the policy query
    result            any      the decision returned to the client, e.g. true or false;
                               ABSENT when the decision was undefined
    requested_by      string   the client (e.g. its address)
    request_context.http.headers  object  configured headers
    timestamp         string   RFC 3339
    metrics           object   performance metrics
    erased, masked    [string] JSON Pointers (prefixed /input, /result or
                               /nd_builtin_cache) erased or masked by system.log.mask
    nd_builtin_cache  object   non-deterministic builtin inputs/outputs
    req_id            number   per-instance request counter
    ids, rule_labels  array    annotation ids / labels of rules evaluated

Not documented as a field: any error. The doc's own example writes the result as
the STRING "true"; the table says a boolean. This adapter maps booleans only.

THE WORD. A decision is not a verdict word: `true` at `authz/allow` is a pass,
`true` at `authz/deny` is a refusal, and OPA cannot say which. So the caller
declares the polarity of each path it trusts (`allow_paths`, `deny_paths`), and the
adapter writes its own per-event word (as mcp-scan's adapter does):

    allowed          a boolean result that lets the request through   -> VERIFIED
    denied           a boolean result that refuses it                -> BROKEN
    undeclared_path  a boolean result at a path in neither list      -> COULD NOT LOOK
    non_boolean      a result that is not JSON true/false             -> COULD NOT LOOK
    undefined        no result (OPA's undefined decision)            -> COULD NOT LOOK
    masked           the result was erased or masked (/result pointer) -> COULD NOT LOOK

THE ROW. The check.verdict.relayed row of arcaeon.connector.core, plus ONE
adapter key, `decision`:

    decision.event_index, path, query, timestamp, labels {id, version},
    bundles {name: revision}, erased, masked, input_masked,
    input_digest (the base's sha256:jcs:v1 digest of `input`, or None),
    result_digest (the same over `result`), polarity ("allow" | "deny" | None),
    payload_encoding ("gzip" | "identity")

    vendor_id   the event's decision_id
    subject     {"name": "opa:<path>", "sha256": hex of input_digest}: what OPA judged.
                With input_masked true the digest is of the input AFTER masking.
    attestation always NONE: decision logs are unsigned, so every row is reported
                by sender

Not copied: requested_by, request_context (client addresses and headers), metrics,
nd_builtin_cache, the input and result themselves (kept by digest only).
vendor_payload_digest is over the body exactly as received (gzipped or not).

WHICH POLICY. `join_bundles(rows, seals)` joins each row's bundle revisions to
bundles sealed by arcaeon.connector.opa_bundle.seal_bundle (VERIFIED, BROKEN or
COULD NOT LOOK in `policy_join`); see that function and docs/CONNECTOR_ADAPTER.md.

`recheck` says COULD NOT LOOK for these rows (one payload, many rows); re-run
`ingest` with the same body and path lists to compare. Never raises on what OPA
sends. Stdlib only. No network: this reads a body you already hold.
"""
from __future__ import annotations

import json
import zlib
from typing import Any

from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED, could_not_look

from .core import (JCS_DIGEST_PREFIX, AdapterError, Extracted, VendorAdapter, _now_iso,
                   _safe_str, _too_deep, register)
from arcaeon.record.row import loads_strict

from .core import ROW_KIND
from .opa_bundle import SEAL_KIND, parse_ts

__all__ = ["VENDOR", "ADAPTER_VERSION", "TABLE", "MAX_PAYLOAD_BYTES", "MAX_BODY_BYTES",
           "MAX_DEPTH", "MAX_ROWS", "OpaDecisionLogAdapter", "OPA", "ingest", "join_bundles"]

VENDOR = "opa"
ADAPTER_VERSION = "1"
#: The body as received (gzipped or not) over this is digested, never read.
MAX_PAYLOAD_BYTES = 8 << 20
#: The decompressed body over this is not read (a gzip bomb is bounded).
MAX_BODY_BYTES = 32 << 20
#: Inputs are documents; leave room for one.
MAX_DEPTH = 64
#: More events than this in one body: the rest are not read, and a row says so.
MAX_ROWS = 10000

TABLE = {
    "allowed": VERIFIED,
    "denied": BROKEN,
    "undeclared_path": COULD_NOT_LOOK,
    "non_boolean": COULD_NOT_LOOK,
    "undefined": COULD_NOT_LOOK,
    "masked": COULD_NOT_LOOK,
}

_WHERE = "OPA decision log"
_WHY = {
    "undeclared_path": ("name_not_found", "the path is in neither allow_paths nor deny_paths, "
                                          "so true/false cannot be read as pass or fail"),
    "non_boolean": ("unreadable", "the result is not JSON true or false"),
    "undefined": ("missing", "the event has no result (OPA's undefined decision)"),
    "masked": ("missing", "the result was erased or masked before upload"),
}


class OpaDecisionLogAdapter(VendorAdapter):
    """OPA decision logs on the one adapter base. One body, many rows: read it with
    `ingest`, not import_verdict (whose `extract` path refuses it)."""
    name = VENDOR
    version = ADAPTER_VERSION
    table = TABLE
    max_payload_bytes = MAX_PAYLOAD_BYTES
    max_depth = MAX_DEPTH
    one_row_per_payload = False

    def extract(self, doc: dict) -> Extracted:
        raise AdapterError("an OPA decision log is one row per event; read it with "
                           "arcaeon.connector.opa.ingest")


OPA = register(OpaDecisionLogAdapter())

_cnl = OPA.mark_could_not_look


def _norm(path: Any) -> str | None:
    return path.lstrip("/") if isinstance(path, str) else None


def _paths(given: Any, which: str) -> set:
    if isinstance(given, str):
        given = (given,)
    out = set()
    for p in given or ():
        n = _norm(p)
        if not n:
            raise ValueError(f"{which}: every path must be a non-empty string")
        out.add(n)
    return out


def _gunzip(raw: bytes) -> bytes:
    """One gzip member, fully present, at most MAX_BODY_BYTES out. Raises ValueError
    (bounded) or zlib.error / EOFError (unreadable)."""
    d = zlib.decompressobj(wbits=31)
    out = d.decompress(raw, MAX_BODY_BYTES + 1)
    if len(out) > MAX_BODY_BYTES:
        raise OverflowError
    if not d.eof:
        raise EOFError("truncated gzip body")
    if d.unused_data or d.unconsumed_tail:
        raise EOFError("bytes after the gzip member")
    return out


def _digest(v: Any) -> str | None:
    try:
        return OPA.digest(v)
    except Exception:  # noqa: BLE001 - a value JCS refuses has no digest
        return None


def _ptrs(v: Any) -> list | None:
    if not isinstance(v, list):
        return None
    return [s for s in (_safe_str(p) for p in v[:64]) if s is not None]


def _labels(v: Any) -> dict | None:
    if not isinstance(v, dict):
        return None
    return {k: _safe_str(v.get(k)) for k in ("id", "version") if k in v}


def _bundles(v: Any) -> dict | None:
    if not isinstance(v, dict):
        return None
    out = {}
    for k in sorted(v, key=str)[:32]:
        b = v[k]
        out[_safe_str(k) or ""] = _safe_str(b.get("revision")) if isinstance(b, dict) else None
    return out


def _word(ev: dict, path: str | None, allow: set, deny: set,
          erased: list | None, masked: list | None) -> tuple[str, str | None]:
    hidden = [p for p in (erased or []) + (masked or [])
              if p == "/result" or p.startswith("/result/")]
    if hidden:
        return "masked", None
    if "result" not in ev:
        return "undefined", None
    res = ev["result"]
    if not isinstance(res, bool):
        return "non_boolean", None
    if path in allow:
        return ("allowed" if res else "denied"), "allow"
    if path in deny:
        return ("denied" if res else "allowed"), "deny"
    return "undeclared_path", None


def _event_row(base: dict, i: int, ev: Any, allow: set, deny: set, enc: str) -> dict:
    row = json.loads(json.dumps(base))
    if not isinstance(ev, dict):
        row["decision"] = {"event_index": i, "payload_encoding": enc}
        return _cnl(row, "a decision event object", f"{_WHERE}[{i}]", "unreadable",
                    "the event is not a JSON object")
    path = _norm(ev.get("path"))
    erased, masked = _ptrs(ev.get("erased")), _ptrs(ev.get("masked"))
    word, polarity = _word(ev, path, allow, deny, erased, masked)
    has_input = "input" in ev
    in_dig = _digest(ev["input"]) if has_input else None
    d = {"event_index": i, "path": _safe_str(path), "query": _safe_str(ev.get("query")),
         "timestamp": _safe_str(ev.get("timestamp")), "labels": _labels(ev.get("labels")),
         "bundles": _bundles(ev.get("bundles")), "erased": erased, "masked": masked,
         "input_masked": any(p == "/input" or p.startswith("/input/")
                             for p in (erased or []) + (masked or [])),
         "input_digest": in_dig,
         "result_digest": _digest(ev["result"]) if "result" in ev else None,
         "polarity": polarity, "payload_encoding": enc}
    row["decision"] = d
    row["vendor_id"] = _safe_str(ev.get("decision_id"))
    row["vendor_word"] = word
    row["mapping"] = {"rule": "table"}
    row["relayed_verdict"] = TABLE[word]
    if d["path"] or in_dig:
        row["subject"] = {"name": f"opa:{d['path'] or ''}",
                          "sha256": in_dig[len(JCS_DIGEST_PREFIX):] if in_dig else None}
    if TABLE[word] == COULD_NOT_LOOK:
        row["could_not_look"] = could_not_look("an OPA decision this adapter can read as "
                                               "pass or fail", f"{_WHERE}[{i}]", *_WHY[word])
    return row


_JOIN_RANK = {VERIFIED: 0, COULD_NOT_LOOK: 1, BROKEN: 2}


def _usable_seal(s: Any) -> bool:
    return (isinstance(s, dict) and s.get("kind") == SEAL_KIND and s.get("seal") == VERIFIED
            and isinstance(s.get("bundle_name"), str) and isinstance(s.get("revision"), str)
            and bool(s.get("revision")) and isinstance(s.get("bundle_sha256"), str))


def _window(s: dict) -> tuple:
    return parse_ts(s.get("active_from")), parse_ts(s.get("active_until"))


def _covers(s: dict, ts) -> bool:
    lo, hi = _window(s)
    return (lo is None or ts >= lo) and (hi is None or ts < hi)


def _join_one(name: str, rev: Any, ts, seals: list) -> dict:
    """One (bundle name, revision) of one decision against the seals."""
    out = {"revision": rev, "join": COULD_NOT_LOOK, "bundle_sha256": None,
           "opa_signature_verified": None, "reason": None}

    def cnl(word, reason):
        out["reason"] = reason
        out["could_not_look"] = could_not_look("a sealed OPA bundle for this revision",
                                               f"sealed bundles named {name!r}", word, reason)
        return out

    if not isinstance(rev, str) or not rev:
        return cnl("missing", "the decision names no revision for this bundle")
    same = [s for s in seals if _safe_str(s["bundle_name"]) == name]
    in_force = [s for s in same if any(_window(s)) and ts is not None and _covers(s, ts)]
    if in_force:
        hit = [s for s in in_force if _safe_str(s["revision"]) == rev]
        if not hit:
            other = sorted({_safe_str(s["revision"]) for s in in_force})
            out["join"] = BROKEN
            out["reason"] = (f"the bundle sealed as in force at the decision time has revision "
                             f"{other[0]!r}, not {rev!r}")
            return out
    else:
        hit = [s for s in same if _safe_str(s["revision"]) == rev]
        if not hit:
            return cnl("name_not_found", "no sealed bundle has this revision")
        hit = [s for s in hit if not any(_window(s))]
        if not hit:
            if ts is None:
                return cnl("missing", "the decision has no readable timestamp to place in the "
                                      "sealed bundle's window")
            return cnl("name_not_found", "the sealed bundle with this revision was not in force "
                                         "at the decision time")
    if len({s["bundle_sha256"] for s in hit}) > 1:
        return cnl("name_not_found", "two sealed bundles with different bytes share this "
                                     "revision; which one is unknown")
    s = hit[0]
    fh = s.get("file_hashes") if isinstance(s.get("file_hashes"), dict) else {}
    out["opa_signature_verified"] = s.get("opa_signature_verified")
    if s.get("opa_signature_verified") == BROKEN or fh.get("verdict") == BROKEN:
        out["join"] = BROKEN
        out["reason"] = "the sealed bundle with this revision fails its own OPA signature"
        return out
    out["join"], out["bundle_sha256"] = VERIFIED, s["bundle_sha256"]
    out["reason"] = "the decision's revision is the sealed bundle's revision"
    return out


def _join_row(r: dict, seals: list) -> dict:
    row = json.loads(json.dumps(r))
    row["signed_by_vendor"] = False
    row["policy_bundle_sha256"] = None
    d = row.get("decision") if isinstance(row.get("decision"), dict) else {}
    bundles = d.get("bundles") if isinstance(d.get("bundles"), dict) else {}
    ts = parse_ts(d.get("timestamp"))
    per = {str(n): _join_one(str(n), rev, ts, seals) for n, rev in sorted(bundles.items())}
    if isinstance(row.get("decision"), dict):
        row["decision"]["policy_bundles"] = per
    if not per:
        row["policy_join"] = COULD_NOT_LOOK
        row["policy_join_could_not_look"] = could_not_look(
            "a bundle revision in the decision", f"{_WHERE} bundles", "missing",
            "the decision names no bundle revision")
        return row
    word = max((p["join"] for p in per.values()), key=_JOIN_RANK.__getitem__)
    row["policy_join"] = word
    if word == COULD_NOT_LOOK:
        row["policy_join_could_not_look"] = next(p["could_not_look"] for p in per.values()
                                                 if "could_not_look" in p)
    elif word == VERIFIED and len(per) == 1:
        row["policy_bundle_sha256"] = next(iter(per.values()))["bundle_sha256"]
    return row


def join_bundles(rows: Any, seals: Any) -> list:
    """Decision rows (from `ingest`) joined on `bundles.<name>.revision` to sealed
    bundles (statements from arcaeon.connector.opa_bundle.seal_bundle). Returns new
    rows; the input is not changed. Each relayed row gains:

        signed_by_vendor      False: OPA signs bundles, not decisions
        policy_join           VERIFIED  every bundle the decision names matched one
                                        sealed bundle of that name and revision
                              BROKEN    a sealed bundle declared in force at the
                                        decision time has another revision, or the
                                        matching sealed bundle fails its own signature
                              COULD NOT LOOK  no revision, no sealed bundle for it,
                                        two different sealed bundles share it, or the
                                        matching seal's window excludes the decision
        policy_bundle_sha256  the sealed bundle's sha256 when the row names exactly
                              one bundle and joined VERIFIED, else None
        decision.policy_bundles  {name: {revision, join, bundle_sha256,
                              opa_signature_verified, reason}}

    The relayed verdict is untouched. Anything that is not a relayed row passes
    through as is; unreadable seals are ignored. Never raises."""
    if not isinstance(rows, (list, tuple)):
        return []
    good = [s for s in (seals if isinstance(seals, (list, tuple)) else ()) if _usable_seal(s)]
    out = []
    for r in rows:
        if not isinstance(r, dict) or r.get("kind") != ROW_KIND:
            out.append(r)
            continue
        try:
            out.append(_join_row(r, good))
        except Exception as e:  # noqa: BLE001 - never a traceback on a row
            row = json.loads(json.dumps(r, default=str))
            row.update(signed_by_vendor=False, policy_bundle_sha256=None,
                       policy_join=COULD_NOT_LOOK,
                       policy_join_could_not_look=could_not_look(
                           "a joinable decision row", "row", "unreadable",
                           f"the join failed: {type(e).__name__}"))
            out.append(row)
    return out


def ingest(raw: Any, *, allow_paths: Any = (), deny_paths: Any = (),
           received_at: str | None = None) -> list:
    """An OPA decision-log POST body (bytes as received, gzipped or plain) -> a list
    of relayed rows, one per event (plus one per event that cannot be read).

    `allow_paths`: decision paths where `true` lets the request through.
    `deny_paths`: decision paths where `true` refuses it. A leading slash is
    ignored. A path in both raises ValueError (a caller error, not vendor input).
    Never raises on the body; an unreadable body is one COULD NOT LOOK row."""
    allow, deny = _paths(allow_paths, "allow_paths"), _paths(deny_paths, "deny_paths")
    if allow & deny:
        raise ValueError(f"paths in both allow_paths and deny_paths: {sorted(allow & deny)}")
    at = received_at if isinstance(received_at, str) else _now_iso()
    try:
        if isinstance(raw, str):
            raw = raw.encode("utf-8", "surrogatepass")
        if not isinstance(raw, (bytes, bytearray)):
            return [_cnl(OPA.base_row(None, at), "OPA decision log bytes", "argument",
                         "unreadable", f"payload is a {type(raw).__name__}, not bytes")]
        raw = bytes(raw)
        base = OPA.base_row(raw, at)
        if not raw:
            return [_cnl(base, "an OPA decision log body", _WHERE, "empty", "the body is empty")]
        if len(raw) > MAX_PAYLOAD_BYTES:
            return [_cnl(base, "an OPA decision log body", _WHERE, "bounded",
                         f"body is {len(raw)} bytes, over the {MAX_PAYLOAD_BYTES}-byte "
                         f"limit; digested, not read")]
        enc = "identity"
        body = raw
        if raw[:2] == b"\x1f\x8b":
            enc = "gzip"
            try:
                body = _gunzip(raw)
            except OverflowError:
                return [_cnl(base, "an OPA decision log body", _WHERE, "bounded",
                             f"the gzip body inflates past {MAX_BODY_BYTES} bytes; not read")]
            except (zlib.error, EOFError) as e:
                return [_cnl(base, "an OPA decision log body", _WHERE, "unreadable",
                             f"the gzip body cannot be read: {type(e).__name__}")]
        try:
            doc = loads_strict(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as e:
            return [_cnl(base, "an OPA decision log JSON array", _WHERE, "unreadable",
                         f"body is not one unambiguous UTF-8 JSON value: {type(e).__name__}")]
        if _too_deep(doc, MAX_DEPTH):
            return [_cnl(base, "an OPA decision log JSON array", _WHERE, "unreadable",
                         f"body nests deeper than {MAX_DEPTH}")]
        if not isinstance(doc, list):
            return [_cnl(base, "an OPA decision log JSON array", _WHERE, "name_not_found",
                         f"body is a JSON {type(doc).__name__}, not an array of events")]
        if not doc:
            return [_cnl(base, "an OPA decision event", _WHERE, "empty",
                         "the body lists no decision events")]
        rows = []
        for i, ev in enumerate(doc):
            if i >= MAX_ROWS:
                rows.append(_cnl(json.loads(json.dumps(base)), "every event in the body", _WHERE,
                                 "bounded", f"more than {MAX_ROWS} events; the rest were not read"))
                break
            rows.append(_event_row(base, i, ev, allow, deny, enc))
        return rows
    except Exception as e:  # noqa: BLE001 - never a traceback on what OPA sends
        return [_cnl(OPA.base_row(None, at), "an OPA decision log body", _WHERE, "unreadable",
                     f"the adapter failed: {type(e).__name__}")]
