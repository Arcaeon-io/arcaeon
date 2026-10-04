# SPDX-License-Identifier: MIT
"""arcaeon.prove.mcp_scan: an mcp-scan (Snyk Agent Scan) JSON result becomes
relayed check rows, one per scanned MCP tool, each carrying a digest of the tool
definition that was scanned; `verify_tool_called` then asks whether the tool an
agent is about to call is the one that was scanned.

Library only (no verb): this base has no `connector` CLI group. docs/MCP_SCAN.md
cites the mcp-scan sources this reads and lists what it does not prove.

THE ADAPTER. McpScanAdapter subclasses arcaeon.connector.core.VendorAdapter, the
one adapter base class; MCP_SCAN is its registered instance. One mcp-scan payload
becomes many rows (one per tool), so it builds rows with the base's `base_row`
and `mark_could_not_look` instead of import_verdict, and `recheck` says COULD NOT
LOOK for its rows (use verify_tool_called).

THE ROW. The check.verdict.relayed row of arcaeon.connector.core (field list in
that module and in docs/CONNECTOR_ADAPTER.md). For mcp-scan:

    vendor               {"name": "mcp-scan", "adapter_version": "1"}
    vendor_id            None (mcp-scan's JSON carries no scan id)
    vendor_word          the adapter's per-tool summary of mcp-scan's output (mcp-scan
                         writes no per-tool word): "no_findings", "findings",
                         "error", "not_inspected" or "not_analyzed"
    relayed_verdict      that word in our words, from TABLE
    subject              {"name": "<server>/<tool>", "sha256": <hex of the tool digest>}
    attestation          always NONE: mcp-scan output is unsigned, so every row is
                         reported by sender

plus ONE adapter-specific key, `tool`:

    tool.name, tool.server, tool.server_index, tool.entity_index, tool.scan_path,
    tool.client, tool.format ("v0.5-path-keyed" | "v0.6-scan-response"),
    tool.findings        issue codes / risk names that point at this tool or its server
    tool.digest          the base's digest (connector.core.jcs_digest) of
                         TOOL_DIGEST_KEYS, or None
    tool.digest_parts    {name, description, inputSchema}: the hex of each part's digest
    tool.mcp_scan_hash   mcp-scan's OWN pin rule recomputed by us (md5 of the
                         description, v0.3.x hash_entity); mcp-scan's --json never
                         published it

There is no bare `verdict` key, as in d011.

DIGEST. tool.digest is the base's digest (scheme defined once, in
docs/CONNECTOR_ADAPTER.md, "The sha256:jcs:v1 digest") of the object
{"name", "description" (or null), "inputSchema" (or null)}. Only those three
fields: a change to title, annotations, outputSchema or _meta is not seen. It is
not mcp-scan's hash (theirs was md5 over the description alone).

Never raises on what a scanner sends. Stdlib only.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from arcaeon.connector.core import (JCS_DIGEST_PREFIX, MAX_STR, ROW_KIND, AdapterError,
                                    Extracted, VendorAdapter, _now_iso, _safe_str, _too_deep,
                                    register)
from arcaeon.prove import jcs
from arcaeon.record.row import loads_strict
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED, could_not_look

__all__ = ["ROW_KIND", "VENDOR", "ADAPTER_VERSION", "TABLE", "TOOL_DIGEST_KEYS",
           "DIGEST_PREFIX", "MAX_PAYLOAD_BYTES", "MAX_DEPTH", "MAX_STR", "MAX_ROWS",
           "McpScanAdapter", "MCP_SCAN", "tool_digest", "mcp_scan_md5", "ingest",
           "verify_tool_called"]

VENDOR = "mcp-scan"
ADAPTER_VERSION = "1"
#: The base's digest prefix (arcaeon.connector.core.JCS_DIGEST_PREFIX).
DIGEST_PREFIX = JCS_DIGEST_PREFIX
TOOL_DIGEST_KEYS = ("name", "description", "inputSchema")
#: A scan of many servers is bigger than one vendor verdict (the base uses 1 MiB).
MAX_PAYLOAD_BYTES = 8 << 20
#: Path -> servers -> signature -> tools -> inputSchema leaves room for a schema.
MAX_DEPTH = 64
#: More tools than this in one payload: the rest are not read, and a row says so.
MAX_ROWS = 10000

#: The whole mapping from the adapter's per-tool word to ours.
TABLE = {
    "no_findings": VERIFIED,     # analysed, nothing pointed at this tool or its server
    "findings": BROKEN,          # an E*/W* issue or a risk index points at it
    "error": COULD_NOT_LOOK,     # a path or server error, or an X* failure code
    "not_inspected": COULD_NOT_LOOK,  # configured but never connected to (signature null)
    "not_analyzed": COULD_NOT_LOOK,   # inspect output: tools listed, never analysed
}

FORMAT_V05 = "v0.5-path-keyed"
FORMAT_V06 = "v0.6-scan-response"

_CHECKED = ("that the called tool's name, description and inputSchema hash to the digest "
            "of a tool definition mcp-scan reported scanning; NOT that the tool is safe")


class McpScanAdapter(VendorAdapter):
    """mcp-scan on the one adapter base. One payload, many rows: read it with
    `ingest`, not import_verdict (whose `extract` path refuses it as not one verdict)."""
    name = VENDOR
    version = ADAPTER_VERSION
    table = TABLE
    max_payload_bytes = MAX_PAYLOAD_BYTES
    max_depth = MAX_DEPTH
    one_row_per_payload = False

    def extract(self, doc: dict) -> Extracted:
        raise AdapterError("an mcp-scan result is one row per tool; read it with "
                           "arcaeon.prove.mcp_scan.ingest")


MCP_SCAN = register(McpScanAdapter())

# ---------------------------------------------------------------- small helpers


def tool_digest(tool: Any) -> tuple[str, dict] | None:
    """(digest, parts) for one MCP tool definition, or None when it cannot be read:
    not an object, no string name, a non-string description, a non-object
    inputSchema, or a value JCS refuses (NaN, a lone surrogate, a non-JSON type)."""
    try:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"]:
            return None
        desc = tool.get("description")
        schema = tool.get("inputSchema")
        if desc is not None and not isinstance(desc, str):
            return None
        if schema is not None and not isinstance(schema, dict):
            return None
        if _too_deep(schema, MAX_DEPTH):
            return None
        canon = {"name": tool["name"], "description": desc, "inputSchema": schema}
        parts = {k: jcs.sha256_hex(canon[k]) for k in TOOL_DIGEST_KEYS}
        return MCP_SCAN.digest(canon), parts
    except Exception:  # noqa: BLE001 - hostile input is a could-not-look, never a traceback
        return None


def mcp_scan_md5(tool: Any) -> dict | None:
    """mcp-scan's own pin, recomputed: md5 hex of the UTF-8 description, with
    "no description available" when there is none (v0.3.30 models.hash_entity).
    Recorded for cross-reference only; md5 is not our digest."""
    if not isinstance(tool, dict):
        return None
    desc = tool.get("description")
    if desc is None:
        desc = "no description available"
    if not isinstance(desc, str):
        return None
    try:
        value = hashlib.md5(desc.encode("utf-8"), usedforsecurity=False).hexdigest()
    except (UnicodeEncodeError, TypeError):
        return None
    return {"alg": "md5", "over": "description", "value": value,
            "rule": "mcp-scan v0.3.x models.hash_entity",
            "published_by_mcp_scan": False}


# ---------------------------------------------------------------- the row

def _base(received_at: str, raw: bytes | None) -> dict:
    return MCP_SCAN.base_row(raw, received_at)


_cnl = MCP_SCAN.mark_could_not_look


def _tool_row(base: dict, *, fmt: str, scan_path: Any, client: Any, server: Any,
              server_index: int, entity_index: int | None, name: Any, definition: Any,
              word: str, findings: list, has_definition: bool = False) -> dict:
    row = json.loads(json.dumps(base))
    t = {"name": _safe_str(name), "server": _safe_str(server), "server_index": server_index,
         "entity_index": entity_index, "scan_path": _safe_str(scan_path),
         "client": _safe_str(client), "format": fmt,
         "findings": [s for s in (_safe_str(f) for f in findings[:64]) if s],
         "digest": None, "digest_parts": None, "mcp_scan_hash": None}
    row["tool"] = t
    row["vendor_word"] = word
    row["mapping"] = {"rule": "table"}
    row["relayed_verdict"] = TABLE[word]
    if has_definition:  # a tool entry was listed, even if it is null or garbage
        got = tool_digest(definition)
        if got is None:
            t["mcp_scan_hash"] = mcp_scan_md5(definition)
            return _cnl(row, "a readable MCP tool definition", "signature.tools", "unreadable",
                        "the tool definition is not {name: str, description: str|null, "
                        "inputSchema: object|null} JSON")
        t["digest"], t["digest_parts"] = got
        t["mcp_scan_hash"] = mcp_scan_md5(definition)
    if t["name"] or t["digest"]:
        row["subject"] = {"name": f"{t['server'] or ''}/{t['name'] or ''}",
                          "sha256": t["digest"][len(DIGEST_PREFIX):] if t["digest"] else None}
    if TABLE[word] == COULD_NOT_LOOK:
        why = {"error": ("missing", "mcp-scan reported an error for this path or server"),
               "not_inspected": ("missing", "mcp-scan never connected to this server "
                                            "(signature is null)"),
               "not_analyzed": ("missing", "this is inspect output: tools were listed, "
                                           "never analysed")}[word]
        row["could_not_look"] = could_not_look("an mcp-scan analysis of this tool",
                                               "mcp-scan result", *why)
    return row


def _codes(issue: Any) -> str | None:
    return issue.get("code") if isinstance(issue, dict) and isinstance(issue.get("code"), str) else None


def _word(findings: list, failed: bool) -> str:
    if any(not f.startswith("X") for f in findings):
        return "findings"
    if failed or findings:
        return "error"
    return "no_findings"


def _ref(issue: dict) -> tuple[Any, Any]:
    ref = issue.get("reference")
    if ref is None:
        return None, None
    def _int(x: Any) -> bool:
        return type(x) is int and x >= 0  # not bool, not negative
    if isinstance(ref, list) and len(ref) == 2 and _int(ref[0]) \
            and (ref[1] is None or _int(ref[1])):
        return ref[0], ref[1]
    return "bad", "bad"  # an unreadable reference counts against every tool on the path


def _v05(doc: dict, base: dict, inspect_only: bool) -> list:
    rows: list = []
    for path, res in doc.items():
        if not isinstance(res, dict):
            rows.append(_cnl(json.loads(json.dumps(base)), "a ScanPathResult object",
                             f"result[{_safe_str(path)!r}]", "unreadable",
                             "the path entry is not an object"))
            continue
        analysed = "issues" in res and not inspect_only
        issues = res.get("issues") if isinstance(res.get("issues"), list) else []
        servers = res.get("servers")
        client = res.get("client")
        if not isinstance(servers, list):
            word = "error" if res.get("error") is not None else "not_inspected"
            rows.append(_tool_row(base, fmt=FORMAT_V05, scan_path=path, client=client, server=None,
                                  server_index=-1, entity_index=None, name=None, definition=None,
                                  word=word, findings=[]))
            continue
        path_wide = [c for i in issues if (c := _codes(i)) and _ref(i)[0] is None]
        bad_ref = [c for i in issues if (c := _codes(i)) and _ref(i)[0] == "bad"]
        for si, srv in enumerate(servers):
            if not isinstance(srv, dict):
                rows.append(_cnl(json.loads(json.dumps(base)), "a server entry", f"servers[{si}]",
                                 "unreadable", "the server entry is not an object"))
                continue
            sig, sname = srv.get("signature"), srv.get("name")
            failed = srv.get("error") is not None or res.get("error") is not None
            mine = [(_ref(i)[1], c) for i in issues if (c := _codes(i)) and _ref(i)[0] == si]
            srv_wide = [c for e, c in mine if e is None] + path_wide + bad_ref
            if not isinstance(sig, dict) or not isinstance(sig.get("tools", []), list):
                word = "error" if failed else "not_inspected"
                rows.append(_tool_row(base, fmt=FORMAT_V05, scan_path=path, client=client,
                                      server=sname, server_index=si, entity_index=None, name=None,
                                      definition=None, word=word, findings=srv_wide))
                continue
            lens = [sig.get(k, []) for k in ("prompts", "resources", "resource_templates")]
            offset = sum(len(x) for x in lens) if all(isinstance(x, list) for x in lens) else None
            for tj, tool in enumerate(sig.get("tools", [])):
                if len(rows) >= MAX_ROWS:
                    rows.append(_cnl(json.loads(json.dumps(base)), "every tool in the payload",
                                     "mcp-scan result", "bounded",
                                     f"more than {MAX_ROWS} tools; the rest were not read"))
                    return rows
                ei = offset + tj if offset is not None else None
                # with no countable offset, any entity-level issue on this server counts
                own = [c for e, c in mine if e is not None and (ei is None or e == ei)]
                found = own + srv_wide
                if not analysed:
                    word = "error" if failed else "not_analyzed"
                else:
                    word = _word(found, failed)
                rows.append(_tool_row(base, fmt=FORMAT_V05, scan_path=path, client=client,
                                      server=sname, server_index=si, entity_index=ei,
                                      name=tool.get("name") if isinstance(tool, dict) else None,
                                      definition=tool, word=word, findings=found,
                                      has_definition=True))
    return rows


def _v06(doc: dict, base: dict) -> list:
    rows: list = []
    sprs = doc.get("scan_path_responses")
    for pi, spr in enumerate(sprs):
        if not isinstance(spr, dict):
            rows.append(_cnl(json.loads(json.dumps(base)), "a scan path response",
                             f"scan_path_responses[{pi}]", "unreadable", "not an object"))
            continue
        path, client = spr.get("path"), spr.get("client")
        srs = spr.get("server_risks")
        if not isinstance(srs, list):
            word = "error" if spr.get("error") is not None else "not_inspected"
            rows.append(_tool_row(base, fmt=FORMAT_V06, scan_path=path, client=client, server=None,
                                  server_index=-1, entity_index=None, name=None, definition=None,
                                  word=word, findings=[]))
            continue
        for si, sr in enumerate(srs):
            if not isinstance(sr, dict) or not isinstance(sr.get("entities", []), list):
                rows.append(_cnl(json.loads(json.dumps(base)), "a server risk entry",
                                 f"server_risks[{si}]", "unreadable", "not a readable object"))
                continue
            risks = sr.get("risk_indexes") if isinstance(sr.get("risk_indexes"), dict) else {}
            failed = sr.get("error") is not None or spr.get("error") is not None
            for k, ent in enumerate(sr.get("entities", [])):
                if not isinstance(ent, dict) or ent.get("type") != "tool":
                    continue
                if len(rows) >= MAX_ROWS:
                    rows.append(_cnl(json.loads(json.dumps(base)), "every tool in the payload",
                                     "mcp-scan result", "bounded",
                                     f"more than {MAX_ROWS} tools; the rest were not read"))
                    return rows
                found = []
                for rname, rv in risks.items():
                    aff = rv.get("affected_tools") if isinstance(rv, dict) else None
                    if not isinstance(aff, list) or any(type(a) is int and a == k for a in aff):
                        found.append(rname)
                row = _tool_row(base, fmt=FORMAT_V06, scan_path=path, client=client,
                                server=sr.get("name"), server_index=si, entity_index=k,
                                name=ent.get("name"), definition=None,
                                word=_word(found, failed), findings=found)
                rows.append(row)
    return rows


def ingest(raw: Any, *, received_at: str | None = None, inspect_only: bool = False) -> list:
    """An mcp-scan `--json` output (the bytes as received) -> a list of relayed rows,
    one per tool (plus one per server or path that could not be read). Never raises;
    an unreadable payload is one COULD NOT LOOK row. `inspect_only=True` says the
    payload came from `inspect` (v0.5 inspect output looks like a clean scan)."""
    at = received_at if isinstance(received_at, str) else _now_iso()
    try:
        if isinstance(raw, str):
            raw = raw.encode("utf-8", "surrogatepass")
        if not isinstance(raw, (bytes, bytearray)):
            return [_cnl(_base(at, None), "mcp-scan JSON bytes", "argument", "unreadable",
                         f"payload is a {type(raw).__name__}, not bytes")]
        raw = bytes(raw)
        base = _base(at, raw)
        where = "mcp-scan result"
        if not raw:
            return [_cnl(base, "mcp-scan JSON", where, "empty", "the payload is empty")]
        if len(raw) > MAX_PAYLOAD_BYTES:
            return [_cnl(base, "mcp-scan JSON", where, "bounded",
                         f"payload is {len(raw)} bytes, over the {MAX_PAYLOAD_BYTES}-byte "
                         f"limit; digested, not read")]
        try:
            doc = loads_strict(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as e:
            return [_cnl(base, "mcp-scan JSON", where, "unreadable",
                         f"payload is not one unambiguous UTF-8 JSON value: {type(e).__name__}")]
        if _too_deep(doc, MAX_DEPTH):
            return [_cnl(base, "mcp-scan JSON", where, "unreadable",
                         f"payload nests deeper than {MAX_DEPTH}")]
        if isinstance(doc, dict) and isinstance(doc.get("scan_path_responses"), list) \
                and len(doc) == 1:
            rows = _v06(doc, base)
        elif isinstance(doc, dict) and doc and all(
                isinstance(v, dict) and "path" in v and "servers" in v for v in doc.values()):
            rows = _v05(doc, base, inspect_only)
        else:
            return [_cnl(base, "an mcp-scan result (path-keyed or scan_path_responses)", where,
                         "name_not_found", "the JSON is not an mcp-scan result shape")]
        if not rows:
            return [_cnl(base, "a scanned MCP tool", where, "empty",
                         "the result lists no MCP tools")]
        return rows
    except Exception as e:  # noqa: BLE001 - never a traceback on what a scanner sends
        return [_cnl(_base(at, None), "mcp-scan JSON", "mcp-scan result", "unreadable",
                     f"the adapter failed: {type(e).__name__}")]


# ---------------------------------------------------------------- the check

def _result(verdict: str, summary: str, name: Any = None, digest: Any = None, **extra) -> dict:
    # as in d011: on COULD NOT LOOK the could_not_look keys (their `reason`) override
    out = {"verdict": verdict, "tool": _safe_str(name), "digest": digest, "reason": summary,
           "what_was_checked": _CHECKED}
    out.update(extra)
    return out


def _read_definition(td: Any) -> Any:
    if isinstance(td, str):
        td = td.encode("utf-8", "surrogatepass")
    if isinstance(td, (bytes, bytearray)):
        if len(td) > MAX_PAYLOAD_BYTES:
            return None
        td = loads_strict(bytes(td).decode("utf-8"))
    return td


def verify_tool_called(tool_definition: Any, rows: Any, *, server: str | None = None) -> dict:
    """Is the tool being called the tool mcp-scan reported scanning?

    VERIFIED: its digest equals the digest on a relayed mcp-scan row of the same name
    (and server, if given). The matching row's own relayed_verdict and findings are
    returned too: a VERIFIED match on a tool mcp-scan flagged is still flagged.
    BROKEN: a row of that name carries a digest and none equals this one (the
    definition changed after the scan: a rug pull). `fields` names the parts that differ.
    COULD NOT LOOK: the definition or rows cannot be read, the name was never scanned,
    or every row of that name carries no digest (v0.6 output, not inspected).
    Never raises."""
    try:
        try:
            td = _read_definition(tool_definition)
        except (UnicodeDecodeError, ValueError):
            td = None
        name = td.get("name") if isinstance(td, dict) else None
        got = tool_digest(td) if td is not None else None
        if got is None:
            return _result(COULD_NOT_LOOK, "the called tool's definition cannot be read", name,
                           **could_not_look("a readable MCP tool definition", "tool_definition",
                                            "unreadable", "not {name, description, inputSchema} JSON"))
        digest, parts = got
        if not isinstance(rows, (list, tuple)):
            return _result(COULD_NOT_LOOK, "no rows to check against", name, digest,
                           **could_not_look("mcp-scan rows", "rows", "missing",
                                            "rows is not a list"))
        cands = []
        for i, r in enumerate(rows):
            if not isinstance(r, dict) or r.get("kind") != ROW_KIND:
                continue
            v, t = r.get("vendor"), r.get("tool")
            if not isinstance(v, dict) or v.get("name") != VENDOR or not isinstance(t, dict):
                continue
            if t.get("name") != name or (server is not None and t.get("server") != server):
                continue
            cands.append((i, r, t))
        if not cands:
            return _result(COULD_NOT_LOOK, "mcp-scan never reported scanning a tool by this name",
                           name, digest,
                           **could_not_look(f"an mcp-scan row for tool {_safe_str(name)!r}",
                                            "rows", "name_not_found", "never scanned"))
        for i, r, t in cands:
            if t.get("digest") == digest:
                return _result(VERIFIED, "the called tool's digest equals the scanned digest",
                               name, digest, row_index=i, server=t.get("server"),
                               relayed_verdict=r.get("relayed_verdict"),
                               findings=t.get("findings"), checked_by_us=False, relayed=True)
        pinned = [(i, r, t) for i, r, t in cands if isinstance(t.get("digest"), str)]
        if pinned:
            fields = set()
            for _, _, t in pinned:
                dp = t.get("digest_parts") if isinstance(t.get("digest_parts"), dict) else {}
                diff = [k for k in TOOL_DIGEST_KEYS if dp.get(k) != parts[k]]
                fields.update(diff or ["digest"])
            return _result(BROKEN, "the tool name matches a scanned tool but its definition "
                                   "differs from what was scanned (rug pull)", name, digest,
                           fields=[k for k in (*TOOL_DIGEST_KEYS, "digest") if k in fields],
                           scanned_digests=sorted({t["digest"] for _, _, t in pinned}),
                           row_indexes=[i for i, _, _ in pinned])
        return _result(COULD_NOT_LOOK, "mcp-scan reported this tool by name only; no "
                                       "definition was scanned to compare", name, digest,
                       **could_not_look("a scanned tool digest", "rows", "missing",
                                        "the matching rows carry no digest"))
    except Exception as e:  # noqa: BLE001
        return _result(COULD_NOT_LOOK, "the check failed", None, None,
                       **could_not_look("a readable tool definition and rows", "arguments",
                                        "unreadable", f"{type(e).__name__}"))
