# SPDX-License-Identifier: MIT
"""The route table: every HTTP route `arcaeon serve` answers, in one list.

Declared up front by K002 so parallel work never edits the list: later items
implement the handler a row names, in their own module. The OpenAPI document
(K013), the MCP parity check (K091) and the server's dispatch (K004) all read
this table; none keeps a second copy.

A handler is named by dotted path, `module:function`, and imported only when
its route is called. It takes the request body (a dict; `{}` for a GET) and
returns the CLI's --json dict plus an integer `exit`.

Every free route names the MCP tool that does the same thing, or says why
there is none (`mcp_exempt_reason`). `tier="paid"` marks a route that can
spend: it refuses without a key and, even with one, unless the server was
started with --allow-paid (K012).
"""
from __future__ import annotations

from dataclasses import dataclass

#: The longest path or name a request field may carry.
MAX_PATH = 4096
#: The longest inline content (JSONL text, or its base64): the body cap.
MAX_CONTENT = 10 * 1024 * 1024

_PATH = {"type": "string", "maxLength": MAX_PATH}
_CONTENT = {"type": "string", "maxLength": MAX_CONTENT,
            "description": "the file's text (JSONL), for an agent with no file access"}
_CONTENT_B64 = {"type": "string", "maxLength": MAX_CONTENT,
                "description": "the file's bytes, base64"}
_NOTHING = {"type": "object", "properties": {}}


def _verdict(**props) -> dict:
    """A verdict body: the CLI's --json fields plus the integer exit."""
    return {
        "type": "object",
        "required": ["exit"],
        "properties": {
            "exit": {"type": "integer", "enum": [0, 1, 2, 3],
                     "description": "0 good, 1 a bad finding, 2 bad usage, 3 COULD NOT LOOK"},
            "verdict": {"type": "string"},
            "reason_word": {"type": "string"},
            **props,
        },
    }


def _req(required=(), **props) -> dict:
    return {"type": "object", "required": list(required), "properties": props}


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    handler: str                      # "module:function", imported on call
    summary: str
    request_schema: dict
    response_schema: dict
    tier: str = "free"                # "free" | "paid"
    mcp_tool: str | None = None
    mcp_exempt_reason: str | None = None

    @property
    def open(self) -> bool:
        """Answered without a token (K005)."""
        return self.path in OPEN_PATHS

    def resolve(self):
        """The handler function. Raises ImportError / AttributeError if the
        item that builds it has not landed yet."""
        import importlib
        mod, _, fn = self.handler.partition(":")
        return getattr(importlib.import_module(mod), fn)


#: Paths answered without a token.
OPEN_PATHS = frozenset({"/health", "/openapi.json"})

_H = "arcaeon.serve."
_NO_TOOL_YET = "no MCP tool for this route yet"

ROUTES: tuple[Route, ...] = (
    Route("GET", "/health", _H + "server:health",
          "is the server up", _NOTHING,
          {"type": "object", "required": ["ok"], "properties": {"ok": {"type": "boolean"}}},
          mcp_exempt_reason="a liveness probe for HTTP clients; an MCP client "
                            "knows its server is up from the session"),
    Route("GET", "/openapi.json", _H + "openapi:document",
          "this API as an OpenAPI 3.1 document", _NOTHING,
          {"type": "object", "required": ["openapi", "paths"],
           "properties": {"openapi": {"type": "string"}, "paths": {"type": "object"}}},
          mcp_exempt_reason="describes the HTTP API itself; an MCP client lists tools instead"),
    Route("GET", "/", _H + "dashboard:index",
          "the local dashboard (HTML)", _NOTHING,
          {"type": "string", "description": "text/html"},
          mcp_exempt_reason="a page for a person in a browser, not a check"),
    Route("POST", "/v1/log", _H + "h_record:log",
          "append one JSON row to a ledger; returns the new chain value",
          _req(["ledger"], ledger=_PATH,
               fields={"type": "object", "description": "the row's fields"},
               row={"type": "object", "description": "a whole row, instead of fields"}),
          _verdict(chain={"type": "string"}, rows={"type": "integer"}),
          mcp_tool="ledger_append"),
    Route("POST", "/v1/verify", _H + "h_record:verify",
          "check a ledger's chain: VERIFIED / BROKEN / COULD NOT LOOK",
          _req(ledger=_PATH, content=_CONTENT, content_b64=_CONTENT_B64,
               strict={"type": "boolean"}, witness=_PATH, ns=_PATH),
          _verdict(rows={"type": "integer"}, first_break={"type": ["string", "null"]}),
          mcp_tool="ledger_verify_peer_ledger"),
    Route("POST", "/v1/reconcile", _H + "h_reconcile:reconcile",
          "two tapes and a counter: MATCHED / MISSING / ALTERED / COULD NOT LOOK",
          _req(kind={"type": "string", "enum": ["tapes", "readings"]},
               tape_a=_PATH, tape_b=_PATH, content_a=_CONTENT, content_b=_CONTENT,
               pin=_PATH),
          _verdict(),
          mcp_exempt_reason=_NO_TOOL_YET),
    Route("POST", "/v1/audit/verify", _H + "h_audit:verify",
          "verify an audit log or an exported bundle",
          _req(path=_PATH, content=_CONTENT, content_b64=_CONTENT_B64),
          _verdict(),
          mcp_exempt_reason=_NO_TOOL_YET),
    Route("POST", "/v1/audit/export", _H + "h_audit:export",
          "export a ledger as an audit bundle into a directory under the served root",
          _req(["ledger", "out"], ledger=_PATH, out=_PATH),
          _verdict(out={"type": "string"}),
          mcp_exempt_reason=_NO_TOOL_YET),
    Route("POST", "/v1/receipt/verify", _H + "h_misc:receipt_verify",
          "verify a portable receipt",
          _req(receipt=_PATH, content=_CONTENT, content_b64=_CONTENT_B64),
          _verdict(reason={"type": "string"}),
          mcp_exempt_reason=_NO_TOOL_YET),
    Route("GET", "/v1/status", _H + "h_misc:status",
          "what arcaeon did lately here: last run per verb, open COULD NOT LOOKs",
          _NOTHING,
          _verdict(balance={"type": "string"}),
          mcp_tool="arcaeon_status"),
    Route("POST", "/v1/pin", _H + "h_pin:pin",
          "record a ledger head in a local witness file under the served root "
          "(remote pin is the paid lane)",
          _req(["ledger"], ledger=_PATH, witness=_PATH, ns=_PATH,
               remote={"type": "boolean"}),
          _verdict(namespace={"type": "string"}, chain={"type": "string"}),
          mcp_exempt_reason="the MCP pin tool (witness_pin) is the hosted, paid pin; "
                            "a local pin over MCP is not built"),
    Route("POST", "/v1/seal", _H + "h_pin:seal",
          "PAID: a badge sealed by the hosted witness (needs ARCAEON_KEY and "
          "a server started with --allow-paid)",
          _req(["path"], path=_PATH, ns=_PATH),
          _verdict(sealed={"type": "boolean"}),
          tier="paid",
          mcp_exempt_reason="paid lane: never offered as an MCP tool an agent could "
                            "call by surprise"),
    Route("POST", "/v1/evidence-pack", _H + "h_evidence:build",
          "build an evidence pack for a ledger and a time window",
          _req(["ledger", "out"], ledger=_PATH, out=_PATH,
               agent={"type": "string", "maxLength": MAX_PATH},
               since={"type": "string", "maxLength": 64},
               until={"type": "string", "maxLength": 64}),
          _verdict(out={"type": "string"}),
          mcp_tool="evidence_pack_build"),
    Route("POST", "/v1/evidence-pack/verify", _H + "h_evidence:verify",
          "verify an evidence pack: every file rehashed, the chain, the window, the pins",
          _req(["pack"], pack=_PATH),
          _verdict(),
          mcp_tool="evidence_pack_verify"),
    Route("POST", "/v1/export/aat", _H + "h_evidence:export_aat",
          "write a ledger out in the agent-audit-trail format",
          _req(["ledger"], ledger=_PATH, out=_PATH),
          _verdict(out={"type": "string"}),
          mcp_exempt_reason=_NO_TOOL_YET),
    Route("POST", "/v1/mandate/check", _H + "h_mandate:check",
          "check a call against a mandate (record-only: says inside or outside, blocks nothing)",
          _req(["mandate"], mandate=_PATH, fields={"type": "object"}),
          _verdict(reason={"type": "string"}),
          mcp_tool="mandate_check"),
    Route("POST", "/v1/readings", _H + "h_readings:submit",
          "submit one reader's reading of a claim, chained into a readings ledger",
          _req(["ledger", "reader_id", "claim_id", "reading"], ledger=_PATH,
               reader_id={"type": "string", "maxLength": 256},
               provider={"type": "string", "maxLength": 256},
               claim_id={"type": "string", "maxLength": 256},
               claim={"type": "string", "maxLength": MAX_CONTENT},
               criterion_sha256={"type": "string", "maxLength": 64},
               reading={"type": "string", "enum": ["yes", "no", "undetermined"]}),
          _verdict(chain={"type": "string"}),
          mcp_tool="second_read_submit"),
    Route("POST", "/v1/second-read/compare", _H + "h_readings:compare",
          "line up two readings ledgers: COMPARED / MISSING / BROKEN / COULD NOT LOOK",
          _req(["a", "b"], a=_PATH, b=_PATH),
          _verdict(disagreed={"type": "integer"}, read={"type": "integer"}),
          mcp_tool="second_read_compare"),
    Route("POST", "/v1/handshake/propose", _H + "h_handshake:propose",
          "propose terms to another agent; each side keeps its own ledger",
          _req(["ledger", "terms"], ledger=_PATH, terms={"type": "object"}),
          _verdict(),
          mcp_exempt_reason=_NO_TOOL_YET),
    Route("POST", "/v1/handshake/accept", _H + "h_handshake:accept",
          "countersign proposed terms",
          _req(["ledger", "proposal"], ledger=_PATH, proposal={"type": "object"}),
          _verdict(),
          mcp_exempt_reason=_NO_TOOL_YET),
    Route("POST", "/v1/handshake/verify", _H + "h_handshake:verify",
          "line up both sides' ledgers: AGREED TERMS / DIFFERENT TERMS / MISSING / COULD NOT LOOK",
          _req(["a", "b"], a=_PATH, b=_PATH),
          _verdict(),
          mcp_exempt_reason=_NO_TOOL_YET),
)

METHODS = ("GET", "POST")


def find(method: str, path: str) -> Route | None:
    """The route for this method and path, or None."""
    for r in ROUTES:
        if r.method == method and r.path == path:
            return r
    return None


def methods_for(path: str) -> list[str]:
    """The methods a path answers (empty: 404; non-empty without this method: 405)."""
    return [r.method for r in ROUTES if r.path == path]


def validate(route: Route, body) -> str | None:
    """The first problem with a request body, naming the field, or None."""
    from arcaeon.serve.schema_check import first_problem
    return first_problem(route.request_schema, body)
