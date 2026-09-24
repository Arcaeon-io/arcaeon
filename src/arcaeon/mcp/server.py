"""The one server. Every Arcaeon tool on one list, over stdio.

RE-EXPORT, NOT REIMPLEMENTATION. The ledger tools dispatch into
`arcaeon_ledger.mcp_server.handle` — literally the function the standalone
ledger server runs on every call — and take their descriptions off that
package's own `TOOLS` list. The vet tools call `mcp_vet.server.scan_recorded` /
`grade_recorded` — the same read-scan/grade-record sequence mcp-vet's own
`mcp_vet_scan` / `mcp_vet_grade` tool handlers run, exposed as library calls —
and take their descriptions off `mcp_vet.server`'s own `SCAN_DESCRIPTION` /
`GRADE_DESCRIPTION` constants. (Board C-agent-31, 2026-08-30: this used to call
`mcp_vet.checks.scan_source` / `mcp_vet.grade.grade_source` straight, which
scans and grades correctly but never writes to mcp-vet's audit ledger — a vet
call through the connector left no row while the identical call through
mcp-vet's own server did. `scan_recorded` / `grade_recorded` close that gap at
the layer that owns the ledger.) Nothing here re-derives a result that one of
those packages already knows how to produce, because the day two copies
disagree is the day the connector lies about a chain.

NAMESPACING. Upstream names that already read as ledger tools keep their names
(`ledger_append`, `ledger_verify`); the agent-facing three get the prefix
(`ledger_prove_my_conduct`, and so on), and mcp-vet's `mcp_vet_*` becomes
`vet_*`. One list of eleven tools where the prefix says which product answers.

THE DRIFT RISK, stated. The wrappers are written out by hand rather than
generated, because the SDK derives a tool's JSON schema from a real Python
signature and a synthesized one is a second schema that can disagree with
upstream's. The cost is that a new upstream tool does not appear here for free.
That cost is paid by a test: `test_every_underlying_ledger_tool_is_re_exported`
walks upstream's TOOLS and goes red naming anything this file forgot. A bundler
that silently ships less than it bundles is the failure mode; it fails loudly
instead.

THE PAID LANE. Exactly two tools spend money on our side, and both are gated on
ARCAEON_KEY. With no key they return a plain sentence naming the free tier, the
$5 pack and the link — the refusal is a product surface, not an exception.

THE LICENSE GATE (idea I-daniel-17), OFF BY DEFAULT. A second, optional gate
sits in front of the same two tools and answers a different question: not "does
this caller have a witness account" but "is this copy of the package licensed".
It is inert unless LICENSE_GATE_REQUIRED=1, imports nothing while off, and
fails CLOSED when on with no gate module installed. See licensing.py.

THE CONNECTOR'S OWN CALL RECORD (OWASP MCP08, 0.1.4). mcp-vet's `audit-record`
check graded this file gate 0 of 4 on 2026-09-02: a tool call through the
connector left nothing behind that said the connector had been called. (The
ledger tools write the CALLER's ledger and the vet tools write mcp-vet's; a
record of the connector's own invocations existed for neither.) Every one of
the eleven handlers now ends in `_record_call(...)`, which appends one row -
tool name, UTC timestamp, sha256 of the canonical-JSON arguments, outcome - to
a hash-chained JSONL file beside the ledger log (`$ARCAEON_CALL_RECORD`, default
`arcaeon.calls.jsonl` in the same directory as `ARCAEON_LEDGER_LOG`). The
chaining is arcaeon-ledger's own `Ledger`, not a second implementation: same
row format as the other four Arcaeon servers, verifiable with
`ledger_verify_peer_ledger` or `arcaeon-ledger verify`, and `verify_call_record`
here. The record is written AFTER the work and carries `ok` / `error`, so a
refused call is recorded as a refusal, never as a success. Arguments are
digested, not copied: a call record that inlined every appended record would be
a second copy of the caller's ledger.
"""
from __future__ import annotations

import hashlib
import functools
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from arcaeon.record.ledger import Ledger
from arcaeon.record.ledger import __version__ as LEDGER_VERSION
from arcaeon.record.ledger.mcp_server import TOOLS as _LEDGER_UPSTREAM
from arcaeon.record.ledger.mcp_server import handle as _ledger_handle
from arcaeon.prove.vet import __version__ as VET_VERSION
from arcaeon.prove.vet.server import GRADE_DESCRIPTION as _VET_GRADE_DESCRIPTION
from arcaeon.prove.vet.server import SCAN_DESCRIPTION as _VET_SCAN_DESCRIPTION
from arcaeon.prove.vet.server import grade_recorded as _vet_grade_recorded
from arcaeon.prove.vet.server import scan_recorded as _vet_scan_recorded
from arcaeon.prove.vet.server import verify_audit_ledger as _vet_verify_audit_ledger

from . import __version__
from arcaeon.remote import licensing
from arcaeon.remote import witness
from arcaeon.remote.offers import CATALOG_URL, upgrade_message

SERVER_NAME = "arcaeon"

# upstream tool name -> the name this connector advertises.
LEDGER_TOOLS = {
    t["name"]: (t["name"] if t["name"].startswith("ledger_") else f"ledger_{t['name']}")
    for t in _LEDGER_UPSTREAM
}
_LEDGER_DESC = {t["name"]: t["description"] for t in _LEDGER_UPSTREAM}

VET_TOOLS = {
    "mcp_vet_scan": "vet_scan",
    "mcp_vet_grade": "vet_grade",
    "mcp_vet_audit_verify": "vet_audit_verify",
}

WITNESS_TOOLS = ("witness_pin", "witness_renew")
PAID_TOOLS = WITNESS_TOOLS
STATUS_TOOL = "arcaeon_status"

ALL_TOOLS = sorted([*LEDGER_TOOLS.values(), *VET_TOOLS.values(), *WITNESS_TOOLS, STATUS_TOOL])
FREE_TOOLS = [n for n in ALL_TOOLS if n not in PAID_TOOLS]


# --- configuration (read at CALL time, never cached at import) -------------
# A cached path is a path that ignores the client's environment on the second
# call, and clients do change it between sessions.

def ledger_path() -> Path:
    return Path(os.environ.get("ARCAEON_LEDGER_LOG", "agent.log.jsonl"))


def ns_dir() -> Path:
    """Where the per-namespace agent ledgers live. Same default as upstream:
    `ledgers/` beside the main log."""
    override = os.environ.get("ARCAEON_LEDGER_NS_DIR")
    return Path(override) if override else ledger_path().resolve().parent / "ledgers"


def _key() -> str | None:
    """The witness credential, or None when there is not one.

    THE EMPTY-STRING SHAPE, stated because it is the one that reads wrong at a
    glance (board item 39, 2026-09-05). The `""` in `.get()` is a SENTINEL for
    `.strip()`, never a default credential: `"".strip() or None` is None, and so
    is `"   ".strip() or None`. An empty or whitespace-only ARCAEON_KEY is
    therefore identical to an unset one everywhere it matters - `_witness_call`
    returns the upgrade message that names the variable, `arcaeon_status`
    reports `key_present: false`, and nothing reaches `witness._http_post`. The
    fail-open shape this deliberately is NOT is
    `os.environ.get("ARCAEON_KEY", "")` returned bare, which would send
    `Authorization: Bearer ` to the witness and let the server decide whether
    an unauthenticated caller is a caller. `test_empty_key.py` pins both arms.

    NOT a startup check, on purpose. Ten of the eleven tools are free and need
    no key at all, so refusing to START over a blank optional variable would
    take the whole free lane down to enforce a gate on two tools. The refusal
    lives at the call, which is also where the config is read (see the note
    above this block): a key set after the server started is honoured, and a key
    blanked after it started is refused.
    """
    return os.environ.get("ARCAEON_KEY", "").strip() or None


def call_record_path() -> Path:
    """The connector's OWN call record: `$ARCAEON_CALL_RECORD` if set (the same
    variable the other Arcaeon servers honour), else `arcaeon.calls.jsonl` in
    the connector's state dir, which is the directory the ledger log lives in
    (the same convention `ns_dir()` uses for the per-namespace ledgers). NOT
    the ledger log itself: that file is the caller's conduct record, and mixing
    the connector's rows into it would change what `ledger_verify` counts."""
    override = os.environ.get("ARCAEON_CALL_RECORD")
    return Path(override) if override else ledger_path().resolve().parent / "arcaeon.calls.jsonl"


# --- the connector's own call record (OWASP MCP08) -------------------------

_ARGS_DIGEST_ALG = "sha256"


def _tool_error_class():
    """The SDK's ToolError, or None when it cannot be imported.

    Why this matters (CI, mcp 2.1.1, 2026-09-06): from 2.1 the server sorts a
    tool's exception into two piles by TYPE. `ToolError` is "a failure you
    anticipated" and keeps its own text after the prefix; anything else is a
    crash, and the caller is told only "Error executing tool <name>" while the
    reason stays on the server. An upstream refusal -- "no ledger for namespace
    'ghost'" -- is the anticipated kind, and a caller who cannot read it cannot
    fix the call. The row in the call record was always right; this is about
    what reaches the caller. mcp 2.0 (installed here) had no such split, which
    is why the suite was green locally and red on CI.
    """
    for path, name in (("mcp.server.mcpserver.exceptions", "ToolError"),
                       ("mcp.server.fastmcp.exceptions", "ToolError")):  # SDK 1.x
        try:
            return getattr(__import__(path, fromlist=[name]), name)
        except Exception:  # noqa: BLE001 - no SDK at all is a valid state here
            continue
    return None


def _anticipated(fn):
    """Wrap ONE registered tool handler so its failure crosses the MCP boundary
    as ToolError, with its text intact.

    Only here, never in `_Outcome.deliver`: a direct library caller of
    `_record_call` still gets the original exception type (there is a test that
    asserts a FileNotFoundError stays a FileNotFoundError). The re-typing is a
    property of the SDK edge, not of the library.
    """
    cls = _tool_error_class()
    if cls is None:
        return fn

    @functools.wraps(fn)
    def _wrapped(*a, **k):
        try:
            return fn(*a, **k)
        except cls:
            raise
        except Exception as exc:  # noqa: BLE001 - re-typed, not swallowed
            raise cls(f"{type(exc).__name__}: {exc}") from exc

    return _wrapped


class _Outcome:
    """What a handler's work produced: a result, or the exception it raised.
    Carried, not decided, so the record can be written before the answer (or
    the error) goes back to the caller."""
    __slots__ = ("result", "error")

    def __init__(self, result=None, error: BaseException | None = None) -> None:
        self.result = result
        self.error = error

    def deliver(self):
        if self.error is not None:
            raise self.error
        return self.result


def _attempt(fn, *args, **kwargs) -> _Outcome:
    """Run the handler's work and capture either answer. Only ordinary
    exceptions are captured; a KeyboardInterrupt or SystemExit is not a tool
    outcome and propagates untouched."""
    try:
        return _Outcome(result=fn(*args, **kwargs))
    except Exception as e:  # noqa: BLE001 - the whole point is to record it
        return _Outcome(error=e)


def _args_digest(args: dict) -> tuple[str, int]:
    """sha256 over the canonical JSON of the arguments (sorted keys, compact
    separators, non-JSON values via str) - byte-identical to the digest the
    other four Arcaeon servers write, so one verifier reads all five."""
    raw = json.dumps(args, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest(), len(raw)


def _record_call(tool: str, args: dict, outcome: _Outcome | None = None):
    """Append one hash-chained row for a tool call, then deliver the outcome.

    Called as the LAST line of every handler, after the work: the row carries
    `ok` and, on a refused call, the error text, so a call that failed is
    recorded as a failure rather than not at all. The chaining is
    arcaeon-ledger's `Ledger.append` (`chain = sha256(prev_chain + row)`), so
    the prev-hash link is the `chain` field itself and the file verifies under
    every arcaeon-ledger verifier as well as `verify_call_record` below. If
    the record cannot be written the tool errors out even though its work ran,
    the same rule the sibling servers apply: a call answered as if it were
    logged when it was not is the failure this exists to catch.
    """
    outcome = outcome if outcome is not None else _Outcome()
    digest, nbytes = _args_digest(args)
    row = {
        "op": "tool_call",
        "tool": tool,
        "ts": datetime.now(timezone.utc).isoformat(),
        "args_digest": digest,
        "args_digest_alg": _ARGS_DIGEST_ALG,
        "args_bytes": nbytes,
        "ok": outcome.error is None,
    }
    if outcome.error is not None:
        # An upstream error can quote the caller's own argument back (mcp-vet's
        # "not a readable file: <path>"), and a caller can put a lone surrogate
        # in that argument ("\ud800" is legal JSON). Ledger.append writes strict
        # utf-8, so until 2026-09-05 that one character failed the record write
        # and the caller was told the call could not be recorded. Replace, do
        # not fail: the row must land.
        text = f"{type(outcome.error).__name__}: {outcome.error}"[:2000]
        row["error"] = text.encode("utf-8", "replace").decode("utf-8")
    try:
        Ledger(call_record_path()).append(row)
    except Exception as e:
        raise RuntimeError(
            f"{tool} ran but its call record could not be written to "
            f"{call_record_path()}: {e}") from outcome.error
    return outcome.deliver()


def verify_call_record(path: str | Path | None = None) -> dict:
    """Recompute the chain over the connector's own call record. `ok` is
    three-valued the way arcaeon-ledger's is (True / False / None when the
    scan was bounded or there is no record yet); `rows`, `breaks` and
    `first_break` name the damage when there is any."""
    p = Path(path) if path else call_record_path()
    if not p.exists():
        return {"ok": None, "rows": 0, "breaks": 0, "first_break": None,
                "path": str(p), "note": "no call record yet"}
    v = Ledger(p).verify(strict=True)
    return {"ok": v.ok, "rows": v.rows, "breaks": v.breaks,
            "first_break": v.first_break, "path": str(p),
            "verified_scope": v.verified_scope}


# --- the ledger seam -------------------------------------------------------

def _ledger_call(upstream_name: str, arguments: dict) -> dict:
    """One tools/call through the ledger server's own handler.

    Building the JSON-RPC envelope by hand looks like ceremony next to calling
    the private helpers directly, and it is the whole point: `handle` is the
    surface upstream tests and ships. Reaching past it into `_prove_my_conduct`
    would mean the connector and the standalone server take different paths to
    the same answer.
    """
    resp = _ledger_handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": upstream_name, "arguments": arguments}},
        Ledger(ledger_path()),
        ns_dir=ns_dir(),
    )
    result = resp["result"]
    text = "".join(c.get("text", "") for c in result.get("content", []))
    try:
        payload = json.loads(text) if text else {}
    except ValueError:  # pragma: no cover - upstream always emits JSON text
        payload = {"error": text}
    if result.get("isError"):
        # A caller-fixable argument problem, handed back as the tool erroring
        # with upstream's own sentence. The alternative — returning it as a
        # normal result — is a silent green, which is exactly what these two
        # products exist to prevent.
        raise ValueError(payload.get("error", text or "ledger tool failed"))
    return payload


def _witness_call(tool: str, write, args: dict):
    """The paid lane's two gates, in order, then the HTTP hop.

    License first, account second. "May this copy run at all" is a different
    question from "does this caller have a witness account", and answering
    them in the other order would sell a pack to someone whose copy we are
    about to refuse anyway. The license gate is off unless asked for. A
    refusal is a returned sentence, not an exception: it is a product surface,
    and the call record marks it `ok` because the connector answered exactly
    as designed.
    """
    refused = licensing.refusal_for(tool, args["namespace"])
    if refused:
        return refused
    key = _key()
    if not key:
        return upgrade_message(tool, FREE_TOOLS)
    return write(args["namespace"], args["rows"], args["chain"], key)


def _server_class():
    """The SDK's server class under whichever name the installed version uses
    (2.x: MCPServer; 1.x: FastMCP). Same probe mcp-vet ships."""
    try:
        from mcp.server.mcpserver import MCPServer  # SDK >= 2.0
        return MCPServer
    except ImportError:
        pass
    try:
        from mcp.server.fastmcp import FastMCP  # SDK 1.x
        return FastMCP
    except ImportError as e:  # pragma: no cover - the SDK is a hard dependency
        raise RuntimeError(
            "arcaeon needs the MCP Python SDK: pip install 'mcp>=1.0'") from e


def build_server():
    """Build the server. Separated from serve() so tests drive it with the
    SDK's in-process client instead of spawning a subprocess."""
    mcp = _server_class()(
        name=SERVER_NAME,
        version=__version__,
        instructions=(
            "Arcaeon's toolbox on one connector. ledger_* keeps a tamper-evident, "
            "hash-chained record of what an agent did and judges another agent's "
            "exported log. vet_* statically checks MCP-server source before you "
            "connect to it. witness_* pins your ledger head with a party you "
            "cannot advance (the only thing that catches truncation) and is the "
            "one paid lane — it needs ARCAEON_KEY; everything else is free and "
            "needs nothing. Call arcaeon_status for versions and the free/paid "
            "split. None of these tools claim your records are TRUE: they prove "
            "a record was not altered, which is a different and smaller thing."
        ),
    )

    # --- ledger, re-exported whole ---------------------------------------
    # Every handler has the same three-line shape: name the arguments once, do
    # the work under `_attempt`, and END in `_record_call`, which writes the
    # connector's own chained row and only then hands back the result (or
    # re-raises the error). The recorder is the last line on purpose: a check
    # that reads handler bodies finds it there, and a row written before the
    # work would have to guess the outcome.

    # Every handler goes through _anticipated: from mcp 2.1 a plain exception
    # is a "crash" whose text is withheld from the caller, and our refusals are
    # anticipated failures whose text is the whole point (CI, 2026-09-06).
    def _tool(**kw):
        deco = mcp.tool(**kw)
        return lambda fn: deco(_anticipated(fn))

    @_tool(name=LEDGER_TOOLS["ledger_append"], description=_LEDGER_DESC["ledger_append"])
    def ledger_append(record: dict) -> dict:
        args = {"record": record}
        outcome = _attempt(_ledger_call, "ledger_append", args)
        return _record_call("ledger_append", args, outcome)

    @_tool(name=LEDGER_TOOLS["ledger_verify"], description=_LEDGER_DESC["ledger_verify"])
    def ledger_verify(strict: bool = False) -> dict:
        args = {"strict": strict}
        outcome = _attempt(_ledger_call, "ledger_verify", args)
        return _record_call("ledger_verify", args, outcome)

    @_tool(name=LEDGER_TOOLS["prove_my_conduct"], description=_LEDGER_DESC["prove_my_conduct"])
    def ledger_prove_my_conduct(namespace: str, events: list[str]) -> dict:
        args = {"namespace": namespace, "events": events}
        outcome = _attempt(_ledger_call, "prove_my_conduct", args)
        return _record_call("ledger_prove_my_conduct", args, outcome)

    @_tool(name=LEDGER_TOOLS["verify_peer_ledger"],
              description=_LEDGER_DESC["verify_peer_ledger"])
    def ledger_verify_peer_ledger(jsonl_text: str, strict: bool = False) -> dict:
        args = {"jsonl_text": jsonl_text, "strict": strict}
        outcome = _attempt(_ledger_call, "verify_peer_ledger", args)
        return _record_call("ledger_verify_peer_ledger", args, outcome)

    @_tool(name=LEDGER_TOOLS["declare_break"], description=_LEDGER_DESC["declare_break"])
    def ledger_declare_break(namespace: str, reason: str) -> dict:
        args = {"namespace": namespace, "reason": reason}
        outcome = _attempt(_ledger_call, "declare_break", args)
        return _record_call("ledger_declare_break", args, outcome)

    # --- mcp-vet ----------------------------------------------------------

    @_tool(name=VET_TOOLS["mcp_vet_scan"], description=_VET_SCAN_DESCRIPTION)
    def vet_scan(path: str) -> list[dict]:
        args = {"path": path}
        outcome = _attempt(_vet_scan_recorded, path)
        return _record_call("vet_scan", args, outcome)

    @_tool(name=VET_TOOLS["mcp_vet_grade"], description=_VET_GRADE_DESCRIPTION)
    def vet_grade(path: str) -> dict:
        args = {"path": path}
        outcome = _attempt(_vet_grade_recorded, path)
        return _record_call("vet_grade", args, outcome)

    @_tool(
        name=VET_TOOLS["mcp_vet_audit_verify"],
        description=(
            "Recompute the hash chain over mcp-vet's OWN call-record ledger "
            "(one tamper-evident row per vet_scan / vet_grade call it made) and "
            "report whether it is intact: ok (true / false / null when the scan "
            "was bounded - not a green), rows, breaks, and first_break naming "
            "the first line that does not reproduce. Also reports whether the "
            "record is switched on at all - the failure worth catching is an "
            "audit trail the caller wrongly believes exists. Reads only; never "
            "writes to the ledger it is verifying, and never records itself."),
    )
    def vet_audit_verify(path: str | None = None) -> dict:
        args = {"path": path}
        outcome = _attempt(_vet_verify_audit_ledger, path)
        return _record_call("vet_audit_verify", args, outcome)

    # --- the paid lane ----------------------------------------------------
    # No return annotation on purpose: the gated answer is a plain sentence and
    # the paid answer is the witness's JSON. Pinning one output schema over both
    # would force the refusal to wear a shape it does not have.

    @_tool(
        name="witness_pin",
        description=(
            "PAID (needs ARCAEON_KEY). Record your ledger head (rows + chain) with "
            "the hosted witness, a party you cannot advance — the only thing that "
            "catches TRUNCATION, which a hash chain alone cannot. Returns the "
            "stored pin, the public commit, and the history URL. Without a key it "
            "returns a plain note with the free tier and the $5 pack; it never "
            "silently does nothing. Proves no-truncation only relative to what the "
            "witness saw and only as recently as the last pin: the pin gap IS the "
            "security parameter."),
    )
    def witness_pin(namespace: str, rows: int, chain: str):
        args = {"namespace": namespace, "rows": rows, "chain": chain}
        outcome = _attempt(_witness_call, "witness_pin", witness.pin, args)
        return _record_call("witness_pin", args, outcome)

    @_tool(
        name="witness_renew",
        description=(
            "PAID (needs ARCAEON_KEY). Restate an UNCHANGED head so a finished log "
            "stops looking abandoned: rows and chain must match the current head "
            "exactly (a mismatch is refused, 409 renewal_head_mismatch) — a renewal "
            "moves the cadence deadline and can never launder a re-mint or erase a "
            "deadline that was already missed. Without a key it returns a plain "
            "note with the free tier and the $5 pack."),
    )
    def witness_renew(namespace: str, rows: int, chain: str):
        args = {"namespace": namespace, "rows": rows, "chain": chain}
        outcome = _attempt(_witness_call, "witness_renew", witness.renew, args)
        return _record_call("witness_renew", args, outcome)

    # --- what is in here, and what costs money ----------------------------

    @_tool(
        name=STATUS_TOOL,
        description=(
            "What this connector is made of and what any of it costs: the version "
            "of each bundled package, every tool split into free and paid, whether "
            "an ARCAEON_KEY is currently set, and where the ledger it writes to "
            "lives. Call this first if a tool refused you."),
    )
    def arcaeon_status() -> dict:
        outcome = _attempt(_status_payload)
        return _record_call("arcaeon_status", {}, outcome)

    return mcp


def _status_payload() -> dict:
    """The body of `arcaeon_status`, kept as a plain function so the handler
    itself has the same record-last shape as the other ten."""
    return {
        "connector_version": __version__,
        "components": {
            "arcaeon-ledger": LEDGER_VERSION,
            "mcp-vet": VET_VERSION,
            "arcaeon-connector": __version__,
        },
        "free_tools": list(FREE_TOOLS),
        "paid_tools": list(PAID_TOOLS),
        "key_present": _key() is not None,
        "key_env_var": "ARCAEON_KEY",
        "license_gate": licensing.status(),
        "witness_endpoint": witness.base_url(),
        "ledger_path": str(ledger_path()),
        "ns_dir": str(ns_dir()),
        "call_record_path": str(call_record_path()),
        "price_list": CATALOG_URL,
        "notes": [
            "Everything except witness_* is free forever and needs no key; "
            "the witness LIBRARY is self-hostable free too, the paid part is "
            "us hosting it.",
            "The witness free tier is 100 pins/month, no card — email "
            "hello@arcaeon.io for a key.",
            "Auth is bearer-key only (auth_level bearer-stage0): a leaked key "
            "can pin and renew in your name. Owner-signature auth is designed, "
            "not built.",
            "Tamper-evidence is not truth: these tools prove a record was not "
            "altered, never that what it records was correct.",
            "Every call through this connector, this one included, appends one "
            "hash-chained row to call_record_path (tool, UTC timestamp, sha256 "
            "of the arguments, outcome). verify_call_record() recomputes it.",
        ],
    }


def serve() -> None:
    """Run over stdio. Local pipe only — the tools read caller-named paths, so
    do not put this behind a network transport without auth in front (which is
    what vet_scan's own zero-auth check would tell you)."""
    build_server().run(transport="stdio")


if __name__ == "__main__":  # pragma: no cover
    serve()
