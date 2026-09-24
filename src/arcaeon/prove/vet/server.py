"""mcp_vet as an MCP server (stdio). C-agent-02, 2026-08-30.

The checker's natural consumer is an agent deciding whether to trust a server it
is about to connect to. Making that a shell-out to a CLI puts a parsing step
between the agent and the answer; making it MCP puts the answer where the agent
already looks. Three tools, no more:

  mcp_vet_scan(path)   -> list[finding dict]  — same findings the CLI prints
  mcp_vet_grade(path)  -> grade dict          — the SAME artifact `grade` emits,
                                                source_sha256 and blind_spots
                                                included
  mcp_vet_audit_verify() -> verdict dict      — recompute the chain over this
                                                server's OWN call record and
                                                name the first broken line

`grade` returns the whole artifact rather than a verdict string on purpose: the
only thing this project sells is a result a skeptic can re-run, and a summary is
not re-runnable. An agent gets the pinned hash and can hand it to `verify()`.

THE AUDIT TRAIL (v0.0.7, board B2b). v0.0.6 shipped the MCP08 `audit-record`
check and this file scored **high** on it — all four gates false, published in
the README rather than fixed in the same breath, because the finding was the
more useful artifact. This is the fix, and the shape of it matters: every
`mcp_vet_scan` / `mcp_vet_grade` call appends ONE hash-chained row to a real
`arcaeon_ledger` file (tool, ISO-8601 UTC timestamp, the path asked for, the
sha256 of the exact bytes read, the finding count and the verdict), and
`mcp_vet_audit_verify` recomputes the chain and names the first line that does
not reproduce. The gates are met by a record that exists at runtime and can be
checked by somebody who does not trust us — not by source text arranged to
satisfy our own heuristic, which is the failure this whole project is a
complaint about.

Three honest edges on it, none of them papered over:

  1. `arcaeon_ledger` is an OPTIONAL extra (now `arcaeon.record.ledger`, in the base `pip install arcaeon`). The
     scanner core stays stdlib-only. Without it the server still runs and the
     record is OFF — but never silently: the status is in the server's
     instructions, in `mcp_vet_audit_verify`'s reply, and on stderr at startup.
     Which means our own gate-1 pass is conditional on an import the static
     check cannot see. That is a real miss in the checker and it is confessed as
     one (`grade.py: _BS_MCP08_OPTIONAL`), rather than enjoyed quietly.
  2. `mcp_vet_audit_verify` does NOT record itself. A verify that mutates its
     own subject can never report on it cleanly. That leaves one of three tools
     outside the trail — precisely the per-handler coverage gap the tool already
     confesses as a blind spot. We sit in our own blind spot knowingly and say
     so here.
  3. A ledger write failure RAISES through the tool call. An audit trail you
     cannot write to is a fact the caller needs; swallowing the error to keep
     the scan looking healthy is the silent green this tool exists to catch.

DISCLOSED EXPOSURE, and a disclosed MISS. This server hands a caller-named path
to the scanner: mcp_vet's own `path-traversal` class pointed at itself. Reading
the named file is the entire function of a file scanner, so the exposure is by
design. The miss is not. `mcp_vet scan mcp_vet/server.py` does not report it,
because the taint runs path -> _read(path) -> read_text, one hop through a
helper, and multi-hop taint through function calls is the blind spot v0.0.4
left open. Our own server is a live demonstration of a gap we already
published. It is stated here and in the README rather than laundered out of the
self-audit, and it is deliberately NOT worked around by inlining the read to
make the checker fire: gaming your own checker is the exact dishonesty this
project exists to catch.

Mitigation, until the analysis catches up, is operational rather than
analytical: run stdio/local only, and do not bind this to a network transport
without an auth layer in front, which is what our own `zero-auth` check would
tell you.

No code execution, no network, no authority claim — same stance as the CLI.

SDK compatibility: the `mcp` Python SDK renamed FastMCP -> MCPServer in 2.0.
Both are probed so this works either side of that rename.
"""
from __future__ import annotations

import functools
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from .checks import scan_source
from .grade import grade_source

SERVER_NAME = "mcp-vet"

# --- the call record ---------------------------------------------------------
#
# arcaeon_ledger is an append-only hash-chained JSONL log: each row carries the
# chain hash of the one before it, so a mid-file edit, deletion or reorder
# breaks every later link and `verify_file()` names the exact line. That is what
# makes gate 3 (tamper-evidence) and gate 4 (reconstructability) true here
# rather than aspirational. It is an OPTIONAL extra on purpose — the scanner
# core is stdlib-only, and a checker that drags in a dependency tree is a
# supply-chain surface of its own.
try:
    from arcaeon.record.ledger import Ledger, verify_file
    AUDIT_AVAILABLE = True
    _IMPORT_ERROR = ""
except ImportError as _exc:  # pragma: no cover - depends on the optional extra
    Ledger = None
    verify_file = None
    AUDIT_AVAILABLE = False
    _IMPORT_ERROR = str(_exc)


def _audit_off_reason() -> str:
    """Why the record is off, in words an operator can act on. Built from a
    constant rather than only from the caught ImportError, because the trail can
    also be switched off by a host that stubs the dependency out — and a reason
    string that comes back empty in that case is the silent-off failure this
    whole surface is built to prevent."""
    because = (" (%s)" % _IMPORT_ERROR) if _IMPORT_ERROR else ""
    return ("arcaeon_ledger is not available%s, so tool calls are NOT being "
            "recorded. Install the extra to turn the audit trail on: "
            "pip install -U arcaeon" % because)

#: Environment override for the ledger location. Read at CALL time, never
#: cached at import: a server that pinned the path when the module loaded would
#: ignore an operator who set the variable in the launching shell.
AUDIT_LEDGER_ENV = "MCP_VET_AUDIT_LEDGER"


def audit_ledger_path() -> Path:
    """Where the call record lives. `$MCP_VET_AUDIT_LEDGER`, else
    `~/.mcp_vet/audit.jsonl`."""
    override = os.environ.get(AUDIT_LEDGER_ENV)
    return Path(override) if override else Path.home() / ".mcp_vet" / "audit.jsonl"


def audit_status_line() -> str:
    """One line, ON or OFF, said out loud everywhere the operator might look.

    The failure mode worth engineering against is not "no audit trail" — it is
    an audit trail the operator BELIEVES exists. So the status rides in the
    server instructions, in every `mcp_vet_audit_verify` reply, and on stderr at
    startup, and it is never inferred from the absence of an error."""
    if AUDIT_AVAILABLE:
        return "audit record: ON (hash-chained, %s)" % audit_ledger_path()
    return "audit record: OFF — %s" % _audit_off_reason()


#: How much of a caller-supplied path we echo back or write down. A path is an
#: address; a megabyte of one is an attack on the reply and the record (the
#: 2026-09-05 input fuzz got a 1 MB path into a 2 MB audit row and a 2 MB error
#: reply, per call, with no cap). The digest of the full path stays exact.
PATH_ECHO_MAX = 512
ERROR_TEXT_MAX = 2000


def _clip(text: str, limit: int) -> str:
    """`text`, cut to `limit` chars with the cut named, and with any lone
    surrogate replaced so the result survives a strict utf-8 write. A lone
    surrogate is legal JSON ("\\ud800") and used to abort the audit row: the
    ledger's strict encode raised, the row was lost, and the caller was told the
    record could not be written. One hostile character must not erase a call
    from the record the call exists to leave."""
    text = str(text).encode("utf-8", "replace").decode("utf-8")
    if len(text) <= limit:
        return text
    return "%s...[%d more chars]" % (text[:limit], len(text) - limit)


def _record_call(tool: str, path: str, source: str | None,
                 findings: int | None = None, verdict: str | None = None,
                 error: str | None = None) -> None:
    """Append ONE tamper-evident row for one tool call. This is the MCP08
    control, and each field is here because a gate asks for it:

      tool          — WHICH tool ran. A record that cannot say that answers
                      nothing (gate 2, and the reason a bare `logging.info`
                      does not count as presence in our own check).
      ts            — ISO-8601 UTC, stamped here rather than left to the
                      library, so the completeness of the row is a property of
                      THIS file and not of a dependency one import away.
      args          — what the caller asked for.
      source_sha256 — the exact bytes that were graded. This is what makes the
                      row re-testable: anyone holding the file can recompute the
                      digest and prove the row is about the bytes it claims.
      findings /
      verdict       — the outcome, so the record reconstructs the answer given,
                      not merely that something was asked.
      error         — a call that failed still happened. An audit trail that
                      only remembers the successes is a marketing document.

    A write failure raises. See the module docstring, note 3."""
    if not AUDIT_AVAILABLE:
        return
    target = audit_ledger_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    digest = (hashlib.sha256(source.encode("utf-8", "replace")).hexdigest()
              if source is not None else None)
    path = str(path)
    args: dict = {"path": _clip(path, PATH_ECHO_MAX)}
    if args["path"] != path:
        # Clipped or cleaned: keep an exact fingerprint of what was really asked
        # for, so the row still answers "was it THIS path" without carrying it.
        args["path_sha256"] = hashlib.sha256(
            path.encode("utf-8", "surrogatepass")).hexdigest()
        args["path_len"] = len(path)
    record = {
        "tool": tool,
        "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "args": args,
        "source_sha256": digest,
        "findings": findings,
        "verdict": verdict,
        "error": _clip(error, ERROR_TEXT_MAX) if error is not None else None,
    }
    ledger = Ledger(target)
    ledger.append(record)


def verify_audit_ledger(path: str | None = None) -> dict:
    """Recompute the chain over the call record and report the first break.

    This is gate 4 — an independent party can replay the record set — and it is
    deliberately a real recomputation by the library that wrote the rows, not a
    self-attestation. `ok` is three-valued by `arcaeon_ledger`'s design and is
    passed through unflattened: True means every row verified, False means a
    break was found, and None means no break was found but the scan was BOUNDED
    (unchained legacy rows skipped, or a break excused by a declaration).
    Collapsing None into True here would mint exactly the false green that
    three-valued result exists to prevent."""
    # A caller-named path goes through the scan fence (when one is set), with
    # the server's own ledger admitted even when it lives outside the root. An
    # out-of-root path raises the same PermissionError `_read` raises, before
    # any existence check, for the same reason: no oracle.
    target = _fenced(path, allow=audit_ledger_path()) if path else audit_ledger_path()
    shown = _clip(str(target), PATH_ECHO_MAX)
    base = {"enabled": AUDIT_AVAILABLE, "ledger": shown, "ok": None,
            "rows": 0, "first_break": None, "breaks": 0,
            "verified_scope": None, "detail": ""}
    if not AUDIT_AVAILABLE:
        base["detail"] = _audit_off_reason()
        return base
    if not target.is_file():
        base["detail"] = ("no ledger at %s yet — no tool call has been recorded "
                          "on this path" % shown)
        return base
    result = verify_file(target)
    base.update(ok=result.ok, rows=result.rows, breaks=result.breaks,
                first_break=result.first_break,
                verified_scope=result.verified_scope,
                detail=("chain intact" if result.ok is True else
                        "chain broken" if result.ok is False else
                        "no break found, but the scan was bounded"))
    return base


def build_instructions() -> str:
    """The server's instructions block, audit status included. Built rather than
    a constant so the ON/OFF line can never drift from the actual state."""
    return (
        "Static checker for MCP server source. Reports a small set of "
        "documented failure classes (unsafe-exec, ssrf, path-traversal, "
        "zero-auth, secret-in-code, audit-record) with exact line numbers. NOT "
        "a vetting authority and NOT a certification: a clean result means "
        "these checks found nothing, and every grade carries its own blind "
        "spots inline. Every scan/grade call is itself recorded — "
        + audit_status_line()
    )


def _server_class():
    """Return the SDK's server class, whatever it is called in the installed
    version. 2.x: mcp.server.mcpserver.MCPServer. 1.x: mcp.server.fastmcp.FastMCP."""
    try:
        from mcp.server.mcpserver import MCPServer  # SDK >= 2.0
        return MCPServer
    except ImportError:
        pass
    try:
        from mcp.server.fastmcp import FastMCP  # SDK 1.x
        return FastMCP
    except ImportError as e:  # pragma: no cover - depends on missing optional dep
        raise RuntimeError(
            "arcaeon vet's MCP server needs the MCP Python SDK. Install the extra:\n"
            "    pip install 'arcaeon[mcp]'"
        ) from e


SCAN_ROOT_ENV = "MCP_VET_SCAN_ROOT"


def _fenced_root() -> Path | None:
    """The opt-in scan fence (2026-09-02).

    This server reads files on request from whatever agent connects to it. With
    no fence it will read ANY absolute path it is handed, which is a disclosed
    exposure and a perfectly reasonable default for the local single-user case
    it was built for. It is not reasonable the moment the server is exposed to a
    caller you do not control, and "the operator knows" stops being true exactly
    when it matters most.

    Setting MCP_VET_SCAN_ROOT confines every read to that subtree. Opt-in rather
    than on-by-default because turning it on by default would silently break
    every existing caller passing absolute paths, and a security control that
    arrives as a mystery breakage gets switched off rather than understood.

    Returns None when unset, which leaves prior behaviour byte-identical."""
    raw = os.environ.get(SCAN_ROOT_ENV)
    if not raw:
        return None
    try:
        return Path(raw).resolve(strict=False)
    except Exception:
        return None


def _read(path: str) -> tuple[str, str]:
    """Read the target source. A missing/unreadable path RAISES: a scanner that
    answers 'no findings' for a file it never opened is a silent green, which is
    the exact failure mode this tool exists to catch in other people's servers.

    Fence check happens BEFORE the existence check, deliberately. Reporting
    "not a readable file" for a path outside the root would leak whether that
    path exists, so an out-of-root request is refused the same way whether the
    file is there or not."""
    p = _fenced(path)
    if not p.is_file():
        raise FileNotFoundError(f"not a readable file: {_clip(path, PATH_ECHO_MAX)}")
    return p.read_text(encoding="utf-8", errors="replace"), str(p)


def _fenced(path: str, allow: Path | None = None) -> Path:
    """The caller's path, admitted through the MCP_VET_SCAN_ROOT fence (or passed
    through untouched when no fence is set). Split out of `_read` on 2026-09-05
    so `verify_audit_ledger` goes through the SAME gate: it took a caller-named
    path straight to `verify_file`, which made it a read-any-file existence
    oracle (rows + first_break + line counts) that the fence did not cover.

    `allow` is one path admitted even when outside the root — the server's own
    audit ledger, which lives under ~ by default and is the file this tool is for."""
    root = _fenced_root()
    p = Path(path)
    if root is None:
        return p
    # A RELATIVE path resolves against the ROOT, not the process cwd. That is
    # the whole point: if relatives resolved against cwd, then chdir would be
    # an escape hatch and the fence would only hold for callers who were
    # already behaving. It also makes the fence usable - a caller inside the
    # root can pass ordinary relative paths and they mean what they look like.
    candidate = p if p.is_absolute() else (root / p)
    # resolve() both sides so ../ traversal and symlinks normalise away
    # before comparison; is_relative_to is a containment test, not a string
    # prefix, so /rootless does not slip past a /root fence.
    try:
        candidate = candidate.resolve(strict=False)
    except Exception:
        raise PermissionError(f"refused: unresolvable path under {SCAN_ROOT_ENV}: "
                              f"{_clip(path, PATH_ECHO_MAX)}")
    if allow is not None:
        try:
            if candidate == allow.resolve(strict=False):
                return candidate
        except Exception:
            pass
    if not candidate.is_relative_to(root):
        # Refuse identically whether or not the file exists: a distinct
        # "not found" for an out-of-root path would answer questions about
        # the filesystem outside the fence, one bit at a time.
        raise PermissionError(
            f"refused: {_clip(path, PATH_ECHO_MAX)} is outside {SCAN_ROOT_ENV} ({root}). "
            f"This server only reads inside its configured root.")
    return candidate


def _severity_verdict(findings: list[dict]) -> str:
    for sev in ("high", "medium", "low"):
        if any(f.get("severity") == sev for f in findings):
            return "%s-severity findings" % sev
    return "no findings in the checked classes"


# --- library-level recorded entry points (C-agent-31, 2026-08-30) -----------
#
# `mcp_vet_scan` / `mcp_vet_grade` below are thin MCP wrappers around these two
# functions, on purpose: `_record_call` is a module-private helper, so any
# caller that wants scan/grade PLUS the audit row without going through a full
# MCP round-trip (stdio subprocess, in-process client, JSON-RPC envelope) had
# no supported way to get it. The connector was reaching past that gap into
# `mcp_vet.checks.scan_source` / `mcp_vet.grade.grade_source` directly, which
# scans and grades correctly but never calls `_record_call` — a vet call made
# through the connector left no row in mcp-vet's own audit ledger, while the
# identical call through mcp-vet's own server did. That is exactly the silent
# gap MCP08 exists to catch, just one layer removed from the server that
# fixed it in 0.0.7. `scan_recorded` / `grade_recorded` are the fix: the SAME
# read-scan-record (or read-grade-record) sequence the tool handlers run,
# exposed as ordinary library calls so any caller in-process can get the
# recorded behavior without speaking MCP to itself.
def scan_recorded(path: str) -> list[dict]:
    """`scan_source` plus the audit row `mcp_vet_scan` writes. Raises the same
    way `_read` does on a missing/unreadable path, and records the failure
    before re-raising — a call that failed still happened."""
    try:
        source, name = _read(path)
        out = [f.as_dict() for f in scan_source(source, name)]
    except Exception as exc:
        _record_call("mcp_vet_scan", path, None, error=repr(exc))
        raise
    _record_call("mcp_vet_scan", name, source, findings=len(out),
                 verdict=_severity_verdict(out))
    return out


def grade_recorded(path: str) -> dict:
    """`grade_source` plus the audit row `mcp_vet_grade` writes. Same failure
    handling as `scan_recorded`."""
    try:
        source, name = _read(path)
        out = json.loads(grade_source(source, name).to_json())
    except Exception as exc:
        _record_call("mcp_vet_grade", path, None, error=repr(exc))
        raise
    _record_call("mcp_vet_grade", name, source,
                 findings=len(out["findings"]), verdict=out["verdict"])
    return out


#: The `mcp_vet_scan` / `mcp_vet_grade` tool descriptions, pulled out as module
#: constants (rather than left inline in `build_server`) so the connector can
#: import the exact text instead of hand-copying it — the same reason the
#: connector reads its ledger tool descriptions off `arcaeon_ledger`'s own
#: `TOOLS` list. A hand-copied string drifts the day one server's wording
#: changes and the other's doesn't; an imported constant cannot.
SCAN_DESCRIPTION = (
    "Statically scan a Python MCP-server source file and return the "
    "findings as a list. Each finding carries check, severity "
    "(high/medium/info), file, line, and detail. An empty list means "
    "the checked classes found nothing - not that the file is safe. "
    "The call is recorded to this server's tamper-evident ledger."
)

GRADE_DESCRIPTION = (
    "Grade a Python MCP-server source file and return the full "
    "re-testable grade artifact: source_sha256 pinning the exact bytes "
    "graded, the findings, the checks that were run, the tool's own "
    "declared blind spots, and a verdict. Feed it back to "
    "mcp_vet.grade.verify() to confirm it reproduces. The call is "
    "recorded to this server's tamper-evident ledger."
)


def _tool_error_class():
    """The SDK's ToolError, or None when it cannot be imported."""
    for path, name in (("mcp.server.mcpserver.exceptions", "ToolError"),
                       ("mcp.server.fastmcp.exceptions", "ToolError")):  # SDK 1.x
        try:
            return getattr(__import__(path, fromlist=[name]), name)
        except Exception:  # noqa: BLE001 - no SDK at all is a valid state here
            continue
    return None


def _anticipated(fn):
    """Wrap one registered handler so its failure crosses the MCP boundary as
    ToolError, text intact.

    From mcp 2.1 the server sorts a tool's exception by TYPE: ToolError is "a
    failure you anticipated" and keeps its message; anything else is a crash
    and the caller is told only "Error executing tool <name>". This server's
    refusals are the whole product -- "refused: <path> is outside
    MCP_VET_SCAN_ROOT" is the sentence a caller needs to see, and under 2.1 it
    was being withheld (caught on CI 2026-09-06; the hostile-path tests are
    what noticed). The library functions keep raising their own types; only
    the SDK edge is re-typed.
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


def build_server():
    """Build the MCP server. Separated from run() so tests can drive it with the
    SDK's in-process client instead of spawning a subprocess."""
    from . import __version__

    mcp = _server_class()(
        name=SERVER_NAME,
        version=__version__,
        instructions=build_instructions(),
    )

    def _tool(**kw):
        deco = mcp.tool(**kw)
        return lambda fn: deco(_anticipated(fn))

    @_tool(name="mcp_vet_scan", description=SCAN_DESCRIPTION)
    def mcp_vet_scan(path: str) -> list[dict]:
        return scan_recorded(path)

    @_tool(name="mcp_vet_grade", description=GRADE_DESCRIPTION)
    def mcp_vet_grade(path: str) -> dict:
        return grade_recorded(path)

    @_tool(
        name="mcp_vet_audit_verify",
        description=(
            "Recompute the hash chain over THIS server's own call record and "
            "report whether it is intact: ok (true / false / null when the "
            "scan was bounded), rows, breaks, and first_break naming the first "
            "line that does not reproduce. Also reports whether the record is "
            "switched on at all - an audit trail an operator wrongly believes "
            "exists is worse than none. Reads only; it does not write to the "
            "ledger it is verifying."
        ),
    )
    def mcp_vet_audit_verify(path: str | None = None) -> dict:
        return verify_audit_ledger(path)

    return mcp


def serve() -> None:
    """Run over stdio. Local pipe only - see the disclosed exposure above."""
    print(audit_status_line(), file=sys.stderr)
    build_server().run(transport="stdio")


if __name__ == "__main__":  # pragma: no cover
    serve()
