"""arcaeon-ledger MCP server — tamper-evident action logging as MCP tools.

Wraps the FREE arcaeon-ledger library (hash-chained, append-only JSONL log)
and exposes three tools any MCP client can call:

  ledger_create(path)          -> report/initialize a ledger at a path
  ledger_append(path, record)  -> append one record, return its chain hash
  ledger_verify(path)          -> verify the whole chain, name the first break

What it proves and does NOT prove (kept honest, in the tool descriptions too):
the chain proves the file was not ALTERED after each row was written — an edit,
deletion, or reorder anywhere breaks every later link and verify names the exact
line. It does NOT prove the logged action was correct, wise, or truthful at write
time, and by itself does not stop someone rewriting the whole chain from a chosen
point forward (for that you anchor the head somewhere you don't control — a
commit, a timestamp service, a witness).

Built on the official MCP Python SDK (`mcp` package, MCPServer / FastMCP-style
decorator API). Run:  python -m arcaeon.mcp.ledger_server
Wire into an MCP client (e.g. Claude Code .mcp.json):
  { "mcpServers": { "arcaeon-ledger": {
      "command": "python", "args": ["-m", "arcaeon.mcp.ledger_server"] } } }
"""
from __future__ import annotations

# Was arcaeon_ledger_mcp/__init__.py's only content (unpublished 0.1.0).
__version__ = "0.1.0"

import datetime as _dt
import hashlib
import json as _json
import os
from pathlib import Path
from typing import Any

# --- import the wrapped library ------------------------------------------------
# arcaeon-ledger is pip-installed (declared as a dependency) and its top-level
# package is `arcaeon_ledger`. No sys.path fallback: a missing package must fail
# loudly rather than silently load the stale copy in projects/ledger (see
# projects/ledger/STALE_COPY_README.md). Never modifies the ledger package itself.
from arcaeon.record.ledger import Ledger, verify_file  # type: ignore

from mcp.server import MCPServer

mcp = MCPServer("arcaeon-ledger")

# Every tool takes a caller-supplied `path`, and the caller is a model. Without a
# fence that is "append a hash-chained line to any file the process can write"
# and "read the first lines of any file it can read" (2026-09-01 audit). Ledger
# files must sit under ARCAEON_LEDGER_ROOT (default: the working directory) and
# end in .jsonl. Refusal is a plain error the model can read, never a silent
# redirect — a redirect would make the returned `path` a false record.
_ROOT_ENV = "ARCAEON_LEDGER_ROOT"


def _ledger_root() -> Path:
    return Path(os.environ.get(_ROOT_ENV) or os.getcwd()).resolve()


def _contained(path: str) -> Path:
    if not isinstance(path, str) or not path.strip():
        raise ValueError("path must be a non-empty string")
    root = _ledger_root()
    p = (root / path).resolve() if not Path(path).is_absolute() else Path(path).resolve()
    if p.suffix != ".jsonl":
        raise ValueError(f"ledger path must end in .jsonl; got {path!r}")
    try:
        p.relative_to(root)
    except ValueError:
        raise ValueError(f"ledger path must sit under {_ROOT_ENV}={root}; got {path!r}") from None
    return p


@mcp.tool()
def ledger_create(path: str) -> dict[str, Any]:
    """Open (or report) a tamper-evident, hash-chained action log at `path`.

    A ledger is a single append-only JSONL file. Creation is lazy: the file is
    written on the first append, so this tool never overwrites an existing log.
    Use it to confirm a path is usable and to see the current state (whether the
    file already exists, and how many rows it holds and whether they verify).

    Returns: {path, exists, rows, verified, first_break}. `verified` and
    `first_break` describe an existing file's current integrity (verified=True
    and first_break=null for a brand-new/empty ledger).
    """
    p = _contained(path)
    exists = p.exists()
    res = verify_file(p) if exists else None
    return {
        "path": str(p),
        "exists": exists,
        "rows": (res.rows if res else 0),
        "verified": (bool(res.ok) if res else True),
        "first_break": (res.first_break if res else None),
    }


def _args_digest(record: dict[str, Any]) -> str:
    """sha256 over the caller-supplied record, computed before any server-side
    field is added, so it is a digest of exactly what the caller submitted."""
    payload = _json.dumps(record, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@mcp.tool()
def ledger_append(path: str, record: dict[str, Any]) -> dict[str, Any]:
    """Append one action record to the tamper-evident log at `path`.

    `record` is any JSON object describing the action (args, result, actor,
    amount, decision...). Three audit fields are stamped by the SERVER, not
    trusted from the caller, and always win over a same-named key already in
    `record` (2026-09-05 fix, mcp_vet audit-record gate 2 — completeness — was
    unmet: the row this tool wrote carried no tool name, no timestamp, and no
    digest of what was actually sent, all three caller-spoofable if left to
    `record` itself): `tool` (this tool's own name, literal), `ts` (UTC
    ISO-8601, the server's own clock), `args_digest` (sha256 over the raw
    caller-supplied `record`, taken BEFORE these fields are added — proof of
    what was submitted, not of the enriched row). The row is hash-chained to
    the one before it, so any later edit/deletion/reorder is detectable by
    ledger_verify. Returns the new row's chain hash.

    Proves the record cannot later be altered undetected. Does NOT vouch that
    the action itself was correct or that its contents are true — only that,
    once logged, the entry stands unchanged.

    Returns: {ok, chain, path}.
    """
    p = _contained(path)
    log = Ledger(p)
    entry = {
        **record,
        "tool": "ledger_append",
        "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "args_digest": _args_digest(record),
    }
    chain = log.append(entry)
    return {"ok": True, "chain": chain, "path": str(p)}


@mcp.tool()
def ledger_verify(path: str) -> dict[str, Any]:
    """Verify the hash chain over the whole log file at `path`.

    Recomputes every link from the genesis seed. If the file was edited, had a
    row deleted, or was reordered, verification fails and names the EXACT first
    broken line (e.g. "line 3: chain mismatch").

    This proves the file has not been ALTERED since writing. It does NOT prove the
    writer was honest at write time, and does not by itself defend against a full
    rewrite of the chain from a chosen point forward (anchor the head externally
    for that).

    Returns: {ok, rows, chained, prechain, first_break}. ok=True means intact;
    first_break is null when ok, else the exact failing line.
    """
    res = verify_file(_contained(path))
    return {
        "ok": bool(res.ok),
        "rows": res.rows,
        "chained": res.chained,
        "prechain": res.prechain,
        "first_break": res.first_break,
    }


def main() -> None:
    """Run the server over stdio (the transport MCP clients wire up locally)."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
