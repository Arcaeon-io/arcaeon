# SPDX-License-Identifier: MIT
"""A stdlib-only mini-ledger for the MCP server's own call record (OWASP MCP08).

arcaeon-mcp-vet's `audit-record` check graded this package's MCP server on
2026-09-02, first in the registry-benchmark queue with the other four of ours,
and gave it gate 0 of 4: no record of a tool call on any tool-handling path.
This module is the fix, kept small so the package keeps its zero-dependency
pitch. It writes hash-chained JSONL rows in the SAME format as arcaeon-ledger
(`chain = sha256(prev + json.dumps(row minus chain, sort_keys=True))[:32]`,
genesis "genesis"), so a call record verifies under `arcaeon-ledger verify`
or `verify_peer_ledger` as well as under `CallRecord.verify()` here. One
format, not a fork of one.

What goes in a row is decided in `mcp_server.py`, next to the handler that
produces it; this module only chains and appends.

Honest limits. Single-writer: a stdio MCP server is one process, and this
does not take the cross-process lock the full ledger does, so two servers
pointed at one file can fork the chain, which `verify()` will then report.
The record proves the server said what it did; it does not prove the tool's
work was correct.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from arcaeon.record.row import GENESIS as _GENESIS
from arcaeon.record.row import chain as _chain


def default_path(server_name: str) -> Path:
    """`$ARCAEON_CALL_RECORD` if set, else `./<server>.calls.jsonl`."""
    env = os.environ.get("ARCAEON_CALL_RECORD")
    return Path(env) if env else Path(f"{server_name}.calls.jsonl")


class CallRecord:
    """Append-only, hash-chained JSONL file. `append(row)` links the row to the
    previous one and writes it; `verify()` walks the chain from genesis."""

    def __init__(self, path) -> None:
        self.path = Path(path)

    def _last_chain(self) -> str:
        if not self.path.exists():
            return _GENESIS
        last = None
        with self.path.open("r", encoding="utf-8", errors="surrogatepass") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last is None:
            return _GENESIS
        try:
            return str(json.loads(last).get("chain") or _GENESIS)
        except ValueError:
            return _GENESIS

    def append(self, row: dict) -> dict:
        row = dict(row)
        row["chain"] = _chain(self._last_chain(), row)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            fh.flush()
        return row

    def verify(self) -> dict:
        """`ok` True/False/None (no file), `rows`, `first_break` (1-based line)."""
        if not self.path.exists():
            return {"ok": None, "rows": 0, "first_break": None, "note": "no call record yet"}
        prev, rows = _GENESIS, 0
        with self.path.open("r", encoding="utf-8", errors="surrogatepass") as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    row = json.loads(line)
                except ValueError:
                    return {"ok": False, "rows": rows, "first_break": n, "note": "unparseable line"}
                if not isinstance(row, dict) or row.get("chain") != _chain(prev, row):
                    return {"ok": False, "rows": rows, "first_break": n, "note": "chain mismatch"}
                prev = row["chain"]
                rows += 1
        return {"ok": True, "rows": rows, "first_break": None}


def verify_call_record(path) -> dict:
    return CallRecord(path).verify()
