"""`arcaeon-mcp` — the console entry point.

Flags mirror the standalone ledger server's (`--log`, `--ns-dir`) because the
people wiring this in have already read that runbook. They are written into the
environment rather than threaded through, so a client that prefers env config
(`ARCAEON_LEDGER_LOG`) and a client that prefers args land in the same place,
and there is only one resolution path to reason about.
"""
from __future__ import annotations

import argparse
import json
import os
import sys


def main(argv=None, prog: str = "arcaeon-mcp") -> int:
    ap = argparse.ArgumentParser(
        prog=prog,
        description="Arcaeon's tools on one MCP stdio server (ledger, vet, witness).")
    ap.add_argument("--log", default=None,
                    help="ledger file path (default: agent.log.jsonl, or $ARCAEON_LEDGER_LOG)")
    ap.add_argument("--ns-dir", default=None,
                    help="directory for the per-namespace agent ledgers "
                         "(default: ledgers/ beside --log)")
    ap.add_argument("--tools", action="store_true",
                    help="print the tool list and the free/paid split, then exit "
                         "(no server, no stdio) — for checking an install")
    args = ap.parse_args(argv)

    if args.log:
        os.environ["ARCAEON_LEDGER_LOG"] = args.log
    if args.ns_dir:
        os.environ["ARCAEON_LEDGER_NS_DIR"] = args.ns_dir

    from .server import FREE_TOOLS, PAID_TOOLS, serve

    if args.tools:
        print(json.dumps({"free": list(FREE_TOOLS), "paid": list(PAID_TOOLS)}, indent=2))
        return 0

    serve()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
