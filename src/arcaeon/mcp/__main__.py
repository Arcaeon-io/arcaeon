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
    ap.add_argument("--print-front-door", action="store_true",
                    help="print the object the arcaeon_front_door tool returns, as JSON, "
                         "then exit (no server, no stdio, no network)")
    ap.add_argument("--http", action="store_true",
                    help="serve over streamable HTTP on 127.0.0.1 instead of stdio "
                         "(needs arcaeon[mcp]; same token as `arcaeon serve`; loopback "
                         "only, so a remote client needs a tunnel you choose and run)")
    ap.add_argument("--port", type=int, default=None,
                    help="with --http: the port (default 8788; 0 picks a free one, "
                         "printed on the listening line)")
    args = ap.parse_args(argv)
    if args.port is not None and not args.http:
        ap.error("--port goes with --http")

    if args.log:
        os.environ["ARCAEON_LEDGER_LOG"] = args.log
    if args.ns_dir:
        os.environ["ARCAEON_LEDGER_NS_DIR"] = args.ns_dir

    if args.print_front_door:
        from .front_door import front_door
        print(json.dumps(front_door(), indent=2))
        return 0

    if args.http and not args.tools:
        from . import http_transport
        port = http_transport.DEFAULT_PORT if args.port is None else args.port
        return http_transport.run(port)

    from .server import FREE_TOOLS, PAID_TOOLS, serve

    if args.tools:
        print(json.dumps({"free": list(FREE_TOOLS), "paid": list(PAID_TOOLS)}, indent=2))
        return 0

    serve()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
