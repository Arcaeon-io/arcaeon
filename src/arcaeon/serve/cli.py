# SPDX-License-Identifier: MIT
"""`arcaeon serve`: start the local HTTP/JSON API on 127.0.0.1.

Exit codes: 0 a clean stop (Ctrl+C), 2 bad usage (including any --host but
127.0.0.1: exposing the server is a deploy decision), 3 the server could not
start (the port is taken, the address cannot be bound, the token file cannot
be read or created).

Every route but /health and /openapi.json needs the token in serve.token
(K005); `arcaeon serve --print-token` prints it and exits 0.
"""
from __future__ import annotations

import argparse
import sys

from arcaeon import verdict as V
from arcaeon.serve import DEFAULT_PORT


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="arcaeon serve",
        description="Start the local HTTP/JSON API. It binds 127.0.0.1 only; putting it "
                    "on a network is a deploy decision, not a flag.")
    ap.add_argument("--host", default="127.0.0.1",
                    help="must be 127.0.0.1 (anything else is refused, exit 2)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help=f"default {DEFAULT_PORT}; 0 picks a free port")
    ap.add_argument("--root", default=None, metavar="DIR",
                    help="the only directory requests may name paths in (default: the "
                         "directory serve starts in)")
    ap.add_argument("--print-token", action="store_true",
                    help="print the bearer token clients send (created on first run) and exit")
    return ap


def main(argv: list[str] | None = None) -> int:
    a = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    from arcaeon.serve import auth
    if a.print_token:
        try:
            print(auth.load_or_create())
        except OSError as e:
            print(f"arcaeon serve: cannot read or create {auth.token_path()} "
                  f"({e.strerror or type(e).__name__})", file=sys.stderr)
            return V.EXIT_COULD_NOT_LOOK
        return V.EXIT_GOOD
    if not 0 <= a.port <= 65535:
        print(f"arcaeon serve: --port {a.port} is not a port (0 to 65535)", file=sys.stderr)
        return V.EXIT_USAGE
    import os
    root = os.path.abspath(a.root) if a.root is not None else os.getcwd()
    if not os.path.isdir(root):
        print(f"arcaeon serve: --root {a.root} is not a directory", file=sys.stderr)
        return V.EXIT_USAGE
    from arcaeon.serve import server as S
    try:
        srv = S.make_server(a.host, a.port, root=root)
    except S.HostRefused as e:
        print(f"arcaeon serve: {e}", file=sys.stderr)
        return V.EXIT_USAGE
    except OSError as e:
        if getattr(e, "filename", None):      # the token file, not the socket
            print(f"arcaeon serve: cannot read or create {auth.token_path()} "
                  f"({e.strerror or type(e).__name__})", file=sys.stderr)
            return V.EXIT_COULD_NOT_LOOK
        print(f"arcaeon serve: cannot listen on 127.0.0.1:{a.port} "
              f"({e.strerror or type(e).__name__})", file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK
    print(f"arcaeon serve: serving paths under {srv.fence.root}", file=sys.stderr, flush=True)
    print(f"arcaeon serve: token in {auth.token_path()} "
          "(send it as `Authorization: Bearer <token>`; --print-token shows it)",
          file=sys.stderr, flush=True)
    S.run(srv)
    return V.EXIT_GOOD
