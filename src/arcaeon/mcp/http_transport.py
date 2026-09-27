# SPDX-License-Identifier: MIT
"""`arcaeon mcp --http`: the same MCP server over streamable HTTP, loopback only (KH8).

Some MCP clients only take a remote URL. This runs the exact server
`arcaeon mcp` runs on stdio (the one `build_server()`, so the tool list is
the same list, not a copy of it) behind the SDK's streamable HTTP transport,
bound to 127.0.0.1 and nothing else. Pointing a remote client at it goes
through a tunnel the user chooses and runs; the tunnel and any public URL are
the user's, and nothing here opens one.

Two locks in front of every request, both the same as `arcaeon serve`:

- Host. A Host header that names anything but 127.0.0.1 or localhost (with
  or without this port) is refused with 400 before anything else is read, so
  a web page elsewhere cannot reach it through a DNS name that points at
  127.0.0.1. A tunnel must present the loopback Host (most can rewrite it).
- Token. The serve.token file (`arcaeon serve --print-token`), as
  `Authorization: Bearer <token>` or `X-Arcaeon-Token: <token>`. Without it,
  401 with the sentence serve sends; the token is never echoed or logged.

Needs the [mcp] extra (the SDK brings the HTTP server it runs on). Without
it, `--http` fails closed: COULD NOT LOOK, exit 3, naming the extra.
"""
from __future__ import annotations

import json
import socket
import sys

from arcaeon import verdict as V

LOOPBACK = "127.0.0.1"
MCP_PATH = "/mcp"
DEFAULT_PORT = 8788
HOST_REFUSED = "this server answers only on its loopback address"
NEEDS_EXTRA = (f"{V.COULD_NOT_LOOK}: arcaeon mcp --http needs the [mcp] extra "
               "(the MCP SDK and the HTTP server it runs on): pip install 'arcaeon[mcp]'")


def missing_extra() -> str | None:
    """The first module of the [mcp] extra that will not import, or None."""
    for name in ("mcp", "uvicorn", "starlette"):
        try:
            __import__(name)
        except ImportError:
            return name
    return None


def _host_ok(host: str, port: int) -> bool:
    host = host.strip().lower()
    return host in {f"127.0.0.1:{port}", f"localhost:{port}", "127.0.0.1", "localhost"}


class Guard:
    """Pure ASGI wrapper: Host check, then token check, then the SDK app."""

    def __init__(self, app, token: str, port: int) -> None:
        self.app, self.token, self.port = app, token, port

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        headers = {k.decode("latin-1").title(): v.decode("latin-1")
                   for k, v in scope.get("headers") or []}
        if not _host_ok(headers.get("Host", ""), self.port):
            return await _reply(send, 400, {"error": HOST_REFUSED, "exit": V.EXIT_USAGE})
        from arcaeon.serve import auth
        refused = auth.check(self.token, headers)
        if refused is not None:
            return await _reply(send, 401, {"error": refused},
                                extra=[(b"www-authenticate", b"Bearer")])
        return await self.app(scope, receive, send)


async def _reply(send, status: int, body: dict, extra=()) -> None:
    data = json.dumps(body).encode("utf-8")
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(data)).encode("ascii")),
                            (b"connection", b"close"), *extra]})
    await send({"type": "http.response.body", "body": data})


def build_app(token: str, port: int):
    """The guarded ASGI app for a server on 127.0.0.1:<port>."""
    from mcp.server.transport_security import TransportSecuritySettings
    from .server import build_server
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=["127.0.0.1", "localhost", f"127.0.0.1:{port}", f"localhost:{port}"],
        allowed_origins=[f"http://127.0.0.1:{port}", f"http://localhost:{port}"])
    app = build_server().streamable_http_app(
        streamable_http_path=MCP_PATH, json_response=True, stateless_http=True,
        transport_security=security, host=LOOPBACK)
    return Guard(app, token, port)


def run(port: int, out=None) -> int:
    """Bind 127.0.0.1:<port> (0 picks one), print the URL, serve until stopped."""
    out = out or sys.stdout
    gone = missing_extra()
    if gone is not None:
        print(f"{NEEDS_EXTRA} (cannot import {gone})", file=sys.stderr, flush=True)
        return V.EXIT_COULD_NOT_LOOK
    if not 0 <= port <= 65535:
        print(f"arcaeon mcp: --port {port} is not a port (0 to 65535)", file=sys.stderr)
        return V.EXIT_USAGE
    from arcaeon.serve import auth
    try:
        token = auth.load_or_create()
    except OSError as e:
        print(f"arcaeon mcp: {V.COULD_NOT_LOOK}: cannot read or create {auth.token_path()} "
              f"({e.strerror or type(e).__name__})", file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((LOOPBACK, port))
    except OSError as e:
        sock.close()
        print(f"arcaeon mcp: {V.COULD_NOT_LOOK}: cannot listen on {LOOPBACK}:{port} "
              f"({e.strerror or type(e).__name__})", file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK
    bound = sock.getsockname()[1]
    import uvicorn
    config = uvicorn.Config(build_app(token, bound), log_level="warning",
                            access_log=False, lifespan="on")
    server = uvicorn.Server(config)
    print(f"arcaeon mcp: token in {auth.token_path()} "
          "(send it as `Authorization: Bearer <token>`; `arcaeon serve --print-token` shows it)",
          file=sys.stderr, flush=True)
    print(f"arcaeon mcp: listening on http://{LOOPBACK}:{bound}{MCP_PATH} "
          "(loopback only; Ctrl+C stops)", file=out, flush=True)
    try:
        server.run(sockets=[sock])
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
    return V.EXIT_GOOD
