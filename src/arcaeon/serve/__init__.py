# SPDX-License-Identifier: MIT
"""`arcaeon serve`: one local HTTP/JSON API any model or agent framework can call.

The route table (routes.py) is the one list of what the server answers; the
OpenAPI document, the MCP parity check and the server's dispatch all read it.
Handlers are named by dotted path and imported only when a route is called,
so importing this package pulls in nothing beyond the standard library.

Loopback only: the server binds 127.0.0.1. Exposing it to a network is a
deploy decision, not a flag.

Response rule, every route: HTTP 200 whenever a verdict was reached (MATCHED,
BROKEN, COULD NOT LOOK alike), carrying the same JSON the CLI's --json prints
plus an integer `exit`. 400 bad usage, 401 no token, 404, 405, 413 a body over
MAX_BODY bytes. A verdict never rides in the HTTP status.
"""
from __future__ import annotations

#: Largest request body the server reads (section 0: 413 over 10 MB).
MAX_BODY = 10 * 1024 * 1024
#: The default port `arcaeon serve` binds on 127.0.0.1.
DEFAULT_PORT = 8787
