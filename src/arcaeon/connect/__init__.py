# SPDX-License-Identifier: MIT
"""`arcaeon connect`: the config an AI client needs to reach arcaeon.

The catalog (catalog.py) is the one list of clients: where each keeps its
config file on each OS, the top-level key the arcaeon entry goes under, the
transport (stdio MCP, or HTTP with the OpenAPI document), and the public
doc page each path was read from, with the date it was read. A path that
page did not state is marked unconfirmed, and `connect` says so.

`arcaeon connect <client>` prints what it would change and writes nothing;
`--write` applies it. Stdlib only; nothing here touches the network.
"""
from __future__ import annotations
