# SPDX-License-Identifier: MIT
"""Handlers for `POST /v1/handshake/propose`, `/accept` and `/verify` (KH7).

The routes are declared in routes.py (K002); this module only answers them.
Never a second implementation: each handler calls the same function
`arcaeon deal handshake` calls (arcaeon.record.handshake.api_*), so the HTTP
body and the CLI's JSON are one shape by construction, plus the integer
`exit`. A verdict never rides in the HTTP status: AGREED TERMS, DIFFERENT
TERMS, MISSING and COULD NOT LOOK all come back 200 with `exit` 0, 1, 1, 3.

Each agent runs its own server over its own ledger: agent A calls its server's
propose, hands the returned `proposal` to agent B, and B calls its server's
accept. Either side can call verify with both ledger paths.
"""
from __future__ import annotations

from arcaeon.record import handshake as _hs


def propose(body: dict) -> dict:
    """{ledger, terms, agent?, to?, handshake?} -> {proposal, exit}."""
    return _hs.api_propose(body)


def accept(body: dict) -> dict:
    """{ledger, proposal, agent?} -> {acceptance, exit}."""
    return _hs.api_accept(body)


def verify(body: dict) -> dict:
    """{a, b, handshake?} -> AGREED TERMS / DIFFERENT TERMS / MISSING / COULD NOT LOOK."""
    return _hs.api_verify(body)
