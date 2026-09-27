# SPDX-License-Identifier: MIT
"""POST /v1/log and POST /v1/verify (K008).

`/v1/log` takes `{"ledger": path, "fields": {...}}` or
`{"ledger": path, "row": {...}}` (both: fields over the row, the CLI's
merge) and answers `{"chain": <the new chain value>, "exit": 0}`.
`/v1/verify` answers the `arcaeon verify --json` object plus `exit`, for a
ledger path under the served root or for `content` / `content_b64`.

Both run the CLI's own verbs through h_core; the server has already fenced
every path to the served root (K006) and checked the token (K005).
"""
from __future__ import annotations

from arcaeon.serve import h_core


def log(body: dict) -> dict:
    """Append one row; the new chain value comes back as `chain`."""
    return h_core.log(body)


def verify(body: dict) -> dict:
    """VERIFIED / BROKEN / COULD NOT LOOK, the CLI's JSON plus `exit`."""
    return h_core.verify(body)
