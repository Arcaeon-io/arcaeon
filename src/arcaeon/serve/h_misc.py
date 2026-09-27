# SPDX-License-Identifier: MIT
"""POST /v1/receipt/verify and GET /v1/status (K011).

`/v1/receipt/verify` runs `arcaeon receipt verify <receipt>` (a path under
the served root, or `content` / `content_b64`) and answers its JSON plus
`exit`, with two plain additions read off that JSON: `verdict` (VERIFIED
when the receipt's `ok` is true, BROKEN when it is false) and, on a BROKEN,
`reason`, the first of the receipt's own `notes` (for a changed body field:
`body digest mismatch: a body field was altered after issue`). A receipt
that cannot be read is the CLI's error, carried as `error`.

`/v1/status` runs `arcaeon status --json`. `balance` comes back as one
sentence: `not checked, no key` when ARCAEON_KEY is unset (no request is
made), else the witness's answer as the CLI renders it; the structured
answer rides beside it as `balance_detail`.
"""
from __future__ import annotations

from arcaeon import verdict as V
from arcaeon.serve import h_core


def receipt_verify(body: dict) -> dict:
    res = h_core.receipt_verify(body)
    ok = res.get("ok")
    if ok is True:
        res["verdict"] = V.VERIFIED
    elif ok is False:
        res["verdict"] = V.BROKEN
        notes = res.get("notes")
        if isinstance(notes, list) and notes and isinstance(notes[0], str):
            res["reason"] = notes[0]
    return res


def status(body: dict | None = None) -> dict:
    res = h_core.status(body)
    b = res.get("balance")
    if isinstance(b, dict):
        res["balance_detail"] = b
        res["balance"] = (b.get("sentence") if b.get("checked") else b.get("reason")) \
            or "balance not read"
    return res
