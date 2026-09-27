# SPDX-License-Identifier: MIT
"""POST /v1/audit/verify and POST /v1/audit/export (K010).

`/v1/audit/verify` takes `path` (an audit log, or an exported bundle
directory, which means its `records.jsonl`) or `content` / `content_b64`,
and runs `arcaeon audit verify`. `/v1/audit/export` takes `ledger` and
`out` and runs `arcaeon audit export <ledger> <out>`; the server has
already fenced both to the served root (K006), so the bundle lands inside it.

Both verbs print plain text, so the answer carries it as `output`, plus the
verdict word the text leads with as `verdict` (verify: VERIFIED, UNVERIFIED,
FAIL, COULD NOT LOOK; export: the `Verdict:` line's word) and `exit` from
the one table: 0 nothing wrong found, 1 an accusation, 3 COULD NOT LOOK.
The words are the CLI's own, read off its output, never recomputed here.
"""
from __future__ import annotations

import os
import re

from arcaeon.serve import h_core

BUNDLE_LOG = "records.jsonl"
_DASH = "\u2014"
_EXPORT_VERDICT = re.compile(r"^Verdict:\s+(\S+)", re.M)


def _lead_word(text: str) -> str | None:
    head = text.split(_DASH, 1)[0].strip() if _DASH in text else ""
    return head or None


def verify(body: dict) -> dict:
    """`arcaeon audit verify`; a bundle directory verifies its records.jsonl."""
    if isinstance(body, dict):
        p = body.get("path")
        if isinstance(p, str) and p and os.path.isdir(p):
            inner = os.path.join(p, BUNDLE_LOG)
            if not os.path.isfile(inner):
                return h_core._usage(f"`path` is a directory with no {BUNDLE_LOG} "
                                     "(not an exported bundle)")
            body = {**body, "path": inner}
    res = h_core.audit_verify(body)
    word = _lead_word(res.get("output", ""))
    if word:
        res["verdict"] = word
    return res


def export(body: dict) -> dict:
    """`arcaeon audit export <ledger> <out>`; the bundle directory comes back as `out`."""
    bad = h_core._need(body, "ledger", "out")
    if bad:
        return bad
    rc, out, err = h_core.run_verb("audit", ["export", body["ledger"], body["out"]])
    res = h_core._result(rc, out, err)
    m = _EXPORT_VERDICT.search(out)
    if m:
        res["verdict"] = m.group(1)
    res["out"] = body["out"]
    return res
