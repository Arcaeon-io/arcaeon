# SPDX-License-Identifier: MIT
"""Pin a tape's head at the witness: the COUNTER in "two tapes and a counter".

    pin = pin_tape("tool.tape.jsonl", HostedWitness(url, key), pair="acme-agent")

A tape (`arcaeon-tape/1`, one row per tool call, rows in call order) is pinned
exactly like any ledger, through `publish_head`: the witness's existing body
`{namespace, rows, chain}`, where `rows` is the call count and `chain` the head
after the last call. `publish_head` already refuses an empty or unverified log;
this module adds the tape-specific refusals (not a tape, mixed sides, no or
contradictory namespace) BEFORE anything leaves the machine.

The design's two optional fields ride along as `extra`:
  `record_format: "arcaeon-tape/1"`  so a reader knows rows = calls
  `pair: <the other side's namespace>` so a stranger can find the other counter
Whether the witness KEPT them is reported, never assumed (see HostedWitness).

The return value is a pin record `arcaeon-ledger reconcile --pin` reads
directly: `{namespace, rows, chain, side, ...}`.

Stdlib only.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import Ledger, verify_file
from .witness import publish_head

__all__ = ["pin_tape", "TAPE_FORMAT"]

TAPE_FORMAT = "arcaeon-tape/1"
_NS = re.compile(r"^[a-z0-9-]{1,64}$")   # the hosted witness's NS_RE


def _tape_facts(path: Path) -> tuple[str | None, str | None]:
    """(side, ns) of a tape whose every row is an arcaeon-tape/1 row. Raises
    ValueError on anything that is not one tape of one side and one namespace."""
    side = ns = None
    seen = False
    text = path.read_text(encoding="utf-8", errors="replace")
    for n, raw in enumerate((ln for ln in text.split("\n") if ln.strip()), start=1):
        row = json.loads(raw)
        if not (isinstance(row, dict) and row.get("evt") == "tape_call"
                and row.get("tape") == TAPE_FORMAT and row.get("side") in ("agent", "tool")):
            raise ValueError(f"{path} row {n} is not an {TAPE_FORMAT} row: only a tape is "
                             f"pinned as a call counter")
        if not seen:
            side, ns, seen = row["side"], row.get("ns"), True
        elif row["side"] != side or row.get("ns") != ns:
            raise ValueError(f"{path} row {n} changes side or namespace; one tape is one "
                             f"side under one namespace")
    return side, ns


def pin_tape(tape_path, store, *, namespace: str | None = None, pair: str | None = None,
             received_at: str | None = None) -> dict:
    """Pin `tape_path`'s head with `store` (a `HostedWitness`, or any store
    `publish_head` accepts). Returns a pin record; raises ValueError before any
    request when the tape cannot honestly be pinned, and HostedWitnessError
    when a hosted witness does not record it."""
    path = Path(tape_path)
    res = verify_file(path, strict=True)
    if res.ok is False:
        raise ValueError(f"refusing to pin {path}: the tape does not verify "
                         f"({res.first_break})")
    if res.ok is None and res.verified_scope == "empty":
        raise ValueError(f"refusing to pin {path}: an empty tape counts no calls")
    if res.ok is not True:
        raise ValueError(f"refusing to pin {path}: the tape did not verify in full "
                         f"({res.verified_scope}); every row of a tape must be chained")
    side, row_ns = _tape_facts(path)
    ns = namespace if namespace is not None else row_ns
    if ns is None:
        raise ValueError(f"refusing to pin {path}: no namespace given and the tape rows "
                         f"carry none")
    if row_ns is not None and ns != row_ns:
        raise ValueError(f"refusing to pin {path} under namespace {ns!r}: its rows say "
                         f"{row_ns!r}, and reconcile matches a pin to a tape by namespace")
    if not _NS.match(ns):
        raise ValueError(f"namespace {ns!r} must match [a-z0-9-]{{1,64}}")
    if pair is not None and (not isinstance(pair, str) or not _NS.match(pair) or pair == ns):
        raise ValueError(f"pair {pair!r} must be the OTHER side's namespace, "
                         f"matching [a-z0-9-]{{1,64}}")
    extra = {"record_format": TAPE_FORMAT}
    if pair is not None:
        extra["pair"] = pair
    rec = publish_head(store, ns, Ledger(path), received_at=received_at, extra=extra)
    out = {"namespace": ns, "rows": rec.get("rows"), "chain": str(rec.get("chain", "")).lower(),
           "side": side, "record_format": TAPE_FORMAT, "pair": pair,
           "extra_fields": rec.get("extra_fields", "not_sent"), "status": "pinned"}
    for k in ("pinned_at", "seq", "next_pin_due_by", "witness", "witness_status",
              "idempotent", "received_at"):
        if k in rec:
            out[k] = rec[k]
    return out
