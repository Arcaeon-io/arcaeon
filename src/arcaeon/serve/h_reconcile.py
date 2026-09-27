# SPDX-License-Identifier: MIT
"""POST /v1/reconcile (K009).

`kind: "tapes"` (the default): two tapes and an optional pin, answered with
`arcaeon reconcile <tape_a> <tape_b> [--pin PIN]`'s JSON plus `exit`:
MATCHED 0, MISSING or ALTERED 1, COULD NOT LOOK 3, always in a 200 body.
Each tape may come as a path under the served root (`tape_a`, `tape_b`) or
inline (`content_a` / `content_a_b64`, `content_b` / `content_b_b64`).

`kind: "readings"` (K035): `tape_a` and `tape_b` name two readings ledgers
(or come inline the same way), answered with the readings compare,
`arcaeon.prove.readings_compare.compare(a, b)`, which carries its own
`exit`: COMPARED 0, MISSING or BROKEN 1, COULD NOT LOOK 3, in a 200 body.
A pin with readings is bad usage (400).
"""
from __future__ import annotations

import json

from arcaeon import verdict as V
from arcaeon.serve import h_core

_TAPES = [("tape_a", "content_a", "content_a_b64"), ("tape_b", "content_b", "content_b_b64")]
READINGS_NOT_BUILT = "readings compare not built"


def _readings(body: dict) -> dict:
    if body.get("pin") is not None:
        return h_core._usage("a pin is for tapes; kind \"readings\" takes two ledgers only")
    try:
        from arcaeon.prove.readings_compare import compare
    except ImportError:
        return h_core._usage(READINGS_NOT_BUILT)
    try:
        with h_core._inputs(body, _TAPES) as (paths, tmpdir):
            res = compare(paths["tape_a"], paths["tape_b"])
            text = h_core._scrub(json.dumps(res, ensure_ascii=False), tmpdir, paths)
    except h_core._Usage as e:
        return h_core._usage(str(e))
    out = json.loads(text)
    if not isinstance(out.get("exit"), int):
        out["exit"] = V.EXIT_COULD_NOT_LOOK
    return out


def reconcile(body: dict) -> dict:
    if not isinstance(body, dict):
        return h_core._usage("the request body must be a JSON object")
    kind = body.get("kind", "tapes")
    if kind == "readings":
        return _readings(body)
    return h_core.reconcile(body)
