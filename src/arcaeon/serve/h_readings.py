# SPDX-License-Identifier: MIT
"""POST /v1/readings and POST /v1/second-read/compare (K040).

`/v1/readings` is the interop door: another agent posts its OWN reading of a
claim, and it is chained into a readings ledger under the served root without
arcaeon calling any model. Body fields: `ledger`, `reader_id`, `provider`,
`claim_id`, `reading` (`yes | no | undetermined`), the claim as `claim` (its
text) or `claim_sha256`, and optionally `criterion_sha256` or `criterion`
(the criterion text, frozen first if the ledger lacks it; with neither, the
ledger's latest criterion), `model`, `near_match_id`, `rationale`,
`keep_text`. The answer is `arcaeon.prove.readings_cli.submit`'s object plus
`exit`: 0 filed, 2 bad usage (a 400), 3 COULD NOT LOOK (no such criterion,
a 200 body). "Filed" says the row was written, never that it is right.

`/v1/second-read/compare` lines up two readings ledgers, `a` and `b` (paths
under the served root, or inline as `content_a` / `content_a_b64`,
`content_b` / `content_b_b64`), answered with the readings compare object:
COMPARED 0, MISSING or BROKEN 1, COULD NOT LOOK 3, always in a 200 body.

The server has already fenced every path to the served root (K006) and
checked the token (K005).
"""
from __future__ import annotations

import json

from arcaeon import verdict as V
from arcaeon.serve import h_core

_SIDES = [("a", "content_a", "content_a_b64"), ("b", "content_b", "content_b_b64")]
_OPTIONAL_STR = ("provider", "claim", "claim_sha256", "criterion_sha256", "criterion", "model",
                 "near_match_id", "rationale")


def submit(body: dict) -> dict:
    """File one reading the caller took itself."""
    bad = h_core._need(body, "ledger", "reader_id", "claim_id", "reading")
    if bad:
        return bad
    for name in _OPTIONAL_STR:
        if body.get(name) is not None and not isinstance(body[name], str):
            return h_core._usage(f"`{name}` must be a string")
    if not h_core._str(body, "provider"):
        return h_core._usage("missing required field 'provider' (the reader's provider, "
                             "as you assert it)")
    keep = body.get("keep_text", False)
    if not isinstance(keep, bool):
        return h_core._usage("`keep_text` must be true or false")
    from arcaeon.prove.readings_cli import submit as _submit
    with h_core._LOCK:
        return _submit(body["ledger"], reader_id=body["reader_id"], provider=body["provider"],
                       claim_id=body["claim_id"], reading=body["reading"],
                       claim_text=body.get("claim"), claim_sha256=body.get("claim_sha256"),
                       criterion_sha256=body.get("criterion_sha256"),
                       criterion_text=body.get("criterion"), model=body.get("model"),
                       near_match_id=body.get("near_match_id"),
                       rationale=body.get("rationale"), keep_text=keep)


def compare(body: dict) -> dict:
    """COMPARED / MISSING / BROKEN / COULD NOT LOOK for two readings ledgers."""
    from arcaeon.prove.readings_compare import compare as _compare
    try:
        with h_core._inputs(body, _SIDES) as (paths, tmpdir):
            res = _compare(paths["a"], paths["b"])
            text = h_core._scrub(json.dumps(res, ensure_ascii=False), tmpdir, paths)
    except h_core._Usage as e:
        return h_core._usage(str(e))
    out = json.loads(text)
    if not isinstance(out.get("exit"), int):
        out["exit"] = V.EXIT_COULD_NOT_LOOK
    return out
