# SPDX-License-Identifier: MIT
"""POST /v1/mandate/check: is one call inside a mandate? (K075)

    {"mandate": "mandate.json", "fields": {"name": "place_order", "total": "19.00"}}

Never a second implementation: the body becomes the argv of
`arcaeon mandate check`, run through h_core.run_verb, and the verb's --json
comes back with its integer `exit` (inside 0, outside 1, could_not_look 3).
A verdict never rides in the HTTP status. Record-only by construction: the
route says inside or outside and blocks nothing.
"""
from __future__ import annotations

import json

from arcaeon import verdict as V
from arcaeon.serve import h_core


def _usage(msg: str) -> dict:
    return {"exit": V.EXIT_USAGE, "error": msg}


def check(body: dict) -> dict:
    """`arcaeon mandate check <mandate> --field k=v ... [--at T] [--spent A] --json`."""
    if not isinstance(body, dict):
        return _usage("the request body must be a JSON object")
    mandate = body.get("mandate")
    if not isinstance(mandate, str) or not mandate:
        return _usage("missing required field 'mandate'")
    fields = body.get("fields", {})
    if not isinstance(fields, dict):
        return _usage("`fields` must be a JSON object")
    argv = ["check", mandate, "--json"]
    for k, v in fields.items():
        if not isinstance(k, str) or not k or "=" in k or k.endswith(":"):
            return _usage(f"field name {k!r} cannot be passed as --field")
        # A string stays a string; anything else keeps its JSON type (KEY:=JSON),
        # so an amount sent as 19.00 is not silently turned into "19.0".
        argv += ["--field", f"{k}={v}" if isinstance(v, str)
                 else f"{k}:={json.dumps(v, ensure_ascii=False)}"]
    for name in ("at", "spent"):
        v = body.get(name)
        if v is not None:
            if not isinstance(v, str):
                return _usage(f"`{name}` must be a string")
            argv += [f"--{name}", v]
    return h_core._result(*h_core.run_verb("mandate", argv))
