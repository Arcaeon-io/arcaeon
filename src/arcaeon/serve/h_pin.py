# SPDX-License-Identifier: MIT
"""POST /v1/pin (free, local) and the paid lane: /v1/pin with remote, /v1/seal (K012).

Local pin is free: `{"ledger", "witness", "ns"}` runs `arcaeon pin <ledger>
--witness <witness> --ns <ns>`, the witness file fenced to the served root
like every other path. The answer is the CLI's JSON plus `exit`, with the
pin's `namespace` and `chain` lifted to the top.

The paid lane can spend: `/v1/pin` with `"remote": true` (the hosted
witness) and `/v1/seal` (the existing PAID badge seal, not a free "seal a
record"). Two opt-ins, checked in this order, before anything is sent:

1. ARCAEON_KEY must be set. Without it the answer is the plain refusal
   sentence the MCP paid lane gives (arcaeon.remote.offers.upgrade_message).
2. The server must have been started with `--allow-paid`. Without it the
   answer says so, and nothing is sent even though a key is set.

A refusal is COULD NOT LOOK (exit 3, `refused: true`, the sentence as
`reason`) in a 200 body: the paid half was not looked at, and a refusal is
never green. The flag is read from the server (serve.server.current_server),
never from the request, so an agent cannot grant itself the spend.
"""
from __future__ import annotations

from arcaeon import verdict as V
from arcaeon.serve import h_core

NOT_ALLOWED = ("this server was started without --allow-paid, so the paid lane does not "
               "spend even with ARCAEON_KEY set; nothing was sent. Restart it with "
               "`arcaeon serve --allow-paid` to allow it.")


def _refused(sentence: str) -> dict:
    return {"verdict": V.COULD_NOT_LOOK, "exit": V.EXIT_COULD_NOT_LOOK, "refused": True,
            "reason": sentence}


def paid_refusal(tool: str) -> dict | None:
    """None when the paid lane may spend; else the refusal body."""
    from arcaeon import remote
    from arcaeon.remote.offers import upgrade_message
    if not remote.key():
        return _refused(upgrade_message(tool))
    from arcaeon.serve.server import current_server
    srv = current_server()
    if not getattr(srv, "allow_paid", False):
        return _refused(NOT_ALLOWED)
    return None


def _lift(res: dict) -> dict:
    p = res.get("pin")
    if isinstance(p, dict):
        for k_from, k_to in (("namespace", "namespace"), ("ns", "namespace"),
                             ("chain", "chain")):
            if k_to not in res and isinstance(p.get(k_from), str):
                res[k_to] = p[k_from]
    return res


def pin(body: dict) -> dict:
    bad = h_core._need(body, "ledger")
    if bad:
        return bad
    remote = body.get("remote")
    if remote is not None and not isinstance(remote, bool):
        return h_core._usage("`remote` must be true or false")
    if remote:
        if body.get("witness") is not None:
            return h_core._usage("send `witness` (a local pin) or `remote`, not both")
        refused = paid_refusal("witness_pin")
        if refused:
            return refused
        argv = [body["ledger"], "--remote"]
        if h_core._str(body, "ns"):
            argv += ["--ns", body["ns"]]
        return _lift(h_core._result(*h_core.run_verb("pin", argv)))
    bad = h_core._need(body, "witness", "ns")
    if bad:
        return bad
    rc, out, err = h_core.run_verb("pin", [body["ledger"], "--witness", body["witness"],
                                           "--ns", body["ns"]])
    return _lift(h_core._result(rc, out, err))


def seal(body: dict) -> dict:
    bad = h_core._need(body, "path")
    if bad:
        return bad
    refused = paid_refusal("seal")
    if refused:
        return refused
    argv = [body["path"]]
    if h_core._str(body, "ns"):
        argv += ["--ns", body["ns"]]
    return h_core._result(*h_core.run_verb("seal", argv))
