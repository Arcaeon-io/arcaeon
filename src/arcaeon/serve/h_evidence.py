# SPDX-License-Identifier: MIT
"""POST /v1/evidence-pack, /v1/evidence-pack/verify and /v1/export/aat (K069).

Each runs the CLI's own verb with --json through h_core, so the answer is
`arcaeon evidence-pack ... --json` (or `evidence-pack verify`, or `export
--format agent-audit-trail`) plus `exit`, key for key. The server has
already fenced every path (ledger, out, pack, witness) to the served root.

- `/v1/evidence-pack`: `ledger`, `out`; optional `agent`, `since`, `until`,
  `witness`, `namespace`, `system_id`, `provider`, `formats` (a list, e.g.
  `["aat"]`), `mandate` (the mandate file, K066), `receipt` (a second-read
  comparison receipt, the CLI's --readings, K067), `zip` (true also writes
  `<out>.zip`, K068) and `built_at` (YYYY-MM-DDTHH:MM:SSZ). `mandate` and
  `receipt` are fenced path fields. `deal` (a deal id) with `buyer` /
  `seller` (tapes) and `readings_ledger` (the ledger the receipt was issued
  into) are taken too (K069b): the fence names buyer, seller and
  readings_ledger, so they are resolved under the root like every other
  path. `readings` is refused: over HTTP the receipt field is `receipt`.
- `/v1/evidence-pack/verify`: `pack`; optional `witness`, `namespace`, and
  `remote` (true reads the pack's remote pins from the public witness: the
  network, and an unreachable witness is COULD NOT LOOK, reason network).
- `/v1/export/aat`: `ledger`, `out` (a new .jsonl file under the root).
"""
from __future__ import annotations

from arcaeon.serve import h_core

_OPT = (("agent", "--agent"), ("since", "--from"), ("until", "--to"),
        ("witness", "--witness"), ("namespace", "--namespace"),
        ("system_id", "--system-id"), ("provider", "--provider"),
        ("deal", "--deal"), ("buyer", "--buyer"), ("seller", "--seller"),
        ("readings_ledger", "--readings-ledger"))


#: Refused over HTTP: `readings` is the CLI's flag name; the body's field is `receipt`.
_UNFENCED = ("readings",)


def build(body: dict) -> dict:
    bad = h_core._need(body, "ledger", "out")
    if bad:
        return bad
    sent = [f for f in _UNFENCED if body.get(f) is not None]
    if sent:
        return h_core._usage(f"{', '.join('`' + f + '`' for f in sent)} not taken over "
                             "HTTP: the served-root fence does not cover those paths "
                             "(use `receipt` for the second-read receipt)")
    argv = ["--ledger", body["ledger"], "--out", body["out"]]
    for field, flag in _OPT:
        if h_core._str(body, field):
            argv += [flag, body[field]]
    for field, flag in (("mandate", "--mandate"), ("receipt", "--readings"),
                        ("built_at", "--built-at")):
        if body.get(field) is not None:
            if not h_core._str(body, field):
                return h_core._usage(f"`{field}` must be a non-empty string")
            argv += [flag, body[field]]
    zip_out = body.get("zip")
    if zip_out is not None and not isinstance(zip_out, bool):
        return h_core._usage("`zip` must be true or false")
    if zip_out:
        # <out>.zip sits beside `out`, inside the root: `out` is fenced, and it
        # cannot be the root itself, which holds the ledger and so is not empty.
        argv.append("--zip")
    formats = body.get("formats")
    if formats is not None:
        if not isinstance(formats, list) or not all(isinstance(f, str) and f for f in formats):
            return h_core._usage("`formats` must be a list of format names")
        for f in formats:
            argv += ["--format", f]
    return h_core._result(*h_core.run_verb("evidence-pack", [*argv, "--json"]))


def verify(body: dict) -> dict:
    bad = h_core._need(body, "pack")
    if bad:
        return bad
    remote = body.get("remote")
    if remote is not None and not isinstance(remote, bool):
        return h_core._usage("`remote` must be true or false")
    argv = ["verify", body["pack"]]
    if h_core._str(body, "witness"):
        argv += ["--witness", body["witness"]]
    if h_core._str(body, "namespace"):
        argv += ["--namespace", body["namespace"]]
    if remote:
        argv.append("--remote")
    return h_core._result(*h_core.run_verb("evidence-pack", [*argv, "--json"]))


def export_aat(body: dict) -> dict:
    bad = h_core._need(body, "ledger", "out")
    if bad:
        return bad
    return h_core._result(*h_core.run_verb(
        "export", [body["ledger"], "--format", "agent-audit-trail", "--out", body["out"],
                   "--json"]))
