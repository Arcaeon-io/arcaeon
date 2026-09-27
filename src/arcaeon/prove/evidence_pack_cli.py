# SPDX-License-Identifier: MIT
"""`arcaeon evidence-pack`: build an evidence pack folder.

    arcaeon evidence-pack --ledger L --out DIR [--agent ID] [--from TS] [--to TS]
                          [--witness STORE --namespace NS]
                          [--system-id ID] [--provider NAME] [--format aat]
                          [--deal ID (--buyer B | --seller S)]
                          [--mandate FILE] [--json]
    arcaeon evidence-pack verify PACK [--json]

Exit codes as every verb: 0 VERIFIED, 1 BROKEN, 2 bad usage, 3 COULD NOT LOOK.
"""
from __future__ import annotations

import argparse
import json
import sys

from arcaeon import verdict as V


def _parser(prog: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog, description="Build an evidence pack: one folder, evidence toward "
        "the EU AI Act logging duties (not a claim of compliance).")
    p.add_argument("--ledger", required=True, help="the ledger (JSONL) to pack")
    p.add_argument("--out", required=True, help="a new or empty folder to write")
    p.add_argument("--agent", default=None,
                   help="the agent: matches a row's `agent` or `system_id`")
    p.add_argument("--from", dest="since", default=None,
                   help="window start, ISO 8601, inclusive (no zone means UTC)")
    p.add_argument("--to", dest="until", default=None,
                   help="window end, ISO 8601, inclusive (no zone means UTC)")
    p.add_argument("--witness", default=None, help="path to a witness store (JSONL)")
    p.add_argument("--namespace", default=None, help="the witness namespace to check")
    p.add_argument("--system-id", default="", help="the system's id, for the summary")
    p.add_argument("--provider", default="", help="the provider's name, for the summary")
    p.add_argument("--format", dest="formats", action="append", default=[],
                   choices=("aat",),
                   help="also write the records as agent-audit-trail JSONL (aat.jsonl "
                        "and aat_gaps.json, checked on verify)")
    p.add_argument("--deal", default=None,
                   help="fold one deal's dispute into the pack (arcaeon deal pack)")
    p.add_argument("--buyer", default=None,
                   help="with --deal: the buyer's tape (default: --ledger)")
    p.add_argument("--seller", default=None,
                   help="with --deal: the seller's tape (default: --ledger)")
    p.add_argument("--mandate", default=None,
                   help="the mandate file the gate judged the window against: its "
                        "inside / outside / could-not-look counts, its sha256 and the "
                        "outside rows go in mandate_rows.json")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    return p


def main(argv: list[str] | None = None, *, prog: str = "arcaeon evidence-pack") -> int:
    from arcaeon.prove.evidence_pack import PackUsageError, build_pack

    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["verify"]:
        from arcaeon.prove import evidence_pack_verify
        return evidence_pack_verify.main(argv[1:], prog=f"{prog} verify")
    a = _parser(prog).parse_args(argv)
    try:
        res = build_pack(a.ledger, a.out, system_id=a.system_id, provider=a.provider,
                         witness=a.witness, witness_namespace=a.namespace,
                         agent=a.agent, since=a.since, until=a.until,
                         formats=tuple(a.formats), deal=a.deal,
                         deal_buyer=a.buyer, deal_seller=a.seller,
                         mandate=a.mandate)
    except PackUsageError as e:
        print(f"{prog}: {e}", file=sys.stderr)
        return V.EXIT_USAGE
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        # No folder was written when the ledger was missing: say so, never
        # "evidence pack at None".
        line = (f"{res['verdict']}: evidence pack at {res['out']}" if res.get("out")
                else f"{res['verdict']}: no evidence pack written")
        if res.get("reason"):
            line += f" ({res['reason_word']}: {res['reason']})"
        print(line)
    return res["exit"]


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
