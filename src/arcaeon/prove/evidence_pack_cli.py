# SPDX-License-Identifier: MIT
"""`arcaeon evidence-pack`: build an evidence pack folder.

    arcaeon evidence-pack --ledger L --out DIR [--witness STORE --namespace NS]
                          [--system-id ID] [--provider NAME] [--json]

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
    p.add_argument("--witness", default=None, help="path to a witness store (JSONL)")
    p.add_argument("--namespace", default=None, help="the witness namespace to check")
    p.add_argument("--system-id", default="", help="the system's id, for the summary")
    p.add_argument("--provider", default="", help="the provider's name, for the summary")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    return p


def main(argv: list[str] | None = None, *, prog: str = "arcaeon evidence-pack") -> int:
    from arcaeon.prove.evidence_pack import PackUsageError, build_pack

    a = _parser(prog).parse_args(argv)
    try:
        res = build_pack(a.ledger, a.out, system_id=a.system_id, provider=a.provider,
                         witness=a.witness, witness_namespace=a.namespace)
    except PackUsageError as e:
        print(f"{prog}: {e}", file=sys.stderr)
        return V.EXIT_USAGE
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        line = f"{res['verdict']}: evidence pack at {res['out']}"
        if res.get("reason"):
            line += f" ({res['reason_word']}: {res['reason']})"
        print(line)
    return res["exit"]


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
