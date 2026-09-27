# SPDX-License-Identifier: MIT
"""`arcaeon export`: write a ledger out in another record format.

    arcaeon export --format agent-audit-trail LEDGER --out FILE.jsonl [--json]

One format today: draft-sharif-agent-audit-trail, JSONL only, the subset of
fields the rows actually hold, each record carrying our original `chain`.
It is not AAT-conformant: a subset, with the original chain beside it.

Exit codes as every verb: 0 VERIFIED, 1 BROKEN, 2 bad usage, 3 COULD NOT LOOK.
"""
from __future__ import annotations

import argparse
import json
import sys

from arcaeon import verdict as V


def _parser(prog: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog, description="Write a ledger out as draft-sharif-agent-audit-trail "
        "records (JSONL, a subset of fields, our original chain kept on each).")
    p.add_argument("ledger", help="the ledger (JSONL) to export")
    p.add_argument("--format", required=True, choices=("agent-audit-trail",),
                   help="the record format (only agent-audit-trail today)")
    p.add_argument("--out", required=True, help="a new .jsonl file to write")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    return p


def main(argv: list[str] | None = None, *, prog: str = "arcaeon export") -> int:
    from arcaeon.prove.aat_export import AatUsageError, export_aat

    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        a = _parser(prog).parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else V.EXIT_USAGE
    try:
        res = export_aat(a.ledger, a.out)
    except AatUsageError as e:
        print(f"{prog}: {e}", file=sys.stderr)
        return V.EXIT_USAGE
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        if res.get("out"):
            line = (f"{res['verdict']}: {res['records']} record(s) written to {res['out']} "
                    f"(source chain {res['verdict'].lower()})")
        else:
            line = f"{res['verdict']}: nothing exported"
        if res.get("finding"):
            line += f" ({res['finding']})"
        elif res.get("reason"):
            line += f" ({res['reason_word']}: {res['reason']})"
        print(line)
    return res["exit"]


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
