# SPDX-License-Identifier: MIT
"""arcaeon.prove.readings_cli: the `arcaeon second-read` verb.

    arcaeon second-read criterion FILE --ledger L [--supersedes SHA] [--json]
    arcaeon second-read compare A B [--json]

`compare` lines up two readings ledgers (see `arcaeon.prove.readings_compare`)
and prints a human first line such as

    compared 24 claims: 3 disagreed of 24 read

or, with `--json`, the whole comparison object plus nothing else.

Exit codes (the arcaeon table): COMPARED 0 (the comparison completed; a
disagreement is filed, not failed), MISSING 1, BROKEN 1, COULD NOT LOOK 3,
bad usage 2. Nothing printed here says a claim holds: two readers agreeing
measures how ambiguous the sentence was for them.

Stdlib only.
"""
from __future__ import annotations

import argparse
import json
import sys

from arcaeon import verdict as _v

__all__ = ["main", "compare_main", "human_lines", "SUBCOMMANDS"]

_PROG = "arcaeon second-read"


def human_lines(res: dict) -> list[str]:
    """The human rendering of a compare result, first line first."""
    s = res.get("summary") or {}
    word = res.get("verdict")
    claims = res.get("claims") or []
    lines: list[str] = []
    if s.get("read") is None:
        lines.append(f"{word}: {res.get('reason') or s.get('counts_reason') or 'no reason given'}")
        lines.append(f"counts not computed: {s.get('counts_reason')}")
        return lines
    lines.append(f"compared {len(claims)} claims: {s['disagreed']} disagreed of {s['read']} read")
    if word == _v.COMPARED:
        lines.append("COMPARED: both ledgers were read and lined up")
    else:
        lines.append(f"{word}: {res.get('reason') or _missing_reason(s)}")
    if s.get("not_yet_informative"):
        lines.append(f"not yet informative: fewer than 20 claims read ({s['read']})")
    if res.get("independence"):
        lines.append(f"readers: {res['independence']}")
    for c in claims:
        st = c.get("status")
        a, b = c.get("a") or {}, c.get("b") or {}
        if st == "DISAGREED":
            lines.append(
                f"  DISAGREED {c['claim_id']}: a={a.get('reading')} ({a.get('reader_id')}, "
                f"near {a.get('near_match_id')}) b={b.get('reading')} ({b.get('reader_id')}, "
                f"near {b.get('near_match_id')})")
        elif st == _v.MISSING:
            lines.append(f"  MISSING {c['claim_id']}: not read in ledger {c.get('side')}")
        elif st == _v.COULD_NOT_LOOK:
            lines.append(f"  COULD NOT LOOK {c['claim_id']}: {c.get('reason')}")
    lines.append("agreement says nothing about whether a claim holds")
    return lines


def _missing_reason(s: dict) -> str:
    return f"{s.get('missing')} claim(s) read on one side only"


def compare_main(argv: list[str] | None = None) -> int:
    """`second-read compare A B [--json]`."""
    p = argparse.ArgumentParser(prog=f"{_PROG} compare",
                                description="line up two readings ledgers, claim by claim")
    p.add_argument("a", help="the first readings ledger")
    p.add_argument("b", help="the second readings ledger")
    p.add_argument("--json", action="store_true", help="print the comparison object as JSON")
    args = p.parse_args(argv)
    from arcaeon.prove.readings_compare import compare
    res = compare(args.a, args.b)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, sort_keys=True))
    else:
        print("\n".join(human_lines(res)))
    return res["exit"]


def _criterion(argv):
    from arcaeon.prove.readings import criterion_main
    return criterion_main(argv)


#: subcommand -> (handler(argv) -> exit code, one-line help)
SUBCOMMANDS = {
    "criterion": (_criterion, "freeze a criterion sentence into a readings ledger"),
    "compare": (compare_main, "line up two readings ledgers: COMPARED / MISSING / BROKEN / COULD NOT LOOK"),
}


def _usage() -> str:
    width = max(len(k) for k in SUBCOMMANDS)
    rows = [f"  {k.ljust(width)}  {v[1]}" for k, v in SUBCOMMANDS.items()]
    return (f"usage: {_PROG} <subcommand> [args...]\n\nsubcommands:\n" + "\n".join(rows)
            + "\n\nexit 0 COMPARED, 1 MISSING or BROKEN, 2 bad usage, 3 COULD NOT LOOK")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(_usage(), file=sys.stdout if argv else sys.stderr)
        return _v.EXIT_GOOD if argv else _v.EXIT_USAGE
    sub, rest = argv[0], argv[1:]
    if sub not in SUBCOMMANDS:
        print(f"{_PROG}: unknown subcommand {sub!r}\n{_usage()}", file=sys.stderr)
        return _v.EXIT_USAGE
    try:
        return SUBCOMMANDS[sub][0](rest)
    except SystemExit as e:  # argparse: --help is 0, bad usage is 2
        return e.code if isinstance(e.code, int) else (_v.EXIT_GOOD if e.code is None else _v.EXIT_USAGE)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
