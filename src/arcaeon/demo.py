# SPDX-License-Identifier: MIT
"""`arcaeon demo`: the whole idea in thirty seconds, on your own machine (K116).

    arcaeon demo

It makes a temp folder, writes two rows to a ledger there, checks it
(VERIFIED), changes one word on line 1 the way a quiet edit would, checks
again (BROKEN, naming line 1), and removes the folder. No network, nothing
left behind. It prints a short story in plain words; the last line is the
BROKEN line.

Exit 0 when the demo showed what it says: VERIFIED first, then BROKEN on
line 1. Exit 1 if either check came back any other way (the demo itself
found something wrong), 2 for bad usage.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from arcaeon import verdict as V

USAGE = ("usage: arcaeon demo\n"
         "log two rows in a temp folder, verify, change one word, verify again; "
         "no network, nothing left behind")

ROWS = (
    {"agent": "demo-agent", "did": "refund", "order": "1001", "amount": "20 dollars",
     "ts": "2026-01-01T09:00:00Z"},
    {"agent": "demo-agent", "did": "email", "to": "customer 1001", "said": "refund sent",
     "ts": "2026-01-01T09:00:05Z"},
)
OLD, NEW = '"20 dollars"', '"200 dollars"'


def _word(r) -> str:
    return V.VERIFIED if r.ok is True else (V.COULD_NOT_LOOK if r.ok is None else V.BROKEN)


def story(out=print) -> int:
    from arcaeon.record.ledger import Ledger, verify_file
    with tempfile.TemporaryDirectory(prefix="arcaeon-demo-") as d:
        path = Path(d) / "agent.jsonl"
        out("An agent does two things and writes each one down as it goes.")
        led = Ledger(path)
        for row in ROWS:
            led.append(dict(row))
        out("  line 1: it refunded 20 dollars on order 1001")
        out("  line 2: it emailed the customer to say the refund was sent")
        out("Each line carries a link that covers itself and every line before it.")
        out("")
        first = verify_file(path)
        out(f"Check the record: {_word(first)}, {first.rows} rows, every link holds.")
        out("")
        raw = path.read_text(encoding="utf-8")
        path.write_text(raw.replace(OLD, NEW, 1), encoding="utf-8")
        out("Now someone opens the file and changes one word on line 1:")
        out("  20 dollars becomes 200 dollars. Nothing else moves.")
        out("")
        second = verify_file(path)
        out("Check the record again. The link on line 1 no longer fits:")
        out(f"{_word(second)}: {second.first_break}")
    good = (_word(first) == V.VERIFIED and _word(second) == V.BROKEN
            and str(second.first_break or "").startswith("line 1:"))
    return V.EXIT_GOOD if good else V.EXIT_BAD


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(a in ("-h", "--help") for a in argv):
        print(USAGE)
        return V.EXIT_GOOD
    if argv:
        print(f"arcaeon demo: takes no arguments, got {argv[0]!r}\n{USAGE}", file=sys.stderr)
        return V.EXIT_USAGE
    return story()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
