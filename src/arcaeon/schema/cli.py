# SPDX-License-Identifier: MIT
"""`arcaeon schema --format openapi [--out FILE]` (K013).

Prints the OpenAPI 3.1 document `arcaeon serve` answers at /openapi.json,
built from the same route table, so the two are the same document. `--out`
writes it to a file instead (UTF-8, LF), the way docs/openapi.json is made.

Exit codes: 0 printed or written, 2 bad usage, 3 the file could not be written.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from arcaeon import verdict as V

FORMATS = ("openapi",)


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="arcaeon schema",
        description="Print the local HTTP API as an OpenAPI 3.1 document (the one "
                    "`arcaeon serve` answers at /openapi.json).")
    ap.add_argument("--format", choices=FORMATS, default="openapi",
                    help="openapi (the default and, for now, the only one)")
    ap.add_argument("--out", default=None, metavar="FILE",
                    help="write the document to FILE instead of printing it")
    return ap


def main(argv: list[str] | None = None) -> int:
    try:
        a = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else V.EXIT_USAGE
    from arcaeon.serve import openapi
    text = openapi.dumps()
    if a.out:
        try:
            Path(a.out).write_bytes(text.encode("utf-8"))
        except OSError as e:
            print(f"arcaeon schema: cannot write {a.out} ({e.strerror or type(e).__name__})",
                  file=sys.stderr)
            return V.EXIT_COULD_NOT_LOOK
        print(f"arcaeon schema: wrote {a.out}", file=sys.stderr)
        return V.EXIT_GOOD
    sys.stdout.write(text)
    return V.EXIT_GOOD
