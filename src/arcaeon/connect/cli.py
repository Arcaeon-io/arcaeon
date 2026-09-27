# SPDX-License-Identifier: MIT
"""`arcaeon connect`: list the clients it knows (K018)."""
from __future__ import annotations

import json
import sys

from arcaeon import verdict as V
from arcaeon.connect import catalog as C

USAGE = "usage: arcaeon connect --list [--json]"


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(a in ("-h", "--help") for a in argv):
        print(USAGE)
        return V.EXIT_GOOD
    if "--list" in argv:
        extra = [a for a in argv if a not in ("--list", "--json")]
        if extra:
            print(f"arcaeon connect: --list takes no {extra[0]!r}\n{USAGE}", file=sys.stderr)
            return V.EXIT_USAGE
        if "--json" in argv:
            print(json.dumps({"os": C.current_os(), "clients": C.list_rows()}, indent=1))
        else:
            print(C.render_list())
        return V.EXIT_GOOD
    print(f"arcaeon connect: printing a client's config is not built in this checkout "
          f"(K019)\n{USAGE}", file=sys.stderr)
    return V.EXIT_USAGE
