"""arcaeon once -- inspect a key's receipt, reclaim one crashed key, or
rebuild the concurrency index.

    arcaeon once receipt ops.log.jsonl "refund:pi_123"
    arcaeon once reclaim ops.log.jsonl "refund:pi_123"
    arcaeon once rebuild-index ops.log.jsonl

`reclaim` frees ONE crashed key for retry, and only after proving its
recorded holder process is dead -- no quiesce needed, live claims are never
touched. It refuses loudly (nonzero exit) when the holder is alive or its
liveness cannot be determined; the refusal message names the fallback
(quiesce -> rebuild-index).

Exit code 0 = command ran (receipt may still show state="never" or a broken
ledger -- that's information, not a CLI failure). Nonzero = bad usage, a
ledger that failed to verify when `receipt` was asked to check it, or a
`reclaim` that refused.
"""
from __future__ import annotations

import json
import sys

from arcaeon.record.once import (
    HolderAlive, LivenessUnknown, rebuild_index, receipt, reclaim,
)


def main(argv: "list[str] | None" = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2 or argv[0] not in ("receipt", "reclaim", "rebuild-index"):
        print((__doc__ or "usage: arcaeon once receipt|reclaim|rebuild-index <ledger> [key]").strip())
        return 1
    cmd, path = argv[0], argv[1]
    if cmd == "receipt":
        if len(argv) < 3:
            print("receipt needs a key argument")
            return 1
        r = receipt(argv[2], ledger_path=path)
        print(json.dumps(r.to_dict(), indent=1, default=str))
        # `is True`, not truthiness: a bounded verdict (ok=None) is not
        # a clean bill of health and must not exit 0.
        return 0 if r.ledger_ok is True else 1
    if cmd == "reclaim":
        if len(argv) < 3:
            print("reclaim needs a key argument")
            return 1
        try:
            r = reclaim(argv[2], ledger_path=path)
        except (HolderAlive, LivenessUnknown, ValueError) as e:
            print(json.dumps({"reclaimed": False,
                              "refusal": type(e).__name__,
                              "detail": str(e)}, indent=1))
            return 1
        print(json.dumps({"reclaimed": True, "receipt": r.to_dict()},
                         indent=1, default=str))
        return 0
    # rebuild-index
    n = rebuild_index(path)
    print(json.dumps({"keys_indexed": n}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
