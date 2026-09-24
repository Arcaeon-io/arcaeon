"""python -m arcaeon.prove.continuity {selftest,calibration}"""
from __future__ import annotations

import sys


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "selftest":
        from . import selftest
        return selftest.run()
    if argv and argv[0] == "calibration":
        from . import calibration
        return calibration.main(argv[1:])
    print("usage: python -m arcaeon.prove.continuity {selftest,calibration}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
