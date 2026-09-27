# SPDX-License-Identifier: MIT
"""Tray stub (K110): the one thing a future tray icon does, and nothing else.

    py tools/tray/tray_stub.py --dry-run       print the command it would run, run nothing
    py tools/tray/tray_stub.py                 run `arcaeon open`
    py tools/tray/tray_stub.py --no-browser    run `arcaeon open --no-browser`

A planned `arcaeon[desktop]` extra would put an icon in the system tray whose
click opens the local dashboard. That click is exactly `arcaeon open` (K107):
find a running `arcaeon serve` on 127.0.0.1 or start one, then open the
browser with a one-time sign-in code. This stub is that click, as a script.

It draws no icon, imports no GUI toolkit, reads no token and opens no socket
of its own: every read goes through `arcaeon open`, which goes through the
local server's token and fence. It is not packaged: it lives in tools/, which
the wheel leaves out (MANIFEST.in prunes tools; `py tools/release_check.py
--offline` prints the `tools not in wheel` line). See tools/tray/README.md.

Exit codes: whatever `arcaeon open` returns (0 opened or printed, 2 bad
usage, 3 COULD NOT LOOK); 0 for --dry-run.
"""
from __future__ import annotations

import argparse
import subprocess
import sys


def command(no_browser: bool = False) -> list[str]:
    """The argv the tray click runs: this interpreter's `arcaeon open`."""
    argv = [sys.executable, "-m", "arcaeon", "open"]
    if no_browser:
        argv.append("--no-browser")
    return argv


def _quote(arg: str) -> str:
    return f'"{arg}"' if (" " in arg or not arg) else arg


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="tray_stub.py",
        description="The tray icon's click, as a script: runs `arcaeon open`. Not packaged.")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the command it would run and exit 0; runs nothing")
    ap.add_argument("--no-browser", action="store_true",
                    help="pass --no-browser to `arcaeon open` (print the link, open nothing)")
    a = ap.parse_args(argv)
    cmd = command(a.no_browser)
    if a.dry_run:
        print("would run: " + " ".join(_quote(c) for c in cmd))
        print("nothing was run (dry run)")
        return 0
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
