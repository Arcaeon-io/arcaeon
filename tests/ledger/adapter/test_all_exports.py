# SPDX-License-Identifier: MIT
"""Every name in arcaeon.record.adapter.__all__ resolves, and the star import works.

main, relay and run are provided lazily by the package's PEP 562 __getattr__,
so a static checker reports them as missing. This pins that they are really
there, in a fresh interpreter, and that a plain import still leaves proxy
unloaded (the reason they are lazy).
"""
import json
import os
import subprocess
import sys
from pathlib import Path

SRC = str(Path(__file__).resolve().parents[3] / "src")

_PROBE = r"""
import json, sys
import arcaeon.record.adapter as A
lazy_before = "arcaeon.record.adapter.proxy" in sys.modules
ns = {}
exec("from arcaeon.record.adapter import *", ns)
missing = [n for n in A.__all__ if n not in ns]
print(json.dumps({"lazy_before": lazy_before, "missing": missing,
                  "callable": [n for n in ("main", "relay", "run") if callable(ns.get(n))]}))
"""


def test_star_import_resolves_every_all_name():
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC
    p = subprocess.run([sys.executable, "-W", "error", "-c", _PROBE],
                       capture_output=True, text=True, env=env, timeout=120)
    assert p.returncode == 0, p.stderr
    out = json.loads(p.stdout.strip().splitlines()[-1])
    assert out["missing"] == []
    assert out["callable"] == ["main", "relay", "run"]
    assert out["lazy_before"] is False
