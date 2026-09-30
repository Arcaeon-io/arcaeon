# SPDX-License-Identifier: MIT
"""gate_drift's two private gates degrade to NO COVERAGE without the private checkout.

Their matcher lives in a private repo's bridge/witness/seal_chain.py, which is
not shipped in arcaeon. With a corpus present (a source checkout) or passed
in, check_gate used to reach the lazy `from bridge.witness import ...` and
raise ImportError, and the CLI died on it, taking every other gate's report
with it. Each check runs in a fresh interpreter from an empty directory with
only arcaeon's src on the path, so no `bridge` package can be found.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

SRC = str(Path(__file__).resolve().parents[2] / "src")
PRIVATE_GATES = ("seal_chain.publishable_event", "seal_chain.publishable_path_key")

_PROBE = r"""
import contextlib, io, json, sys
from arcaeon.prove.vet import gate_drift as G
out = {"reports": {}}
for name in sys.argv[1].split(","):
    r = G.check_gate(name, corpus=["checked", "not-a-real-event"])
    out["reports"][name] = [r.status, r.message]
    u = G.update_baseline_from_corpus(name)
    out["reports"][name + ":update"] = [u.status, u.message]
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    out["cli_exit"] = G.main([])
out["cli"] = buf.getvalue()
out["bridge_loaded"] = any(m == "bridge" or m.startswith("bridge.") for m in sys.modules)
print(json.dumps(out))
"""


def _run(tmp_path, private_root=None):
    env = {k: v for k, v in os.environ.items() if k != "ARCAEON_VET_PRIVATE_ROOT"}
    env["PYTHONPATH"] = SRC
    if private_root is not None:
        env["ARCAEON_VET_PRIVATE_ROOT"] = str(private_root)
    p = subprocess.run([sys.executable, "-c", _PROBE, ",".join(PRIVATE_GATES)],
                       capture_output=True, text=True, env=env, cwd=str(tmp_path),
                       timeout=120)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout.strip().splitlines()[-1])


def _assert_no_coverage(out):
    assert out["bridge_loaded"] is False
    for key, (status, message) in out["reports"].items():
        assert status == "no_coverage", (key, status, message)
        assert "COULD NOT LOOK" in message, (key, message)
    # every gate still reports; the private ones say why, none crashes the run
    for name in PRIVATE_GATES:
        assert f"[NO_COVERAGE] {name}: " in out["cli"]
    assert "checks.secret_public_prefix_exemption" in out["cli"]
    assert out["cli_exit"] == 2


def test_private_gates_without_env_report_no_coverage(tmp_path):
    _assert_no_coverage(_run(tmp_path))


def test_private_gates_with_env_but_no_bridge_report_no_coverage(tmp_path):
    empty = tmp_path / "not_a_private_checkout"
    empty.mkdir()
    _assert_no_coverage(_run(tmp_path, private_root=empty))
