"""policies/ (the OPA/Rego gate policy, D053) ships in the sdist.

docs/OPA.md tells a reader to run `opa eval --data policies/opa/arcaeon_gate.rego`.
No Python code loads the policy, so it is not package data and the wheel does
not carry it; the sdist is the download that holds the source tree, so it must.
Before this test the MANIFEST.in had no rule for policies/ and setuptools left
it out (the D053 gap).

The build runs with --no-isolation: it uses the setuptools already installed and
fetches nothing from the network.
"""
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
POLICIES = ROOT / "policies"

pytest.importorskip("build")


def _sdist_names() -> list[str]:
    with tempfile.TemporaryDirectory() as td:
        subprocess.run([sys.executable, "-m", "build", "--sdist", "--no-isolation",
                        "--outdir", td], cwd=ROOT, check=True, capture_output=True)
        tars = list(Path(td).glob("*.tar.gz"))
        assert tars, "no sdist produced"
        with tarfile.open(tars[0]) as tf:
            return [m.name.split("/", 1)[1] for m in tf.getmembers()
                    if m.isfile() and "/" in m.name]


def test_every_policy_file_ships_in_the_sdist():
    repo = sorted(p.relative_to(ROOT).as_posix() for p in POLICIES.rglob("*") if p.is_file())
    assert "policies/opa/arcaeon_gate.rego" in repo
    shipped = set(_sdist_names())
    missing = [p for p in repo if p not in shipped]
    assert not missing, f"sdist is missing policy files: {missing}"
