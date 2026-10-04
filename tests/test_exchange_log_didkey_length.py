"""A hostile did:key in an exchange log cannot hang `arcaeon exchange pair`
(review finding F4, D072, stack side).

`counterparty` and `signer` are read through envelope._pubkey_from_did; a ~1 MB
`did:key:z...` used to pin a core in the quadratic base58 decode. Each case runs
`arcaeon exchange pair --json` in a child process with a hard 5 s bound.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from arcaeon import verdict as V
from arcaeon.prove import envelope as E
from arcaeon.prove import exchange_log as X
from arcaeon.record.ledger import Ledger

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

SRC = str(Path(E.__file__).resolve().parents[2])
HOSTILE = "did:key:z" + "z" * 1_000_000


def _cli_bounded(argv: list[str], tmp_path: Path, bound: float = 5.0) -> dict:
    """`arcaeon <argv>` in a fresh interpreter; returns {rc, out, took}. Fails
    (never hangs) if still running after `bound` seconds; no traceback allowed."""
    script = tmp_path / "child.py"
    script.write_text(textwrap.dedent(f"""
        import contextlib, io, json, time
        from arcaeon import cli
        buf = io.StringIO()
        t0 = time.monotonic()
        with contextlib.redirect_stdout(buf):
            rc = cli.main({argv!r})
        print(json.dumps({{"rc": rc, "out": buf.getvalue(), "took": time.monotonic() - t0}}))
    """), encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": SRC + os.pathsep + os.environ.get("PYTHONPATH", ""),
           "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        p = subprocess.run([sys.executable, str(script)], capture_output=True, text=True,
                           timeout=bound, env=env, cwd=str(tmp_path))
    except subprocess.TimeoutExpired:
        pytest.fail(f"still decoding after {bound} s (hang on a hostile did:key)")
    assert p.returncode == 0 and "Traceback" not in p.stderr, p.stderr
    return json.loads(p.stdout.strip().splitlines()[-1])


def _seed_and_did():
    from arcaeon.prove.vet import receipts as R
    seed = secrets.token_bytes(32)
    return seed, R.did_key(R.public_key_from_seed(seed))


@pytest.mark.parametrize("field", ["counterparty", "signer"])
def test_hostile_did_in_a_log_row_pairs_to_a_verdict_in_under_a_second(tmp_path, field):
    sa, da = _seed_and_did()
    sb, db = _seed_and_did()
    la, lb = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    Ledger(lb).append(X.build_row(seed=sb, exchange_id="ex-1", counterparty=da,
                                  file_sha256="0" * 64, reaction=V.VERIFIED))
    row = X.build_row(seed=sa, exchange_id="ex-1", counterparty=db,
                      file_sha256="0" * 64, reaction=V.VERIFIED)
    row[field] = HOSTILE
    Ledger(la).append(row)
    out = _cli_bounded(["exchange", "pair", str(la), str(lb), "--owner-a", da, "--json"],
                       tmp_path)
    r = json.loads(out["out"])
    assert r["verdict"] in (V.BROKEN, V.COULD_NOT_LOOK), r["verdict"]
    assert out["rc"] != 0 and out["took"] < 1.0, out["took"]


def test_hostile_owner_flag_is_refused_in_under_a_second(tmp_path):
    la, lb = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    Ledger(la).append({"kind": X.KIND})
    Ledger(lb).append({"kind": X.KIND})
    out = _cli_bounded(["exchange", "pair", str(la), str(lb), "--owner-a", HOSTILE, "--json"],
                       tmp_path)
    assert out["rc"] == V.EXIT_USAGE and out["took"] < 1.0, (out["rc"], out["took"])


def test_hostile_owner_via_the_api_is_could_not_look_in_under_a_second(tmp_path):
    la, lb = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    Ledger(la).append({"kind": X.KIND})
    Ledger(lb).append({"kind": X.KIND})
    script = tmp_path / "api.py"
    script.write_text(textwrap.dedent(f"""
        import json, time
        from arcaeon.prove import exchange_log as X
        t0 = time.monotonic()
        r = X.pair({str(la)!r}, {str(lb)!r}, owner_a="did:key:z" + "z" * 1_000_000)
        print(json.dumps({{"verdict": r["verdict"], "took": time.monotonic() - t0}}))
    """), encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": SRC + os.pathsep + os.environ.get("PYTHONPATH", ""),
           "PYTHONDONTWRITEBYTECODE": "1"}
    try:
        p = subprocess.run([sys.executable, str(script)], capture_output=True, text=True,
                           timeout=5.0, env=env, cwd=str(tmp_path))
    except subprocess.TimeoutExpired:
        pytest.fail("still decoding after 5 s (hang on a hostile --owner-a)")
    assert p.returncode == 0 and "Traceback" not in p.stderr, p.stderr
    r = json.loads(p.stdout.strip().splitlines()[-1])
    assert r["verdict"] == V.COULD_NOT_LOOK and r["took"] < 1.0, r
