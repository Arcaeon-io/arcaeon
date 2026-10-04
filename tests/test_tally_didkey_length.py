"""A hostile did:key cannot hang `arcaeon tally build` (review finding F4,
D072, stack side).

The same ~1 MB `did:key:z...` as a chain row's `counterparty` / `signer`, as a
groups member and as an alias key: each `tally build --json` runs in a child
process with a hard 5 s bound and must return a verdict, no traceback.
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
from arcaeon.prove import tally as T
from arcaeon.record.ledger import Ledger

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

SRC = str(Path(E.__file__).resolve().parents[2])
HOSTILE = "did:key:z" + "z" * 1_000_000
NOW_S = "2026-10-04T12:00:00Z"


def _cli_bounded(argv: list[str], tmp_path: Path, bound: float = 5.0) -> dict:
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


def _logs(tmp_path: Path, field: str | None = None):
    sa, da = _seed_and_did()
    sb, db = _seed_and_did()
    la, lb = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    Ledger(lb).append(X.build_row(seed=sb, exchange_id="ex-1", counterparty=da,
                                  file_sha256="0" * 64, reaction=V.VERIFIED))
    row = X.build_row(seed=sa, exchange_id="ex-1", counterparty=db,
                      file_sha256="0" * 64, reaction=V.VERIFIED)
    if field:
        row[field] = HOSTILE
    Ledger(la).append(row)
    return la, lb, da, db


@pytest.mark.parametrize("field", ["counterparty", "signer"])
def test_hostile_did_in_a_chain_row_tallies_to_a_verdict_in_under_a_second(tmp_path, field):
    la, lb, _, _ = _logs(tmp_path, field)
    out = _cli_bounded(["tally", "build", str(la), str(lb), "--now", NOW_S, "--json"], tmp_path)
    r = json.loads(out["out"])
    assert r["verdict"] in (V.BROKEN, V.COULD_NOT_LOOK), r["verdict"]
    assert out["rc"] != 0 and out["took"] < 1.0, out["took"]


def test_hostile_did_as_a_group_member_is_could_not_look_in_under_a_second(tmp_path):
    la, lb, da, _ = _logs(tmp_path)
    g = tmp_path / "groups.json"
    g.write_text(json.dumps({"groups": [{"name": "g", "members": [da, HOSTILE]}]}),
                 encoding="utf-8")
    out = _cli_bounded(["tally", "build", str(la), str(lb), "--now", NOW_S,
                        "--groups", str(g), "--json"], tmp_path)
    r = json.loads(out["out"])
    assert r["verdict"] == V.COULD_NOT_LOOK and out["took"] < 1.0, (r["verdict"], out["took"])


def test_hostile_did_as_an_alias_key_returns_a_verdict_in_under_a_second(tmp_path):
    la, lb, da, _ = _logs(tmp_path)
    a = tmp_path / "aliases.json"
    a.write_text(json.dumps({"aliases": [{"kind": T.ALIAS_KIND, "old": HOSTILE, "new": da,
                                          "at": NOW_S, "sig_old": "AA==",
                                          "sig_new": "AA=="}]}), encoding="utf-8")
    out = _cli_bounded(["tally", "build", str(la), str(lb), "--now", NOW_S,
                        "--aliases", str(a), "--json"], tmp_path)
    r = json.loads(out["out"])
    assert r["verdict"] in (V.VERIFIED, V.BROKEN, V.COULD_NOT_LOOK), r["verdict"]
    assert out["took"] < 1.0, out["took"]
    [rec] = r["aliases"]   # a malformed alias is not applied and says why
    assert rec["applied"] is False and "Ed25519 did:key" in rec["finding"], rec
