"""h_core (K003): each handler returns what the CLI prints, key for key, with
the CLI's exit code as `exit`. The CLI side runs as a real subprocess,
`py -m arcaeon <verb> ...`, so the two share nothing but the code."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from arcaeon.serve import h_core as H

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def env(tmp_path, monkeypatch):
    home = tmp_path / "arcaeon-home"
    home.mkdir()
    monkeypatch.setenv("ARCAEON_HOME", str(home))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    return dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONIOENCODING="utf-8")


def cli(env, *args) -> tuple[int, str]:
    p = subprocess.run([sys.executable, "-m", "arcaeon", *args], capture_output=True,
                       text=True, encoding="utf-8", errors="replace", env=env,
                       cwd=os.getcwd(), timeout=120)
    return p.returncode, p.stdout


def cli_json(env, *args) -> dict:
    rc, out = cli(env, *args)
    return {**json.loads(out), "exit": rc}


def _ledger(path: Path, n: int = 2) -> Path:
    for i in range(n):
        assert H.log({"ledger": str(path), "fields": {"i": i}})["exit"] == 0
    return path


def _tamper(path: Path) -> Path:
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace('"i": 0', '"i": 9')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


# --- verify -----------------------------------------------------------------

def test_verify_good_ledger_matches_the_cli(env, tmp_path):
    led = _ledger(tmp_path / "good.jsonl")
    got = H.verify({"ledger": str(led)})
    want = cli_json(env, "verify", str(led))
    assert got == want
    assert got["verdict"] == "VERIFIED" and got["exit"] == 0


def test_verify_tampered_ledger_matches_the_cli(env, tmp_path):
    led = _tamper(_ledger(tmp_path / "bad.jsonl"))
    got = H.verify({"ledger": str(led)})
    assert got == cli_json(env, "verify", str(led))
    assert got["verdict"] == "BROKEN" and got["exit"] == 1


def test_verify_missing_file_matches_the_cli(env, tmp_path):
    missing = str(tmp_path / "nope.jsonl")
    got = H.verify({"ledger": missing})
    assert got == cli_json(env, "verify", missing)
    assert got["exit"] == 3 and got["reason_word"] == "missing"


def test_verify_strict_matches_the_cli(env, tmp_path):
    led = _ledger(tmp_path / "s.jsonl")
    assert H.verify({"ledger": str(led), "strict": True}) == cli_json(
        env, "verify", str(led), "--strict")


# --- log --------------------------------------------------------------------

def test_log_returns_the_chain_the_cli_would_print_and_writes_the_same_row(env, tmp_path):
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    got = H.log({"ledger": str(a), "row": {"x": 1}, "fields": {"y": "2"}})
    rc, out = cli(env, "log", str(b), '{"x": 1}', "--field", "y=2")
    assert got["exit"] == rc == 0
    assert set(got) == {"chain", "exit"}
    row_a = json.loads(a.read_text(encoding="utf-8").splitlines()[-1])
    row_b = json.loads(b.read_text(encoding="utf-8").splitlines()[-1])
    assert got["chain"] == row_a["chain"] and out.strip() == row_b["chain"]
    strip = lambda r: {k: v for k, v in r.items() if k not in ("ts", "chain")}  # noqa: E731
    assert strip(row_a) == strip(row_b) == {"x": 1, "y": "2"}


def test_log_refusal_matches_the_cli_exit(env, tmp_path):
    bad = tmp_path / "bin.jsonl"
    bad.write_bytes(b"\xff\xfe\x00junk\n")
    got = H.log({"ledger": str(bad), "fields": {"a": "1"}})
    rc, out = cli(env, "log", str(bad), "--field", "a=1")
    assert got["exit"] == rc == 3
    assert {k: v for k, v in got.items() if k != "exit"} == json.loads(out)


# --- reconcile --------------------------------------------------------------

def test_reconcile_matches_the_cli(env, tmp_path):
    a = _ledger(tmp_path / "ta.jsonl")
    b = _ledger(tmp_path / "tb.jsonl")
    got = H.reconcile({"tape_a": str(a), "tape_b": str(b)})
    assert got == cli_json(env, "reconcile", str(a), str(b))
    assert got["exit"] == 3


def test_reconcile_missing_tape_matches_the_cli(env, tmp_path):
    a = _ledger(tmp_path / "ta.jsonl")
    missing = str(tmp_path / "gone.jsonl")
    got = H.reconcile({"tape_a": str(a), "tape_b": missing})
    assert got == cli_json(env, "reconcile", str(a), missing)
    assert got["exit"] == 3


# --- audit verify, receipt verify, status -----------------------------------

@pytest.mark.parametrize("tampered", [False, True])
def test_audit_verify_matches_the_cli(env, tmp_path, tampered):
    led = _ledger(tmp_path / "audit.jsonl")
    if tampered:
        _tamper(led)
    got = H.audit_verify({"path": str(led)})
    rc, out = cli(env, "audit", "verify", str(led))
    assert got["exit"] == rc
    assert got["output"] == out.rstrip("\n")
    assert rc == (1 if tampered else 0)


def _receipt(env, tmp_path) -> Path:
    ballot = tmp_path / "ballot.json"
    ballot.write_text('{"score": 90}', encoding="utf-8")
    out = tmp_path / "rec.json"
    rc, _ = cli(env, "receipt", "ballot", str(ballot), "--trainee", "t1", "--scenario", "s1",
                "--no-anchor", "--no-witness", "--ledger", str(tmp_path / "r.jsonl"),
                "--out", str(out), "--timestamp", "2026-09-27T00:00:00Z")
    assert rc == 0 and out.is_file()
    return out


def test_receipt_verify_matches_the_cli(env, tmp_path):
    rec = _receipt(env, tmp_path)
    got = H.receipt_verify({"receipt": str(rec)})
    assert got == cli_json(env, "receipt", "verify", str(rec))
    assert got["exit"] == 0 and got["body_digest_ok"] is True


def test_receipt_verify_edited_body_matches_the_cli(env, tmp_path):
    rec = _receipt(env, tmp_path)
    text = rec.read_text(encoding="utf-8")
    assert '"score": 90' in text
    rec.write_text(text.replace('"score": 90', '"score": 99'), encoding="utf-8")
    got = H.receipt_verify({"receipt": str(rec)})
    assert got == cli_json(env, "receipt", "verify", str(rec))
    assert got["exit"] != 0


def test_status_matches_the_cli(env):
    got = H.status({})
    assert got == cli_json(env, "status", "--json")
    assert got["exit"] == 0


# --- usage and the front-door rule --------------------------------------------

@pytest.mark.parametrize("fn,body,field", [
    (H.verify, {}, "ledger"), (H.log, {"fields": {}}, "ledger"),
    (H.reconcile, {"tape_a": "a"}, "tape_b"), (H.audit_verify, {}, "path"),
    (H.receipt_verify, {}, "receipt"),
])
def test_missing_field_is_usage_2_naming_it(fn, body, field):
    got = fn(body)
    assert got["exit"] == 2 and f"'{field}'" in got["error"]


def test_a_non_object_body_is_usage_2():
    assert H.verify(["x"])["exit"] == 2


def test_a_verb_that_raises_is_could_not_look_naming_the_class(monkeypatch):
    from arcaeon import cli as C

    def boom(argv):
        raise RuntimeError("secret path /srv/private/x")
    monkeypatch.setitem(C.HANDLERS, "verify", boom)
    got = H.verify({"ledger": "x.jsonl"})
    assert got["exit"] == 3
    assert "RuntimeError" in got["error"] and "secret" not in got["error"]


def test_h_core_does_not_journal(env, tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_JOURNAL", "1")
    led = _ledger(tmp_path / "j.jsonl")
    H.verify({"ledger": str(led)})
    assert not any((tmp_path / "arcaeon-home").iterdir())
