# SPDX-License-Identifier: MIT
"""Genuine false yeses the 2026-10-10 must-fail pass found in the REAL code.

Each test states what the code should answer and fails today, so each is a
strict expected failure: the suite stays green while the bug stands, and the
day the code is fixed the XPASS turns the suite red until the mark is removed.
The claim each one breaks is quoted in its reason, and named in its function
name. Nothing under src/ was changed by this pass.
"""
import json

import pytest

from arcaeon import cli
from arcaeon.record.ledger import Ledger, WitnessStore, publish_head, verify_against_witness


@pytest.mark.xfail(strict=True, reason=(
    "GENUINE FALSE YES. docs/VERBS.md, verify: 'Answers: has this ledger been "
    "changed since it was written?' and '`--witness PINS` compares against a local "
    "pin file'. The comparison is a row count only (cli._verify reads "
    "rows_since_pin, never the pinned chain), so a ledger re-minted after its pin "
    "with the same number of rows is VERIFIED, exit 0, while the library's own "
    "verify_against_witness on the same two files says 'rewritten'."))
def test_claim_verify_witness_compares_against_a_local_pin_file_reminted_ledger_is_not_verified(
        tmp_path, capsys):
    p, w = tmp_path / "a.jsonl", tmp_path / "pins.jsonl"
    for i in range(3):
        cli.main(["log", str(p), json.dumps({"op": i})])
    assert cli.main(["pin", str(p), "--ns", "demo", "--witness", str(w)]) == 0
    p.unlink()                                   # re-mint from genesis, one value changed
    for i in range(3):
        Ledger(p).append({"op": 99 if i == 1 else i})
    assert verify_against_witness(WitnessStore(w), "demo", Ledger(p)).verdict == "rewritten"
    capsys.readouterr()
    rc = cli.main(["verify", str(p), "--witness", str(w)])
    j = json.loads(capsys.readouterr().out)
    assert rc != 0 and j["verdict"] != "VERIFIED"


@pytest.mark.xfail(strict=True, reason=(
    "GENUINE FALSE YES. arcaeon/record/row.py, DuplicateKeyError: 'the line means "
    "two different things to two honest readers. A verifier must not pick one and "
    "say green.' WitnessStore.verify() reads pins with json.loads (last wins), so "
    "a pin line carrying `rows` twice verifies ok=True (truthy) and "
    "verify_against_witness answers 'consistent' over it. `arcaeon pin` and "
    "`arcaeon verify --witness` refuse the same file (cli._witness_file_problem "
    "reads it strictly); the library verifier, audit export and evidence-pack "
    "pin checks do not."))
def test_claim_a_verifier_must_not_pick_one_and_say_green_witness_pin_with_duplicate_key(tmp_path):
    log, pins = tmp_path / "a.jsonl", tmp_path / "pins.jsonl"
    for i in range(5):
        Ledger(log).append({"op": i})
    store = WitnessStore(pins)
    publish_head(store, "demo", Ledger(log))
    line = pins.read_text(encoding="utf-8").strip()
    dup = line.replace('"rows": 5', '"rows": 2, "rows": 5', 1)   # first-wins reads 2
    assert dup != line
    pins.write_text(dup + "\n", encoding="utf-8")
    v = store.verify()
    assert v["ok"] is not True and not v


@pytest.mark.xfail(strict=True, reason=(
    "GENUINE FALSE YES. arcaeon/remote/__init__.py _result sets "
    "'\"ok\": 200 <= status < 300' and then out.update(payload), so a refusal "
    "status whose JSON body says ok:true is reported ok. `arcaeon stamp` on a "
    "503 {\"ok\": true} answer prints it as a stamp and exits 0. The same order "
    "is in arcaeon/remote/witness.py _write ('\"ok\": status in (200, 201)'), "
    "which `pin --remote` and `seal` read."))
def test_claim_ok_is_200_le_status_lt_300_a_503_with_ok_true_body_is_not_a_stamp(
        tmp_path, monkeypatch, capsys):
    import arcaeon.remote as R
    monkeypatch.setattr(R, "_request", lambda *a, **k: (503, {"ok": True}))
    f = tmp_path / "f.txt"
    f.write_text("hello", encoding="utf-8")
    rc = cli.main(["stamp", str(f)])
    out = json.loads(capsys.readouterr().out)
    assert rc != 0 and out["ok"] is not True


@pytest.mark.xfail(strict=True, reason=(
    "GENUINE FALSE YES, same order as above in arcaeon/remote/witness.py _write: "
    "'\"ok\": status in (200, 201)' then out.update(payload). A 403 refusal whose "
    "body says ok:true reads as a recorded pin."))
def test_claim_ok_is_status_in_200_201_a_403_with_ok_true_body_is_not_a_pin(monkeypatch):
    import arcaeon.remote.witness as RW
    monkeypatch.setattr(RW, "_http_post", lambda url, body, key, timeout=30: (403, {"ok": True}))
    assert RW.pin("ns", 1, "c" * 32, "key")["ok"] is not True
