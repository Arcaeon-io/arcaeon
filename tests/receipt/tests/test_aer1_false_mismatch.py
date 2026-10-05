"""A01: `receipt verify` on an AER-1 receipt must not say "body digest mismatch".

An AER-1 receipt (a foreign format: result_sha256 / output_hash, no Arcaeon
receipt_version, no body_digest) was run through the Arcaeon body-digest
recompute, which compared a missing body_digest to the digest of seven None
fields and printed "body digest mismatch: a body field was altered after
issue". Nothing was altered; the verifier never read that format. The
fixture is SYNTHETIC (no real receipt, nothing downloaded).
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

from arcaeon.record.receipt import cli, verify_batch
from arcaeon.record.receipt.core import load_receipt, verify_receipt

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "aer1_synthetic.receipt.json"
EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "ballots"
MISMATCH = "body digest mismatch"


def _first_example() -> Path:
    return sorted(p for p in EXAMPLES.glob("*.receipt.json") if "anchored" not in p.name)[0]


def test_core_does_not_claim_alteration_on_aer1():
    res = verify_receipt(load_receipt(FIXTURE))
    assert not any(MISMATCH in n for n in res["notes"]), res["notes"]
    assert res["ok"] is False and res["body_digest_ok"] is False
    assert res.get("foreign_format") == "AER-1"
    assert any("not an Arcaeon receipt" in n for n in res["notes"]), res["notes"]


def test_cli_verify_aer1_prints_no_false_mismatch(capsys):
    rc = cli.main(["verify", str(FIXTURE)])
    out = capsys.readouterr().out
    assert MISMATCH not in out, out
    assert "AER-1" in out
    assert rc == 2  # still not ok: nothing was verified


def test_batch_aer1_is_could_not_look_not_broken(tmp_path):
    shutil.copy2(FIXTURE, tmp_path / FIXTURE.name)
    result = verify_batch.verify_batch([str(tmp_path)])
    row = result["rows"][0]
    assert MISMATCH not in row["reason"], row["reason"]
    assert row["verdict"] == verify_batch.UNDETERMINED
    assert verify_batch.exit_code(result) == 4


def test_tampered_arcaeon_receipt_still_says_mismatch(tmp_path):
    rc = json.loads(_first_example().read_text(encoding="utf-8"))
    rc["subject"] = {"tampered": True}
    res = verify_receipt(rc)
    assert any(MISMATCH in n for n in res["notes"]), res["notes"]
    assert "foreign_format" not in res


def test_both_stripped_arcaeon_receipt_still_says_mismatch():
    rc = json.loads(_first_example().read_text(encoding="utf-8"))
    del rc["receipt_version"], rc["body_digest"]
    res = verify_receipt(rc)
    assert res["ok"] is False and "foreign_format" not in res
    assert any(MISMATCH in n for n in res["notes"]), res["notes"]


def test_stripped_version_with_body_digest_still_says_mismatch():
    rc = json.loads(_first_example().read_text(encoding="utf-8"))
    del rc["receipt_version"]
    res = verify_receipt(rc)
    assert res["ok"] is False
    assert any(MISMATCH in n for n in res["notes"]), res["notes"]
