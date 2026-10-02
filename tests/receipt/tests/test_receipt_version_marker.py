"""A receipt is ours by EITHER marker: receipt_version arcaeon-receipt/* or a
body_digest string starting sha256:json-c14n:v1: (the same two markers the
web verifier's detect.js checks).

Before this, not_our_format looked only at receipt_version, so deleting or
rewriting that one field on a genuine receipt turned a tampered receipt into
COULD NOT LOOK name_not_found (exit 3/4) instead of BROKEN (exit 1/2). Editing
a field away must never move a receipt out of the check it failed.

  (a) receipt_version deleted, body_digest kept           -> BROKEN
  (b) receipt_version replaced with a foreign string      -> BROKEN
  (c) a truly foreign object (neither marker)             -> COULD NOT LOOK
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from arcaeon import cli as ARC
from arcaeon import verdict as V
from arcaeon.record.receipt import cli as RCLI
from arcaeon.record.receipt import core, verify_batch
from arcaeon.record.receipt.verify_batch import FAIL, UNDETERMINED


@pytest.fixture(autouse=True)
def _no_hosted_witness(monkeypatch):
    monkeypatch.delenv("ARCAEON_WITNESS_URL", raising=False)
    monkeypatch.delenv("ARCAEON_WITNESS_KEY", raising=False)


def _honest(tmp: Path) -> dict:
    rc = core.build_receipt(
        "conformance", {"trainee": "t. a", "scenario": "s1"},
        [{"name": "c1", "score": 88, "verdict": "PASS"}],
        {"proves": ["the grader returned these scores"],
         "does_not_prove": ["the scores are correct"]},
        ledger_path=tmp / "shared.ledger.jsonl", namespace="conf",
        witness=False, anchor=False, issued_at="2026-09-22T12:00:00Z")
    assert core.verify_receipt(rc)["ok"] is True
    assert rc["body_digest"].startswith("sha256:json-c14n:v1:")
    return rc


def _deleted(rc):
    del rc["receipt_version"]
    return rc


def _foreign_string(rc):
    rc["receipt_version"] = "otherco-receipt/2"
    return rc


EDITS = {"version_deleted": _deleted, "version_foreign_string": _foreign_string}


@pytest.mark.parametrize("edit", list(EDITS), ids=list(EDITS))
def test_ours_with_version_edited_is_broken(edit, tmp_path, capsys):
    rc = EDITS[edit](_honest(tmp_path))
    assert core.not_our_format(rc) is None

    res = core.verify_receipt(rc)
    assert res["ok"] is False
    assert "not_arcaeon_receipt" not in res
    assert any("body digest mismatch" in n for n in res["notes"])

    p = tmp_path / "r.receipt.json"
    p.write_text(json.dumps(rc), encoding="utf-8")
    assert RCLI.main(["verify", str(p)]) == 2
    err = capsys.readouterr().err
    assert err.startswith(f"{V.BROKEN}: {p} -- ") and "COULD NOT LOOK" not in err

    assert ARC.main(["receipt", "verify", str(p)]) == V.EXIT_BAD == 1
    out = capsys.readouterr().out
    assert json.loads(out)["verdict"] == "BROKEN"

    row = verify_batch.verify_one(p)
    assert row["verdict"] == FAIL != UNDETERMINED


def test_truly_foreign_object_is_still_could_not_look(tmp_path, capsys):
    obj = {"receipt_version": "otherco-receipt/2", "kind": "x",
           "body_digest": "sha256:" + "0" * 64, "payload": {"amount": 5}}
    reason = core.not_our_format(obj)
    assert reason and reason.startswith("not an Arcaeon receipt: receipt_version")

    res = core.verify_receipt(obj)
    assert res["ok"] is False and res["not_arcaeon_receipt"] == reason

    p = tmp_path / "vendor.receipt.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    assert RCLI.main(["verify", str(p)]) == 4
    assert ARC.main(["receipt", "verify", str(p)]) == V.EXIT_COULD_NOT_LOOK == 3
    capsys.readouterr()
    assert verify_batch.verify_one(p)["verdict"] == UNDETERMINED


@pytest.mark.parametrize("bd", [None, 42, "", "sha256:json-c14n:v2:" + "0" * 64,
                                "SHA256:JSON-C14N:V1:" + "0" * 64])
def test_body_digest_marker_matches_detect_js_exactly(bd):
    # detect.js: typeof body_digest === "string" && indexOf("sha256:json-c14n:v1:") === 0
    assert core.not_our_format({"body_digest": bd}) is not None
    assert core.not_our_format({"body_digest": "sha256:json-c14n:v1:"}) is None
