"""`receipt verify` says COULD NOT LOOK, loudly, when the file is not ours.

Three cases the verifier used to get wrong, each now COULD NOT LOOK with a
one-line reason and its own exit code (3 through `arcaeon receipt`, 4 from
the direct `arcaeon-receipt` entry), never BROKEN and never a traceback:

  1. another vendor's JSON (no receipt_version): "not an Arcaeon receipt:
     missing <field>", not "body digest mismatch";
  2. a JSONL file (one receipt per line): "JSONL is not supported; pass one
     receipt per file", not a JSONDecodeError;
  3. a JSONL file with a malformed line, and plain unparseable text.

BROKEN stays reserved for a file that IS our format and fails its check.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from arcaeon import cli as ARC
from arcaeon import verdict as V
from arcaeon.record.receipt import cli as RCLI
from arcaeon.record.receipt import core, verify_batch
from arcaeon.record.receipt.verify_batch import FAIL, UNDETERMINED

FIX = Path(__file__).parent / "fixtures" / "universal"
VALID = FIX / "arc_valid.json"
TAMPERED = FIX / "arc_tampered_payload.json"

FOREIGN = {"id": "rcpt_123", "vendor": "OtherCo", "issued": "2026-09-01T00:00:00Z",
           "signature": "abc", "payload": {"amount": 5}}


def _front(argv, capsys):
    rc = ARC.main(["receipt", "verify", *argv])
    out = capsys.readouterr()
    return rc, out.out, out.err


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# --- 1. a foreign format ---------------------------------------------------

def test_foreign_json_is_could_not_look_not_broken(tmp_path, capsys):
    p = _write(tmp_path, "vendor.json", json.dumps(FOREIGN, indent=2))
    rc, out, err = _front([str(p)], capsys)
    assert rc == V.EXIT_COULD_NOT_LOOK == 3
    assert "digest mismatch" not in out + err and "BROKEN" not in out + err
    lines = err.strip().splitlines()
    assert lines == [f"COULD NOT LOOK: {p} -- not an Arcaeon receipt: missing "
                     "receipt_version, kind, issued_at, subject, checks, scope, extra, "
                     "body_digest"]
    rep = json.loads(out)
    assert rep["verdict"] == "COULD NOT LOOK" and rep["ok"] is False
    assert rep["reason"].startswith("not an Arcaeon receipt: missing receipt_version")
    assert rep["reason_word"] == "name_not_found"


def test_foreign_version_string_is_could_not_look(tmp_path, capsys):
    p = _write(tmp_path, "v.json", json.dumps({"receipt_version": "otherco-receipt/2",
                                               "body_digest": "x"}))
    rc, _, err = _front([str(p)], capsys)
    assert rc == 3 and "not an Arcaeon receipt: receipt_version" in err


def test_our_format_tampered_is_still_broken(tmp_path, capsys):
    rc, out, err = _front([str(TAMPERED)], capsys)
    assert rc == V.EXIT_BAD == 1
    assert err.startswith(f"BROKEN: {TAMPERED} -- body digest mismatch")
    assert json.loads(out)["verdict"] == "BROKEN"


def test_our_format_valid_is_verified_same_line_shape(tmp_path, capsys):
    rc, out, err = _front([str(VALID)], capsys)
    assert rc == 0
    assert err.strip() == f"VERIFIED: {VALID}"
    rep = json.loads(out)
    assert rep["verdict"] == "VERIFIED" and rep["ok"] is True


def test_core_does_not_say_digest_mismatch_for_foreign():
    res = core.verify_receipt(dict(FOREIGN))
    assert res["ok"] is False
    assert res["not_arcaeon_receipt"].startswith("not an Arcaeon receipt: missing")
    assert not any("digest mismatch" in n for n in res["notes"])


def test_batch_foreign_row_is_undetermined_not_fail(tmp_path):
    p = _write(tmp_path, "vendor.receipt.json", json.dumps(FOREIGN))
    row = verify_batch.verify_one(p)
    assert row["verdict"] == UNDETERMINED != FAIL
    assert row["reason"].startswith("not an Arcaeon receipt: missing")


# --- 2. JSONL --------------------------------------------------------------

def _jsonl(*objs_or_text):
    return "\n".join(o if isinstance(o, str) else json.dumps(o) for o in objs_or_text) + "\n"


def test_jsonl_is_could_not_look_with_one_line_reason(tmp_path, capsys):
    one = json.loads(VALID.read_text(encoding="utf-8"))
    p = _write(tmp_path, "many.jsonl", _jsonl(one, one, one))
    rc, out, err = _front([str(p)], capsys)
    assert rc == 3
    assert "Traceback" not in err and "JSONDecodeError" not in err
    assert err.strip() == (f"COULD NOT LOOK: {p} -- JSONL is not supported; "
                           "pass one receipt per file")
    assert json.loads(out)["reason"] == core.JSONL_REASON


def test_jsonl_with_malformed_line_is_could_not_look(tmp_path, capsys):
    one = json.loads(VALID.read_text(encoding="utf-8"))
    p = _write(tmp_path, "torn.jsonl", _jsonl(one, '{"receipt_version": "arcaeon-rec', one))
    rc, out, err = _front([str(p)], capsys)
    assert rc == 3 and "Traceback" not in err
    assert "JSONL is not supported" in err


def test_one_good_line_then_garbage_is_could_not_look(tmp_path, capsys):
    one = json.loads(VALID.read_text(encoding="utf-8"))
    p = _write(tmp_path, "half.json", _jsonl(one, "{not json"))
    rc, out, err = _front([str(p)], capsys)
    assert rc == 3 and "Traceback" not in err
    assert err.startswith(f"COULD NOT LOOK: {p} -- not readable JSON")


def test_batch_jsonl_row_names_jsonl(tmp_path):
    one = json.loads(VALID.read_text(encoding="utf-8"))
    p = _write(tmp_path, "many.receipt.json", _jsonl(one, one))
    row = verify_batch.verify_one(p)
    assert row["verdict"] == UNDETERMINED and row["reason"] == core.JSONL_REASON


# --- 3. exit codes and help ------------------------------------------------

def test_exit_codes_direct_entry_are_distinct(tmp_path, capsys):
    foreign = _write(tmp_path, "vendor.json", json.dumps(FOREIGN))
    assert RCLI.main(["verify", str(VALID)]) == 0
    assert RCLI.main(["verify", str(TAMPERED)]) == 2
    assert RCLI.main(["verify", str(foreign)]) == 4
    capsys.readouterr()


def test_exit_codes_front_door_map_to_the_one_table(tmp_path, capsys):
    foreign = _write(tmp_path, "vendor.json", json.dumps(FOREIGN))
    codes = {w: _front([str(p)], capsys)[0]
             for w, p in (("VERIFIED", VALID), ("BROKEN", TAMPERED),
                          ("COULD NOT LOOK", foreign))}
    assert codes == {w: V.exit_for(w) for w in codes} == {
        "VERIFIED": 0, "BROKEN": 1, "COULD NOT LOOK": 3}
    # --legacy-exit keeps the old tool's code
    assert ARC.main(["receipt", "verify", str(foreign), "--legacy-exit"]) == 4
    capsys.readouterr()


@pytest.mark.parametrize("front", [True, False])
def test_help_names_could_not_look_and_its_code(front, capsys):
    with pytest.raises(SystemExit) as e:
        if front:
            RCLI.main(["verify", "--help"], prog="arcaeon receipt")
        else:
            RCLI.main(["verify", "--help"])
    assert e.value.code == 0
    text = " ".join(capsys.readouterr().out.split())
    assert "COULD NOT LOOK" in text and "JSONL" in text
    assert ("3 COULD NOT LOOK" if front else "4 COULD NOT LOOK") in text
