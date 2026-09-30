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


# --- 4. a path verify cannot read (R943 residual) ----------------------------
# Missing, a directory, permission denied, empty: COULD NOT LOOK with the path
# and the cause, exit 3 (front door) / 4 (direct), never exit 1. Exit 1 stays
# for usage errors only.

BALLOTS = Path(__file__).resolve().parent.parent / "examples" / "ballots"


def _assert_could_not_look_path(p, capsys, cause, reason_word):
    rc, out, err = _front([str(p)], capsys)
    assert rc == V.EXIT_COULD_NOT_LOOK == 3
    assert "Traceback" not in err and "error:" not in err
    assert err.strip().splitlines() == [f"COULD NOT LOOK: {p} -- {cause}: {p}"]
    rep = json.loads(out)
    assert rep["verdict"] == "COULD NOT LOOK" and rep["ok"] is False
    assert rep["reason"] == f"{cause}: {p}" and rep["reason_word"] == reason_word
    assert rep["where"] == str(p)
    assert RCLI.main(["verify", str(p)]) == 4
    capsys.readouterr()


def test_missing_path_is_could_not_look_not_usage(tmp_path, capsys):
    _assert_could_not_look_path(tmp_path / "gone.json", capsys, "no such file", "missing")


def test_directory_is_could_not_look_not_usage(tmp_path, capsys):
    d = tmp_path / "a_folder"
    d.mkdir()
    _assert_could_not_look_path(d, capsys, "is a directory, not a receipt file",
                                "unreadable")


def test_permission_denied_is_could_not_look_not_usage(tmp_path, capsys, monkeypatch):
    p = _write(tmp_path, "locked.json", VALID.read_text(encoding="utf-8"))
    real = Path.read_text

    def denied(self, *a, **kw):
        if Path(self) == p:
            raise PermissionError(13, "Permission denied", str(self))
        return real(self, *a, **kw)

    monkeypatch.setattr(Path, "read_text", denied)
    _assert_could_not_look_path(p, capsys, "permission denied", "unreadable")


@pytest.mark.parametrize("body", ["", "  \n\n"])
def test_empty_file_is_could_not_look_not_usage(tmp_path, capsys, body):
    p = _write(tmp_path, "empty.json", body)
    _assert_could_not_look_path(p, capsys, "empty file", "empty")


def test_usage_errors_still_exit_1_or_argparse(capsys):
    # no argument: usage, exit 1 (unchanged)
    assert RCLI.main(["verify"]) == 1
    assert "verify needs a receipt path" in capsys.readouterr().err
    # a bad flag: argparse usage error, never a verdict
    with pytest.raises(SystemExit) as e:
        RCLI.main(["verify", "--no-such-flag", str(VALID)])
    assert e.value.code not in (0, 3, 4)
    assert "COULD NOT LOOK" not in capsys.readouterr().err


def test_batch_one_missing_among_good_counts_as_could_not_look(tmp_path, capsys):
    good = sorted(p for p in BALLOTS.glob("*.receipt.json") if "anchored" not in p.name)[:3]
    assert len(good) == 3
    missing = tmp_path / "gone.receipt.json"
    targets = [str(good[0]), str(missing), str(good[1]), str(good[2])]
    ledger = str(BALLOTS / "ledger.jsonl")
    result = verify_batch.verify_batch(targets, ledger_path=ledger)
    assert (result["verified"], result["failed"], result["undetermined"]) == (3, 0, 1)
    row = next(r for r in result["rows"] if r["path"] == str(missing))
    assert row["verdict"] == UNDETERMINED and row["reason_word"] == "missing"
    assert row["reason"] == f"no such file: {missing}"
    text = verify_batch.render(result)
    assert text.splitlines()[-1] == "4 receipts: 3 VERIFIED, 0 BROKEN, 1 COULD NOT LOOK"
    assert verify_batch.exit_code(result) == 4
    assert RCLI.main(["verify", "--batch", *targets, "--ledger", ledger]) == 4
    assert "4 receipts: 3 VERIFIED, 0 BROKEN, 1 COULD NOT LOOK" in capsys.readouterr().out
    assert ARC.main(["receipt", "verify", "--batch", *targets, "--ledger", ledger]) == 3
    capsys.readouterr()
