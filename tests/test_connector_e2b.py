# SPDX-License-Identifier: MIT
"""L2-11: the E2B sandbox run receipt adapter. A caller serialises an E2B run
result (a CommandResult or a code-interpreter Execution) to JSON; each run becomes
one relayed check.verdict row, unsigned, reported by the sender. A failed run is
BROKEN, a run that reports success relays VERIFIED only as the sender's word, and
anything the adapter cannot read is COULD NOT LOOK. Fixtures are shaped from E2B's
public SDK source, not a live capture. No network."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from arcaeon.connector import ROW_KIND, VendorAdapter, adapter_for, import_verdict, recheck
from arcaeon.connector import e2b as E
from arcaeon.verdict import BROKEN, COULD_NOT_LOOK, VERIFIED

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "e2b"
CMD_OK = (FIX / "command_ok.json").read_bytes()
CMD_FAIL = (FIX / "command_failed.json").read_bytes()
EXE_OK = (FIX / "execution_ok.json").read_bytes()
EXE_ERR = (FIX / "execution_to_json_error.json").read_bytes()
AT = "2026-10-05T12:00:00Z"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _ing(raw, **kw):
    return E.ingest(raw, received_at=AT, **kw)


def _one(raw):
    rows = _ing(raw)
    assert len(rows) == 1
    _sealed(rows[0])
    return rows[0]


def _doc(**fields):
    return _one(json.dumps(fields).encode())


def _sealed(r):
    assert r["signed_by_vendor"] is False
    assert r["standing"] == "reported_by_sender"
    assert r["attestation"] == {"status": "NONE", "checked_by_us": False, "claimed": None}
    assert r["vendor"] == {"name": "e2b", "adapter_version": "1"}
    assert r["kind"] == ROW_KIND and r["relayed"] is True and r["checked_by_us"] is False
    assert "verdict" not in r
    assert r["relayed_verdict"] in (VERIFIED, BROKEN, COULD_NOT_LOOK)


# --- the adapter ------------------------------------------------------------------

def test_adapter_is_on_the_one_base_and_registered():
    assert isinstance(E.E2B, VendorAdapter) and E.E2B.one_row_per_payload is False
    assert adapter_for("e2b") is E.E2B
    assert E.STANDING == "reported_by_sender"


def test_import_verdict_refuses_and_recheck_says_could_not_look():
    row = import_verdict(E.E2B, CMD_OK, received_at=AT)
    assert row["relayed_verdict"] == COULD_NOT_LOOK
    r = _one(CMD_OK)
    assert recheck(r, CMD_OK)["verdict"] == COULD_NOT_LOOK


# --- commands.run CommandResult ---------------------------------------------------

def test_command_exit_zero_relays_verified_as_the_senders_word():
    r = _one(CMD_OK)
    assert r["relayed_verdict"] == VERIFIED
    assert r["vendor_word"] == "command_exit_zero" and r["mapping"] == {"rule": "table"}
    assert "could_not_look" not in r
    assert r["input_sha256"] == _sha(CMD_OK)
    run = r["run"]
    assert run["shape"] == "command" and run["exit_code"] == 0
    assert run["sandbox_id"] == "isynthetic0000000001" and run["template_id"] == "base"
    assert r["vendor_id"] == "isynthetic0000000001"
    out = "hello from a synthetic run\n".encode()
    assert run["stdout_sha256"] == _sha(out) and run["stdout_bytes"] == len(out)
    assert run["stderr_sha256"] == _sha(b"") and run["stderr_bytes"] == 0
    assert run["metadata_keys"] == 1 and run["metadata_digest"].startswith("sha256:jcs:v1:")


def test_output_is_hashed_never_copied():
    blob = json.dumps(_one(CMD_OK))
    assert "hello from a synthetic run" not in blob
    assert "synthetic-demo" not in blob
    blob = json.dumps(_one(CMD_FAIL))
    assert "no such file" not in blob and "exit status 2" not in blob
    blob = json.dumps(_one(EXE_ERR))
    assert "division by zero" not in blob and "synthetic traceback" not in blob
    assert "before the error" not in blob


def test_command_nonzero_exit_is_broken():
    r = _one(CMD_FAIL)
    assert r["relayed_verdict"] == BROKEN and r["vendor_word"] == "command_exit_nonzero"
    assert r["run"]["exit_code"] == 2 and r["run"]["error_present"] is True
    assert r["run"]["error_digest"] == _sha(b"exit status 2")


def test_command_error_with_exit_zero_is_broken():
    r = _doc(stdout="", stderr="", exit_code=0, error="killed")
    assert r["relayed_verdict"] == BROKEN and r["vendor_word"] == "command_error"


def test_command_empty_error_string_is_no_error():
    assert _doc(stdout="x", stderr="", exit_code=0, error="")["relayed_verdict"] == VERIFIED


@pytest.mark.parametrize("bad", [None, "0", 0.0, True, False, [0], {"c": 0}])
def test_unreadable_or_missing_exit_code_is_could_not_look(bad):
    doc = {"stdout": "", "stderr": "", "error": None}
    if bad is not None:
        doc["exit_code"] = bad
    r = _doc(**doc)
    assert r["relayed_verdict"] == COULD_NOT_LOOK and "could_not_look" in r


def test_camelcase_exit_code_is_not_read():
    r = _doc(stdout="", stderr="", exitCode=0, error=None)
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    assert "exitCode" in r["run"]["ignored_keys"]


def test_nonzero_exit_stays_broken_whatever_else_is_wrong():
    r = _doc(exit_code=1, stdout=5, stderr=[1], error=7, sandbox_id=9, extra="x",
             signed_by_vendor=True, standing="vendor_signed")
    assert r["relayed_verdict"] == BROKEN


def test_unknown_field_blocks_a_success():
    r = _doc(stdout="", stderr="", exit_code=0, error=None, surprise=1)
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    assert r["run"]["ignored_keys"] == ["surprise"]


@pytest.mark.parametrize("field,val", [("stdout", 1), ("stderr", ["a"]), ("error", 3),
                                       ("sandbox_id", 1), ("template_id", []),
                                       ("metadata", "x"), ("metadata", {"k": 1})])
def test_wrong_type_blocks_a_success(field, val):
    doc = {"stdout": "", "stderr": "", "exit_code": 0, "error": None}
    doc[field] = val
    assert _doc(**doc)["relayed_verdict"] == COULD_NOT_LOOK


def test_claims_of_signature_are_ignored():
    r = _doc(stdout="", stderr="", exit_code=1, error=None, signed_by_vendor=True,
             signature="AAAA", attestation={"sig": "x"})
    assert r["signed_by_vendor"] is False and r["attestation"]["status"] == "NONE"


# --- code-interpreter Execution ---------------------------------------------------

def test_execution_without_error_relays_verified():
    r = _one(EXE_OK)
    assert r["relayed_verdict"] == VERIFIED and r["vendor_word"] == "execution_no_error"
    run = r["run"]
    assert run["shape"] == "execution" and run["execution_count"] == 1
    assert run["results_count"] == 1 and run["exit_code"] is None
    assert run["stdout_sha256"] == _sha(b"computing\n") and run["stdout_lines"] == 1
    assert run["stderr_sha256"] == _sha(b"") and run["stderr_lines"] == 0


def test_execution_to_json_shape_with_error_is_broken():
    r = _one(EXE_ERR)
    assert r["relayed_verdict"] == BROKEN and r["vendor_word"] == "execution_error"
    run = r["run"]
    assert run["error_name"] == "ZeroDivisionError" and run["error_present"] is True
    assert run["error_digest"].startswith("sha256:jcs:v1:")
    assert run["stdout_sha256"] == _sha(b"before the error\n")
    assert run["execution_count"] is None


def test_execution_to_json_shape_without_error_is_verified():
    body = json.dumps({"results": [], "logs": json.dumps({"stdout": ["a"], "stderr": []}),
                       "error": None}).encode()
    r = _one(body)
    assert r["relayed_verdict"] == VERIFIED and r["run"]["stdout_sha256"] == _sha(b"a")


def test_execution_that_does_not_say_whether_it_errored_is_could_not_look():
    r = _doc(results=[], logs={"stdout": [], "stderr": []})
    assert r["relayed_verdict"] == COULD_NOT_LOOK


@pytest.mark.parametrize("logs", ["not json", 5, {"stdout": "x", "stderr": []},
                                  {"stdout": [1], "stderr": []}, "[1, 2]"])
def test_unreadable_logs_block_a_success(logs):
    assert _doc(results=[], logs=logs, error=None)["relayed_verdict"] == COULD_NOT_LOOK


def test_unreadable_logs_do_not_hide_an_error():
    r = _doc(results=[], logs=5, error={"name": "E", "value": "v", "traceback": "t"})
    assert r["relayed_verdict"] == BROKEN


@pytest.mark.parametrize("err", [5, True, [1]])
def test_error_of_a_wrong_type_is_could_not_look(err):
    assert _doc(results=[], logs={"stdout": [], "stderr": []}, error=err)[
        "relayed_verdict"] == COULD_NOT_LOOK


def test_ambiguous_shape_is_could_not_look():
    r = _doc(exit_code=0, stdout="", stderr="", error=None, logs={"stdout": [], "stderr": []})
    assert r["relayed_verdict"] == COULD_NOT_LOOK


def test_object_with_no_run_shape_is_could_not_look():
    assert _doc(hello="world")["relayed_verdict"] == COULD_NOT_LOOK
    assert _doc(error=None)["relayed_verdict"] == COULD_NOT_LOOK


# --- many runs, rollup ------------------------------------------------------------

def test_list_of_runs_is_one_row_per_run():
    body = b"[" + CMD_OK + b"," + CMD_FAIL + b"," + EXE_OK + b"," + EXE_ERR + b", 7]"
    rows = _ing(body)
    assert [r["relayed_verdict"] for r in rows] == [VERIFIED, BROKEN, VERIFIED, BROKEN,
                                                   COULD_NOT_LOOK]
    assert [r["run"]["index"] for r in rows] == [0, 1, 2, 3, 4]
    for r in rows:
        _sealed(r)
        assert r["input_sha256"] == _sha(body)


def test_too_many_runs_is_bounded():
    body = json.dumps([{"exit_code": 0, "stdout": "", "stderr": "", "error": None}]
                      * (E.MAX_ROWS + 3)).encode()
    rows = _ing(body)
    assert len(rows) == E.MAX_ROWS + 1
    assert rows[-1]["relayed_verdict"] == COULD_NOT_LOOK


def test_standing_verdict_is_never_verified():
    ok = _ing(CMD_OK) + _ing(EXE_OK)
    assert all(r["relayed_verdict"] == VERIFIED for r in ok)
    s = E.standing_verdict(ok)
    assert s["relayed_verdict"] == COULD_NOT_LOOK and s["signed_by_vendor"] is False
    assert "verdict" not in s and s["counts"][VERIFIED] == len(ok)
    assert s["standing"] == "reported_by_sender"
    s = E.standing_verdict(ok + _ing(CMD_FAIL))
    assert s["relayed_verdict"] == BROKEN
    assert E.standing_verdict([])["relayed_verdict"] == COULD_NOT_LOOK
    assert E.standing_verdict("junk")["relayed_verdict"] == COULD_NOT_LOOK
    assert E.rollup(ok)["relayed_verdict"] == COULD_NOT_LOOK


def test_standing_verdict_ignores_other_vendors_rows():
    fake = dict(_one(CMD_FAIL))
    fake["vendor"] = {"name": "reported", "adapter_version": "1"}
    assert E.standing_verdict([fake])["relayed_verdict"] == COULD_NOT_LOOK


# --- hostile input never raises ---------------------------------------------------

@pytest.mark.parametrize("raw", [b"", b"not json", b"\xff\xfe", b"[]", b"5", b"null",
                                 b'{"a": 1, "a": 2}', "text", None, 5, 3.5, ["x"],
                                 bytearray(b'{"exit_code": "0"}'),
                                 b"[" * 200 + b"]" * 200,
                                 b'{"exit_code": ' + b"9" * 5000 + b"}"])
def test_hostile_bodies_never_raise(raw):
    rows = _ing(raw)
    assert rows and all(r["relayed_verdict"] in (COULD_NOT_LOOK, BROKEN) for r in rows)
    for r in rows:
        _sealed(r)


def test_huge_body_is_digested_not_read():
    raw = b" " * (E.MAX_PAYLOAD_BYTES + 1)
    r = _one(raw)
    assert r["relayed_verdict"] == COULD_NOT_LOOK and r["input_sha256"] == _sha(raw)


def test_deep_nesting_inside_logs_string_never_raises():
    deep = "[" * 5000 + "]" * 5000
    r = _doc(results=[], logs=deep, error=None)
    assert r["relayed_verdict"] == COULD_NOT_LOOK
    r = _doc(results=[], logs={"stdout": [], "stderr": []}, error=deep)
    assert r["relayed_verdict"] in (BROKEN, COULD_NOT_LOOK)


def test_lone_surrogates_in_output_never_raise():
    body = b'{"exit_code": 0, "stdout": "\\ud800", "stderr": "", "error": null}'
    r = _one(body)
    assert r["relayed_verdict"] == VERIFIED and r["run"]["stdout_sha256"]


def test_rows_round_trip_json():
    for raw in (CMD_OK, CMD_FAIL, EXE_OK, EXE_ERR, b"junk"):
        for r in _ing(raw):
            assert json.loads(json.dumps(r)) == r
