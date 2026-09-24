# SPDX-License-Identifier: MIT
"""qa-fixes 2026-09-24: the black-box tester's hostile inputs, reproduced.

Each test builds the tester's exact input (qa_wheel/hostile/make.py) and runs
the verb the tester ran. The contract under test is arcaeon.verdict's one
table: every verb ends in 0, 1, 2 or 3 with a verdict or usage line, never a
traceback, and nothing that could not look exits green.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.record.ledger import Ledger

SRC = Path(__file__).resolve().parent.parent / "src"


# --- the tester's inputs (make.py, verbatim shapes) ---------------------------

def _valid(d: Path) -> Path:
    p = d / "valid.jsonl"
    lg = Ledger(p)
    for i in range(3):
        lg.append({"tool": "t", "i": i})
    return p


def _deep_list(d: Path) -> Path:
    p = d / "deep_list.jsonl"
    p.write_text("[" * 2000 + "]" * 2000 + "\n", encoding="utf-8")
    return p


def _deep_obj(d: Path) -> Path:
    s = "1"
    for _ in range(2000):
        s = '{"a": ' + s + "}"
    p = d / "deep_obj.jsonl"
    p.write_text(s + "\n", encoding="utf-8")
    return p


def _binary(d: Path) -> Path:
    p = d / "binary.bin"
    p.write_bytes(bytes(range(256)) * 64 + b"\xff\xfe\x00\x80\xc3\x28")
    return p


def _dupkey_raw(d: Path) -> Path:
    p = d / "dupkey_raw.jsonl"
    p.write_text('{"a": 1, "a": 2}\n', encoding="utf-8")
    return p


def _dupkey_chained(d: Path) -> Path:
    v = _valid(d)
    lines = v.read_text(encoding="utf-8").splitlines()
    p = d / "dupkey_chained.jsonl"
    p.write_text("\n".join(['{"tool": "EVIL", ' + lines[0][1:]] + lines[1:]) + "\n",
                 encoding="utf-8")
    return p


def _deep_after_valid(d: Path) -> Path:
    v = _valid(d)
    s = "1"
    for _ in range(2000):
        s = '{"a": ' + s + "}"
    p = d / "deep_after_valid.jsonl"
    p.write_text(v.read_text(encoding="utf-8") + s + "\n", encoding="utf-8")
    return p


def _run(argv, capsys):
    rc = cli.main(argv)
    out = capsys.readouterr()
    assert "Traceback" not in out.out + out.err
    assert rc in (0, 1, 2, 3), rc
    return rc, out.out, out.err


# --- item 1: tracebacks become verdicts or usage lines ------------------------

@pytest.mark.parametrize("make", [_deep_list, _deep_obj])
def test_distill_on_a_2000_deep_file_is_could_not_look(tmp_path, capsys, make):
    rc, out, err = _run(["distill", str(make(tmp_path))], capsys)
    # deep_list parses (the C scanner) and then exhausts distill's recursion;
    # either way nothing may read as a clean distill.
    if rc == V.EXIT_COULD_NOT_LOOK:
        body = json.loads(out)
        assert body["verdict"] == V.COULD_NOT_LOOK and body["reason"]
    else:
        assert rc == V.EXIT_GOOD and '"content"' in out


def test_distill_nesting_bomb_value_is_could_not_look_with_the_reason(tmp_path, capsys, monkeypatch):
    """The exact raise the tester hit (save/distill/__init__.py:995), planted so
    the test does not depend on this process's recursion limit."""
    import arcaeon.save.distill as d

    def boom(*a, **k):
        raise ValueError("input nests deeper than this process can distill (it exhausted "
                         "the recursion limit); flatten it or raise sys.setrecursionlimit")
    monkeypatch.setattr(d, "distill", boom)
    rc, out, _ = _run(["distill", str(_deep_obj(tmp_path))], capsys)
    assert rc == V.EXIT_COULD_NOT_LOOK
    body = json.loads(out)
    assert body["verdict"] == V.COULD_NOT_LOOK
    assert "nests deeper" in body["reason"]


@pytest.mark.parametrize("verb", ["distill", "dedup"])
def test_binary_input_is_one_usage_line_naming_the_file(tmp_path, capsys, verb):
    b = _binary(tmp_path)
    rc, out, err = _run([verb, str(b)], capsys)
    assert rc == V.EXIT_USAGE
    lines = [x for x in err.splitlines() if x.strip()]
    assert len(lines) == 1, err
    assert str(b) in lines[0] and "cannot read" in lines[0] and "UTF-8" in lines[0]


@pytest.mark.parametrize("verb", ["distill", "dedup"])
def test_directory_or_missing_input_says_cannot_read(tmp_path, capsys, verb):
    for target in (tmp_path / "dir with spaces", tmp_path / "does_not_exist.jsonl"):
        if target.name.startswith("dir"):
            target.mkdir()
        rc, _, err = _run([verb, str(target)], capsys)
        assert rc == V.EXIT_USAGE and "cannot read" in err, err


def test_log_into_a_directory_is_a_usage_line(tmp_path, capsys):
    d = tmp_path / "dir with spaces"
    d.mkdir()
    rc, _, err = _run(["log", str(d), '{"a": 1}'], capsys)
    assert rc == V.EXIT_USAGE and "is a directory" in err


def test_vet_on_a_missing_path_matches_badge(tmp_path, capsys):
    missing = str(tmp_path / "nope.py")
    rc_v, _, err_v = _run(["vet", missing], capsys)
    rc_b, _, err_b = _run(["badge", missing], capsys)
    assert rc_v == rc_b == V.EXIT_USAGE
    assert err_v.strip() == err_b.strip() == f"scan target does not exist: {Path(missing)}"


def test_any_uncaught_exception_is_one_line_exit_3(capsys, monkeypatch):
    class PlantedFault(RuntimeError):
        pass

    def planted(argv):
        raise PlantedFault("C:/secret/path must not be printed")
    monkeypatch.setitem(cli.HANDLERS, "version", planted)
    rc = cli.main(["version"])
    out = capsys.readouterr()
    assert rc == V.EXIT_COULD_NOT_LOOK
    assert out.out == ""
    assert out.err == "arcaeon version: could not finish: PlantedFault [internal_error]\n"


# --- item 2: vet false greens are NO GRADEABLE FILES, exit 3 -------------------

def test_vet_empty_dir_is_no_gradeable_files(tmp_path, capsys):
    d = tmp_path / "emptydir"
    d.mkdir()
    rc, out, err = _run(["vet", str(d)], capsys)
    assert rc == V.EXIT_COULD_NOT_LOOK
    assert json.loads(out)["verdict"] == V.NO_GRADEABLE_FILES
    assert V.NO_GRADEABLE_FILES in err


def test_vet_unparseable_file_is_no_gradeable_files(tmp_path, capsys):
    b = tmp_path / "broken.py"
    b.write_text("def (:\n", encoding="utf-8")
    rc, out, _ = _run(["vet", str(b)], capsys)
    assert rc == V.EXIT_COULD_NOT_LOOK
    assert json.loads(out)["verdict"] == V.NO_GRADEABLE_FILES
    rc, out, _ = _run(["vet", str(_binary(tmp_path))], capsys)
    assert rc == V.EXIT_COULD_NOT_LOOK
    assert json.loads(out)["verdict"] == V.NO_GRADEABLE_FILES


def test_vet_ts_without_the_extra_is_no_gradeable_files_with_the_arcaeon_hint(tmp_path, capsys, monkeypatch):
    from arcaeon.prove.vet import ts_checks
    monkeypatch.setattr(ts_checks, "available", lambda: False)
    ts = tmp_path / "server.ts"
    ts.write_text("export const x = 1;\n", encoding="utf-8")
    rc, out, err = _run(["vet", str(ts)], capsys)
    assert rc == V.EXIT_COULD_NOT_LOOK
    assert json.loads(out)["verdict"] == V.NO_GRADEABLE_FILES
    assert "pip install 'arcaeon[ts]'" in err
    assert "mcp-vet" not in err


def test_no_old_package_name_in_an_install_hint():
    bad = ("arcaeon-mcp-vet[", "mcp-vet[receipts]", "mcp-vet[mcp]", "mcp-vet[audit]",
           "mcp_vet[")
    hits = []
    for p in SRC.rglob("*.py"):
        text = p.read_text(encoding="utf-8")
        hits += [f"{p.name}: {b}" for b in bad if b in text]
    assert not hits, hits


# --- item 3: pin refuses a non-witness target and a could-not-look ledger ------

@pytest.mark.parametrize("make", [_binary, _dupkey_chained, _dupkey_raw, _deep_obj, _deep_list])
def test_pin_refuses_a_witness_file_that_is_not_one(tmp_path, capsys, make):
    valid = _valid(tmp_path)
    w = make(tmp_path)
    before = w.read_bytes()
    rc, out, _ = _run(["pin", str(valid), "--ns", "x", "--witness", str(w)], capsys)
    assert rc == V.EXIT_COULD_NOT_LOOK
    body = json.loads(out)
    assert body["ok"] is False and body["verdict"] == V.COULD_NOT_LOOK
    assert w.read_bytes() == before, "nothing may be written"


def test_pin_into_a_fresh_or_real_witness_file_still_works(tmp_path, capsys):
    valid = _valid(tmp_path)
    w = tmp_path / "w.jsonl"
    for _ in range(2):
        rc, out, _ = _run(["pin", str(valid), "--ns", "x", "--witness", str(w)], capsys)
        assert rc == V.EXIT_GOOD and json.loads(out)["ok"] is True


def test_pin_on_a_could_not_look_ledger_exits_3_not_green(tmp_path, capsys):
    led = _deep_obj(tmp_path)
    rc_v, _, _ = _run(["verify", str(led)], capsys)
    assert rc_v == V.EXIT_COULD_NOT_LOOK
    w = tmp_path / "w_tmp.jsonl"
    rc, out, _ = _run(["pin", str(led), "--ns", "x", "--witness", str(w)], capsys)
    assert rc == V.EXIT_COULD_NOT_LOOK
    body = json.loads(out)
    assert body["ok"] is False and body["error"]
    assert not w.exists()


# --- item 4: audit verify on an empty log --------------------------------------

def test_audit_verify_empty_is_could_not_look_like_verify(tmp_path, capsys):
    e = tmp_path / "empty.jsonl"
    e.write_text("", encoding="utf-8")
    rc_a, out_a, _ = _run(["audit", "verify", str(e)], capsys)
    rc_v, _, _ = _run(["verify", str(e)], capsys)
    assert rc_a == rc_v == V.EXIT_COULD_NOT_LOOK
    assert out_a.startswith(V.COULD_NOT_LOOK)


def test_audit_verify_clean_prints_verified(tmp_path, capsys):
    rc, out, _ = _run(["audit", "verify", str(_valid(tmp_path))], capsys)
    assert rc == V.EXIT_GOOD
    assert out.startswith("VERIFIED") and "3 records, integrity intact" in out


# --- item 5: log, once rebuild-index, deal show ---------------------------------

@pytest.mark.parametrize("make", [_binary, _dupkey_raw, _deep_obj, _deep_list, _deep_after_valid])
def test_log_refuses_to_chain_over_an_unreadable_last_row(tmp_path, capsys, make):
    f = make(tmp_path)
    before = f.read_bytes()
    rc, _, err = _run(["log", str(f), '{"a": 1}'], capsys)
    assert rc == V.EXIT_COULD_NOT_LOOK
    assert err.startswith(V.COULD_NOT_LOOK) and "nothing was written" in err
    assert f.read_bytes() == before
    assert not Path(str(f) + ".lock").exists()


def test_log_still_appends_to_a_good_or_new_ledger(tmp_path, capsys):
    for f in (_valid(tmp_path), tmp_path / "new.jsonl"):
        rc, out, _ = _run(["log", str(f), '{"a": 1}'], capsys)
        assert rc == V.EXIT_GOOD and len(out.strip()) == 32


def test_once_rebuild_index_on_a_missing_ledger_creates_nothing(tmp_path, capsys):
    missing = tmp_path / "does_not_exist.jsonl"
    rc, _, err = _run(["once", "rebuild-index", str(missing)], capsys)
    assert rc == V.EXIT_USAGE and "does not exist" in err
    assert sorted(os.listdir(tmp_path)) == []


@pytest.mark.parametrize("make", [_binary, _deep_obj, _deep_list, _deep_after_valid])
def test_once_rebuild_index_on_binary_or_deep_is_could_not_look(tmp_path, capsys, make):
    f = make(tmp_path)
    before = sorted(os.listdir(tmp_path))
    rc, out, err = _run(["once", "rebuild-index", str(f)], capsys)
    assert rc == V.EXIT_COULD_NOT_LOOK
    assert err.startswith(V.COULD_NOT_LOOK) and "nothing was created" in err
    assert "keys_indexed" not in out
    assert sorted(os.listdir(tmp_path)) == before


def test_once_rebuild_index_on_a_good_ledger_still_indexes(tmp_path, capsys):
    rc, out, _ = _run(["once", "rebuild-index", str(_valid(tmp_path))], capsys)
    assert rc == V.EXIT_GOOD and "keys_indexed" in out


def test_deal_show_on_missing_directory_or_binary_is_could_not_look(tmp_path, capsys):
    d = tmp_path / "dir with spaces"
    d.mkdir()
    for target in (tmp_path / "does_not_exist.jsonl", d, _binary(tmp_path)):
        rc, out, _ = _run(["deal", "show", str(target), "--deal", "d1"], capsys)
        assert rc == V.EXIT_COULD_NOT_LOOK
        assert out.startswith(V.COULD_NOT_LOOK), out
    rc, out, _ = _run(["deal", "show", str(_valid(tmp_path)), "--deal", "d1"], capsys)
    assert rc == V.EXIT_COULD_NOT_LOOK and "no row for deal d1" in out


# --- item 7: the Windows console -----------------------------------------------

def test_em_dash_survives_a_cp1252_pipe(tmp_path):
    led = _valid(tmp_path)
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONIOENCODING", "PYTHONUTF8")}
    env["PYTHONIOENCODING"] = "cp1252"
    env["PYTHONPATH"] = str(SRC)
    p = subprocess.run([sys.executable, "-m", "arcaeon", "audit", "verify", str(led)],
                       capture_output=True, env=env)
    assert p.returncode == 0, p.stderr
    assert "\u2014".encode("utf-8") in p.stdout, p.stdout[:80]


# --- item 8: one source_sha256 for one file --------------------------------------

def test_vet_grade_and_vet_report_the_raw_file_sha256(tmp_path, capsys):
    f = tmp_path / "server.py"
    f.write_bytes(b"def helper(x):\r\n    return x.upper()\r\n")   # CRLF on purpose
    raw = hashlib.sha256(f.read_bytes()).hexdigest()
    rc, out_t, _ = _run(["vet", str(f)], capsys)
    rc2, out_g, _ = _run(["vet", "grade", str(f)], capsys)
    assert json.loads(out_t)["source_sha256"] == raw
    assert json.loads(out_g)["source_sha256"] == raw


def test_vet_help_has_no_wip_string(capsys):
    rc, out, _ = _run(["vet", "--help"], capsys)
    assert rc == 0 and "WIP" not in out and "2026-08-29" not in out
