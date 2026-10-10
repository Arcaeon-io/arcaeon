# SPDX-License-Identifier: MIT
"""Gaps the 2026-10-10 must-fail pass closed: each test here fails with one or
more planted defects (named in its docstring by mutant id) and passes on the
real code. None of them touches the code under test.

The pass aimed at one failure: a broken, edited or truncated record reading as
verified. Mutant ids and the full table are in the pass's report.
"""
import json

import pytest

from arcaeon.record.adapter import _ledger as adapter_ledger


# --- the adapter's FALLBACK verifier (no arcaeon-ledger importable) -------------
# tests/ledger/test_adapter_fallback_verify.py covers this path, but it imports
# `adapter.arcaeon_adapter`, which does not exist, so it is never collected.

@pytest.fixture
def fallback(monkeypatch):
    monkeypatch.setattr(adapter_ledger, "_HAVE_LEDGER", False)
    return adapter_ledger


def _fallback_log(tmp_path, fallback, n=3):
    log = tmp_path / "seam.jsonl"
    lg = fallback.open_ledger(str(log))
    for i in range(n):
        lg.append({"i": i})
    return log


def test_fallback_empty_seam_log_is_not_a_green(tmp_path, fallback):
    """F01, F06: an empty seam log checked nothing; ok is None and the verdict is falsy."""
    log = tmp_path / "seam.jsonl"
    log.write_text("", encoding="utf-8")
    v = fallback.verify_seam_log(str(log))
    assert v.ok is None and not v and v.verified_scope == "empty"


def test_fallback_one_edited_value_is_a_break(tmp_path, fallback):
    """F02, F04: one value edited after the write is one break, and one break is red."""
    log = _fallback_log(tmp_path, fallback)
    assert fallback.verify_seam_log(str(log)).ok is True
    lines = log.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[1])
    row["i"] = 41
    lines[1] = json.dumps(row)
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    v = fallback.verify_seam_log(str(log))
    assert v.ok is False and v.breaks == 1 and v.first_break == "line 2: chain mismatch"


def test_fallback_unparseable_line_is_a_break(tmp_path, fallback):
    """F03: a torn or garbage line is counted as a break, not stepped over."""
    log = _fallback_log(tmp_path, fallback, n=1)
    with log.open("a", encoding="utf-8") as fh:
        fh.write('{"i": 1, "chain": \n')
    v = fallback.verify_seam_log(str(log))
    assert v.ok is False and v.breaks == 1 and "unparseable" in v.first_break


def test_fallback_unreadable_seam_log_is_not_verified(tmp_path, fallback):
    """F05: a path that cannot be read (here a directory) is never ok."""
    v = fallback.verify_seam_log(str(tmp_path))
    assert v.ok is False and not v
