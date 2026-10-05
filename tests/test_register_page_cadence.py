# SPDX-License-Identifier: MIT
"""L3-07b: the register page's cadence line, read from a pin task's log.

The pin log is JSONL, one row per pin, each with a UTC time. Given one
(`--pin-log [MEMBER=]FILE`, library `pin_logs=`), the member's line says
"observed every ~N hours (last K pins)"; absent, unreadable, or with fewer
than two dated rows, it stays "not stated". Never a guess. Fixture logs are
made under tmp_path; keys are TEST-ONLY and thrown away. No network."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

from arcaeon import cli  # noqa: E402
from arcaeon import verdict as V  # noqa: E402
from arcaeon.prove import register as G  # noqa: E402
from arcaeon.prove import register_page as P  # noqa: E402
from arcaeon.prove.vet import receipts as R  # noqa: E402

T0 = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)
A = "acct:operator-a@arcaeon.io"
B = "acct:operator-b@arcaeon.io"
NOT_STATED = "publishing cadence: not stated"


def _key():
    seed = os.urandom(32)
    return seed, R.did_key(R.public_key_from_seed(seed))


@pytest.fixture
def op():
    return _key()


def _reg(op, members=(A,)):
    rows = G.new_register()
    for m in members:
        G.add(rows, op[0], member=m, what="key", value=_key()[1], at=T0)
    return rows


def _pins(tmp_path, name, hours, n, field="at", start=T0, extra=None):
    p = tmp_path / name
    lines = []
    for k in range(n):
        t = start + timedelta(hours=hours * k)
        lines.append(json.dumps({field: t.strftime("%Y-%m-%dT%H:%M:%SZ"), "head": f"h{k}"}))
    lines += extra or []
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _line(page, member=A):
    sec = page.split(member, 1)[1]
    return next(ln for ln in sec.splitlines() if "publishing cadence" in ln)


def test_observed_cadence_from_the_pin_log(op, tmp_path):
    log = _pins(tmp_path, "witness_pin_log.jsonl", 6, 5)
    page = P.render_page(_reg(op), operator_keys=[op[1]], pin_logs=[str(log)])
    line = _line(page)
    assert "observed every ~6 hours (last 5 pins)" in line, line
    assert "witness_pin_log.jsonl" in line and str(tmp_path) not in page
    assert "2026-10-06T12:00:00Z" in line            # the latest pin seen


def test_only_the_recent_rows_count(op, tmp_path):
    # 30 old pins a day apart, then 10 recent ones 2 hours apart: the recent ones
    old = [json.dumps({"at": (T0 - timedelta(days=60 - d)).strftime("%Y-%m-%dT%H:%M:%SZ")})
           for d in range(30)]
    log = tmp_path / "pins.jsonl"
    log.write_text("\n".join(old) + "\n", encoding="utf-8")
    with open(log, "a", encoding="utf-8") as fh:
        for k in range(10):
            fh.write(json.dumps({"at": (T0 + timedelta(hours=2 * k)).strftime(
                "%Y-%m-%dT%H:%M:%SZ")}) + "\n")
    line = _line(P.render_page(_reg(op), operator_keys=[op[1]], pin_logs=[str(log)]))
    assert "observed every ~2 hours (last 10 pins)" in line, line


def test_other_time_field_names_and_offsets_are_read(op, tmp_path):
    p = tmp_path / "pins.jsonl"
    rows = [{"ts": "2026-10-05T12:00:00+00:00"}, {"pinned_at": "2026-10-05T15:00:00.250Z"},
            {"timestamp": "2026-10-05T18:00:00Z"}]
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    line = _line(P.render_page(_reg(op), operator_keys=[op[1]], pin_logs=[str(p)]))
    assert "observed every ~3 hours (last 3 pins)" in line, line


def _task_row(t, outcome, exit_code=0):
    return json.dumps({"ts": t.strftime("%Y-%m-%dT%H:%M:%S+00:00"), "outcome": outcome,
                       "pin": t.strftime("%Y-%m-%dT%H%MZ"), "exit_code": exit_code})


def test_only_pinned_runs_count_not_nothing_new_or_failed(op, tmp_path):
    """The pin task's log: a row per run, {"ts", "outcome": "pinned" |
    "nothing-new", "pin", "exit_code"}. A run that pinned nothing, or exited
    non-zero, is not a pin and does not shrink the interval."""
    lines = []
    for k in range(5):                                       # pinned every 6 hours
        lines.append(_task_row(T0 + timedelta(hours=6 * k), "pinned"))
        if k < 4:
            lines.append(_task_row(T0 + timedelta(hours=6 * k + 3), "nothing-new"))
    lines.append(_task_row(T0 + timedelta(hours=25), "pinned", exit_code=1))
    log = tmp_path / "witness_pin_log.jsonl"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    line = _line(P.render_page(_reg(op), operator_keys=[op[1]], pin_logs=[str(log)]))
    assert "observed every ~6 hours (last 5 pins)" in line, line
    assert "latest pin 2026-10-06T12:00:00Z" in line, line


def test_only_nothing_new_runs_is_not_stated(op, tmp_path):
    log = tmp_path / "pins.jsonl"
    log.write_text("\n".join(_task_row(T0 + timedelta(hours=k), "nothing-new")
                             for k in range(4)) + "\n", encoding="utf-8")
    line = _line(P.render_page(_reg(op), operator_keys=[op[1]], pin_logs=[str(log)]))
    assert NOT_STATED in line and "observed" not in line, line


@pytest.mark.parametrize("case", ["missing", "not utf-8", "no json", "one pin", "naive time",
                                  "no time field"])
def test_absent_or_unreadable_stays_not_stated(op, tmp_path, case):
    p = tmp_path / "pins.jsonl"
    if case == "not utf-8":
        p.write_bytes(b"\xff\xfe\x00garbage")
    elif case == "no json":
        p.write_text("not json\nalso not\n", encoding="utf-8")
    elif case == "one pin":
        _pins(tmp_path, "pins.jsonl", 6, 1)
    elif case == "naive time":
        p.write_text('{"at": "2026-10-05T12:00:00"}\n{"at": "2026-10-05T18:00:00"}\n',
                     encoding="utf-8")
    elif case == "no time field":
        p.write_text('{"head": "x"}\n{"head": "y"}\n', encoding="utf-8")
    page = P.render_page(_reg(op), operator_keys=[op[1]], pin_logs=[str(p)])
    line = _line(page)
    assert NOT_STATED in line and "observed" not in line, (case, line)


def test_no_pin_log_is_byte_identical_to_before(op):
    rows = _reg(op)
    assert P.render_page(rows, operator_keys=[op[1]]) == \
        P.render_page(rows, operator_keys=[op[1]], pin_logs=None)
    assert NOT_STATED in P.render_page(rows, operator_keys=[op[1]])


def test_a_member_named_log_goes_to_that_member_only(op, tmp_path):
    log = _pins(tmp_path, "b-pins.jsonl", 12, 4)
    page = P.render_page(_reg(op, (A, B)), operator_keys=[op[1]], pin_logs=[f"{B}={log}"])
    assert "observed every ~12 hours (last 4 pins)" in _line(page, B)
    assert NOT_STATED in _line(page, A)


def test_a_bare_log_with_two_members_is_not_guessed(op, tmp_path):
    log = _pins(tmp_path, "pins.jsonl", 6, 4)
    page = P.render_page(_reg(op, (A, B)), operator_keys=[op[1]], pin_logs=[str(log)])
    for m in (A, B):
        line = _line(page, m)
        assert NOT_STATED in line and "MEMBER=FILE" in line, line


def test_cli_takes_pin_log(op, tmp_path, capsys):
    rows = _reg(op)
    reg = tmp_path / "register.jsonl"
    reg.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    log = _pins(tmp_path, "witness_pin_log.jsonl", 6, 3)
    out = tmp_path / "page.html"
    assert cli.main(["register", "page", str(reg), "--operator-key", op[1],
                     "--pin-log", str(log), "--out", str(out)]) == V.EXIT_GOOD
    assert "observed every ~6 hours (last 3 pins)" in out.read_text(encoding="utf-8")
    assert "--pin-log" in P.USAGE
