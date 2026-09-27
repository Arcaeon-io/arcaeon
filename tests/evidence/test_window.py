"""K052: --agent and --from/--to select window.jsonl; each row keeps its line number."""
import json

import pytest

from arcaeon import verdict as V
from arcaeon.prove import evidence_pack_cli
from arcaeon.prove.evidence_pack import PackUsageError, build_pack


def _window(out):
    return [json.loads(l) for l in (out / "window.jsonl").read_text(encoding="utf-8").splitlines()]


def _ledger_lines(ledger):
    return ledger.read_bytes().decode("utf-8").splitlines()


def test_agent_filter_keeps_line_numbers(ledger, tmp_path):
    out = tmp_path / "pack"
    res = build_pack(ledger, out, agent="agent-a")
    w = _window(out)
    assert [r["line"] for r in w] == [1, 3]
    lines = _ledger_lines(ledger)
    for r in w:
        assert r["raw"] == lines[r["line"] - 1]
    assert res["verdict"] == V.VERIFIED and res["exit"] == 0
    assert res["window"]["first_line"] == 1 and res["window"]["last_line"] == 3


def test_agent_matches_system_id(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="sys-b")
    assert [r["line"] for r in _window(out)] == [2, 4]


def test_time_window_inclusive(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, since="2026-09-01T11:00:00Z", until="2026-09-02T09:30:00Z")
    assert [r["line"] for r in _window(out)] == [2, 3]


def test_agent_and_window_together(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-b", since="2026-09-02")
    assert [r["line"] for r in _window(out)] == [4]


def test_no_filter_is_every_row(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out)
    assert [r["line"] for r in _window(out)] == [1, 2, 3, 4]


def test_offset_zone_is_honoured(ledger, tmp_path):
    out = tmp_path / "pack"
    # 2026-09-01T04:00:00-07:00 is 11:00Z: rows 2, 3, 4 are at or after it
    build_pack(ledger, out, since="2026-09-01T04:00:00-07:00")
    assert [r["line"] for r in _window(out)] == [2, 3, 4]


def test_empty_window_is_could_not_look_empty(ledger, tmp_path):
    out = tmp_path / "pack"
    res = build_pack(ledger, out, agent="agent-c")
    assert res["verdict"] == V.COULD_NOT_LOOK and res["exit"] == 3
    assert res["reason_word"] == "empty"
    assert (out / "window.jsonl").read_bytes() == b""


def test_empty_window_never_hides_broken(ledger, tmp_path):
    lines = ledger.read_bytes().split(b"\n")
    lines[0] = lines[0].replace(b"system_start", b"system_stort")
    ledger.write_bytes(b"\n".join(lines))
    res = build_pack(ledger, tmp_path / "pack", agent="agent-c")
    assert res["verdict"] == V.BROKEN and res["exit"] == 1


def test_unreadable_ts_is_named_not_guessed(tmp_path):
    from arcaeon.record.ledger import Ledger
    p = tmp_path / "l.jsonl"
    lg = Ledger(p)
    lg.append({"ts": "2026-09-01T10:00:00Z", "agent": "a", "event": "x"})
    lg.append({"ts": "yesterday", "agent": "a", "event": "y"})
    res = build_pack(p, tmp_path / "pack", agent="a", since="2026-01-01")
    assert res["window"]["rows"] == 1
    assert res["window"]["unplaced_lines"] == [2]


def test_bad_timestamps_are_usage(ledger, tmp_path):
    with pytest.raises(PackUsageError):
        build_pack(ledger, tmp_path / "p1", since="not a time")
    with pytest.raises(PackUsageError):
        build_pack(ledger, tmp_path / "p2", since="2026-09-03", until="2026-09-01")
    assert evidence_pack_cli.main(["--ledger", str(ledger), "--out", str(tmp_path / "p3"),
                                   "--from", "soon"]) == 2


def test_cli_flags(ledger, tmp_path, capsys):
    out = tmp_path / "pack"
    rc = evidence_pack_cli.main(["--ledger", str(ledger), "--out", str(out), "--agent",
                                 "agent-a", "--from", "2026-09-02", "--to", "2026-09-30",
                                 "--json"])
    assert rc == 0
    assert [r["line"] for r in _window(out)] == [3]
