# SPDX-License-Identifier: MIT
"""Failure-first tests for `arcaeon_ledger.reconcile` (two tapes and a counter).

Written the Sigstore way: almost every test hands reconcile a BAD pair and
demands the right non-green verdict. One positive control proves the green is
reachable at all. Then two break arms swap in lying reconcilers (one that always
says MATCHED, one that files every ALTERED as MISSING) and prove the failure
cases would catch them; a suite never watched failing against a liar has not
been shown to test anything.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import arcaeon.prove.reconcile as R
from arcaeon.record.ledger import Ledger, digest_json
from arcaeon.record.ledger.cli import main as cli_main


# -- building tapes ----------------------------------------------------------

def req(n):
    return digest_json({"name": "echo", "arguments": {"text": f"call {n}"}})


def resp(n, tag=""):
    return digest_json({"result": {"content": [{"type": "text", "text": f"call {n}{tag}"}]}})


def row(side, idx, rq, rs, ns=None, status="ok"):
    return {"evt": "tape_call", "tape": R.TAPE_FORMAT, "side": side,
            "ns": ns or f"demo-{side}", "idx": idx, "tool": "echo",
            "req": rq, "resp": rs, "status": status if rs is not None else "unanswered"}


def write(path: Path, rows):
    Path(path).touch()          # an empty tape is a real, zero-row file
    lg = Ledger(path)
    for r in rows:
        lg.append(r)
    return path


def pair(tmp, n=5):
    """Two honest tapes of n calls."""
    a = [row("agent", k, req(k), resp(k)) for k in range(1, n + 1)]
    t = [row("tool", k, req(k), resp(k)) for k in range(1, n + 1)]
    return a, t


def run(tmp, a_rows, t_rows, pin=None, swap=False):
    a = write(tmp / "agent.tape.jsonl", a_rows) if a_rows is not None else tmp / "nope-a.jsonl"
    t = write(tmp / "tool.tape.jsonl", t_rows) if t_rows is not None else tmp / "nope-t.jsonl"
    pin_path = None
    if pin is not None:
        pin_path = tmp / "pin.json"
        pin_path.write_text(pin if isinstance(pin, str) else json.dumps(pin), encoding="utf-8")
    x, y = (t, a) if swap else (a, t)
    return R.reconcile(x, y, pin_path=pin_path)


def head_of(path, rows):
    from arcaeon.record.ledger import chain_at
    return chain_at(path, rows)


# -- the failure cases, as data, so the break arms can replay them -----------
# Each builder takes tmp_path and returns (Reconciliation, expected_verdict,
# expected_at, expected_side). `None` in an expected slot means "not checked".

def c_tool_truncated_tail(tmp):
    a, t = pair(tmp)
    return run(tmp, a, t[:3]), R.MISSING, 4, "tool"


def c_agent_truncated_tail(tmp):
    a, t = pair(tmp)
    return run(tmp, a[:2], t), R.MISSING, 3, "agent"


def c_dropped_in_transit_mid(tmp):
    # The tool never saw agent call 3, so it numbers agent-4 as its own 3.
    a, _ = pair(tmp)
    t = [row("tool", i, req(k), resp(k)) for i, k in enumerate([1, 2, 4, 5], start=1)]
    return run(tmp, a, t), R.MISSING, 3, "tool"


def c_extra_on_tool_side(tmp):
    # The tool served a call the agent tape never recorded (injected upstream of it).
    _, t = pair(tmp)
    a = [row("agent", i, req(k), resp(k)) for i, k in enumerate([1, 2, 4, 5], start=1)]
    return run(tmp, a, t), R.MISSING, 3, "agent"


def c_index_gap(tmp):
    a, t = pair(tmp)
    return run(tmp, a[:2] + a[3:], t), R.MISSING, 3, "agent"


def c_response_lost(tmp):
    a, t = pair(tmp)
    a[1] = row("agent", 2, req(2), None)
    return run(tmp, a, t), R.MISSING, 2, "agent"


def c_empty_tool_tape(tmp):
    a, _ = pair(tmp)
    return run(tmp, a, []), R.MISSING, 1, "tool"


def c_response_altered(tmp):
    a, t = pair(tmp)
    a[2] = row("agent", 3, req(3), resp(3, " (edited in transit)"))
    return run(tmp, a, t), R.ALTERED, 3, None


def c_request_altered(tmp):
    a, t = pair(tmp)
    t[3] = row("tool", 4, digest_json({"name": "echo", "arguments": {"text": "rm -rf"}}), resp(4))
    return run(tmp, a, t), R.ALTERED, 4, None


def c_duplicate_index(tmp):
    a, t = pair(tmp)
    return run(tmp, a[:3] + [row("agent", 3, req(9), resp(9))] + a[3:], t), R.ALTERED, 3, "agent"


def c_reordered_rechained(tmp):
    # Rows moved AND the chain recomputed over the new order: the chain verifies,
    # the index walk does not.
    a, t = pair(tmp)
    return run(tmp, a, [t[0], t[2], t[1], t[3], t[4]]), R.ALTERED, 2, "tool"


def c_content_swapped_rechained(tmp):
    # Indices kept in order, the digests under them swapped, chain recomputed.
    a, t = pair(tmp)
    t[1] = row("tool", 2, req(3), resp(3))
    t[2] = row("tool", 3, req(2), resp(2))
    return run(tmp, a, t), R.ALTERED, 2, None


def c_reordered_raw_lines(tmp):
    a, t = pair(tmp)
    run(tmp, a, t)
    p = tmp / "tool.tape.jsonl"
    lines = p.read_bytes().split(b"\n")
    lines[1], lines[2] = lines[2], lines[1]
    p.write_bytes(b"\n".join(lines))
    return R.reconcile(tmp / "agent.tape.jsonl", p), R.ALTERED, None, "tool"


def c_edited_row_no_rechain(tmp):
    a, t = pair(tmp)
    run(tmp, a, t)
    p = tmp / "agent.tape.jsonl"
    p.write_bytes(p.read_bytes().replace(resp(2).encode(), resp(2, "x").encode()))
    return R.reconcile(p, tmp / "tool.tape.jsonl"), R.ALTERED, 2, "agent"


def c_torn_tail(tmp):
    a, t = pair(tmp)
    run(tmp, a, t)
    p = tmp / "tool.tape.jsonl"
    b = p.read_bytes().rstrip(b"\n")
    p.write_bytes(b[:-25])     # cut mid-row: a crash or a clumsy truncation
    return R.reconcile(tmp / "agent.tape.jsonl", p), R.ALTERED, 5, "tool"


def c_both_truncated_in_agreement_with_pin(tmp):
    # Colluding (or co-crashing) truncation: without a pin this MATCHES 3 of 3.
    a, t = pair(tmp)
    write(tmp / "full.agent.jsonl", a)
    pin = {"namespace": "demo-agent", "rows": 5, "chain": head_of(tmp / "full.agent.jsonl", 5)}
    return run(tmp, a[:3], t[:3], pin=pin), R.MISSING, 4, "agent"


def c_pin_count_beyond_both(tmp):
    # A pin naming neither namespace is held against both tapes; it counts 7,
    # both tapes hold 5.
    a, t = pair(tmp)
    pin = {"namespace": "someone-else", "rows": 7, "chain": "0" * 32}
    return run(tmp, a, t, pin=pin), R.MISSING, 6, "both"


def c_rewritten_after_pin(tmp):
    # The tool tape is rewritten (chain recomputed) after its head was pinned at
    # call 4; the rewrite is invisible to verify_file and to the other tape if
    # the agent tape was rewritten to agree, but not to the pin.
    a, t = pair(tmp)
    write(tmp / "orig.tool.jsonl", t)
    pin = {"tool": {"namespace": "demo-tool", "rows": 4,
                    "chain": head_of(tmp / "orig.tool.jsonl", 4)}}
    a[1] = row("agent", 2, req(2), resp(2, "!"))
    t[1] = row("tool", 2, req(2), resp(2, "!"))
    return run(tmp, a, t, pin=pin), R.ALTERED, 4, "tool"


FAILURE_CASES = [c_tool_truncated_tail, c_agent_truncated_tail, c_dropped_in_transit_mid,
                 c_extra_on_tool_side, c_index_gap, c_response_lost, c_empty_tool_tape,
                 c_response_altered, c_request_altered, c_duplicate_index,
                 c_reordered_rechained, c_content_swapped_rechained, c_reordered_raw_lines,
                 c_edited_row_no_rechain, c_torn_tail,
                 c_both_truncated_in_agreement_with_pin, c_pin_count_beyond_both,
                 c_rewritten_after_pin]


def c_missing_file(tmp):
    a, _ = pair(tmp)
    return run(tmp, a, None), R.COULD_NOT_LOOK, None, None


def c_both_empty(tmp):
    r = run(tmp, [], [])
    assert "both tapes are empty" in r.reason, r.reason   # empty, not merely absent
    return r, R.COULD_NOT_LOOK, None, None


def c_not_a_tape(tmp):
    a, _ = pair(tmp)
    write(tmp / "seam.jsonl", [{"evt": "tool_call", "seam": "mcp-stdio", "seq": 1}])
    return R.reconcile(write(tmp / "a.jsonl", a), tmp / "seam.jsonl"), R.COULD_NOT_LOOK, None, None


def c_same_side_twice(tmp):
    a, _ = pair(tmp)
    return R.reconcile(write(tmp / "a1.jsonl", a), write(tmp / "a2.jsonl", a)), \
        R.COULD_NOT_LOOK, None, None


def c_pin_unreadable(tmp):
    a, t = pair(tmp)
    return run(tmp, a, t, pin="{not json"), R.COULD_NOT_LOOK, None, None


def c_directory_as_tape(tmp):
    a, _ = pair(tmp)
    (tmp / "adir").mkdir()
    return R.reconcile(write(tmp / "a.jsonl", a), tmp / "adir"), R.COULD_NOT_LOOK, None, None


CNL_CASES = [c_missing_file, c_both_empty, c_not_a_tape, c_same_side_twice,
             c_pin_unreadable, c_directory_as_tape]


def _check(case, tmp):
    r, verdict, at, side = case(tmp)
    assert r.verdict == verdict, f"{case.__name__}: {r.summary}"
    if at is not None:
        assert r.at == at, f"{case.__name__}: at={r.at}, wanted {at}: {r.summary}"
    if side is not None:
        assert r.side == side, f"{case.__name__}: side={r.side}, wanted {side}: {r.summary}"
    assert r.exit_code == R.EXIT_CODES[verdict]
    assert not r, "a non-MATCHED reconciliation must be falsy"
    return r


@pytest.mark.parametrize("case", FAILURE_CASES + CNL_CASES, ids=lambda c: c.__name__)
def test_bad_pair_is_never_matched(case, tmp_path):
    _check(case, tmp_path)


# -- positive controls -------------------------------------------------------

def test_positive_control_matched_n_of_n(tmp_path):
    a, t = pair(tmp_path, 6)
    r = run(tmp_path, a, t)
    assert r.verdict == R.MATCHED and r.matched == 6 and r.exit_code == 0
    assert r.summary == "MATCHED 6 of 6"
    assert bool(r) and not r.findings and not r.could_not_look


def test_positive_control_argument_order_does_not_matter(tmp_path):
    a, t = pair(tmp_path, 4)
    assert run(tmp_path, a, t, swap=True).summary == "MATCHED 4 of 4"


def test_positive_control_with_agreeing_pins(tmp_path):
    a, t = pair(tmp_path, 5)
    run(tmp_path, a, t)
    pins = {"agent": {"namespace": "demo-agent", "rows": 3,
                      "chain": head_of(tmp_path / "agent.tape.jsonl", 3)},
            "tool": {"namespace": "demo-tool", "rows": 5,
                     "chain": head_of(tmp_path / "tool.tape.jsonl", 5)}}
    (tmp_path / "pin.json").write_text(json.dumps(pins), encoding="utf-8")
    r = R.reconcile(tmp_path / "agent.tape.jsonl", tmp_path / "tool.tape.jsonl",
                    pin_path=tmp_path / "pin.json")
    assert r.verdict == R.MATCHED, r.summary
    assert [p["result"] for p in r.pins_checked] == ["agrees", "agrees"]


def test_truncation_in_agreement_matches_without_a_pin(tmp_path):
    """The honest ceiling, pinned as a test: two tapes cut at the same call agree
    with each other. Only the counter catches it (c_both_truncated_in_agreement_with_pin)."""
    a, t = pair(tmp_path)
    assert run(tmp_path, a[:3], t[:3]).summary == "MATCHED 3 of 3"


def test_every_result_carries_its_limits(tmp_path):
    a, t = pair(tmp_path, 2)
    d = run(tmp_path, a, t).to_dict()
    assert any("colluding" in s for s in d["limits"])
    assert any("never calls" in s for s in d["limits"])


def test_finding_beats_could_not_look(tmp_path):
    """A defect found is a fact even when the other tape is unreachable."""
    a, _ = pair(tmp_path)
    r = R.reconcile(write(tmp_path / "a.jsonl", a[:2] + a[3:]), tmp_path / "gone.jsonl")
    assert r.verdict == R.MISSING and r.at == 3 and r.could_not_look


def test_all_findings_are_listed_not_just_the_first(tmp_path):
    a, t = pair(tmp_path)
    a[1] = row("agent", 2, req(2), resp(2, "x"))
    a[3] = row("agent", 4, req(4), resp(4, "y"))
    r = run(tmp_path, a, t)
    assert r.at == 2 and [f.at for f in r.findings] == [2, 4]


# -- CLI ---------------------------------------------------------------------

@pytest.mark.parametrize("case,code", [(None, 0), (c_tool_truncated_tail, 1),
                                       (c_response_altered, 1), (c_missing_file, 3)])  # arcaeon 0.9: 2 -> 3
def test_cli_exit_codes_and_json(case, code, tmp_path, capsys):
    if case is None:
        a, t = pair(tmp_path, 3)
        run(tmp_path, a, t)
        argv = ["reconcile", str(tmp_path / "agent.tape.jsonl"), str(tmp_path / "tool.tape.jsonl")]
    else:
        case(tmp_path)
        tp = tmp_path / "tool.tape.jsonl"
        argv = ["reconcile", str(tmp_path / "agent.tape.jsonl"),
                str(tp if tp.exists() else tmp_path / "nope-t.jsonl")]
    capsys.readouterr()
    assert cli_main(argv) == code
    out = json.loads(capsys.readouterr().out)
    assert out["exit_code"] == code and out["verdict"] in R.EXIT_CODES


def test_cli_pin_flag(tmp_path, capsys):
    r, *_ = c_pin_count_beyond_both(tmp_path)
    capsys.readouterr()
    code = cli_main(["reconcile", str(tmp_path / "agent.tape.jsonl"),
                     str(tmp_path / "tool.tape.jsonl"), "--pin", str(tmp_path / "pin.json")])
    assert code == 1 and json.loads(capsys.readouterr().out)["side"] == "both"


def test_cli_usage_is_not_a_green(capsys):
    assert cli_main(["reconcile", "only-one.jsonl"]) == 2


# -- break arms --------------------------------------------------------------

def _always_matched(a, b, **kw):
    return R.Reconciliation(verdict=R.MATCHED, matched=5, reason="liar")


@pytest.mark.parametrize("case", FAILURE_CASES + CNL_CASES, ids=lambda c: c.__name__)
def test_breakarm_always_matched_fails_every_case(case, tmp_path, monkeypatch):
    monkeypatch.setattr(R, "reconcile", _always_matched)
    with pytest.raises(AssertionError):
        _check(case, tmp_path)


_real = R.reconcile


def _altered_filed_as_missing(a, b, **kw):
    r = _real(a, b, **kw)
    if r.verdict == R.ALTERED:
        r.verdict = R.MISSING
    return r


@pytest.mark.parametrize("case", [c for c in FAILURE_CASES
                                  if c.__name__ in {"c_response_altered", "c_request_altered",
                                                    "c_duplicate_index", "c_torn_tail",
                                                    "c_rewritten_after_pin"}],
                         ids=lambda c: c.__name__)
def test_breakarm_blurring_altered_into_missing_is_caught(case, tmp_path, monkeypatch):
    monkeypatch.setattr(R, "reconcile", _altered_filed_as_missing)
    with pytest.raises(AssertionError):
        _check(case, tmp_path)
