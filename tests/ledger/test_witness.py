# SPDX-License-Identifier: MIT
"""Tests for arcaeon_ledger.witness — the outside check that closes truncation.

The load-bearing test is the one the chain ALONE cannot pass: a truncated log
still self-verifies (proved in test_ledger.py), but the external witness catches
it. Also: rewrite detection, the honest 'consistent-and-grown' case, and
'no_record' never returning a false ok. Run: python test_witness.py
"""
import tempfile
from pathlib import Path

from arcaeon.record.ledger import (Head, Ledger, WitnessStore, publish_head,
                            verify_against_witness, chain_at)


def _log_with(d, name, n):
    log = Ledger(Path(d) / name)
    for i in range(n):
        log.append({"event": i})
    return log


def test_witness_catches_truncation_that_chain_misses():
    with tempfile.TemporaryDirectory() as d:
        log = _log_with(d, "log.jsonl", 6)
        store = WitnessStore(Path(d) / "witness.jsonl")
        publish_head(store, "agent-7", log)          # witness records (rows=6, chain=...)

        # truncate: drop the last two rows
        p = log.path
        lines = p.read_text(encoding="utf-8").splitlines()
        p.write_text("\n".join(lines[:-2]) + "\n", encoding="utf-8")

        # the chain alone still says clean — that's the gap
        assert log.verify().ok, "truncated remainder self-verifies (the whole point)"

        # the witness catches it
        v = verify_against_witness(store, "agent-7", log)
        assert v.verdict == "truncated", v
        assert not v, "a truncated verdict must be falsy"
        assert v.witness_rows == 6 and v.local_rows == 4, v
    print("PASS witness catches truncation the chain alone misses")


def test_witness_catches_truncation_of_exactly_one_row():
    """The boundary case, not just the comfortable one: lop off exactly the
    LAST witnessed row (not two, not a full rewrite) and the witness must
    still call it 'truncated' THROUGH THE ROW-COUNT CHECK -- not by accident
    via the separate 'row unreachable' fallback a few lines down, which (for
    any truncation at all) also independently lands on verdict=='truncated'
    and would mask a weakened `local_rows < w_rows` comparison from a verdict
    -only assertion. The two branches emit different `detail` text, so pinning
    the row-count branch's exact wording is what actually distinguishes a
    `local_rows < w_rows` comparison loosened by one (e.g. to `w_rows - 1`)
    from the honest check: loosened by one, this exact single-row truncation
    no longer trips the primary check and 'truncated' would come from the
    fallback's 'cannot reach row N' wording instead."""
    with tempfile.TemporaryDirectory() as d:
        log = _log_with(d, "log.jsonl", 6)
        store = WitnessStore(Path(d) / "witness.jsonl")
        publish_head(store, "agent-7", log)          # witness pins rows=6

        # truncate by exactly ONE row
        p = log.path
        lines = p.read_text(encoding="utf-8").splitlines()
        p.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

        assert log.verify().ok, "truncated remainder self-verifies (the whole point)"

        v = verify_against_witness(store, "agent-7", log)
        assert v.verdict == "truncated", v
        assert not v, "a truncated verdict must be falsy"
        assert v.witness_rows == 6 and v.local_rows == 5, v
        # pin the ROW-COUNT branch specifically, not the unreachable-row fallback
        assert v.detail == (
            "log has 5 rows but the witness recorded 6: "
            "1 witnessed row(s) are missing (truncation)"), v.detail
    print("PASS witness catches truncation of exactly one row via the row-count check")


def test_witness_consistent_when_untouched():
    with tempfile.TemporaryDirectory() as d:
        log = _log_with(d, "log.jsonl", 5)
        store = WitnessStore(Path(d) / "w.jsonl")
        publish_head(store, "ns", log)
        v = verify_against_witness(store, "ns", log)
        assert v.verdict == "consistent" and bool(v) is True, v
    print("PASS untouched log verifies consistent against the witness")


def test_witness_consistent_after_growth():
    with tempfile.TemporaryDirectory() as d:
        log = _log_with(d, "log.jsonl", 3)
        store = WitnessStore(Path(d) / "w.jsonl")
        publish_head(store, "ns", log)               # pinned at 3 rows
        for i in range(4):
            log.append({"more": i})                  # grow to 7
        v = verify_against_witness(store, "ns", log)
        assert v.verdict == "consistent", v
        assert v.witness_rows == 3 and v.local_rows == 7, v
        assert "grown" in v.detail
    print("PASS growth since the pin is consistent (not a false alarm)")


def test_witness_catches_rewrite():
    with tempfile.TemporaryDirectory() as d:
        log = _log_with(d, "log.jsonl", 5)
        store = WitnessStore(Path(d) / "w.jsonl")
        publish_head(store, "ns", log)               # pin (rows=5, chain=X)

        # rewrite from genesis with different content but a fresh, self-consistent chain
        p = Path(d) / "log.jsonl"
        p.unlink()
        rewritten = Ledger(p)
        for i in range(5):
            rewritten.append({"event": i + 100})     # different payloads -> different chain
        assert rewritten.verify().ok, "a re-minted log self-verifies (why the witness is needed)"

        v = verify_against_witness(store, "ns", rewritten)
        assert v.verdict == "rewritten", v
        assert not v
    print("PASS witness catches a full rewrite (same row count, different chain)")


def test_witness_rewrite_check_is_full_width_not_prefix():
    """The rewrite check must compare the FULL chain string, not a short
    prefix. Forge a witness pin whose chain shares the log's real chain's
    first 8 hex characters at the witnessed row but differs after that -- an
    8-hex-char prefix compare (a 32-bit space, well within reach of a
    deliberate second-preimage search on commodity hardware) would wrongly
    call this 'consistent'. A full-width compare must still call it
    'rewritten'."""
    with tempfile.TemporaryDirectory() as d:
        log = _log_with(d, "log.jsonl", 5)
        real_head = log.head()
        real_chain = real_head.chain

        # forge a pin sharing real_chain's first 8 hex chars but differing
        # over the remainder -- exactly the collision an 8-char prefix
        # compare cannot distinguish from the honest pin.
        tail = "0" * (len(real_chain) - 8)
        if real_chain[8:] == tail:
            tail = "1" * (len(real_chain) - 8)
        forged_chain = real_chain[:8] + tail
        assert forged_chain != real_chain
        assert forged_chain[:8] == real_chain[:8]

        forged_head = Head(chain=forged_chain, rows=real_head.rows,
                           as_of=real_head.as_of)
        store = WitnessStore(Path(d) / "w.jsonl")
        store.record("ns", forged_head)       # a pin the real log never produced

        v = verify_against_witness(store, "ns", log)
        assert v.verdict == "rewritten", v
        assert not v, "a rewritten verdict must be falsy"
    print("PASS rewrite check compares the full chain, not an 8-char prefix")


def test_no_record_is_not_a_false_ok():
    with tempfile.TemporaryDirectory() as d:
        log = _log_with(d, "log.jsonl", 2)
        store = WitnessStore(Path(d) / "w.jsonl")
        v = verify_against_witness(store, "never-pinned", log)
        assert v.verdict == "no_record" and bool(v) is False, v
    print("PASS a namespace the witness never saw returns no_record, never a false ok")


def test_chain_at_matches_head():
    with tempfile.TemporaryDirectory() as d:
        log = _log_with(d, "log.jsonl", 4)
        h = log.head()
        # chain_at(total rows) must equal the head's chain
        assert chain_at(log.path, h.rows) == h.chain
        assert chain_at(log.path, 99) is None          # beyond the log
        assert chain_at(log.path, 0) == "genesis"
    print("PASS chain_at is consistent with head() and honest past the end")


def test_witness_store_is_append_only_history():
    with tempfile.TemporaryDirectory() as d:
        log = _log_with(d, "log.jsonl", 2)
        store = WitnessStore(Path(d) / "w.jsonl")
        publish_head(store, "ns", log)
        log.append({"event": 99})
        publish_head(store, "ns", log)
        hist = store.history("ns")
        assert len(hist) == 2 and hist[0]["rows"] == 2 and hist[1]["rows"] == 3, hist
        assert store.latest("ns")["rows"] == 3
    print("PASS witness keeps append-only pin history; latest() returns the newest")


def test_witness_verify_not_crash_on_lone_surrogate_pin():
    """2026-09-01 audit finding #1: a FOREIGN-written pin line carrying a lone
    surrogate (the JSON escape backslash-u-d-8-0-0 — legal JSON, emitted by
    JS/Python json by default) parses into a lone-surrogate str, and
    _digest_record's plain .encode() then raised UnicodeEncodeError — the
    OUTSIDE verifier crashing instead of returning a verdict on hostile input,
    the one thing it swears never to do. The pin file is written as raw ASCII
    (the escape sequence, exactly as a hostile third party produces it); verify()
    reads with errors='replace' and must reach a verdict, not a traceback."""
    with tempfile.TemporaryDirectory() as d:
        wpath = Path(d) / "w.jsonl"
        # ASCII bytes: the six-char JSON escape, never our strict write path.
        hostile = '{"namespace":"ns","rows":1,"self":"x","evil":"\\ud800"}\n'
        wpath.write_text(hostile, encoding="ascii")
        store = WitnessStore(wpath)
        v = store.verify()          # pre-fix: UnicodeEncodeError; post-fix: a verdict
        assert v["pins"] == 1, v     # it processed the hostile pin without crashing
    print("PASS witness.verify() returns a verdict (not a crash) on a lone-surrogate pin")


if __name__ == "__main__":
    test_witness_catches_truncation_that_chain_misses()
    test_witness_catches_truncation_of_exactly_one_row()
    test_witness_consistent_when_untouched()
    test_witness_consistent_after_growth()
    test_witness_catches_rewrite()
    test_witness_rewrite_check_is_full_width_not_prefix()
    test_no_record_is_not_a_false_ok()
    test_chain_at_matches_head()
    test_witness_store_is_append_only_history()
    test_witness_verify_not_crash_on_lone_surrogate_pin()
    print("\nALL PASS — the external witness catches truncation AND rewrite that the "
          "chain alone cannot, stays quiet on honest growth, and never returns a false ok.")


def test_witness_skips_non_object_and_hostile_lines_instead_of_crashing():
    """0.7.2 (2026-09-01 audit): a valid-JSON line that is not an object
    ("[]", "42") raised AttributeError out of latest()/history(); a 3000-deep
    array raised RecursionError. A witness log that can be crashed by one
    appended line is a witness that can be silenced. Both now skip."""
    with tempfile.TemporaryDirectory() as d:
        store = WitnessStore(Path(d) / "w.jsonl")
        log = _log_with(d, "a.jsonl", 3)
        publish_head(store, "ns", log)
        with open(store.path, "a", encoding="utf-8") as fh:
            fh.write('[]\n42\n"str"\n' + "[" * 3000 + "]" * 3000 + "\n")
        rec = store.latest("ns")
        assert rec is not None and rec["namespace"] == "ns"
        assert len(store.history("ns")) == 1
