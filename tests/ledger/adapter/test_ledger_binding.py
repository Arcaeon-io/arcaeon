# SPDX-License-Identifier: MIT
"""Tests for the ledger binding, including the claim that degradation is honest.

`_ledger.py` says: if `arcaeon-ledger` is not installed, we still write rows, in
the library's own on-disk shape, using a local implementation of its two frozen
recipes — and a machine that DOES have the library can verify those files later.

That is a strong claim and it would be easy to ship as a comment. So it is tested:
the fallback writer and the real `Ledger` are driven over identical rows and their
files must come out byte-identical (modulo the `ts` stamp, which is a clock read).
If the recipes ever drift apart, this goes red here rather than silently producing
a second, incompatible dialect of "arcaeon ledger" in the field.

Run: pytest -q
"""
import json

import pytest

from arcaeon.record.adapter import _ledger as L


def test_backend_names_which_writer_is_live():
    """A reviewer must never have to guess which implementation made the chain."""
    b = L.backend()
    assert b.startswith("arcaeon-ledger/") or b == "fallback-jsonl/1"


def test_canon_json_is_the_frozen_recipe():
    assert L.canon_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'
    assert L.canon_json({"u": "é🔒"}) == '{"u":"é🔒"}'.encode("utf-8")  # not \\u escaped
    with pytest.raises(ValueError):
        L.canon_json({"bad": float("nan")})   # no token other languages can't parse


def test_digest_is_self_describing_never_a_bare_hash():
    d = L.digest_json({"a": 1})
    algo, recipe, ver, hexpart = d.split(":")
    assert (algo, recipe, ver) == ("sha256", "json-c14n", "v1")
    assert len(hexpart) == 64 and int(hexpart, 16) >= 0


def test_digest_matches_the_frozen_golden_vector():
    assert L.digest_json({"b": 2, "a": 1}) == (
        "sha256:json-c14n:v1:"
        "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777")


def test_fallback_chain_is_byte_compatible_with_the_real_ledger(tmp_path):
    """The degradation claim, actually checked."""
    real_cls = L._RealLedger
    if real_cls is None:                      # pragma: no cover
        pytest.skip("arcaeon-ledger not installed; nothing to compare against")

    rows = [{"evt": "session_begin", "seq": 1, "ts": "2026-08-19T00:00:00Z"},
            {"evt": "tool_call", "seq": 2, "tool": "echo", "ts": "2026-08-19T00:00:01Z"},
            {"evt": "session_end", "seq": 3, "ts": "2026-08-19T00:00:02Z"}]

    a, b = tmp_path / "real.jsonl", tmp_path / "fallback.jsonl"
    real, fake = real_cls(a), L._FallbackLedger(b)
    for r in rows:
        ca, cb = real.append(dict(r)), fake.append(dict(r))
        assert ca == cb, f"chain hash diverged on {r['evt']}: {ca} vs {cb}"
    assert a.read_bytes() == b.read_bytes()


def test_fallback_resumes_an_existing_chain(tmp_path):
    """Appending to a file the real library wrote must continue its chain, not fork
    one — the failure mode that makes earlier rows quietly detachable."""
    real_cls = L._RealLedger
    if real_cls is None:                      # pragma: no cover
        pytest.skip("arcaeon-ledger not installed")
    p = tmp_path / "mixed.jsonl"
    real_cls(p).append({"evt": "written_by_library"})
    L._FallbackLedger(p).append({"evt": "written_by_fallback"})
    v = L.verify_seam_log(p)
    assert v.ok is True, v


def test_fallback_verifier_catches_an_edited_row(tmp_path):
    """The fallback verifier exists so `selftest` still observes tampering being
    caught on a machine without the library. It must actually catch it."""
    p = tmp_path / "f.jsonl"
    log = L._FallbackLedger(p)
    for i in range(4):
        log.append({"evt": "tool_call", "n": i})
    lines = [l for l in p.read_text(encoding="utf-8").split("\n") if l.strip()]
    obj = json.loads(lines[1])
    obj["n"] = 999
    lines[1] = json.dumps(obj, ensure_ascii=False)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Verify with the fallback verifier explicitly, regardless of what's installed.
    saved = L._HAVE_LEDGER
    try:
        L._HAVE_LEDGER = False
        v = L.verify_seam_log(p)
    finally:
        L._HAVE_LEDGER = saved
    assert v.ok is False
    assert v.first_break == "line 2: chain mismatch"   # same string either way
    assert not v                                        # falsy, so `if v:` fails safe


def test_verify_reports_a_missing_file_as_a_failure_not_a_green(tmp_path):
    saved = L._HAVE_LEDGER
    try:
        L._HAVE_LEDGER = False
        v = L.verify_seam_log(tmp_path / "nope.jsonl")
    finally:
        L._HAVE_LEDGER = saved
    assert v.ok is False and "unreadable" in v.first_break


def test_open_ledger_creates_parent_directories(tmp_path):
    """A `--ledger logs/seam.jsonl` into a non-existent dir must not kill a session."""
    log = L.open_ledger(tmp_path / "deep" / "nested" / "seam.jsonl")
    log.append({"evt": "session_begin"})
    assert (tmp_path / "deep" / "nested" / "seam.jsonl").exists()


def test_fallback_ledger_and_verifier_survive_an_over_deep_line(tmp_path):
    """2026-09-01 audit (adapter #1/#2): one deeply nested JSON line in the
    ledger file raised RecursionError out of _last_chain() -> append() ->
    session_begin() -> the proxy died before the child spawned. And the
    fallback verifier raised instead of returning a verdict on the same line."""
    p = tmp_path / "f.jsonl"
    log = L._FallbackLedger(p)
    log.append({"evt": "tool_call", "n": 0})
    deep = "[" * 200_000 + "]" * 200_000
    with p.open("a", encoding="utf-8") as fh:
        fh.write('{"evt":"x","payload":' + deep + ',"chain":"deadbeef"}' + "\n")
    chain = L._FallbackLedger(p).append({"evt": "session_begin"})   # must not raise
    assert chain
    saved = L._HAVE_LEDGER
    try:
        L._HAVE_LEDGER = False
        v = L.verify_seam_log(p)
    finally:
        L._HAVE_LEDGER = saved
    assert v.ok is False
    assert "unparseable" in (v.first_break or "")


# --- ported 2026-09-04 from the fenced standalone checkout (board item 54) ----
# These four landed in the standalone arcaeon-adapter checkout (commit 5afb00b, 2026-08-28)
# alongside the _ledger.py fix they watch. The FIX was ported here; the TESTS were
# not, so from 0.1.2 through 0.1.3 the three-valued verdict shipped with nothing
# holding it. That is the exact shape this package sells against: a green nobody
# checked. Ported verbatim before the fenced tree is deleted, because a deletion
# that drops the only coverage of a shipped behavior is a silent regression.


def test_empty_seam_log_is_not_a_green(tmp_path):
    """A scan that checked ZERO rows must not report `ok is True`.

    An empty seam log is this package's own signature failure: the proxy came
    up, the observer recorded nothing, and the file sat there at zero bytes.
    Reporting that as verified-clean is the worst possible answer, because it is
    indistinguishable from "I checked everything and it was fine". The library's
    `verify_file` returns ok=None / verified_scope="empty" here; the fallback
    must not be more generous than the thing it stands in for.
    """
    p = tmp_path / "empty.jsonl"
    p.write_text("", encoding="utf-8")
    saved = L._HAVE_LEDGER
    try:
        L._HAVE_LEDGER = False
        v = L.verify_seam_log(p)
    finally:
        L._HAVE_LEDGER = saved
    assert v.ok is None, f"empty scan minted ok={v.ok!r}"
    assert v.verified_scope == "empty"
    assert v.rows == 0
    assert not v, "an empty scan must be falsy so `if v:` fails safe"


def test_whitespace_only_seam_log_is_not_a_green(tmp_path):
    """Same rule, but the file has bytes in it - none of them rows."""
    p = tmp_path / "ws.jsonl"
    p.write_text("\n\n   \n", encoding="utf-8")
    saved = L._HAVE_LEDGER
    try:
        L._HAVE_LEDGER = False
        v = L.verify_seam_log(p)
    finally:
        L._HAVE_LEDGER = saved
    assert v.ok is None and v.verified_scope == "empty"


def test_fallback_counts_every_break_not_just_the_first(tmp_path):
    """A verdict that reports the first fault teaches its reader there is one fault.

    The library's VerifyResult carries `breaks`; the fallback must too, or a
    reviewer on a machine without arcaeon-ledger sees "line 2" and stops looking.
    """
    p = tmp_path / "f.jsonl"
    log = L._FallbackLedger(p)
    for i in range(6):
        log.append({"evt": "tool_call", "n": i})
    lines = [l for l in p.read_text(encoding="utf-8").split("\n") if l.strip()]
    for idx in (1, 3):                       # TWO tampered rows, not one
        obj = json.loads(lines[idx])
        obj["n"] = 999
        lines[idx] = json.dumps(obj, ensure_ascii=False)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    saved = L._HAVE_LEDGER
    try:
        L._HAVE_LEDGER = False
        v = L.verify_seam_log(p)
    finally:
        L._HAVE_LEDGER = saved
    assert v.ok is False
    assert v.first_break == "line 2: chain mismatch"
    assert v.breaks == 2, f"reported {v.breaks} break(s); the file has 2"
    assert v.verified_scope == "full"


def test_a_good_log_reports_full_scope(tmp_path):
    """The other side of the contract: a real, fully-walked clean scan IS green."""
    p = tmp_path / "good.jsonl"
    log = L._FallbackLedger(p)
    for i in range(3):
        log.append({"evt": "tool_call", "n": i})
    saved = L._HAVE_LEDGER
    try:
        L._HAVE_LEDGER = False
        v = L.verify_seam_log(p)
    finally:
        L._HAVE_LEDGER = saved
    assert v.ok is True and v.verified_scope == "full" and v.breaks == 0
    assert bool(v) is True
