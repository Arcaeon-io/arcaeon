"""Hypothesis-driven property tests for arcaeon_compact's core invariants.

Complements test_compact.py's hand-written cases (which pin specific named
scenarios) with generated-input coverage over three invariants called out for
this pass — arcaeon-compact was dogfooded but had no property/mutation
coverage of its own before now:

  1. SEAL/VERIFY ROUND-TRIP DETERMINISM. `seal()` is a pure function of
     (pre_content, post_content, compactor, method) modulo the wall-clock
     `ts`/`opened_at` and the ledger `chain` link: sealing the same content
     twice, into two independent ledgers, must produce identical
     `receipt_digest` and identical `pre`/`post`/`dropped`/`introduced`
     blocks. And for ANY generated pre/post content, a freshly sealed row
     must self-verify AND recompute-verify against that same content.

  2. THE v2 UNDERSTATEMENT GUARANTEE (HIGH-1, 2026-08-15). `introduced.bytes`
     is computed for real from the actual post-content handed to
     `record_kept()` — not a number a caller can hand-wave — so it can never
     UNDER-claim what a compaction introduced. Property-tested two ways:
     (a) positive — for any generated content, `introduced.bytes` equals an
     independently-recomputed value (not seal()'s own arithmetic, a parallel
     computation from `_digest_content`), for any split of pre into
     kept+dropped plus any extra "introduced" items; (b) negative — forging
     `dropped.bytes` OR `introduced.bytes` away from the honest value (either
     direction, any nonzero delta) breaks `verify_receipt`'s v2 byte
     reconciliation with no content held. This generalizes
     test_compact.py's test_high1_understated_dropped_bytes_behind_introduction_is_caught
     from one hand-picked case to an adversarially-searched space.

  3. THE U+0085/U+2028/U+2029 JSONL CLASS. arcaeon_compact writes receipts
     exclusively through `arcaeon_ledger.Ledger.append()` (ensure_ascii=False,
     writes the row's own free-text fields raw) and never reads its own
     JSONL — reading is entirely arcaeon_ledger's job (`Ledger.__iter__`,
     `verify_file`, `chain_at`, all fixed to split("\\n") not splitlines() as
     of this pass; see arcaeon-ledger's own test_hypothesis_ledger.py for the
     read-side property tests). CONTENT items never land in the row at all —
     only their digests do (privacy by construction, see the module
     docstring) — so the only free-text surface that can carry one of these
     characters into the actual JSONL bytes is `compactor`/`method`. That is
     exactly what this test targets: seal a receipt whose compactor/method
     strings are laced with the NEL/LINE SEPARATOR/PARAGRAPH SEPARATOR class,
     round-trip it through a REAL Ledger file, and confirm the row reads back
     byte-identical, the chain verifies, and verify_receipt still passes.

Run: python -m pytest test_hypothesis_compact.py -q
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from hypothesis import given, assume, settings, HealthCheck, strategies as st

from arcaeon.record.ledger import Ledger
from arcaeon.prove.compact import (
    CompactionReceipt, verify_receipt, SCHEMA_V2, _core_body, _digest_content,
)


# --- strategies --------------------------------------------------------------

_safe_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), max_codepoint=0xFFFF),
    max_size=20,
)

_json_scalar = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-10**9, max_value=10**9),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    _safe_text,
)

# Recursive JSON value (covers the third branch of _digest_item: anything
# that isn't bytes/bytearray/str gets json-c14n digested). max_leaves kept
# small -- this is fuzzing the classification logic, not stress-testing
# json.dumps.
_json_value = st.recursive(
    _json_scalar,
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(_safe_text, children, max_size=3),
    ),
    max_leaves=5,
)

# A content item exercises all three _digest_item branches: str (utf-8 raw),
# bytes (raw), and "anything else" (json-c14n). Excludes NaN/Infinity (out of
# scope for these three invariants; _digest_item's allow_nan=False already
# refuses them by design, not a bug this pass is chasing).
_content_item = st.one_of(_safe_text, st.binary(max_size=20), _json_value)


@st.composite
def _pre_kept_extra(draw, max_pre=6, max_extra=3):
    """(pre, kept-subset-of-pre, extra-introduced-items).

    `kept` is pre with an arbitrary boolean mask applied (duplicates and
    order preserved) -- a legitimate "some items survived, some didn't"
    split. `extra` stands in for compactor-introduced content (typically
    summary text) that never appeared in pre. post_content = kept + extra.
    """
    pre = draw(st.lists(_content_item, max_size=max_pre))
    mask = draw(st.lists(st.booleans(), min_size=len(pre), max_size=len(pre)))
    kept = [item for item, keep in zip(pre, mask) if keep]
    extra = draw(st.lists(_content_item, max_size=max_extra))
    return pre, kept, extra


# The exact characters implicated in the U+2028-class bug: NOT escaped by
# json.dumps(ensure_ascii=False) (they sit outside the mandatory
# U+0000-U+001F escape range) but treated as row/line boundaries by
# str.splitlines() -- distinct from the literal "\n" the ledger writer
# actually emits as its row delimiter. Mirrors arcaeon-ledger's own
# LINE_BOUNDARY_LOOKALIKES set.
_LOOKALIKES = "\x85  \x0b\x0c\x1c\x1d\x1e"


@st.composite
def _tricky_label(draw, min_segments=1, max_segments=4):
    """A free-text label (stand-in for compactor/method) built from ordinary
    word-ish segments interleaved with U+0085/U+2028/U+2029/C0-separator
    characters -- the class that round-trips raw into JSONL row content
    under ensure_ascii=False but is NOT the writer's own "\\n" delimiter."""
    segments = draw(st.lists(
        st.text(alphabet=st.characters(blacklist_categories=("Cs", "Cc"),
                                        max_codepoint=0x2100),
                min_size=1, max_size=6),
        min_size=min_segments, max_size=max_segments,
    ))
    seps = draw(st.lists(st.sampled_from(_LOOKALIKES),
                          min_size=max(len(segments) - 1, 0),
                          max_size=max(len(segments) - 1, 0)))
    out = segments[0]
    for seg, sep in zip(segments[1:], seps):
        out += sep + seg
    return out


# --- 1. seal/verify round-trip determinism -----------------------------------

@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(_pre_kept_extra())
def test_seal_then_verify_roundtrips_for_any_content(pke):
    pre, kept, extra = pke
    post = kept + extra
    with tempfile.TemporaryDirectory() as d:
        r = CompactionReceipt.open(pre)
        r.record_kept(post)
        row = r.seal(Path(d) / "l.jsonl", compactor="c", method="m")

    assert row["schema"] == SCHEMA_V2
    # self-consistency needs no content
    v0 = verify_receipt(row)
    assert v0["ok"] and v0["self_consistent"], v0["notes"]
    # recompute-verify against the exact content used to build it
    v1 = verify_receipt(row, pre, post)
    assert v1["ok"] and v1["content"] == "match", v1["notes"]


@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(_pre_kept_extra())
def test_seal_is_a_pure_function_of_its_content(pke):
    """Sealing identical (pre, post, compactor, method) twice -- into two
    independent ledger files -- must produce an identical deterministic core
    (and therefore identical receipt_digest), regardless of the wall-clock
    ts/opened_at or the per-ledger chain link, which are the only fields
    allowed to differ."""
    pre, kept, extra = pke
    post = kept + extra
    with tempfile.TemporaryDirectory() as d:
        r1 = CompactionReceipt.open(pre)
        r1.record_kept(post)
        row1 = r1.seal(Path(d) / "a.jsonl", compactor="same-c", method="same-m")

        r2 = CompactionReceipt.open(pre)
        r2.record_kept(post)
        row2 = r2.seal(Path(d) / "b.jsonl", compactor="same-c", method="same-m")

    assert _core_body(row1) == _core_body(row2)
    assert row1["receipt_digest"] == row2["receipt_digest"]


# --- 2. the v2 understatement guarantee --------------------------------------

@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(_pre_kept_extra())
def test_introduced_bytes_matches_independent_recomputation(pke):
    """Positive half of HIGH-1: introduced.bytes is never a caller-suppliable
    number -- recompute it independently (via _digest_content, the same
    primitive seal() uses internally, but driven fresh here rather than
    trusting seal()'s own arithmetic) and require an EXACT match, not just
    a lower bound. An implementation that ever under-reports what a
    compaction introduced fails this test."""
    pre, kept, extra = pke
    post = kept + extra
    with tempfile.TemporaryDirectory() as d:
        r = CompactionReceipt.open(pre)
        r.record_kept(post)
        row = r.seal(Path(d) / "l.jsonl", compactor="c", method="m")

    # Independent recomputation: what pre/post digest to, and which post
    # items are "leftover" (introduced) once kept items are matched off.
    from collections import Counter
    pre_digests, pre_sizes, _, _ = _digest_content(pre)
    post_digests, post_sizes, _, _ = _digest_content(post)
    remaining = Counter(post_digests)
    for d_ in pre_digests:
        if remaining[d_] > 0:
            remaining[d_] -= 1
    size_by_digest = {}
    for d_, n in zip(post_digests, post_sizes):
        size_by_digest.setdefault(d_, n)
    expected_introduced_bytes = sum(
        cnt * size_by_digest[d_] for d_, cnt in remaining.items() if cnt > 0)
    expected_introduced_count = sum(remaining.values())

    assert row["introduced"]["count"] == expected_introduced_count
    assert row["introduced"]["bytes"] == expected_introduced_bytes
    # the never-understate guarantee, stated as an inequality too, so a
    # future refactor that only breaks the >= direction still fails loudly
    assert row["introduced"]["bytes"] >= expected_introduced_bytes


def _forge(row, **overrides):
    """Rewrite a row's core and re-seal its receipt_digest -- exactly the
    move any editor of a raw row can make (mirrors test_compact.py's
    private _forge helper)."""
    import json
    from arcaeon.record.ledger import digest_json
    forged = json.loads(json.dumps(row))
    forged.update(json.loads(json.dumps(overrides)))
    forged["receipt_digest"] = digest_json(_core_body(forged))
    return forged


@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(_pre_kept_extra(), st.integers(min_value=1, max_value=500))
def test_forged_dropped_bytes_is_caught(pke, delta):
    """Negative half of HIGH-1, generalized: forge dropped.bytes away from
    the honest value by ANY nonzero delta (both directions) while leaving
    introduced.bytes at its true value -- verify_receipt's v2 byte
    reconciliation must catch it with no content held, every time."""
    pre, kept, extra = pke
    post = kept + extra
    with tempfile.TemporaryDirectory() as d:
        r = CompactionReceipt.open(pre)
        r.record_kept(post)
        honest = r.seal(Path(d) / "l.jsonl", compactor="c", method="m")
    assert verify_receipt(honest)["self_consistent"]

    for sign in (1, -1):
        forged_bytes = honest["dropped"]["bytes"] + sign * delta
        assume(forged_bytes >= 0)  # negative bytes is a different, also-caught check
        assume(forged_bytes != honest["dropped"]["bytes"])
        liar = _forge(honest, dropped={**honest["dropped"], "bytes": forged_bytes})
        v = verify_receipt(liar)
        assert not v["self_consistent"], (sign, delta, v)
        assert v["schema"] == "v2"


@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(_pre_kept_extra(), st.integers(min_value=1, max_value=500))
def test_forged_understated_introduced_bytes_is_caught(pke, delta):
    """The exact HIGH-1 shape stated directly: understating introduced.bytes
    (claiming the compaction introduced FEWER bytes than it really did)
    while dropped.bytes stays honest must break v2 reconciliation. This is
    the guarantee the prompt names: introduced.bytes can never claim less
    than reality and still verify clean."""
    pre, kept, extra = pke
    post = kept + extra
    with tempfile.TemporaryDirectory() as d:
        r = CompactionReceipt.open(pre)
        r.record_kept(post)
        honest = r.seal(Path(d) / "l.jsonl", compactor="c", method="m")
    assume(honest["introduced"]["bytes"] > 0)
    assert verify_receipt(honest)["self_consistent"]

    understate_by = min(delta, honest["introduced"]["bytes"])
    assume(understate_by > 0)
    liar = _forge(honest, introduced={
        **honest["introduced"], "bytes": honest["introduced"]["bytes"] - understate_by})
    v = verify_receipt(liar)
    assert not v["self_consistent"], v
    assert any("bytes do not reconcile" in n for n in v["notes"]), v["notes"]


# --- 3. the U+0085/U+2028/U+2029 JSONL class ---------------------------------

@settings(suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(_tricky_label(), _tricky_label())
def test_unicode_lineseparator_class_survives_the_ledger_roundtrip(compactor, method):
    """compactor/method are the only free-text fields that land raw in the
    JSONL bytes (content is digest-only by design -- see module docstring).
    Lace both with the NEL/LINE-SEPARATOR/PARAGRAPH-SEPARATOR class and
    confirm: seals clean, the row reads back byte-identical through
    arcaeon_ledger's real Ledger, the chain verifies, and verify_receipt
    still passes against the original content."""
    pre = ["a", "b"]
    post = ["a", "summary"]
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "l.jsonl"
        r = CompactionReceipt.open(pre)
        r.record_kept(post)
        row = r.seal(path, compactor=compactor, method=method)

        led = Ledger(path)
        rows_back = list(led)
        assert len(rows_back) == 1, (
            f"row split into {len(rows_back)} lines on read-back -- the "
            "U+2028-class bug is back")
        assert rows_back[0] == row
        vr = led.verify()
        assert vr.ok, vr

    v = verify_receipt(row, pre, post)
    assert v["ok"] and v["content"] == "match", v["notes"]


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
