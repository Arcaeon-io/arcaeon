"""Tests for arcaeon-compact — the product claim is "a compactor cannot claim
nothing was dropped while dropping something," so the negative tests (the lie
is CAUGHT) are the load-bearing ones.
Run: python test_compact.py
"""
import json
import tempfile
from pathlib import Path

from arcaeon.record.ledger import Ledger, digest_json
from arcaeon.prove.compact import (
    CompactionReceipt, verify_receipt, SCHEMA, SCHEMA_V1, SCHEMA_V2,
    _core_body, _digest_content,
)

PRE = ["turn 1: hello", {"role": "assistant", "text": "turn 2"},
       b"turn 3 raw", "turn 4: the important one"]
POST = ["turn 1: hello", "summary of turns 2-3"]


def _sealed(tmp, pre=PRE, post=POST, **kw):
    r = CompactionReceipt.open(pre)
    r.record_kept(post)
    kw.setdefault("compactor", "test-compactor")
    kw.setdefault("method", "unit-test")
    return r.seal(Path(tmp) / "receipts.jsonl", **kw)


def test_happy_path_full_verify():
    with tempfile.TemporaryDirectory() as d:
        row = _sealed(d)
        assert row["schema"] == SCHEMA
        assert row["pre"]["count"] == 4 and row["post"]["count"] == 2
        assert row["dropped"]["count"] == 3      # turns 2, 3, 4
        assert row["introduced"]["count"] == 1   # the summary line
        assert len(row["dropped"]["items"]) == 3
        v = verify_receipt(row, PRE, POST)
        assert v["ok"] and v["self_consistent"] and v["content"] == "match", v
    print("PASS happy path: open/record/seal + full content verify")


def test_row_lands_on_ledger_chain():
    with tempfile.TemporaryDirectory() as d:
        row = _sealed(d)
        led = Ledger(Path(d) / "receipts.jsonl")
        assert led.verify().ok
        (stored,) = list(led)
        assert stored == row, "returned row must equal the chained row"
    print("PASS sealed row equals the chained ledger row; chain verifies")


def test_planted_drop_is_caught():
    # The lie: record_kept(everything), ship a survivor missing item 4.
    with tempfile.TemporaryDirectory() as d:
        row = _sealed(d, post=PRE)                 # claims nothing dropped
        v = verify_receipt(row, PRE, PRE[:3])      # reality: one item gone
        assert not v["ok"] and v["content"] == "mismatch", v
        assert any("drop-manifest disagrees" in n for n in v["notes"]), v["notes"]
    print("PASS planted drop caught (claimed 0 dropped, reality says 1)")


def test_row_edit_caught_without_content():
    # Shave one dropped item + fix the counts to stay arithmetic-consistent:
    # the receipt_digest must still catch the edit, even outside the ledger.
    with tempfile.TemporaryDirectory() as d:
        row = json.loads(json.dumps(_sealed(d)))
        row["dropped"]["items"] = row["dropped"]["items"][:-1]
        row["dropped"]["count"] -= 1
        row["introduced"]["count"] -= 1  # keep post - introduced == pre - dropped
        v = verify_receipt(row)
        assert not v["ok"] and not v["self_consistent"], v
        assert any("receipt_digest" in n for n in v["notes"]), v["notes"]
    print("PASS in-row edit caught by receipt_digest (no content, no ledger)")


def test_explicit_dropped_reconciled():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "r.jsonl"
        # honest explicit claim seals fine
        r = CompactionReceipt.open(PRE)
        r.record_kept(POST)
        r.record_dropped([PRE[1], PRE[2], PRE[3]])
        row = r.seal(p, compactor="c", method="m")
        assert verify_receipt(row, PRE, POST)["ok"]
        # understating the drop refuses to seal
        r = CompactionReceipt.open(PRE)
        r.record_kept(POST)
        r.record_dropped([PRE[1]])                 # claims 1, reality 3
        try:
            r.seal(p, compactor="c", method="m")
            assert False, "inconsistent record_dropped sealed!"
        except ValueError as e:
            assert "disagrees" in str(e)
    print("PASS explicit record_dropped reconciled; inconsistent claim refused")


def test_duplicates_counted_as_multiset():
    pre = ["dup", "dup", "unique"]
    with tempfile.TemporaryDirectory() as d:
        row = _sealed(d, pre=pre, post=["dup"])    # kept ONE copy of two
        assert row["dropped"]["count"] == 2        # the other dup + unique
        v = verify_receipt(row, pre, ["dup"])
        assert v["ok"], v
    print("PASS duplicate items counted as a multiset (kept 1 of 2 drops 1)")


def test_dropped_bytes_totals():
    pre = ["abcd", b"\x00" * 10]
    with tempfile.TemporaryDirectory() as d:
        row = _sealed(d, pre=pre, post=["abcd"])
        assert row["pre"]["bytes"] == 14 and row["dropped"]["bytes"] == 10, row
    print("PASS byte totals: pre=14, dropped=10 for a 4-char str + 10 raw bytes")


def test_seal_requires_record_kept_and_is_final():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "r.jsonl"
        r = CompactionReceipt.open(PRE)
        try:
            r.seal(p, compactor="c", method="m")
            assert False, "sealed without record_kept!"
        except ValueError:
            pass
        r.record_kept([])                          # everything dropped: valid
        row = r.seal(p, compactor="c", method="m")
        assert row["dropped"]["count"] == 4 and row["post"]["count"] == 0
        for fn in (lambda: r.record_kept([]), lambda: r.record_dropped([]),
                   lambda: r.seal(p, compactor="c", method="m")):
            try:
                fn()
                assert False, "mutated a sealed receipt!"
            except RuntimeError:
                pass
    print("PASS seal requires record_kept; sealed receipt is immutable")


def test_unknown_schema_refused():
    with tempfile.TemporaryDirectory() as d:
        row = dict(_sealed(d))
        row["schema"] = "arcaeon-compact:receipt:v99"
        v = verify_receipt(row)
        assert not v["ok"] and any("unknown schema" in n for n in v["notes"])
    print("PASS unknown schema refused, never half-verified")


def test_partial_content_pre_only():
    with tempfile.TemporaryDirectory() as d:
        row = _sealed(d)
        v = verify_receipt(row, pre_content=PRE)
        assert v["ok"] and v["content"] == "match", v
        v = verify_receipt(row, pre_content=PRE[:2])   # wrong pre
        assert not v["ok"] and v["content"] == "mismatch"
    print("PASS pre-only verify works; wrong pre-content mismatches")


def _forge(row, **overrides):
    """Rewrite a row's core and re-seal its receipt_digest — what any editor
    of a row can trivially do, since the receipt digest is unkeyed."""
    from arcaeon.prove.compact import _core_body
    from arcaeon.record.ledger import digest_json
    forged = json.loads(json.dumps(row))
    forged.update(json.loads(json.dumps(overrides)))
    forged["receipt_digest"] = digest_json(_core_body(forged))
    return forged


def test_impossible_byte_arithmetic_is_not_self_consistent():
    """A drop receipt's headline number is "how much did you cut." After a
    compaction the dropped content is GONE, so self-consistency (the
    no-content check) is the only check anyone can still run — and it never
    looked at the byte totals at all. Caught by audit 2026-08-14: a receipt
    could claim it dropped a billion bytes out of 600, or 1 byte out of 500,
    and verify clean."""
    with tempfile.TemporaryDirectory() as d:
        r = CompactionReceipt.open(["a" * 100, "b" * 200, "c" * 300])
        r.record_kept(["a" * 100])
        row = r.seal(Path(d) / "l.jsonl", compactor="x", method="m")
    assert verify_receipt(row)["self_consistent"], "honest row must still pass"

    over = _forge(row, dropped={**row["dropped"], "bytes": 10 ** 9})
    v = verify_receipt(over)
    assert not v["self_consistent"], "dropped.bytes > pre.bytes passed!"
    assert any("dropped.bytes" in n for n in v["notes"]), v["notes"]

    under = _forge(row, dropped={**row["dropped"], "bytes": 1})
    v = verify_receipt(under)
    assert not v["self_consistent"], "understated dropped.bytes passed!"
    assert any("introduced" in n or "bytes" in n for n in v["notes"]), v["notes"]

    nodrop = _forge(row, dropped={"count": 0, "bytes": 500, "items": []},
                    post={**row["post"], "count": 3})
    assert not verify_receipt(nodrop)["self_consistent"], \
        "dropped.count=0 with dropped.bytes=500 passed!"
    print("PASS impossible byte arithmetic fails self-consistency, no content needed")


def test_byte_arithmetic_allows_honest_introductions():
    """The tightened check must not fire on a real summarizer, which drops
    content AND introduces the summary text (post.bytes then exceeds the kept
    bytes legitimately). Only the impossible direction is refused."""
    with tempfile.TemporaryDirectory() as d:
        pre = ["turn one, at length" * 20, "turn two, at length" * 20]
        post = ["turn one, at length" * 20, "summary: two turns happened"]
        r = CompactionReceipt.open(pre)
        r.record_kept(post)
        row = r.seal(Path(d) / "l.jsonl", compactor="summarizer", method="llm")
        assert row["introduced"]["count"] == 1
        v = verify_receipt(row)
        assert v["ok"] and v["self_consistent"], v["notes"]
        v = verify_receipt(row, pre, post)
        assert v["ok"] and v["content"] == "match", v["notes"]
    print("PASS a real summarize-and-introduce receipt still verifies clean")


def test_empty_items_keep_zero_dropped_bytes_legal():
    """dropped.count>0 with dropped.bytes==0 is legal: empty strings are
    zero-byte items. The check must not assume bytes track count."""
    with tempfile.TemporaryDirectory() as d:
        r = CompactionReceipt.open(["", "", "keeper"])
        r.record_kept(["keeper"])
        row = r.seal(Path(d) / "l.jsonl", compactor="x", method="m")
        assert row["dropped"] == {"count": 2, "bytes": 0, "items": row["dropped"]["items"]}
        assert verify_receipt(row, ["", "", "keeper"], ["keeper"])["ok"]
    print("PASS dropping two empty items (0 bytes) stays self-consistent")


def _legacy_v1_row(pre, post, *, compactor: str, method: str) -> dict:
    """Hand-build the exact row shape `seal()` produced before 0.1.2: same
    fields, but `introduced` has no `bytes` key and `schema` is v1. Stands in
    for a receipt already sitting in someone's ledger from before this
    release -- the regression is that HIGH-1's fix must not strand it."""
    from collections import Counter
    pre_digests, pre_sizes, pre_whole, pre_bytes = _digest_content(pre)
    post_digests, post_sizes, post_whole, post_bytes = _digest_content(post)
    remaining = Counter(post_digests)
    dropped, dropped_bytes = [], 0
    for d, n in zip(pre_digests, pre_sizes):
        if remaining[d] > 0:
            remaining[d] -= 1
        else:
            dropped.append(d)
            dropped_bytes += n
    body = {
        "schema": SCHEMA_V1,
        "pre": {"count": len(pre_digests), "bytes": pre_bytes, "digest": pre_whole},
        "post": {"count": len(post_digests), "bytes": post_bytes, "digest": post_whole},
        "dropped": {"count": len(dropped), "bytes": dropped_bytes, "items": dropped},
        "introduced": {"count": sum(remaining.values())},  # v1 shape: no bytes
        "compactor": compactor,
        "method": method,
    }
    row = dict(body)
    row["receipt_digest"] = digest_json(body)
    return row


def test_seal_mints_v2_with_introduced_bytes():
    """HIGH-1 (scrutiny 2026-08-15): `seal()` now writes schema v2 and
    records `introduced.bytes` for real, computed from the actual
    post-content given to `record_kept()` -- not a number a caller can
    supply directly."""
    with tempfile.TemporaryDirectory() as d:
        pre = ["a" * 100, "b" * 400]
        post = ["a" * 100, "sum"]              # drops 400 bytes, introduces 3
        r = CompactionReceipt.open(pre)
        r.record_kept(post)
        row = r.seal(Path(d) / "l.jsonl", compactor="summarizer", method="llm")
        assert row["schema"] == SCHEMA == SCHEMA_V2
        assert row["introduced"] == {"count": 1, "bytes": 3}
        v = verify_receipt(row)
        assert v["ok"] and v["schema"] == "v2" and v["understatement_check"] == "full", v
    print("PASS seal() mints v2 rows with a real introduced.bytes")


def test_high1_understated_dropped_bytes_behind_introduction_is_caught():
    """The report's exact reproduction: a receipt understates dropped.bytes
    while claiming an introduction. Under v1 this passed self-consistency
    with NO content held (the HIGH-1 finding). Under v2, introduced.bytes is
    now part of the arithmetic, so leaving it at its TRUE value while lying
    about dropped.bytes breaks the exact reconciliation -- caught with no
    content."""
    with tempfile.TemporaryDirectory() as d:
        r = CompactionReceipt.open(["a" * 100, "b" * 400])
        r.record_kept(["a" * 100, "sum"])
        honest = r.seal(Path(d) / "l.jsonl", compactor="summarizer", method="llm")
    assert verify_receipt(honest)["ok"]

    liar = _forge(honest, dropped={**honest["dropped"], "bytes": 1})
    v = verify_receipt(liar)
    assert not v["ok"] and not v["self_consistent"], v
    assert any("bytes do not reconcile" in n for n in v["notes"]), v["notes"]
    assert v["schema"] == "v2"
    print("PASS HIGH-1: understated dropped.bytes behind a real introduction "
          "is caught by v2 self-consistency with no content held")


def test_legacy_v1_row_still_verifies_under_v1_rule():
    """A row already sealed under the old v1 schema (no `introduced.bytes`)
    must keep verifying after the HIGH-1 fix -- old ledgers aren't stranded.
    verify_receipt must say which rule applied, honestly: schema="v1",
    understatement_check="truncation-only" (not "full" -- v1 genuinely can't
    pin post.bytes once something was introduced)."""
    pre = ["turn 1: hello", {"role": "assistant", "text": "turn 2"}, b"turn 3 raw"]
    post = ["turn 1: hello", "summary of turn 2-3"]
    row = _legacy_v1_row(pre, post, compactor="old-summarizer", method="llm-summary")
    assert row["schema"] == SCHEMA_V1
    assert "bytes" not in row["introduced"]

    v = verify_receipt(row)
    assert v["ok"] and v["self_consistent"], v
    assert v["schema"] == "v1"
    assert v["understatement_check"] == "truncation-only"

    v = verify_receipt(row, pre, post)
    assert v["ok"] and v["content"] == "match", v
    print("PASS legacy v1 row (no introduced.bytes) still verifies; "
          "verify_receipt reports schema='v1', understatement_check='truncation-only'")


def test_v1_row_understatement_behind_introduction_still_only_lower_bounded():
    """Documents the residual honestly, both in code and in a real check: a
    v1-shaped row (schema unchanged, old ledgers) still can't pin post.bytes
    once something was introduced -- that's not a bug in verify_receipt, v1
    genuinely doesn't carry the field needed. Reproduces the report's exact
    shape: understate dropped.bytes AND inflate post.bytes to stay above the
    fake (now-smaller) kept_bytes floor -- that's the move the old inequality
    left open. The row is (correctly, honestly) still self-consistent, and
    understatement_check says "truncation-only" so a caller reading it knows
    not to trust the magnitude blindly."""
    pre = ["a" * 100, "b" * 400]
    post = ["a" * 100, "sum"]
    row = _legacy_v1_row(pre, post, compactor="old-summarizer", method="llm")
    assert row["introduced"]["count"] == 1
    assert row["pre"]["bytes"] == 500

    understated = dict(row)
    understated["dropped"] = {**row["dropped"], "bytes": 1}    # real drop was 400
    understated["post"] = {**row["post"], "bytes": 499}        # >= fake kept_bytes (500-1)
    understated["receipt_digest"] = digest_json(_core_body(understated))
    v = verify_receipt(understated)
    assert v["ok"] and v["self_consistent"], v  # the v1 gap, stated plainly
    assert v["schema"] == "v1" and v["understatement_check"] == "truncation-only"
    print("PASS v1 rows are honestly labeled truncation-only: an understated "
          "dropped.bytes + inflated post.bytes behind an introduction still "
          "passes v1 self-consistency (the exact gap HIGH-1's v2 fix closes "
          "going forward)")


def test_dropped_bytes_exceeding_pre_bytes_caught_even_when_v2_pin_is_compensated():
    """Mutation-testing find (generated-input coverage pass, 2026-08-16):
    test_impossible_byte_arithmetic_is_not_self_consistent already forges
    dropped.bytes > pre.bytes, but WITHOUT compensating introduced.bytes --
    so that forgery happens to ALSO break the v2 exact-pin equation
    (post.bytes == pre.bytes - dropped.bytes + introduced.bytes), and a
    mutant that disables the dedicated "dropped.bytes exceeds pre.bytes"
    guard still passes every existing test, because the v2 pin check catches
    the same forged row for an unrelated reason. That made the dedicated
    guard LOOK redundant when it is not: a forger who also inflates
    introduced.bytes to rebalance the pin sails straight through the pin
    check while still claiming a physically impossible drop (more bytes
    dropped than pre ever held). This receipt must still be refused, and
    only the dedicated guard catches it."""
    with tempfile.TemporaryDirectory() as d:
        r = CompactionReceipt.open(["a" * 100, "b" * 400])
        r.record_kept(["a" * 100, "sum"])
        honest = r.seal(Path(d) / "l.jsonl", compactor="x", method="m")
    assert verify_receipt(honest)["ok"]

    delta = 1000
    forged_dropped_bytes = honest["pre"]["bytes"] + delta        # impossible
    # Rebalance introduced.bytes so post.bytes = pre.bytes - dropped.bytes +
    # introduced.bytes STILL holds against the unchanged, honest post.bytes --
    # the v2 pin check alone would wave this through.
    compensated_introduced_bytes = (honest["post"]["bytes"] - honest["pre"]["bytes"]
                                     + forged_dropped_bytes)
    liar = _forge(honest,
                  dropped={**honest["dropped"], "bytes": forged_dropped_bytes},
                  introduced={**honest["introduced"],
                              "bytes": compensated_introduced_bytes})

    want_post = liar["pre"]["bytes"] - liar["dropped"]["bytes"] + liar["introduced"]["bytes"]
    assert want_post == liar["post"]["bytes"], "the pin must be satisfied for this to be a real test"

    v = verify_receipt(liar)
    assert not v["ok"] and not v["self_consistent"], v
    assert any("exceeds pre.bytes" in n for n in v["notes"]), v["notes"]
    print("PASS dropped.bytes > pre.bytes caught even with a compensated v2 pin "
          "(the dedicated impossible-arithmetic guard is load-bearing, not redundant)")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
    print(f"\nALL {len(fns)} TESTS PASSED")


# --- 0.1.4: a bounded verification must say so -------------------------------
# The defect these pin: verify_receipt returned ok=True with an EMPTY notes
# list for a scan that recomputed nothing, and for a v1 row whose dropped.bytes
# was understated behind a claimed introduction by an arbitrary margin. `ok`
# answers "did anything I looked at contradict the row"; it never answered
# "how much did I look at." arcaeon-ledger refuses to mint a green off a scan
# that did not cover everything; these tests hold this package to the same rule
# in its own field, without changing what `ok` means for existing consumers.

def _sealed_scope(tmp_path, pre, post):
    r = CompactionReceipt.open(pre)
    r.record_kept(post)
    return r.seal(str(tmp_path / "r.jsonl"), compactor="c", method="m")


def test_no_content_verification_is_labelled_bounded(tmp_path):
    row = _sealed_scope(tmp_path, ["alpha", "beta", "gamma"], ["beta", "gamma"])
    v = verify_receipt(row)
    assert v["ok"] is True
    assert v["verified_scope"] == "bounded_no_content", v["verified_scope"]
    assert any("bounded scan" in n for n in v["notes"]), v["notes"]


def test_both_contents_verification_is_full_scope(tmp_path):
    pre, post = ["alpha", "beta", "gamma"], ["beta", "gamma"]
    row = _sealed_scope(tmp_path, pre, post)
    v = verify_receipt(row, pre, post)
    assert v["ok"] and v["content"] == "match"
    assert v["verified_scope"] == "full", v["verified_scope"]
    assert v["notes"] == [], v["notes"]


def test_one_sided_content_is_bounded_not_full(tmp_path):
    pre, post = ["alpha", "beta", "gamma"], ["beta", "gamma"]
    row = _sealed_scope(tmp_path, pre, post)
    assert verify_receipt(row, pre, None)["verified_scope"] == "bounded_pre_only"
    assert verify_receipt(row, None, post)["verified_scope"] == "bounded_post_only"


def test_v1_understated_drop_behind_introduction_is_flagged(tmp_path):
    """The HIGH-1 gap, live: a v1 row that destroyed 30 bytes claims it
    destroyed 1, re-seals its own digest, and self-verifies with ok=True.
    That verdict is not wrong -- v1 genuinely cannot pin it -- but it must
    not arrive silent."""
    import json as _json
    from arcaeon.prove.compact import SCHEMA_V1
    from arcaeon.record.ledger import digest_json as _dj
    import arcaeon.prove.compact as _ac

    row = _sealed_scope(tmp_path, ["alpha secret wire instructions", "beta", "gamma"],
                  ["beta", "gamma", "A SUMMARY THAT WAS INTRODUCED"])
    v1 = _json.loads(_json.dumps(row))
    v1["schema"] = SCHEMA_V1
    del v1["introduced"]["bytes"]
    true_dropped = v1["dropped"]["bytes"]
    v1["dropped"]["bytes"] = 1
    v1.pop("chain", None)
    v1["receipt_digest"] = _dj(_ac._core_body(v1))

    v = verify_receipt(v1)
    assert true_dropped > 1
    assert v["ok"] is True and v["self_consistent"] is True   # v1 cannot catch it
    assert v["verified_scope"] == "bounded_no_content+v1_lower_bound", v["verified_scope"]
    assert any("lower bound" in n for n in v["notes"]), v["notes"]
    # and content recomputation DOES close it
    v_full = verify_receipt(v1,
                            ["alpha secret wire instructions", "beta", "gamma"],
                            ["beta", "gamma", "A SUMMARY THAT WAS INTRODUCED"])
    assert not v_full["ok"], "content recomputation must catch the understatement"
    assert v_full["verified_scope"] == "full"
