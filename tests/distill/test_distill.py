"""Tests for arcaeon-distill.

The product claim is determinism-under-budget plus an honest drop receipt, so
those are the load-bearing checks: same input -> byte-identical output across
repeated runs, and a receipt whose internal claims are self-consistent (or
caught when they aren't). Per-strategy coverage (json/tabular/text) proves
each path actually shrinks and actually reports what it cut.

Two extra layers of the determinism claim live here too (board item 19):

  - Cross-PROCESS determinism. Same-process determinism (below) only proves
    the algorithm doesn't depend on anything that varies call-to-call within
    one interpreter. It does NOT rule out dependence on something that
    varies process-to-process — PYTHONHASHSEED-driven set/dict iteration
    order being the classic one. `distill()` doesn't rely on hash-order
    directly (JSON dumps use sort_keys=True and structures are lists/dicts
    walked in insertion order), but the only way to actually PROVE that,
    rather than assert it, is to run it in two separate interpreters and
    diff the bytes.
  - Cross-VERSION stability (golden fixtures). The digest-based golden
    vectors in selftest.py prove byte-identity indirectly (through a hash);
    they don't show you what changed if a future edit alters the output.
    The GOLDEN_* constants below freeze the actual output values instead —
    the promise-keeper the README's cache-stability section points to.

Run: python test_distill.py
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from arcaeon.save.distill import (
    distill, estimate_tokens, DropReceipt, verify_receipt, SCHEMA,
    _char_budget,
)


def _stable_receipt(receipt) -> dict:
    """Receipt fields relevant to a determinism check, excluding the
    wall-clock `created_at` stamp.

    `created_at` is set via `datetime.now()` (see DropReceipt / _now_iso in
    __init__.py) and is EXPECTED to differ between two separate distill()
    calls — that's not nondeterminism, it's a timestamp doing its job.
    Asserting whole-receipt equality including it (the previous version of
    this test did) is flaky by construction: it fails whenever the two
    calls straddle a wall-clock second, which is exactly what happened when
    this file was run as part of the board-19 pass on 2026-08-14. That was
    a test bug, not a product bug — .content and every digest-bearing
    receipt field were byte-identical both times. Strip the timestamp
    before comparing so the check tests what it claims to test.
    """
    d = receipt.to_dict()
    d.pop("created_at", None)
    return d


def _big_json():
    return {
        "status": "ok",
        "query": "weather stations",
        "summary": "A" * 2000,
        "results": [
            {"id": i, "name": f"station-{i}", "note": "reading " * 20}
            for i in range(200)
        ],
    }


def _big_rows():
    return [{"id": i, "value": i * 3, "label": f"row-{i}"} for i in range(300)]


def _big_text():
    lead = "The outage began at 03:14 UTC and affected the west region. "
    middle = " ".join(f"Diagnostic step {i} found nothing conclusive and "
                      f"logs for shard {i} were inconclusive as well."
                      for i in range(60))
    tail = " Root cause was a stale DNS record fixed at 04:02 UTC, and the incident closed clean."
    return lead + middle + tail


def test_determinism_json():
    data = _big_json()
    r1 = distill(data, budget=300)
    r2 = distill(_big_json(), budget=300)  # fresh equal-but-not-identical object
    assert json.dumps(r1.content, sort_keys=True) == json.dumps(r2.content, sort_keys=True)
    assert _stable_receipt(r1.receipt) == _stable_receipt(r2.receipt)
    print("PASS determinism: json strategy, same input -> identical output twice")


def test_determinism_tabular():
    r1 = distill(_big_rows(), budget=400)
    r2 = distill(_big_rows(), budget=400)
    assert json.dumps(r1.content, sort_keys=True) == json.dumps(r2.content, sort_keys=True)
    assert _stable_receipt(r1.receipt) == _stable_receipt(r2.receipt)
    print("PASS determinism: tabular strategy, same input -> identical output twice")


def test_determinism_text():
    text = _big_text()
    r1 = distill(text, budget=100, query="root cause")
    r2 = distill(text, budget=100, query="root cause")
    assert r1.content == r2.content
    assert _stable_receipt(r1.receipt) == _stable_receipt(r2.receipt)
    print("PASS determinism: text strategy, same input+query -> identical output twice")


def test_determinism_repeated_many_runs():
    data = _big_json()
    outs = {json.dumps(distill(data, budget=250).content, sort_keys=True) for _ in range(8)}
    assert len(outs) == 1, "8 runs of the same input produced different outputs"
    print("PASS determinism: 8 repeated runs collapse to one output")


# ---------------------------------------------------------------------------
# Cross-process determinism + cross-version golden-output guard (board 19).
#
# `golden_fixtures.json` holds four (input, budget, schema_hint, query)
# cases, one per strategy path (json / tabular-rows / tabular-csv-text /
# text), each frozen with the exact `distill()` output it produced at
# package version 0.1.0 (2026-08-14). It backs BOTH checks below:
#   - golden-output: proves TODAY's code produces the SAME output as the
#     frozen one, for unchanged input — the cross-version promise-keeper.
#   - cross-process: proves the SAME input distilled in two independent
#     python interpreters (not just two calls in this one process) produces
#     byte-identical stdout — rules out anything that could vary
#     process-to-process (e.g. PYTHONHASHSEED-driven ordering) that a
#     same-process check can't rule out.
# ---------------------------------------------------------------------------

_GOLDEN_FIXTURES_PATH = Path(__file__).resolve().parent / "golden_fixtures.json"
_GOLDEN_FIXTURES = json.loads(_GOLDEN_FIXTURES_PATH.read_text(encoding="utf-8"))

_CROSS_PROCESS_WORKER = r"""
import json, sys
from arcaeon.save.distill import distill

payload = json.loads(sys.stdin.read())
kwargs = {"budget": payload["budget"]}
if payload.get("schema_hint") is not None:
    kwargs["schema_hint"] = payload["schema_hint"]
if payload.get("query") is not None:
    kwargs["query"] = payload["query"]
result = distill(payload["input"], **kwargs)
receipt = result.receipt.to_dict() if result.receipt else None
if receipt is not None:
    receipt.pop("created_at", None)  # wall-clock, expected to differ -- see _stable_receipt
out = {"content": result.content, "strategy": result.strategy,
       "truncated": result.truncated, "receipt_stable": receipt}
# sort_keys=False deliberately: dict KEY ORDER is part of the bytes an LLM and
# a prefix cache see, and it is the one thing PYTHONHASHSEED could plausibly
# move. sort_keys=True erased exactly what this guard exists to pin. Writing
# encoded bytes (not text) keeps a non-ASCII fixture from dying on a cp1252
# console.
sys.stdout.buffer.write(json.dumps(out, sort_keys=False,
                                   ensure_ascii=False).encode("utf-8"))
"""


def _distill_in_subprocess(case: dict) -> str:
    """Runs distill() for `case` in a FRESH python interpreter (not this
    process) and returns its stdout verbatim."""
    payload = json.dumps({"input": case["input"], "budget": case["budget"],
                           "schema_hint": case["schema_hint"], "query": case["query"]})
    proc = subprocess.run(
        [sys.executable, "-c", _CROSS_PROCESS_WORKER],
        input=payload.encode("utf-8"), capture_output=True,
        cwd=str(Path(__file__).resolve().parent), timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"cross-process worker for {case['name']!r} failed: "
                            f"{proc.stderr.decode('utf-8', 'replace')}")
    return proc.stdout


def test_cross_process_determinism():
    for case in _GOLDEN_FIXTURES["cases"]:
        out1 = _distill_in_subprocess(case)
        out2 = _distill_in_subprocess(case)
        assert out1 == out2, (
            f"{case['name']}: same input distilled in two separate python "
            f"processes produced different bytes -- real nondeterminism")
    print(f"PASS cross-process determinism: {len(_GOLDEN_FIXTURES['cases'])} cases, "
          f"each run in two independent interpreters, byte-identical stdout")


def test_golden_output_matches_frozen_v0_1_0():
    for case in _GOLDEN_FIXTURES["cases"]:
        kwargs = {"budget": case["budget"]}
        if case["schema_hint"] is not None:
            kwargs["schema_hint"] = case["schema_hint"]
        if case["query"] is not None:
            kwargs["query"] = case["query"]
        result = distill(case["input"], **kwargs)
        # Compare SERIALIZED bytes, not the objects: `{"a":1,"b":2} ==
        # {"b":2,"a":1}` is True in Python and False for every cache in front
        # of this. The order-blind comparison would have passed a total
        # rewrite of emitted key order.
        got = json.dumps(result.content, ensure_ascii=False, separators=(",", ":"),
                         sort_keys=False)
        want = json.dumps(case["golden_content"], ensure_ascii=False,
                          separators=(",", ":"), sort_keys=False)
        assert got == want, (
            f"{case['name']}: output for this UNCHANGED input no longer matches "
            f"the frozen {_GOLDEN_FIXTURES['frozen_at_package_version']} golden "
            f"fixture -- distill() behavior changed for existing inputs")
        assert result.strategy == case["golden_strategy"]
        assert result.truncated == case["golden_truncated"]
    print(f"PASS golden output: {len(_GOLDEN_FIXTURES['cases'])} cases match the "
          f"frozen {_GOLDEN_FIXTURES['frozen_at_package_version']} fixtures byte-for-byte")


def test_budget_adherence_json():
    result = distill(_big_json(), budget=200)
    assert result.est_tokens_after <= result.est_tokens_before
    assert result.truncated
    # best-effort, not a hard cap — assert it's in the right ballpark, not exact
    assert result.est_tokens_after < result.est_tokens_before * 0.5
    print(f"PASS budget adherence (json): {result.est_tokens_before} -> "
          f"{result.est_tokens_after} tokens, budget 200")


def test_budget_adherence_tabular():
    result = distill(_big_rows(), budget=300)
    assert result.truncated
    assert result.est_tokens_after < result.est_tokens_before
    print(f"PASS budget adherence (tabular): {result.est_tokens_before} -> "
          f"{result.est_tokens_after} tokens, budget 300")


def test_budget_adherence_text():
    result = distill(_big_text(), budget=80)
    assert result.truncated
    assert result.est_tokens_after < result.est_tokens_before
    print(f"PASS budget adherence (text): {result.est_tokens_before} -> "
          f"{result.est_tokens_after} tokens, budget 80")


def test_passthrough_under_budget():
    small = {"ok": True, "n": 3}
    result = distill(small, budget=2000)
    assert result.content == small
    assert not result.truncated
    assert result.receipt is not None  # receipt=True is distill()'s default
    assert result.receipt.drops == []
    v = verify_receipt(result.receipt)
    assert v["ok"], v
    print("PASS passthrough: small input under budget is returned unmodified, no drops")


def test_json_strategy_shape():
    result = distill(_big_json(), budget=150, schema_hint="json")
    assert result.strategy == "json"
    c = result.content
    assert set(c.keys()) == {"status", "query", "summary", "results"}
    assert c["summary"].endswith("more chars")
    assert any(isinstance(x, str) and "more items" in x for x in c["results"])
    assert result.receipt is not None  # receipt=True is distill()'s default
    kinds = {d["kind"] for d in result.receipt.drops}
    assert "string_truncated" in kinds
    assert "list_truncated" in kinds
    print("PASS json strategy: keys kept, long string capped with a count, "
          "long list head/tail with a dropped-item marker")


def test_tabular_strategy_shape_list_of_dicts():
    result = distill(_big_rows(), budget=400, schema_hint="tabular")
    assert result.strategy == "tabular"
    assert isinstance(result.content, list)
    assert result.content[0] == {"id": 0, "value": 0, "label": "row-0"}
    assert result.content[-1] == {"id": 299, "value": 897, "label": "row-299"}
    assert any("__distilled_dropped_rows__" in row for row in result.content
               if isinstance(row, dict))
    assert result.receipt is not None  # receipt=True is distill()'s default
    assert result.receipt.drops[0]["kind"] == "rows_dropped"
    print("PASS tabular strategy (list-of-dicts): head+tail rows kept, "
          "dropped-row marker present")


def test_tabular_strategy_shape_csv_text():
    header = "id,value,label"
    rows = [f"{i},{i*3},row-{i}" for i in range(200)]
    csv_text = "\n".join([header] + rows)
    result = distill(csv_text, budget=300)
    assert result.strategy == "tabular"
    assert result.content.startswith(header)
    assert "rows dropped" in result.content
    assert result.receipt is not None  # receipt=True is distill()'s default
    assert result.receipt.drops[0]["kind"] == "rows_dropped"
    print("PASS tabular strategy (CSV text): header kept, dropped-row count in body")


def test_dunder_version_matches_pyproject():
    """The two-place version gap found in 3 of 3 sibling packages checked on
    2026-08-24 (audit/baseline/continuity all had __version__ trailing the
    pyproject bump). Pinned here too, per the sweep rule: assume the class,
    not the instance."""
    import tomllib
    import arcaeon.save.distill
    declared = tomllib.loads(
        (Path(__file__).parent / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]["version"]
    assert arcaeon.save.distill.__version__ == declared, (
        f"__version__={arcaeon.save.distill.__version__!r} but pyproject.toml "
        f"declares {declared!r}")
    print("PASS __version__ matches pyproject.toml")


def test_verify_receipt_rejects_malformed_dropped_count():
    """D-1 (verdict-field audit 2026-08-20, fixed 2026-08-24): the docstring
    always claimed 'non-negative counts' are checked, but only dropped_bytes
    was ever validated — dropped_count could be negative, a string, a bool,
    or absent and the receipt still stamped 'self-consistent'. The claimed
    predicate exceeded the delivered one on the package's own honesty hook."""
    result = distill(_big_rows(), budget=400, schema_hint="tabular")
    base = result.receipt.to_dict()
    assert verify_receipt(base)["ok"], "control: genuine receipt must verify"

    for bad, label in [(-5, "negative"), ("banana", "string"),
                       (True, "bool"), (None, "absent/None")]:
        forged = json.loads(json.dumps(base))
        if bad is None:
            forged["drops"][0].pop("dropped_count", None)
        else:
            forged["drops"][0]["dropped_count"] = bad
        v = verify_receipt(forged)
        assert not v["ok"], (
            f"a receipt with a {label} dropped_count verified as "
            f"self-consistent — the count check the docstring promises "
            f"never ran (D-1)")
        assert any("dropped_count" in n for n in v["notes"]), v["notes"]
    print("PASS verify_receipt rejects negative/string/bool/absent "
          "dropped_count (D-1)")


def test_tabular_text_preserves_leading_and_trailing_newlines():
    """D-2 (verdict-field audit 2026-08-20, fixed 2026-08-24): the tabular
    text path stripped leading/trailing newlines from the input and never
    restored them — content dropped from the output with no drops[] row and
    truncated=False, in the package whose whole contract is that every
    dropped byte is receipted. Fix: the affixes are preserved, so nothing
    leaves the output except content carried in a receipt."""
    header = "id,value,label"
    rows = [f"{i},{i*3},row-{i}" for i in range(5)]
    core = "\n".join([header] + rows)
    padded = "\n\n" + core + "\n\n\n"

    # Small table, generous budget: nothing should be dropped at all, so the
    # output must be byte-identical to the input — including the newlines.
    result = distill(padded, budget=2000, schema_hint="tabular")
    assert result.strategy == "tabular"
    assert result.receipt.drops == [], "control: nothing should drop here"
    assert result.receipt.truncated is False
    assert result.content == padded, (
        f"newline affixes were dropped without a receipt (D-2): "
        f"input had lead={padded[:2]!r} trail={padded[-3:]!r}, "
        f"output starts {result.content[:2]!r} ends {result.content[-3:]!r}")

    # And when rows DO drop, the affixes still survive alongside the receipt.
    big_rows = [f"{i},{i*3},row-{i}" for i in range(200)]
    big_padded = "\n" + "\n".join([header] + big_rows) + "\n\n"
    result2 = distill(big_padded, budget=300, schema_hint="tabular")
    assert result2.receipt.drops, "rows should drop under this budget"
    assert result2.content.startswith("\n" + header), \
        "leading newline lost on the truncating path"
    assert result2.content.endswith("\n\n"), \
        "trailing newlines lost on the truncating path"
    print("PASS tabular text preserves newline affixes, truncating or not (D-2)")


def test_text_strategy_reassembles_in_original_order():
    text = _big_text()
    result = distill(text, budget=100, schema_hint="text", query="DNS root cause")
    assert result.strategy == "text"
    assert result.content.startswith("The outage began")
    assert "stale DNS record" in result.content or "Root cause" in result.content
    assert result.receipt is not None  # receipt=True is distill()'s default
    assert result.receipt.drops[0]["kind"] == "sentences_dropped"
    print("PASS text strategy: extractive selection keeps lead + query-relevant "
          "sentence, reassembled in original order")


def test_drop_receipt_catches_planted_inconsistency():
    # Plant the lie: claim truncated=False while a drop is recorded (or the
    # reverse). verify_receipt must catch the internal contradiction.
    honest = distill(_big_json(), budget=150).receipt
    assert honest is not None  # receipt=True is distill()'s default
    v_honest = verify_receipt(honest)
    assert v_honest["ok"], v_honest

    tampered = DropReceipt(**{**honest.to_dict(), "truncated": False})
    v_tampered = verify_receipt(tampered)
    assert not v_tampered["ok"]
    assert any("disagrees" in n for n in v_tampered["notes"]), v_tampered["notes"]
    print("PASS drop receipt: planted truncated/drops mismatch is caught by verify_receipt")


def test_drop_receipt_catches_corrupted_digest():
    receipt = distill(_big_rows(), budget=300).receipt
    assert receipt is not None  # receipt=True is distill()'s default
    row = receipt.to_dict()
    row["distilled"]["digest"] = "not-a-real-digest"
    v = verify_receipt(row)
    assert not v["ok"]
    assert any("well-formed" in n for n in v["notes"]), v["notes"]
    print("PASS drop receipt: malformed digest field is caught by verify_receipt")


def test_receipt_never_contains_full_content():
    result = distill(_big_json(), budget=150)
    assert result.receipt is not None  # receipt=True is distill()'s default
    blob = json.dumps(result.receipt.to_dict())
    assert "A" * 50 not in blob  # the long summary value never appears verbatim
    print("PASS drop receipt: dropped content is digested, never carried verbatim")


def test_receipt_optional():
    result = distill(_big_json(), budget=150, receipt=False)
    assert result.receipt is None
    print("PASS receipt=False skips receipt computation")


def test_estimate_tokens_heuristic():
    """The ~4-chars-per-token constant is pinned at points that can SEE it.

    Mutation finding (2026-08-28): changing the divisor from 4 to 3 left this
    test green. Every input it sampled was a coincidence point -- `4 // 4` and
    `4 // 3` are both 1, `8 // 4` and `8 // 3` are both 2 -- so the assertions
    could not discriminate the constant they existed to pin. The cases below
    are chosen so 4 and 3 give DIFFERENT answers, and they cover the documented
    round trip with `_char_budget`, which carries the same constant in the
    opposite direction: if one drifts without the other, every budget in the
    package silently means something new.
    """
    assert estimate_tokens("") == 0
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens({"a": 1}) > 0
    assert estimate_tokens(b"abcdefgh") == 2
    # Discriminating points: 12//4 == 3 but 12//3 == 4; 9//4 == 2 but 9//3 == 3.
    assert estimate_tokens("a" * 12) == 3, "the ~4-chars-per-token constant moved"
    assert estimate_tokens("a" * 40) == 10
    assert estimate_tokens("some text") == 2, "value documented in README.md"
    # The inverse constant must stay the matched pair of the one above.
    assert _char_budget(1) == 4
    assert _char_budget(250) == 1000
    assert estimate_tokens("x" * _char_budget(37)) == 37
    print("PASS estimate_tokens: 4-chars-per-token pinned at discriminating points, "
          "round-trips with _char_budget")


def test_schema_hint_forces_strategy():
    text_like_json = json.dumps({"a": 1})
    result = distill(text_like_json, budget=2000, schema_hint="text")
    assert result.strategy == "text"
    print("PASS schema_hint overrides auto-detection")


def test_invalid_budget_rejected():
    try:
        distill({"a": 1}, budget=0)
    except ValueError:
        print("PASS budget<=0 raises ValueError")
        return
    raise AssertionError("expected ValueError for budget=0")


def test_seal_reports_honestly_whether_or_not_the_ledger_is_installed(tmp_path):
    """Both branches assert something, and neither writes outside tmp_path.

    The previous version of this test passed `"nonexistent.jsonl"` as if the
    name were a sentinel meaning "this path does not exist". It is not: it is a
    live relative path, resolved against pytest's cwd -- the repo root. With
    arcaeon-ledger installed the `except ImportError` never fired, the test fell
    through to an unconditional PASS print having asserted NOTHING about the
    branch that actually ran, and `seal()` appended a real hash-chained row to
    `./nonexistent.jsonl` (and `os.open`'d `./nonexistent.jsonl.lock`) on every
    single run. That file reached 38 KB across ~60 runs, and the zero-byte lock
    was committed and shipped inside the 0.1.4 sdist.

    A test that is green whether the ledger is present or absent, while
    verifying only the absent branch, is a test that cannot fail.
    """
    result = distill({"a": "b" * 500}, budget=10)
    assert result.receipt is not None  # receipt=True is distill()'s default
    ledger = tmp_path / "receipts.jsonl"
    try:
        row = result.receipt.seal(ledger)
    except ImportError as e:
        assert "arcaeon-ledger" in str(e), (
            "without arcaeon-ledger, seal() must name the missing package")
        assert not ledger.exists(), "a failed seal must not leave a partial file"
        print("PASS seal() without arcaeon-ledger raises a clear, named ImportError")
        return
    # The branch the old test never checked: the seal actually happened.
    assert ledger.exists(), "seal() returned without writing the ledger"
    assert isinstance(row, dict) and row.get("chain"), (
        "a sealed row must carry the ledger chain hash")
    written = [json.loads(l) for l in
               ledger.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(written) == 1, f"expected exactly one sealed row, got {len(written)}"
    assert written[0]["chain"] == row["chain"]
    print("PASS seal() with arcaeon-ledger writes exactly one chained row, in tmp_path")


# ---------------------------------------------------------------------------
# Input admission (audit 2026-08-14).
#
# The cache-stability claim is the product. Three input shapes broke it and no
# downstream code path could repair them, so they are refused at the door. The
# nastiest part: the cross-process guard above cannot SEE any of them, because
# its transport is JSON and a set, a heap object, and a non-str dict key all
# fail to cross a JSON pipe. A live hash seed with nothing to test.
# ---------------------------------------------------------------------------

_ADVERSARIAL_WORKER = r"""
import sys
from arcaeon.save.distill import distill
payload = {"a" * 10: "x" * 200, "b" * 10: "y" * 200, "zz": {"n": 1, "m": 2}}
r = distill(payload, budget=60, receipt=True)
import json
sys.stdout.buffer.write(json.dumps(
    {"c": r.content, "d": r.receipt.to_dict()["full"]["digest"]},
    sort_keys=False, ensure_ascii=False).encode("utf-8"))
"""


def test_arbitrary_object_is_refused_not_stringified():
    """`str(obj)` embeds a heap address, so the documented "anything else is
    stringified" path violated byte-identity on EVERY run (ASLR), not just
    across machines."""
    class ApiResponse:
        def __init__(self):
            self.rows = list(range(50))

    for value in (ApiResponse(), object(), lambda x: x):
        try:
            distill(value, budget=200, receipt=False)
            assert False, f"{type(value).__name__} was accepted"
        except TypeError as e:
            assert "deterministic" in str(e)
    print("PASS an arbitrary object is a typed refusal, not a heap address in the output")


def test_sets_are_refused():
    """A set iterates in PYTHONHASHSEED order -- the textbook cross-process
    nondeterminism, and unreachable by a JSON-transport guard."""
    for value in ({"a", "b", "c"}, frozenset({"a", "b"}),
                  {"rows": [{"tags": {"x", "y"}}]}):
        try:
            distill(value, budget=200, receipt=False)
            assert False, f"{value!r} was accepted"
        except TypeError as e:
            assert "PYTHONHASHSEED" in str(e)
    print("PASS set/frozenset input is refused, nested ones too")


def test_non_string_dict_keys_are_refused():
    """json.dumps coerces non-str keys, so {1: v} and {"1": v} -- unequal
    inputs -- produced the SAME receipt digest. A digest that can't tell two
    inputs apart cannot prove which output it describes."""
    for value in ({1: "a" * 400}, {True: "x"}, {1.0: "x"},
                  {"ok": {2: "nested"}}):
        try:
            distill(value, budget=100)
            assert False, f"{value!r} was accepted"
        except TypeError as e:
            assert "not str" in str(e)
    # and the collision it prevented is real, so pin the pair explicitly
    a, b = {1: "a" * 400}, {"1": "a" * 400}
    assert a != b
    print("PASS non-str dict keys are refused (they collided two unequal inputs "
          "onto one digest)")


def test_nan_and_infinity_are_refused_consistently():
    """The package disagreed with itself: receipt=True raised out of `json`,
    receipt=False emitted the literals NaN/Infinity -- which are not JSON --
    straight into an agent's context."""
    for value in ({"x": float("nan"), "pad": "p" * 400},
                  {"x": float("inf"), "pad": "p" * 400},
                  [float("-inf")]):
        for receipt in (True, False):
            try:
                distill(value, budget=50, receipt=receipt)
                assert False, f"{value!r} accepted with receipt={receipt}"
            except ValueError as e:
                assert "NaN/Infinity" in str(e)
    print("PASS NaN/Infinity refused identically with and without a receipt")


def test_common_non_json_types_fail_typed():
    import datetime as _dt
    import decimal
    for value in (_dt.datetime(2026, 8, 14), decimal.Decimal("1.5")):
        try:
            distill(value, budget=100)
            assert False, f"{type(value).__name__} accepted"
        except TypeError as e:
            assert "deterministic serialization" in str(e)
    print("PASS datetime/Decimal fail with a distill-level TypeError, not one "
          "from inside json.encoder")


def test_tabular_hint_on_a_dict_does_not_silently_distill_the_keys():
    """`list(a_dict)` yields KEYS. schema_hint='tabular' on a dict threw away
    every value, reported truncated=False with an empty drop list, and
    verify_receipt certified it ok. Affirmatively certified total data loss."""
    payload = {"rows": [{"id": 1}], "meta": {"page": 1}}
    try:
        distill(payload, budget=100, schema_hint="tabular")
        assert False, "a dict was accepted as tabular"
    except TypeError as e:
        assert "list of row dicts" in str(e)
    for bad in (12345, "x"):
        try:
            distill(bad, budget=100, schema_hint="tabular")
        except (TypeError, ValueError):
            pass
    print("PASS schema_hint='tabular' on a dict raises instead of distilling the key names")


def test_shared_reference_is_accepted_not_rejected_as_cycle():
    """H2 (scrutiny 2026-08-15): a value referenced twice is a DAG, not a
    cycle. json.dumps handles it fine; the old admission walker's global
    `seen` set (never popped on backtrack) refused it as "a reference
    cycle" -- a false message on valid, JSON-serializable input."""
    shared = [1, 2, 3]
    data = {"a": shared, "b": shared}
    result = distill(data, budget=200)
    assert result.content == {"a": [1, 2, 3], "b": [1, 2, 3]}
    assert result.receipt is not None  # receipt=True is distill()'s default
    v = verify_receipt(result.receipt)
    assert v["ok"], v
    # a value shared three ways, and nested, still isn't a cycle
    nested_shared = {"x": 1}
    data2 = {"a": [nested_shared, nested_shared], "b": nested_shared}
    result2 = distill(data2, budget=200)
    assert result2.content == {"a": [{"x": 1}, {"x": 1}], "b": {"x": 1}}
    print("PASS shared reference (DAG) is accepted, not refused as a cycle")


def test_true_reference_cycle_is_still_rejected():
    """The H2 fix must not turn off real-cycle detection. A container that
    contains itself (directly or through one hop) still raises -- otherwise
    `_walk_json` would recurse it to a RecursionError instead of a clean,
    typed refusal at the door."""
    self_referencing_list: list = []
    self_referencing_list.append(self_referencing_list)
    try:
        distill(self_referencing_list, budget=200)
        assert False, "a list containing itself was accepted"
    except ValueError as e:
        assert "reference cycle" in str(e)

    a: dict = {}
    b = {"a": a}
    a["b"] = b
    try:
        distill(a, budget=200)
        assert False, "an indirect a->b->a cycle was accepted"
    except ValueError as e:
        assert "reference cycle" in str(e)
    print("PASS a real reference cycle (direct and indirect) is still refused")


def test_wide_dict_budget_is_enforced():
    """M1 (scrutiny 2026-08-15): the json strategy capped string length and
    list length but never dict BREADTH, so a wide dict (many keys -- an
    id->status map, a flat config) blew the budget ~194x with
    truncated=False (honest -- nothing was cut -- but misleading, since
    ordinary-shaped input was expected to land near budget). A dict-key cap
    now shrinks alongside str_cap/list_cap; the drop is recorded like any
    other, not silently absorbed."""
    data = {f"key_{i}": i for i in range(5000)}
    result = distill(data, budget=100)  # char_budget = 400
    est_size = len(json.dumps(result.content, ensure_ascii=False, separators=(",", ":")))
    assert result.truncated
    assert est_size < 4 * 400, (  # was ~194x over; must now be in the same ballpark as budget
        f"wide dict still blew the budget: {est_size} chars vs a 400-char budget")
    assert result.receipt is not None
    kinds = {d["kind"] for d in result.receipt.drops}
    assert "dict_truncated" in kinds
    assert "__distilled_dropped_keys__" in result.content
    v = verify_receipt(result.receipt)
    assert v["ok"], v
    print(f"PASS wide dict (5000 keys, budget 100) now truncates: "
          f"{est_size} chars (was 194.4x over budget pre-fix), truncated=True, "
          f"dict_truncated recorded, verify_receipt ok")


def test_dict_at_exact_cap_is_not_truncated():
    """Mutation-testing find (2026-08-16): `_walk_json`'s dict-breadth check
    is `len(obj) > dict_cap` (default 200). An off-by-one mutant (`>=`)
    SURVIVED the full suite -- nothing exercised a dict with EXACTLY
    `dict_cap` keys, so the boundary itself was unverified. A dict of
    exactly 200 keys must round-trip whole: no `__distilled_dropped_keys__`
    marker, no `dict_truncated` drop, `truncated=False` -- the cap is a
    "more than this shrinks" line, not "this much or more shrinks"."""
    data = {f"k{i}": i for i in range(200)}  # == default dict_cap, not over it
    result = distill(data, budget=5000)  # generous budget: no shrink-loop interference
    assert result.strategy == "json"
    assert not result.truncated, "a dict of exactly dict_cap keys was truncated"
    assert "__distilled_dropped_keys__" not in result.content
    assert len(result.content) == 200
    assert result.content == data
    print("PASS a 200-key dict (== default dict_cap) survives whole, untruncated")


def test_list_at_exact_cap_is_not_truncated():
    """Mutation-testing find (2026-08-16): same off-by-one shape as the dict
    cap, on `_walk_json`'s list-length check (`> list_cap`, default 20). A
    `>=` mutant SURVIVED -- no test used a list of exactly `list_cap` items.
    At exactly 20 items nothing should be cut: no "...+N more items"
    marker, no `list_truncated` drop."""
    data = list(range(20))  # == default list_cap, not over it
    result = distill(data, budget=5000, schema_hint="json")
    assert not result.truncated, "a list of exactly list_cap items was truncated"
    assert result.content == data
    assert not any(isinstance(x, str) and x.startswith("...+") for x in result.content)
    print("PASS a 20-item list (== default list_cap) survives whole, untruncated")


def test_string_at_exact_cap_is_unchanged():
    """Mutation-testing find (2026-08-16): same off-by-one shape again on the
    string cap (`> str_cap`, default 300). The `>=` mutant is worse than the
    dict/list cases -- at len(s) == str_cap, `cut = obj[str_cap:]` is EMPTY,
    so the mutant appends a live '...+0 more chars' suffix to an
    already-complete string, making the 'distilled' output LONGER than the
    original while claiming a drop happened. A 300-char string must come
    back byte-identical, not with a phantom marker for zero dropped chars."""
    s = "x" * 300  # == default str_cap, not over it
    result = distill({"s": s}, budget=5000)
    assert not result.truncated, "a string of exactly str_cap chars was truncated"
    assert result.content["s"] == s, (
        f"300-char string round-tripped as {result.content['s']!r} "
        f"({len(result.content['s'])} chars) -- expected byte-identical")
    print("PASS a 300-char string (== default str_cap) round-trips unchanged")


def test_two_row_list_of_dicts_is_detected_as_tabular():
    """Mutation-testing find (2026-08-16): `_is_row_list`'s length guard is
    `len(data) < 2` (the tabular strategy needs at least a header shape, so
    a 0- or 1-row list falls back to json). An off-by-one mutant (`<= 2`)
    SURVIVED -- no test checked strategy auto-detection on the SMALLEST
    valid tabular input, exactly 2 rows. Under the mutant, a 2-row
    list-of-dicts silently detects as "json" instead of "tabular" -- still
    correct output, but the wrong strategy label and the wrong receipt
    shape (dict/list drops instead of rows_dropped) for any caller that
    branches on `result.strategy`."""
    rows = [{"a": 1, "b": 2}, {"a": 3, "b": 4}]  # smallest valid tabular input
    result = distill(rows, budget=5000)  # no schema_hint: exercise auto-detect
    assert result.strategy == "tabular", (
        f"a 2-row list-of-dicts auto-detected as {result.strategy!r}, not 'tabular'")
    print("PASS a 2-row list-of-dicts auto-detects as the tabular strategy")


def test_cross_process_determinism_on_an_adversarial_payload():
    """The JSON-transport guard can't express a hostile payload, so build one
    INSIDE the worker: long equal-length values (ranking ties), nested dicts
    (key order), and two runs under different explicit hash seeds."""
    import os
    outs = []
    for seed in ("0", "1", "12345"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        proc = subprocess.run(
            [sys.executable, "-c", _ADVERSARIAL_WORKER], capture_output=True,
            cwd=str(Path(__file__).resolve().parent), timeout=30, env=env)
        assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
        outs.append(proc.stdout)
    assert len(set(outs)) == 1, (
        "the same payload distilled under PYTHONHASHSEED 0/1/12345 produced "
        "different bytes -- real cross-process nondeterminism")
    print("PASS adversarial payload is byte-identical under three explicit hash seeds")


def test_json_shrink_loop_stops_at_exact_budget_not_past_it():
    """Mutation-testing find (2026-08-16): the shrink-loop stop condition in
    `_distill_json` is `size <= char_budget` -- inclusive, so a pass that
    lands EXACTLY on budget stops right there instead of shrinking again for
    no reason. A `<=` -> `<` mutant SURVIVED the whole suite because no
    existing case makes a shrink-loop iteration's serialized size land on
    char_budget exactly; that requires solving for the budget from the
    output size, not guessing one.

    A dict with a single 301-char string value truncates, at the DEFAULT
    str_cap=300, to a 300-char string plus a "...+1 more chars" marker; the
    whole distilled JSON blob is exactly 324 chars, which is char_budget for
    budget=81 tokens (81*4=324) -- the *first* shrink-loop pass already
    lands on budget to the byte.

    Correct code stops there (a 1-char drop). A `<` mutant sees
    `324 < 324` is False, does not stop, halves the caps (str_cap 300->150),
    re-walks, and that deeper pass becomes the new smallest-seen result: 151
    chars dropped instead of 1, at the identical budget -- needless
    truncation the exact-fit pass never required."""
    data = {"s": "x" * 301}
    r = distill(data, budget=81, receipt=False)
    size = len(json.dumps(r.content, ensure_ascii=False, separators=(",", ":")))
    assert size == 324, "fixture drifted: exact-budget size changed (%d)" % size
    assert r.content["s"] == "x" * 300 + "...+1 more chars", (
        "shrink loop over-truncated past the exact-fit first pass: %r"
        % r.content["s"])
    print("PASS shrink-loop stop is <= (inclusive): an exact-budget fit "
          "is not shrunk further")


ALL_TESTS = [v for k, v in list(globals().items()) if k.startswith("test_")]


def run() -> int:
    failures = 0
    for t in ALL_TESTS:
        try:
            t()
        except AssertionError as e:
            failures += 1
            print(f"FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failures += 1
            print(f"ERROR {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(ALL_TESTS) - failures}/{len(ALL_TESTS)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(run())


def test_well_formed_rejects_digests_that_only_look_right():
    """The note on failure says "not a well-formed self-describing digest".

    It must mean that. The package emits exactly two digest shapes, both
    `sha256:<recipe>:v1:<64 lowercase hex>`, so a validator that accepts a
    one-character body, an `0x` prefix, a negative number, an underscore
    separator or surrounding whitespace is not checking the property its own
    failure message names — it is checking colon count. A forged receipt whose
    digests merely have the right punctuation must not pass structural review.
    """
    from arcaeon.save.distill import _well_formed
    good = "sha256:json-c14n:v1:" + "0" * 64
    assert _well_formed(good) is True
    assert _well_formed("sha256:raw-bytes:v1:" + "ab" * 32) is True

    for bad, why in [
        ("x:y:z:5", "one hex char, no algorithm, no recipe"),
        ("md5:lol:v9:deadbeef", "wrong algorithm and an 8-char body"),
        ("sha256:raw-bytes:v1:0x" + "f" * 62, "int(_, 16) accepts an 0x prefix"),
        ("sha256:raw-bytes:v1:-" + "f" * 63, "int(_, 16) accepts a sign"),
        ("sha256:raw-bytes:v1:" + "f_f" + "f" * 60, "int(_, 16) accepts underscores"),
        ("sha256:raw-bytes:v1: " + "f" * 63 + " ", "int(_, 16) strips whitespace"),
        ("sha256:raw-bytes:v1:" + "٠" * 64, "Arabic-Indic digits are int()-parseable"),
        ("sha256:json-c14n:v1:" + "A" * 64, "hexdigest() is lowercase"),
        ("sha256:json-c14n:v1:" + "f" * 63, "63 chars is not a sha256"),
        ("sha256:json-c14n:v1:" + "f" * 65, "65 chars is not a sha256"),
        ("not-a-real-digest", "no colons at all"),
    ]:
        assert _well_formed(bad) is False, f"accepted {bad!r} ({why})"
    print("PASS _well_formed rejects 11 digests that only look right")


def test_golden_fixture_set_is_never_silently_empty():
    """Both golden tests are bare `for case in ...` loops that print an
    affirmative PASS. On an empty `cases` list they pass in 0.8s having checked
    nothing, and announce that zero cases matched. A truncated file or a bad
    regeneration turns the package's only cross-version guarantee into a no-op
    that reports success, so the count is pinned here.
    """
    cases = _GOLDEN_FIXTURES["cases"]
    assert cases, "golden fixture set is EMPTY -- the golden tests would pass vacuously"
    assert len(cases) == 4, (
        f"golden fixture count changed to {len(cases)}; if that is intentional, "
        f"update this pin -- it exists so an emptied fixture file cannot mint a green")


def test_verify_receipt_declares_that_its_scope_is_structural_only():
    """`ok: True` from this function means "the shape is consistent", NOT
    "these digests describe this content" -- it cannot mean the latter, because
    the receipt deliberately never carries the original input.

    A receipt with a made-up strategy, a negative budget and three fabricated
    digests used to come back `{"ok": True, "notes": ["self-consistent"]}` with
    nothing in the result naming how narrow that check was. The caller branches
    on `ok`, so the result object has to carry its own scope.
    """
    r = distill({"a": "b" * 500}, budget=10).receipt.to_dict()

    honest = verify_receipt(r)
    assert honest["ok"] is True
    assert honest["verified_scope"] == "structural_only", (
        "a clean structural check must say that structure is all it checked")

    forged = dict(r)
    forged["full"] = {"digest": "sha256:json-c14n:v1:" + "0" * 64, "bytes": 1}
    forged["distilled"] = {"digest": "sha256:json-c14n:v1:" + "1" * 64, "bytes": 1}
    got = verify_receipt(forged)
    # Structural review still passes -- that is the honest answer, and the
    # scope field is what stops it from reading as content verification.
    assert got["verified_scope"] == "structural_only"
    assert any("does not re-derive" in n or "structural" in n.lower()
               for n in got["notes"]), (
        f"a structural-only pass must say so in its notes; got {got['notes']}")

    bad_schema = dict(r, schema="not-a-real-schema/v9")
    assert verify_receipt(bad_schema)["verified_scope"] == "unknown_schema"

    missing = {k: v for k, v in r.items() if k != "drops"}
    assert verify_receipt(missing)["verified_scope"] == "malformed"
    print("PASS verify_receipt carries verified_scope on all four return paths")


# ---------------------------------------------------------------------------
# 0.1.6 sell-code audit regressions. Every one of these was a raw crash --
# AttributeError / UnicodeEncodeError / RecursionError -- reachable from a
# normal call, on inputs the package's own contract says it refuses "at the
# door" with a typed error, or (verify_receipt) says it fails safe on.
# ---------------------------------------------------------------------------

def _refusal(exc_type, fn, *args, **kwargs) -> str:
    """Call fn; return the message of the exc_type it raised. Fails the test
    if it returned, or raised something else (a RecursionError, a
    UnicodeEncodeError) -- the 'something else' is the bug class here."""
    try:
        fn(*args, **kwargs)
    except exc_type as e:
        if type(e) is not exc_type:
            raise AssertionError(f"raised {type(e).__name__}, not {exc_type.__name__}: {e}")
        return str(e)
    except BaseException as e:  # noqa: BLE001
        raise AssertionError(f"raised {type(e).__name__}, not {exc_type.__name__}: {e}")
    raise AssertionError(f"{fn.__name__} accepted {args[:1]!r} instead of refusing")

def test_verify_receipt_fails_safe_on_malformed_shapes_instead_of_raising():
    """A verifier gets pointed at receipts it did not mint. `full` as a
    string, `drops` as a string, a drop that is not an object, or a receipt
    that is not an object at all used to escape as AttributeError/TypeError
    from `.get`/`dict()`; each is a malformed receipt and must be reported
    as one."""
    good = distill({"a": "b" * 500}, budget=10).receipt.to_dict()
    bad_shapes = {
        "full is a str": dict(good, full="x"),
        "distilled is None": dict(good, distilled=None),
        "drops is a str": dict(good, drops="nope"),
        "drop item is a str": dict(good, drops=["x"]),
        "receipt is a list": [1, 2],
        "receipt is None": None,
    }
    for label, bad in bad_shapes.items():
        got = verify_receipt(bad)  # must not raise
        assert got["ok"] is False, label
        assert got["verified_scope"] == "malformed", (label, got)
        assert any("malformed" in n for n in got["notes"]), (label, got)
    # the good receipt still verifies through the same code path
    assert verify_receipt(good)["verified_scope"] == "structural_only"
    print("PASS verify_receipt reports malformed shapes instead of raising")


def test_lone_surrogates_are_refused_at_the_door_for_every_input_form():
    """A str with a lone surrogate (surrogateescape output, or the JSON
    escape for U+D800 inside JSON text) has no UTF-8 serialization. Before
    0.1.6, receipt=True died with a UnicodeEncodeError from the digest step
    and receipt=False returned the string as if nothing were wrong -- the two
    switches disagreed about admissibility. Both now refuse, typed, naming
    the path, for a Python value, a dict KEY, and a JSON-text escape."""
    bad = "a" + chr(0xD800) + "b"
    json_escape = '{"k": "a' + chr(92) + 'ud800b"}'  # {"k": "a\ud800b"} as bytes on the wire
    cases = {
        "value": {"k": bad},
        "key": {bad: 1},
        "list item": ["ok", bad],
        "bare str": bad,
        "json text escape": json_escape,
    }
    for label, value in cases.items():
        for rc in (True, False):
            msg = _refusal(ValueError, distill, value, budget=1000, receipt=rc)
            assert "lone surrogate" in msg and msg.startswith("input"), (label, rc, msg)
    assert "['k']" in _refusal(ValueError, distill, {"k": bad}, budget=10)
    # non-ASCII text that IS valid UTF-8 is untouched by the new check
    ok = distill({"k": "café \U0001f525"}, budget=1000)
    assert ok.content == {"k": "café \U0001f525"}
    print("PASS lone surrogates refused at the door, receipt on or off")


def test_nan_inside_json_text_gets_the_same_typed_refusal_as_a_python_nan():
    """`json.loads` accepts the NaN/Infinity tokens, so NaN arriving as JSON
    TEXT slipped past the admission walker (which only saw the raw str) and
    surfaced as json.dumps's own "Out of range float" ValueError from deep
    inside a strategy, with no path. The parsed value now takes the same
    door as a Python object."""
    for text, hint in (('{"x": NaN}', None), ("[1, Infinity]", None),
                       ("NaN", "json"), ('{"x": -Infinity}', "json")):
        msg = _refusal(ValueError, distill, text, budget=1000, schema_hint=hint)
        assert "NaN/Infinity" in msg and msg.startswith("input"), (text, msg)
    print("PASS NaN in JSON text is refused with the walker's path-named error")


def test_pathological_nesting_is_a_typed_refusal_not_a_recursion_error():
    """json.loads, the JSON walker and json.dumps are all recursive; input
    nested thousands deep used to escape as a raw RecursionError. It is now
    a ValueError like every other refused input. Depth 5000 is well past the
    default recursion limit (1000) on every supported Python."""
    deep = []
    for _ in range(5000):
        deep = [deep]
    assert "nests deeper" in _refusal(ValueError, distill, deep, budget=100)
    assert "nests deeper" in _refusal(ValueError, distill, "[" * 5000 + "]" * 5000, budget=100)
    # modest nesting is still distilled, not refused
    shallow = {"a": {"b": {"c": {"d": [1, [2, [3]]]}}}}
    assert distill(shallow, budget=10_000).content == shallow
    print("PASS pathological nesting is refused with ValueError")


def test_mcp_server_survives_non_object_jsonrpc_lines():
    """One line that parses as JSON but is not an object ([1,2], "x", 123,
    null) used to raise AttributeError out of handle() and kill the server,
    so every valid call after it went unanswered. Same for a non-object
    `params`. Checked at the function AND end-to-end over stdio: the
    tools/list sent AFTER the bad lines must still get its answer.

    0.1.7 tightened the answer. 0.1.6 stopped the crash by returning None,
    i.e. silence, and this test asserted that silence. JSON-RPC 2.0 answers a
    non-object request with Invalid Request and a null id, and a caller that
    sent a request and got nothing waits forever - a hang is a quieter version
    of the same defect. So the survival guarantee below is unchanged and the
    response assertion is now -32600 rather than None."""
    from arcaeon.save.distill import mcp_server
    for msg in ([1, 2], "x", 123, None):
        resp = mcp_server.handle(msg)
        assert resp["id"] is None and resp["error"]["code"] == -32600, resp
    bad_params = mcp_server.handle({"id": 7, "method": "tools/call", "params": [1]})
    assert bad_params["id"] == 7 and bad_params["error"]["code"] == -32602

    lines = ('[1,2]\n"x"\n123\nnull\n'
             '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[1]}\n'
             '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n')
    proc = subprocess.run(
        [sys.executable, "-m", "arcaeon.save.distill.mcp_server"], input=lines.encode(),
        capture_output=True, cwd=str(Path(__file__).resolve().parent), timeout=30)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    responses = [json.loads(l) for l in proc.stdout.decode().splitlines() if l.strip()]
    # Four Invalid Request answers (id null), then the two real replies. The
    # point of the test is the tail: id 1 and id 2 still get answered.
    assert [r["id"] for r in responses] == [None, None, None, None, 1, 2], responses
    # The four Invalid Request answers come first now, so the two real replies
    # sit at the tail rather than at index 0 and 1.
    assert all(r["error"]["code"] == -32600 for r in responses[:4]), responses[:4]
    assert responses[4]["error"]["code"] == -32602
    assert responses[5]["result"]["tools"][0]["name"] == "distill_tool_output"
    print("PASS MCP server keeps answering after non-object JSON-RPC lines")


def _calls_rows(path):
    return [json.loads(l) for l in Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]


def test_mcp_server_every_tool_call_leaves_a_chained_record(tmp_path, monkeypatch):
    """OWASP MCP08. arcaeon-mcp-vet graded this server gate 0 of 4 on
    2026-09-02: no record of a tool call on any tool path. Every tools/call
    now appends one hash-chained row (tool, server timestamp, args digest,
    outcome) to the call record, and the chain verifies."""
    from arcaeon.save.distill import mcp_server
    from arcaeon.record.call_record import verify_call_record
    rec = tmp_path / "calls.jsonl"
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(rec))
    r = mcp_server.handle({"id": 1, "method": "tools/call", "params": {
        "name": "distill_tool_output", "arguments": {"tool_output": "a b c", "budget": 5}}})
    assert "isError" not in r["result"]
    rows = _calls_rows(rec)
    assert len(rows) == 1
    row = rows[0]
    assert row["tool"] == "distill_tool_output" and row["ok"] is True
    assert row["ts"].endswith("+00:00") and len(row["chain"]) == 32
    assert row["args"] == {"tool_output": "a b c", "budget": 5}
    assert row["args_digest"] == hashlib.sha256(
        json.dumps(row["args"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    assert verify_call_record(rec) == {"ok": True, "rows": 1, "first_break": None}
    print("PASS MCP server leaves a chained call record")


def test_mcp_server_records_failed_calls_and_a_tampered_record_fails_verify(tmp_path, monkeypatch):
    from arcaeon.save.distill import mcp_server
    from arcaeon.record.call_record import verify_call_record
    rec = tmp_path / "calls.jsonl"
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(rec))
    mcp_server.handle({"id": 1, "method": "tools/call", "params": {
        "name": "distill_tool_output", "arguments": {"tool_output": "x"}}})
    bad = mcp_server.handle({"id": 2, "method": "tools/call", "params": {
        "name": "distill_tool_output", "arguments": {}}})
    assert bad["result"]["isError"] is True
    unk = mcp_server.handle({"id": 3, "method": "tools/call", "params": {"name": "nope"}})
    assert unk["result"]["isError"] is True
    rows = _calls_rows(rec)
    assert [r["ok"] for r in rows] == [True, False, False]
    assert "tool_output is required" in rows[1]["error"]
    assert rows[2]["tool"] == "nope"
    assert verify_call_record(rec)["ok"] is True
    # edit the middle row's outcome: the chain must break at line 2
    lines = rec.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"ok": false', '"ok": true')
    rec.write_text("\n".join(lines) + "\n", encoding="utf-8")
    v = verify_call_record(rec)
    assert v["ok"] is False and v["first_break"] == 2
    print("PASS failed calls are recorded and tampering is caught")


def test_mcp_server_call_record_verifies_under_arcaeon_ledger(tmp_path, monkeypatch):
    """Same chain format as arcaeon-ledger, on purpose: one record format
    across the five servers, and a reader with the full ledger installed can
    verify this file with the tool they already have."""
    pytest.importorskip("arcaeon.record.ledger")
    from arcaeon.record.ledger import verify_file
    from arcaeon.save.distill import mcp_server
    rec = tmp_path / "calls.jsonl"
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(rec))
    for i in range(3):
        mcp_server.handle({"id": i, "method": "tools/call", "params": {
            "name": "distill_tool_output", "arguments": {"tool_output": "x" * i}}})
    v = verify_file(str(rec))
    assert v.ok is True and v.rows == 3, v
    print("PASS call record verifies under arcaeon-ledger")


def test_mcp_server_verify_calls_flag(tmp_path, monkeypatch):
    from arcaeon.save.distill import mcp_server
    rec = tmp_path / "calls.jsonl"
    monkeypatch.setenv("ARCAEON_CALL_RECORD", str(rec))
    mcp_server.handle({"id": 1, "method": "tools/call", "params": {
        "name": "distill_tool_output", "arguments": {"tool_output": "x"}}})
    proc = subprocess.run([sys.executable, "-m", "arcaeon.save.distill.mcp_server", "--verify-calls"],
                          capture_output=True, cwd=str(Path(__file__).resolve().parent),
                          env={**os.environ, "ARCAEON_CALL_RECORD": str(rec)}, timeout=30)
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    out = json.loads(proc.stdout.decode())
    assert out["ok"] is True and out["rows"] == 1
    print("PASS --verify-calls reports the record verdict")
