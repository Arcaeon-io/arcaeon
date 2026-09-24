"""0.1.5 — sell-code audit, 2026-09-01. Each test was RED against 0.1.4.

Three findings, none of them a verdict change on an honest row:

  1. `verify_receipt` CRASHED (TypeError / AttributeError) on a malformed or
     hostile row -- a string count, a null count, a non-list manifest, an
     object or int inside the manifest, a row that is not an object. A
     verifier that raises on the thing it verifies can be switched off by
     one planted row in a ledger sweep. It now returns ok=False with a
     "malformed receipt row" note, like the unknown-schema path always did.
  2. `_well_formed` used `int(tail, 16)`, which accepts `0x1f`, `+1f`,
     ` 1f`, `1_f` -- shapes no digest recipe emits (disclosed in 0.1.3's
     changelog, unfixed until now). Explicit lowercase-hex allowlist.
  3. README + docstring said "an edited row is caught even out of its
     ledger"; the receipt_digest covers only the core, so a backdated `ts`
     / `opened_at` passes out-of-ledger verification. Wording fixed; the
     limitation is pinned here so a future change to the core is deliberate.
"""
import json
import tempfile
from pathlib import Path

import pytest

from arcaeon.prove.compact import (CompactionReceipt, verify_receipt, _core_body,
                             _well_formed, __version__)
from arcaeon.record.ledger import digest_json

PRE = ["a" * 100, "b" * 400]
POST = ["a" * 100, "sum"]


def _honest():
    with tempfile.TemporaryDirectory() as d:
        r = CompactionReceipt.open(PRE)
        r.record_kept(POST)
        return r.seal(Path(d) / "l.jsonl", compactor="c", method="m")


def _forge(row, **overrides):
    forged = json.loads(json.dumps(row))
    forged.update(json.loads(json.dumps(overrides)))
    forged["receipt_digest"] = digest_json(_core_body(forged))
    return forged


# --------------------------------------------------------------------------
# 1. a hostile row gets a verdict, not a traceback
# --------------------------------------------------------------------------

@pytest.mark.parametrize("row", [["not", "a", "row"], "row", None, 7])
def test_non_object_row_is_a_verdict_not_a_crash(row):
    v = verify_receipt(row)
    assert v["ok"] is False and v["self_consistent"] is False
    assert any("malformed receipt row" in n for n in v["notes"]), v["notes"]


@pytest.mark.parametrize("block,key,bad", [
    ("pre", "count", "2"), ("dropped", "count", None), ("post", "bytes", 1.5),
    ("introduced", "count", True), ("pre", "bytes", -1),
    ("introduced", "bytes", "3"),
])
def test_non_integer_counts_are_refused_without_crashing(block, key, bad):
    row = _honest()
    forged = _forge(row, **{block: {**row[block], key: bad}})
    v = verify_receipt(forged)
    assert v["ok"] is False and v["self_consistent"] is False, v
    assert any("non-negative integers" in n for n in v["notes"]), v["notes"]


@pytest.mark.parametrize("items", [7, None, "sha256:raw-bytes:v1:ab",
                                   [{"x": 1}], [5], [None], {"k": "v"}])
def test_bad_manifest_is_refused_with_and_without_content(items):
    row = _honest()
    forged = _forge(row, dropped={**row["dropped"], "items": items})
    for args in ((), (PRE,), (PRE, POST)):
        v = verify_receipt(forged, *args)
        assert v["ok"] is False and v["self_consistent"] is False, (args, v)
        assert any("dropped.items must be a list" in n for n in v["notes"]), v["notes"]


def test_honest_row_still_verifies_after_the_shape_gate():
    """GREEN CONTROL: the gate must not eat a real receipt."""
    row = _honest()
    v = verify_receipt(row, PRE, POST)
    assert v["ok"] and v["verified_scope"] == "full" and v["notes"] == [], v


# --------------------------------------------------------------------------
# 2. a digest tail is hex, not whatever int() will swallow
# --------------------------------------------------------------------------

@pytest.mark.parametrize("tail", ["0x1f", "+1f", " 1f", "1_f", "1F", "1f\n", ""])
def test_well_formed_rejects_int_isms(tail):
    assert not _well_formed(f"sha256:raw-bytes:v1:{tail}"), tail


def test_well_formed_accepts_a_real_digest():
    row = _honest()
    for d in (row["pre"]["digest"], row["post"]["digest"],
              row["receipt_digest"], *row["dropped"]["items"]):
        assert _well_formed(d), d


# --------------------------------------------------------------------------
# 3. what out-of-ledger verification does NOT cover, said out loud
# --------------------------------------------------------------------------

def test_timestamps_are_outside_the_receipt_digest():
    """A backdated copy passes out of the ledger. That is the documented
    limit, not a bug; this pins it so the core cannot grow or shrink quietly."""
    row = _honest()
    backdated = dict(row, ts="1999-01-01T00:00:00Z", opened_at="1999-01-01T00:00:00Z")
    assert verify_receipt(backdated)["ok"] is True
    assert set(_core_body(row)) == {"schema", "pre", "post", "dropped",
                                    "introduced", "compactor", "method"}
    readme = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")
    assert "does\n  **not** cover `ts` or `opened_at`" in readme
    assert "so an edited row is\n  caught even when it's been copied" not in readme


def test_readme_status_names_the_shipped_version():
    readme = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")
    assert f"\nv{__version__}. " in readme, "README Status line lags the package"
