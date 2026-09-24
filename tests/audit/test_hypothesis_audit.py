"""Hypothesis-driven property tests for arcaeon_audit's core verify invariants.

arcaeon-audit's tamper-evidence rides entirely on arcaeon-ledger's hash chain
(`verify_file`, imported and re-exported unchanged) plus a witness-based
truncation cross-check layered on top in `export_bundle`. These tests probe
the invariants at AUDIT's own surface -- `AuditLog.record`/`.verify`/
`.export_bundle` -- rather than re-testing the ledger primitives already
covered by arcaeon-ledger's own property suite (test_property_ledger.py,
test_hypothesis_ledger.py). Three invariants, named:

  1. HONEST RECORDS EXPORT CLEAN: any sequence of `.record()` calls, any
     content, must produce chain_ok=True, zero unreadable lines, and a
     verdict that is never "FAIL".

  2. ANY ROW MUTATION IN THE EXPORTED LOG FAILS THE BUNDLE: edit one row's
     content in records.jsonl post-export (leave its stale chain), and the
     bundle's own re-verification (integrity.json, reproducible by anyone
     via `verify_file(records.jsonl)`) must report chain_ok=False and
     verdict="FAIL" -- regardless of whether a witness is configured, since
     an in-chain edit is a strictly stronger break than truncation.

  3. UNICODE / LINE-BOUNDARY LOOKALIKES SURVIVE THE FULL PIPELINE: U+0085 /
     U+2028 / U+2029 (the characters implicated in last night's continuity
     splitlines find, and confirmed present as a real bug in
     arcaeon-ledger's read path -- fixed as part of this same pass) embedded
     in `inputs`/`outputs`/`decision` fields must not corrupt row counts,
     content, or the chain verdict anywhere in record -> export ->
     re-verify. `_read_rows` in arcaeon_audit already reads with
     `raw.split(b"\\n")` (byte-level, not str.splitlines()) so it was never
     vulnerable itself; this test locks that in and additionally exercises
     the composed pipeline through the now-fixed arcaeon_ledger.verify_file.

A fourth test covers the witness-based truncation/rewrite verdicts across
randomized pin/truncate points, since that logic is audit's own (not
inherited from the ledger) and was the subject of the 0.1.3/0.1.4 hardening
passes in CHANGELOG.md.

Run: python -m pytest test_hypothesis_audit.py -q
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from hypothesis import given, settings, HealthCheck, strategies as st

from arcaeon.prove.audit import AuditLog, export_bundle
from arcaeon.record.ledger import Ledger, verify_file
from arcaeon.record.ledger.witness import WitnessStore, publish_head


# --- strategies --------------------------------------------------------------

_safe_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), max_codepoint=0x10FFFF),
    max_size=25,
)

_json_scalar = st.one_of(
    st.none(), st.booleans(),
    st.integers(min_value=-10**9, max_value=10**9),
    st.floats(allow_nan=False, allow_infinity=False, width=32),
    _safe_text,
)

_json_value = st.recursive(
    _json_scalar,
    lambda children: st.one_of(
        st.lists(children, max_size=3),
        st.dictionaries(_safe_text, children, max_size=3),
    ),
    max_leaves=6,
)

_event = st.sampled_from(["tool_call", "decision", "output", "input",
                          "human_review", "error", "custom_unknown_type"])

_record_kwargs = st.fixed_dictionaries({
    "event": _event,
    "inputs": _json_value,
    "outputs": _json_value,
    "decision": _safe_text,
})

# The exact line-boundary lookalikes: NOT escaped by json.dumps(...,
# ensure_ascii=False) (outside the mandatory U+0000-U+001F range) but treated
# as row boundaries by str.splitlines() -- distinct from the ledger's actual
# "\n" delimiter. This was a real, confirmed bug in arcaeon-ledger's read
# path (fixed as part of this pass); audit's own _read_rows was never
# vulnerable (splits on b"\n" directly), but the composed pipeline still
# needs to prove it end to end.
LINE_BOUNDARY_LOOKALIKES = "   "

# NOTE on fixtures: every test below builds its own tempfile.mkdtemp() dir
# inside the function body instead of taking pytest's `tmp_path` as a
# parameter. `tmp_path` is scoped to the test FUNCTION CALL, not to each of
# Hypothesis's internal replays -- reusing it across examples silently
# accumulates rows from every prior example into the same file (this bit the
# sibling arcaeon-ledger property suite first; fixed here before it could
# repeat the same false failure).
_slow_settings = settings(max_examples=40, deadline=None,
                          suppress_health_check=[HealthCheck.too_slow])
_char_settings = settings(max_examples=60, deadline=None,
                          suppress_health_check=[HealthCheck.too_slow])


def _new_log(d: Path) -> tuple[AuditLog, Path]:
    p = d / "audit.jsonl"
    return AuditLog(p, system_id="prop-test-system", provider="Arcaeon"), p


def _fresh_dir(prefix: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix))


# --- 1. honest records export clean -------------------------------------------

@_slow_settings
@given(records=st.lists(_record_kwargs, min_size=1, max_size=10))
def test_honest_records_export_clean_never_FAIL(records):
    d = _fresh_dir("audit_hyp_")
    log, p = _new_log(d)
    for r in records:
        log.record(agent="test-agent", event=r["event"], inputs=r["inputs"],
                   outputs=r["outputs"], decision=r["decision"])

    assert log.verify().ok

    out = log.export_bundle(d / "bundle")
    integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert integ["chain_ok"] is True
    assert integ["finding"] != "FAIL"
    assert integ["unreadable_lines"] == 0
    assert manifest["unreadable_lines"] == 0
    assert manifest["record_count"] == len(records)


# --- 2. any row mutation in the exported log fails the bundle ----------------

@_slow_settings
@given(records=st.lists(_record_kwargs, min_size=1, max_size=10),
       seed=st.integers(min_value=0))
def test_any_row_mutation_in_export_fails_verdict(records, seed):
    d = _fresh_dir("audit_hyp_")
    log, p = _new_log(d)
    for r in records:
        log.record(agent="test-agent", event=r["event"], inputs=r["inputs"],
                   outputs=r["outputs"], decision=r["decision"])

    out = log.export_bundle(d / "bundle")
    rec_path = out / "records.jsonl"
    lines = rec_path.read_text(encoding="utf-8").split("\n")
    body_idx = [i for i, ln in enumerate(lines) if ln.strip()]
    assert len(body_idx) == len(records)

    target = body_idx[seed % len(body_idx)]
    obj = json.loads(lines[target])
    obj["decision"] = f"__mutated__{obj.get('decision')}"
    stale_chain = obj["chain"]
    mutated = json.dumps({**{k: v for k, v in obj.items() if k != "chain"},
                          "chain": stale_chain}, ensure_ascii=False)
    if mutated == lines[target]:
        return
    lines[target] = mutated
    rec_path.write_text("\n".join(lines), encoding="utf-8")

    vr = verify_file(rec_path)
    assert not vr.ok, "row mutation went undetected in re-verification"

    # re-run export_bundle over the now-tampered source to prove the FULL
    # bundle path (not just verify_file) reports the break honestly
    out2 = export_bundle(rec_path, d / "bundle2",
                         system_id="prop-test-system")
    integ2 = json.loads((out2 / "integrity.json").read_text(encoding="utf-8"))
    assert integ2["chain_ok"] is False
    assert integ2["finding"] == "FAIL"
    assert integ2["first_break"] is not None


# --- 3. unicode / line-boundary lookalikes survive the full pipeline ---------

@_char_settings
@given(values=st.lists(
    st.text(alphabet=LINE_BOUNDARY_LOOKALIKES + "abcXYZ 09", min_size=1, max_size=20),
    min_size=1, max_size=6))
def test_line_boundary_lookalikes_survive_record_export_reverify(values):
    d = _fresh_dir("audit_hyp_")
    log, p = _new_log(d)
    for v in values:
        log.record(agent="test-agent", event="decision",
                   inputs={"raw": v}, outputs={"echo": v}, decision=v)

    assert log.verify().ok, "honest lookalike-bearing log verified RED"

    out = log.export_bundle(d / "bundle")
    integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    assert integ["chain_ok"] is True
    assert integ["unreadable_lines"] == 0, (
        "a lookalike character fractured a row into an unreadable fragment")
    assert integ["rows"] == len(values)
    assert manifest["record_count"] == len(values)

    # content round-trips exactly through the exported, byte-identical file
    rows = list(Ledger(out / "records.jsonl"))
    assert len(rows) == len(values)
    for original, row in zip(values, rows):
        assert row["decision"] == original
        assert row["inputs"]["raw"] == original
        assert row["outputs"]["echo"] == original


@_char_settings
@given(pos=st.integers(min_value=0, max_value=2),
       ch=st.sampled_from(list(LINE_BOUNDARY_LOOKALIKES)))
def test_each_lookalike_char_individually_survives_export(pos, ch):
    d = _fresh_dir("audit_hyp_")
    log, p = _new_log(d)
    log.record(agent="a", event="decision", decision="before")
    text = {0: ch + "xy", 1: "x" + ch + "y", 2: "xy" + ch}[pos]
    log.record(agent="a", event="decision", decision=text)
    log.record(agent="a", event="decision", decision="after")

    out = log.export_bundle(d / "bundle")
    integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
    assert integ["chain_ok"] is True and integ["rows"] == 3, (
        f"char {ch!r} at pos {pos} broke the export: {integ}")
    rows = list(Ledger(out / "records.jsonl"))
    assert rows[1]["decision"] == text


# --- 4. witness truncation/rewrite verdicts under randomized pin points ------

@_slow_settings
@given(n=st.integers(min_value=2, max_value=8),
       keep=st.integers(min_value=1, max_value=7))
def test_witness_truncation_verdict_matches_pin_vs_keep(n, keep):
    """Pin the witness at `n` rows; truncate the exported log to `keep` rows
    (< n or == n). The verdict must be exactly PASS when untouched and
    exactly TRUNCATION_DETECTED whenever rows were actually dropped below
    the pinned count -- never a silent PASS on a shortened log."""
    if keep > n:
        return
    d = _fresh_dir("audit_hyp_")
    log, p = _new_log(d)
    for i in range(n):
        log.record(agent="a", event="decision", decision=f"d{i}")

    store = WitnessStore(d / "witness.jsonl")
    ns = "prop/ns"
    publish_head(store, ns, Ledger(p))  # witness sees n rows

    if keep < n:
        lines = p.read_text(encoding="utf-8").split("\n")
        body = [ln for ln in lines if ln.strip()]
        p.write_text("\n".join(body[:keep]) + "\n", encoding="utf-8")

    out = export_bundle(p, d / "bundle", system_id="prop-test-system",
                        witness=store, witness_namespace=ns)
    integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))

    if keep == n:
        assert integ["finding"] == "PASS", integ
        assert integ["truncation_ok"] is True
    else:
        assert integ["finding"] == "TRUNCATION_DETECTED", integ
        assert integ["truncation_ok"] is False
        assert integ["witness"]["local_rows"] == keep
        assert integ["witness"]["witness_rows"] == n


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
