# SPDX-License-Identifier: MIT
"""integrity.json's `verdict` is the one Arcaeon word; `finding` is the detail.

0.9.0 moved arcaeon-audit's ten-value string (PASS, VERIFIED_MODULO_TRUNCATION,
EMPTY_LOG, FAIL, ...) from `verdict` to `finding`, unchanged, and put the
arcaeon.verdict word in `verdict`. The word follows the export exit code; the
finding keeps the distinctions the word does not carry (a truncation that was
never checked, an empty log). These tests pin that the two never disagree, on
every path the export can take, and that a bundle exported by the old code
(finding in `verdict`, no `finding` key) still verifies and still reads.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from arcaeon import verdict as V
from arcaeon.prove.audit import FINDING_WORD, export_bundle, finding_of, word_for_finding
from arcaeon.record.ledger import Ledger, verify_file
from arcaeon.record.ledger.witness import WitnessStore, publish_head


def _run(*args):
    p = subprocess.run([sys.executable, "-m", "arcaeon.prove.audit.cli", *args],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace")
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def _chained(d, n=6):
    p = Path(d) / "audit.jsonl"
    log = Ledger(p)
    for i in range(n):
        log.append({"actor": "agent", "decision": f"d{i}"})
    return p


def _pinned(d, p, ns="acme-prod"):
    store = WitnessStore(Path(d) / "w.jsonl")
    publish_head(store, ns, Ledger(p))
    return store


def _truncate(p, keep):
    rows = p.read_text(encoding="utf-8").strip().split("\n")
    p.write_text("\n".join(rows[:keep]) + "\n", encoding="utf-8")


def _path_pass(d):
    p = _chained(d)
    return p, ["--witness", str(_pinned(d, p).path), "--namespace", "acme-prod"]


def _path_modulo_truncation(d):
    return _chained(d), []


def _path_empty(d):
    p = Path(d) / "audit.jsonl"
    p.write_text("", encoding="utf-8")
    return p, []


def _path_fail(d):
    p = _chained(d)
    p.write_text(p.read_text(encoding="utf-8").replace('"d2"', '"dX"'), encoding="utf-8")
    return p, []


def _path_truncated(d):
    p = _chained(d, n=10)
    store = _pinned(d, p)
    _truncate(p, 6)
    return p, ["--witness", str(store.path), "--namespace", "acme-prod"]


def _path_witness_no_record(d):
    p = _chained(d)
    store = _pinned(d, p)
    return p, ["--witness", str(store.path), "--namespace", "mistyped-namespace"]


def _path_unverified_scope(d):
    p = _chained(d)
    rows = p.read_text(encoding="utf-8").strip().split("\n")
    rows = [re.sub(r',\s*"chain":\s*"[0-9a-f]+"\s*\}$', "}", r) for r in rows]
    p.write_text("\n".join(rows) + "\n", encoding="utf-8")
    return p, []


# (builder, expected finding, expected word): the pass, fail and could-not-look
# paths the export can actually reach from the command line.
PATHS = [
    (_path_pass, "PASS", V.VERIFIED),
    (_path_modulo_truncation, "VERIFIED_MODULO_TRUNCATION", V.VERIFIED),
    (_path_empty, "EMPTY_LOG", V.COULD_NOT_LOOK),   # qa-fixes 2026-09-24: was VERIFIED
    (_path_fail, "FAIL", V.BROKEN),
    (_path_truncated, "TRUNCATION_DETECTED", V.BROKEN),
    (_path_witness_no_record, "WITNESS_CHECK_FAILED", V.COULD_NOT_LOOK),
    (_path_unverified_scope, "UNVERIFIED_SCOPE", V.COULD_NOT_LOOK),
]


@pytest.mark.parametrize("build,finding,word", PATHS, ids=[f for _, f, _ in PATHS])
def test_word_and_finding_agree_with_each_other_and_the_exit_code(build, finding, word):
    with tempfile.TemporaryDirectory() as d:
        p, extra = build(d)
        out = Path(d) / "bundle"
        code, text = _run("export", str(p), str(out), *extra)
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))

        assert list(integ)[:2] == ["verdict", "finding"], list(integ)[:3]
        assert integ["finding"] == finding, text
        assert integ["verdict"] == word, integ
        assert integ["verdict"] == word_for_finding(integ["finding"])
        # the word's exit code in the one table == the export's code, once the
        # front door has translated the old could-not-complete 2 into 3
        assert V.exit_for(integ["verdict"]) == V.unify("audit", code), (code, text)
        assert f"Verdict: {word}" in text and f"finding: {finding}" in text


def test_every_finding_maps_onto_a_word_from_arcaeon_verdict():
    known = ["PASS", "VERIFIED_MODULO_TRUNCATION", "EMPTY_LOG", "FAIL",
             "TRUNCATION_DETECTED", "REWRITE_DETECTED", "WITNESS_CHECK_FAILED",
             "UNVERIFIED_SCOPE", "UNRECOGNIZED_WITNESS_VERDICT:quantum_uncertain",
             "UNRECOGNIZED_WITNESS_VERDICT:none"]
    for f in known:
        assert word_for_finding(f) in (V.VERIFIED, V.BROKEN, V.COULD_NOT_LOOK)
    assert set(FINDING_WORD.values()) <= set(V.WORDS)
    # anything this table has never heard of is never a green
    assert word_for_finding("SOMETHING_NEW") == V.COULD_NOT_LOOK
    assert V.exit_for(word_for_finding("SOMETHING_NEW")) == V.EXIT_COULD_NOT_LOOK


def test_a_bundle_exported_by_the_old_code_still_verifies_and_reads():
    """Old shape (arcaeon-audit 0.1.8): the finding sat in `verdict` and there
    was no `finding` key. Rebuilt from a real export so every other field is
    exactly what the old code wrote."""
    with tempfile.TemporaryDirectory() as d:
        p, extra = _path_pass(d)
        store = WitnessStore(Path(extra[1]))
        out = export_bundle(p, Path(d) / "bundle", witness=store,
                            witness_namespace="acme-prod")
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        old = {"verdict": integ.pop("finding")}
        integ.pop("verdict")
        old.update(integ)
        (out / "integrity.json").write_text(json.dumps(old, indent=2), encoding="utf-8")

        old = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert "finding" not in old and old["verdict"] == "PASS"
        assert finding_of(old) == "PASS"
        assert word_for_finding(finding_of(old)) == V.VERIFIED

        # the bundle's own re-check still holds: the pinned bytes and the chain
        import hashlib
        records = out / "records.jsonl"
        assert hashlib.sha256(records.read_bytes()).hexdigest() == old["records_sha256"]
        assert verify_file(records).ok is True
        code, text = _run("verify", str(records))
        assert code == 0, text
