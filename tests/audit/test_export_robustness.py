"""Regression tests for the 0.1.2 export audit.

The export exists to hand a regulator the evidence. Written FAILING against
0.1.1, where it crashed on exactly the logs that most need exporting: the
damaged ones.

Run: python -m pytest test_export_robustness.py
"""
import json
import tempfile
from pathlib import Path

import pytest

from arcaeon.prove.audit import AuditLog, export_bundle
from arcaeon.record.ledger import verify_file


def _log(d, n=2):
    p = Path(d) / "audit.jsonl"
    log = AuditLog(p, system_id="triage-v3", provider="Acme AI")
    for i in range(n):
        log.record(event="decision", agent="triage-v3", decision=f"d{i}")
    return log, p


# --------------------------------------------------------------------------
# 1. A damaged log must EXPORT (with a FAIL verdict), never crash
# --------------------------------------------------------------------------

@pytest.mark.parametrize("junk,label", [
    (b"{oops truncated write\n", "unparseable"),
    (b"\xff\xfe not utf-8\n", "undecodable"),
    (b"123\n", "non-object"),
    (b"\n\n", "blank"),
])
def test_export_survives_a_damaged_log(junk, label):
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d)
        with p.open("ab") as fh:
            fh.write(junk)
        out = log.export_bundle(Path(d) / "bundle")     # must not raise
        integrity = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")
        if label == "blank":
            assert integrity["ok"] is True
        else:
            assert integrity["ok"] is False, f"{label} did not fail integrity"
            assert integrity["first_break"], integrity
            assert "FAIL" in summary
            assert manifest["unreadable_lines"] >= 1, manifest


# --------------------------------------------------------------------------
# 2. records.jsonl must be the source bytes, and integrity must describe IT
# --------------------------------------------------------------------------

def test_records_are_byte_identical_to_the_source_log():
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=3)
        out = log.export_bundle(Path(d) / "bundle")
        assert (out / "records.jsonl").read_bytes() == p.read_bytes(), \
            "records.jsonl is a re-serialization, not the log"


def test_integrity_describes_the_exported_file_not_the_source():
    """The bundle's verdict must be reproducible from the bundle alone."""
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=3)
        out = log.export_bundle(Path(d) / "bundle")
        integrity = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        re_run = verify_file(out / "records.jsonl")
        assert re_run.ok == integrity["ok"]
        assert re_run.rows == integrity["rows"]
        assert re_run.first_break == integrity["first_break"]
        assert integrity["records_sha256"] == __import__("hashlib").sha256(
            (out / "records.jsonl").read_bytes()).hexdigest()


def test_tampered_export_reverifies_as_broken():
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=4)
        out = log.export_bundle(Path(d) / "bundle")
        rec = out / "records.jsonl"
        lines = rec.read_text(encoding="utf-8").splitlines()
        row = json.loads(lines[2])
        row["decision"] = "tampered"
        lines[2] = json.dumps(row)
        rec.write_text("\n".join(lines) + "\n", encoding="utf-8")
        vr = verify_file(rec)
        assert not vr.ok and vr.first_break == "line 3: chain mismatch"


# --------------------------------------------------------------------------
# 3. Summaries must not crash on non-object rows either
# --------------------------------------------------------------------------

def test_manifest_counts_only_real_rows():
    with tempfile.TemporaryDirectory() as d:
        log, p = _log(d, n=2)
        with p.open("a", encoding="utf-8") as fh:
            fh.write("[1,2]\n")
        out = log.export_bundle(Path(d) / "bundle")
        manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["record_count"] == 2
        assert manifest["unreadable_lines"] == 1


def test_empty_log_exports_cleanly():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "empty.jsonl"
        p.write_text("", encoding="utf-8")
        out = export_bundle(p, Path(d) / "bundle", system_id="s", provider="p")
        manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["record_count"] == 0
        # TEETH (external audit 2026-08-23): this test passed for weeks while the
        # bundle verdict for an empty log was FAIL — "The record set has been
        # altered, truncated, or reordered" — because it never read the verdict.
        # A day-one customer's export accused them of tampering, in the document
        # meant for a regulator, and the test that owned this path could not see
        # it. The verdict is the point; assert it.
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        assert integ["finding"] == "EMPTY_LOG", integ["finding"]
        summary = (out / "ARTICLE_12_SUMMARY.md").read_text(encoding="utf-8")
        assert "altered" not in summary.split("EMPTY_LOG")[1][:400].lower()             if "EMPTY_LOG" in summary else True
        assert "EMPTY_LOG" in summary


def test_missing_log_is_a_clear_error_not_a_silent_empty_bundle():
    with tempfile.TemporaryDirectory() as d:
        with pytest.raises(FileNotFoundError):
            export_bundle(Path(d) / "nope.jsonl", Path(d) / "bundle")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
