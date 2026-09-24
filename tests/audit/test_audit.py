"""Smoke test for arcaeon-audit v0: record, verify, export, tamper-detect."""
import sys, os, json, tempfile
from pathlib import Path

import pytest

from arcaeon.prove.audit import AuditLog, verify_file

d = Path(tempfile.mkdtemp(prefix="audit_"))
log = AuditLog(d / "agent.jsonl", system_id="triage-agent-v3", provider="Acme AI")
log.record(event="system_start", agent="triage-agent-v3")
log.record(event="input", agent="triage-agent-v3", inputs={"patient_msg": "chest pain"})
log.record(event="tool_call", agent="triage-agent-v3", inputs={"q": "symptom lookup"}, outputs={"match": "cardiac"})
log.record(event="decision", agent="triage-agent-v3", decision="escalate",
           outputs={"routed_to": "ER", "priority": 1}, capability_version="v2")
log.record(event="custom_weird", agent="triage-agent-v3")  # unknown type

print("verify (clean):", log.verify().ok, "| rows:", log.verify().rows)

out = log.export_bundle(d / "export")
print("bundle files:", sorted(os.listdir(out)))
man = json.load(open(out / "manifest.json"))
print("event_counts:", man["event_counts"], "| unknown_flagged:", man["unknown_event_types"])
print("integrity.ok:", json.load(open(out / "integrity.json"))["ok"])

# tamper: alter record #3's output, re-verify the exported records
p = out / "records.jsonl"
lines = p.read_text(encoding="utf-8").splitlines()
row = json.loads(lines[2]); row["outputs"] = {"match": "benign"}; lines[2] = json.dumps(row)
p.write_text("\n".join(lines) + "\n", encoding="utf-8")
vr = verify_file(p)
print("verify (tampered):", vr.ok, "| first_break:", vr.first_break)

assert log.verify().ok and not vr.ok, "tamper-evidence FAILED"
print("PASS — records, exports, and catches tampering both directions.")


# ---------------------------------------------------------------------------
# Reserved stamps (pre-invite adversarial audit, 2026-08-23).
#
# record()'s `row.update(extra)` ran AFTER the ts/system_id stamps, so a caller
# could set them. A backdated, forged-system-id row then CHAINED GREEN -- the
# chain faithfully seals whatever it is handed -- and manifest.json reported the
# forged window as period_covered, while the summary says records are "appended
# automatically at the time it happens".
#
# A record whose AUTHOR chose its timestamp is a self-report wearing a chain.
# ---------------------------------------------------------------------------

def test_caller_cannot_backdate_a_record(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl", system_id="real-system")
    with pytest.raises(ValueError) as e:
        log.record(event="decision", agent="a", ts="1999-01-01T00:00:00Z")
    assert "ts" in str(e.value)


def test_caller_cannot_forge_the_system_id(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl", system_id="real-system")
    with pytest.raises(ValueError):
        log.record(event="decision", agent="a", system_id="some-other-system")


def test_the_refusal_names_every_colliding_key(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl", system_id="real-system")
    with pytest.raises(ValueError) as e:
        log.record(event="decision", agent="a",
                   ts="1999-01-01T00:00:00Z", system_id="fake")
    msg = str(e.value)
    assert "ts" in msg and "system_id" in msg


def test_ordinary_extra_fields_still_ride_along(tmp_path):
    """GREEN CONTROL: the fix must not turn **extra into a walled garden --
    arbitrary domain data is the point of it. Only the two stamps are reserved."""
    p = tmp_path / "a.jsonl"
    log = AuditLog(p, system_id="real-system")
    log.record(event="decision", agent="a", case_id="XYZ-1",
               timestamp_from_vendor="1999-01-01", ts_value="also fine")
    row = json.loads(p.read_text(encoding="utf-8").strip().split("\n")[0])
    assert row["case_id"] == "XYZ-1"
    assert row["timestamp_from_vendor"] == "1999-01-01"
    assert row["ts_value"] == "also fine"
    assert row["system_id"] == "real-system"
    assert row["ts"].endswith("Z") and row["ts"].startswith("20")
