"""Shared fixture for the evidence-pack tests: a four-row, two-agent ledger."""
import pytest

from arcaeon.record.ledger import Ledger

ROWS = [
    {"ts": "2026-09-01T10:00:00Z", "system_id": "sys-a", "agent": "agent-a",
     "event": "system_start"},
    {"ts": "2026-09-01T11:00:00Z", "system_id": "sys-b", "agent": "agent-b",
     "event": "tool_call", "inputs": {"q": "lookup"}},
    {"ts": "2026-09-02T09:30:00Z", "system_id": "sys-a", "agent": "agent-a",
     "event": "decision", "decision": "escalate", "outputs": {"to": "desk"}},
    {"ts": "2026-09-03T08:00:00Z", "system_id": "sys-b", "agent": "agent-b",
     "event": "system_stop"},
]


@pytest.fixture
def ledger(tmp_path):
    p = tmp_path / "ledger.jsonl"
    lg = Ledger(p)
    for r in ROWS:
        lg.append(r)
    return p
