"""The $25/month ballot-pin absorption ceiling, as a counted number.

Pricing sitting 2026-09-13 (M5) made ballot issuance and verification free
forever and put the optional witness pin under a $25/month ceiling, separate
from the $50 AI ceiling. The sitting's own condition was that the ceiling be
COUNTED before the next sitting cites it as a control, so what these tests
guard is the difference between a number and a sentence:

  1. a pin REQUEST counts and a plain issuance does not (issuance is free;
     counting receipts would count the wrong thing),
  2. the status flips at 80% and again at 100%,
  3. an absent or empty ledger says ABSENT, never a silent zero.

Every test pins the ledger path to tmp via ARCAEON_BALLOT_PIN_LEDGER, so a
test run can never touch the real monthly count.
"""
from __future__ import annotations

import copy
import json
from datetime import datetime, timezone

import pytest

from arcaeon.record.receipt import ballot

_BALLOT = {"per_answer": [{"score": 82, "verdict": "GOOD"}],
           "overall": {"score": 82, "verdict": "GOOD", "summary": "Passes."}}

MONTH = datetime.now(timezone.utc).strftime("%Y-%m")


@pytest.fixture()
def pin_ledger(tmp_path, monkeypatch):
    path = tmp_path / "ballot_pin_ledger.jsonl"
    monkeypatch.setenv(ballot.PIN_LEDGER_ENV, str(path))
    return path


def _rows(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _seed(path, pins: int, month: str = MONTH, pin_kind: str = "hosted") -> None:
    cost = ballot.pin_cost_usd(pin_kind)
    with path.open("a", encoding="utf-8") as handle:
        for i in range(pins):
            handle.write(json.dumps({
                "at": f"{month}-05T00:00:00Z", "month": month, "receipt_id": f"d{i:06d}",
                "pin_kind": pin_kind, "est_usd": cost, "pin_status": "pinned",
            }) + "\n")


# ---------------------------------------------------------------- the counter

def test_pin_request_counts_and_plain_issuance_does_not(pin_ledger, tmp_path):
    # witness=False: a free, unpinned receipt. Nothing may reach the ledger.
    ballot.ballot_receipt(copy.deepcopy(_BALLOT), trainee="a. writer",
                          scenario="oral_board.set1", ledger_path=tmp_path / "l.jsonl",
                          timestamp="2026-09-12T08:00:00Z", witness=False, anchor=False)
    assert _rows(pin_ledger) == [], "an unpinned issuance charged the ceiling"

    # witness=True: one pin request, one row.
    rc = ballot.ballot_receipt(copy.deepcopy(_BALLOT), trainee="a. writer",
                               scenario="oral_board.set1", ledger_path=tmp_path / "l2.jsonl",
                               timestamp="2026-09-12T09:00:00Z", witness=True, anchor=False)
    rows = _rows(pin_ledger)
    assert len(rows) == 1, rows
    row = rows[0]
    assert set(row) >= {"at", "month", "receipt_id", "pin_kind", "est_usd"}
    assert row["receipt_id"] == rc["body_digest"]
    assert row["month"] == row["at"][:7]
    # no ARCAEON_WITNESS_URL/KEY in a test env, so the pin is the local sidecar:
    # counted as a pin, costed at $0 because no hosted credit was spent.
    assert row["pin_kind"] == "local-file"
    assert row["est_usd"] == 0.0

    # a second pin request appends rather than replacing
    ballot.ballot_receipt(copy.deepcopy(_BALLOT), trainee="b. writer",
                          scenario="oral_board.set1", ledger_path=tmp_path / "l3.jsonl",
                          timestamp="2026-09-12T10:00:00Z", witness=True, anchor=False)
    assert len(_rows(pin_ledger)) == 2


def test_hosted_pins_cost_and_local_pins_do_not(pin_ledger):
    assert ballot.pin_cost_usd("hosted") == 0.005
    assert ballot.pin_cost_usd("local-file") == 0.0
    # the constant and the ceiling agree with M5's own arithmetic: $25 is
    # "about 5,000 pins at Mini rate"
    assert ballot.PIN_RATE_USD_PER_1000 == 5.0
    assert ballot.PIN_CEILING_USD / ballot.pin_cost_usd("hosted") == 5000


# ---------------------------------------------------------------- the ceiling

def test_ceiling_status_flips_at_eighty_and_one_hundred_percent(pin_ledger):
    _seed(pin_ledger, 3999)                       # $19.995 -> 79.98%
    below = ballot.pin_ceiling_status()
    assert below["pins"] == 3999
    assert below["status"] == "ok", below

    _seed(pin_ledger, 1)                          # 4,000 pins -> $20.00, exactly 80%
    at_warn = ballot.pin_ceiling_status()
    assert at_warn["pins"] == 4000
    assert round(at_warn["est_usd"], 2) == 20.00
    assert at_warn["pct"] == 80.0
    assert at_warn["status"] == "warn", at_warn

    _seed(pin_ledger, 999)                        # 4,999 -> $24.995, still short
    assert ballot.pin_ceiling_status()["status"] == "warn"

    _seed(pin_ledger, 1)                          # 5,000 -> $25.00, the ceiling
    at_red = ballot.pin_ceiling_status()
    assert at_red["pins"] == 5000
    assert round(at_red["est_usd"], 2) == 25.00
    assert at_red["pct"] == 100.0
    assert at_red["status"] == "red", at_red
    assert at_red["ceiling_usd"] == 25.0


def test_the_count_is_per_month_and_last_month_does_not_bleed_in(pin_ledger):
    _seed(pin_ledger, 5000, month="2026-08")
    _seed(pin_ledger, 10, month=MONTH)
    now = ballot.pin_ceiling_status()
    assert now["pins"] == 10 and now["status"] == "ok"
    assert now["rows_all_months"] == 5010
    prior = ballot.pin_ceiling_status("2026-08")
    assert prior["pins"] == 5000 and prior["status"] == "red"


# ----------------------------------------------------------------- absent


def test_absent_ledger_reports_absent_not_zero(pin_ledger):
    assert not pin_ledger.exists()
    res = ballot.pin_ceiling_status()
    assert res["ledger_present"] is False
    assert res["path_exists"] is False
    assert res["pins"] == 0 and res["est_usd"] == 0.0
    assert res["status"] == "unknown", "an unread ledger must not report a healthy 'ok'"
    assert res["ceiling_usd"] == 25.0


def test_empty_ledger_file_also_reports_absent(pin_ledger):
    pin_ledger.write_text("", encoding="utf-8")
    res = ballot.pin_ceiling_status()
    assert res["path_exists"] is True
    assert res["ledger_present"] is False, "a file with no rows cannot prove the writer ever fired"
    assert res["status"] == "unknown"


def test_unparsed_lines_are_named_not_dropped_silently(pin_ledger):
    pin_ledger.write_text("{not json\n", encoding="utf-8")
    _seed(pin_ledger, 2)
    res = ballot.pin_ceiling_status()
    assert res["unparsed_lines"] == 1
    assert res["pins"] == 2 and res["ledger_present"] is True
