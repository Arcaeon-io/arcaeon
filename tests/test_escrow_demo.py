"""examples/escrow_two_agents_demo.py: two local agents, one deal under escrow.
Clean response releases; a response doctored after the receipt holds (ALTERED)
with dispute evidence, and is refunded only on a recorded dispute outcome.
Mock rail, no network, nothing written outside a temp dir."""
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "escrow_two_agents_demo.py"

EXPECTED = [
    "run 1 (clean response): buyer settle -> RELEASED (MATCHED)",
    "run 1 (clean response): seller settle -> RELEASED (MATCHED)",
    "run 2 (doctored response): buyer settle -> HELD (ALTERED)",
    "run 2 (doctored response): seller settle -> HELD (ALTERED)",
    "run 2 (dispute outcome: refund): buyer -> REFUNDED",
    "run 2 (dispute outcome: refund): seller -> REFUNDED",
    "mock rail: nothing is held or moved",
]


def test_demo_script_releases_clean_and_holds_doctored_until_the_outcome(tmp_path):
    env = dict(os.environ, ARCAEON_HOME=str(tmp_path / "home"))
    p = subprocess.run([sys.executable, str(DEMO)], capture_output=True, text=True,
                       env=env, cwd=str(tmp_path), timeout=120)
    assert p.returncode == 0, p.stdout + p.stderr
    assert p.stdout.splitlines() == EXPECTED
    assert not any(tmp_path.rglob("*")), "the demo writes only under its own temp dir"


def test_run_once_in_process_without_network(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "home"))
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: pytest.fail("network used"))
    sys.path.insert(0, str(DEMO.parent))
    try:
        import escrow_two_agents_demo as demo
    finally:
        sys.path.remove(str(DEMO.parent))
    from arcaeon.record import escrow
    from arcaeon.record.deal import deal_rows

    clean = demo.run_once(tmp_path / "clean", doctored=False)
    bad = demo.run_once(tmp_path / "bad", doctored=True)
    assert clean == {"buyer": ("RELEASED", "MATCHED"), "seller": ("RELEASED", "MATCHED")}
    assert bad == {"buyer": ("HELD", "ALTERED"), "seller": ("HELD", "ALTERED")}
    for side in ("buyer", "seller"):
        rows = deal_rows(tmp_path / "clean" / f"{side}.jsonl", demo.DEAL)
        assert rows[-1]["kind"] == "deal.release" and rows[-1]["shared"]["rail"] == "mock"
        rows = deal_rows(tmp_path / "bad" / f"{side}.jsonl", demo.DEAL)
        assert rows[-1]["kind"] == "deal.look" and rows[-1]["shared"]["verdict"] == "ALTERED"
        assert not any(r["kind"] == "deal.refund" for r in rows), "the look never refunds"
        ev = list((tmp_path / "bad" / f"DEAL-{demo.DEAL}").glob(f"{side}.escrow-dispute.*.json"))
        assert len(ev) == 1 and json.loads(ev[0].read_text(encoding="utf-8"))["verdict"] == "ALTERED"
    assert escrow.state(tmp_path / "bad" / "buyer.jsonl", demo.DEAL) == escrow.HELD
    assert demo.decide_dispute(tmp_path / "bad") == {"buyer": "REFUNDED", "seller": "REFUNDED"}
    refund = deal_rows(tmp_path / "bad" / "buyer.jsonl", demo.DEAL)[-1]
    assert refund["kind"] == "deal.refund" and refund["shared"]["cause"] == "dispute_outcome"
    assert refund["shared"]["rail"] == "mock"
