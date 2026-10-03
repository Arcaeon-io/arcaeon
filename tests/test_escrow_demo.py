"""examples/escrow_two_agents_demo.py: two local agents, one deal under escrow.
Clean response releases; a response doctored after the receipt refunds
(ALTERED). Mock rail, no network, nothing written outside a temp dir."""
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
    "run 2 (doctored response): buyer settle -> REFUNDED (ALTERED)",
    "run 2 (doctored response): seller settle -> REFUNDED (ALTERED)",
    "mock rail: nothing is held or moved",
]


def test_demo_script_releases_clean_and_refunds_doctored(tmp_path):
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
    assert bad == {"buyer": ("REFUNDED", "ALTERED"), "seller": ("REFUNDED", "ALTERED")}
    for d, last in ((tmp_path / "clean", "deal.release"), (tmp_path / "bad", "deal.refund")):
        for side in ("buyer", "seller"):
            rows = deal_rows(d / f"{side}.jsonl", demo.DEAL)
            assert rows[-1]["kind"] == last and rows[-1]["shared"]["rail"] == "mock"
    assert escrow.state(tmp_path / "bad" / "buyer.jsonl", demo.DEAL) == escrow.REFUNDED
    refund = deal_rows(tmp_path / "bad" / "buyer.jsonl", demo.DEAL)[-1]
    assert refund["shared"]["cause"] == "ALTERED"
