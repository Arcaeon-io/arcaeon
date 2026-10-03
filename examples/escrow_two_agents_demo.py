# SPDX-License-Identifier: MIT
"""Two local agents do a deal under escrow. MOCK RAIL: nothing is held or moved.

    py examples/escrow_two_agents_demo.py

Both agents live in this process; there is no network. A buying agent asks a
selling agent (a tool) for one answer and puts the price on hold, with the
release criteria frozen at hold time. The seller answers and issues a call
receipt on its own ledger. Then each side runs the release rule.

  Run 1: the seller's response is clean. The receipt recomputes and matches
         the criteria, so settle RELEASES the hold on both tapes.
  Run 2: the seller doctors the response AFTER the receipt was issued (swaps
         in a different answer's digest). The receipt no longer recomputes,
         so settle REFUNDS the hold, cause ALTERED, on both tapes.

Every step is a deal row each side can check. Everything is written under a
throwaway directory, and ARCAEON_HOME points there too, so the real home is
never touched. Exit 0 when both runs end the way they should.
"""
from __future__ import annotations

import hashlib
import json
import os
import socket
import sys
import tempfile
from pathlib import Path

_SRC = Path(__file__).resolve().parents[1] / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

DEAL = "d-demo"
SELLER = "acme-tools"
URL = "https://tool.example/v1/answer"
ITEMS = [{"sku": "answer-1", "qty": 1, "unit_price": "0.30"}]
CRITERIA = {"seller": SELLER, "url": URL, "response_status": 200}
TIMEOUT_AT = "2026-10-03T00:00:00Z"
NOW = "2026-10-02T12:00:00Z"


class BuyerAgent:
    """Records a mandate with a recourse tier, commits, and holds the price."""

    def __init__(self, workdir: Path):
        from arcaeon.record.deal import Deal
        self.ledger = workdir / "buyer.jsonl"
        self.deal = Deal(self.ledger, "buyer", DEAL)

    def open_deal(self) -> dict:
        from arcaeon.record import escrow
        self.deal.mandate(merchant=SELLER, cap="1.00", currency="USD",
                          recourse="escrow_challenge_window")
        commit = self.deal.commit(items=ITEMS, total="0.30", currency="USD", seller=SELLER)
        escrow.hold(self.ledger, "buyer", DEAL, amount="0.30", currency="USD",
                    criteria_digest=escrow.criteria_digest(CRITERIA),
                    recourse="escrow_challenge_window", timeout_at=TIMEOUT_AT)
        return commit


class SellerAgent:
    """Mirrors the commit and hold, answers the call, and receipts it."""

    def __init__(self, workdir: Path):
        from arcaeon.record.deal import Deal
        self.workdir = workdir
        self.ledger = workdir / "seller.jsonl"
        self.call_ledger = workdir / "seller-calls.jsonl"
        self.deal = Deal(self.ledger, "seller", DEAL)

    def accept(self, buyer_commit: dict) -> None:
        from arcaeon.record import escrow
        self.deal.commit(items=ITEMS, total="0.30", currency="USD", seller=SELLER,
                         mandate_digest=buyer_commit["shared"]["mandate_digest"])
        escrow.hold(self.ledger, "seller", DEAL, amount="0.30", currency="USD",
                    criteria_digest=escrow.criteria_digest(CRITERIA),
                    recourse="escrow_challenge_window", timeout_at=TIMEOUT_AT)

    def answer(self, question: str) -> Path:
        """Answer in-process and write the call receipt. Returns its path."""
        from arcaeon.record.receipt.call import call_receipt
        from arcaeon.record.receipt.core import save_receipt
        rc = call_receipt({"method": "POST", "url": URL, "body": {"q": question}},
                          {"status": 200, "body": f"the answer to {question}"},
                          ledger_path=self.call_ledger, seller=SELLER, elapsed_ms=12,
                          witness=False, anchor=False)
        return Path(save_receipt(rc, self.workdir / "call.receipt.json"))

    def doctor(self, receipt: Path) -> None:
        """After the receipt was issued, swap in a different answer's digest."""
        rc = json.loads(receipt.read_text(encoding="utf-8"))
        other = hashlib.sha256(b"a different, cheaper answer").hexdigest()
        rc["checks"][0]["response_digest"] = "sha256:" + other
        receipt.write_text(json.dumps(rc, indent=1), encoding="utf-8")


def run_once(workdir: Path, *, doctored: bool) -> dict:
    """One deal from mandate to settlement. Returns what each side's settle
    decided: {"buyer": (state, verdict), "seller": (state, verdict)}."""
    from arcaeon.record import escrow
    workdir.mkdir(parents=True, exist_ok=True)
    buyer, seller = BuyerAgent(workdir), SellerAgent(workdir)
    seller.accept(buyer.open_deal())
    receipt = seller.answer("what is two plus two")
    if doctored:
        seller.doctor(receipt)
    out = {}
    for party, ledger in (("buyer", buyer.ledger), ("seller", seller.ledger)):
        s = escrow.settle(ledger, party, DEAL, receipt=receipt,
                          receipt_ledger=seller.call_ledger, criteria=CRITERIA, now=NOW)
        out[party] = (s.state, s.look.verdict)
    return out


def _no_network(*_a, **_k):
    raise RuntimeError("the escrow demo makes no network calls")


def main(argv: list[str] | None = None) -> int:
    with tempfile.TemporaryDirectory(prefix="arcaeon-escrow-demo-") as tmp:
        root = Path(tmp)
        old_home = os.environ.get("ARCAEON_HOME")
        old_connect = socket.socket.connect
        os.environ["ARCAEON_HOME"] = str(root / "home")
        socket.socket.connect = _no_network
        try:
            clean = run_once(root / "run1-clean", doctored=False)
            bad = run_once(root / "run2-doctored", doctored=True)
        finally:
            socket.socket.connect = old_connect
            if old_home is None:
                os.environ.pop("ARCAEON_HOME", None)
            else:
                os.environ["ARCAEON_HOME"] = old_home
    for label, res in (("run 1 (clean response)", clean), ("run 2 (doctored response)", bad)):
        for party in ("buyer", "seller"):
            st, word = res[party]
            print(f"{label}: {party} settle -> {st} ({word})")
    print("mock rail: nothing is held or moved")
    ok = (all(v == ("RELEASED", "MATCHED") for v in clean.values())
          and all(v == ("REFUNDED", "ALTERED") for v in bad.values()))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
