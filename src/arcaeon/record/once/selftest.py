"""Self-test: golden outcome-digest vectors + the planted-tamper fixture.

    python -m arcaeon.record.once.selftest

Ships in the package (not only in CI) so a stranger runs it on THEIR machine
and trusts their own output:

1. Golden vectors. `_outcome_digest` is a thin wrapper over
   `arcaeon_ledger.digest_json` (json-c14n recipe) -- frozen here so a future
   change to how we call it doesn't silently drift what an existing receipt's
   `outcome_digest` means. Determinism across repeated calls is checked too.

2. The planted tamper. The whole claim of this library is "a deleted or
   edited executed record breaks the chain." This plants exactly that: build
   a real intent+executed pair, confirm `receipt()` reports `ledger_ok=True`,
   then flip one character in the executed row's `outcome_digest` on disk (a
   plausible "quietly re-enable a re-fire" attack) and confirm `receipt()`
   flips to `ledger_ok=False` with a `first_break` naming the row.

Exit code 0 = every check passed.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from arcaeon.record.once import _outcome_digest, guard, receipt

# Frozen at schema freeze (arcaeon-once:receipt:v1, 0.1.0, 2026-08-14).
# These never change -- a future schema gets NEW vectors alongside these.
# Computed once via `digest_json(FIXTURE_OUTCOME)` and pinned; if this build
# computes anything else, `_outcome_digest`'s underlying recipe (or
# arcaeon-ledger's json-c14n implementation) drifted -- do not trust receipts
# from it, and do not silently widen the vector.
FIXTURE_OUTCOME = {"refund_id": "re_test123", "amount_cents": 4900, "status": "succeeded"}
GOLDEN_OUTCOME_DIGEST = ("sha256:json-c14n:v1:"
    "0c8c824da586b33babb0e688e343f0cae4fe769ef063c5e6073bc660c0ccb693")


def run() -> int:
    failures = 0

    print("== golden vector (outcome digest is a pinned recipe) ==")
    got = _outcome_digest(FIXTURE_OUTCOME)
    ok = got == GOLDEN_OUTCOME_DIGEST
    failures += 0 if ok else 1
    print(f"  {'PASS' if ok else 'FAIL'}  outcome digest matches frozen golden vector")
    if not ok:
        print(f"        want {GOLDEN_OUTCOME_DIGEST}\n        got  {got}")

    print("== determinism (5 repeated calls, same outcome value) ==")
    outs = {_outcome_digest(FIXTURE_OUTCOME) for _ in range(5)}
    ok = len(outs) == 1
    failures += 0 if ok else 1
    print(f"  {'PASS' if ok else 'FAIL'}  5 calls collapse to one digest")

    print("== distinct outcomes produce distinct digests ==")
    other = _outcome_digest({**FIXTURE_OUTCOME, "amount_cents": 5900})
    ok = other != got
    failures += 0 if ok else 1
    print(f"  {'PASS' if ok else 'FAIL'}  changing one field changes the digest")

    print("== planted tamper (executed row edited after the fact) ==")
    with tempfile.TemporaryDirectory() as td:
        ledger_path = Path(td) / "selftest.log.jsonl"
        key = "selftest:refund:1"
        with guard(key, ledger_path=ledger_path, store_outcome=True) as g:
            g.done(FIXTURE_OUTCOME)
        clean = receipt(key, ledger_path=ledger_path)
        ok = clean.state == "executed" and clean.ledger_ok
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  honest receipt: executed + ledger_ok")

        # Flip one character in the file -- simulating exactly the attack the
        # chain exists to catch: quietly editing an inconvenient record.
        text = ledger_path.read_text(encoding="utf-8")
        tampered = text.replace(FIXTURE_OUTCOME["refund_id"], "re_HACKED12", 1)
        ok = tampered != text
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  fixture actually mutated the file")
        ledger_path.write_text(tampered, encoding="utf-8")

        dirty = receipt(key, ledger_path=ledger_path)
        ok = dirty.ledger_ok is False and dirty.ledger_first_break is not None
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  tampered receipt: ledger_ok=False, "
              f"first_break={dirty.ledger_first_break!r}")

    print(f"\n{'ALL PASSED' if failures == 0 else f'{failures} CHECK(S) FAILED'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(run())
