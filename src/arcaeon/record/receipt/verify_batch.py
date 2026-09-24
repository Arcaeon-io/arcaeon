"""Bulk verification: a whole class's paper in one pass.

The mirror of the cohort driver in `ballot.py`. That one turns a roster into
twenty sealed receipts with one command; this one turns twenty sealed
receipts back into one answer a training coordinator can act on. A
coordinator who has to run `verify` twenty times and eyeball twenty JSON
blobs will not do it, and a proof nobody checks is a decoration.

THREE VERDICTS, NOT TWO. `ok` and `FAIL` cannot carry the case where the
file will not open, or where the receipt claims a ledger row and no ledger
file was available to check it against. Folding either of those into `ok`
overclaims; folding them into `FAIL` accuses a receipt that may be
perfectly good. So `undetermined` is its own count with its own exit code,
and it never silently merges with either neighbour. A determinable negative
still wins: a receipt whose body digest does not recompute is a FAIL even
if its ledger is also missing, because that verdict IS determined.

THE CAP IS A REFUSAL, NOT A TRUNCATION. VENDOR_PACKAGE_SPEC 2.5 publishes
a cap of 20 receipts per free bulk pass. Past the cap this module verifies
NOTHING and says so, naming the cap and the count. Verifying the first 20
of 21 and printing a summary would hand back a page that looks like a
finished answer for a class that was never fully checked -- the same
failure `ballot.read_roster` refuses for a class that comes out one receipt
short, in the opposite direction.
"""
from __future__ import annotations

import glob as globmod
import json
from pathlib import Path
from typing import Iterable, List, Optional

from .core import ANCHOR_POSITIVE, verify_receipt

#: Published cap on receipts per free bulk verification pass
#: (docs/VENDOR_PACKAGE_SPEC.md 2.5). Printed on the surface next to the
#: words "free to verify", and enforced here as a refusal.
CAP = 20

OK = "ok"
FAIL = "FAIL"
UNDETERMINED = "undetermined"

#: The words a person reads. The three values above are the machine values
#: (row["verdict"] in JSON, the roster CSV and the archive manifest) and do
#: not change; what prints is one vocabulary across every Arcaeon surface:
#: VERIFIED for a pass in this run, BROKEN for a failure, COULD NOT LOOK
#: for "this run did not get to look". (Vocabulary pass, 2026-09-23.)
SAY = {OK: "VERIFIED", FAIL: "BROKEN", UNDETERMINED: "COULD NOT LOOK"}

#: Ledger verdicts from core.verify_receipt that are a definite negative --
#: the receipt's own sequence claim was checked against the ledger and did
#: not hold. Anything outside this set is either "consistent" or "we could
#: not look", and those two must never be confused with each other.
LEDGER_NEGATIVE = ("chain_broken", "row_not_found", "head_mismatch")

RECEIPT_GLOB = "*.receipt.json"


class CapExceeded(ValueError):
    """Raised before a single file is opened when a batch is over the cap."""

    def __init__(self, count: int, cap: int = CAP):
        self.count = count
        self.cap = cap
        super().__init__(
            f"refusing this batch: {count} receipts, cap is {cap} per pass. "
            f"Nothing was verified. Split the batch into runs of {cap} or "
            f"fewer -- a partial pass reported as a finished one is the "
            f"failure this refusal exists to prevent."
        )


class NoReceiptsFound(ValueError):
    """A batch target that matched nothing. Refused rather than reported as
    a clean run of zero receipts, which is what an empty summary line would
    look like to a coordinator who mistyped a directory."""


# --------------------------------------------------------------------------
# collecting the batch
# --------------------------------------------------------------------------

def collect_paths(targets: Iterable[str | Path]) -> List[Path]:
    """Expand directories, globs and plain paths into an ordered file list.

    A directory yields its `*.receipt.json` files, and only if that finds
    nothing does it fall back to `*.json` -- an export directory holds the
    receipts, the exhibits and the ledger side by side, and `*.jsonl`
    ledgers and `.witness.jsonl` sidecars must never be swept in as
    receipts. The expansion is non-recursive on purpose: `examples/ballots/`
    has an `inputs/` subdirectory full of raw ballot objects that are not
    receipts at all.

    Globs are expanded here rather than left to the shell because PowerShell
    (this project's primary shell) does not expand them for the callee.
    Duplicates collapse, order is stable.
    """
    out: List[Path] = []
    seen = set()

    def add(p: Path) -> None:
        rp = p.resolve()
        if rp not in seen:
            seen.add(rp)
            out.append(p)

    for raw in targets:
        s = str(raw)
        if any(ch in s for ch in "*?[") and not Path(s).exists():
            for hit in sorted(globmod.glob(s, recursive=True)):
                hp = Path(hit)
                if hp.is_file():
                    add(hp)
            continue
        p = Path(s)
        if p.is_dir():
            found = sorted(p.glob(RECEIPT_GLOB))
            if not found:
                found = sorted(p.glob("*.json"))
            for hp in found:
                add(hp)
            continue
        add(p)
    return out


def resolve_ledger(receipt: dict, receipt_path: Path,
                   explicit: Optional[str | Path]) -> tuple:
    """Decide which ledger file (if any) this receipt gets checked against.

    Returns (path_or_None, claims_ledger). An explicit --ledger wins for the
    whole batch. Otherwise the receipt's own `ledger.path` -- a bare
    filename, written by core.build_receipt as `ledger_path.name` -- is
    looked for beside the receipt, which is exactly the shape of a bulk
    export directory. Only the basename is ever used, so a receipt cannot
    point the verifier at an arbitrary path on the checker's disk.
    """
    led = receipt.get("ledger")
    claims = isinstance(led, dict) and led.get("chain") is not None
    if explicit is not None:
        p = Path(explicit)
        return (p if p.exists() else None), claims
    if not claims:
        return None, False
    name = Path(str(led.get("path") or "")).name
    if not name:
        return None, claims
    sibling = receipt_path.parent / name
    return (sibling if sibling.exists() else None), claims


# --------------------------------------------------------------------------
# verifying one, then the batch
# --------------------------------------------------------------------------

def verify_one(path: Path, *, ledger_path: Optional[str | Path] = None,
               ots: bool = False) -> dict:
    """One receipt, one row. Typed, never raises -- a batch must not die on
    file seven and leave the coordinator guessing about eight through
    twenty."""
    row = {"id": path.name, "path": str(path), "verdict": UNDETERMINED,
           "ledger": "not_checked", "anchor": None, "reason": ""}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        row["reason"] = f"unreadable file: {str(exc)[:120]}"
        return row
    except UnicodeDecodeError as exc:
        # A ValueError, not an OSError: without this, one non-UTF-8 file
        # raised out of verify_one and killed the whole batch.
        row["reason"] = f"not UTF-8 text: {str(exc)[:120]}"
        return row
    try:
        rc = json.loads(text)
    except ValueError as exc:
        row["reason"] = f"not readable JSON: {str(exc)[:120]}"
        return row
    if not isinstance(rc, dict):
        row["reason"] = "not a JSON object: a receipt is an object at the top level"
        return row

    led_path, claims_ledger = resolve_ledger(rc, path, ledger_path)
    try:
        res = verify_receipt(rc, ledger_path=led_path, ots=ots, source_text=text)
    except Exception as exc:  # defensive: core says it never raises
        row["reason"] = f"verifier could not run on this file: {str(exc)[:120]}"
        return row

    row["ledger"] = res["ledger"]["status"]
    anc = (rc.get("anchor") or {}).get("status")
    if ots and res["anchor"].get("status") not in (None, "not_checked"):
        anc = res["anchor"]["status"]
    row["anchor"] = anc if anc and anc != "skipped" else None
    # True only when THIS run ran the OpenTimestamps proof; otherwise the
    # status is the receipt's own statement and renders as claimed.
    row["anchor_checked"] = bool(ots and res["anchor"].get("status") not in (None, "not_checked"))

    if res.get("duplicate_keys"):
        # Determined, not undetermined: the file is ambiguous by construction,
        # and whichever value a reader sees, the verifier cannot vouch for it.
        row["verdict"] = FAIL
        row["reason"] = (f"{res['duplicate_keys']}: the file reads differently to "
                         "a first-wins and a last-wins parser, so no verdict can "
                         "cover it")
        return row
    if not res["body_digest_ok"]:
        row["verdict"] = FAIL
        row["reason"] = ("body digest mismatch: a body field was altered "
                         "after issue")
        return row
    if row["ledger"] in LEDGER_NEGATIVE:
        row["verdict"] = FAIL
        row["reason"] = f"ledger says {row['ledger']}"
        return row
    wv = (res.get("witness") or {}).get("verdict")
    row["witness"] = wv if wv not in (None, "absent", "not_checked") else None
    if wv == "inconsistent":
        row["verdict"] = FAIL
        row["reason"] = "witness block is inconsistent: " + "; ".join(res["witness"].get("problems") or [])
        return row
    if (res.get("attestation_signature") or {}).get("verdict") == "mismatch":
        row["verdict"] = FAIL
        row["reason"] = ("attestation signature does not belong to this receipt: "
                         + "; ".join(res["attestation_signature"].get("problems") or []))
        return row
    if res["anchor"].get("status") == "failed":
        row["verdict"] = FAIL
        row["reason"] = "anchor verification failed"
        return row
    if ots and res["anchor"].get("status") not in ANCHOR_POSITIVE:
        # The caller asked for the anchor to be checked and it was not
        # proven: stripped, tool missing, tool error, pending, or output we do
        # not recognise. Not a pass and not an accusation.
        row["reason"] = (f"body digest ok, but the anchor was asked for and not "
                         f"proven (status {res['anchor'].get('status')})")
        return row
    if not claims_ledger:
        # Every receipt this format issues carries a ledger claim
        # (build_receipt requires a ledger and always writes the block). The
        # block sits outside the body digest, so deleting it, or nulling its
        # chain, must not make the receipt look like one that never needed a
        # ledger check: removing evidence never raises a verdict.
        row["reason"] = ("body digest ok, but the receipt carries no ledger "
                         "claim (block missing or chain null): its sequence "
                         "is unchecked")
        return row
    if led_path is None:
        # The body is intact, but the receipt makes a sequence claim nobody
        # in this run could check. Not a pass and not an accusation.
        name = Path(str((rc.get("ledger") or {}).get("path") or "")).name or "the ledger"
        row["reason"] = (f"body digest ok, but {name} was not found beside the "
                         "receipt: its ledger sequence claim is unchecked")
        return row
    row["verdict"] = OK
    return row


def _verify_one_guarded(path: Path, **kw) -> dict:
    """verify_one is typed and never raises; this guard makes that a property
    of the batch, not a promise: one hostile file gets an undetermined row,
    the other nineteen still get their verdicts."""
    try:
        return verify_one(path, **kw)
    except Exception as exc:  # defensive
        return {"id": path.name, "path": str(path), "verdict": UNDETERMINED,
                "ledger": "not_checked", "anchor": None,
                "reason": f"verifier could not run on this file: {str(exc)[:120]}"}


def verify_batch(targets: Iterable[str | Path], *,
                 ledger_path: Optional[str | Path] = None,
                 ots: bool = False, cap: int = CAP) -> dict:
    """Collect, refuse-if-over-cap, then verify every receipt in the batch.

    The cap check happens between collection and the first `read_text`, so
    a refused batch has demonstrably verified nothing.
    """
    paths = collect_paths(targets)
    if not paths:
        raise NoReceiptsFound(
            "no receipts matched: a batch target must be a directory holding "
            f"{RECEIPT_GLOB} files, a glob, or one or more receipt paths"
        )
    if len(paths) > cap:
        raise CapExceeded(len(paths), cap)
    rows = [_verify_one_guarded(p, ledger_path=ledger_path, ots=ots) for p in paths]
    counts = {OK: 0, FAIL: 0, UNDETERMINED: 0}
    for r in rows:
        counts[r["verdict"]] += 1
    return {"rows": rows, "verified": counts[OK], "failed": counts[FAIL],
            "undetermined": counts[UNDETERMINED], "cap": cap}


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def summary_line(result: dict) -> str:
    n = len(result["rows"])
    return (f"{n} receipt{'s' if n != 1 else ''}: {result['verified']} VERIFIED, "
            f"{result['failed']} BROKEN, {result['undetermined']} COULD NOT LOOK")


def render(result: dict) -> str:
    """One line per receipt, then one summary line. The per-receipt lines are
    the audit; the summary is the thing that goes in an email."""
    rows = result["rows"]
    w = min(max((len(r["id"]) for r in rows), default=0), 60)
    lines = []
    for r in rows:
        bits = [f"{r['id']:<{w}}", f"{SAY.get(r['verdict'], r['verdict']):<14}", f"ledger={r['ledger']}"]
        if r["anchor"]:
            bits.append(f"anchor={r['anchor']}" + ("" if r.get("anchor_checked") else "(claimed)"))
        if r.get("witness"):
            # "claimed": shown, never as checked. The witness's kind and
            # independence are the issuer's word (see core._check_witness).
            bits.append(f"witness={r['witness']}")
        if r["reason"]:
            bits.append(f"-- {r['reason']}")
        lines.append("  ".join(bits).rstrip())
    lines.append(summary_line(result))
    return "\n".join(lines)


def exit_code(result: dict) -> int:
    """0 only when every receipt is ok. 2 when one is a definite FAIL, 4 when
    nothing failed but something could not be determined -- a distinct code
    because "we could not check" is not "it is bad", and a caller scripting
    a gate deserves to tell them apart without parsing text."""
    if result["failed"]:
        return 2
    if result["undetermined"]:
        return 4
    return 0
