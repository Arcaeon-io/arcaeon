"""Ballot Receipt: a finished training-sim grade, bound at the moment it closed.

Buyer: a trainee finishing a graded simulation (call-taking, oral board,
radio drill, traffic stop) who wants to hand a hiring center something
stronger than a screenshot of a results screen -- proof the score and the
ballot text they are showing came out of the sim unedited, at the time
claimed. The grading itself is unchanged by this receipt: whatever engine
produced the score (a deterministic scorer or an LLM judge, see
`judge_declaration` on boards like `api/grade_board.js`) still owns the
grading. This adapter only seals what it produced.

The wording is the product, same as every other adapter here. A ballot
receipt says the score and the ballot text are UNALTERED since the stated
time. It says nothing about whether the grade itself is correct, and
nothing about whether this is the trainee's first attempt at the scenario:
a receipt that implied either would be lying about the one thing it can
actually check.
"""
from __future__ import annotations

import csv
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional

from arcaeon.record.ledger import digest_json

from .core import build_receipt, render_exhibit, save_receipt

KIND = "ballot"

SCOPE = {
    "proves": [
        "the score and the ballot are unaltered since the timestamp",
    ],
    "does_not_prove": [
        "the score is correct",
        "the sim was not attempted before",
    ],
    "method": "sha256 digest of the canonical JSON ballot object (score, verdict, and whatever "
              "fields the grading engine produced), bound to a stated timestamp inside the receipt "
              "body; hash-chained in arcaeon-ledger, one row per ballot.",
}


# --------------------------------------------------------------------------
# pin absorption ceiling: the counter
# --------------------------------------------------------------------------
# Issuing a ballot receipt is free and verifying one is free, forever
# (pricing sitting 2026-09-13, motion M5, approved by Daniel 6:49 AM). The
# only thing that costs us money is the OPTIONAL witness pin, which rides the
# existing hosted-witness credit packs under a stated $25/month absorption
# ceiling -- deliberately separate from the $50 AI ceiling so neither can mask
# the other. The sitting's own condition was that the ceiling be a COUNTED
# number before the next sitting cites it as a control, which is what this
# block is: every pin REQUEST writes one row, and the 3-day pricing review
# reads the total. A ceiling nobody counts is a sentence, not a control.
#
# ONE constant, with its date and its source. $25/month is "about 5,000 pins
# at Mini rate" in M5, i.e. $0.005/pin = $5 per 1,000 pins. If the hosted rate
# moves, it moves here; rows already written keep the estimate they were
# written with, which is what makes the ledger a record instead of a
# recalculation.
PIN_RATE_USD_PER_1000 = 5.0
PIN_RATE_SOURCE = (
    "hosted-witness Mini rate, $5 per 1,000 pins, as of 2026-09-13 -- "
    "PRICING_MOTION_2026-09-13_HELD_NUMBERS.md M5"
)
PIN_CEILING_USD = 25.0
PIN_CEILING_SOURCE = "PRICING_MOTION_2026-09-13_HELD_NUMBERS.md M5 (2026-09-13)"
PIN_WARN_FRACTION = 0.80
_PIN_EPS = 1e-9  # float sums of 5,000 half-cent pins land a hair either side of $25

PIN_LEDGER_ENV = "ARCAEON_BALLOT_PIN_LEDGER"
#: Per-user default. Never a machine-specific path: this ships in the public wheel.
DEFAULT_PIN_LEDGER = Path.home() / ".arcaeon" / "ballot_pin_ledger.jsonl"


def pin_ledger_path() -> Path:
    """Where the pin rows land. Env-overridable so tests never touch the real
    monthly count (and so a second machine can point at its own file)."""
    override = os.environ.get(PIN_LEDGER_ENV, "").strip()
    return Path(override) if override else DEFAULT_PIN_LEDGER


def pin_cost_usd(pin_kind: str) -> float:
    """A hosted pin spends credit; a local-file pin does not.

    The local witness writes a sidecar file we own, so charging it against an
    absorption ceiling would inflate a spend number with dollars nobody paid.
    The row still gets written either way -- the pin COUNT is real usage and
    the ceiling's denominator -- it just carries $0.00 until the hosted key is
    in play.
    """
    return round(PIN_RATE_USD_PER_1000 / 1000.0, 6) if pin_kind == "hosted" else 0.0


def record_pin_request(receipt: dict, *, at: Optional[str] = None,
                       path: str | Path | None = None) -> Optional[dict]:
    """Append one row for one pin REQUEST. Returns the row, or None if it could
    not be written.

    Keyed off the request, not the receipt: issuance is free and a receipt
    minted with witness=False costs nothing, so counting receipts would count
    the wrong thing. A failed hosted pin still counted here on purpose -- the
    request left the building, and a counter that only counts successes hides
    exactly the runs worth looking at.

    A write failure never breaks receipt issuance (a pricing counter is not
    worth a failed receipt) but it is never silent either: it says so on
    stderr, because an uncounted pin is the one thing this file exists to
    prevent.
    """
    witness = receipt.get("witness") or {}
    kind = str(witness.get("kind") or "unknown")
    stamp = at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    row = {
        "at": stamp,
        "month": stamp[:7],
        "receipt_id": receipt.get("body_digest", ""),
        "pin_kind": kind,
        "est_usd": pin_cost_usd(kind),
        "pin_status": str(witness.get("status") or "unknown"),
    }
    target = Path(path) if path else pin_ledger_path()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    except OSError as exc:
        sys.stderr.write(f"[ballot] pin NOT counted ({target}): {exc}\n")
        return None
    return row


def pin_ceiling_status(month: Optional[str] = None, *, path: str | Path | None = None,
                       now: Optional[datetime] = None) -> dict:
    """The reader. One month's pin count against the $25 ceiling.

    An absent or empty ledger reports pins=0 with `ledger_present: false` and
    status "unknown" -- never a silent zero. Not read and no pins are
    different facts, and the whole point of the counter is that the next
    sitting can tell them apart.
    """
    target = Path(path) if path else pin_ledger_path()
    stamp = now or datetime.now(timezone.utc)
    month = month or stamp.strftime("%Y-%m")
    out: dict = {
        "month": month,
        "pins": 0,
        "billable_pins": 0,
        "est_usd": 0.0,
        "ceiling_usd": PIN_CEILING_USD,
        "pct": 0.0,
        "status": "unknown",
        "ledger_present": False,
        "ledger_path": str(target),
        "path_exists": target.exists(),
        "rows_all_months": 0,
        "unparsed_lines": 0,
        "rate_usd_per_1000": PIN_RATE_USD_PER_1000,
        "rate_source": PIN_RATE_SOURCE,
        "ceiling_source": PIN_CEILING_SOURCE,
    }
    if not out["path_exists"]:
        return out
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        out["error"] = str(exc)[:200]
        return out

    total = 0.0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            out["unparsed_lines"] += 1
            continue
        if not isinstance(entry, dict):
            out["unparsed_lines"] += 1
            continue
        out["rows_all_months"] += 1
        if str(entry.get("month") or entry.get("at", "")[:7]) != month:
            continue
        out["pins"] += 1
        cost = float(entry.get("est_usd") or 0.0)
        total += cost
        if cost > 0:
            out["billable_pins"] += 1

    # A file that exists but holds no readable row is indistinguishable from a
    # writer that never fired, so it reports ABSENT too; `path_exists` above
    # keeps the finer distinction for anyone who needs it.
    out["ledger_present"] = out["rows_all_months"] > 0
    out["est_usd"] = round(total, 6)
    out["pct"] = round(out["est_usd"] / PIN_CEILING_USD * 100.0, 2) if PIN_CEILING_USD else 0.0
    if out["ledger_present"]:
        if out["est_usd"] >= PIN_CEILING_USD - _PIN_EPS:
            out["status"] = "red"
        elif out["est_usd"] >= PIN_CEILING_USD * PIN_WARN_FRACTION - _PIN_EPS:
            out["status"] = "warn"
        else:
            out["status"] = "ok"
    return out


# --------------------------------------------------------------------------
# branding: the issuer and the class, inside the digest
# --------------------------------------------------------------------------
# A vendor name printed outside the digest is a name anyone can retype. The
# only version of branding worth selling is one that cannot be changed
# without breaking verification, so issuer and cohort ride in the body's
# `extra` dict, which core.build_receipt() has always digested along with
# everything else (core.py, BODY_FIELDS).
#
# Both default to None and an absent value writes NO key, so an unbranded
# ballot receipt keeps `extra: {}` and is byte-identical to every receipt
# minted before this existed (proven against the committed examples in
# tests/test_ballot_cohort.py).

def branding(issuer: Optional[str] = None, cohort: Optional[str] = None) -> dict:
    """The `extra` payload for a branded ballot. Empty dict when unbranded.

    Whitespace-only is treated as absent, not as a vendor named " ": a blank
    issuer sealed into the digest is a field that looks branded to a reader
    and says nothing.
    """
    out: dict = {}
    if issuer and str(issuer).strip():
        out["issuer"] = str(issuer).strip()
    if cohort and str(cohort).strip():
        out["cohort"] = str(cohort).strip()
    return out


def ballot_receipt(ballot: dict, *, trainee: str, scenario: str, ledger_path: str | Path,
                   namespace: str = "ballot", grader: str = "", timestamp: Optional[str] = None,
                   witness: bool = True, anchor: bool = False,
                   issuer: Optional[str] = None, cohort: Optional[str] = None) -> dict:
    """ballot: the graded object as the grading engine produced it (e.g. the
    per_answer/overall/judge_declaration shape from `api/grade_board.js`, or
    any other trainer's finished-run object) -- stored verbatim as the check,
    never reshaped, so the digest covers exactly what the trainee is showing.

    trainee/scenario name who and what this is for; grader names the engine
    or product that produced the ballot (e.g. "ascenvo.vcs.oral_board" or
    "call_taking.seq_scorer"), for a reader with no other context.

    issuer/cohort are the vendor branding: the academy issuing the document
    and the class it belongs to. Both optional, both sealed inside the body
    digest via `extra`, both absent by default -- see branding() above.

    anchor defaults False, same reasoning as call.py: a training ballot is
    not the $ per-call cadence an OTS stamp is worth by default; the witness
    pin (on by default) already gives it a sequence.
    """
    check = {"ballot": ballot, "ballot_digest": digest_json(ballot),
             "trainee": trainee, "scenario": scenario, "grader": grader,
             "timestamp": timestamp}
    subject = {"trainee": trainee, "scenario": scenario, "grader": grader or "(unspecified)"}
    receipt = build_receipt(KIND, subject, [check], SCOPE, ledger_path=ledger_path,
                            namespace=namespace, witness=witness, anchor=anchor,
                            issued_at=timestamp, extra=branding(issuer, cohort))
    # One row per pin REQUEST, against the $25/month absorption ceiling. Not
    # per receipt: an unpinned ballot is free to issue and costs the ceiling
    # nothing.
    if witness:
        record_pin_request(receipt)
    return receipt


def _line(c: dict) -> str:
    ballot = c.get("ballot") or {}
    overall = ballot.get("overall") or {}
    # Fall back to the sequence-scorer shape (seq_scorer.js's `score()` output:
    # seq_pct/seq_verdict_label, no `score`/`overall` field at all) before giving
    # up -- found 2026-09-12 building the first ten ballot examples: every
    # seq-scored ballot printed "score=(no score field)" in its exhibit even
    # though the receipt itself was correct. The digest and verify path never
    # touched this; only the human-facing line was blind to a second real
    # grader shape this adapter's own docstring says it accepts verbatim.
    score = overall.get("score", ballot.get("score", ballot.get("seq_pct", "(no score field)")))
    verdict = overall.get("verdict", ballot.get("verdict", ballot.get("seq_verdict_label", "")))
    return (f"{c.get('trainee','(unnamed)')}  {c.get('scenario','(unnamed scenario)')}  "
            f"score={score} {verdict}  grader={c.get('grader') or '(unspecified)'}  "
            f"at {c.get('timestamp')}")


TITLE = "BALLOT RECEIPT"
_ISSUED_MARK = "Issued (UTC):"


def _brand_of(receipt: dict) -> tuple:
    extra = receipt.get("extra") or {}
    if not isinstance(extra, dict):
        return "", ""
    return (str(extra.get("issuer") or "").strip(), str(extra.get("cohort") or "").strip())


def exhibit(receipt: dict) -> str:
    """Plain text, with the issuing academy and class on the face of it when
    the receipt carries them. An unbranded receipt is unchanged: the same
    hardcoded "BALLOT RECEIPT" title and not one extra line, so nothing
    already issued renders differently than it did before branding existed.

    The insert happens here rather than in core.render_exhibit() because the
    branding is a ballot-adapter concept, and core stays the one generic
    renderer every adapter shares.
    """
    issuer, cohort = _brand_of(receipt)
    text = render_exhibit(receipt, title=(f"{issuer} - {TITLE}" if issuer else TITLE),
                          check_line=_line)
    if not (issuer or cohort):
        return text
    block = []
    if issuer:
        block.append(f"Issued by: {issuer}")
    if cohort:
        block.append(f"Class: {cohort}")
    # Say WHY the name on the paper is worth anything. A vendor name a reader
    # cannot distinguish from a letterhead is not the product.
    block.append("  (issuer and class are sealed inside the body digest below: "
                 "change either one and this receipt stops verifying)")
    lines = text.split("\n")
    at = next((i for i, ln in enumerate(lines) if ln.startswith(_ISSUED_MARK)), 0)
    lines[at + 1:at + 1] = block
    return "\n".join(lines)


# --------------------------------------------------------------------------
# the cohort driver: one roster in, one receipt per trainee out
# --------------------------------------------------------------------------
# A twenty-seat class finishing its oral boards on a Thursday should be one
# command, not twenty. Every row lands in ONE ledger under ONE namespace, so
# the chain itself proves the order the class was issued in -- a fact no
# per-trainee screenshot carries at any price (VENDOR_PACKAGE_SPEC 2.2).

ROSTER_REQUIRED = ("trainee", "ballot_path")
ROSTER_OPTIONAL = ("scenario", "grader", "timestamp")


class RosterError(ValueError):
    """A roster the driver refuses, naming the row it refused on.

    `row` is the FILE line number, counting the header as row 1, because that
    is what the coordinator sees when they open the CSV to fix it.
    """

    def __init__(self, message: str, row: Optional[int] = None):
        self.row = row
        super().__init__(f"roster row {row}: {message}" if row else f"roster: {message}")


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", str(name).lower()).strip("_")
    return s or "trainee"


def read_roster(path: str | Path, *, scenario_default: str = "", grader_default: str = "",
                timestamp_default: Optional[str] = None) -> List[dict]:
    """Read and FULLY validate a roster CSV before a single receipt is minted.

    Columns: trainee, ballot_path (required); scenario, grader, timestamp
    (optional, each falling back to the run-wide default) -- the same fields
    the single-ballot command takes, one row per trainee.

    Validation is all-or-nothing on purpose. Refusing row 7 halfway through
    a class leaves six sealed receipts, a chain that stops mid-cohort, and a
    coordinator who has to work out which trainees got paper; refusing the
    whole roster before anything is written leaves nothing to clean up. A
    malformed row is never skipped: a silently short class is the one failure
    a roster driver must not have.
    """
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise RosterError(f"cannot read {p}: {exc}") from exc
    reader = csv.DictReader(text.splitlines())
    header = [h.strip() for h in (reader.fieldnames or [])]
    missing = [c for c in ROSTER_REQUIRED if c not in header]
    if missing:
        raise RosterError(f"header must name column(s) {', '.join(missing)} "
                          f"(found: {', '.join(header) or 'nothing'})")

    rows: List[dict] = []
    seen: dict = {}
    for raw in reader:
        line_no = reader.line_num
        get = lambda k, d="": str((raw.get(k) or d) or "").strip()  # noqa: E731
        if not any((raw.get(c) or "").strip() for c in header):
            continue  # a wholly blank line is spacing, not a trainee
        trainee = get("trainee")
        if not trainee:
            raise RosterError("trainee is empty", line_no)
        ballot_path = get("ballot_path")
        if not ballot_path:
            raise RosterError(f"ballot_path is empty for {trainee!r}", line_no)
        bp = Path(ballot_path)
        if not bp.is_absolute():
            bp = p.parent / bp
        if not bp.exists():
            raise RosterError(f"ballot file not found: {bp}", line_no)
        try:
            ballot_obj = json.loads(bp.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RosterError(f"ballot file {bp.name} is not readable JSON: "
                              f"{str(exc)[:120]}", line_no) from exc
        scenario = get("scenario") or scenario_default
        if not scenario:
            raise RosterError(f"no scenario for {trainee!r} (give a scenario column "
                              "or --scenario)", line_no)
        slug = _slug(trainee)
        if slug in seen:
            raise RosterError(f"{trainee!r} collides with row {seen[slug]} "
                              f"(both write {slug}.receipt.json)", line_no)
        seen[slug] = line_no
        rows.append({"row": line_no, "trainee": trainee, "ballot_path": bp, "slug": slug,
                     "ballot": ballot_obj, "scenario": scenario,
                     "grader": get("grader") or grader_default,
                     "timestamp": get("timestamp") or timestamp_default})
    if not rows:
        raise RosterError("no trainee rows found")
    return rows


def mint_cohort(rows: Iterable[dict], *, ledger_path: str | Path, namespace: str = "ballot",
                issuer: Optional[str] = None, cohort: Optional[str] = None,
                out_dir: str | Path = ".", witness: bool = True,
                anchor: bool = False) -> List[dict]:
    """Mint one receipt per validated roster row into one ledger, in order.

    Takes rows from read_roster() (already validated) and writes
    `<trainee-slug>.receipt.json` + `<trainee-slug>.exhibit.txt` into out_dir.
    Returns one record per row for the caller to summarize.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    minted: List[dict] = []
    for r in rows:
        rc = ballot_receipt(r["ballot"], trainee=r["trainee"], scenario=r["scenario"],
                            ledger_path=ledger_path, namespace=namespace,
                            grader=r.get("grader", ""), timestamp=r.get("timestamp"),
                            witness=witness, anchor=anchor, issuer=issuer, cohort=cohort)
        rp = out / f"{r['slug']}.receipt.json"
        ep = out / f"{r['slug']}.exhibit.txt"
        save_receipt(rc, rp)
        ep.write_text(exhibit(rc), encoding="utf-8")
        minted.append({"row": r["row"], "trainee": r["trainee"], "receipt": rc,
                       "receipt_path": rp, "exhibit_path": ep})
    return minted


def cohort_summary(minted: List[dict], *, ledger_path: str | Path,
                   issuer: Optional[str] = None, cohort: Optional[str] = None) -> str:
    """One line: the count and the ledger tip the class ends on."""
    led = (minted[-1]["receipt"].get("ledger") or {}) if minted else {}
    bits = [f"{len(minted)} ballot receipt{'s' if len(minted) != 1 else ''} issued"]
    if cohort:
        bits.append(f"cohort={cohort}")
    if issuer:
        bits.append(f"issuer={issuer}")
    bits.append(f"ledger={Path(ledger_path).name} namespace={led.get('namespace')} "
                f"rows={led.get('rows')} chain={led.get('chain')}")
    return " | ".join(bits)
