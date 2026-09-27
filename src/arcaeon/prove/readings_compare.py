# SPDX-License-Identifier: MIT
"""arcaeon.prove.readings_compare: line up two readings ledgers, claim by claim.

Two ledgers, each written by one reader (see `arcaeon.prove.readings`), each
reading claims against a frozen criterion. For every claim id seen on either
side exactly one of four things is filed:

  AGREED          both sides read the claim, same reading word.
  DISAGREED       both sides read the claim, different reading words. Filed
                  with both readings, both reader ids and each side's
                  near_match_id. Never dropped, never averaged away.
  MISSING         the claim was read on one side only. `side` names the SHORT
                  ledger (the one without the reading).
  COULD NOT LOOK  both sides have the claim but the readings cannot be lined
                  up: the two rows hash different claim text, or cite
                  different criteria. Both sides are still carried.

AGREED is a statement about two readers and one sentence, not about the claim.
Two readers agreeing measures how ambiguous the sentence was for them; it does
not say which reading holds, and a DISAGREED claim does not say either reader
was wrong. Every result carries this in `limits`.

THE COUNTS are two integers, `disagreed` and `read` (claims read on both sides
and lined up), never a lone ratio. `fraction` rides beside them, and is null
with a `fraction_reason` when `read` is 0. Under 20 claims read the counts are
still printed and `not_yet_informative` is true. When the counts were not
computed at all (a ledger BROKEN or not readable), `disagreed` and `read` are
null and `counts_reason` says why.

THE READERS. Each lined-up claim carries `independence`, from what the rows
say about their readers (nothing here checks it):
  same_reader                      one reader id on both sides. That is not a
                                   second read, so the claim is COULD NOT LOOK,
                                   reason "the same reader on both sides",
                                   `reason_word: "bounded"`.
  same_provider                    two reader ids, one provider.
  distinct_provider_self_asserted  two providers, as the rows assert them.
The result's top-level `independence` is the weakest class among lined-up
claims (null with `independence_reason` when none lined up), and
`independence_counts` gives the count per class.

THE VERDICT, first match wins:
  BROKEN          either ledger's chain is broken; names the ledger and line.
  COULD NOT LOOK  a ledger is missing, unreadable, empty, bounded, or cites a
                  criterion it never froze (`reason_word: "name_not_found"`).
  COULD NOT LOOK  one reader id on both sides of any claim (`bounded`).
  MISSING         one or more claims were read on one side only.
  COULD NOT LOOK  one or more claims could not be lined up.
  COMPARED        every claim was lined up. Disagreement is filed, not failed.

Exit codes (the arcaeon table): COMPARED 0, MISSING 1, BROKEN 1, COULD NOT
LOOK 3. Stdlib only. `compare` reads ledgers; it never writes them.

THE RECEIPT (`issue_receipt`, the CLI's `--receipt OUT`). A compare result
can be issued as an `arcaeon-receipt/0.1` receipt carrying both readings
ledgers' heads and every count and per-claim line, so `arcaeon receipt verify
OUT` catches any later edit by the body digest. It is local and free: no
witness pin, no timestamp anchor, nothing sent. The receipt's own row goes to
OUT + ".ledger.jsonl" (the one file this module writes).
"""
from __future__ import annotations

import re
from pathlib import Path

from arcaeon import verdict as _v
from arcaeon.prove.readings import canonical_reader_id, load_readings
from arcaeon.record.ledger import verify_file

__all__ = ["COMPARE_FORMAT", "COMPARED", "AGREED", "DISAGREED", "MISSING", "COULD_NOT_LOOK",
           "BROKEN", "INFORMATIVE_AT", "LIMITS", "EXIT_CODES", "SAME_READER", "SAME_PROVIDER",
           "DISTINCT_PROVIDER", "INDEPENDENCE_CLASSES", "compare", "RECEIPT_KIND",
           "RECEIPT_SCOPE", "issue_receipt", "receipt_ledger_for"]

COMPARE_FORMAT = "arcaeon-readings-compare/1"

#: The comparison completed and every claim was lined up (arcaeon.verdict).
COMPARED = _v.COMPARED
AGREED = "AGREED"
DISAGREED = "DISAGREED"
MISSING = _v.MISSING
COULD_NOT_LOOK = _v.COULD_NOT_LOOK
BROKEN = _v.BROKEN

#: The independence classes, weakest first. Self-asserted by the rows.
SAME_READER = "same_reader"
SAME_PROVIDER = "same_provider"
DISTINCT_PROVIDER = "distinct_provider_self_asserted"
INDEPENDENCE_CLASSES = (SAME_READER, SAME_PROVIDER, DISTINCT_PROVIDER)
SAME_READER_REASON = "the same reader on both sides"

#: Below this many claims read, the counts are printed and marked not yet informative.
INFORMATIVE_AT = 20

EXIT_CODES = {COMPARED: _v.exit_for(_v.COMPARED), MISSING: _v.EXIT_BAD, BROKEN: _v.EXIT_BAD,
              COULD_NOT_LOOK: _v.EXIT_COULD_NOT_LOOK}

LIMITS = (
    "AGREED means two readers read one frozen sentence the same way for that claim; "
    "it says nothing about whether the claim holds.",
    "The disagreement count measures how ambiguous the sentence was for these readers, "
    "not which reader was right.",
    "Reader ids and providers are what each row says about itself; this check does not "
    "confirm who or what wrote them.",
    "Readers from one model family or one vendor share habits; their agreement is worth less.",
    f"Under {INFORMATIVE_AT} claims read, the counts are printed and marked not yet informative.",
)

_LINE = re.compile(r"\bline (\d+)\b")


def _side_view(row: dict) -> dict:
    reader = row.get("reader") or {}
    return {"reading": row.get("reading"), "reader_id": reader.get("id"),
            "provider": reader.get("provider"), "model": reader.get("model"),
            "near_match_id": row.get("near_match_id"), "claim_sha256": row.get("claim_sha256"),
            "criterion_sha256": row.get("criterion_sha256"), "line": row.get("line")}


def _chain_check(name: str, path: Path) -> dict | None:
    """None if the ledger's chain is fully verified; else a BROKEN or COULD NOT LOOK stub."""
    where = str(path)
    if not path.exists():
        return {"verdict": COULD_NOT_LOOK, "ledger": name, **_v.could_not_look(
            "a readings ledger", where, "missing", f"ledger {name} ({where}) does not exist")}
    res = verify_file(path)
    if res.ok is True:
        return None
    fb = res.first_break or ""
    if res.ok is False and fb.startswith("unreadable"):
        return {"verdict": COULD_NOT_LOOK, "ledger": name, **_v.could_not_look(
            "a readings ledger", where, "unreadable", f"ledger {name} ({where}) [{fb}]")}
    if res.ok is False:
        m = _LINE.search(fb)
        return {"verdict": BROKEN, "ledger": name, "where": where,
                "line": int(m.group(1)) if m else None, "first_break": fb,
                "reason": f"ledger {name} ({where}) chain is broken: {fb}"}
    if res.verified_scope == "empty":
        return {"verdict": COULD_NOT_LOOK, "ledger": name, **_v.could_not_look(
            "readings", where, "empty", f"ledger {name} ({where}) has no rows")}
    return {"verdict": COULD_NOT_LOOK, "ledger": name, **_v.could_not_look(
        "a fully verified chain", where, "bounded",
        f"ledger {name} ({where}) verifies only within scope {res.verified_scope}")}


def _not_computed(reason: str) -> dict:
    return {"disagreed": None, "read": None, "agreed": None, "missing": None,
            "could_not_look": None, "not_yet_informative": None, "fraction": None,
            "fraction_reason": reason, "counts_reason": reason}


def _result(a: Path, b: Path, verdict: str, *, claims=None, summary=None, extra=None) -> dict:
    out = {"format": COMPARE_FORMAT, "verdict": verdict, "exit": EXIT_CODES[verdict],
           "ledgers": {"a": str(a), "b": str(b)}, "claims": claims or [],
           "summary": summary, "limits": list(LIMITS)}
    if extra:
        out.update(extra)
    return out


def _latest(readings: list[dict]) -> dict[str, dict]:
    """claim_id -> the LAST reading of it in the ledger (a re-read supersedes)."""
    out: dict[str, dict] = {}
    for row in readings:
        out[row["claim_id"]] = row
    return out


def _pair(claim_id: str, ra: dict | None, rb: dict | None, a: Path, b: Path) -> dict:
    entry: dict = {"claim_id": claim_id}
    if ra is None or rb is None:
        short = "a" if ra is None else "b"
        entry.update({"status": MISSING, "side": short,
                      "where": str(a if short == "a" else b),
                      "a": _side_view(ra) if ra else None, "b": _side_view(rb) if rb else None})
        return entry
    va, vb = _side_view(ra), _side_view(rb)
    entry.update({"a": va, "b": vb})
    if va["claim_sha256"] != vb["claim_sha256"]:
        entry.update({"status": COULD_NOT_LOOK, **_v.could_not_look(
            "one claim text on both sides", f"{a} line {va['line']}, {b} line {vb['line']}",
            "bounded", f"claim {claim_id}: the two readings hash different claim text")})
        return entry
    if va["criterion_sha256"] != vb["criterion_sha256"]:
        entry.update({"status": COULD_NOT_LOOK, **_v.could_not_look(
            "one criterion on both sides", f"{a} line {va['line']}, {b} line {vb['line']}",
            "bounded", f"claim {claim_id}: the two readings cite different criteria")})
        return entry
    entry["independence"] = _independence(va, vb)
    if entry["independence"] == SAME_READER:
        entry.update({"status": COULD_NOT_LOOK, **_v.could_not_look(
            "two different readers", f"{a} line {va['line']}, {b} line {vb['line']}",
            "bounded", SAME_READER_REASON)})
        return entry
    entry["status"] = AGREED if va["reading"] == vb["reading"] else DISAGREED
    return entry


def _canon(value) -> str:
    return canonical_reader_id(value) if isinstance(value, str) else ""


def _independence(va: dict, vb: dict) -> str:
    # canonical form (NFKC, stripped, casefolded): ids that differ only by case
    # are one reader, even in a row that was written by hand
    if _canon(va["reader_id"]) == _canon(vb["reader_id"]):
        return SAME_READER
    pa = (va["provider"] or "").strip().casefold()
    pb = (vb["provider"] or "").strip().casefold()
    return SAME_PROVIDER if pa == pb else DISTINCT_PROVIDER


def _summary(claims: list[dict]) -> dict:
    agreed = sum(1 for c in claims if c["status"] == AGREED)
    disagreed = sum(1 for c in claims if c["status"] == DISAGREED)
    read = agreed + disagreed
    out = {"disagreed": disagreed, "read": read, "agreed": agreed,
           "missing": sum(1 for c in claims if c["status"] == MISSING),
           "could_not_look": sum(1 for c in claims if c["status"] == COULD_NOT_LOOK),
           "not_yet_informative": read < INFORMATIVE_AT}
    if read == 0:
        out.update({"fraction": None, "fraction_reason": "no claim was read and lined up on both sides"})
    else:
        out.update({"fraction": round(disagreed / read, 6), "fraction_reason": None})
    return out


def compare(ledger_a: str | Path, ledger_b: str | Path) -> dict:
    """Compare two readings ledgers. Never raises on bad input; that is an answer too."""
    a, b = Path(ledger_a), Path(ledger_b)
    # 1. Chains first: a broken ledger is BROKEN whatever else is in it.
    checks = {"a": _chain_check("a", a), "b": _chain_check("b", b)}
    for name in ("a", "b"):
        c = checks[name]
        if c and c["verdict"] == BROKEN:
            return _result(a, b, BROKEN, summary=_not_computed(c["reason"]), extra={"broken": c})
    for name in ("a", "b"):
        c = checks[name]
        if c:
            keys = {k: c[k] for k in ("looked_for", "where", "reason_word", "reason")}
            return _result(a, b, COULD_NOT_LOOK, summary=_not_computed(c["reason"]),
                           extra={**keys, "ledger": name})
    # 2. Every reading must cite a criterion frozen earlier in its own ledger.
    loaded = {}
    for name, path in (("a", a), ("b", b)):
        res = load_readings(path)
        if not res["ok"]:
            keys = {k: res[k] for k in ("looked_for", "where", "reason_word", "reason")}
            return _result(a, b, COULD_NOT_LOOK, summary=_not_computed(res["reason"]),
                           extra={**keys, "ledger": name, "line": res.get("line")})
        loaded[name] = _latest(res["readings"])
    la, lb = loaded["a"], loaded["b"]
    if not la and not lb:
        reason = "neither ledger holds a reading"
        return _result(a, b, COULD_NOT_LOOK, summary=_not_computed(reason), extra={
            **_v.could_not_look("readings", f"{a}, {b}", "empty", reason), "ledger": None})
    # 3. Claim by claim, in first-seen order (a's order, then b's extras).
    ids = list(la) + [cid for cid in lb if cid not in la]
    claims = [_pair(cid, la.get(cid), lb.get(cid), a, b) for cid in ids]
    summary = _summary(claims)
    counts = {k: sum(1 for c in claims if c.get("independence") == k) for k in INDEPENDENCE_CLASSES}
    seen = [k for k in INDEPENDENCE_CLASSES if counts[k]]
    indep = {"independence": seen[0] if seen else None, "independence_counts": counts,
             "independence_reason": None if seen else "no claim was on both sides to line up"}
    if counts[SAME_READER]:
        return _result(a, b, COULD_NOT_LOOK, claims=claims, summary=summary, extra={
            **indep, **_v.could_not_look("two different readers", f"{a}, {b}", "bounded",
                                         SAME_READER_REASON), "ledger": None})
    if summary["missing"]:
        word = MISSING
    elif summary["could_not_look"]:
        word = COULD_NOT_LOOK
    else:
        word = COMPARED
    extra = dict(indep)
    if word == COULD_NOT_LOOK:
        n = summary["could_not_look"]
        extra = {**indep, **_v.could_not_look("every claim lined up", f"{a}, {b}", "bounded",
                                     f"{n} claim(s) could not be lined up"), "ledger": None}
    return _result(a, b, word, claims=claims, summary=summary, extra=extra)


# --------------------------------------------------------------------------
# the comparison as a receipt (K043): local, free
# --------------------------------------------------------------------------

RECEIPT_KIND = "readings-compare"
RECEIPT_NAMESPACE = "second-read"
RECEIPT_SCOPE = {
    "proves": [
        "These are the counts and per-claim lines this compare filed for the two readings "
        "ledgers named in the subject, at the two ledger heads named there.",
        "Any later edit to a count, a status, a reading or a head in this receipt changes "
        "its body digest, and `arcaeon receipt verify` names the mismatch.",
    ],
    "does_not_prove": [
        "Whether any claim holds: two readers agreeing measures how ambiguous the sentence "
        "was for them, not which reading is right.",
        "Who or what wrote either ledger: reader ids and providers are what the rows say "
        "about themselves.",
        "That the two readers share no habits: readers from one model family or one vendor "
        "agree more for that reason alone.",
        "Anything to a stranger about when it was issued: this receipt is local and "
        "unwitnessed (no witness pin, no timestamp anchor); the witness-sealed version is "
        "the hosted reconcile, which is not deployed.",
    ],
}


def _head_of(path: Path) -> dict:
    from arcaeon.record.ledger import Ledger
    h = Ledger(path).head()
    return {"path": str(path), "rows": h.rows, "chain": h.chain,
            "chain_ok": h.ok, "first_break": h.first_break}


def receipt_ledger_for(out: str | Path) -> Path:
    """The default ledger a compare receipt is chained into: beside OUT."""
    o = Path(out)
    return o.with_name(o.name + ".ledger.jsonl")


def issue_receipt(result: dict, out: str | Path, *, ledger_path: str | Path | None = None,
                  issued_at: str | None = None) -> tuple[dict, Path, Path]:
    """Issue a compare result as a receipt through `arcaeon.record.receipt.core`.

    The subject carries both readings ledgers' heads (rows, chain, and whether
    the chain held); the one check carries the verdict, the two counts, the
    independence class and every per-claim line, so editing any of them
    breaks the body digest. Local and free: no witness pin and no
    OpenTimestamps anchor are made, so nothing leaves this machine. The
    receipt row is chained into `ledger_path` (default: OUT + ".ledger.jsonl").
    Returns (receipt, receipt path, receipt ledger path).
    """
    from arcaeon.record.receipt.core import build_receipt, save_receipt
    led = Path(ledger_path) if ledger_path is not None else receipt_ledger_for(out)
    ledgers = result.get("ledgers") or {}
    subject = {"compare_format": result.get("format"),
               "ledgers": {side: _head_of(Path(ledgers[side])) for side in ("a", "b")
                           if ledgers.get(side)}}
    check = {"verdict": result.get("verdict"), "exit": result.get("exit"),
             "summary": result.get("summary"), "independence": result.get("independence"),
             "independence_counts": result.get("independence_counts"),
             "reason_word": result.get("reason_word"), "reason": result.get("reason"),
             "claims": [{"claim_id": c.get("claim_id"), "status": c.get("status"),
                         "side": c.get("side"), "independence": c.get("independence"),
                         "a": _receipt_side(c.get("a")), "b": _receipt_side(c.get("b"))}
                        for c in result.get("claims") or []]}
    receipt = build_receipt(RECEIPT_KIND, subject, [check], RECEIPT_SCOPE, ledger_path=led,
                            namespace=RECEIPT_NAMESPACE, extra={"limits": list(LIMITS)},
                            witness=False, anchor=False, issued_at=issued_at)
    path = save_receipt(receipt, out)
    return receipt, path, led


def _receipt_side(view: dict | None) -> dict | None:
    if not view:
        return None
    return {k: view.get(k) for k in ("reading", "reader_id", "provider", "model",
                                     "near_match_id", "claim_sha256", "criterion_sha256")}
