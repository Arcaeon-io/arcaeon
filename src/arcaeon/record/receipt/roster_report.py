"""Roster reporting: the one page the person who runs the class opens.

VENDOR_PACKAGE_SPEC 2.3. The cohort driver turns a roster into N sealed
receipts; bulk verification turns N receipts into one verdict line. This
turns the same N receipts into the table a training coordinator actually
works from: one row per trainee, what the grading engine returned, whether
the receipt still verifies today, and whether it carries an independent
anchor. A folder of JSON is not a report, and a coordinator who has to open
twenty files will open none.

WHAT THIS REPORT IS NOT ALLOWED TO SAY. The scope block denies exactly one
thing -- "the score is correct" -- and an aggregate would smuggle that
denial's opposite back in through arithmetic. A class average is a sentence
about the class's competence; a pass rate is a sentence about the cohort's
quality; a ranking is a sentence about one trainee against another. None of
the three is a fact this package can check, and all three read as though it
had. So this report carries counts of VERDICTS (how many receipts verify)
and never a statistic about SCORES. The spec's own words, quoted because
paraphrase widens a claim:

    "The vendor package sells everything that sits around that verdict and
    never the verdict itself"

and section 6.1, which this module is the implementation of the limit of:

    "It does not grade, and it does not improve grading. Everything about
    whether a rubric measures dispatcher competence is untouched by this
    package and unaddressed by it. A receipted 91 is the same 91, sealed."

A FAIL row is a row. It is never dropped, never moved to a footnote, never
summarized away: the whole reason a coordinator runs this is to find the
one document that stopped verifying.

THE CAP, AND WHY A REPORT PAGES INSTEAD OF REFUSING. `verify_batch` refuses
a batch over 20 receipts, and its docstring says why in its own words:
"Verifying the first 20 of 21 and printing a summary would hand back a page
that looks like a finished answer for a class that was never fully checked."
That is an anti-truncation rule, not a meter. A report pages: runs of 20,
every receipt verified, nothing skipped, and the header says how many passes
it took and how large each was. The failure the refusal exists to prevent --
a partial answer wearing a finished answer's clothes -- cannot happen here,
because the report covers every receipt and prints its own pass structure on
its face. Each page is still handed to `verify_batch.verify_batch()` with
`cap=PAGE`, so a page can never exceed the published cap: if the paging in
this module were ever wrong, the refusal fires rather than the cap quietly
widening.

The honest counter-argument, recorded because it changes the answer if it is
ever true: if the cap is re-read as a commercial limit on how much free
verification one command may perform, rather than as the anti-truncation
rule it is written as today, then a 25-seat class must be refused here the
same way. The refusal shape already exists (`verify_batch.CapExceeded`) and
this module would raise it instead of paging. That is a pricing decision,
not a code one, and it is not ours to make quietly.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from . import verify_batch
from .verify_batch import CAP, FAIL, NoReceiptsFound, OK, UNDETERMINED

#: One verification pass is one call into verify_batch, and it is never
#: larger than the published cap. The report pages; the pass does not.
PAGE = CAP

REPORT_NAME = "arcaeon-receipt roster report"

#: The table, in order. `receipt_id` is the body digest, which is the thing
#: that actually identifies a receipt; `file` is kept beside it because that
#: is what a coordinator types to look one up.
COLUMNS = ("file", "receipt_id", "issuer", "cohort", "trainee", "scenario",
           "score", "issued_at", "verdict", "ledger", "anchor", "reason")

#: Header keys, in order. Everything a reader needs to know what this page
#: covers and what it is claiming, before they read a single row.
HEADER_KEYS = ("report", "source", "ledger", "issuer", "cohort", "generated_at",
               "receipts_counted", "verified", "failed", "undetermined",
               "verification_passes", "scope_proves", "scope_does_not_prove")

#: Sentinel copied from `ballot._line()` so the report and the exhibit say
#: the same thing about a ballot that carries no score field at all.
NO_SCORE = "(no score field)"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --------------------------------------------------------------------------
# what the receipt states
# --------------------------------------------------------------------------

def score_of(ballot_obj: dict) -> str:
    """The score AS THE RECEIPT STATES IT, never recomputed.

    Mirrors the fallback chain in `ballot._line()` -- `overall.score`, then a
    bare `score`, then the sequence scorer's `seq_pct` -- because the number
    on the report and the number on the trainee's exhibit must be the same
    number read the same way. `tests/test_roster_report.py` holds the two
    together against every committed example rather than trusting this
    comment.
    """
    if not isinstance(ballot_obj, dict):
        return NO_SCORE
    overall = ballot_obj.get("overall") or {}
    if not isinstance(overall, dict):
        overall = {}
    score = overall.get("score", ballot_obj.get("score", ballot_obj.get("seq_pct", NO_SCORE)))
    return "" if score is None else str(score)


def _check(receipt: dict) -> dict:
    checks = receipt.get("checks") or []
    return checks[0] if checks and isinstance(checks[0], dict) else {}


def _facts(receipt: Optional[dict]) -> dict:
    """The stated fields of one receipt. Everything here is copied out, never
    derived: a report that recomputes a trainee's score is a second grader."""
    if not isinstance(receipt, dict):
        return {"receipt_id": "", "issuer": "", "cohort": "", "trainee": "",
                "scenario": "", "score": "", "issued_at": "", "scope": ""}
    extra = receipt.get("extra") if isinstance(receipt.get("extra"), dict) else {}
    subject = receipt.get("subject") if isinstance(receipt.get("subject"), dict) else {}
    check = _check(receipt)
    scope = receipt.get("scope") if isinstance(receipt.get("scope"), dict) else {}
    return {
        "receipt_id": str(receipt.get("body_digest") or ""),
        "issuer": str(extra.get("issuer") or ""),
        "cohort": str(extra.get("cohort") or ""),
        # the trainee label as the ballot carries it: the check is the sealed
        # copy, the subject block is the same string rendered for a reader.
        "trainee": str(check.get("trainee") or subject.get("trainee") or ""),
        "scenario": str(check.get("scenario") or subject.get("scenario") or ""),
        "score": score_of(check.get("ballot") or {}) if check else "",
        "issued_at": str(receipt.get("issued_at") or ""),
        "scope": scope,
    }


def _load(path: Path) -> Optional[dict]:
    """Never raises. A file the verifier could not read is already an
    `undetermined` row; it must not also be a crash."""
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return obj if isinstance(obj, dict) else None


# --------------------------------------------------------------------------
# targets: a cohort directory, or the ledger sitting in one
# --------------------------------------------------------------------------

def resolve_target(target: str | Path) -> tuple:
    """Return (receipt paths, ledger path or None) for a cohort dir or ledger.

    A coordinator has one of two things in hand: the export directory, or the
    class ledger inside it. Pointing at the ledger reports on the directory it
    lives in and checks every receipt against that exact file -- which is the
    stricter reading, and the one somebody means when they name a ledger.
    """
    p = Path(target)
    if p.is_file() and p.suffix == ".jsonl":
        return verify_batch.collect_paths([p.parent]), p
    return verify_batch.collect_paths([p]), None


# --------------------------------------------------------------------------
# the pass structure
# --------------------------------------------------------------------------

def verify_pages(paths: Sequence[Path], *, ledger_path: Optional[str | Path] = None,
                 ots: bool = False, page: int = PAGE) -> List[dict]:
    """Verify every receipt, in runs of at most `page`, through verify_batch.

    `cap=page` is passed down deliberately: the cap keeps enforcing itself on
    every pass, so a paging bug in this module surfaces as a refusal rather
    than as a silently oversized batch.
    """
    if page < 1:
        raise ValueError("a verification pass must hold at least one receipt")
    pages = [list(paths[i:i + page]) for i in range(0, len(paths), page)]
    return [verify_batch.verify_batch(chunk, ledger_path=ledger_path, ots=ots, cap=page)
            for chunk in pages]


def passes_line(results: Sequence[dict], page: int = PAGE) -> str:
    """Said on the face of the report, because a reader is owed the pass
    structure: how many passes, how big each one was, and that the count adds
    up to the receipts counted above it."""
    sizes = [len(r["rows"]) for r in results]
    n = len(sizes)
    return (f"{n} pass{'es' if n != 1 else ''} of at most {page} "
            f"({', '.join(str(s) for s in sizes)}); every receipt was verified")


# --------------------------------------------------------------------------
# the report
# --------------------------------------------------------------------------

def _one_of(values: Iterable[str], none_text: str) -> str:
    vals = list(values)
    present = sorted({v for v in vals if v})
    blank = sum(1 for v in vals if not v)
    if not present:
        return none_text
    if len(present) == 1 and not blank:
        return present[0]
    out = "(mixed) " + "; ".join(present)
    return out + (f"; {blank} receipt{'s' if blank != 1 else ''} carry none" if blank else "")


def _scope_text(scopes: List[dict], key: str) -> str:
    """The scope block's own sentences, verbatim, joined by '; ' when a block
    carries more than one. Both `proves` and `does_not_prove` go on the
    report: printing what it proves without printing what it declines to
    prove is the overclaim the scope block exists to stop."""
    seen = []
    for sc in scopes:
        vals = sc.get(key) if isinstance(sc, dict) else None
        if not isinstance(vals, list):
            continue
        text = "; ".join(str(v) for v in vals)
        if text and text not in seen:
            seen.append(text)
    return " | ".join(seen)


def build_report(target: str | Path, *, ledger_path: Optional[str | Path] = None,
                 ots: bool = False, page: int = PAGE,
                 generated_at: Optional[str] = None) -> dict:
    """{'header': {...}, 'columns': [...], 'rows': [{...}]}, all values strings.

    All strings on purpose: the CSV is the artifact a coordinator keeps, and
    the JSON is the SAME table for a machine, not a richer one. A JSON that
    carried types the CSV cannot would be a second report quietly disagreeing
    with the first.
    """
    paths, from_target = resolve_target(target)
    if not paths:
        raise NoReceiptsFound(
            f"no receipts under {target}: a roster report reads a cohort "
            f"directory of {verify_batch.RECEIPT_GLOB} files, or the class "
            "ledger sitting beside them"
        )
    led = ledger_path if ledger_path is not None else from_target
    results = verify_pages(paths, ledger_path=led, ots=ots, page=page)

    rows: List[dict] = []
    scopes: List[dict] = []
    counts = {OK: 0, FAIL: 0, UNDETERMINED: 0}
    for result in results:
        for vrow in result["rows"]:
            # the path the verifier actually read, not a parallel list this
            # function zipped up and hoped stayed aligned
            facts = _facts(_load(Path(vrow["path"])))
            if isinstance(facts["scope"], dict) and facts["scope"]:
                scopes.append(facts["scope"])
            counts[vrow["verdict"]] += 1
            rows.append({
                "file": vrow["id"],
                "receipt_id": facts["receipt_id"],
                "issuer": facts["issuer"],
                "cohort": facts["cohort"],
                "trainee": facts["trainee"],
                "scenario": facts["scenario"],
                "score": facts["score"],
                "issued_at": facts["issued_at"],
                "verdict": vrow["verdict"],
                "ledger": str(vrow["ledger"] or ""),
                "anchor": str(vrow["anchor"] or ""),
                "reason": str(vrow["reason"] or ""),
            })

    header = {
        "report": REPORT_NAME,
        "source": str(target),
        "ledger": (Path(led).name if led else
                   "(each receipt's own, read beside it)"),
        "issuer": _one_of((r["issuer"] for r in rows),
                          "(none: these receipts carry no issuer)"),
        "cohort": _one_of((r["cohort"] for r in rows),
                          "(none: these receipts carry no cohort)"),
        "generated_at": generated_at or _now(),
        "receipts_counted": str(len(rows)),
        "verified": str(counts[OK]),
        "failed": str(counts[FAIL]),
        "undetermined": str(counts[UNDETERMINED]),
        "verification_passes": passes_line(results, page),
        "scope_proves": _scope_text(scopes, "proves"),
        "scope_does_not_prove": _scope_text(scopes, "does_not_prove"),
    }
    return {"header": header, "columns": list(COLUMNS), "rows": rows}


def exit_code(report: dict) -> int:
    """Same three-way meaning as `verify_batch.exit_code`, over the whole
    report: 0 all ok, 2 a definite FAIL somewhere, 4 nothing failed but
    something could not be determined."""
    if int(report["header"]["failed"]):
        return 2
    if int(report["header"]["undetermined"]):
        return 4
    return 0


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def to_csv(report: dict) -> str:
    """Header block (one `# key,value` row each), a blank line, then the table.

    The `#` prefix keeps the header rows out of a naive two-column read while
    leaving them visible in the spreadsheet the coordinator actually opens.
    """
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    for key in HEADER_KEYS:
        w.writerow([f"# {key}", report["header"][key]])
    w.writerow([])
    w.writerow(report["columns"])
    for row in report["rows"]:
        w.writerow([row[c] for c in report["columns"]])
    return buf.getvalue()


def to_json(report: dict) -> str:
    return json.dumps(report, indent=1, ensure_ascii=False) + "\n"


def summary_line(report: dict) -> str:
    h = report["header"]
    n = h["receipts_counted"]
    return (f"{n} receipt{'s' if n != '1' else ''}: {h['verified']} VERIFIED, "
            f"{h['failed']} BROKEN, {h['undetermined']} COULD NOT LOOK "
            f"({h['verification_passes']})")
