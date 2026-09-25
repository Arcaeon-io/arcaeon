"""arcaeon-receipt CLI.

  arcaeon-receipt cite <brief.txt> [--ledger L] [--namespace NS] [--out receipt.json]
                       [--exhibit exhibit.txt] [--fixture saved_api_response.json]
                       [--no-anchor] [--no-witness]
  arcaeon-receipt ballot <ballot.json> --trainee NAME --scenario NAME
                       [--grader G] [--timestamp TS] [--ledger L] [--namespace NS]
                       [--issuer ACADEMY] [--cohort CLASS]
                       [--out receipt.json] [--exhibit exhibit.txt]
                       [--no-anchor] [--no-witness]
  arcaeon-receipt ballot --roster roster.csv [--scenario NAME] [--grader G]
                       [--issuer ACADEMY] [--cohort CLASS] [--ledger L]
                       [--namespace NS] [--out-dir DIR] [--no-anchor] [--no-witness]
  arcaeon-receipt verify <receipt.json> [--ledger L] [--ots]
  arcaeon-receipt verify --batch <dir|glob|receipt.json ...> [--ledger L] [--ots]
  arcaeon-receipt roster-report <cohort-dir|class-ledger.jsonl> [--out report.csv]
                       [--json] [--ledger L] [--ots]
  arcaeon-receipt archive <cohort-dir|class-ledger.jsonl> --out class.zip
                       [--ledger L] [--ots]
  arcaeon-receipt exhibit <receipt.json>

Exit codes: 0 ok; 1 usage/transport error; 2 verify failed; 3 receipt has
flagged checks (cite: a citation not found or with an invalid reporter);
4 (--batch, roster-report and archive): nothing BROKEN but the check
COULD NOT LOOK at one or more receipts.
Exit 3 is deliberate: a pre-filing gate should stop on a flag, not on a
clean receipt. `ballot` has no flagged-check concept (a ballot is already a
finished, already-graded object) so it only ever exits 0 or 1. Exit 4 is
the same kind of deliberate: a coordinator scripting a gate must be able to
tell "this receipt is bad" from "I could not check this receipt" without
parsing text.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import (__version__, approval, archive, authorship, ballot, call, cite,
               roster_report, verify_batch)
from .core import load_receipt, render_exhibit, save_receipt, verify_receipt

EXHIBITS = {cite.KIND: cite.exhibit, call.KIND: call.exhibit,
            approval.KIND: approval.exhibit, authorship.KIND: authorship.exhibit,
            ballot.KIND: ballot.exhibit}


def _exhibit(receipt: dict) -> str:
    return EXHIBITS.get(receipt.get("kind"), render_exhibit)(receipt)


def _does_not_prove(scope: dict) -> str:
    """A-034: `--help` on a receipt-issuing subcommand must name what it does
    NOT prove, matching core.py's own scope rule (a receipt without a
    stated limit is refused at build time; the CLI's own --help should not
    be silent about the same limits). Pulled directly from the adapter's
    own SCOPE dict rather than restated by hand, so this text cannot drift
    from what the issued receipt itself says."""
    return "Does NOT prove: " + "; ".join(scope["does_not_prove"]) + "."


def main(argv=None, prog: str = "arcaeon-receipt") -> int:
    ap = argparse.ArgumentParser(prog=prog)
    ap.add_argument("--version", action="version", version=f"arcaeon-receipt {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("cite", help="citation existence receipt for a brief",
                       description="Citation Receipt: existence checks against CourtListener. "
                                   + _does_not_prove(cite.SCOPE))
    c.add_argument("path")
    c.add_argument("--ledger", default="receipts.log.jsonl")
    c.add_argument("--namespace", default="citation-receipt")
    c.add_argument("--out", default=None)
    c.add_argument("--exhibit", default=None)
    c.add_argument("--fixture", default=None, help="replay a saved API response instead of calling CourtListener")
    c.add_argument("--no-anchor", action="store_true")
    c.add_argument("--no-witness", action="store_true")

    b = sub.add_parser("ballot", help="ballot receipt for a finished training-sim grade",
                       description="Ballot Receipt: a finished training-sim grade, sealed at close. "
                                   + _does_not_prove(ballot.SCOPE))
    b.add_argument("path", nargs="?", default=None,
                   help="JSON file holding the graded ballot object, verbatim "
                        "(omit when using --roster)")
    b.add_argument("--trainee", default=None)
    b.add_argument("--scenario", default=None,
                   help="required for a single ballot; with --roster it is the "
                        "fallback for rows that carry no scenario column")
    b.add_argument("--grader", default="", help="name of the grading engine that produced the ballot")
    b.add_argument("--timestamp", default=None, help="issued_at override; defaults to now (UTC)")
    b.add_argument("--issuer", default=None,
                   help="issuing academy or vendor; sealed inside the body digest")
    b.add_argument("--cohort", default=None,
                   help="class or cohort id; sealed inside the body digest")
    b.add_argument("--roster", default=None,
                   help="CSV roster (columns: trainee, ballot_path[, scenario, grader, "
                        "timestamp]); mints one receipt per row into one ledger")
    b.add_argument("--out-dir", dest="out_dir", default=".",
                   help="--roster only: where the per-trainee receipt/exhibit pairs land")
    b.add_argument("--ledger", default="receipts.log.jsonl")
    b.add_argument("--namespace", default="ballot")
    b.add_argument("--out", default=None)
    b.add_argument("--exhibit", default=None)
    b.add_argument("--no-anchor", action="store_true")
    b.add_argument("--no-witness", action="store_true")

    v = sub.add_parser("verify", help="recompute a receipt's digests",
                       description="Verify one receipt, or a whole class at once with "
                                   f"--batch (cap: {verify_batch.CAP} receipts per pass, "
                                   "refused past it, never truncated).")
    v.add_argument("path", nargs="?", default=None)
    v.add_argument("--batch", nargs="+", default=None, metavar="TARGET",
                   help="verify every receipt in a directory, glob, or explicit "
                        f"list of paths; refuses past {verify_batch.CAP} in one pass")
    v.add_argument("--ledger", default=None,
                   help="with --batch, the one ledger every receipt is checked "
                        "against; omit it and each receipt is checked against the "
                        "ledger named on its own face, if that file sits beside it")
    v.add_argument("--ots", action="store_true", help="also run `ots verify` on the anchor")

    r = sub.add_parser("roster-report", help="one row per trainee across a class",
                       description="Roster report: one row per trainee across a cohort -- "
                                   "what the grading engine returned and whether the "
                                   "receipt still verifies. Verdict counts only: this "
                                   "report carries no statistic about scores, because "
                                   "the scope block denies that the score is correct.")
    r.add_argument("target", help="the cohort export directory, or the class ledger in it")
    r.add_argument("--out", default=None, help="write the report here (default: stdout)")
    r.add_argument("--json", action="store_true", dest="as_json",
                   help="emit the same table as JSON instead of CSV")
    r.add_argument("--ledger", default=None,
                   help="check every receipt against this one ledger; omit it and "
                        "each receipt is checked against the ledger named on its own "
                        "face, if that file sits beside it")
    r.add_argument("--ots", action="store_true", help="also run `ots verify` on anchors")

    ar = sub.add_parser("archive", help="one portable file holding the whole class",
                        description="Bulk export: every receipt, every exhibit, the "
                                    "ledger they name, the roster report, a manifest "
                                    "of sha256 digests, and a README telling a human "
                                    "with no tools how to verify it. Receipts are "
                                    "copied byte for byte. A receipt that does not "
                                    "verify is packed with its verdict on the "
                                    "manifest, never dropped.")
    ar.add_argument("target", help="the cohort export directory, or the class ledger in it")
    ar.add_argument("--out", required=True, help="the .zip to write")
    ar.add_argument("--ledger", default=None,
                    help="check every receipt against this one ledger; omit it and "
                         "each receipt is checked against the ledger named on its own "
                         "face, if that file sits beside it")
    ar.add_argument("--ots", action="store_true", help="also run `ots verify` on anchors")

    e = sub.add_parser("exhibit", help="print the plain-text exhibit")
    e.add_argument("path")

    a = ap.parse_args(argv)

    if a.cmd == "cite":
        text = Path(a.path).read_text(encoding="utf-8", errors="replace")
        transport = cite.fixture_transport(a.fixture) if a.fixture else None
        try:
            rc = cite.citation_receipt(text, ledger_path=a.ledger, namespace=a.namespace,
                                       document_name=Path(a.path).name, transport=transport,
                                       witness=not a.no_witness, anchor=not a.no_anchor)
        except (RuntimeError, ValueError, OSError) as ex:
            print(f"error: {ex}", file=sys.stderr)
            return 1
        out = a.out or (Path(a.path).stem + ".receipt.json")
        save_receipt(rc, out)
        text_ex = cite.exhibit(rc)
        if a.exhibit:
            Path(a.exhibit).write_text(text_ex, encoding="utf-8")
        print(text_ex)
        print(f"receipt written: {out}")
        return 3 if rc["extra"]["summary"]["flagged"] else 0

    if a.cmd == "ballot":
        # The cohort driver. A malformed row refuses the WHOLE roster before
        # anything is minted (see ballot.read_roster) -- a class that comes out
        # silently one receipt short is the failure this branch exists to avoid.
        if a.roster:
            if a.path or a.trainee:
                print("error: --roster mints a whole class; drop the single-ballot "
                      "path/--trainee arguments", file=sys.stderr)
                return 1
            try:
                rows = ballot.read_roster(a.roster, scenario_default=a.scenario or "",
                                          grader_default=a.grader,
                                          timestamp_default=a.timestamp)
                minted = ballot.mint_cohort(rows, ledger_path=a.ledger, namespace=a.namespace,
                                            issuer=a.issuer, cohort=a.cohort,
                                            out_dir=a.out_dir, witness=not a.no_witness,
                                            anchor=not a.no_anchor)
            except (ballot.RosterError, ValueError, OSError) as ex:
                print(f"error: {ex}", file=sys.stderr)
                return 1
            print(ballot.cohort_summary(minted, ledger_path=a.ledger,
                                        issuer=a.issuer, cohort=a.cohort))
            return 0

        if not a.path or not a.trainee or not a.scenario:
            print("error: a single ballot needs the ballot JSON path, --trainee and "
                  "--scenario (or use --roster for a whole class)", file=sys.stderr)
            return 1
        try:
            ballot_obj = json.loads(Path(a.path).read_text(encoding="utf-8"))
        except (OSError, ValueError) as ex:
            print(f"error: {ex}", file=sys.stderr)
            return 1
        try:
            rc = ballot.ballot_receipt(ballot_obj, trainee=a.trainee, scenario=a.scenario,
                                       ledger_path=a.ledger, namespace=a.namespace,
                                       grader=a.grader, timestamp=a.timestamp,
                                       witness=not a.no_witness, anchor=not a.no_anchor,
                                       issuer=a.issuer, cohort=a.cohort)
        except (ValueError, OSError) as ex:
            print(f"error: {ex}", file=sys.stderr)
            return 1
        out = a.out or (Path(a.path).stem + ".receipt.json")
        save_receipt(rc, out)
        text_ex = ballot.exhibit(rc)
        if a.exhibit:
            Path(a.exhibit).write_text(text_ex, encoding="utf-8")
        print(text_ex)
        print(f"receipt written: {out}")
        return 0

    if a.cmd == "verify":
        # The bulk pass. Mirrors `ballot --roster`: one command for a whole
        # class, and a refusal rather than a partial answer when the batch is
        # over the published cap.
        if a.batch:
            if a.path:
                print("error: --batch takes its own target list; drop the single "
                      "receipt path", file=sys.stderr)
                return 1
            try:
                result = verify_batch.verify_batch(a.batch, ledger_path=a.ledger,
                                                   ots=a.ots)
            except (verify_batch.CapExceeded, verify_batch.NoReceiptsFound) as ex:
                print(f"error: {ex}", file=sys.stderr)
                return 1
            print(verify_batch.render(result))
            return verify_batch.exit_code(result)

        if not a.path:
            print("error: verify needs a receipt path (or --batch for a whole "
                  "class)", file=sys.stderr)
            return 1
        try:
            rc = load_receipt(a.path)
        except (OSError, ValueError) as ex:
            print(f"error: {ex}", file=sys.stderr)
            return 1
        res = verify_receipt(rc, ledger_path=a.ledger, ots=a.ots)
        print(json.dumps(res, indent=1))
        return 0 if res["ok"] else 2

    if a.cmd == "roster-report":
        # Pages in runs of the published cap rather than refusing a class of
        # 25: every receipt is verified and the header prints the pass
        # structure, so the partial-answer failure the cap's refusal exists to
        # prevent cannot happen here. See roster_report.py's module docstring
        # for the argument and for what would change the answer.
        try:
            report = roster_report.build_report(a.target, ledger_path=a.ledger, ots=a.ots)
        except (verify_batch.CapExceeded, verify_batch.NoReceiptsFound,
                ValueError, OSError) as ex:
            print(f"error: {ex}", file=sys.stderr)
            return 1
        text = (roster_report.to_json(report) if a.as_json
                else roster_report.to_csv(report))
        if a.out:
            Path(a.out).write_text(text, encoding="utf-8")
            print(roster_report.summary_line(report))
            print(f"report written: {a.out}")
        else:
            sys.stdout.write(text)
        return roster_report.exit_code(report)

    if a.cmd == "archive":
        # Written at every verdict. Exit 2 says a FAIL is inside and 4 says
        # something could not be determined, but the archive exists in both
        # cases: an export that refused to build over a failing receipt would
        # hide the one document the coordinator is running this to find.
        try:
            manifest = archive.build_archive(a.target, a.out, ledger_path=a.ledger,
                                             ots=a.ots)
        except (verify_batch.CapExceeded, verify_batch.NoReceiptsFound,
                archive.ArchiveIntegrityError, ValueError, OSError) as ex:
            print(f"error: {ex}", file=sys.stderr)
            return 1
        print(archive.summary_line(manifest, a.out))
        print(f"archive written: {a.out}")
        return archive.exit_code(manifest)

    if a.cmd == "exhibit":
        try:
            print(_exhibit(load_receipt(a.path)))
        except (OSError, ValueError) as ex:
            print(f"error: {ex}", file=sys.stderr)
            return 1
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
