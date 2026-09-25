"""arcaeon-audit CLI: verify a log's integrity, or export a regulator-ready bundle.

  arcaeon-audit verify  <log.jsonl>
  arcaeon-audit pin     <log.jsonl> <witness.jsonl> <namespace>
  arcaeon-audit export  <log.jsonl> <out_dir/> [--system-id ID] [--provider NAME]
                        [--witness <witness.jsonl> --namespace <ns>]
                        [--instrument-notes <notes.md>]

`pin` records the log's current head with an external witness; `export --witness`
then cross-checks the bundle for TRUNCATION — the one failure a hash chain
provably cannot catch on its own. Without a witness, an export honestly reports
"truncation not checked", never a clean PASS.

`--instrument-notes` embeds an author-written statement of THIS check's known
false positives, known false negatives, and what it did not exercise (see the
README's "Instrument defects" section) verbatim into the bundle. Contents are
never validated — the point is that the slot exists and travels with the
artefact. Asked for and unreadable, the export ABORTS rather than shipping a
bundle whose missing disclosure looks like a clean one.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import verify_file, export_bundle, finding_of, __version__


class _InstrumentNotesError(Exception):
    """--instrument-notes was given and could not be honoured."""


def _read_instrument_notes(path: str) -> str:
    """Read the author's instrument-defects notes VERBATIM, or refuse to export.

    Two rules, both load-bearing:

    * **Verbatim.** Bytes in, strict UTF-8 decode, no newline translation
      (`read_text()` would silently fold CRLF to LF on Windows). Whatever the
      author wrote is what the bundle carries; this tool does not reflow,
      re-wrap, strip, or normalise someone else's disclosure of their own
      blind spots.
    * **Loud.** A notes file that is missing, unreadable, or not UTF-8 raises,
      and the export never runs. Emitting the bundle anyway would produce an
      artefact indistinguishable from one whose author was never asked --
      an absence laundered into a presence, which is the exact failure the
      whole convention exists to fight. Silence here would be the worst
      possible default because the caller ASKED for the disclosure.
    """
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise _InstrumentNotesError(
            f"--instrument-notes: cannot read {path!r}: "
            f"{exc.strerror or exc}") from exc
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _InstrumentNotesError(
            f"--instrument-notes: {path!r} is not valid UTF-8 ({exc}). "
            "Notes are embedded verbatim, so they must decode cleanly.") from exc


def main(argv: list[str] | None = None, prog: str = "arcaeon-audit") -> int:
    ap = argparse.ArgumentParser(prog=prog,
                                 description="Tamper-evident audit logs for AI agents. A mechanism, not a certification.")
    ap.add_argument("--version", action="version", version=f"arcaeon-audit {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="check a log's tamper-evidence")
    v.add_argument("log")

    p = sub.add_parser("pin", help="record the log's head with an external witness")
    p.add_argument("log")
    p.add_argument("witness", help="path to the witness store (JSONL)")
    p.add_argument("namespace", help="namespace to pin this log under")

    e = sub.add_parser("export", help="build a regulator-ready export bundle")
    e.add_argument("log")
    e.add_argument("out_dir")
    e.add_argument("--system-id", default="")
    e.add_argument("--provider", default="")
    e.add_argument("--witness", default=None,
                   help="path to a witness store; enables the truncation check")
    e.add_argument("--namespace", default=None,
                   help="namespace to check against the witness (with --witness)")
    e.add_argument("--instrument-notes", default=None, metavar="PATH",
                   help="path to a file naming this check's known false-positive "
                        "modes, false-negative modes, and what was NOT exercised; "
                        "embedded verbatim and unvalidated. Unreadable = the "
                        "export aborts.")

    a = ap.parse_args(argv)

    if a.cmd == "verify":
        r = verify_file(a.log)
        # `r.ok` is TRI-STATE and a bare truthiness test collapses it (external
        # audit, 2026-08-23). `if r.ok:` sent ok=None down the FAIL branch, so a
        # brand-new empty log — and any log adopted from unchained history —
        # was told "altered, truncated, or reordered" with a first_break of
        # None, exit 1, while `export` on the SAME file exited 0. Two
        # subcommands, two contradictory verdicts on one file. Match export's
        # contract: 0 = nothing wrong found, 1 = an accusation, 2 = the check
        # could not complete.
        if r.ok:
            print(f"VERIFIED — {r.rows} records, integrity intact (no tampering detected). "
                  "Note: chain verification cannot detect TRUNCATION; use `pin` + "
                  "`export --witness` to close that gap.")
            return 0
        if r.ok is None:
            scope = getattr(r, "verified_scope", "")
            if scope == "empty" and r.rows == 0:
                # COULD NOT LOOK, not a pass (qa-fixes 2026-09-24): the same
                # word `arcaeon verify` gives an empty file. Still no accusation.
                print("COULD NOT LOOK — EMPTY: no records have been written yet. "
                      "Nothing to verify and nothing to accuse.")
                return 2
            # Name the ACTUAL bound (audit 2026-08-28). ok=None has more than
            # one cause and 0.6.0 added `bounded_declared_break`, whose prechain
            # is 0 — so this printed "(0 carry no chain links)" beside an
            # unverified verdict: a count that contradicts the verdict, a cause
            # the reader does not have, and advice ("chain the log going
            # forward") for a condition they are not in. Exit 2 is unchanged.
            pre = getattr(r, "prechain", 0) or 0
            decl = getattr(r, "declared_breaks", 0) or 0
            bits = []
            if pre:
                bits.append(f"{pre} carry no chain links")
            if decl:
                bits.append(f"{decl} declared break(s) bound the scan")
            if not bits:
                bits.append("the scan was bounded")
            print(f"UNVERIFIED — {r.rows} record(s) present, but the chain could not "
                  f"speak for all of them ({'; '.join(bits)}; verified_scope="
                  f"{scope or 'bounded'!r}). This is not a pass and not an "
                  "accusation: chain the log going forward and pin it to a witness.")
            return 2
        print(f"FAIL — integrity broken at {r.first_break}. "
              f"The log was altered, truncated, or reordered since it was written.")
        return 1

    if a.cmd == "pin":
        from arcaeon.record.ledger import Ledger
        from arcaeon.record.ledger.witness import WitnessStore, publish_head
        rec = publish_head(WitnessStore(a.witness), a.namespace, Ledger(a.log))
        print(f"Pinned {a.namespace!r}: rows={rec['rows']} chain={rec['chain']} "
              f"-> {a.witness}")
        return 0

    if a.cmd == "export":
        # Read the notes BEFORE anything is written. Exit 2 ("the check could
        # not complete"), not 1 ("an accusation"): nothing is wrong with the
        # LOG, the operator asked for a disclosure this run cannot honour. And
        # not 0 under any circumstance -- a requested-but-absent instrument
        # block must never ship looking like an ordinary clean export.
        try:
            notes = (_read_instrument_notes(a.instrument_notes)
                     if a.instrument_notes is not None else None)
        except _InstrumentNotesError as exc:
            print(f"arcaeon-audit: {exc}", file=sys.stderr)
            print("arcaeon-audit: aborting; no bundle was written.", file=sys.stderr)
            return 2
        out = export_bundle(a.log, a.out_dir, system_id=a.system_id,
                            provider=a.provider, witness=a.witness,
                            witness_namespace=a.namespace,
                            instrument_notes=notes)
        integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
        files = "records.jsonl, integrity.json, manifest.json, ARTICLE_12_SUMMARY.md"
        if (out / "witness.json").exists():
            files += ", witness.json"
        if (out / "INSTRUMENT_NOTES.md").exists():
            files += ", INSTRUMENT_NOTES.md"
        print(f"Exported bundle to {out}/ ({files})")
        w = integ.get("witness") or {}
        print(f"Verdict: {integ['verdict']}  (finding: {finding_of(integ)})  "
              f"(chain_ok={integ['chain_ok']}, truncation_checked="
              f"{integ['truncation_checked']}, truncation_ok={integ['truncation_ok']})")
        print(f"Witness: {w.get('kind', 'unknown')}  "
              f"(independence={w.get('independence', 'unknown')})")
        # Exit code carries the verdict (external audit 2026-08-23: export always
        # returned 0, so CI/cron gating on it treated TRUNCATION_DETECTED as
        # success while `verify` exited 1 on FAIL — two subcommands answering the
        # same question differently). Contract mirrors verify's, three-valued:
        #   0 = nothing wrong found (PASS, VERIFIED_MODULO_TRUNCATION)
        #   1 = an accusatory verdict (FAIL / TRUNCATION_DETECTED / REWRITE_DETECTED)
        #   2 = the check itself could not complete or was not understood
        #       (WITNESS_CHECK_FAILED / UNRECOGNIZED_WITNESS_VERDICT /
        #        UNVERIFIED_SCOPE — rows exist that the chain could not verify;
        #        an unanswered question must never gate CI green)
        # Gate on the detailed finding (0.9.0 moved it from `verdict` to
        # `finding`); the codes below are unchanged since arcaeon-audit 0.1.8.
        v = finding_of(integ)
        if v in ("PASS", "VERIFIED_MODULO_TRUNCATION"):
            return 0
        # EMPTY_LOG falls through to 2 (front door: 3, COULD NOT LOOK): an
        # empty log verified nothing (qa-fixes 2026-09-24).
        if v in ("FAIL", "TRUNCATION_DETECTED", "REWRITE_DETECTED"):
            return 1
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
