"""arcaeon vet: check MCP-server source.

    python -m arcaeon.prove.vet scan   <file>            # print findings
    python -m arcaeon.prove.vet grade  <file>            # emit a re-testable grade (JSON)
    python -m arcaeon.prove.vet grade-target <path>      # grade a whole server (file OR dir)
    python -m arcaeon.prove.vet badge <path> [--receipt] [--sealed]  # free Markdown badge
                                                # + JSON report; --sealed is
                                                # PAID (ARCAEON_KEY, one credit)
    python -m arcaeon.prove.vet verify <grade.json> <file>   # confirm a grade reproduces
    python -m arcaeon.prove.vet serve                    # run as an MCP server over stdio
    python -m arcaeon.prove.vet audit-verify [ledger]    # check the server's own call record
    python -m arcaeon.prove.vet probe [opts] -- <cmd...> # LIVE, opt-in: launch a server
                                                # over stdio and test whether
                                                # its declared filter params
                                                # actually bind

The grade/verify pair is the point: anyone can re-run `verify` against the same
bytes and get the same answer, or the grade was lying. No network, no code
execution, no authority claim.

`probe` is the one verb that breaks that stance, on purpose and in its own
lane: it CALLS the server's read-only tools. It is never folded into scan /
grade / badge, and its artifact says "as observed at T", not "reproduces".
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import ts_checks
from .checks import scan_file, except_success_coverage
from .grade import grade_source, verify


def _no_checks_reason(findings) -> str:
    """Why nothing was graded, in one line an operator can act on."""
    for f in findings:
        d = f.get("detail", "") if isinstance(f, dict) else getattr(f, "detail", "")
        if "arcaeon[ts]" in d:
            return "a TypeScript file needs the [ts] extra: pip install 'arcaeon[ts]'"
    for f in findings:
        chk = f.get("check") if isinstance(f, dict) else getattr(f, "check", "")
        if chk == "parse":
            return "no file could be parsed, so zero checks ran"
    return "no .py, .ts or .js file to grade"


def main(argv=None, prog: str = "arcaeon vet") -> int:
    ap = argparse.ArgumentParser(prog=prog, description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan"); s.add_argument("file")
    g = sub.add_parser("grade"); g.add_argument("file")
    gt = sub.add_parser("grade-target",
                        help="grade a whole MCP server (a file OR a directory) "
                             "as one deterministic result"); gt.add_argument("path")
    bd = sub.add_parser("badge",
                        help="free Markdown badge + JSON report: verdict, "
                             "checks run, fixture-census of the grader's own "
                             "tests, and the origin note")
    bd.add_argument("path")
    bd.add_argument("--receipt", action="store_true",
                    help="sign the report (mcp_vet.receipts); prints UNSIGNED "
                         "and why, never silently, if no key/backend")
    bd.add_argument("--sealed", action="store_true",
                    help="PAID (needs ARCAEON_KEY, nothing else): witness the "
                         "badge through the arcaeon connector's existing "
                         "credit lane, one credit per scan. The witness's pin "
                         "is the seal; the badge is also signed (implies "
                         "--receipt) when a signing key is present, and is "
                         "recorded UNSIGNED otherwise. Refuses with a plain "
                         "message, never a crash, if ARCAEON_KEY is unset or "
                         "the balance is zero; the free badge is never affected")
    bd.add_argument("--ns", "--namespace", dest="ns", default=None,
                    help="with --sealed: the witness namespace to pin under; "
                         "it must start with your key's prefix (default: "
                         "mcp-vet-sealed-scans, and if the witness refuses it "
                         "and names your prefix, <prefix>-sealed-scans)")
    v = sub.add_parser("verify"); v.add_argument("grade"); v.add_argument("file")
    sub.add_parser("serve", help="expose scan/grade as an MCP server over stdio "
                                 "(needs the [mcp] extra)")
    av = sub.add_parser("audit-verify",
                        help="recompute the hash chain over the MCP server's own "
                             "call record and name the first break")
    av.add_argument("ledger", nargs="?", default=None,
                    help="ledger path (default: $MCP_VET_AUDIT_LEDGER, else "
                         "~/.mcp_vet/audit.jsonl)")
    pr = sub.add_parser("probe",
                        help="LIVE, opt-in (needs the [mcp] extra): launch the "
                             "server command over stdio, list its tools, and "
                             "call each readOnlyHint=true tool with an "
                             "impossible filter value and an unknown key to "
                             "see whether declared parameters bind. Never "
                             "part of scan/grade/badge")
    pr.add_argument("--cwd", default=None, help="working directory for the server")
    pr.add_argument("--max-calls", type=int, default=None,
                    help="global cap on tool calls (default 40); the artifact "
                         "says when it was hit")
    pr.add_argument("--timeout", type=float, default=None,
                    help="per-call timeout in seconds (default 20)")
    pr.add_argument("--json", action="store_true",
                    help="print the JSON artifact instead of the summary")
    pr.add_argument("command", nargs=argparse.REMAINDER,
                    help="the server command, after `--`")
    args = ap.parse_args(argv)

    if args.cmd == "scan":
        path = Path(args.file)
        if not path.is_file():
            print("scan target does not exist or is not a file: %s" % path, file=sys.stderr)
            return 2
        fs = scan_file(path)
        for f in fs:
            print(f"[{f.severity}] {f.check} @ {f.file}:{f.line} — {f.detail}")
        print(f"{len(fs)} finding(s)")
        # Coverage counts line (2026-09-04). `except-returns-success` only asks
        # its question of tool-REACHABLE bodies, so "0 findings" from it means
        # one of two very different things: nothing to find, or nothing looked
        # at. The summary says which. No new output channel: it is one more line
        # on the summary the command already prints.
        #
        # BOTH front ends print it as of the reachability fix, same day. It was
        # Python-only, and the one repo that most needed it was TypeScript:
        # supabase-mcp walked 29 bodies and reached ZERO catch clauses, and the
        # tool had no way to say so on a .ts file.
        src = path.read_text(encoding="utf-8", errors="replace")
        if ts_checks.is_ts_path(path.name):
            c = ts_checks.ts_except_success_coverage(src, str(path))
            print("except-returns-success coverage: %d handler root(s), "
                  "%d reachable body/bodies, %d catch clause(s) examined, "
                  "%d file(s) could not be parsed, "
                  "%d site(s) via %d handler(s)"
                  % (c["handler_roots"], c["bodies_examined"],
                     c["catch_clauses_examined"], c["files_unparsed"],
                     c["sites_reported"], c["handlers_reaching"]))
        elif path.suffix == ".py":
            c = except_success_coverage(src, str(path))
            print("except-returns-success coverage: %d tool handler(s), "
                  "%d reachable body/bodies, %d except handler(s) examined, "
                  "%d file(s) could not be parsed, "
                  "%d call(s) on unresolved instances, "
                  "%d site(s) via %d handler(s), "
                  "%d possibly-dead KeyError clause(s)"
                  % (c["tool_handlers"], c["bodies_examined"],
                     c["except_handlers_examined"], c["files_unparsed"],
                     c["unresolved_instance_calls"],
                     c["sites_reported"], c["handlers_reaching"],
                     c["dead_keyerror_candidates"]))
        if any(f.severity == "high" for f in fs):
            return 1
        # A parse failure (or a .ts file without the [ts] extra) means nothing
        # was checked: NO GRADEABLE FILES, exit 3, never a green.
        if any(f.check == "parse" for f in fs):
            print("NO GRADEABLE FILES: " + next(f.detail for f in fs if f.check == "parse"),
                  file=sys.stderr)
            return 3
        return 0

    if args.cmd == "grade":
        try:
            raw = Path(args.file).read_bytes()
        except OSError as exc:
            print("grade target could not be read: %s" % exc, file=sys.stderr)
            return 2
        # Bytes, not read_text: keeps CRLF, so source_sha256 is the file's own
        # sha256 (the same number grade-target and sha256sum give).
        g = grade_source(raw.decode("utf-8", errors="replace"), args.file)
        print(g.to_json())
        if not g.checks_run:
            print("NO GRADEABLE FILES: " + _no_checks_reason(g.findings), file=sys.stderr)
            return 3
        return 0

    if args.cmd == "grade-target":
        from .service import scan_target, NO_GRADEABLE_FILES
        try:
            g = scan_target(args.path)
        except FileNotFoundError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(g.to_json())
        if g.verdict == NO_GRADEABLE_FILES:
            print("NO GRADEABLE FILES: " + _no_checks_reason(g.findings), file=sys.stderr)
            return 3
        # exit non-zero on a high-severity server so CI/callers can gate on it
        return 1 if g.verdict == "high-severity findings" else 0

    if args.cmd == "badge":
        from .badge_cli import build_badge, render_badge_text
        from .service import NO_GRADEABLE_FILES
        try:
            built = build_badge(args.path, receipt=args.receipt or args.sealed)
        except FileNotFoundError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        sealed_ok = None
        if args.sealed:
            from .badge_cli import seal_badge
            seal_result = seal_badge(built["json"], namespace=args.ns)
            built["json"]["sealed_scan"] = seal_result
            sealed_ok = bool(seal_result.get("sealed"))
            if not sealed_ok:
                print(seal_result.get("reason", "sealed scan refused"),
                     file=sys.stderr)
        print(render_badge_text(built))
        # exit non-zero on a high-severity server, same contract as
        # grade-target; NO_GRADEABLE_FILES is neither a pass nor a fail --
        # a repo with nothing to grade should not break a CI gate, but it
        # should not silently exit 0 as if it were graded clean either, so
        # it gets its own third exit code rather than sharing 0 with a real
        # clean pass. A refused --sealed (no key, no connector, zero balance)
        # is its own fourth code: the free badge above still printed fine, so
        # it must not share exit 2 (file trouble) or read as a scan failure.
        if built["json"]["verdict"] == "high-severity findings":
            return 1
        if built["json"]["verdict"] == NO_GRADEABLE_FILES:
            return 3
        if sealed_ok is False:
            return 4
        return 0

    if args.cmd == "verify":
        try:
            prior = json.loads(Path(args.grade).read_text(encoding="utf-8"))
            src = Path(args.file).read_bytes().decode("utf-8", errors="replace")
        except (OSError, ValueError) as exc:
            print("verify could not read its inputs: %s" % exc, file=sys.stderr)
            return 2
        r = verify(prior, src)
        print(json.dumps(r, indent=2, ensure_ascii=False))
        return 0 if r["reproduced"] else 2

    if args.cmd == "audit-verify":
        # The verifier is deliberately reachable WITHOUT an MCP client. An audit
        # trail only anybody-with-our-server can check is a claim; a plain
        # command anyone can run against the file is evidence. Exit 2 on a
        # broken chain, 3 when the verification was BOUNDED (ok is None) —
        # never 0, because "no break found within scope" is not "verified".
        from .server import verify_audit_ledger
        r = verify_audit_ledger(args.ledger)
        print(json.dumps(r, indent=2, ensure_ascii=False))
        return 0 if r["ok"] is True else (2 if r["ok"] is False else 3)

    if args.cmd == "serve":
        # Imported lazily: the MCP SDK is an optional extra, and `scan`/`grade`
        # must keep working in an install that never took it.
        from .server import serve
        serve()
        return 0

    if args.cmd == "probe":
        from .probe import (DEFAULT_MAX_CALLS, DEFAULT_TIMEOUT, render_probe_text,
                            run_probe)
        command = list(args.command)
        if command and command[0] == "--":     # REMAINDER keeps the separator
            command = command[1:]
        if not command:
            print("probe needs a server command after `--`, e.g. "
                  "arcaeon vet probe -- python my_server.py", file=sys.stderr)
            return 2
        try:
            art = run_probe(command, cwd=args.cwd,
                            max_calls=args.max_calls or DEFAULT_MAX_CALLS,
                            timeout=args.timeout or DEFAULT_TIMEOUT)
        except ImportError:
            print("arcaeon vet probe needs the MCP Python SDK (the [mcp] extra): "
                  "pip install 'arcaeon[mcp]'", file=sys.stderr)
            return 2
        if args.json:
            print(json.dumps(art, indent=2, ensure_ascii=False))
        else:
            print(render_probe_text(art))
        # Exit contract, same family as scan/grade-target: 1 on a high
        # finding, 2 when the server could not be reached (nothing was
        # tested, so neither a pass nor a fail), else 0. Blind spots and a
        # hit cap are stated in the artifact, not turned into an exit code:
        # a probe that could only test half the tools still tested half.
        if not art["connected"]:
            return 2
        return 1 if any(f["severity"] == "high" for f in art["findings"]) else 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
