# SPDX-License-Identifier: MIT
"""`arcaeon`: one command, one verb list.

Every verb dispatches to the moved code of the tool it replaces; nothing here
reimplements a check. Exit codes are arcaeon.verdict's one table (0 good,
1 bad finding, 2 bad usage, 3 COULD NOT LOOK); `--legacy-exit` on a verb
returns the old tool's own code for the 0.9.x release.

NETWORK: `pin --remote`, `seal`, `stamp` and `credits` reach the hosted
witness, through arcaeon.remote. Two more go online on request: `receipt cite`
looks each citation up with CourtListener's API (unless --fixture), and
`proxy --pin-witness URL` pins the tape head at that witness at session end.
Every other verb works offline.

THE 30-DAY FALLBACK. Before 0.9, `uvx arcaeon` (what an MCP registry client
runs) started the MCP server, because the connector owned this name. Until the
registry entry says `packageArguments: ["mcp"]`, `arcaeon` with no verb and a
stdin that is not a terminal still starts the server (a notice goes to stderr,
never stdout, which is the protocol channel). With a terminal it prints help.
The fallback is removed in 1.0.0.
"""
from __future__ import annotations

import hashlib
import json
import sys
from functools import partial
from pathlib import Path

from arcaeon import __version__
from arcaeon import verdict as V

# verb -> (family, one-line summary). Order is the order `--help` prints.
VERBS = {
    "log":       ("record", "append one JSON row to a ledger"),
    "verify":    ("record", "check a ledger's chain: VERIFIED / BROKEN / COULD NOT LOOK"),
    "receipt":   ("record", "issue or verify a portable receipt (cite, ballot, verify, ...)"),
    "once":      ("record", "executed-once receipts for side effects (receipt, reclaim, ...)"),
    "proxy":     ("record", "wrap an MCP server and record every call at the seam"),
    "pin":       ("record", "record a ledger head with a witness (local file, or --remote)"),
    "deal":      ("record", "a witnessed transaction: mandate, commit, pay, ship, deliver, cancel, dispute, pack"),
    "reconcile": ("prove",  "two tapes and a counter: MATCHED / MISSING / ALTERED / COULD NOT LOOK"),
    "audit":     ("prove",  "verify a log or export a regulator-ready bundle"),
    "vet":       ("prove",  "check MCP-server source (scan, grade, grade-target, verify, probe)"),
    "badge":     ("prove",  "free Markdown badge + JSON report for an MCP server"),
    "seal":      ("prove",  "PAID: a badge sealed by the hosted witness (needs ARCAEON_KEY)"),
    "baseline":  ("prove",  "register and compare pre-registered probe sets"),
    "compact":   ("prove",  "verify a compaction receipt"),
    "distill":   ("save",   "cut a tool output down to a token budget, with a drop receipt"),
    "dedup":     ("save",   "drop near-verbatim repeats from a list of texts"),
    "meter":     ("save",   "keyed usage metering: keys, usage, export"),
    "stamp":     ("remote", "stamp a file's sha256 with the hosted witness"),
    "credits":   ("remote", "show your witness balance (needs ARCAEON_KEY)"),
    "buy":       ("remote", "print the checkout link for a plan (opens nothing)"),
    "mcp":       ("serve",  "start the MCP connector server on stdio (needs arcaeon[mcp])"),
    "selftest":  ("check",  "run every bundled selftest"),
    "version":   ("check",  "print arcaeon's version and each family's"),
}

FAMILY_TITLES = {"record": "Record", "prove": "Prove", "save": "Save", "remote": "Hosted",
                 "serve": "Serve", "check": "This install"}


def help_text() -> str:
    lines = [f"arcaeon {__version__}: a record of what an agent did that the agent cannot",
             "quietly rewrite, and a way for anyone who doubts it to check.", "",
             "usage: arcaeon <verb> [args...]      arcaeon <verb> --help", ""]
    for fam, title in FAMILY_TITLES.items():
        lines.append(f"{title}:")
        for verb, (f, summary) in VERBS.items():
            if f == fam:
                lines.append(f"  {verb:<10} {summary}")
        lines.append("")
    lines += ["Exit codes, every verb: 0 good, 1 a bad finding, 2 bad usage, 3 COULD NOT LOOK.",
              "--legacy-exit returns the old tool's own code (0.9.x only)."]
    return "\n".join(lines)


def _stdin_is_terminal() -> bool:
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except (AttributeError, ValueError, OSError):
        return False


def _utf8_console() -> None:
    """Windows consoles and pipes default to cp1252: an em dash in a verdict
    line came out as mojibake when piped (qa-fixes item 7). Reconfigure both
    streams to UTF-8, replacing anything unencodable rather than crashing."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass            # a replaced stream (pytest capture, StringIO) keeps its own


def main(argv: list[str] | None = None) -> int:
    _utf8_console()
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        if _stdin_is_terminal():
            print(help_text())
            return V.EXIT_GOOD
        print("arcaeon: no verb and stdin is not a terminal, so starting the MCP server "
              "(the pre-0.9 behaviour). Use `arcaeon mcp`; this fallback is removed in 1.0.0.",
              file=sys.stderr)
        return _mcp([])
    verb, rest = argv[0], argv[1:]
    if verb in ("-h", "--help", "help"):
        print(help_text())
        return V.EXIT_GOOD
    if verb in ("-V", "--version"):
        return _version([])
    handler = HANDLERS.get(verb)
    if handler is None:
        print(f"arcaeon: unknown verb {verb!r}\n", file=sys.stderr)
        print(help_text(), file=sys.stderr)
        return V.EXIT_USAGE
    try:
        return handler(rest)
    except KeyboardInterrupt:
        raise
    except Exception as e:  # noqa: BLE001  the one front-door catch
        # Never a traceback, never a green: a verb that fell over mid-check
        # could not look. One line on stderr names the exception class only
        # (a message can carry a path or a value; the class cannot).
        print(f"arcaeon {verb}: could not finish: {type(e).__name__} [internal_error]",
              file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK


# --- dispatch helpers --------------------------------------------------------

def _run(fn, argv) -> int:
    """Call a moved tool's main(argv). An argparse usage error or --help
    surfaces as SystemExit; its code is returned, never translated."""
    try:
        rc = fn(argv)
    except SystemExit as e:
        code = e.code
        if code is None:
            return 0
        if isinstance(code, int):
            return code
        print(code, file=sys.stderr)
        return V.EXIT_USAGE
    return 0 if rc is None else rc


def _translated(verb: str, fn, argv, subcommand=None) -> int:
    argv, legacy = V.pop_legacy_flag(argv)
    try:
        rc = fn(argv)
    except SystemExit as e:          # usage/--help: never translated
        return e.code if isinstance(e.code, int) else (0 if e.code is None else V.EXIT_USAGE)
    rc = 0 if rc is None else rc
    return V.unify(verb, rc, subcommand, legacy=legacy)


def _usage(msg: str) -> int:
    print(f"arcaeon: {msg}", file=sys.stderr)
    return V.EXIT_USAGE


def _wants_help(argv) -> bool:
    return any(a in ("-h", "--help") for a in argv)


# --- record --------------------------------------------------------------------

def _log(argv) -> int:
    if _wants_help(argv) or len(argv) != 2:
        print("usage: arcaeon log <ledger.jsonl> '<json object>'")
        return V.EXIT_GOOD if _wants_help(argv) else V.EXIT_USAGE
    p = Path(argv[0])
    if p.is_dir():
        return _usage(f"log: cannot append to {argv[0]}: it is a directory, not a ledger file")
    problem = _last_row_problem(p)
    if problem:
        print(f"{V.COULD_NOT_LOOK}: refusing to append to {argv[0]}: {problem}; "
              f"nothing was written", file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK
    from arcaeon.record.ledger import cli
    try:
        return _run(cli.main, ["append", argv[0], argv[1]])
    except OSError as e:
        return _usage(f"log: cannot write {argv[0]}: {e.strerror or type(e).__name__}")


def _last_row_problem(p: Path) -> str | None:
    """Why the ledger's last line cannot be chained from, or None if it can
    (or the file is absent/empty: a fresh ledger starts at genesis). The
    library's own tail read walks PAST a corrupt last line on purpose (torn
    write recovery); the `log` verb refuses instead, so a binary file, a
    duplicate-key row or a nesting bomb is never quietly chained over."""
    if not p.exists():
        return None
    from arcaeon.prove.reconcile import MAX_DEPTH, _depth_before_stop
    from arcaeon.record.row import loads_strict
    try:
        data = p.read_bytes()
    except OSError as e:
        return f"cannot read it ({e.strerror or type(e).__name__})"
    lines = [ln for ln in data.split(b"\n") if ln.strip()]
    if not lines:
        return None
    last = lines[-1].strip()
    try:
        text = last.decode("utf-8")
    except UnicodeDecodeError:
        return "its last line is not UTF-8 text (a binary file?)"
    if text.count("[") + text.count("{") > MAX_DEPTH and _depth_before_stop(text) > MAX_DEPTH:
        return f"its last line is nested deeper than {MAX_DEPTH} levels [nesting_too_deep]"
    try:
        row = loads_strict(text)
    except ValueError as e:
        return f"its last line does not parse as one JSON row ({e})"
    if not isinstance(row, dict) or not isinstance(row.get("chain"), str):
        return "its last line is not a chained ledger row"
    return None


def _verify(argv) -> int:
    argv, _legacy = V.pop_legacy_flag(argv)       # verify already used 3; nothing to keep
    if _wants_help(argv) or len([a for a in argv if a != "--strict"]) != 1:
        print("usage: arcaeon verify <ledger.jsonl> [--strict]\n"
              "exit 0 VERIFIED, 1 BROKEN, 3 COULD NOT LOOK (rows the chain could not speak for)")
        return V.EXIT_GOOD if _wants_help(argv) else V.EXIT_USAGE
    # The ledger's own report, with the verdict word added as the first key
    # (the ledger CLI prints the same fields without it). The word comes from
    # the same three-valued `ok` the old exit code came from, so the two
    # cannot disagree: True VERIFIED 0, None COULD NOT LOOK 3, False BROKEN 1.
    from arcaeon.record.ledger import verify_file
    strict = "--strict" in argv
    path = next((a for a in argv if a != "--strict"), None)
    if path is None or any(a.startswith("-") and a != "--strict" for a in argv):
        print("usage: arcaeon verify <ledger.jsonl> [--strict]", file=sys.stderr)
        return V.EXIT_USAGE
    r = verify_file(path, strict=strict)
    word = V.VERIFIED if r.ok is True else (V.COULD_NOT_LOOK if r.ok is None else V.BROKEN)
    print(json.dumps({"verdict": word, **r.__dict__}, indent=1))
    return V.exit_for(word)


def _receipt(argv) -> int:
    from arcaeon.record.receipt import cli
    sub = next((a for a in argv if not a.startswith("-")), None)
    return _translated("receipt", partial(cli.main, prog="arcaeon receipt"), argv, sub)


def _once(argv) -> int:
    from arcaeon.record.once import cli
    if argv in (["-h"], ["--help"]):       # the old CLI answered --help with exit 1
        print("usage: arcaeon once receipt|reclaim|rebuild-index <ledger> [key]\n")
        print((cli.__doc__ or "").strip())
        return V.EXIT_GOOD
    if argv[:1] == ["rebuild-index"] and len(argv) >= 2 and not Path(argv[1]).is_file():
        # Checked BEFORE the index opens: rebuild_index() creates the sidecar
        # .idx.sqlite3 and its lock file, which must never appear beside a
        # ledger that is not there (qa-fixes item 5).
        why = "is a directory" if Path(argv[1]).is_dir() else "does not exist"
        return _usage(f"once rebuild-index: cannot index {argv[1]}: the ledger {why}; nothing was created")
    if argv[:1] == ["rebuild-index"] and len(argv) >= 2:
        # A binary file or a nesting bomb used to index as {"keys_indexed": 0},
        # exit 0: a look that could not happen reported as an empty result.
        # Checked before the index opens, so nothing is created (seal-for-strangers).
        problem = _unindexable_ledger_problem(Path(argv[1]))
        if problem:
            print(f"{V.COULD_NOT_LOOK}: once rebuild-index: cannot index {argv[1]}: "
                  f"{problem}; nothing was created", file=sys.stderr)
            return V.EXIT_COULD_NOT_LOOK
    return _run(cli.main, argv)


def _unindexable_ledger_problem(p: Path) -> str | None:
    """Why no line of this ledger can be read for indexing, or None. Every
    non-blank line must be UTF-8 text nested no deeper than MAX_DEPTH; a
    line that is text but not JSON is left to the library (torn-write rule)."""
    from arcaeon.prove.reconcile import MAX_DEPTH, _depth_before_stop
    try:
        data = p.read_bytes()
    except OSError as e:
        return f"cannot read it ({e.strerror or type(e).__name__})"
    for i, raw in enumerate(data.split(b"\n"), 1):
        if not raw.strip():
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return f"line {i} is not UTF-8 text (a binary file?)"
        if text.count("[") + text.count("{") > MAX_DEPTH and _depth_before_stop(text) > MAX_DEPTH:
            return f"line {i} is nested deeper than {MAX_DEPTH} levels [nesting_too_deep]"
    return None


def _proxy(argv) -> int:
    from arcaeon.record.adapter import proxy
    return _run(partial(proxy.main, prog="arcaeon proxy"), argv)


def _pin(argv) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="arcaeon pin", description=(
        "Record a ledger's current head with a witness. Local: --witness FILE "
        "(an append-only pin file you keep somewhere the log's writer cannot "
        "reach). Hosted: --remote (POST to the hosted witness; needs ARCAEON_KEY)."))
    ap.add_argument("ledger")
    ap.add_argument("--ns", "--namespace", dest="ns", required=True)
    where = ap.add_mutually_exclusive_group(required=True)
    where.add_argument("--witness", help="local witness pin file (JSONL)")
    where.add_argument("--remote", action="store_true", help="the hosted witness")
    ap.add_argument("--renew", action="store_true",
                    help="with --remote: restate an unchanged head instead of pinning")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else V.EXIT_USAGE
    from arcaeon.record.ledger import Ledger, verify_file
    # A ledger `verify` rates COULD NOT LOOK is not pinned green (qa-fixes item
    # 3). Absent or empty stays pinnable as genesis, the library's own rule.
    lp = Path(a.ledger)
    if lp.is_file():
        vr = verify_file(lp)
        if vr.ok is None and vr.verified_scope != "empty":
            print(json.dumps({"ok": False, "verdict": V.COULD_NOT_LOOK,
                              "error": f"refusing to pin a ledger verify cannot vouch for "
                                       f"({vr.verified_scope}; {vr.prechain} unchained "
                                       f"row(s)); run `arcaeon verify` for the detail"},
                             indent=1))
            return V.EXIT_COULD_NOT_LOOK
    if a.witness:
        from arcaeon.record.ledger.witness import WitnessStore, publish_head
        problem = _witness_file_problem(Path(a.witness))
        if problem:
            print(json.dumps({"ok": False, "verdict": V.COULD_NOT_LOOK,
                              "error": f"refusing to write to {a.witness}: {problem}; "
                                       f"nothing was written"}, indent=1))
            return V.EXIT_COULD_NOT_LOOK
        try:
            rec = publish_head(WitnessStore(a.witness), a.ns, Ledger(a.ledger))
        except (ValueError, OSError) as e:
            print(json.dumps({"ok": False, "error": str(e)}, indent=1))
            return V.EXIT_BAD
        print(json.dumps({"ok": True, "pin": rec}, indent=1))
        return V.EXIT_GOOD
    from arcaeon import remote
    head = Ledger(a.ledger).head()
    if head.ok is False:
        print(json.dumps({"ok": False, "error": f"refusing to pin a ledger that does not "
                          f"verify: {head.first_break}"}, indent=1))
        return V.EXIT_BAD
    fn = remote.renew if a.renew else remote.pin
    out = fn(a.ns, head.rows, head.chain, remote.key() or "")
    print(json.dumps(out, indent=1))
    return V.EXIT_GOOD if out.get("ok") else V.EXIT_BAD


def _witness_file_problem(p: Path) -> str | None:
    """Why `p` is not a witness pin file we may append to, or None. Absent or
    empty is fine (a new store). Anything else must be UTF-8 JSONL whose every
    row is a pin ({namespace, rows, chain}) and whose pin chain does not break:
    a binary file, a ledger, a nesting bomb or a broken store is refused
    before a byte is written (qa-fixes item 3)."""
    if not p.exists():
        return None
    if not p.is_file():
        return "it is not a regular file"
    from arcaeon.prove.reconcile import MAX_DEPTH, _depth_before_stop
    from arcaeon.record.row import loads_strict
    try:
        text = p.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        return "it is not UTF-8 text (a binary file?)"
    except OSError as e:
        return f"cannot read it ({e.strerror or type(e).__name__})"
    for i, raw in enumerate(text.split("\n"), 1):
        raw = raw.strip()
        if not raw:
            continue
        if raw.count("[") + raw.count("{") > MAX_DEPTH and _depth_before_stop(raw) > MAX_DEPTH:
            return f"line {i} is nested deeper than {MAX_DEPTH} levels [nesting_too_deep]"
        try:
            row = loads_strict(raw)
        except ValueError as e:
            return f"line {i} does not parse ({e})"
        if not (isinstance(row, dict) and {"namespace", "rows", "chain"} <= set(row)):
            return f"line {i} is not a witness pin (a pin carries namespace, rows, chain)"
    from arcaeon.record.ledger.witness import WitnessStore
    wv = WitnessStore(p).verify()
    if wv.get("ok") is False:
        return f"its pin chain does not verify ({wv.get('first_break')})"
    return None


def _deal(argv) -> int:
    from arcaeon.record import deal
    return _run(deal.main, argv)


# --- prove ---------------------------------------------------------------------

def _reconcile(argv) -> int:
    from arcaeon.prove import reconcile
    if _wants_help(argv):
        print("usage: arcaeon reconcile <tape_a> <tape_b> [--pin PIN] [--legacy-exit]\n"
              "exit 0 MATCHED, 1 MISSING or ALTERED, 3 COULD NOT LOOK "
              "(2 under --legacy-exit, 0.9.x only)")
        return V.EXIT_GOOD
    return _run(reconcile.main, argv)


def _audit(argv) -> int:
    from arcaeon.prove.audit import cli
    sub = next((a for a in argv if not a.startswith("-")), None)
    return _translated("audit", partial(cli.main, prog="arcaeon audit"), argv, sub)


_VET_SUBCOMMANDS = {"scan", "grade", "grade-target", "badge", "verify", "serve",
                    "audit-verify", "probe"}


def _vet(argv) -> int:
    from arcaeon.prove.vet import __main__ as vet_main
    argv, legacy = V.pop_legacy_flag(argv)
    if argv and argv[0] not in _VET_SUBCOMMANDS and not argv[0].startswith("-"):
        argv = ["grade-target", *argv]          # `arcaeon vet ./server` grades the target
    sub = argv[0] if argv else None
    if legacy:
        argv = [*argv, V.LEGACY_EXIT_FLAG]
    return _translated("vet", vet_main.main, argv, sub)


def _badge(argv) -> int:
    from arcaeon.prove.vet import __main__ as vet_main
    # prog "arcaeon" makes the badge subparser's usage read `arcaeon badge`
    return _translated("badge", partial(vet_main.main, prog="arcaeon"), ["badge", *argv], "badge")


def _seal(argv) -> int:
    rest = list(argv)
    ns = None
    for flag in ("--ns", "--namespace"):
        if flag in rest:
            i = rest.index(flag)
            if i + 1 >= len(rest):
                return _usage(f"seal: {flag} needs a value")
            ns = rest[i + 1]
            del rest[i:i + 2]
    if _wants_help(argv) or len([a for a in rest if not a.startswith("-")]) != 1:
        print("usage: arcaeon seal <path-to-mcp-server> [--ns NAMESPACE]\n"
              "PAID: grades the server, then seals the report with the hosted witness "
              "(one credit). Needs ARCAEON_KEY and nothing else: the witness's pin is "
              "the seal. With the [sign] extra and MCP_VET_RECEIPT_KEY the report is "
              "also signed (SIGNED); without them it is sealed UNSIGNED. --ns picks the "
              "namespace, which must start with your key's prefix. Without --ns it tries "
              "mcp-vet-sealed-scans, and if the witness refuses that and names your "
              "key's prefix, retries once under <prefix>-sealed-scans (the refusal "
              "costs no credit). Without a key nothing is sent.")
        return V.EXIT_GOOD if _wants_help(argv) else V.EXIT_USAGE
    return _badge([*rest, "--sealed", *(["--ns", ns] if ns else [])])


def _baseline(argv) -> int:
    from arcaeon.prove.baseline import cli
    return _run(partial(cli.main, prog="arcaeon baseline"), argv)


def _compact(argv) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="arcaeon compact", description=(
        "Verify a compaction receipt row (arcaeon.prove.compact). Self-consistency "
        "always; give --pre/--post (JSON lists) to recompute the digests from content."))
    ap.add_argument("receipt", help="the receipt row, as a JSON file")
    ap.add_argument("--pre", help="JSON list: the content before compaction")
    ap.add_argument("--post", help="JSON list: the content after compaction")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else V.EXIT_USAGE
    from arcaeon.prove.compact import verify_receipt
    try:
        row = json.loads(Path(a.receipt).read_text(encoding="utf-8"))
        pre = json.loads(Path(a.pre).read_text(encoding="utf-8")) if a.pre else None
        post = json.loads(Path(a.post).read_text(encoding="utf-8")) if a.post else None
    except (OSError, ValueError) as e:
        print(json.dumps({"verdict": V.COULD_NOT_LOOK, "reason": str(e)}, indent=1))
        return V.EXIT_COULD_NOT_LOOK
    out = verify_receipt(row, pre, post)
    word = V.VERIFIED if out.get("ok") is True else (V.BROKEN if out.get("ok") is False
                                                      else V.COULD_NOT_LOOK)
    print(json.dumps({"verdict": word, **out}, indent=1, default=str))
    return V.exit_for(word)


# --- save ----------------------------------------------------------------------

class _Unreadable(Exception):
    """The input file could not be read as UTF-8 text; the message is the one line."""


def _read_input(path: str, verb: str = "arcaeon") -> str:
    """The input as text, or _Unreadable with one line naming the file."""
    if path == "-":
        return sys.stdin.read()
    p = Path(path)
    try:
        return p.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        raise _Unreadable(f"arcaeon {verb}: cannot read {path}: not UTF-8 text "
                          f"(a binary file?)") from None
    except IsADirectoryError:
        raise _Unreadable(f"arcaeon {verb}: cannot read {path}: it is a directory") from None
    except OSError as e:
        why = "it is a directory" if p.is_dir() else (e.strerror or type(e).__name__)
        raise _Unreadable(f"arcaeon {verb}: cannot read {path}: {why}") from None


def _distill(argv) -> int:
    from arcaeon.save.distill import mcp_server
    if argv[:1] == ["serve"]:
        return _run(mcp_server.main, argv[1:])
    if argv[:1] == ["--verify-calls"]:
        return _run(mcp_server.main, argv)
    import argparse
    ap = argparse.ArgumentParser(prog="arcaeon distill", description=(
        "Deterministically cut a tool output to a token budget. `arcaeon distill "
        "serve` runs the distill MCP server; `--verify-calls [path]` checks its call record."))
    ap.add_argument("input", help="file with the tool output (JSON or text), or - for stdin")
    ap.add_argument("--budget", type=int, default=2000)
    ap.add_argument("--query", default=None)
    ap.add_argument("--schema-hint", choices=("json", "tabular", "text"), default=None)
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else V.EXIT_USAGE
    from arcaeon.save.distill import distill
    try:
        raw = _read_input(a.input, "distill")
    except _Unreadable as e:
        print(str(e), file=sys.stderr)
        return V.EXIT_USAGE
    try:
        value = json.loads(raw)
    except (ValueError, RecursionError):
        value = raw
    try:
        r = distill(value, budget=a.budget, query=a.query, schema_hint=a.schema_hint)
    except (ValueError, RecursionError) as e:
        # e.g. input nested deeper than this process can walk: nothing was cut,
        # and nothing may read as a clean distill (qa-fixes item 1).
        print(json.dumps({"verdict": V.COULD_NOT_LOOK, "reason": str(e)}, indent=1))
        return V.EXIT_COULD_NOT_LOOK
    print(json.dumps({"content": r.content, "strategy": r.strategy,
                      "est_tokens_before": r.est_tokens_before,
                      "est_tokens_after": r.est_tokens_after, "truncated": r.truncated,
                      "receipt": r.receipt.to_dict() if r.receipt else None},
                     indent=1, ensure_ascii=False))
    return V.EXIT_GOOD


def _dedup(argv) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="arcaeon dedup", description=(
        "Drop near-verbatim repeats. Input: a JSON list of strings, or one item per line."))
    ap.add_argument("input", help="file, or - for stdin")
    ap.add_argument("--max-hamming", type=int, default=12)
    ap.add_argument("--min-overlap", type=float, default=0.95)
    ap.add_argument("--keep", choices=("first", "last"), default="first")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else V.EXIT_USAGE
    from arcaeon.save.dedup import dedupe
    try:
        raw = _read_input(a.input, "dedup")
    except _Unreadable as e:
        print(str(e), file=sys.stderr)
        return V.EXIT_USAGE
    try:
        items = json.loads(raw)
        if not (isinstance(items, list) and all(isinstance(x, str) for x in items)):
            raise ValueError
    except (ValueError, RecursionError):
        items = [line for line in raw.splitlines() if line.strip()]
    kept, report = dedupe(items, max_hamming=a.max_hamming, min_overlap=a.min_overlap,
                          keep=a.keep)
    print(json.dumps({"kept": kept, "report": {
        "kept": report.kept, "removed": report.removed, "chars_saved": report.chars_saved,
        "est_tokens_saved": report.est_tokens_saved,
        "removed_indices": report.removed_indices}}, indent=1, ensure_ascii=False))
    return V.EXIT_GOOD


def _meter(argv) -> int:
    from arcaeon.save.meter import cli
    return _run(partial(cli.main, prog="arcaeon meter"), argv)


# --- hosted --------------------------------------------------------------------

def _stamp(argv) -> int:
    if _wants_help(argv) or len(argv) != 1:
        print("usage: arcaeon stamp <file>\n"
              "Sends the file's sha256 and size (never its bytes) to the hosted witness. "
              "ARCAEON_KEY optional; without it the free daily allowance applies.")
        return V.EXIT_GOOD if _wants_help(argv) else V.EXIT_USAGE
    from arcaeon import remote
    p = Path(argv[0])
    try:
        data = p.read_bytes()
    except OSError as e:
        return _usage(str(e))
    out = remote.stamp(hashlib.sha256(data).hexdigest(), len(data))
    print(json.dumps(out, indent=1))
    return V.EXIT_GOOD if out.get("ok") else V.EXIT_BAD


def _credits(argv) -> int:
    if _wants_help(argv):
        print("usage: arcaeon credits\nYour hosted-witness balance (reads ARCAEON_KEY; "
              "looking never consumes a credit).")
        return V.EXIT_GOOD
    from arcaeon import remote
    if not remote.key():
        print(remote.BLANK_KEY_ERROR, file=sys.stderr)
        return V.EXIT_USAGE
    out = remote.balance()
    print(json.dumps(out, indent=1))
    return V.EXIT_GOOD if out.get("ok") else V.EXIT_BAD


def _buy(argv) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="arcaeon buy", description=(
        "Print the checkout link for a plan, read from offers.json. Opens no "
        "browser and takes no card: payment happens on Stripe's page."))
    ap.add_argument("plan", nargs="?", help="plan name (omit to list every plan)")
    ap.add_argument("--offers", help="offers.json to read (default: the bundled snapshot)")
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else V.EXIT_USAGE
    from arcaeon import remote
    try:
        links = remote.checkout_links(remote.load_offers(a.offers))
    except (OSError, ValueError) as e:
        return _usage(f"could not read offers.json: {e}")
    if a.plan:
        hits = [x for x in links if x["plan"] == a.plan]
        if not hits:
            return _usage(f"no plan named {a.plan!r}; plans: "
                          + ", ".join(x["plan"] for x in links))
        print(hits[0]["checkout"])
        return V.EXIT_GOOD
    for x in links:
        print(f"{x['plan']:<10} {x['price']:<10} {x['cap']:<18} {x['checkout']}")
    return V.EXIT_GOOD


# --- serve / check -----------------------------------------------------------------

def _mcp(argv) -> int:
    try:
        import mcp  # noqa: F401  (the SDK; the [mcp] extra)
    except ImportError:
        print("arcaeon mcp needs the MCP Python SDK: pip install 'arcaeon[mcp]'",
              file=sys.stderr)
        return V.EXIT_USAGE
    from arcaeon.mcp import __main__ as mcp_main
    return _run(partial(mcp_main.main, prog="arcaeon mcp"), argv)


#: name -> (module, entry). Each entry returns 0 when every check it claims passed.
SELFTESTS = {
    "ledger": ("arcaeon.record.ledger.selftest", "run"),
    "adapter": ("arcaeon.record.adapter.selftest", "main"),
    "once": ("arcaeon.record.once.selftest", "run"),
    "compact": ("arcaeon.prove.compact.selftest", "run"),
    "continuity": ("arcaeon.prove.continuity.selftest", "run"),
    "baseline": ("arcaeon.prove.baseline.selftest", "run"),
    "distill": ("arcaeon.save.distill.selftest", "run"),
}


def _selftest(argv) -> int:
    import importlib
    names = [a for a in argv if not a.startswith("-")] or list(SELFTESTS)
    unknown = [n for n in names if n not in SELFTESTS]
    if unknown or _wants_help(argv):
        print("usage: arcaeon selftest [" + " ".join(SELFTESTS) + "]")
        return V.EXIT_GOOD if _wants_help(argv) and not unknown else V.EXIT_USAGE
    results = {}
    for n in names:
        mod, fn = SELFTESTS[n]
        entry = getattr(importlib.import_module(mod), fn)
        rc = _run(entry, []) if fn == "main" else _run(lambda _a, e=entry: e(), [])
        results[n] = rc
    failed = [n for n, rc in results.items() if rc != 0]
    print(json.dumps({"selftests": results, "failed": failed}, indent=1))
    return V.EXIT_GOOD if not failed else V.EXIT_BAD


#: family module -> the component version its code was moved at
COMPONENTS = {
    "arcaeon.record.ledger": "arcaeon-ledger",
    "arcaeon.record.adapter": "arcaeon-adapter",
    "arcaeon.record.receipt": "arcaeon-receipt",
    "arcaeon.record.once": "arcaeon-once",
    "arcaeon.prove.audit": "arcaeon-audit",
    "arcaeon.prove.compact": "arcaeon-compact",
    "arcaeon.prove.continuity": "arcaeon-continuity",
    "arcaeon.prove.baseline": "arcaeon-baseline",
    "arcaeon.prove.vet": "arcaeon-mcp-vet",
    "arcaeon.save.dedup": "arcaeon-dedup",
    "arcaeon.save.distill": "arcaeon-distill",
    "arcaeon.save.meter": "arcaeon-meter",
}


def _version(argv) -> int:
    import importlib
    if _wants_help(argv):
        print("usage: arcaeon version [--short]\n"
              "print arcaeon's version and each moved family's; --short: the version only")
        return V.EXIT_GOOD
    if "--short" in argv:
        print(__version__)
        return V.EXIT_GOOD
    print(f"arcaeon {__version__} (python {sys.version.split()[0]})")
    for mod, old in COMPONENTS.items():
        try:
            m = importlib.import_module(mod)
            v = getattr(m, "__version__", None) or getattr(m, "VERSION", "?")
        except Exception as e:  # a broken family must not hide the others
            v = f"import failed: {type(e).__name__}"
        print(f"  {mod:<26} moved from {old} {v}")
    return V.EXIT_GOOD


HANDLERS = {
    "log": _log, "verify": _verify, "receipt": _receipt, "once": _once, "proxy": _proxy,
    "pin": _pin, "deal": _deal, "reconcile": _reconcile, "audit": _audit, "vet": _vet, "badge": _badge,
    "seal": _seal, "baseline": _baseline, "compact": _compact, "distill": _distill,
    "dedup": _dedup, "meter": _meter, "stamp": _stamp, "credits": _credits, "buy": _buy,
    "mcp": _mcp, "selftest": _selftest, "version": _version,
}
assert set(HANDLERS) == set(VERBS), "every listed verb has a handler"


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
