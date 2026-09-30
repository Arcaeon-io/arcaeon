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
import os
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
    "mandate":   ("record", "check a call against a mandate, record-only (lint, explain, check)"),
    "reconcile": ("prove",  "two tapes and a counter: MATCHED / MISSING / ALTERED / COULD NOT LOOK"),
    "audit":     ("prove",  "verify a log or export a regulator-ready bundle"),
    "vet":       ("prove",  "check MCP-server source (scan, grade, grade-target, verify, probe)"),
    "badge":     ("prove",  "free Markdown badge + JSON report for an MCP server"),
    "seal":      ("prove",  "PAID: a badge sealed by the hosted witness (needs ARCAEON_KEY)"),
    "baseline":  ("prove",  "register and compare pre-registered probe sets"),
    "compact":   ("prove",  "verify a compaction receipt"),
    "second-read": ("prove", "line up two readers' readings of the same claims (criterion, compare, ...)"),
    "evidence-pack": ("prove", "build or verify an evidence pack for a ledger and a time window"),
    "export":    ("prove",  "write a ledger out in another record format (agent-audit-trail)"),
    "distill":   ("save",   "cut a tool output down to a token budget, with a drop receipt"),
    "dedup":     ("save",   "drop near-verbatim repeats from a list of texts"),
    "meter":     ("save",   "keyed usage metering: keys, usage, export"),
    "stamp":     ("remote", "stamp a file's sha256 with the hosted witness"),
    "credits":   ("remote", "show your witness balance (needs ARCAEON_KEY)"),
    "buy":       ("remote", "print the checkout link for a plan (opens nothing)"),
    "mcp":       ("serve",  "start the MCP connector server on stdio (needs arcaeon[mcp])"),
    "serve":     ("serve",  "start the local HTTP/JSON API on 127.0.0.1 (loopback only)"),
    "connect":   ("serve",  "print (or, with --write, apply) the config an AI client needs"),
    "schema":    ("serve",  "print the API as an OpenAPI document or as tool schemas"),
    "open":      ("serve",  "open the local dashboard in a browser"),
    "status":    ("check",  "what arcaeon did lately here: last run per verb, open COULD NOT LOOKs"),
    "selftest":  ("check",  "run every bundled selftest"),
    "version":   ("check",  "print arcaeon's version and each family's"),
    "doctor":    ("check",  "check this install: Python, extras, key set or not, server, clients"),
    "demo":      ("check",  "a short walk-through: log two rows, verify, change a word, verify again"),
}

#: Verbs registered up front by the 9/27 plug-in batch (K001), before their
#: code exists: verb -> (the module whose main(argv) runs it, the batch item
#: that builds it). Each handler imports its module only when the verb runs,
#: so `arcaeon --help` stays light. A module that is not there yet answers
#: "arcaeon <verb>: not built in this checkout" on stderr and exit 2 (usage:
#: the verb cannot be used here), never a traceback and never a pass.
#: tools/release_check.py fails while any of these modules is missing.
LAZY_VERBS = {
    "mandate":       ("arcaeon.record.mandate_cli", "K074"),
    "second-read":   ("arcaeon.prove.readings_cli", "K034"),
    "evidence-pack": ("arcaeon.prove.evidence_pack_cli", "K051"),
    "export":        ("arcaeon.prove.aat_cli", "K061"),
    "serve":         ("arcaeon.serve.cli", "K004"),
    "connect":       ("arcaeon.connect.cli", "K019"),
    "schema":        ("arcaeon.schema.cli", "K013"),
    "open":          ("arcaeon.serve.open_cli", "K107"),
    "doctor":        ("arcaeon.doctor", "K115"),
    "demo":          ("arcaeon.demo", "K116"),
}

FAMILY_TITLES = {"record": "Record", "prove": "Prove", "save": "Save", "remote": "Hosted",
                 "serve": "Serve", "check": "This install"}


def help_text() -> str:
    lines = [f"arcaeon {__version__}: a record of what an agent did that the agent cannot",
             "quietly rewrite, and a way for anyone who doubts it to check.", "",
             "usage: arcaeon <verb> [args...]      arcaeon <verb> --help", ""]
    width = max(10, *(len(v) for v in VERBS))
    for fam, title in FAMILY_TITLES.items():
        lines.append(f"{title}:")
        for verb, (f, summary) in VERBS.items():
            if f == fam:
                lines.append(f"  {verb:<{width}} {summary}")
        lines.append("")
    lines += ["Exit codes, every verb: 0 good, 1 a bad finding, 2 bad usage, 3 COULD NOT LOOK.",
              "--legacy-exit returns the old tool's own code (0.9.x only)."]
    from arcaeon.remote.registration import registration_line
    reg = registration_line()
    if reg:
        lines += ["", reg]
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
    if _asks_version(rest):
        # One answer for every verb (0.9.1): the moved tools each had their own
        # --version, and `arcaeon audit --version` printed "arcaeon-audit 0.1.8".
        print(f"arcaeon {verb} {__version__}")
        return V.EXIT_GOOD
    try:
        rc = handler(rest)
    except KeyboardInterrupt:
        raise
    except Exception as e:  # noqa: BLE001  the one front-door catch
        # Never a traceback, never a green: a verb that fell over mid-check
        # could not look. One line on stderr names the exception class only
        # (a message can carry a path or a value; the class cannot).
        print(f"arcaeon {verb}: could not finish: {type(e).__name__} [internal_error]",
              file=sys.stderr)
        rc = V.EXIT_COULD_NOT_LOOK
    _journal(verb, rest, rc)
    return rc


#: Verbs the activity journal does not record: `status` reads the journal
#: (recording it would bury the runs it reports), `mcp` and `serve` are
#: servers (serve journals each HTTP call itself, as serve:<route>).
_UNJOURNALED = {"status", "mcp", "serve"}
#: Verbs whose first positional word is a subcommand, not the target.
_SUBCOMMAND_VERBS = {"receipt", "once", "audit", "vet", "baseline", "meter", "deal", "distill",
                     "second-read", "evidence-pack", "mandate"}


def _journal_target(verb: str, rest: list[str]) -> str | None:
    """The file a verb looked at: its first positional argument (after a
    subcommand word, for verbs that have one). The journal stores only its
    sha256; this function never opens it."""
    head = rest[:rest.index("--")] if "--" in rest else rest
    pos = [a for a in head if not a.startswith("-") or a == "-"]
    if verb in _SUBCOMMAND_VERBS and pos and not Path(pos[0]).exists() \
            and not any(c in pos[0] for c in "/\\."):
        pos = pos[1:]
    return pos[0] if pos else None


def _journal(verb: str, rest: list[str], rc) -> None:
    """One activity line per verb run (arcaeon.journal). Help is not a run.
    Never raises, never changes rc."""
    if verb in _UNJOURNALED or _wants_help(rest):
        return
    try:
        from arcaeon import journal
        journal.append(verb, journal.word_for(verb, rc), rc, _journal_target(verb, rest))
    except Exception:  # noqa: BLE001  the journal never breaks the verb
        pass


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


def _asks_version(argv) -> bool:
    """`--version` anywhere before a `--`, or `-V` alone. No verb takes either
    as an option of its own, so neither can be a verb's argument by accident."""
    head = argv[:argv.index("--")] if "--" in argv else argv
    return "--version" in head or argv == ["-V"]


# --- record --------------------------------------------------------------------

_LOG_USAGE = ("usage: arcaeon log <ledger.jsonl> '<json object>' | - | --field KEY=VALUE ...\n"
              "The row is a JSON object: as one argument, read from stdin (-), or built\n"
              "from --field KEY=VALUE (repeatable; the value is a string) and\n"
              "--field KEY:=JSON (the value parsed as JSON: 5, true, null, [1,2]).\n"
              "--field needs no JSON quoting, so it works the same in PowerShell, cmd\n"
              "and sh. Fields are added over a JSON or stdin row when both are given.")


def _log_row(argv) -> tuple[str | None, str | None, str | None]:
    """(ledger, row as JSON text, usage error). Never touches the ledger."""
    pos, fields, i = [], [], 0
    while i < len(argv):
        a = argv[i]
        if a == "--field" or a.startswith("--field="):
            if a == "--field":
                if i + 1 >= len(argv):
                    return None, None, "log: --field needs KEY=VALUE"
                val, i = argv[i + 1], i + 2
            else:
                val, i = a[len("--field="):], i + 1
            fields.append(val)
            continue
        if a.startswith("-") and a != "-":
            return None, None, f"log: unknown option {a}"
        pos.append(a)
        i += 1
    if not pos or len(pos) > 2 or (len(pos) == 1 and not fields):
        return None, None, None
    ledger, body = pos[0], (pos[1] if len(pos) == 2 else None)
    if body == "-":
        body = sys.stdin.read()
    if not fields:
        return ledger, body, None
    row: dict = {}
    if body is not None and body.strip():
        try:
            row = json.loads(body)
        except ValueError as e:
            return None, None, f"log: the row is not JSON ({e})"
        if not isinstance(row, dict):
            return None, None, "log: the row is not a JSON object"
    for f in fields:
        typed = ":=" in f and ("=" not in f or f.index(":=") < f.index("="))
        k, sep, v = f.partition(":=") if typed else f.partition("=")
        if not sep or not k:
            return None, None, f"log: --field wants KEY=VALUE or KEY:=JSON, got {f!r}"
        if typed:
            try:
                v = json.loads(v)
            except ValueError as e:
                return None, None, f"log: --field {k}:= is not JSON ({e})"
        row[k] = v
    return ledger, json.dumps(row, ensure_ascii=False), None


def _log(argv) -> int:
    if _wants_help(argv):
        print(_LOG_USAGE)
        return V.EXIT_GOOD
    ledger, body, err = _log_row(argv)
    if err:
        return _usage(err)
    if ledger is None:
        print(_LOG_USAGE)
        return V.EXIT_USAGE
    p = Path(ledger)
    if p.is_dir():
        return _usage(f"log: cannot append to {ledger}: it is a directory, not a ledger file")
    problem = _last_row_problem(p)
    if problem:
        print(f"{V.COULD_NOT_LOOK}: refusing to append to {ledger}: {problem}; "
              f"nothing was written", file=sys.stderr)
        return _emit_could_not_look(V.could_not_look(
            "a chained last row to append after", ledger, "unreadable", problem))
    from arcaeon.record.ledger import cli
    try:
        return _run(cli.main, ["append", ledger, body])
    except OSError as e:
        return _usage(f"log: cannot write {ledger}: {e.strerror or type(e).__name__}")


def _emit_could_not_look(detail: dict, extra: dict | None = None, *, echo: bool = True) -> int:
    """Print a COULD NOT LOOK's looked_for and where (stderr, one line) and
    emit them with reason_word as JSON on stdout. Returns exit 3."""
    if echo:
        print(f"  looked for: {detail['looked_for']}; where: {detail['where']}; "
              f"reason_word: {detail['reason_word']}", file=sys.stderr)
    print(json.dumps({"ok": False, "verdict": V.COULD_NOT_LOOK, **(extra or {}), **detail},
                     indent=1))
    return V.EXIT_COULD_NOT_LOOK


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
    # verify already used 3 for a bounded chain; --legacy-exit keeps only the
    # 0.9.0 code for a file that could not be read (1, BROKEN), see below
    argv, legacy = V.pop_legacy_flag(argv)
    usage = ("usage: arcaeon verify <ledger.jsonl> [--strict] [--witness PINS [--ns NS]]\n"
             "exit 0 VERIFIED, 1 BROKEN, 3 COULD NOT LOOK (rows the chain could not speak "
             "for, or a file that could not be read). With --witness (a local pin file) "
             "it also says how many rows were added since the ledger's last pin there.")
    if _wants_help(argv):
        print(usage)
        return V.EXIT_GOOD
    # The ledger's own report, with the verdict word added as the first key
    # (the ledger CLI prints the same fields without it). The word comes from
    # the same three-valued `ok` the old exit code came from, so the two
    # cannot disagree: True VERIFIED 0, None COULD NOT LOOK 3, False BROKEN 1.
    from arcaeon.record.ledger import verify_file
    strict, pins, ns, pos, i = False, None, None, [], 0
    while i < len(argv):
        a = argv[i]
        if a == "--strict":
            strict = True
        elif a in ("--witness", "--ns"):
            if i + 1 >= len(argv):
                print(f"arcaeon: verify: {a} needs a value", file=sys.stderr)
                return V.EXIT_USAGE
            pins, ns = (argv[i + 1], ns) if a == "--witness" else (pins, argv[i + 1])
            i += 1
        elif a.startswith("-"):
            pos.append(None)                   # an unknown flag: usage below
        else:
            pos.append(a)
        i += 1
    if len(pos) != 1 or pos[0] is None or (ns and not pins):
        print(usage.splitlines()[0], file=sys.stderr)
        return V.EXIT_USAGE
    path = pos[0]
    r = verify_file(path, strict=strict)
    word = V.VERIFIED if r.ok is True else (V.COULD_NOT_LOOK if r.ok is None else V.BROKEN)
    # A missing, unreadable or directory path: verify_file() reports ok=False
    # "unreadable: ..." with zero rows read. Nothing was checked, so no break
    # was found either: that is COULD NOT LOOK (exit 3), not BROKEN (0.9.1).
    unread = (r.ok is False and not r.rows
              and str(r.first_break or "").startswith("unreadable:"))
    if unread:
        word = V.COULD_NOT_LOOK
    report = {"verdict": word, **r.__dict__}
    if word == V.COULD_NOT_LOOK:
        if unread:
            rw = "missing" if not Path(path).exists() else "unreadable"
            d = V.could_not_look("a ledger file", path, rw, str(r.first_break))
        elif r.verified_scope == "empty":
            d = V.could_not_look("chained rows", path, "empty", "the ledger has no rows")
        else:
            d = V.could_not_look("a chain value on every row", path, "bounded",
                                 f"{r.prechain} row(s) carry no chain, so the chain cannot "
                                 f"speak for them ({r.verified_scope})")
        report.update(d)
        print(f"{V.COULD_NOT_LOOK} ({d['reason_word']}): looked for {d['looked_for']} "
              f"in {d['where']}: {d['reason']}", file=sys.stderr)
    if pins:
        report["since_pin"] = _rows_since_pin_report(path, pins, ns)
        sp = report["since_pin"]
        if sp.get("rows_since_pin") is not None and sp["rows_since_pin"] < 0:
            # Fewer rows than were pinned: rows were cut off the end. A chain
            # that verifies on its own cannot see this; the pin can.
            sp["truncated"] = True
            if word == V.VERIFIED:
                word = report["verdict"] = V.BROKEN
            print(f"{V.BROKEN}: the ledger holds {-sp['rows_since_pin']} fewer row(s) than "
                  f"its last pin ({sp['namespace']}, {sp['pinned_rows']} rows)", file=sys.stderr)
        elif sp.get("rows_since_pin") is not None:
            print(f"rows added since the last pin ({sp['namespace']}, {sp['pinned_rows']} "
                  f"rows): {sp['rows_since_pin']}", file=sys.stderr)
        else:
            print(f"no pin compared: {sp['reason']}", file=sys.stderr)
    print(json.dumps(report, indent=1))
    if unread and legacy:
        return V.EXIT_BAD                      # 0.9.0 / arcaeon-ledger verify said 1
    return V.exit_for(word)


def _rows_since_pin_report(ledger: str, pins: str, ns: str | None) -> dict:
    """The ledger's latest pin in a local pin file and the rows added since it
    (arcaeon.record.ledger.witness.rows_since_pin). Without --ns the file must
    hold pins for one namespace only. Never raises; says why when it cannot."""
    from arcaeon.record.ledger import witness as W
    if not Path(pins).is_file():
        return {"rows_since_pin": None, "reason": f"no pin file at {pins}"}
    problem = _witness_file_problem(Path(pins))
    if problem:
        return {"rows_since_pin": None, "reason": f"the pin file cannot be read: {problem}",
                **V.could_not_look("a witness pin file", pins, "unreadable", problem)}
    store = W.WitnessStore(pins)
    if ns is None:
        names = set()
        for raw in Path(pins).read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                names.add(json.loads(raw)["namespace"])
            except (ValueError, KeyError, TypeError):
                continue
        if len(names) != 1:
            return {"rows_since_pin": None,
                    "reason": f"the pin file holds {len(names)} namespaces; pass --ns"}
        ns = names.pop()
    pin = store.latest(ns)
    if not pin:
        return {"rows_since_pin": None, "namespace": ns, "reason": f"no pin for {ns} in {pins}"}
    rows_since = getattr(W, "rows_since_pin", None)
    try:
        n = rows_since(ledger, pin) if rows_since else None
    except (ValueError, OSError) as e:
        return {"rows_since_pin": None, "namespace": ns, "reason": str(e)}
    if n is None:
        return {"rows_since_pin": None, "namespace": ns,
                "reason": "this install has no witness.rows_since_pin"}
    return {"rows_since_pin": n, "namespace": ns, "pinned_rows": pin.get("rows"),
            "pinned_chain": pin.get("chain")}


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
            return _emit_could_not_look(V.could_not_look(
                "UTF-8 JSON lines to index", argv[1], "unreadable", problem))
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
    ap.add_argument("--ns", "--namespace", dest="ns", default=None,
                    help="required with --witness; with --remote it defaults to one "
                         "derived from your key's prefix and the ledger")
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
    if a.witness and not a.ns:
        return _usage("pin: --ns is required with --witness")
    lp = Path(a.ledger)
    if lp.is_file():
        vr = verify_file(lp)
        if vr.ok is None and vr.verified_scope != "empty":
            err = (f"refusing to pin a ledger verify cannot vouch for "
                   f"({vr.verified_scope}; {vr.prechain} unchained "
                   f"row(s)); run `arcaeon verify` for the detail")
            print(f"{V.COULD_NOT_LOOK}: {err}", file=sys.stderr)
            return _emit_could_not_look(V.could_not_look(
                "a chain value on every row", a.ledger, "bounded", err), {"error": err})
    if a.witness:
        from arcaeon.record.ledger.witness import WitnessStore, publish_head
        problem = _witness_file_problem(Path(a.witness))
        if problem:
            err = f"refusing to write to {a.witness}: {problem}; nothing was written"
            print(f"{V.COULD_NOT_LOOK}: {err}", file=sys.stderr)
            return _emit_could_not_look(V.could_not_look(
                "a witness pin file to append to", a.witness, "unreadable", problem),
                {"error": err})
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
    key = remote.key() or ""
    if a.ns:
        out = fn(a.ns, head.rows, head.chain, key)
    else:
        out = _pin_ns_from_key(fn, lp, head, key)
    print(json.dumps(out, indent=1))
    return V.EXIT_GOOD if out.get("ok") else V.EXIT_BAD


#: The first namespace `pin --remote` tries with no --ns, before it knows the
#: key's prefix (the operator's own key covers it).
_PIN_NS_BASE = "arcaeon"


def _ledger_ns_part(p: Path) -> str:
    """`ledger-<12 hex>` from the ledger's FIRST row's chain value: stable
    when the file moves, different per ledger (two ledgers in one namespace
    would fight over the witness's monotonic head), and it carries no part of
    the path. An empty or unreadable ledger is just `ledger`."""
    from arcaeon.record.row import loads_strict
    try:
        with open(p, "rb") as f:
            for raw in f:
                if raw.strip():
                    row = loads_strict(raw.decode("utf-8"))
                    chain = row.get("chain") if isinstance(row, dict) else None
                    if isinstance(chain, str) and chain:
                        return "ledger-" + hashlib.sha256(chain.encode()).hexdigest()[:12]
                    break
    except Exception:  # noqa: BLE001  an id we cannot derive is just "ledger"
        pass
    return "ledger"


def _pin_ns_from_key(fn, lp: Path, head, key: str) -> dict:
    """`pin --remote` with no --ns: seal's namespace-from-the-key logic
    (arcaeon.remote.sealed_scan). Try `<learned prefix>-ledger-<id>` if this
    process already learned the key's prefix, else `arcaeon-ledger-<id>`; on a
    403 that names the key's prefix (it spends no credit), remember the prefix
    and retry ONCE under `<prefix>-ledger-<id>`. The namespace used is in the
    printed answer so the next run can pass it as --ns."""
    from arcaeon.remote import sealed_scan as S
    part = _ledger_ns_part(lp)

    def join(prefix: str) -> str:
        return prefix + part if prefix.endswith("-") else prefix + "-" + part

    known = S._prefix_cache.get(S._key_id(key)) if key else None
    ns = join(known) if known else join(_PIN_NS_BASE)
    out = fn(ns, head.rows, head.chain, key)
    prefix = S.prefix_from_refusal(out) if not out.get("ok") else None
    if prefix and key:
        S._prefix_cache[S._key_id(key)] = prefix
        derived = join(prefix)
        if derived != ns and S._NS_RE.match(derived):
            ns = derived
            out = fn(ns, head.rows, head.chain, key)
    return {**out, "namespace": out.get("namespace", ns)}


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


AUDIT_BUNDLE_LOG = "records.jsonl"


def _audit_bundle_dir(argv) -> tuple[list, str | None]:
    """`audit verify <dir>`: an exported bundle directory means its records.jsonl,
    the same resolution POST /v1/audit/verify makes (K010b). Returns the argv
    to run and, for a directory with no records.jsonl, the directory itself."""
    pos = [i for i, a in enumerate(argv) if not a.startswith("-")]
    if len(pos) < 2 or argv[pos[0]] != "verify":
        return argv, None
    i = pos[1]
    if not os.path.isdir(argv[i]):
        return argv, None
    inner = os.path.join(argv[i], AUDIT_BUNDLE_LOG)
    if not os.path.isfile(inner):
        return argv, argv[i]
    return [*argv[:i], inner, *argv[i + 1:]], None


def _audit(argv) -> int:
    from arcaeon.prove.audit import cli
    sub = next((a for a in argv if not a.startswith("-")), None)
    argv, bare_dir = _audit_bundle_dir(list(argv))
    if bare_dir is not None:
        _, legacy = V.pop_legacy_flag(argv)
        print(f"COULD NOT LOOK: {bare_dir} is a directory with no {AUDIT_BUNDLE_LOG} "
              "(not an exported bundle). Nothing to verify and nothing to accuse.")
        return V.unify("audit", 2, sub, legacy=legacy)
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
        # Nothing was stamped and nothing was found wrong: COULD NOT LOOK, the
        # same answer `verify` gives a missing or unreadable file (was usage 2).
        word = "missing" if not p.exists() else "unreadable"
        if word == "missing":
            why = "it does not exist"
        else:
            why = "it is a directory" if p.is_dir() else (e.strerror or type(e).__name__)
        cnl = V.could_not_look("the file to stamp", argv[0], word, f"cannot read {argv[0]}: {why}")
        print(json.dumps({"ok": False, "verdict": V.COULD_NOT_LOOK, **cnl}, indent=1))
        print(f"{V.COULD_NOT_LOOK} ({word}): looked for the file to stamp at {argv[0]}: {why}; "
              f"nothing was sent", file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK
    out = remote.stamp(hashlib.sha256(data).hexdigest(), len(data))
    if not out.get("ok") and out.get("status") == 0:
        out = {**out, "verdict": V.COULD_NOT_LOOK,
               **V.could_not_look("a stamp from the hosted witness", out.get("endpoint"),
                                  "network", str(out.get("error") or "the request never completed"))}
        print(json.dumps(out, indent=1))
        return V.EXIT_COULD_NOT_LOOK
    print(json.dumps(out, indent=1))
    return V.EXIT_GOOD if out.get("ok") else V.EXIT_BAD


def _credits(argv) -> int:
    if _wants_help(argv) or any(a != "--json" for a in argv):
        print("usage: arcaeon credits [--json]\nYour hosted-witness balance as one sentence "
              "(reads ARCAEON_KEY; looking never consumes a credit). --json prints the "
              "witness's raw answer.")
        return V.EXIT_GOOD if _wants_help(argv) else V.EXIT_USAGE
    from arcaeon import remote
    from arcaeon.status import balance_sentence
    if not remote.key():
        print(remote.BLANK_KEY_ERROR, file=sys.stderr)
        return V.EXIT_USAGE
    out = remote.balance()
    never_completed = not out.get("ok") and out.get("status") == 0
    if never_completed:
        # The request never reached an answer: not a "no", a look that did not happen.
        out = {**out, "verdict": V.COULD_NOT_LOOK,
               **V.could_not_look("your balance", out.get("endpoint"), "network",
                                  str(out.get("error") or "the request never completed"))}
    if "--json" in argv:
        print(json.dumps(out, indent=1))
    elif out.get("ok"):
        print(balance_sentence(out))
    elif never_completed:
        print(f"{V.COULD_NOT_LOOK} (network): looked for your balance at {out.get('endpoint')}: "
              f"{out['reason']}")
    else:
        print(f"the witness did not answer with a balance: {out.get('error', out.get('status'))}")
    if never_completed:
        return V.EXIT_COULD_NOT_LOOK
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
    from arcaeon.remote.registration import registration_line
    if a.plan == "evidence-pack":  # K128: the sealed pack is paid in credits
        from arcaeon.remote import offers as _offers
        try:
            cat = remote.load_offers(a.offers)
            lines = _offers.evidence_pack_lines(cat)
        except (OSError, ValueError) as e:
            return _usage(f"could not read the evidence-pack offer: {e}")
        reg = registration_line(cat)
        print("\n".join(lines + ([reg] if reg else [])))
        return V.EXIT_GOOD
    try:
        cat = remote.load_offers(a.offers)
        links = remote.checkout_links(cat)
    except (OSError, ValueError) as e:
        return _usage(f"could not read offers.json: {e}")
    # Dark until the offers document switches registration on: then one
    # sentence, and never on the single-plan path, whose stdout is one URL.
    reg = registration_line(cat)
    if a.plan:
        hits = [x for x in links if x["plan"] == a.plan]
        if not hits:
            return _usage(f"no plan named {a.plan!r}; plans: "
                          + ", ".join(x["plan"] for x in links))
        print(hits[0]["checkout"])
        return V.EXIT_GOOD
    for x in links:
        print(f"{x['plan']:<10} {x['price']:<10} {x['cap']:<18} {x['checkout']}")
    if reg:
        print(reg)
    return V.EXIT_GOOD


# --- serve / check -----------------------------------------------------------------

def _mcp(argv) -> int:
    try:
        import mcp  # noqa: F401  (the SDK; the [mcp] extra)
    except ImportError:
        # KH8: --http fails closed as COULD NOT LOOK, exit 3. --print-front-door
        # needs no SDK: it prints the front door object and starts nothing.
        if "--http" in argv or "--print-front-door" in argv:
            from arcaeon.mcp import __main__ as mcp_main
            return _run(partial(mcp_main.main, prog="arcaeon mcp"), argv)
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


def _status(argv) -> int:
    from arcaeon import status
    return _run(status.main, argv)


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


#: extra name (pyproject optional-dependencies) -> the modules it installs
_EXTRAS = {"mcp": ("mcp",), "ts": ("tree_sitter", "tree_sitter_typescript"),
           "sign": ("cryptography",)}


def _importable(mod: str) -> bool:
    """Installed, without importing it (arcaeon stays light to load)."""
    import importlib.util
    try:
        return importlib.util.find_spec(mod) is not None
    except (ImportError, ValueError):
        return False


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
    from arcaeon import remote
    extras = [name for name, mods in _EXTRAS.items() if all(_importable(m) for m in mods)]
    # Whether a key is set, never the key: a version line gets pasted into bug reports.
    print(f"  extras: {', '.join(extras) or 'none'}; key: {'set' if remote.key() else 'not set'}")
    for mod, old in COMPONENTS.items():
        try:
            m = importlib.import_module(mod)
            v = getattr(m, "__version__", None) or getattr(m, "VERSION", "?")
        except Exception as e:  # a broken family must not hide the others
            v = f"import failed: {type(e).__name__}"
        print(f"  {mod:<26} moved from {old} {v}")
    return V.EXIT_GOOD


def verb_built(verb: str) -> bool:
    """False only for a LAZY_VERBS verb whose module is not in this install."""
    return verb not in LAZY_VERBS or _importable(LAZY_VERBS[verb][0])


def _lazy(verb: str, argv) -> int:
    mod = LAZY_VERBS[verb][0]
    if not _importable(mod):
        print(f"arcaeon {verb}: not built in this checkout", file=sys.stderr)
        return V.EXIT_USAGE
    import importlib
    return _run(importlib.import_module(mod).main, argv)


HANDLERS = {
    "log": _log, "verify": _verify, "receipt": _receipt, "once": _once, "proxy": _proxy,
    "pin": _pin, "deal": _deal, "reconcile": _reconcile, "audit": _audit, "vet": _vet, "badge": _badge,
    "seal": _seal, "baseline": _baseline, "compact": _compact, "distill": _distill,
    "dedup": _dedup, "meter": _meter, "stamp": _stamp, "credits": _credits, "buy": _buy,
    "mcp": _mcp, "status": _status, "selftest": _selftest, "version": _version,
    **{verb: partial(_lazy, verb) for verb in LAZY_VERBS},
}
assert set(HANDLERS) == set(VERBS), "every listed verb has a handler"


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
