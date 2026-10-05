# SPDX-License-Identifier: MIT
"""arcaeon.prove.register_page: the register of named operators as one static
HTML page (L3-04).

    arcaeon register page REGISTER.jsonl [--operator-key DID...] [--out FILE]

Reads a register (arcaeon.prove.register rows, one JSON object per line, or
one JSON array) and checks it with check_register against the register
operator key(s) the reader names. The verdict is the first thing on the page.

  VERIFIED        the page lists each named operator (member), the keys,
                  chains and witness endpoints the rows give it, when each
                  was added, each revocation (when, why, compromised since),
                  the head digest and the row count.
  BROKEN          the page says where the register breaks and shows no row
                  as the register's word: not the rows past the break, and
                  not the rows before it either, since a register that does
                  not check as a whole names no one.
  COULD NOT LOOK  no rows, no operator key named, no Ed25519 backend: the
                  reason, and no rows.

The page is a view, not a service: inline CSS, no script, no link, no image,
no font, nothing fetched. Every value is HTML-escaped (tally_html's _e). The
same register and the same named keys give the same bytes: nothing on the page
depends on the clock or on where the file sits (the file's name only).
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from arcaeon import verdict as V
from arcaeon.prove import exchange_log as X
from arcaeon.prove import register as G
from arcaeon.prove.tally_html import _e
from arcaeon.record.row import loads_strict

__all__ = ["MAX_INPUT", "RegisterPageError", "load_rows", "render_page", "page_cli", "main",
           "USAGE", "HELP", "LIMITS"]

MAX_INPUT = 64 << 20

USAGE = "usage: arcaeon register page REGISTER.jsonl [--operator-key DID...] [--out FILE]"

HELP = USAGE + """

page reads a register of named operators (arcaeon.prove.register rows, one
JSON object per line or one JSON array) and checks it against the register
operator key(s) you name with --operator-key (repeatable; the key comes from
you, never from the rows). It prints the verdict and writes one static HTML
page: the verdict first, then, only when the register is VERIFIED, each
operator with its keys, chains and witness endpoints, the revocations (what,
when, reason, compromised since), the head digest and the row count. A BROKEN
or COULD NOT LOOK register shows the reason and no rows. No script, nothing
fetched, every value escaped; the same register gives the same bytes.
Without --out the page goes to stdout and the verdict line to stderr. --out
is never overwritten.

Exit codes: 0 VERIFIED (page written), 1 BROKEN (page written), 3 COULD NOT
LOOK (page written; or the file cannot be read as JSON, nothing written),
2 bad usage or --out exists."""

#: The limits sentence, on every page whatever the verdict.
LIMITS = ("This page shows what the register's signed rows say, in one copy of the "
          "register, and nothing more. It cannot show that a named operator is who they "
          "claim to be offline, that a key was never copied, that a time a row states is "
          "true, or that this copy is the newest one: a revocation written after it is not "
          "seen here.")
COMMAND = "arcaeon register page REGISTER.jsonl --operator-key DID --out page.html"

_CSS = """body{font-family:system-ui,sans-serif;margin:1.5em;color:#111;background:#fff;max-width:72em}
table{border-collapse:collapse;font-size:13px;margin:.3em 0 1em 0}
th,td{border:1px solid #999;padding:3px 6px;vertical-align:top;text-align:left}
td.id,code{font-family:monospace;word-break:break-all}
thead th{background:#eee}
p.verdict{font-weight:bold;font-size:1.1em;border:2px solid #111;padding:.4em .6em}
ul{margin:.3em 0 1em 1.2em;padding:0}"""

_EXIT = {V.VERIFIED: V.EXIT_GOOD, V.BROKEN: V.EXIT_BAD}


class RegisterPageError(ValueError):
    """The file is not one this page can read. Nothing was written."""


def load_rows(path: Any) -> list:
    """The register rows in a file: a JSON array, or one JSON value per line
    (blank lines skipped; an empty file is an empty register).
    RegisterPageError when the file cannot be read as JSON."""
    p = Path(path)
    try:
        if not p.is_file():
            raise RegisterPageError(f"{p.name} is not there")
        if p.stat().st_size > MAX_INPUT:
            raise RegisterPageError(f"{p.name} is over {MAX_INPUT} bytes; not read")
        text = p.read_bytes().decode("utf-8")
        if text.lstrip().startswith("["):
            rows = loads_strict(text)
            if not isinstance(rows, list):
                raise RegisterPageError(f"{p.name} is not a JSON array of rows")
            return rows
        return [loads_strict(line) for line in text.splitlines() if line.strip()]
    except RegisterPageError:
        raise
    except (OSError, UnicodeDecodeError, ValueError) as e:
        raise RegisterPageError(f"{p.name} is not JSON rows ({type(e).__name__})") from None


def _keys(operator_keys: Any) -> list[str]:
    if isinstance(operator_keys, str):
        return [operator_keys]
    return [str(k) for k in (operator_keys or ())]


def _status(entry: dict) -> str:
    rv = entry["revoked"]
    if rv is None:
        return "current (no revocation in this copy)"
    s = f"REVOKED at {rv['at']} ({rv['reason']})"
    if rv["compromised_since"] is not None:
        s += f", compromised since {rv['compromised_since']}"
    return s


def _row(cells: list[tuple[str, Any]]) -> str:
    return "<tr>" + "".join(f'<td class="{k}">{_e(v)}</td>' if k else f"<td>{_e(v)}</td>"
                            for k, v in cells) + "</tr>"


def _table(head: list[str], rows: list[str]) -> list[str]:
    return (["<table>", "<thead><tr>" + "".join(f"<th>{_e(h)}</th>" for h in head)
             + "</tr></thead>", "<tbody>"] + rows + ["</tbody>", "</table>"])


def _verified_body(rows: list, chk: dict) -> list[str]:
    _, things, _ = G._walk(rows, verify=False)
    out = ["<h2>The register</h2>",
           f"<p>head <code>{_e(chk['head'])}</code>; {_e(chk['rows'])} rows; signed by "
           f"{_e(', '.join(chk['signers']))}</p>",
           "<p>A reader holding the same head holds the same register.</p>",
           "<h2>Operators</h2>"]
    members: list[str] = []
    for e in things.values():
        if e["member"] not in members:
            members.append(e["member"])
    head = ["what", "value", "register digest", "added", "status"]
    for m in members:
        nm = X.ACCOUNT_ID_RE.fullmatch(m)
        out.append(f"<h3>{_e(nm.group('name'))} ({_e(m)})</h3>" if nm else f"<h3>{_e(m)}</h3>")
        out.append("<p>publishing cadence: not stated (the register's rows carry no "
                   "cadence)</p>")
        out += _table(head, [_row([("", e["what"]), ("id", e["value"]), ("id", d),
                                   ("", e["added_at"]), ("", _status(e))])
                             for d, e in things.items() if e["member"] == m])
    out.append("<h2>Witness endpoints</h2>")
    ends = [_row([("", e["member"]), ("id", e["value"]), ("", _status(e))])
            for e in things.values() if e["what"] == "witness_endpoint"]
    out += _table(["operator", "endpoint", "status"], ends) if ends else \
        ["<p>none in this register</p>"]
    out.append("<h2>Revocations</h2>")
    revs = []
    for i, r in enumerate(rows):
        if r["event"] == "revoke":
            revs.append(_row([("", i), ("", r["member"]), ("", r["what"]),
                              ("id", things[r["digest"]]["value"]), ("", r["at"]),
                              ("", r["reason"]), ("", r["compromised_since"])]))
    out += _table(["row", "operator", "what", "value", "revoked at", "reason",
                   "compromised since"], revs) if revs else ["<p>none in this register</p>"]
    return out


def _render(rows: Any, operator_keys: Any = (), source: Any = None) -> tuple[str, dict]:
    keys = _keys(operator_keys)
    chk = G.check_register(rows, operator_keys=keys)
    word = chk["verdict"]
    out = ["<!doctype html>", '<html lang="en">', "<head>", '<meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           f"<title>register of named operators: {_e(word)}</title>",
           f"<style>{_CSS}</style>", "</head>", "<body>",
           "<h1>Register of named operators</h1>",
           f'<p class="verdict">register {_e(word)}: {_e(chk["reason"])}</p>']
    if source is not None:
        out.append(f"<p>read from {_e(source)}</p>")
    out.append("<p>checked against the register operator key(s) you named: "
               f"{_e(', '.join(keys) if keys else 'none named')}</p>")
    if word == V.VERIFIED:
        out += _verified_body(rows, chk)
    elif word == V.BROKEN:
        out.append("<p>The register does not check, so no row is shown: not the rows past "
                   "the break, and not the rows before it as the register's word. A register "
                   "that does not check as a whole names no one. No head is given.</p>")
    else:
        out.append("<p>The register could not be checked, so no row is shown and no head "
                   "is given.</p>")
    out += ["<h2>What this page cannot tell you</h2>", f"<p>{_e(LIMITS)}</p>",
            f"<p>The register proves: {_e(G.PROVES)}. It does not prove: "
            f"{_e(G.DOES_NOT_PROVE)}.</p>",
            "<p>Check the chain yourself, from the register file and the operator key you "
            f"trust: <code>{_e(COMMAND)}</code> prints the verdict and writes this page "
            "again, byte for byte.</p>",
            "</body>", "</html>", ""]
    return "\n".join(out), chk


def render_page(rows: Any, operator_keys: Any = (), source: Any = None) -> str:
    """The page, as text. Same rows and keys in, same bytes out. Never raises
    on hostile rows (check_register never raises; a BROKEN or COULD NOT LOOK
    register renders no row)."""
    return _render(rows, operator_keys, source)[0]


class _Usage(Exception):
    pass


def page_cli(argv: list[str]) -> int:
    from arcaeon.prove.envelope import _parse, _Usage as EU
    try:
        pos, o = _parse(argv, {"--operator-key": "list", "--out": "value"})
    except EU as e:
        raise _Usage(str(e)) from None
    if len(pos) != 1:
        raise _Usage("page takes one register file")
    out = o.get("--out")
    if out and Path(out).exists():
        raise _Usage(f"--out {Path(out).name} exists; it is never overwritten")
    try:
        rows = load_rows(pos[0])
    except RegisterPageError as e:
        print(f"arcaeon register page: {V.COULD_NOT_LOOK}: {e}; nothing written",
              file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK
    page, chk = _render(rows, o.get("--operator-key") or [], Path(pos[0]).name)
    line = f"register {chk['verdict']}: {chk['reason']}"
    if out:
        with open(out, "x", encoding="utf-8", newline="\n") as fh:
            fh.write(page)
        print(f"{line}\nwrote {Path(out).name}")
    else:
        sys.stdout.write(page)
        print(line, file=sys.stderr)
    return _EXIT.get(chk["verdict"], V.EXIT_COULD_NOT_LOOK)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help") or any(a in ("-h", "--help") for a in argv):
        print(HELP)
        return V.EXIT_GOOD if argv else V.EXIT_USAGE
    try:
        if argv[0] != "page":
            raise _Usage(f"unknown subcommand {argv[0]!r} (page)")
        return page_cli(argv[1:])
    except _Usage as e:
        print(f"arcaeon register: {e}\n{USAGE}", file=sys.stderr)
        return V.EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
