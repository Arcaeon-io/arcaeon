# SPDX-License-Identifier: MIT
"""arcaeon.prove.tally_html: the tally as one static HTML page (A14).

    arcaeon tally html TALLY.json [--out FILE]

Reads a tally (kind arcaeon.tally/v1, from `tally build --json`, `tally seal
--out` or `tally.build`) and writes one self-contained page: inline CSS, no
script, nothing fetched. One table row per ID per window, in the order the
tally emits them; the columns are the tally's own facts (the same labels and
values as the text render) and the last cell of every row is the sentence.
No score, no rank, no grade, no colour for good or bad, no sorting. Every
value is HTML-escaped. The page is a view of the JSON, not a check of it:
`tally verify` checks; this only shows.
"""
from __future__ import annotations

import html
import json
import sys
from pathlib import Path
from typing import Any

from arcaeon import verdict as V
from arcaeon.prove import tally as T
from arcaeon.record.row import loads_strict

__all__ = ["COLUMNS", "MAX_INPUT", "TallyHtmlError", "load", "render_html", "main"]

MAX_INPUT = 64 << 20
COLUMNS = ("id", "window", "unrated", "keys", "first row at", "age days",
           *(label for label, _ in T._ROWS), "sentence")

_CSS = """body{font-family:system-ui,sans-serif;margin:1.5em;color:#111;background:#fff}
table{border-collapse:collapse;font-size:13px}
th,td{border:1px solid #999;padding:3px 6px;vertical-align:top;text-align:left}
td.n{text-align:right;white-space:nowrap}
td.id{font-family:monospace;word-break:break-all;max-width:22em}
thead th{position:sticky;top:0;background:#eee}
p.sentence{font-weight:bold}
ul{margin:.3em 0 1em 1.2em;padding:0}"""


class TallyHtmlError(ValueError):
    """The input is not a tally this page can show. Nothing was written."""


def _e(v: Any) -> str:
    return html.escape("-" if v is None else str(v), quote=True)


def load(path: Any) -> dict:
    """Read a tally JSON file; TallyHtmlError when it is not one."""
    p = Path(path)
    try:
        if not p.is_file():
            raise TallyHtmlError(f"{p.name} is not there")
        if p.stat().st_size > MAX_INPUT:
            raise TallyHtmlError(f"{p.name} is over {MAX_INPUT} bytes; not read")
        r = loads_strict(p.read_bytes().decode("utf-8"))
    except TallyHtmlError:
        raise
    except (OSError, UnicodeDecodeError, ValueError) as e:
        raise TallyHtmlError(f"{p.name} is not JSON ({type(e).__name__})") from None
    _check(r)
    return r


def _check(r: Any) -> None:
    if not isinstance(r, dict) or r.get("kind") != T.KIND:
        raise TallyHtmlError(f"not a tally of kind {T.KIND}")
    if not isinstance(r.get("ids"), list) or not isinstance(r.get("windows"), list):
        raise TallyHtmlError("the tally has no list of ids or windows")
    for w in r["windows"]:
        if not isinstance(w, dict) or not isinstance(w.get("name"), str):
            raise TallyHtmlError("a window has no name")
    for i in r["ids"]:
        if not isinstance(i, dict) or not isinstance(i.get("windows"), dict):
            raise TallyHtmlError("an id has no windows")


def _fact(fn, block: Any) -> str:
    try:
        return fn(block)
    except Exception:  # noqa: BLE001  a missing fact shows as missing, never a guess
        return "?"


def _row(i: dict, name: str) -> list[tuple[str, str]]:
    """(css class, escaped text) per COLUMNS entry."""
    block = i["windows"].get(name)
    unrated = ("unrated: " + "; ".join(str(x) for x in i.get("unrated_because") or [])
               if i.get("unrated") else "no")
    keys = i.get("keys") or []
    cells = [("id", _e(i.get("id"))), ("", _e(name)), ("", _e(unrated)),
             ("id", _e(", ".join(str(k) for k in keys) if keys != [i.get("id")] else "-")),
             ("n", _e(i.get("first_row_at"))), ("n", _e(i.get("age_days")))]
    for _, fn in T._ROWS:
        cells.append(("n", _e(_fact(fn, block) if isinstance(block, dict) else "?")))
    cells.append(("", _e(T.SENTENCE)))
    return cells


def _list(title: str, items) -> list[str]:
    items = [x for x in (items or [])]
    if not items:
        return []
    return [f"<h2>{_e(title)}</h2>", "<ul>"] + [f"<li>{_e(x)}</li>" for x in items] + ["</ul>"]


def render_html(r: dict) -> str:
    """The page, as text. Same tally in, same bytes out."""
    _check(r)
    names = [w["name"] for w in r["windows"]]
    out = ["<!doctype html>", '<html lang="en">', "<head>", '<meta charset="utf-8">',
           "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
           f"<title>tally {_e(r.get('verdict'))} at {_e(r.get('now'))}</title>",
           f"<style>{_CSS}</style>", "</head>", "<body>",
           f'<p class="sentence">{_e(T.SENTENCE)}</p>',
           f"<p>tally {_e(r.get('verdict'))}: {_e(r.get('reason'))}</p>",
           f"<p>now {_e(r.get('now'))}; {_e(r.get('order'))}</p>"]
    win = "; ".join(f"{w['name']} from {w.get('from') or 'the first row'} to {w.get('to')}"
                    for w in r["windows"])
    out.append(f"<p>windows: {_e(win)}</p>")
    f = r.get("filters") or {}
    out.append(f"<p>filters: settled only {_e(f.get('settled_only'))}, checked only "
               f"{_e(f.get('checked_only'))}</p>")
    th = r.get("thresholds") or {}
    out.append(f"<p>unrated while under {_e(th.get('unrated_under_exchanges'))} exchanges "
               f"or {_e(th.get('unrated_under_days'))} days</p>")
    chains = []
    for c in r.get("chains") or []:
        if isinstance(c, dict):
            chains.append(f"{c.get('log')}: {c.get('verdict') or 'skipped'}"
                          + (f" owner {c['owner']}" if c.get("owner") else "")
                          + (f" ({c.get('reason')})" if c.get("verdict") != V.VERIFIED else ""))
    out += _list("chains", chains)
    out += _list("bindings", [f"{b.get('account')} -> {b.get('key')}: "
                              + ("applied (signed binding row)" if b.get("applied")
                                 else str(b.get("finding")))
                              for b in r.get("bindings") or [] if isinstance(b, dict)])
    out += _list("aliases", [f"{a.get('new')} -> {a.get('old')}: "
                             + ("applied (signed by both keys)" if a.get("applied")
                                else str(a.get("finding")))
                             for a in r.get("aliases") or [] if isinstance(a, dict)])
    out += ["<table>", "<thead><tr>"] + [f"<th>{_e(c)}</th>" for c in COLUMNS] \
        + ["</tr></thead>", "<tbody>"]
    for i in r["ids"]:
        for name in names:
            cells = "".join(f'<td class="{k}">{v}</td>' if k else f"<td>{v}</td>"
                            for k, v in _row(i, name))
            out.append(f"<tr>{cells}</tr>")
    out += ["</tbody>", "</table>"]
    notes = []
    for i in r["ids"]:
        for x in i.get("record_broken") or []:
            notes.append(f"{i.get('id')}: BROKEN record: {x}")
        for c in i.get("claims") or []:
            if isinstance(c, dict):
                notes.append(f"{i.get('id')}: DISPUTED {c.get('role')} {c.get('signer')} on "
                             f"{c.get('exchange_id')} at {c.get('at')}: {c.get('reason')}")
        for x in i.get("excluded") or []:
            if isinstance(x, dict):
                notes.append(f"{i.get('id')}: excluded {x.get('exchange_id')} "
                             f"({x.get('side')}, {x.get('counterparty')}): {x.get('reason')}")
        for x in i.get("findings") or []:
            notes.append(f"{i.get('id')}: note: {x}")
    out += _list("per ID", notes)
    out += _list("findings", r.get("findings"))
    defs = r.get("definitions") if isinstance(r.get("definitions"), dict) else {}
    out += _list("definitions", [f"{k}: {v}" for k, v in defs.items()])
    out += _list("proves", [r.get("proves")] if r.get("proves") else [])
    out += _list("does not prove", [r.get("does_not_prove")] if r.get("does_not_prove") else [])
    out += _list("limits", r.get("limits"))
    out += [f"<p>{_e(T.LIMITS[0])}</p>", f'<p class="sentence">{_e(T.SENTENCE)}</p>',
            "</body>", "</html>", ""]
    return "\n".join(out)


def html_cli(argv: list[str]) -> int:
    """`tally html TALLY.json [--out FILE]`; raises T._Usage on bad usage."""
    pos, o = T._parse(argv, {"--out": "value"})
    if len(pos) != 1:
        raise T._Usage("html takes one tally JSON file")
    out = o.get("--out")
    if out and Path(out).exists():
        raise T._Usage(f"--out {Path(out).name} exists; it is never overwritten")
    try:
        page = render_html(load(pos[0]))
    except TallyHtmlError as e:
        print(f"arcaeon tally html: COULD NOT LOOK: {e}; nothing written", file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK
    if out:
        with open(out, "x", encoding="utf-8", newline="\n") as fh:
            fh.write(page)
        print(f"wrote {Path(out).name}")
    else:
        sys.stdout.write(page)
    return V.EXIT_GOOD


def main(argv: list[str] | None = None) -> int:
    return T.main(["html", *(sys.argv[1:] if argv is None else argv)])
