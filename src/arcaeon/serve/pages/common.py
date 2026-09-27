# SPDX-License-Identifier: MIT
"""What every dashboard page shares: templates, escaping, the plain pages.

Templates live in serve/static/*.html and are filled server-side with
string.Template; every value put into one is escaped here first, except
fragments this module or a page built from escaped parts. A page never
shows a path outside the served root: `shown()` turns a path inside it into
its root-relative form, and pages do not print the journal or home paths.
"""
from __future__ import annotations

import html
import os
import re
import string
from functools import lru_cache
from pathlib import Path

STATIC = Path(__file__).resolve().parents[1] / "static"

esc = html.escape

NAV_ITEMS = (("/", "Home"), ("/status", "Status"), ("/verify", "Verify"),
             ("/packs", "Evidence packs"), ("/readings", "Second read"))

LAYOUT = string.Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$title</title>
<link rel="stylesheet" href="/static/placeholder.css">
<script src="/static/app.js" defer></script>
</head>
<body>
$nav
<main>
<h1>$title</h1>
$main
</main>
</body>
</html>
""")


@lru_cache(maxsize=None)
def template(name: str) -> string.Template:
    return string.Template((STATIC / name).read_text(encoding="utf-8"))


def nav(active: str = "") -> str:
    links = []
    for href, label in NAV_ITEMS:
        cur = ' aria-current="page"' if href == active else ""
        links.append(f'<a href="{href}"{cur}>{esc(label)}</a>')
    return '<nav class="top">' + " ".join(links) + "</nav>"


def fill(name: str, *, active: str = "", **values: str) -> str:
    """The named template with nav and every value (already HTML) filled in."""
    return template(name).substitute(nav=nav(active), **values)


def simple_page(title: str, main_html: str) -> str:
    """A small page: `main_html` is trusted HTML, `title` is escaped."""
    return LAYOUT.substitute(title=esc(title), nav=nav(), main=f"<p>{main_html}</p>")


def unauthorized(*, used: bool = False) -> str:
    first = ("That sign-in link was already used or has expired. "
             if used else "This page needs a sign-in. ")
    return simple_page("Sign in", esc(first) + "Run <code>arcaeon open</code> for a fresh "
                       "link. Each link works once, for a short while.")


def could_not_finish(exc_name: str) -> str:
    return LAYOUT.substitute(
        title="COULD NOT LOOK", nav=nav(),
        main=('<div class="verdict state-unknown"><p class="verdict-word">COULD NOT LOOK</p>'
              f'<p class="verdict-sentence">The page could not finish '
              f'({esc(exc_name)}). Nothing was shown as a pass.</p></div>'))


def shown(text, root) -> str:
    """`text` with the served root's path taken off (paths inside it read as
    root-relative). Not escaped."""
    s = "" if text is None else str(text)
    if not root or not s:
        return s
    r = str(root).rstrip("\\/")
    for form in {r, r.replace("\\", "/"), r.replace("\\", "\\\\")}:
        flags = re.IGNORECASE if os.name == "nt" else 0
        s = re.sub(re.escape(form) + r"[\\/]+", "", s, flags=flags)
        s = re.sub(re.escape(form), ".", s, flags=flags)
    return s


NUMBER_WORDS = ("No", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight",
                "Nine", "Ten")


def count_word(n: int) -> str:
    """A count that opens a sentence: One, Two ... Ten, then digits."""
    return NUMBER_WORDS[n] if 0 <= n < len(NUMBER_WORDS) else str(n)


def verdict_block(word, exit_code=None, *, detail_html: str = "") -> str:
    """The verdict word, its class (state-ok / state-bad / state-unknown, from
    arcaeon.words.tone) and its plain sentence. COULD NOT LOOK is never ok."""
    from arcaeon import words
    if not (isinstance(word, str) and word):     # no word at all: never a pass
        word, exit_code = "COULD NOT LOOK", None
    t = words.tone(word, exit_code)
    return (f'<div class="verdict state-{t}"><p class="verdict-word">{esc(word)}</p>'
            f'<p class="verdict-sentence">{esc(words.sentence(word, exit_code))}</p>'
            f"{detail_html}</div>")


#: Folders a file picker never walks into.
SKIP_DIRS = frozenset({".git", "__pycache__", "node_modules", ".venv", "venv"})


def list_files(fence, suffixes=(".jsonl",), limit: int = 500) -> list[str]:
    """Root-relative paths (forward slashes) of files under the fenced root,
    sorted, at most `limit`. Symlinked folders are not followed, and every
    file must resolve inside the root: the fence decides, not the walk."""
    if fence is None:
        return []
    out: list[str] = []
    root = fence.root
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if not name.lower().endswith(tuple(suffixes)):
                continue
            p = Path(dirpath) / name
            try:
                if not fence.inside(p.resolve()):
                    continue
            except (OSError, RuntimeError):
                continue
            out.append(p.relative_to(root).as_posix())
            if len(out) >= limit:
                return out
    return out


def fenced(fence, body: dict) -> tuple[dict | None, str | None]:
    """(body with its path fields fenced and resolved, None), or (None, the
    plain refusal). No fence: every path field is refused."""
    from arcaeon.serve import fence as F
    if fence is None:
        if any(isinstance(body.get(f), str) and body.get(f) for f in F.PATH_FIELDS):
            return None, "This server has no served root, so it opens no files."
        return body, None
    try:
        return fence.apply(body), None
    except F.OutsideRoot as e:
        return None, (f"That path (`{e.field}`) is outside the folder this server "
                      "answers for, so it was not opened.")


def journal_as(method: str, path: str, body: dict, result) -> None:
    """Journal a page's check as the JSON route it stands for (K015)."""
    from arcaeon.serve import routes as R
    from arcaeon.serve import server as S
    route = R.find(method, path)
    if route is not None:
        S.journal_call(route, body, result)


def result_details(res: dict, root, fields=("rows", "first_break", "reason_word",
                                             "reason", "looked_for", "where", "error")) -> str:
    """A small definition list of the answer's fields, paths shown root-relative."""
    from arcaeon import words
    items = []
    for k in fields:
        v = res.get(k)
        if v is None or v == "" or v == []:
            continue
        text = shown(v, root)
        if k == "reason_word":
            why = words.reason_sentence(v)
            text = f"{v}: {why}" if why else str(v)
        items.append(f"<dt>{esc(k.replace('_', ' '))}</dt><dd>{esc(text)}</dd>")
    return '<dl class="details">' + "".join(items) + "</dl>" if items else ""
