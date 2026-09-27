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

NAV_ITEMS = (("/", "Home"),)

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
