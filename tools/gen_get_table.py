# SPDX-License-Identifier: MIT
"""Generate the `connect` table on the site's get page from the client catalog (K123).

    py tools/gen_get_table.py                       print the block
    py tools/gen_get_table.py --site DIR --check    exit 1 if DIR/get.html has drifted
    py tools/gen_get_table.py --site DIR --write    replace the block in DIR/get.html

The block sits between two markers in get.html:

    <!-- connect-table:start (tools/gen_get_table.py writes this; do not edit by hand) -->
    <!-- connect-table:end -->

Each row is one client from arcaeon.connect.catalog: the command, the file it
keeps on Windows, macOS and Linux (as a user would type it there: `~`,
`%APPDATA%`), and the exact JSON `arcaeon connect <client>` merges into it.
The JSON comes from connect.cli.merge_json, so the page and the command read
the same code. Two things that differ from machine to machine are fixed for
the page: the launch form is the installed one (`arcaeon mcp`, what pipx or
pip puts on the path; `connect` itself may print a uvx or absolute-interpreter
form on a given machine), and paths are shown for another machine on every OS,
never this one's real home. Reads the catalog and one HTML file; no network.
"""
from __future__ import annotations

import argparse
import contextlib
import html
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from arcaeon.connect import catalog as C  # noqa: E402
from arcaeon.connect import cli as CC  # noqa: E402

START = ("<!-- connect-table:start (tools/gen_get_table.py writes this; "
         "do not edit by hand) -->")
END = "<!-- connect-table:end -->"
#: The launch form a user has after the installer, pipx or pip.
PUBLIC_FORM = {"command": "arcaeon", "args": ["mcp"]}
OS_LABEL = {"windows": "Windows", "macos": "Mac", "linux": "Linux"}
INDENT = "      "


@contextlib.contextmanager
def public_view():
    """Fix the launch form and treat every OS as another machine's, for the page."""
    saved = (CC.launch_form, C.current_os)
    home_override = os.environ.pop(C.HOME_ENV, None)
    CC.launch_form = lambda *a, **k: dict(PUBLIC_FORM)
    C.current_os = lambda: "page"
    try:
        yield
    finally:
        CC.launch_form, C.current_os = saved
        if home_override is not None:
            os.environ[C.HOME_ENV] = home_override


def rows() -> list[dict]:
    """One dict per catalog client, in catalog order: what the page shows."""
    out = []
    with public_view():
        for e in C.CATALOG:
            r = {"client": e.name, "title": e.title, "transport": e.transport,
                 "command": f"arcaeon connect {e.name}", "files": {}, "unconfirmed": [],
                 "snippet": None, "says": None}
            if e.writes_file:
                for os_name in C.OSES:
                    path = C.config_path(e, os_name)
                    if path:
                        r["files"][os_name] = path
                        if not C.confirmed_for(e, os_name):
                            r["unconfirmed"].append(os_name)
                r["snippet"] = json.dumps(CC.merge_json(e), indent=2)
            elif e.transport == "http-openapi":
                r["says"] = (f"Nothing to write. Point the framework at "
                             f"{CC.DEFAULT_URL}/openapi.json on a running arcaeon serve; "
                             "the token is in ~/.arcaeon/serve.token.")
            else:
                r["says"] = (f"Nothing to write. {e.title} reaches outside tools only at a "
                             "public HTTPS address, and arcaeon serve binds 127.0.0.1 "
                             f"only, so it {CC.DEPLOY_LINE}.")
            out.append(r)
    return out


def _cell_files(r: dict) -> str:
    if not r["files"]:
        return "none"
    parts = []
    for os_name, path in r["files"].items():
        mark = " (not stated in the app's docs; check it first)" if os_name in r["unconfirmed"] else ""
        parts.append(f"{OS_LABEL[os_name]}: <code>{html.escape(path, quote=False)}</code>{mark}")
    return "<br>".join(parts)


def render_block(nl: str = "\n") -> str:
    lines = [START, INDENT + '<div class="table-wrap"><table>',
             INDENT + "  <tr><th>App</th><th>Command</th><th>File</th><th>What goes in it</th></tr>"]
    for r in rows():
        what = (f"<pre><code>{html.escape(r['snippet'], quote=False)}</code></pre>"
                if r["snippet"] else html.escape(r["says"], quote=False))
        lines.append(INDENT + f"  <tr><td>{html.escape(r['title'], quote=False)}</td>"
                     f"<td><code>{html.escape(r['command'], quote=False)}</code></td>"
                     f"<td>{_cell_files(r)}</td><td>{what}</td></tr>")
    lines += [INDENT + "</table></div>", INDENT + END]
    return nl.join("\n".join(lines).split("\n"))


def current_block(page: str) -> str | None:
    """The block as it stands in `page`, markers included, or None."""
    i = page.find(START)
    j = page.find(END, i + 1) if i >= 0 else -1
    if i < 0 or j < 0:
        return None
    return page[i:j + len(END)]


def _nl(page: str) -> str:
    return "\r\n" if "\r\n" in page else "\n"


def main(argv: list[str] | None = None) -> int:
    assert __doc__ is not None, "gen_get_table.py needs its module docstring"
    ap = argparse.ArgumentParser(prog="gen_get_table.py", description=__doc__.splitlines()[0])
    ap.add_argument("--site", help="the site checkout holding get.html")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--check", action="store_true", help="exit 1 if get.html has drifted")
    g.add_argument("--write", action="store_true", help="replace the block in get.html")
    a = ap.parse_args(argv)
    if not (a.check or a.write):
        print(render_block())
        return 0
    if not a.site:
        print("gen_get_table.py: --check and --write need --site DIR", file=sys.stderr)
        return 2
    page_path = Path(a.site) / "get.html"
    try:
        raw = page_path.read_bytes()
    except OSError as exc:
        print(f"gen_get_table.py: could not read {page_path}: {exc}", file=sys.stderr)
        return 3
    page = raw.decode("utf-8")
    have = current_block(page)
    if have is None:
        print(f"gen_get_table.py: {page_path} has no connect-table markers", file=sys.stderr)
        return 3
    want = render_block(_nl(page))
    if a.check:
        if have == want:
            print(f"get.html connect table matches the catalog ({len(C.CATALOG)} clients)")
            return 0
        print("get.html connect table has drifted from the catalog; run with --write")
        return 1
    if have != want:
        page_path.write_bytes(page.replace(have, want).encode("utf-8"))
        print(f"get.html connect table written ({len(C.CATALOG)} clients)")
    else:
        print("get.html connect table already matches; nothing written")
    return 0


if __name__ == "__main__":
    sys.exit(main())
