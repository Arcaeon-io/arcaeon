# SPDX-License-Identifier: LicenseRef-Arcaeon-Software-License-and-Intellectual-Property-Notice
"""GET /pins: every pin in the pin files under the served root.

A pin file is a `.jsonl` file whose first line is a witness pin (a JSON
object carrying `namespace`, `rows`, `chain` and `received_at`). For each one
the page first checks the file the way `arcaeon verify --witness` does before
it trusts a pin: every line must parse and pass the strict pin rules
(`witness.strict_pin`), and the file's own pin chain must verify
(`WitnessStore.verify`). The answer is VERIFIED, BROKEN or COULD NOT LOOK for
that file; a file that fails the strict rules lists no pins, since no reader
trusts any pin in it.

A pin carries fingerprints and times only: the namespace, the row count, the
ledger's chain at that row, the publisher's `as_of` and the witness's
`received_at`. The page shows exactly those, and never opens a ledger, so a
ledger's contents never reach it. A pin records no assistant label and no
assistant name, and the page says so rather than invent one.

GET /pins?file=F&line=N shows one pin as a receipt the browser can print,
with the command that checks a ledger against it. F goes through the
server's fence like every other path.
"""
from __future__ import annotations

import json
import os
import shlex
from pathlib import Path

from arcaeon import verdict as V
from arcaeon.serve.pages import common as C

METHODS = ("GET",)

#: A pin file bigger than this is not read.
READ_LIMIT = 8 * 1024 * 1024
#: The keys that mark a line as a witness pin (WitnessStore.record writes them).
PIN_KEYS = frozenset({"namespace", "rows", "chain", "received_at"})
#: The fields a pin carries, in the order the page shows them.
FIELDS = (("namespace", "Namespace"), ("rows", "Rows"), ("chain", "Chain"),
          ("as_of", "Publisher's time (as_of)"),
          ("received_at", "Witness's time (received_at)"))
NO_ASSISTANT = ("A pin records no assistant label and no assistant name, so this page "
                "shows none. It shows fingerprints and times only, never a ledger's "
                "contents.")


def _first_object(path: Path):
    """The first non-blank line of `path` parsed, or None."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            raw = raw.strip()
            if raw:
                try:
                    return json.loads(raw)
                except (ValueError, RecursionError):
                    return None
    return None


def is_pin_file(path: Path) -> bool:
    try:
        if not path.is_file() or path.stat().st_size > READ_LIMIT:
            return False
        first = _first_object(path)
    except OSError:
        return False
    return isinstance(first, dict) and PIN_KEYS <= set(first)


def list_pin_files(fence, limit: int = 200) -> list[str]:
    """Root-relative paths of the pin files under the root, sorted."""
    return [f for f in C.list_files(fence, limit=2000)
            if is_pin_file(fence.root / f)][:limit]


def check(path: Path) -> tuple[str, str, list[dict]]:
    """(verdict word, plain reason, pins) for one pin file. The pins are
    empty unless every line passed the strict pin rules."""
    from arcaeon.record.ledger.witness import WitnessStore, strict_pin, PinShapeError
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
    except OSError as e:
        return V.COULD_NOT_LOOK, f"the pin file could not be read ({type(e).__name__})", []
    pins = []
    for i, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            rec = json.loads(raw)
        except (ValueError, RecursionError):
            return V.COULD_NOT_LOOK, f"line {i} does not parse", []
        if not (isinstance(rec, dict) and {"namespace", "rows", "chain"} <= set(rec)):
            return V.COULD_NOT_LOOK, f"line {i} is not a witness pin", []
        try:
            strict_pin(rec)
        except PinShapeError as e:
            return V.COULD_NOT_LOOK, f"line {i} fails the strict pin rules ({e})", []
        pins.append({**rec, "_line": len(pins) + 1})
    if not pins:
        return V.COULD_NOT_LOOK, "the pin file holds no pins", []
    wv = WitnessStore(path).verify()
    ok = wv.get("ok")
    if ok is True:
        return V.VERIFIED, f"{C.count_word(len(pins))} pin(s); the pin chain verifies", pins
    if ok is False:
        return V.BROKEN, f"the pin chain does not verify ({wv.get('first_break')})", pins
    return (V.COULD_NOT_LOOK, "some pins predate the pin chain, so the file could not "
            "be checked in full", pins)


def _text(v) -> str:
    return "not recorded" if v is None or v == "" else str(v)


def _file_block(rel: str, word: str, reason: str) -> str:
    exit_code = {V.VERIFIED: V.EXIT_GOOD, V.BROKEN: V.EXIT_BAD}.get(word, V.EXIT_COULD_NOT_LOOK)
    detail = (f'<p class="checked">Pin file: <code>{C.esc(rel)}</code></p>'
              f'<dl class="details"><dt>why</dt><dd>{C.esc(reason)}</dd></dl>')
    return C.verdict_block(word, exit_code, detail_html=detail)


def _pins_table(rel: str, pins: list[dict]) -> str:
    heads = ["File", "Line"] + [label for _, label in FIELDS] + [""]
    rows = []
    for p in pins:
        n = p["_line"]
        cells = [f"<td><code>{C.esc(rel)}</code></td>", f"<td>{n}</td>"]
        cells += [f"<td>{C.esc(_text(p.get(k)))}</td>" for k, _ in FIELDS]
        href = "/pins?file=" + C.esc(_quote(rel)) + f"&amp;line={n}"
        cells.append(f'<td><a href="{href}">Receipt</a></td>')
        rows.append("<tr>" + "".join(cells) + "</tr>")
    return ('<table class="pins"><tr>' + "".join(f"<th>{C.esc(h)}</th>" for h in heads)
            + "</tr>" + "".join(rows) + "</table>")


def _quote(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="/")


def _section(rel: str, word: str, reason: str, pins: list[dict]) -> str:
    return (f'<section class="pinfile" data-file="{C.esc(rel)}">'
            f"<h2>{C.esc(rel)}</h2>" + _file_block(rel, word, reason)
            + (_pins_table(rel, pins) if pins else "") + "</section>")


def _page(req, main_html: str, status: int = 200):
    return status, C.fill("pins.html", active="/pins", title="Pins",
                          no_assistant=C.esc(NO_ASSISTANT), main=main_html)


def _refusal(req, msg: str):
    html = ('<div class="verdict state-unknown refusal"><p class="verdict-word">Not shown'
            f'</p><p class="verdict-sentence">{C.esc(msg)}</p></div>')
    return _page(req, html, status=400)


def _list(req):
    if req.fence is None:
        return _page(req, '<p class="note">This server has no served root, so it opens '
                          "no pin file.</p>")
    files = list_pin_files(req.fence)
    if not files:
        return _page(req, "<p>No pin file under the served root.</p>")
    parts = []
    for rel in files:
        word, reason, pins = check(req.fence.root / rel)
        parts.append(_section(rel, word, reason, pins))
    return _page(req, "".join(parts))


def _receipt(req, rel: str):
    body, problem = C.fenced(req.fence, {"witness": rel})
    if problem:
        return _refusal(req, problem.replace("`witness`", "`file`"))
    path = Path(body["witness"])
    shown = Path(os.path.relpath(path, req.fence.root)).as_posix()
    if not is_pin_file(path):
        return _refusal(req, f"{shown} is not a pin file under the served root.")
    line = req.query.get("line", "")
    if not line.isdigit():
        return _refusal(req, "The line must be a whole number, the pin's line in its file.")
    word, reason, pins = check(path)
    if not pins:
        return _refusal(req, f"{shown}: {reason}. No pin in it is shown.")
    n = int(line)
    pin = next((p for p in pins if p["_line"] == n), None)
    if pin is None:
        return _refusal(req, f"No pin on line {n} of {shown}.")
    items = [(label, _text(pin.get(k))) for k, label in FIELDS]
    items += [("Pin digest (self)", _text(pin.get("self"))),
              ("Previous pin's digest (prev)", _text(pin.get("prev")))]
    dl = "".join(f"<dt>{C.esc(k)}</dt><dd>{C.esc(v)}</dd>" for k, v in items)
    cmd = (f"arcaeon verify YOUR_LEDGER.jsonl --witness {shlex.quote(shown)} "
           f"--ns {shlex.quote(str(pin['namespace']))}")
    html = (f'<section class="pinfile" data-file="{C.esc(shown)}">'
            + _file_block(shown, word, reason)
            + f'<div class="receipt"><h2>Pin receipt: line {n} of '
              f"<code>{C.esc(shown)}</code></h2><dl>{dl}</dl></div>"
            + '<p>Check it yourself: run this against your copy of the ledger. It '
              "compares the ledger's chain at the pinned row with this pin's chain.</p>"
            + f'<pre class="check-yourself"><code>{C.esc(cmd)}</code></pre>'
            + '<p><button type="button" data-print>Print receipt</button> '
              '<a href="/pins">All pins</a></p>'
            + _pins_table(shown, [pin]) + "</section>")
    return _page(req, html)


def render(req) -> tuple[int, str]:
    rel = (req.query.get("file") or "").strip()
    if rel:
        return _receipt(req, rel)
    return _list(req)
