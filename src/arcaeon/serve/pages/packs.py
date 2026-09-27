# SPDX-License-Identifier: MIT
"""GET and POST /packs: evidence packs under the served root (K104).

GET lists every folder under the root holding an evidence pack's
manifest.json (one that names a `pack_schema`). POST runs the handler core's
evidence-pack verify on one of them, the same code as POST
/v1/evidence-pack/verify and `arcaeon evidence-pack verify`, after the
server's fence has resolved the pack (and the optional pin file) inside the
root. The call is journaled as that route.

The answer shows the pack's verdict and the three counts side by side, how
many of verify's checks came back VERIFIED, BROKEN and COULD NOT LOOK, never
folded into one rate, then each check with its own class. The remote pin
read (network) is not offered here: a remote pin stays COULD NOT LOOK
(network), as the command says without --remote.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from arcaeon import verdict as V
from arcaeon import words
from arcaeon.serve.pages import common as C

METHODS = ("GET", "POST")

MANIFEST = "manifest.json"
#: A manifest bigger than this is not read for the list (it is still verified
#: when named).
MANIFEST_READ_LIMIT = 4 * 1024 * 1024


def list_packs(fence, limit: int = 200) -> list[dict]:
    """[{"path": root-relative folder, "built_at": ...}], sorted, at most `limit`."""
    if fence is None:
        return []
    root = fence.root
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in C.SKIP_DIRS)
        if MANIFEST not in filenames:
            continue
        m = Path(dirpath) / MANIFEST
        try:
            if not fence.inside(m.resolve()) or m.stat().st_size > MANIFEST_READ_LIMIT:
                continue
            doc = json.loads(m.read_text(encoding="utf-8"))
        except (OSError, ValueError, RuntimeError):
            continue
        if not isinstance(doc, dict) or "pack_schema" not in doc:
            continue
        rel = Path(dirpath).relative_to(root).as_posix()
        out.append({"path": rel if rel != "." else ".",
                    "built_at": doc.get("built_at") if isinstance(doc.get("built_at"), str)
                    else None})
        dirnames[:] = []                     # a pack's own folders are not packs
        if len(out) >= limit:
            break
    return sorted(out, key=lambda p: p["path"])


def counts(result: dict) -> dict:
    """VERIFIED / BROKEN / COULD NOT LOOK counts over verify's checks."""
    c = {V.VERIFIED: 0, V.BROKEN: 0, V.COULD_NOT_LOOK: 0}
    for chk in result.get("checks") or []:
        w = chk.get("verdict") if isinstance(chk, dict) else None
        c[w if w in (V.VERIFIED, V.BROKEN) else V.COULD_NOT_LOOK] += 1
    return c


def _list_html(packs: list[dict], chosen: str) -> str:
    if not packs:
        return "<p>No evidence pack under the served root.</p>"
    rows = []
    for p in packs:
        path = C.esc(p["path"])
        mark = ' class="chosen"' if p["path"] == chosen else ""
        rows.append(
            f"<tr{mark}><td><code>{path}</code></td>"
            f"<td>{C.esc(p['built_at'] or 'not recorded')}</td>"
            '<td><form method="post" action="/packs">'
            f'<input type="hidden" name="pack" value="{path}">'
            '<button type="submit">Check this pack</button></form></td></tr>')
    return ('<table class="packs"><tr><th>Pack</th><th>Built at (its own word)</th>'
            "<th></th></tr>" + "".join(rows) + "</table>")


def _counts_html(c: dict) -> str:
    cells = "".join(
        f'<td class="count state-{words.tone(w)}" data-word="{C.esc(w)}">{n}</td>'
        for w, n in c.items())
    heads = "".join(f"<th>{C.esc(w)}</th>" for w in c)
    return f'<table class="counts"><tr>{heads}</tr><tr>{cells}</tr></table>'


def _checks_html(result: dict, root) -> str:
    rows = []
    for chk in result.get("checks") or []:
        if not isinstance(chk, dict):
            continue
        w = chk.get("verdict")
        t = words.tone(w) if isinstance(w, str) and w else "unknown"
        why = chk.get("finding") or chk.get("reason") or ""
        rw = chk.get("reason_word")
        if rw:
            why = f"({rw}) {why}".strip()
        rows.append(f'<tr><td>{C.esc(str(chk.get("check", "")))}</td>'
                    f'<td class="state-{t}">{C.esc(str(w or V.COULD_NOT_LOOK))}</td>'
                    f"<td>{C.esc(C.shown(why, root))}</td></tr>")
    if not rows:
        return ""
    return ('<table class="checks"><tr><th>Check</th><th>Answer</th><th>Why</th></tr>'
            + "".join(rows) + "</table>")


def _page(req, *, result_html: str = "", chosen: str = "", status: int = 200):
    return status, C.fill("packs.html", active="/packs", title="Evidence packs",
                          packs=_list_html(list_packs(req.fence), chosen),
                          result=result_html)


def _refusal(req, msg: str):
    html = ('<div class="verdict state-unknown refusal"><p class="verdict-word">Not checked'
            f'</p><p class="verdict-sentence">{C.esc(msg)}</p></div>')
    return _page(req, result_html=html, status=400)


def render(req) -> tuple[int, str]:
    if req.method != "POST":
        return _page(req)
    from arcaeon.serve import h_evidence
    pack = (req.form.get("pack") or "").strip()
    if not pack:
        return _refusal(req, "Choose a pack first.")
    body = {"pack": pack}
    witness = (req.form.get("witness") or "").strip()
    if witness:
        body["witness"] = witness
    body, problem = C.fenced(req.fence, body)
    if problem:
        return _refusal(req, problem)
    result = h_evidence.verify(body)
    C.journal_as("POST", "/v1/evidence-pack/verify", body, result)
    if not isinstance(result, dict):
        result = {}
    root = req.fence.root if req.fence is not None else None
    word, rc = result.get("verdict"), result.get("exit")
    if rc == V.EXIT_USAGE:
        word = None
    detail = (f'<p class="checked">Pack: <code>{C.esc(pack)}</code></p>'
              + _counts_html(counts(result)) + _checks_html(result, root)
              + C.result_details(result, root, fields=("reason_word", "reason", "error")))
    return _page(req, result_html=C.verdict_block(word, rc, detail_html=detail), chosen=pack)
