# SPDX-License-Identifier: MIT
"""GET and POST /readings: two readers, one frozen sentence, side by side (K105).

Pick two readings ledgers under the served root (the `a` side and the `b`
side). POST runs the handler core's readings compare, the same code as POST
/v1/second-read/compare and `arcaeon second-read compare`, after the server's
fence has resolved both paths inside the root; the call is journaled as that
route.

The answer shows the compare's verdict with its class, then the two integers
side by side, `disagreed` and `read`, never one rate. Under twenty claims
read (readings_compare.INFORMATIVE_AT) the page says "not yet informative".
When the counts were not computed (a ledger BROKEN, missing, empty), the page
says so and why, instead of printing numbers nobody computed.

Every DISAGREED claim is listed with both readings and both reader ids (and
each side's provider as the row asserts it). MISSING and COULD NOT LOOK claims
are listed too, in their own classes, never folded away. Paths in any answer
are shown root-relative.
"""
from __future__ import annotations

from arcaeon import verdict as V
from arcaeon.serve.pages import common as C

METHODS = ("GET", "POST")

NOT_YET = "not yet informative"


def informative_at() -> int:
    from arcaeon.prove.readings_compare import INFORMATIVE_AT
    return INFORMATIVE_AT


def _select(name: str, label: str, files: list[str], chosen: str) -> str:
    opts = ['<option value="">(choose a readings ledger)</option>']
    for f in files:
        sel = " selected" if f == chosen else ""
        opts.append(f'<option value="{C.esc(f)}"{sel}>{C.esc(f)}</option>')
    return (f'<p><label for="{name}">{C.esc(label)}</label> '
            f'<select id="{name}" name="{name}">' + "".join(opts) + "</select></p>")


def _pickers(req, a: str = "", b: str = "") -> str:
    if req.fence is None:
        return ('<p class="note">This server has no served root, so there are no '
                "ledgers to pick.</p>")
    files = C.list_files(req.fence)
    if not files:
        return '<p class="note">No <code>.jsonl</code> file under the served root.</p>'
    return (_select("a", "First reader's ledger (a)", files, a)
            + _select("b", "Second reader's ledger (b)", files, b))


def _counts_html(summary: dict, root) -> str:
    d, r = summary.get("disagreed"), summary.get("read")
    if not (isinstance(d, int) and isinstance(r, int)):
        why = summary.get("counts_reason") or "the comparison did not get that far"
        return ('<p class="counts-not-computed state-unknown">The counts were not '
                f"computed: {C.esc(C.shown(why, root))}</p>")
    table = ('<table class="counts"><tr><th>Disagreed</th><th>Read by both</th></tr>'
             f'<tr><td class="count" data-count="disagreed">{d}</td>'
             f'<td class="count" data-count="read">{r}</td></tr></table>')
    plural = "" if r == 1 else "s"
    line = (f'<p class="counts-sentence">The readers disagreed on {d} of the {r} '
            f"claim{plural} both of them read.</p>")
    n = informative_at()
    if r < n:
        line += (f'<p class="not-yet-informative state-unknown">{NOT_YET}: fewer than '
                 f"{n} claims read ({r}), so these counts are shown but say little "
                 "yet.</p>")
    return table + line


def _side(s) -> tuple[str, str, str]:
    s = s if isinstance(s, dict) else {}
    return (str(s.get("reading") or "not read"), str(s.get("reader_id") or "not recorded"),
            str(s.get("provider") or "not recorded"))


def _disagreements_html(claims: list) -> str:
    rows = []
    for c in claims:
        if not isinstance(c, dict) or c.get("status") != "DISAGREED":
            continue
        ra, ia, pa = _side(c.get("a"))
        rb, ib, pb = _side(c.get("b"))
        rows.append(f'<tr class="disagreed"><td class="claim"><code>'
                    f'{C.esc(str(c.get("claim_id")))}</code></td>'
                    f'<td class="reading-a">{C.esc(ra)}</td>'
                    f'<td class="reader-a">{C.esc(ia)}</td>'
                    f'<td class="provider-a">{C.esc(pa)}</td>'
                    f'<td class="reading-b">{C.esc(rb)}</td>'
                    f'<td class="reader-b">{C.esc(ib)}</td>'
                    f'<td class="provider-b">{C.esc(pb)}</td></tr>')
    if not rows:
        return '<p class="no-disagreements">No claim was read differently by the two readers.</p>'
    return ("<h2>Where the readers disagreed</h2>"
            '<table class="disagreements"><tr><th>Claim</th><th>Reading (a)</th>'
            "<th>Reader id (a)</th><th>Provider (a), as asserted</th><th>Reading (b)</th>"
            "<th>Reader id (b)</th><th>Provider (b), as asserted</th></tr>"
            + "".join(rows) + "</table>")


def _others_html(claims: list, root) -> str:
    rows = []
    for c in claims:
        if not isinstance(c, dict):
            continue
        st = c.get("status")
        if st == V.MISSING:
            other = "b" if c.get("side") == "a" else "a"
            why, cls = f"read only in ledger {other}", "state-bad"
        elif st == V.COULD_NOT_LOOK:
            why = C.shown(c.get("reason") or "could not be lined up", root)
            cls = "state-unknown"
        else:
            continue
        rows.append(f'<tr class="{cls}"><td><code>{C.esc(str(c.get("claim_id")))}</code>'
                    f"</td><td>{C.esc(st)}</td><td>{C.esc(why)}</td></tr>")
    if not rows:
        return ""
    return ("<h2>Claims that could not be lined up</h2>"
            '<table class="unmatched"><tr><th>Claim</th><th>Answer</th><th>Why</th></tr>'
            + "".join(rows) + "</table>")


def _page(req, *, result_html: str = "", a: str = "", b: str = "", status: int = 200):
    return status, C.fill("readings.html", active="/readings", title="Second read",
                          pickers=_pickers(req, a, b), result=result_html)


def _refusal(req, msg: str, a: str = "", b: str = ""):
    html = ('<div class="verdict state-unknown refusal"><p class="verdict-word">Not '
            f'compared</p><p class="verdict-sentence">{C.esc(msg)}</p></div>')
    return _page(req, result_html=html, a=a, b=b, status=400)


def render(req) -> tuple[int, str]:
    if req.method != "POST":
        return _page(req)
    from arcaeon.serve import h_readings
    a = (req.form.get("a") or "").strip()
    b = (req.form.get("b") or "").strip()
    if not a or not b:
        return _refusal(req, "Choose both readings ledgers first.", a, b)
    body, problem = C.fenced(req.fence, {"a": a, "b": b})
    if problem:
        return _refusal(req, problem)
    result = h_readings.compare(body)
    C.journal_as("POST", "/v1/second-read/compare", body, result)
    if not isinstance(result, dict):
        result = {}
    root = req.fence.root if req.fence is not None else None
    word, rc = result.get("verdict"), result.get("exit")
    if rc == V.EXIT_USAGE:
        word = None
    claims = result.get("claims") if isinstance(result.get("claims"), list) else []
    summary = result.get("summary") if isinstance(result.get("summary"), dict) else {}
    indep = result.get("independence")
    indep_html = (f'<p class="independence">Readers, as the rows describe them: '
                  f"{C.esc(str(indep).replace('_', ' '))}.</p>" if indep else "")
    detail = (f'<p class="checked">Compared: <code>{C.esc(a)}</code> (a) with '
              f'<code>{C.esc(b)}</code> (b)</p>' + _counts_html(summary, root) + indep_html
              + C.result_details(result, root, fields=("reason_word", "reason", "error")))
    computed = isinstance(summary.get("read"), int)
    extra = (_disagreements_html(claims) if computed else "") + _others_html(claims, root)
    return _page(req, result_html=C.verdict_block(word, rc, detail_html=detail) + extra,
                 a=a, b=b)
