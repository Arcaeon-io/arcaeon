# SPDX-License-Identifier: MIT
"""GET and POST /verify: check a ledger's chain from the browser (K103).

Pick a `.jsonl` file under the served root, or paste a ledger's text. Either
way the page runs the handler core's `verify`, the same code as POST
/v1/verify and `arcaeon verify`: a picked file goes through the server's
fence first (a path outside the root is refused and never opened), pasted
text goes to a private temporary file the core removes before it answers.
The call is journaled as POST /v1/verify.

The answer is shown with its class: VERIFIED is state-ok, BROKEN is
state-bad, COULD NOT LOOK (and any word the page cannot read) is
state-unknown, never state-ok. Pasted text arrives from a browser with CRLF
line ends; they are read as LF, since a ledger is lines of JSON.
"""
from __future__ import annotations

from arcaeon import verdict as V
from arcaeon.serve.pages import common as C

METHODS = ("GET", "POST")


def _picker(req, chosen: str = "") -> str:
    files = C.list_files(req.fence)
    if req.fence is None:
        return ('<p class="note">This server has no served root, so there are no files '
                "to pick. Paste a ledger below.</p>")
    if not files:
        return ('<p class="note">No <code>.jsonl</code> file under the served root. '
                "Paste a ledger below.</p>")
    opts = ['<option value="">(choose a file)</option>']
    for f in files:
        sel = " selected" if f == chosen else ""
        opts.append(f'<option value="{C.esc(f)}"{sel}>{C.esc(f)}</option>')
    return ('<label for="ledger">A file under the served root</label> '
            '<select id="ledger" name="ledger">' + "".join(opts) + "</select>")


def _page(req, *, result_html: str = "", chosen: str = "", status: int = 200):
    return status, C.fill("verify.html", active="/verify", title="Verify a ledger",
                          picker=_picker(req, chosen), result=result_html)


def _refusal(req, msg: str, chosen: str = "", status: int = 400):
    html = ('<div class="verdict state-unknown refusal"><p class="verdict-word">Not checked'
            f'</p><p class="verdict-sentence">{C.esc(msg)}</p></div>')
    return _page(req, result_html=html, chosen=chosen, status=status)


def render(req) -> tuple[int, str]:
    if req.method != "POST":
        return _page(req)
    from arcaeon.serve import h_record
    ledger = (req.form.get("ledger") or "").strip()
    content = req.form.get("content") or ""
    if ledger and content.strip():
        return _refusal(req, "Pick a file or paste a ledger, not both.", ledger)
    if not ledger and not content.strip():
        return _refusal(req, "Pick a file or paste a ledger first.")
    if ledger:
        body, problem = C.fenced(req.fence, {"ledger": ledger})
        if problem:
            return _refusal(req, problem)
        label = ledger
    else:
        body = {"content": content.replace("\r\n", "\n")}
        label = "the pasted ledger"
    result = h_record.verify(body)
    C.journal_as("POST", "/v1/verify", body, result)
    root = req.fence.root if req.fence is not None else None
    word = result.get("verdict") if isinstance(result, dict) else None
    rc = result.get("exit") if isinstance(result, dict) else None
    if rc == V.EXIT_USAGE:
        word = None               # the check never started: shown as COULD NOT LOOK
    detail = (f'<p class="checked">Checked: <code>{C.esc(label)}</code></p>'
              + C.result_details(result if isinstance(result, dict) else {}, root))
    return _page(req, result_html=C.verdict_block(word, rc, detail_html=detail),
                 chosen=ledger)
