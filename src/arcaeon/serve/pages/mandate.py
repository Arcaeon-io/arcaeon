# SPDX-License-Identifier: MIT
"""GET and POST /mandate: a mandate in sentences, and the last session's
outside rows (K106).

The top of the page is the newest line of this machine's mandate sessions
file (arcaeon.status, K077): when the last gated session ended and how many
of its calls were inside, outside and COULD NOT LOOK. That file holds counts
and a session id only, never a path or a tool name.

The form picks a mandate file (`.json`) under the served root and, if wanted,
a seam ledger (`.jsonl`) a gated proxy wrote. POST runs, through the handler
core (h_core.run_verb, the same code as the CLI):

* `arcaeon mandate explain FILE --json`: the mandate in plain sentences (K074).
  An invalid mandate is not explained; `mandate lint --json` names why. A file
  that is not there or cannot be read is COULD NOT LOOK, never a pass.
* for a picked ledger, first the chain check (h_record.verify, the same code
  as POST /v1/verify, journaled as that route), then the rows of the LAST
  session in it (the session id of the newest row that carries one): every
  `mandate_outside` and `mandate_cap_exceeded` row, and every
  `mandate_could_not_look` row, each listed in its own class. A ledger whose
  chain did not verify still has its rows shown, under its own BROKEN or
  COULD NOT LOOK answer, and marked as unconfirmed.

Both paths go through the server's fence first; a path outside the root is
refused and never opened. Rows are shown by tool, rule, reason and call id;
the mandate path a `mandate_loaded` row carries is never printed.
"""
from __future__ import annotations

import json

from arcaeon import verdict as V
from arcaeon.serve.pages import common as C

METHODS = ("GET", "POST")

OUTSIDE_EVTS = ("mandate_outside", "mandate_cap_exceeded")
CNL_EVT = "mandate_could_not_look"
#: At most this many rows of each kind are listed; the rest are counted.
ROW_LIMIT = 200
#: A ledger bigger than this is not read for rows (its chain is still checked).
LEDGER_READ_LIMIT = 64 * 1024 * 1024


def _select(name: str, label: str, files: list[str], chosen: str, empty: str) -> str:
    opts = [f'<option value="">{C.esc(empty)}</option>']
    for f in files:
        sel = " selected" if f == chosen else ""
        opts.append(f'<option value="{C.esc(f)}"{sel}>{C.esc(f)}</option>')
    return (f'<p><label for="{name}">{C.esc(label)}</label> '
            f'<select id="{name}" name="{name}">' + "".join(opts) + "</select></p>")


def _pickers(req, mandate: str = "", ledger: str = "") -> str:
    if req.fence is None:
        return ('<p class="note">This server has no served root, so there are no files '
                "to pick.</p>")
    mandates = C.list_files(req.fence, suffixes=(".json",))
    if not mandates:
        return '<p class="note">No <code>.json</code> file under the served root.</p>'
    return (_select("mandate", "Mandate file", mandates, mandate, "(choose a mandate file)")
            + _select("ledger", "Ledger a gated session wrote (optional)",
                      C.list_files(req.fence), ledger, "(no ledger)"))


def _last_session_html() -> str:
    from arcaeon import status
    last = status.summarize_mandate(status.read_mandate_sessions()).get("last_session")
    if not isinstance(last, dict):
        return '<p class="last-session">No mandate-gated session recorded on this machine.</p>'
    out, cnl = last.get("outside", 0), last.get("could_not_look", 0)
    tone = "bad" if out else ("unknown" if cnl else "ok")
    from arcaeon.serve.pages.status import _local_time
    when = _local_time(last.get("t"))
    mode = last.get("mode") if isinstance(last.get("mode"), str) else "mode not recorded"
    sentence = (f"The last gated session ended {when} ({mode}): {last.get('inside', 0)} "
                f"inside, {out} outside, {cnl} COULD NOT LOOK.")
    extra = ""
    if cnl:
        extra = (" A call the gate could not judge is not inside; it is listed as "
                 "COULD NOT LOOK in the ledger.")
    return (f'<p class="last-session state-{tone}">{C.esc(sentence + extra)}</p>'
            '<p class="note">Pick that session\'s ledger below to see its rows.</p>')


def _explain(path: str, root) -> tuple[str, bool]:
    """(HTML, explained?) for one fenced mandate file."""
    from arcaeon.serve import h_core
    res = h_core._result(*h_core.run_verb("mandate", ["explain", path, "--json"]))
    rc = res.get("exit")
    if rc == V.EXIT_GOOD and isinstance(res.get("sentences"), list):
        items = "".join(f"<li>{C.esc(C.shown(s, root))}</li>" for s in res["sentences"])
        warns = "".join(f'<li class="state-unknown">{C.esc(C.shown(w, root))}</li>'
                        for w in res.get("warnings") or [])
        html = f'<ul class="mandate-sentences">{items}</ul>'
        if warns:
            html += f'<h3>Warnings</h3><ul class="mandate-warnings">{warns}</ul>'
        return html, True
    if rc == V.EXIT_USAGE:
        lint = h_core._result(*h_core.run_verb("mandate", ["lint", path, "--json"]))
        probs = "".join(f"<li>{C.esc(C.shown(p.get('problem'), root))}</li>"
                        for p in lint.get("problems") or [] if isinstance(p, dict))
        return ('<div class="verdict state-unknown refusal"><p class="verdict-word">Not '
                'explained</p><p class="verdict-sentence">This mandate is not valid, so it '
                "was not explained. Nothing about a session run under it is a pass.</p>"
                f'<ul class="mandate-problems">{probs}</ul></div>'), False
    return C.verdict_block(V.COULD_NOT_LOOK, rc, detail_html=C.result_details(
        res, root, fields=("reason_word", "reason"))), False


def _rows(path) -> tuple[list[dict] | None, str | None]:
    from pathlib import Path
    p = Path(path)
    try:
        if p.stat().st_size > LEDGER_READ_LIMIT:
            return None, "the ledger is too large to list here"
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None, "the ledger could not be read"
    rows = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows, None


def last_session_rows(rows: list[dict]) -> tuple[str | None, list[dict], list[dict]]:
    """(the last session id, its outside rows, its COULD NOT LOOK rows)."""
    sid = next((r["session"] for r in reversed(rows)
                if isinstance(r.get("session"), str) and r["session"]), None)
    if sid is None:
        return None, [], []
    mine = [r for r in rows if r.get("session") == sid]
    return (sid, [r for r in mine if r.get("evt") in OUTSIDE_EVTS],
            [r for r in mine if r.get("evt") == CNL_EVT])


def _row_table(rows: list[dict], cls: str, root, *, cnl: bool) -> str:
    body = []
    for r in rows[:ROW_LIMIT]:
        why = r.get("reason") or ""
        if cnl and r.get("reason_word"):
            why = f"({r['reason_word']}) {why}".strip()
        body.append(f'<tr class="{cls}"><td>{C.esc(str(r.get("seq", "")))}</td>'
                    f'<td><code>{C.esc(str(r.get("tool") or "not named"))}</code></td>'
                    f'<td>{C.esc(str(r.get("rule") or ""))}</td>'
                    f"<td>{C.esc(C.shown(why, root))}</td>"
                    f'<td>{C.esc(str(r.get("rpc_id") or ""))}</td>'
                    f'<td>{C.esc(str(r.get("action") or ""))}</td></tr>')
    more = len(rows) - ROW_LIMIT
    tail = f"<p>And {more} more not listed here.</p>" if more > 0 else ""
    table_cls = "cnl-rows" if cnl else "outside-rows"
    return (f'<table class="{table_cls}"><tr><th>Row</th><th>Tool</th><th>Rule</th>'
            "<th>Why</th><th>Call id</th><th>What happened</th></tr>"
            + "".join(body) + "</table>" + tail)


def _ledger_html(req, ledger: str, path: str, root) -> str:
    from arcaeon.serve import h_record
    res = h_record.verify({"ledger": path})
    C.journal_as("POST", "/v1/verify", {"ledger": path}, res)
    res = res if isinstance(res, dict) else {}
    word, rc = res.get("verdict"), res.get("exit")
    if rc == V.EXIT_USAGE:
        word = None
    head = C.verdict_block(word, rc, detail_html=(
        f'<p class="checked">Ledger: <code>{C.esc(ledger)}</code></p>'
        + C.result_details(res, root, fields=("rows", "first_break", "reason_word",
                                              "reason"))))
    rows, problem = _rows(path)
    if rows is None:
        return head + f'<p class="state-unknown">{C.esc(problem)}.</p>'
    sid, outside, cnl = last_session_rows(rows)
    if sid is None:
        return head + '<p class="state-unknown">No row in this ledger names a session.</p>'
    note = "" if rc == V.EXIT_GOOD else (
        '<p class="unconfirmed state-unknown">The chain did not verify, so the rows '
        "below are unconfirmed.</p>")
    out = (head + note + f'<h2>The last session in this ledger</h2><p class="session">'
           f"Session <code>{C.esc(sid)}</code>: {len(outside)} call"
           f"{'' if len(outside) == 1 else 's'} outside the mandate, {len(cnl)} "
           "COULD NOT LOOK.</p>")
    if outside:
        out += "<h3>Calls outside the mandate</h3>" + _row_table(
            outside, "state-bad", root, cnl=False)
    else:
        out += '<p class="no-outside">No call in the last session was outside.</p>'
    if cnl:
        out += ("<h3>Calls the gate could not judge</h3>"
                + _row_table(cnl, "state-unknown", root, cnl=True))
    return out


def _page(req, *, result_html: str = "", mandate: str = "", ledger: str = "",
          status: int = 200):
    return status, C.fill("mandate.html", active="/mandate", title="Mandate",
                          last_session=_last_session_html(),
                          pickers=_pickers(req, mandate, ledger), result=result_html)


def _refusal(req, msg: str, mandate: str = "", ledger: str = ""):
    html = ('<div class="verdict state-unknown refusal"><p class="verdict-word">Not read'
            f'</p><p class="verdict-sentence">{C.esc(msg)}</p></div>')
    return _page(req, result_html=html, mandate=mandate, ledger=ledger, status=400)


def render(req) -> tuple[int, str]:
    if req.method != "POST":
        return _page(req)
    mandate = (req.form.get("mandate") or "").strip()
    ledger = (req.form.get("ledger") or "").strip()
    if not mandate:
        return _refusal(req, "Choose a mandate file first.", mandate, ledger)
    fields = {"mandate": mandate, **({"ledger": ledger} if ledger else {})}
    body, problem = C.fenced(req.fence, fields)
    if problem:
        return _refusal(req, problem)
    root = req.fence.root if req.fence is not None else None
    explained, _explained = _explain(body["mandate"], root)
    html = (f'<h2>What <code>{C.esc(mandate)}</code> allows</h2>' + explained)
    if ledger:
        html += _ledger_html(req, ledger, body["ledger"], root)
    return _page(req, result_html=html, mandate=mandate, ledger=ledger)
