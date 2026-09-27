# SPDX-License-Identifier: MIT
"""GET /status: what arcaeon checked on this machine, in sentences (K102).

The headline counts today's checks from the activity journal (the file
`arcaeon status` reads): "You checked 3 files today. One could not be read
(missing)." A file is a distinct journal target (the journal keeps sha256 of
the path, never the path); its newest check today decides whether it was
read. The reason in brackets comes from a journal row's `reason_word` when
the row carries one; a row without it still counts, and the sentence then
says only that it could not be read.

Below the headline: the last run of each verb, the open COULD NOT LOOKs
(always listed, never folded away), the mandate counts and the balance line,
all from the handler core's `status` (the same answer as GET /v1/status and
`arcaeon status --json`). The page never prints the journal's own path or
any other path.
"""
from __future__ import annotations

from datetime import date, datetime, timezone

from arcaeon import journal
from arcaeon import verdict as V
from arcaeon import words
from arcaeon.serve.pages import common as C

METHODS = ("GET",)

#: Journal verbs that are checks (a look at a file), CLI and HTTP alike.
CHECK_VERBS = frozenset({
    "verify", "reconcile", "audit", "receipt", "evidence-pack", "second-read",
    "mandate", "compact", "vet", "badge",
    "serve:/v1/verify", "serve:/v1/reconcile", "serve:/v1/audit/verify",
    "serve:/v1/receipt/verify", "serve:/v1/evidence-pack/verify",
    "serve:/v1/second-read/compare", "serve:/v1/mandate/check",
    "serve:/v1/handshake/verify",
})


def _local_day(t) -> date | None:
    try:
        return (datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ")
                .replace(tzinfo=timezone.utc).astimezone().date())
    except (TypeError, ValueError):
        return None


def _local_time(t) -> str:
    try:
        return (datetime.strptime(t, "%Y-%m-%dT%H:%M:%SZ")
                .replace(tzinfo=timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M"))
    except (TypeError, ValueError):
        return "time not recorded"


def today_counts(rows: list[dict], today: date | None = None) -> dict:
    """Files checked today (distinct targets), and how their newest check ended."""
    today = today or datetime.now().astimezone().date()
    newest: dict[str, dict] = {}
    for r in rows:
        tgt = r.get("target")
        if r.get("verb") not in CHECK_VERBS or not isinstance(tgt, str) or not tgt:
            continue
        if _local_day(r.get("t")) != today:
            continue
        newest[tgt] = r
    by_exit = {V.EXIT_GOOD: 0, V.EXIT_BAD: 0, V.EXIT_USAGE: 0, V.EXIT_COULD_NOT_LOOK: 0}
    reasons: list[str] = []
    for r in newest.values():
        rc = r.get("exit")
        key = rc if rc in by_exit and not isinstance(rc, bool) else V.EXIT_COULD_NOT_LOOK
        by_exit[key] += 1
        rw = r.get("reason_word")
        if key == V.EXIT_COULD_NOT_LOOK and rw in V.REASON_WORDS and rw not in reasons:
            reasons.append(rw)
    return {"files": len(newest), "good": by_exit[V.EXIT_GOOD], "bad": by_exit[V.EXIT_BAD],
            "usage": by_exit[V.EXIT_USAGE], "could_not_look": by_exit[V.EXIT_COULD_NOT_LOOK],
            "reasons": reasons}


def headline(c: dict) -> tuple[str, str]:
    """(sentence, tone) for today's counts. Nothing checked is not a pass."""
    n = c["files"]
    if n == 0:
        return "You have not checked any files today.", "unknown"
    parts = [f"You checked {n} file{'' if n == 1 else 's'} today."]
    if c["could_not_look"]:
        why = f" ({', '.join(c['reasons'])})" if c["reasons"] else ""
        parts.append(f"{C.count_word(c['could_not_look'])} could not be read{why}.")
    if c["bad"]:
        parts.append(f"{C.count_word(c['bad'])} came back with a bad finding.")
    if c["usage"]:
        parts.append(f"{C.count_word(c['usage'])} could not start (bad usage).")
    if c["good"] == n:
        parts.append("Every one was checked to the end and held.")
        return " ".join(parts), "ok"
    return " ".join(parts), ("bad" if c["bad"] else "unknown")


def _last_run_table(last_run: dict) -> str:
    if not last_run:
        return '<p>No activity recorded yet.</p>'
    rows = []
    for verb, r in sorted(last_run.items(), key=lambda kv: kv[1].get("t") or "",
                          reverse=True):
        word, rc = r.get("word"), r.get("exit")
        t = words.tone(word, rc) if isinstance(word, str) and word else "unknown"
        rows.append(f'<tr><td><code>{C.esc(verb)}</code></td>'
                    f'<td class="state-{t}">{C.esc(str(word))}</td>'
                    f'<td>{C.esc(words.sentence(word, rc))}</td>'
                    f'<td>{C.esc(_local_time(r.get("t")))}</td></tr>')
    return ('<table class="last-run"><tr><th>What ran</th><th>Answer</th>'
            '<th>What it means</th><th>When</th></tr>' + "".join(rows) + "</table>")


def _open_cnl(items: list) -> str:
    n = len(items)
    cls = "open-count state-unknown" if n else "open-count"
    head = f'<p class="{cls}">Open COULD NOT LOOKs: {n}</p>'
    if not n:
        return head + "<p>None open: no file's newest look ended in COULD NOT LOOK.</p>"
    rows = "".join(
        f'<tr class="state-unknown"><td><code>{C.esc(str(x.get("target", ""))[:12])}</code></td>'
        f'<td><code>{C.esc(str(x.get("verb")))}</code></td>'
        f'<td>{C.esc(_local_time(x.get("t")))}</td></tr>' for x in items)
    return (head + "<p>Each file below was last looked at and could not be read to the "
            "end. It stays here until a check on it finishes.</p>"
            '<table class="open-cnl"><tr><th>File (first 12 of its sha256 id)</th>'
            "<th>What ran</th><th>When</th></tr>" + rows + "</table>")


def _mandate(m) -> str:
    if not isinstance(m, dict) or not m.get("sessions"):
        return "<p>No mandate-gated sessions recorded.</p>"
    s = m["sessions"]
    return (f"<p>{s} gated session{'' if s == 1 else 's'}: {m.get('inside', 0)} inside, "
            f"{m.get('outside', 0)} outside, {m.get('could_not_look', 0)} COULD NOT LOOK, "
            f"{m.get('blocked', 0)} blocked, {m.get('cap_exceeded', 0)} cap exceeded, "
            f"{m.get('changes', 0)} mandate file changes.</p>")


def render(req) -> tuple[int, str]:
    from arcaeon.serve import h_misc
    counts = today_counts(journal.read())
    sentence, tone = headline(counts)
    res = h_misc.status({})
    if not isinstance(res, dict) or res.get("exit") != V.EXIT_GOOD:
        detail = C.verdict_block(V.COULD_NOT_LOOK, detail_html=(
            "<p>The status summary could not be read.</p>"))
        last, cnl, mandate, balance = detail, "", "", ""
    else:
        last = _last_run_table(res.get("last_run") or {})
        cnl = _open_cnl(res.get("open_could_not_look") or [])
        mandate = _mandate(res.get("mandate"))
        balance = C.esc(str(res.get("balance") or "not read"))
    journal_note = "" if journal.enabled() else (
        '<p class="note">The activity journal is off (ARCAEON_JOURNAL=0), so nothing new '
        "is being recorded.</p>")
    return 200, C.fill("status.html", active="/status", title="Status",
                       headline=C.esc(sentence), headline_tone=tone,
                       journal_note=journal_note, last_run=last, open_cnl=cnl,
                       mandate=mandate, balance=balance)
