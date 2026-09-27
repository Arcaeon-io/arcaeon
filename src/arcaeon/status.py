# SPDX-License-Identifier: MIT
"""`arcaeon status`: what this install did lately, read from the activity journal.

    last run per verb    the newest journal line for each verb: word and time
    open COULD NOT LOOKs targets whose newest journal line exited 3 (a look
                         that never completed and has not been retried green)
    balance              the hosted-witness balance, ONLY when ARCAEON_KEY is
                         set; otherwise "balance: not checked, no key" and no
                         request is made
    mandate              counts from every mandate-gated session that ended on
                         this machine (K077): inside, outside, could not look,
                         blocked, cap exceeded, mandate file changed

Mandate counts. Every surface that runs the mandate gate (the stdio proxy,
the HTTP forward proxy, call_proxy) appends one line per session, at session
end, to ~/.arcaeon/mandate_sessions.jsonl (same directory as the journal,
same ARCAEON_JOURNAL=0 off switch, same never-in-the-way rule). The line holds
the session id (which the seam ledger's own rows carry, so a count can be lined
up with its ledger), the mode, the mandate file's sha256 and the counts: never
a path, a tool name or an argument. The seam ledger stays the record; this
file only lets `status` add them up without being told where every ledger is.

The journal holds sha256(target), never the path, so an open COULD NOT LOOK is
named by the first 12 hex digits of that hash. `--json` prints the same facts
as one object. Offline unless a key is set; the one request is
arcaeon.remote.balance(), which never consumes a credit.
"""
from __future__ import annotations

import json
import os
import sys
import time

from arcaeon import journal
from arcaeon import verdict as V

USAGE = ("usage: arcaeon status [--json]\n"
         "What arcaeon did lately on this machine, from the local activity journal "
         "(~/.arcaeon/activity.jsonl, or $ARCAEON_HOME): the last run of each verb, "
         "the targets whose newest look could not finish, and, only when ARCAEON_KEY "
         "is set, your hosted-witness balance.")

NO_KEY = "not checked, no key"

#: One line per mandate-gated session, beside the activity journal.
MANDATE_FILENAME = "mandate_sessions.jsonl"
#: The counts a session line carries, in the order `status` prints them.
MANDATE_COUNTS = ("inside", "outside", "could_not_look", "blocked", "cap_exceeded",
                  "changes")


def mandate_path():
    return journal.home() / MANDATE_FILENAME


def _count(v) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0


def note_mandate_session(session, fields: dict, *, mode, mandate_status,
                         mandate_file_sha256) -> bool:
    """Append one session's mandate counts. `fields` is what the surface put
    in its `session_end` row (`mandate_inside`, `mandate_outside`, ...).
    True if written; False if the journal is off or anything went wrong.
    Never raises: a count that cannot be written never changes a session."""
    try:
        if not journal.enabled():
            return False
        row = {"t": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "session": str(session) if session is not None else None,
               "mode": mode, "mandate_status": mandate_status,
               "mandate_file_sha256": mandate_file_sha256}
        for k in MANDATE_COUNTS:
            row[k] = _count(fields.get(f"mandate_{k}"))
        d = journal.home()
        d.mkdir(parents=True, exist_ok=True)
        with open(d / MANDATE_FILENAME, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(row, separators=(",", ":")) + "\n")
        return True
    except Exception:  # noqa: BLE001  never in the way of the session
        return False


def read_mandate_sessions(p: str | os.PathLike | None = None) -> list[dict]:
    """Every readable session line, oldest first; a bad line is skipped."""
    from pathlib import Path
    p = Path(p) if p is not None else mandate_path()
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def summarize_mandate(rows: list[dict]) -> dict:
    """Totals across session lines, split by mode, plus the newest session."""
    totals = {k: 0 for k in MANDATE_COUNTS}
    by_mode: dict[str, int] = {}
    for r in rows:
        for k in MANDATE_COUNTS:
            totals[k] += _count(r.get(k))
        mode = r.get("mode") if isinstance(r.get("mode"), str) else "unknown"
        by_mode[mode] = by_mode.get(mode, 0) + 1
    last = None
    if rows:
        r = rows[-1]
        last = {"t": r.get("t"), "session": r.get("session"), "mode": r.get("mode"),
                **{k: _count(r.get(k)) for k in MANDATE_COUNTS}}
    return {"sessions": len(rows), **totals, "sessions_by_mode": by_mode,
            "last_session": last}


def summarize(rows: list[dict]) -> dict:
    """last-run-per-verb and open COULD NOT LOOKs from journal rows (oldest first)."""
    last: dict[str, dict] = {}
    newest_by_target: dict[str, dict] = {}
    for r in rows:
        last[r["verb"]] = {"word": r.get("word"), "exit": r.get("exit"), "t": r.get("t")}
        tgt = r.get("target")
        if isinstance(tgt, str) and tgt:
            newest_by_target[tgt] = r
    open_cnl = [{"target": t, "verb": r["verb"], "t": r.get("t")}
                for t, r in newest_by_target.items() if r.get("exit") == V.EXIT_COULD_NOT_LOOK]
    open_cnl.sort(key=lambda x: x.get("t") or "", reverse=True)
    return {"last_run": last, "open_could_not_look": open_cnl}


def balance_sentence(out: dict) -> str:
    """One plain sentence for a /api/balance answer (credits and free tier)."""
    credits = out.get("credit_balance", out.get("balance"))
    parts = []
    if isinstance(credits, (int, float)):
        parts.append(f"{credits:g} credits left")
    ft = out.get("free_tier")
    if isinstance(ft, dict) and ft.get("used") is not None:
        cap = ft.get("cap")
        parts.append(f"{ft['used']} of {cap if cap is not None else 'unlimited'} "
                     f"free pins used this month")
    return ", ".join(parts) if parts else "balance read, but it carried no credit count"


def check_balance() -> dict:
    """{"checked": False, "reason": NO_KEY} with no key (no request made), else
    the witness's answer plus a `sentence`."""
    from arcaeon import remote
    if not remote.key():
        return {"checked": False, "reason": NO_KEY}
    out = remote.balance()
    res = {"checked": True, **out}
    if out.get("ok"):
        res["sentence"] = balance_sentence(out)
    elif out.get("status") == 0:
        res["sentence"] = f"{V.COULD_NOT_LOOK} (network): {out.get('error', 'no answer')}"
    else:
        res["sentence"] = f"the witness said no ({out.get('error', out.get('status'))})"
    return res


def status(argv: list[str] | None = None) -> dict:
    s = summarize(journal.read())
    s["journal"] = {"path": str(journal.path()), "enabled": journal.enabled()}
    s["balance"] = check_balance()
    s["mandate"] = summarize_mandate(read_mandate_sessions())
    s["mandate"]["path"] = str(mandate_path())
    return s


def _short(path: str) -> str:
    """The journal path with the home directory shown as ~ (output gets pasted)."""
    from pathlib import Path
    try:
        return "~/" + Path(path).relative_to(Path.home()).as_posix()
    except (ValueError, RuntimeError, OSError):
        return path


def render(s: dict) -> str:
    lines = [f"arcaeon status  (journal: {_short(s['journal']['path'])}"
             + ("" if s["journal"]["enabled"] else ", OFF: ARCAEON_JOURNAL=0") + ")"]
    if not s["last_run"]:
        lines.append("no activity recorded yet")
    else:
        lines.append("last run per verb:")
        for verb, r in sorted(s["last_run"].items(), key=lambda kv: kv[1].get("t") or "",
                              reverse=True):
            lines.append(f"  {verb:<10} {str(r.get('word')):<18} {r.get('t')}")
    cnl = s["open_could_not_look"]
    lines.append(f"open COULD NOT LOOKs: {len(cnl)}")
    for x in cnl:
        lines.append(f"  {x['verb']:<10} target {x['target'][:12]}  {x.get('t')}")
    m = s.get("mandate")
    if m is not None:
        if not m["sessions"]:
            lines.append("mandate: no gated sessions recorded")
        else:
            lines.append(f"mandate: {m['sessions']} gated session"
                         + ("" if m["sessions"] == 1 else "s") + ": "
                         f"{m['inside']} inside, {m['outside']} outside, "
                         f"{m['could_not_look']} COULD NOT LOOK, {m['blocked']} blocked, "
                         f"{m['cap_exceeded']} cap exceeded, "
                         f"{m['changes']} mandate file changes")
    b = s["balance"]
    lines.append("balance: " + (b["sentence"] if b.get("checked") else b["reason"]))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(a in ("-h", "--help") for a in argv):
        print(USAGE)
        return V.EXIT_GOOD
    unknown = [a for a in argv if a != "--json"]
    if unknown:
        print(USAGE, file=sys.stderr)
        return V.EXIT_USAGE
    s = status(argv)
    if "--json" in argv:
        print(json.dumps(s, indent=1))
    else:
        print(render(s))
    return V.EXIT_GOOD
