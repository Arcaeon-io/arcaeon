# SPDX-License-Identifier: MIT
"""`arcaeon status`: what this install did lately, read from the activity journal.

    last run per verb    the newest journal line for each verb: word and time
    open COULD NOT LOOKs targets whose newest journal line exited 3 (a look
                         that never completed and has not been retried green)
    balance              the hosted-witness balance, ONLY when ARCAEON_KEY is
                         set; otherwise "balance: not checked, no key" and no
                         request is made

The journal holds sha256(target), never the path, so an open COULD NOT LOOK is
named by the first 12 hex digits of that hash. `--json` prints the same facts
as one object. Offline unless a key is set; the one request is
arcaeon.remote.balance(), which never consumes a credit.
"""
from __future__ import annotations

import json
import sys

from arcaeon import journal
from arcaeon import verdict as V

USAGE = ("usage: arcaeon status [--json]\n"
         "What arcaeon did lately on this machine, from the local activity journal "
         "(~/.arcaeon/activity.jsonl, or $ARCAEON_HOME): the last run of each verb, "
         "the targets whose newest look could not finish, and, only when ARCAEON_KEY "
         "is set, your hosted-witness balance.")

NO_KEY = "not checked, no key"


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
    return s


def render(s: dict) -> str:
    lines = [f"arcaeon status  (journal: {s['journal']['path']}"
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
