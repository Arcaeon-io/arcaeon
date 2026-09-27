# SPDX-License-Identifier: MIT
"""`arcaeon mandate`: read a mandate file before an agent runs under it.

    arcaeon mandate lint mandate.json        # unknown keys, bad types; exit 2 if invalid
    arcaeon mandate explain mandate.json     # the mandate in plain sentences
    arcaeon mandate check mandate.json --field name=place_order --field total=19.00

Nothing here forwards, blocks or writes a ledger row. It reads the same file
the proxy's gate reads (arcaeon.record.adapter.mandate_gate, imported, never
copied) and says what is in it. See docs/MANDATE_GATE.md.

Exit codes are arcaeon.verdict's one table: 0 good, 2 an invalid mandate or
bad usage, 3 COULD NOT LOOK (the file is not there or cannot be read). `check`
answers the gate's word: inside 0, outside 1, could_not_look 3.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from arcaeon import verdict as V

__all__ = ["TOP_KEYS", "SPEND_CAP_KEYS", "CHECK_EXIT", "lint", "explain", "check",
           "parse_fields", "main"]

#: Every key a mandate file may carry at the top: the tool shape, the deal
#: lane's body, and the deal lane's sealed sidecar.
TOP_KEYS = {
    "who": "str", "allowed_acts": "list[str]", "forbidden_acts": "list[str]",
    "spend_cap": "object", "not_before": "time", "not_after": "time",
    # deal-lane body (arcaeon deal mandate)
    "may": "list[str]", "may_not": "list[str]", "merchant": "str", "cap": "amount",
    "currency": "str",
}
#: The deal lane's sealed sidecar: {"deal", "mandate_digest", "mandate": body}.
SIDECAR_KEYS = {"deal": "str", "mandate_digest": "str", "mandate": "object"}
SPEND_CAP_KEYS = {
    "amount": "amount", "total": "amount", "currency": "str", "merchant": "str",
    "amount_args": "list[str]", "currency_args": "list[str]", "merchant_args": "list[str]",
}

_TYPE_WORDS = {"str": "a string", "list[str]": "a list of strings", "object": "an object",
               "time": "an ISO 8601 time string", "amount": "an amount written as a string"}


# -- reading ------------------------------------------------------------------

class _CouldNotLook(Exception):
    def __init__(self, reason: str, reason_word: str, where: str):
        super().__init__(reason)
        self.reason, self.reason_word, self.where = reason, reason_word, where


def _read(path: str) -> tuple[Any, str | None, bytes]:
    """(parsed JSON or None, the parse error or None, raw bytes). Raises
    _CouldNotLook when the file is not there or cannot be opened."""
    p = Path(path)
    try:
        data = p.read_bytes()
    except FileNotFoundError:
        raise _CouldNotLook(f"no file at {p}", "missing", str(p)) from None
    except OSError as e:
        raise _CouldNotLook(f"{type(e).__name__}: {e}", "unreadable", str(p)) from None
    try:
        return json.loads(data.decode("utf-8")), None, data
    except (ValueError, UnicodeDecodeError, RecursionError) as e:
        return None, f"not JSON: {type(e).__name__}", data


def _time_ok(v: Any) -> bool:
    if not isinstance(v, str) or not v:
        return False
    try:
        datetime.fromisoformat(v[:-1] + "+00:00" if v.endswith("Z") else v)
    except ValueError:
        return False
    return True


def _amount_ok(v: Any) -> bool:
    from decimal import Decimal, InvalidOperation
    if isinstance(v, bool) or not isinstance(v, (str, int)):
        return False
    try:
        return Decimal(str(v)).is_finite()
    except InvalidOperation:
        return False


def _type_ok(kind: str, v: Any) -> bool:
    if v is None:
        return True                       # a field left null constrains nothing
    if kind == "str":
        return isinstance(v, str)
    if kind == "list[str]":
        return isinstance(v, list) and all(isinstance(x, str) for x in v)
    if kind == "object":
        return isinstance(v, dict)
    if kind == "time":
        return _time_ok(v)
    if kind == "amount":
        return _amount_ok(v)
    return False


def _check_keys(obj: dict, known: dict, prefix: str, problems: list) -> None:
    for k in obj:
        if k not in known:
            problems.append({"key": prefix + k, "problem": f"{prefix + k!r} is not a mandate "
                             f"field (known: {', '.join(sorted(known))})"})
            continue
        if not _type_ok(known[k], obj[k]):
            problems.append({"key": prefix + k, "problem": f"{prefix + k!r} must be "
                             f"{_TYPE_WORDS[known[k]]}, got {json.dumps(obj[k])[:80]}"})


# -- lint -----------------------------------------------------------------------

def lint(obj: Any) -> dict:
    """{"valid": bool, "problems": [...], "warnings": [...], "shape": ...} for a
    parsed mandate. `shape` is "tool", "deal" or "sealed"."""
    problems: list = []
    warnings: list = []
    if not isinstance(obj, dict):
        return {"valid": False, "shape": None, "warnings": [],
                "problems": [{"key": "", "problem": "a mandate is a JSON object"}]}
    shape = "tool"
    if "mandate_digest" in obj or ("mandate" in obj and "deal" in obj):
        shape = "sealed"
        _check_keys(obj, SIDECAR_KEYS, "", problems)
        body = obj.get("mandate")
        if not isinstance(body, dict):
            if not any(p["key"] == "mandate" for p in problems):
                problems.append({"key": "mandate",
                                 "problem": "a sealed sidecar needs its 'mandate' body"})
            return {"valid": False, "shape": shape, "problems": problems, "warnings": []}
        obj, prefix = body, "mandate."
    else:
        prefix = ""
    if shape == "tool" and "cap" in obj and "spend_cap" not in obj:
        shape = "deal"
    _check_keys(obj, TOP_KEYS, prefix, problems)
    cap = obj.get("spend_cap")
    if isinstance(cap, dict):
        _check_keys(cap, SPEND_CAP_KEYS, prefix + "spend_cap.", problems)
        if cap.get("amount") is None and cap.get("total") is None:
            warnings.append(f"{prefix}spend_cap has no amount and no total: every spend "
                            f"will be COULD NOT LOOK")
    for a, b in (("allowed_acts", "may"), ("forbidden_acts", "may_not")):
        if a in obj and b in obj:
            warnings.append(f"both {prefix}{a} and {prefix}{b} are given; the gate reads "
                            f"{a} and ignores {b}")
    if "spend_cap" in obj and "cap" in obj:
        warnings.append(f"both {prefix}spend_cap and {prefix}cap are given; the gate reads "
                        f"spend_cap and ignores cap")
    if not problems:
        # The gate's own reader is the last word: a file lint passes and the
        # gate cannot read would be the worst kind of green.
        from arcaeon.record.adapter import mandate_gate
        try:
            mandate_gate._normalize(obj if shape != "sealed" else
                                    {"mandate": obj, "mandate_digest": ""})
        except ValueError as e:
            problems.append({"key": "", "problem": f"the gate cannot read it: {e}"})
    return {"valid": not problems, "shape": shape, "problems": problems, "warnings": warnings}


# -- explain --------------------------------------------------------------------

def _join(items: list) -> str:
    items = [str(x) for x in items]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " and " + items[-1]


def _or(items: list) -> str:
    items = [str(x) for x in items]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + " or " + items[-1]


def explain(obj: Any) -> list[str]:
    """The mandate in plain sentences, one per line. `obj` must lint valid."""
    from arcaeon.record.adapter import mandate_gate
    if isinstance(obj, dict) and isinstance(obj.get("mandate"), dict) \
            and ("mandate_digest" in obj or "deal" in obj):
        obj = obj["mandate"]                      # deal sealed sidecar
    m = mandate_gate._normalize(obj)
    out: list[str] = []
    if m.get("who"):
        out.append(f"This mandate speaks for {m['who']}. The gate records that name on every "
                   f"row; it does not check it, because it cannot see who is behind the agent.")
    allowed, forbidden = m.get("allowed_acts") or [], m.get("forbidden_acts") or []
    if allowed:
        out.append(f"This agent may call {_join(allowed)}.")
    else:
        out.append("This agent may call any tool that is not forbidden.")
    if forbidden:
        out.append(f"It may not call {_or(forbidden)}, even where an allowed pattern "
                   f"also matches.")
    cap = m.get("spend_cap")
    if cap:
        cur = f" {cap['currency']}" if cap.get("currency") else ""
        where = f", and only with {cap['merchant']}" if cap.get("merchant") else ""
        if cap.get("amount") is not None:
            out.append(f"One call may spend at most {cap['amount']}{cur}{where}.")
        elif cap.get("total") is None:
            out.append("It names a spend cap with no amount, so every spend is COULD NOT "
                       "LOOK.")
        if cap.get("total") is not None:
            out.append(f"The whole session may spend at most {cap['total']}{cur}"
                       f"{where if cap.get('amount') is None else ''}; a spend past that is "
                       f"outside.")
        out.append(f"A call counts as a spend when its arguments carry "
                   f"{_or(cap['amount_args'])}.")
    else:
        out.append("It sets no spend cap.")
    nb, na = m.get("not_before"), m.get("not_after")
    if nb and na:
        out.append(f"It holds from {nb} until {na}.")
    elif nb:
        out.append(f"It holds from {nb}, with no end.")
    elif na:
        out.append(f"It holds until {na}.")
    else:
        out.append("It sets no time window.")
    out.append("Record-only unless the proxy is started with --mandate-enforce: a call "
               "outside this mandate is still forwarded, and the ledger gets a row naming it.")
    return out


# -- check ----------------------------------------------------------------------

#: The gate's word -> the exit code (arcaeon.verdict's table).
CHECK_EXIT = {"inside": V.EXIT_GOOD, "outside": V.EXIT_BAD,
              "could_not_look": V.EXIT_COULD_NOT_LOOK}


def parse_fields(fields: list[str]) -> tuple[dict | None, str | None]:
    """--field KEY=VALUE (a string) or KEY:=JSON (typed), the same rule as
    `arcaeon log --field`. (dict, None) or (None, the usage error)."""
    out: dict = {}
    for f in fields:
        typed = ":=" in f and ("=" not in f or f.index(":=") < f.index("="))
        k, sep, v = f.partition(":=") if typed else f.partition("=")
        if not sep or not k:
            return None, f"--field wants KEY=VALUE or KEY:=JSON, got {f!r}"
        if typed:
            try:
                v = json.loads(v)
            except ValueError as e:
                return None, f"--field {k}:= is not JSON ({e})"
        out[k] = v
    return out, None


def check(mandate_path: str, fields: dict, *, at: str | None = None,
          spent: Any = None) -> dict:
    """The gate's answer for one call. `fields["name"]` is the tool; every other
    field is an argument. `spent` is what the session already spent (for
    spend_cap.total). Record-only by construction: this forwards, blocks and
    writes nothing."""
    from arcaeon.record.adapter import mandate_gate
    gate = mandate_gate.load(mandate_path)
    args = {k: v for k, v in fields.items() if k != "name"}
    call = {"name": fields.get("name"), "arguments": args}
    if spent is not None:
        gate.add_spend(spent)
    verdict, reason, extra = gate.detail(call, at)
    res = {"verdict": verdict, "reason": str(reason), "rule": extra.get("rule"),
           "tool": call["name"] if isinstance(call["name"], str) else None,
           "mandate": mandate_path, "mandate_status": gate.status,
           "mandate_file_sha256": gate.file_sha256, "who": gate.who,
           "blocks": False}
    if extra.get("evt"):
        res["evt"] = extra["evt"]
    if verdict == "could_not_look":
        res.update(looked_for=extra.get("looked_for"), where=extra.get("where"),
                   reason_word=extra.get("reason_word"))
    return res


# -- the verb -----------------------------------------------------------------

def _could_not_look(e: _CouldNotLook, as_json: bool) -> int:
    if as_json:
        print(json.dumps({"verdict": V.COULD_NOT_LOOK_TOKEN, "reason": e.reason,
                          **V.could_not_look("the mandate", e.where, e.reason_word,
                                             e.reason)}, indent=1))
    else:
        print(f"COULD NOT LOOK: {e.reason}", file=sys.stderr)
    return V.EXIT_COULD_NOT_LOOK


def _lint_file(path: str) -> tuple[dict, Any, bytes]:
    obj, err, data = _read(path)
    if err is not None:
        return ({"valid": False, "shape": None, "warnings": [],
                 "problems": [{"key": "", "problem": err}]}, None, data)
    return lint(obj), obj, data


def _cmd_lint(a) -> int:
    try:
        res, _, data = _lint_file(a.mandate)
    except _CouldNotLook as e:
        return _could_not_look(e, a.json)
    res = {"mandate": a.mandate, "file_sha256": hashlib.sha256(data).hexdigest(), **res}
    if a.json:
        print(json.dumps(res, indent=1))
    else:
        for p in res["problems"]:
            print(f"problem: {p['problem']}")
        for w in res["warnings"]:
            print(f"warning: {w}")
        print(f"{a.mandate}: {'valid' if res['valid'] else 'invalid'} ({res['shape'] or 'no'} "
              f"shape, {len(res['problems'])} problem(s), {len(res['warnings'])} warning(s))")
    return V.EXIT_GOOD if res["valid"] else V.EXIT_USAGE


def _cmd_explain(a) -> int:
    try:
        res, obj, _ = _lint_file(a.mandate)
    except _CouldNotLook as e:
        return _could_not_look(e, a.json)
    if not res["valid"]:
        for p in res["problems"]:
            print(f"problem: {p['problem']}", file=sys.stderr)
        print(f"{a.mandate}: invalid; run `arcaeon mandate lint` for the list", file=sys.stderr)
        return V.EXIT_USAGE
    lines = explain(obj)
    if a.json:
        print(json.dumps({"mandate": a.mandate, "sentences": lines,
                          "warnings": res["warnings"]}, indent=1))
    else:
        print("\n".join(lines))
        for w in res["warnings"]:
            print(f"warning: {w}")
    return V.EXIT_GOOD


def _cmd_check(a) -> int:
    fields, err = parse_fields(a.field or [])
    if err:
        print(f"arcaeon mandate check: {err}", file=sys.stderr)
        return V.EXIT_USAGE
    if not isinstance(fields.get("name"), str) or not fields["name"]:
        print("arcaeon mandate check: needs --field name=<tool name>", file=sys.stderr)
        return V.EXIT_USAGE
    res = check(a.mandate, fields, at=a.at, spent=a.spent)
    if a.json:
        print(json.dumps(res, indent=1))
    else:
        print(f"{res['verdict'].replace('_', ' ')}: {res['reason']}")
    return CHECK_EXIT[res["verdict"]]


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="arcaeon mandate",
        description="Read a mandate file: lint it, explain it in plain sentences, or "
                    "check one call against it. Nothing here forwards or blocks a call.")
    sub = ap.add_subparsers(dest="cmd", metavar="{lint,explain,check}")
    for name, fn, text in (("lint", _cmd_lint, "name unknown keys and bad types; exit 2 "
                                                "when invalid"),
                           ("explain", _cmd_explain, "print the mandate in plain sentences")):
        p = sub.add_parser(name, help=text, description=text)
        p.add_argument("mandate", help="the mandate JSON file")
        p.add_argument("--json", action="store_true", help="print JSON")
        p.set_defaults(fn=fn)
    text = ("check one call: inside exit 0, outside 1, could_not_look 3 (record-only: "
            "says, blocks nothing)")
    p = sub.add_parser("check", help=text, description=text)
    p.add_argument("mandate", help="the mandate JSON file")
    p.add_argument("--field", action="append", metavar="KEY=VALUE",
                   help="name=<tool> and each argument (repeatable; KEY:=JSON for a typed "
                        "value). No JSON quoting, so it works the same in PowerShell")
    p.add_argument("--at", default=None, metavar="TIME",
                   help="the call's time, ISO 8601 (default now, UTC)")
    p.add_argument("--spent", default=None, metavar="AMOUNT",
                   help="what the session already spent, for spend_cap.total")
    p.add_argument("--json", action="store_true", help="print JSON")
    p.set_defaults(fn=_cmd_check)
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = _parser()
    a = ap.parse_args(sys.argv[1:] if argv is None else argv)
    if not getattr(a, "fn", None):
        ap.print_usage(sys.stderr)
        return V.EXIT_USAGE
    return a.fn(a)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
