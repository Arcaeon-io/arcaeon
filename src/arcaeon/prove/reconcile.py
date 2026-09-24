# SPDX-License-Identifier: MIT
"""Two tapes and a counter: a COMPLETENESS verdict for an agent's tool calls.

    arcaeon-ledger reconcile agent.tape.jsonl tool.tape.jsonl [--pin pin.json]

WHAT IT ANSWERS
---------------
`verify_file` answers "was this record altered after it was written?". It
cannot answer "is this record COMPLETE?", because a single writer decides what
to write. This module answers the second question for the one place it can be
answered: a tool call has two ends. The agent side keeps a tape of every call
it sent and every answer it got; the tool side keeps its own tape of every call
it received and every answer it sent. Each row carries a call index and the
digest of the request and the response as THAT side saw them. Line the two
tapes up and exactly four things can be true:

  MATCHED n of n   every call on either tape is on the other, same digests.
  MISSING at k     call k is on one tape and not the other (or its response
                   reached one side only). `side` names the SHORT tape.
  ALTERED at k     both tapes have call k and the digests disagree, or a tape
                   contradicts itself (chain broken, duplicate or out-of-order
                   index, head differs from its witness pin).
  COULD NOT LOOK   a tape is unreachable, empty on both sides, not a tape, or a
                   pin could not be read, or a line cannot be read without
                   guessing (nested deeper than 512, a duplicate key that
                   does not parse, whitespace json.loads rejects); the
                   reason names the line and ends with its cause in
                   brackets. Never a green: exit 3, not 0 (exit 2 under
                   --legacy-exit, for the 0.9.x release only). reconcile never
                   raises; that is an answer too.

Exit codes (arcaeon.verdict, the one table): 0 MATCHED, 1 MISSING, 1 ALTERED,
3 COULD NOT LOOK, 2 bad usage. Before arcaeon 0.9 COULD NOT LOOK exited 2;
`--legacy-exit` keeps that for one release.

THE COUNTER
-----------
Each side pins its tape to the witness on the witness's own cadence with the
body the witness already accepts, `{namespace, rows, chain}`. A tape row is one
call and rows are written in index order, so `rows` IS the call count and
`chain` is the head after call `rows`. `--pin` checks a tape against that pin:
fewer rows than pinned is MISSING (removed after the pin), a different chain at
the pinned row is ALTERED (rewritten after the pin). Without a pin, two tapes
truncated or rewritten IN AGREEMENT still match each other; the pin is what
bounds that to "since the last pin".

WHAT IT DOES NOT PROVE (also carried in every result's `limits`)
-----------------------------------------------------------------
* A colluding pair (agent side and tool side run by one party who wants a lie)
  can write two agreeing tapes. MATCHED means two independent recorders agree,
  which is only worth what their independence is worth.
* A call that crossed neither seam leaves no row on either tape. An agent that
  never calls the tool is invisible here; so is an agent that uses a second,
  unwrapped channel.
* Digests compare CONTENT (canonical JSON of the tool name + arguments, and of
  the result or error), not bytes. A relay that re-serializes a frame without
  changing its meaning is MATCHED, on purpose.
* A single tape is never complete by itself: reconcile needs two, and with one
  missing the answer is COULD NOT LOOK, not MATCHED.

Stdlib only. Reads tapes; never writes them.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from arcaeon import verdict as _v
from arcaeon.record.ledger import chain_at, verify_file
from arcaeon.record.row import DuplicateKeyError
from arcaeon.record.row import loads as _loads
from arcaeon.record.row import loads_strict as _loads_strict

__all__ = ["TAPE_FORMAT", "MATCHED", "MISSING", "ALTERED", "COULD_NOT_LOOK",
           "EXIT_CODES", "LEGACY_EXIT_CODES", "Finding", "Reconciliation", "reconcile", "load_pins", "LIMITS"]

TAPE_FORMAT = "arcaeon-tape/1"
SIDES = ("agent", "tool")

MATCHED = "MATCHED"
MISSING = "MISSING"
ALTERED = "ALTERED"
COULD_NOT_LOOK = "COULD_NOT_LOOK"

# The one exit table lives in arcaeon.verdict. COULD_NOT_LOOK moved 2 -> 3 in
# arcaeon 0.9; LEGACY_EXIT_CODES is what --legacy-exit returns for one release.
EXIT_CODES = {MATCHED: _v.EXIT_GOOD, MISSING: _v.EXIT_BAD, ALTERED: _v.EXIT_BAD,
              COULD_NOT_LOOK: _v.EXIT_COULD_NOT_LOOK}
LEGACY_EXIT_CODES = {MATCHED: 0, MISSING: 1, ALTERED: 1, COULD_NOT_LOOK: 2}

LIMITS = [
    "MATCHED means two recorders agree; a colluding agent side and tool side can "
    "write two agreeing tapes of a lie.",
    "A call that crossed neither instrumented seam leaves no row on either tape; "
    "an agent that never calls, or calls through an unwrapped channel, is invisible here.",
    "Digests compare content (canonical JSON), not bytes: a meaning-preserving "
    "re-serialization in transit is MATCHED by design.",
    "Without a witness pin, both tapes truncated or rewritten in agreement still "
    "match; a pin bounds that to the rows written after it.",
]


@dataclass
class Finding:
    verdict: str            # MISSING or ALTERED
    at: int | None          # the call index the finding is about
    side: str | None        # MISSING: the SHORT side. ALTERED: the side that contradicts, or None
    reason: str
    index_side: str | None = None   # whose numbering `at` is in ("agent"/"tool")

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "at": self.at, "side": self.side,
                "index_side": self.index_side, "reason": self.reason}


@dataclass
class Reconciliation:
    verdict: str
    at: int | None = None
    side: str | None = None
    reason: str = ""
    matched: int = 0
    counts: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    could_not_look: list = field(default_factory=list)
    pins_checked: list = field(default_factory=list)
    limits: list = field(default_factory=lambda: list(LIMITS))

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.verdict]

    @property
    def summary(self) -> str:
        if self.verdict == MATCHED:
            return f"MATCHED {self.matched} of {self.matched}"
        if self.verdict == COULD_NOT_LOOK:
            return f"COULD NOT LOOK: {self.reason}"
        where = f" at call {self.at}" if self.at is not None else ""
        who = f" ({self.side} tape)" if self.side else ""
        return f"{self.verdict}{where}{who}: {self.reason}"

    def __bool__(self) -> bool:
        return self.verdict == MATCHED

    def to_dict(self) -> dict:
        return {"verdict": self.verdict, "summary": self.summary, "at": self.at,
                "side": self.side, "reason": self.reason, "matched": self.matched,
                "counts": self.counts,
                "findings": [f.to_dict() for f in self.findings],
                "could_not_look": list(self.could_not_look),
                "pins_checked": list(self.pins_checked),
                "limits": list(self.limits), "exit_code": self.exit_code}


# -- loading one tape --------------------------------------------------------

@dataclass
class _Tape:
    label: str                   # "tape_a" / "tape_b" until the side is known
    path: Path
    side: str | None = None
    ns: str | None = None
    rows: list = field(default_factory=list)       # every tape row, file order
    calls: list = field(default_factory=list)      # rows that passed the index walk
    broken: bool = False
    cnl: str | None = None                         # could-not-look reason

    @property
    def name(self) -> str:
        return self.side or self.label


_LINE = re.compile(r"line (\d+)")

# A tape row is flat. A line nested deeper than this is COULD NOT LOOK, never a
# guess: CPython's own ceiling is a C-stack guard that moves with platform and
# version, so no fixed number reproduces it, and the Node port of this module
# (arcaeon-witness lib/_reconcile_tapes.js MAX_DEPTH) refuses at the same 512.
MAX_DEPTH = 512


def _depth_before_stop(raw: str) -> int:
    """The deepest nesting a JSON parser opens on this line before it stops:
    at the end when the line parses, at the error position when it does not.
    Brackets inside strings do not count."""
    stop = len(raw)
    try:
        json.loads(raw)
    except json.JSONDecodeError as e:
        stop = e.pos
    except (ValueError, RecursionError):
        pass                      # 4300-digit int, or deeper than the C guard: scan it all
    depth = best = 0
    in_str = esc = False
    for c in raw[:stop]:
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "[" or c == "{":
            depth += 1
            if depth > best:
                best = depth
        elif c == "]" or c == "}":
            depth -= 1
    return best


def _cannot_read(label: str, lines: list) -> str | None:
    """Lines verify_file cannot be trusted to answer on, in file order; the first
    one is the COULD NOT LOOK reason. Each reason names the line and ends with
    its cause in brackets. Numbering and stripping are verify_file's own."""
    for i, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        if (raw.count("[") + raw.count("{") > MAX_DEPTH
                and _depth_before_stop(raw) > MAX_DEPTH):
            return f"{label} line {i} is nested deeper than {MAX_DEPTH} levels [nesting_too_deep]"
        try:
            _loads_strict(raw)
        except DuplicateKeyError:
            # verify_file re-reads this line inside its except handler; when the
            # re-read fails too, the error escapes it. Answer before it can.
            try:
                _loads(raw)
            except ValueError:
                return (f"{label} line {i} holds a duplicate key and does not parse "
                        f"[duplicate_key_unparseable]")
        except ValueError:
            pass                  # unparseable: verify_file names it as a break
    return None


def _is_tape_row(row: Any) -> bool:
    if not isinstance(row, dict):
        return False
    idx = row.get("idx")
    return (row.get("evt") == "tape_call" and row.get("tape") == TAPE_FORMAT
            and row.get("side") in SIDES
            and isinstance(idx, int) and not isinstance(idx, bool) and idx >= 1
            and isinstance(row.get("req"), str)
            and (row.get("resp") is None or isinstance(row.get("resp"), str)))


def _load(label: str, path: str | Path, findings: list) -> _Tape:
    t = _Tape(label=label, path=Path(path))
    try:
        t.path.stat()
    except FileNotFoundError:
        t.cnl = f"{label} not found: {t.path}"
        return t
    except OSError as e:
        t.cnl = f"{label} unreadable: {e}"
        return t
    if t.path.is_dir():
        t.cnl = f"{label} is a directory, not a tape: {t.path}"
        return t
    # Read exactly as verify_file reads, and answer COULD NOT LOOK on the lines
    # it would raise on (or that are too deep to read without guessing).
    try:
        lines = t.path.read_text(encoding="utf-8", errors="replace").split("\n")
    except OSError:
        lines = []                # verify_file reports it as unreadable below
    why = _cannot_read(label, lines)
    if why:
        t.cnl = why
        return t
    # strict: every row of a tape must be chained; a tape has no legacy prefix.
    res = verify_file(t.path, strict=True)
    if res.ok is None and res.verified_scope == "empty":
        return t   # a tape with no rows: legal, compared as zero calls
    if res.ok is not True:
        fb = res.first_break or "chain does not verify"
        if fb.startswith("unreadable"):
            t.cnl = f"{label} {fb}"
            return t
        # Try to learn the side from any readable row, so the finding names it.
        t.side = _peek_side(t.path)
        m = _LINE.search(fb)
        t.broken = True
        findings.append(Finding(ALTERED, int(m.group(1)) if m else None, t.name,
                                f"{t.name} tape does not verify ({fb}); a tape that was "
                                f"edited after it was written cannot be reconciled",
                                index_side=t.name))
        return t
    for n, raw in enumerate((ln for ln in lines if ln.strip()), start=1):
        try:
            row = json.loads(raw)
        except (ValueError, RecursionError):
            # verify_file stripped this line with str.strip(), which also removes
            # \x0b \x0c \x1c-\x1f \x85 \xa0 U+2028 U+3000 ...; json.loads does not.
            t.cnl = (f"{label} row {n} verifies but does not read a second time "
                     f"(whitespace json.loads does not strip) [whitespace_outside_json]")
            return t
        if not _is_tape_row(row):
            t.cnl = f"{label} row {n} is not an {TAPE_FORMAT} row"
            return t
        if t.side is None:
            t.side, t.ns = row["side"], row.get("ns")
        elif row["side"] != t.side:
            t.cnl = f"{label} mixes sides ({t.side} and {row['side']}) at row {n}"
            return t
        t.rows.append(row)
    return t


def _peek_side(path: Path) -> str | None:
    try:
        for raw in path.read_text(encoding="utf-8", errors="replace").split("\n"):
            try:
                row = json.loads(raw)
            except (ValueError, RecursionError):
                continue
            if isinstance(row, dict) and row.get("side") in SIDES:
                return row["side"]
    except OSError:
        pass
    return None


def _walk_index(t: _Tape, findings: list) -> None:
    """Rows must be call 1, 2, 3 ... in file order. Anything else is a finding."""
    expect = 1
    for row in t.rows:
        k = row["idx"]
        if k == expect:
            t.calls.append(row)
            expect += 1
        elif k > expect:
            findings.append(Finding(MISSING, expect, t.name,
                                    f"{t.name} tape skips from call {expect - 1} to call {k}: "
                                    f"calls {expect}..{k - 1} were allocated and never written",
                                    index_side=t.name))
            t.calls.append(row)
            expect = k + 1
        elif t.calls and k == t.calls[-1]["idx"]:
            findings.append(Finding(ALTERED, k, t.name,
                                    f"{t.name} tape records call {k} twice; one index, two rows",
                                    index_side=t.name))
        else:
            findings.append(Finding(ALTERED, k, t.name,
                                    f"{t.name} tape has call {k} after call {expect - 1}: "
                                    f"index out of order", index_side=t.name))


# -- the pin -----------------------------------------------------------------

def load_pins(path: str | Path) -> list[dict]:
    """A pin file is one witness record `{namespace, rows, chain, ...}`, a
    `{"agent": pin, "tool": pin}` pair, or a list of pins. Raises ValueError on
    anything else, which reconcile turns into COULD NOT LOOK."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and ("rows" in data or "chain" in data):
        pins = [data]
    elif isinstance(data, dict) and set(data) <= set(SIDES) and data:
        pins = [dict(v, side=k) if isinstance(v, dict) else v for k, v in data.items()]
    elif isinstance(data, list):
        pins = data
    else:
        raise ValueError("pin file is not a pin, a {agent, tool} pair, or a list of pins")
    for p in pins:
        if not isinstance(p, dict):
            raise ValueError("pin is not an object")
        r = p.get("rows")
        if not isinstance(r, int) or isinstance(r, bool) or r < 0:
            raise ValueError(f"pin rows is not a non-negative integer: {r!r}")
        if not isinstance(p.get("chain"), str):
            raise ValueError("pin chain is not a string")
    return pins


def _pin_targets(pin: dict, tapes: list) -> list:
    side = pin.get("side")
    if side in SIDES:
        return [t for t in tapes if t.side == side] or [t for t in tapes if t.side is None]
    ns = pin.get("namespace")
    by_ns = [t for t in tapes if ns is not None and t.ns == ns]
    return by_ns or list(tapes)   # a pin naming neither tape is held against both


def _check_pin(pin: dict, t: _Tape, findings: list, cnl: list, checked: list) -> None:
    m, h = pin["rows"], pin["chain"].lower()
    rec = {"side": t.name, "namespace": pin.get("namespace"), "rows": m}
    checked.append(rec)
    if t.cnl:
        cnl.append(f"pin for {t.name} could not be checked: {t.cnl}")
        rec["result"] = "could_not_look"
        return
    have = len(t.rows)
    if t.broken:
        rec["result"] = "tape_broken"
        return
    if have < m:
        findings.append(Finding(MISSING, have + 1, t.name,
                                f"the witness pinned {m} calls on the {t.name} tape and it now "
                                f"holds {have}: calls {have + 1}..{m} were removed after the pin",
                                index_side=t.name))
        rec["result"] = "short"
        return
    now = chain_at(t.path, m)
    if (now or "").lower() != h:
        findings.append(Finding(ALTERED, m, t.name,
                                f"the {t.name} tape's head at call {m} is {now}, the witness "
                                f"pinned {h}: the tape was rewritten after the pin",
                                index_side=t.name))
        rec["result"] = "head_differs"
        return
    rec["result"] = "agrees"


# -- lining the tapes up -----------------------------------------------------

def _align(A: list, T: list, findings: list) -> int:
    """Walk agent calls A and tool calls T in index order. Returns calls matched.

    Matching is by request digest, not by raw index position, because each side
    numbers its own calls: a request lost in transit makes the tool side's
    numbering run one behind the agent's from that point on, and a position-only
    walk would call every later call ALTERED when exactly one is MISSING.
    """
    i = j = matched = 0
    only_a: list = []     # agent rows with no partner on the tool tape
    only_t: list = []     # tool rows with no partner on the agent tape
    while i < len(A) and j < len(T):
        a, t = A[i], T[j]
        if a["req"] == t["req"]:
            if a.get("resp") == t.get("resp"):
                matched += 1
            elif a.get("resp") is None or t.get("resp") is None:
                short = "agent" if a.get("resp") is None else "tool"
                findings.append(Finding(MISSING, a["idx"], short,
                                        f"call {a['idx']}'s response is on one tape and not the "
                                        f"other ({short} tape has none)", index_side="agent"))
            else:
                findings.append(Finding(ALTERED, a["idx"], None,
                                        f"call {a['idx']}: same request, different response: the "
                                        f"agent saw {a.get('resp')}, the tool sent {t.get('resp')}",
                                        index_side="agent"))
            i += 1
            j += 1
            continue
        da = next((d for d in range(1, len(A) - i) if A[i + d]["req"] == t["req"]), None)
        dt = next((d for d in range(1, len(T) - j) if T[j + d]["req"] == a["req"]), None)
        if da is None and dt is None:
            findings.append(Finding(ALTERED, a["idx"], None,
                                    f"call {a['idx']}: the request differs: the agent sent "
                                    f"{a['req']}, the tool received {t['req']}",
                                    index_side="agent"))
            i += 1
            j += 1
        elif dt is None or (da is not None and da <= dt):
            only_a.extend(A[i:i + da])
            i += da
        else:
            only_t.extend(T[j:j + dt])
            j += dt
    only_a.extend(A[i:])
    only_t.extend(T[j:])
    # A call that is on BOTH tapes, just not at the same place, was not lost: it
    # was moved. Two MISSINGs would under-state that; it is one ALTERED (order).
    for x in list(only_a):
        y = next((y for y in only_t if y["req"] == x["req"]), None)
        if y is None:
            continue
        only_a.remove(x)
        only_t.remove(y)
        findings.append(Finding(ALTERED, x["idx"], None,
                                f"call {x['idx']} is on both tapes at different places (agent "
                                f"call {x['idx']}, tool call {y['idx']}): the order was altered",
                                index_side="agent"))
    for x in only_a:
        findings.append(Finding(MISSING, x["idx"], "tool",
                                f"call {x['idx']} is on the agent tape and not on the tool tape",
                                index_side="agent"))
    for y in only_t:
        findings.append(Finding(MISSING, y["idx"], "agent",
                                f"tool call {y['idx']} is on the tool tape and not on the agent tape",
                                index_side="tool"))
    return matched


def _headline(findings: list) -> Finding:
    first = min(findings, key=lambda f: (f.at if f.at is not None else 0,
                                         0 if f.verdict == ALTERED else 1))
    twins = {f.side for f in findings
             if f.verdict == first.verdict and f.at == first.at and f.side}
    if twins >= {"agent", "tool"}:
        return Finding(first.verdict, first.at, "both",
                       first.reason + " (both tapes)", index_side=first.index_side)
    return first


# -- the verdict -------------------------------------------------------------

def reconcile(tape_a: str | Path, tape_b: str | Path, *,
              pins: list[dict] | None = None, pin_path: str | Path | None = None
              ) -> Reconciliation:
    """Reconcile two tapes, optionally against witness pins. See module docstring.

    Precedence: any MISSING/ALTERED finding is the verdict (earliest call first,
    ALTERED before MISSING at the same call), because a defect found is a fact
    even when another part could not be looked at. Otherwise any could-not-look
    makes the verdict COULD_NOT_LOOK. Only a comparison with no finding and
    nothing unlooked-at is MATCHED.

    Never raises on any input. A line it cannot read without guessing is
    COULD NOT LOOK naming the line and its cause in brackets
    ([nesting_too_deep], [duplicate_key_unparseable], [whitespace_outside_json]);
    anything that raises anyway is COULD NOT LOOK [internal_error], never a
    traceback and never a green.
    """
    try:
        return _reconcile(tape_a, tape_b, pins=pins, pin_path=pin_path)
    except Exception as e:  # the fence: an answer, not a crash
        why = f"reconcile could not finish: {type(e).__name__} [internal_error]"
        return Reconciliation(verdict=COULD_NOT_LOOK, reason=why, could_not_look=[why])


def _reconcile(tape_a, tape_b, *, pins=None, pin_path=None) -> Reconciliation:
    findings: list = []
    cnl: list = []
    checked: list = []
    tapes = [_load("tape_a", tape_a, findings), _load("tape_b", tape_b, findings)]
    for t in tapes:
        if t.cnl:
            cnl.append(t.cnl)

    readable = [t for t in tapes if not t.cnl and not t.broken]
    for t in readable:
        _walk_index(t, findings)

    agent = next((t for t in tapes if t.side == "agent"), None)
    tool = next((t for t in tapes if t.side == "tool"), None)
    sides = [t.side for t in tapes if t.side]
    if len(sides) == 2 and sides[0] == sides[1]:
        cnl.append(f"both tapes are {sides[0]}-side tapes; reconcile needs one of each")
        agent = tool = None
    # An empty tape has no row to name its side: it is the side the other is not.
    if len(readable) == 2 and agent is None and tool is not None:
        agent = next(t for t in readable if t is not tool and t.side is None)
    elif len(readable) == 2 and tool is None and agent is not None:
        tool = next(t for t in readable if t is not agent and t.side is None)
    if len(readable) == 2 and not tapes[0].rows and not tapes[1].rows:
        cnl.append("both tapes are empty: an idle agent and a silent recorder look identical")

    matched = 0
    can_align = (agent is not None and tool is not None and agent in readable
                 and tool in readable and (agent.rows or tool.rows))
    if can_align:
        agent.side, tool.side = "agent", "tool"
        matched = _align(agent.calls, tool.calls, findings)

    if pin_path is not None:
        try:
            pins = list(pins or []) + load_pins(pin_path)
        except (OSError, ValueError) as e:
            cnl.append(f"pin unreadable: {e}")
        except RecursionError:
            cnl.append("pin unreadable: nested deeper than the JSON reader goes [nesting_too_deep]")
    for pin in pins or []:
        for t in _pin_targets(pin, tapes):
            _check_pin(pin, t, findings, cnl, checked)

    counts = {t.name: len(t.rows) for t in tapes}
    r = Reconciliation(verdict=MATCHED, matched=matched, counts=counts,
                       findings=sorted(findings, key=lambda f: (f.at or 0, f.verdict)),
                       could_not_look=cnl, pins_checked=checked)
    if findings:
        h = _headline(findings)
        r.verdict, r.at, r.side, r.reason = h.verdict, h.at, h.side, h.reason
    elif cnl or not can_align:
        r.verdict = COULD_NOT_LOOK
        r.reason = cnl[0] if cnl else "the two tapes could not be paired"
    else:
        r.reason = f"{matched} calls on each tape, same digests"
    return r


def main(argv: list[str]) -> int:
    """`reconcile <tape_a> <tape_b> [--pin PIN] [--legacy-exit]`. Prints JSON,
    returns the exit code from arcaeon.verdict (COULD NOT LOOK = 3), or the
    pre-0.9 code (COULD NOT LOOK = 2) with --legacy-exit."""
    args, legacy = _v.pop_legacy_flag(argv)
    pin = None
    if "--pin" in args:
        k = args.index("--pin")
        if k + 1 >= len(args):
            print(json.dumps({"verdict": COULD_NOT_LOOK, "reason": "--pin needs a path"}))
            return (LEGACY_EXIT_CODES if legacy else EXIT_CODES)[COULD_NOT_LOOK]
        pin = args[k + 1]
        del args[k:k + 2]
    if len(args) != 2:
        print("usage: arcaeon reconcile <tape_a> <tape_b> [--pin <pin.json>] [--legacy-exit]")
        return 2 if legacy else _v.EXIT_USAGE
    r = reconcile(args[0], args[1], pin_path=pin)
    print(json.dumps(r.to_dict(), indent=1))
    return LEGACY_EXIT_CODES[r.verdict] if legacy else r.exit_code
