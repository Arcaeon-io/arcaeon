# SPDX-License-Identifier: MIT
"""arcaeon.prove.tally_chain: the tally and the exchange logs sealed as a chain of their own (TE-47).

    arcaeon tally seal CHAIN.jsonl... --log TALLY_CHAIN.jsonl [--out TALLY.json]
                       [--settled-only] [--checked-only] [--window 30d]
                       [--groups FILE] [--aliases FILE] [--now T]
    arcaeon tally pin --log TALLY_CHAIN.jsonl --dry-run [--out S.json]
                      [--chain-id ID] [--prev-pin-sha256 HEX]
    arcaeon tally verify --log TALLY_CHAIN.jsonl [--inputs CHAIN.jsonl...]
                         [--statement S.json] [--groups FILE] [--aliases FILE]

`seal` runs `tally.build`, replaces every local path in the result with the
file's name, and appends one row (kind "tally.snapshot") to the tally chain
through `Ledger.append`. The row commits to the tally (sha256 of its json-c14n
v1 bytes) and to the exact bytes and tip of every exchange log it read, by
name: no path is sealed.

`pin --dry-run` builds the pin statement for the tally chain's tip and prints
it. It is the only mode: the live pin (a Bitcoin timestamp, a public mirror)
is the operator's scheduled task, not this verb's.

`verify` reads the tally chain (strict ledger verify), checks every snapshot
row's shape and that `at` and the ledger `ts` never go backwards; with
`--inputs` it checks each snapshot's input digests and tips against the logs
now on disk (a log that grew since is fine when the sealed rows are an exact
prefix) and rebuilds the tally from those prefixes; with `--statement` it
checks the statement commits to this chain. VERIFIED / BROKEN / COULD NOT LOOK;
never raises on hostile input.

THE PIN STATEMENT is the v2 pin statement of the operator's canon witness,
reproduced field for field (docs/TALLY.md names the source file and commit):
{chain, chain_values_sha256, file_sha256, file_sha256_of: "lf",
prev_pin_sha256, rows, stated_at, tip, v: 2}, serialized with sorted keys,
"," and ":" separators, UTF-8, not ASCII-escaped. Un-editable is not
un-gameable: a wash trade is sealed faithfully as a wash trade.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from arcaeon import verdict as V
from arcaeon.record.row import canon_json, loads_strict

__all__ = ["SNAPSHOT_KIND", "SNAPSHOT_VERSION", "VERIFY_KIND", "PIN_STATEMENT_FIELDS",
           "DEFAULT_CHAIN_ID", "TallyChainError", "seal", "relativize", "pin_statement",
           "statement_canonical", "statement_sha256", "verify", "main"]

SNAPSHOT_KIND = "tally.snapshot"
SNAPSHOT_VERSION = 1
VERIFY_KIND = "arcaeon.tally.chain.verify/v1"
DEFAULT_CHAIN_ID = "arcaeon-tally"
SHA256_OF = "lf"
#: The v2 pin statement's fields (W18 shape), as the witness builder writes them.
PIN_STATEMENT_KIND = 2
PIN_STATEMENT_FIELDS = ("chain", "chain_values_sha256", "file_sha256", "file_sha256_of",
                        "prev_pin_sha256", "rows", "stated_at", "tip", "v")
LISTING_FIELD = "public_listing_sha256"
MAX_LOG_BYTES = 64 << 20
MAX_STATEMENT_BYTES = 1 << 20
SNAPSHOT_FIELDS = ("kind", "v", "tally_kind", "tally_sha256", "tally_verdict", "options",
                   "inputs", "at", "ts", "chain")
INPUT_FIELDS = ("name", "sha256", "sha256_of", "rows", "chain_tip")
OPTION_FIELDS = ("window", "settled_only", "checked_only", "now", "groups", "aliases")

_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
_HEX = re.compile(r"[0-9a-f]{32,64}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_ABS = re.compile(r"(?:^|[\s'\"(=])(?:[A-Za-z]:[\\/]|\\\\|/(?:[^/\s]+/)+)")

LIMITS = (
    "un-editable, not un-gameable: the chain proves the tally was not changed after it was "
    "sealed, not that the trades behind it were real; a wash trade is sealed faithfully as "
    "a wash trade",
    "`at` and `ts` are the sealer's clock; going backwards is caught, a wrong clock is not",
    "a truncated or re-minted tally chain still verifies on its own: the dry-run statement "
    "is what an operator pins outside their control, and only a pin closes that gap",
)


class TallyChainError(ValueError):
    """seal or pin refused before writing anything."""


# --- bytes and rows ------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _read_capped(path: Path, cap: int) -> bytes:
    """The file's bytes, or OSError/ValueError with a reason."""
    if not path.exists():
        raise FileNotFoundError(f"{path.name} is not there")
    if not path.is_file():
        raise OSError(f"{path.name} is not a file")
    if path.stat().st_size > cap:
        raise ValueError(f"{path.name} is over {cap} bytes; not read")
    return path.read_bytes()


def _lf(data: bytes) -> bytes:
    """LF-canonical bytes: every CRLF becomes LF (a bare CR is left alone)."""
    return bytes(data).replace(b"\r\n", b"\n")


def _lines(lf: bytes) -> list[tuple[int, bytes]]:
    """(end offset, line bytes) of every non-blank line of LF-canonical bytes,
    the end offset just past the line's LF when it has one."""
    out, pos = [], 0
    for part in lf.split(b"\n"):
        end = pos + len(part)
        has_lf = end < len(lf)
        if part.decode("utf-8", "replace").strip():
            out.append((end + 1 if has_lf else end, part))
        pos = end + 1
    return out


def _row_chain(line: bytes) -> str | None:
    try:
        obj = loads_strict(line.decode("utf-8").strip())
    except (UnicodeDecodeError, ValueError):
        return None
    c = obj.get("chain") if isinstance(obj, dict) else None
    return c if isinstance(c, str) else None


def _prefix_sha(lf: bytes, lines: list[tuple[int, bytes]], rows: int) -> str:
    """sha256 of rows 1..rows: the LF-canonical bytes through the end of row
    `rows`, a missing final LF supplied (a later append heals it with one)."""
    b = lf[:lines[rows - 1][0]] if rows else b""
    if b and not b.endswith(b"\n"):
        b += b"\n"
    return hashlib.sha256(b).hexdigest()


def _input_record(path: Path) -> dict:
    data = _read_capped(path, MAX_LOG_BYTES)
    lf = _lf(data)
    lines = _lines(lf)
    return {"name": path.name, "sha256": _prefix_sha(lf, lines, len(lines)),
            "sha256_of": SHA256_OF, "rows": len(lines),
            "chain_tip": _row_chain(lines[-1][1]) if lines else None}


def _side_record(src: Any) -> dict | None:
    if src is None or isinstance(src, (dict, list)):
        return None if src is None else {"name": None, "sha256": hashlib.sha256(
            canon_json(src)).hexdigest(), "sha256_of": "json-c14n"}
    p = Path(src)
    return {"name": p.name, "sha256": hashlib.sha256(_lf(_read_capped(p, MAX_LOG_BYTES)))
            .hexdigest(), "sha256_of": SHA256_OF}


# --- relativize ----------------------------------------------------------------------------

def _path_forms(p: Path) -> set[str]:
    forms = {str(p)}
    for fn in (p.absolute, p.resolve):
        try:
            forms.add(str(fn()))
        except (OSError, RuntimeError, ValueError):
            pass
    return forms | {f.replace("\\", "/") for f in forms} | {f.replace("/", "\\") for f in forms}


def relativize(obj: Any, paths) -> Any:
    """A copy of `obj` with every spelling of each path in `paths` replaced by
    the file's name. Longest spelling first, so a parent never eats a child."""
    repl: list[tuple[str, str]] = []
    for p in paths:
        p = Path(p)
        repl += [(f, p.name) for f in _path_forms(p) if f and f != p.name]
    repl.sort(key=lambda kv: -len(kv[0]))

    def walk(o: Any) -> Any:
        if isinstance(o, str):
            for a, b in repl:
                if a in o:
                    o = o.replace(a, b)
            return o
        if isinstance(o, dict):
            return {walk(k): walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        return o
    return walk(obj)


#: The tally fields that carry a local path (the tool writes them from a file it
#: was handed). Every other string -- a DISPUTED reason, an exchange id, a
#: signer -- is participant-authored or built from file names only, and is
#: never read for paths: a reason of "see /var/log/x/" is the participant's
#: words, and must not stop the seal (review F3).
PATH_FIELDS = ("log", "where", "looked_for")


def _absolute_strings(t: Any) -> list[str]:
    """Strings in a tally's path-carrying fields that look like an absolute
    local path (POSIX, drive letter or UNC): top-level `where`/`looked_for`,
    each chains[] entry's `log`/`where`/`looked_for`, and each ids[] entry's
    chains[] (copies of chains[].log). Nothing else is read."""
    if not isinstance(t, dict):
        return []
    cands: list[Any] = [t.get(k) for k in PATH_FIELDS]
    for c in t.get("chains") or []:
        if isinstance(c, dict):
            cands += [c.get(k) for k in PATH_FIELDS]
    for i in t.get("ids") or []:
        if isinstance(i, dict) and isinstance(i.get("chains"), list):
            cands += i["chains"]
    return [s for s in cands if isinstance(s, str) and _ABS.search(s)]


# --- seal ----------------------------------------------------------------------------------

def _tally_sha(t: dict) -> str:
    return hashlib.sha256(canon_json(t)).hexdigest()


def _build(paths, opts: dict, groups, aliases) -> dict:
    from arcaeon.prove import tally as T
    return T.build(paths, window=opts["window"], settled_only=opts["settled_only"],
                   checked_only=opts["checked_only"], groups=groups, aliases=aliases,
                   now=opts["now"])


def seal(paths, *, log, window: str = "30d", settled_only: bool = False,
         checked_only: bool = False, groups: Any = None, aliases: Any = None,
         now: Any = None, at: datetime | None = None, out: Any = None) -> dict:
    """Build the tally, relativize it, and append one tally.snapshot row to
    `log`. Returns {row, chain, tally, log}. TallyChainError (nothing written)
    when an input cannot be read, two inputs share a file name, or an absolute
    path survives relativization. The row is written whatever the tally's own
    verdict: a BROKEN tally is a fact too, and the row records the verdict."""
    from arcaeon.prove import tally as T
    from arcaeon.record.ledger import Ledger
    paths = [Path(p) for p in paths]
    if not paths:
        raise TallyChainError("seal takes one or more exchange logs")
    names = [p.name for p in paths]
    dup = sorted({n for n in names if names.count(n) > 1})
    if dup:
        raise TallyChainError(f"two inputs share the file name {dup[0]!r}: the sealed row "
                              f"names inputs by file name, so rename one")
    log = Path(log)
    try:
        if log.exists() and any(log.resolve() == p.resolve() for p in paths):
            raise TallyChainError("the tally chain cannot also be one of its inputs")
    except OSError:
        pass
    try:
        T.parse_window(window)
        when_tally = T.parse_now(now) if now is not None else _now()
    except T.TallyError as e:
        raise TallyChainError(str(e)) from None
    inputs = []
    for p in paths:
        try:
            inputs.append(_input_record(p))
        except (OSError, ValueError) as e:
            raise TallyChainError(f"input {p.name} cannot be read ({e}); nothing sealed") from None
    try:
        g_rec, a_rec = _side_record(groups), _side_record(aliases)
    except (OSError, ValueError) as e:
        raise TallyChainError(f"a side file cannot be read ({e}); nothing sealed") from None
    opts = {"window": str(window).strip(), "settled_only": bool(settled_only),
            "checked_only": bool(checked_only), "now": when_tally.strftime(_TS_FMT),
            "groups": g_rec, "aliases": a_rec}
    side_paths = [Path(s) for s in (groups, aliases) if isinstance(s, (str, Path))]
    t = relativize(_build(paths, opts, groups, aliases), paths + side_paths)
    left = _absolute_strings(t)
    if left:
        raise TallyChainError(f"an absolute path survived relativization ({left[0][:80]!r}); "
                              f"nothing sealed")
    stamp = (at or _now()).astimezone(timezone.utc).strftime(_TS_FMT)
    row = {"kind": SNAPSHOT_KIND, "v": SNAPSHOT_VERSION, "tally_kind": t["kind"],
           "tally_sha256": _tally_sha(t), "tally_verdict": t["verdict"], "options": opts,
           "inputs": inputs, "at": stamp, "ts": stamp}
    if out is not None:
        Path(out).write_bytes(canon_json(t) + b"\n")
    chain = Ledger(log).append(dict(row))
    row["chain"] = chain
    return {"log": log.name, "row": row, "chain": chain, "tally": t}


# --- the pin statement (dry run only) ------------------------------------------------------

def statement_canonical(st: dict) -> str:
    """Sorted keys, "," and ":" separators, not ASCII-escaped: the bytes hashed."""
    return json.dumps(st, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def statement_sha256(st: dict) -> str:
    return hashlib.sha256(statement_canonical(st).encode("utf-8")).hexdigest()


def _chain_values(lines: list[tuple[int, bytes]]) -> list[str]:
    vals = []
    for n, (_, line) in enumerate(lines, 1):
        c = _row_chain(line)
        if c is None or not _HEX.fullmatch(c):
            raise TallyChainError(f"row {n} carries no hex chain value")
        vals.append(c)
    return vals


def _values_sha(vals: list[str]) -> str:
    return hashlib.sha256("".join(v + "\n" for v in vals).encode("utf-8")).hexdigest()


def pin_statement(log, *, chain_id: str = DEFAULT_CHAIN_ID, prev_pin_sha256: str | None = None,
                  stated_at: str | None = None) -> dict:
    """The v2 pin statement for the tally chain's current tip. Refuses
    (TallyChainError) a log that is missing, empty or does not verify: a pin
    over a broken chain asserts what the file cannot support."""
    from arcaeon.record.ledger import verify_file
    if not isinstance(chain_id, str) or not chain_id.strip() or chain_id != chain_id.strip():
        raise TallyChainError(f"--chain-id must be non-empty with no edge spaces: {chain_id!r}")
    if prev_pin_sha256 is not None and not _HEX64.fullmatch(str(prev_pin_sha256)):
        raise TallyChainError("--prev-pin-sha256 must be 64 lower-case hex")
    log = Path(log)
    try:
        raw = _read_capped(log, MAX_LOG_BYTES)
    except (OSError, ValueError) as e:
        raise TallyChainError(f"the tally chain cannot be read ({e})") from None
    lf = _lf(raw)
    lines = _lines(lf)
    if not lines:
        raise TallyChainError("the tally chain holds no rows")
    res = verify_file(log, strict=True)
    if res.ok is not True:
        raise TallyChainError(f"the tally chain does not verify "
                              f"({res.first_break or res.verified_scope}); no statement over it")
    try:
        vals = _chain_values(lines)
    except TallyChainError as e:
        raise TallyChainError(f"the tally chain does not verify ({e}); no statement over it") \
            from None
    return {"chain": chain_id, "chain_values_sha256": _values_sha(vals),
            "file_sha256": hashlib.sha256(lf).hexdigest(), "file_sha256_of": SHA256_OF,
            "prev_pin_sha256": prev_pin_sha256, "rows": len(vals),
            "stated_at": stated_at or _now().isoformat(timespec="seconds"),
            "tip": vals[-1], "v": PIN_STATEMENT_KIND}


def _statement_problem(st: Any) -> str | None:
    if not isinstance(st, dict):
        return f"a JSON {type(st).__name__}, not an object"
    keys = set(st)
    if st.get("v") != PIN_STATEMENT_KIND or keys not in (set(PIN_STATEMENT_FIELDS),
                                                       set(PIN_STATEMENT_FIELDS) | {LISTING_FIELD}):
        return f"not a v2 pin statement (v={st.get('v')!r}, fields {sorted(keys)})"
    if st["file_sha256_of"] != SHA256_OF:
        return f"file_sha256_of is {st['file_sha256_of']!r}, not 'lf'"
    if not isinstance(st["chain"], str) or not st["chain"]:
        return "chain is not a non-empty string"
    if not isinstance(st["rows"], int) or isinstance(st["rows"], bool) or st["rows"] < 1:
        return "rows is not a positive integer"
    if not isinstance(st["tip"], str) or not _HEX.fullmatch(st["tip"]):
        return "tip is not hex"
    for k in ("chain_values_sha256", "file_sha256") + ((LISTING_FIELD,) if LISTING_FIELD in st else ()):
        if not isinstance(st[k], str) or not _HEX64.fullmatch(st[k]):
            return f"{k} is not 64 hex"
    p = st["prev_pin_sha256"]
    if p is not None and not (isinstance(p, str) and _HEX64.fullmatch(p)):
        return "prev_pin_sha256 is neither null nor 64 hex"
    if not isinstance(st["stated_at"], str):
        return "stated_at is not a string"
    return None


# --- verify --------------------------------------------------------------------------------

def _at(text: Any) -> datetime | None:
    try:
        return datetime.strptime(text, _TS_FMT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _snapshot_problem(row: Any) -> str | None:
    if not isinstance(row, dict):
        return "not a JSON object"
    if row.get("kind") != SNAPSHOT_KIND:
        return f"kind {row.get('kind')!r} is not {SNAPSHOT_KIND}: a tally chain holds snapshots only"
    if set(row) != set(SNAPSHOT_FIELDS):
        return f"fields must be exactly {', '.join(sorted(SNAPSHOT_FIELDS))}"
    if row["v"] != SNAPSHOT_VERSION or isinstance(row["v"], bool):
        return f"unknown snapshot version {row['v']!r}"
    if not (isinstance(row["tally_sha256"], str) and _HEX64.fullmatch(row["tally_sha256"])):
        return "tally_sha256 is not 64 hex"
    if row["tally_verdict"] not in (V.VERIFIED, V.BROKEN, V.COULD_NOT_LOOK):
        return "tally_verdict is not one of the three words"
    if _at(row["at"]) is None or _at(row["ts"]) is None:
        return "at or ts is not a UTC time YYYY-MM-DDTHH:MM:SSZ"
    o = row["options"]
    if not isinstance(o, dict) or set(o) != set(OPTION_FIELDS) or _at(o.get("now")) is None:
        return "options is not window, settled_only, checked_only, now, groups, aliases"
    ins = row["inputs"]
    if not isinstance(ins, list) or not ins:
        return "inputs is not a non-empty list"
    seen = set()
    for i in ins:
        if not isinstance(i, dict) or set(i) != set(INPUT_FIELDS):
            return f"an input is not exactly {', '.join(INPUT_FIELDS)}"
        n = i["name"]
        if not isinstance(n, str) or not n or n != Path(n).name or "/" in n or "\\" in n \
                or ":" in n or n in seen:
            return f"input name {str(n)[:60]!r} is not a bare, unique file name"
        seen.add(n)
        if not (isinstance(i["sha256"], str) and _HEX64.fullmatch(i["sha256"])) \
                or i["sha256_of"] != SHA256_OF:
            return f"input {n}: sha256 is not 64 hex over lf bytes"
        if not isinstance(i["rows"], int) or isinstance(i["rows"], bool) or i["rows"] < 0:
            return f"input {n}: rows is not a count"
        if i["chain_tip"] is not None and not isinstance(i["chain_tip"], str):
            return f"input {n}: chain_tip is not a string or null"
    return None


def _check_input(rec: dict, path: Path | None) -> tuple[str, str, bytes | None]:
    """(word, reason, prefix bytes or None) for one sealed input against the
    log now on disk."""
    n = rec["name"]
    if path is None:
        return V.COULD_NOT_LOOK, f"input {n} was not given (--inputs)", None
    try:
        lf = _lf(_read_capped(path, MAX_LOG_BYTES))
    except (OSError, ValueError) as e:
        return V.COULD_NOT_LOOK, f"input {n} cannot be read ({e})", None
    lines = _lines(lf)
    rows = rec["rows"]
    if len(lines) < rows:
        return (V.BROKEN, f"input {n}: TRUNCATED, the snapshot read {rows} rows, the file "
                          f"has {len(lines)}", None)
    if _prefix_sha(lf, lines, rows) != rec["sha256"]:
        return (V.BROKEN, f"input {n}: rows 1..{rows} are not the bytes the snapshot sealed "
                          f"(a past row was edited, removed or re-serialized)", None)
    tip = _row_chain(lines[rows - 1][1]) if rows else None
    if tip != rec["chain_tip"]:
        return V.BROKEN, f"input {n}: row {rows} chain {tip} is not the sealed tip", None
    b = lf[:lines[rows - 1][0]] if rows else b""
    more = len(lines) - rows
    return (V.VERIFIED, f"input {n}: rows 1..{rows} match" +
            (f"; {more} row(s) appended since, not covered by this snapshot" if more else ""),
            b if b.endswith(b"\n") or not b else b + b"\n")


def _recompute(row: dict, prefixes: dict[str, bytes], side: dict) -> tuple[str | None, str]:
    """Rebuild the tally from the sealed prefixes; (word or None, note)."""
    o = row["options"]
    srcs = {}
    for k in ("groups", "aliases"):
        if o[k] is None:
            srcs[k] = None
            continue
        p = side.get(k)
        if p is None:
            return None, f"tally not rebuilt: the snapshot used a {k} file (--{k} not given)"
        try:
            got = hashlib.sha256(_lf(_read_capped(Path(p), MAX_LOG_BYTES))).hexdigest()
        except (OSError, ValueError) as e:
            return None, f"tally not rebuilt: the {k} file cannot be read ({e})"
        if got != o[k].get("sha256"):
            return V.BROKEN, f"the {k} file is not the one the snapshot sealed"
        srcs[k] = p
    with tempfile.TemporaryDirectory(prefix="arcaeon-tally-") as d:
        paths = []
        for i in row["inputs"]:
            p = Path(d) / i["name"]
            p.write_bytes(prefixes[i["name"]])
            paths.append(p)
        side_paths = [Path(s) for s in srcs.values() if s is not None]
        t = relativize(_build(paths, o, srcs["groups"], srcs["aliases"]), paths + side_paths)
    if _tally_sha(t) != row["tally_sha256"]:
        return V.BROKEN, "the tally rebuilt from the sealed inputs does not hash to tally_sha256"
    return V.VERIFIED, "the tally rebuilt from the sealed inputs hashes to tally_sha256"


def _check_statement(spath: Path, lf: bytes, lines, vals: list[str]) -> dict:
    out: dict[str, Any] = {"file": spath.name, "verdict": None, "reason": None}
    try:
        st = loads_strict(_read_capped(spath, MAX_STATEMENT_BYTES).decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as e:
        out.update(verdict=V.COULD_NOT_LOOK, reason=f"the statement cannot be read as JSON "
                                                    f"({type(e).__name__})")
        return out
    why = _statement_problem(st)
    if why:
        out.update(verdict=V.COULD_NOT_LOOK, reason=f"the statement is not readable as one: {why}")
        return out
    n = st["rows"]
    out.update(rows=n, tip=st["tip"], chain=st["chain"], stated_at=st["stated_at"],
               statement_sha256=statement_sha256(st))
    if len(vals) < n:
        bad = f"TRUNCATED: the statement names {n} rows, the chain has {len(vals)}"
    elif vals[n - 1] != st["tip"]:
        bad = f"row {n} chain {vals[n - 1]} is not the statement's tip {st['tip']}"
    elif _values_sha(vals[:n]) != st["chain_values_sha256"]:
        bad = f"chain values 1..{n} do not hash to the statement's chain_values_sha256"
    elif hashlib.sha256(lf[:lines[n - 1][0]]).hexdigest() != st["file_sha256"]:
        bad = f"rows 1..{n} do not hash to the statement's file_sha256 (re-serialized bytes)"
    else:
        bad = None
    if bad:
        out.update(verdict=V.BROKEN, reason=f"the statement does not commit to this chain: {bad}")
    else:
        more = len(vals) - n
        out.update(verdict=V.VERIFIED, reason=f"the statement commits to rows 1..{n}, tip "
                   f"{st['tip']}" + (f"; {more} row(s) appended since are not covered"
                                     if more else " (the current tip)"))
    return out


def verify(log, *, inputs=None, statement=None, groups=None, aliases=None) -> dict:
    """VERIFIED / BROKEN / COULD NOT LOOK for a tally chain. Never raises."""
    r: dict[str, Any] = {"kind": VERIFY_KIND, "verdict": None, "reason": None,
                         "log": Path(str(log)).name, "chain": None, "snapshots": [],
                         "statement": None, "findings": [], "limits": list(LIMITS)}
    try:
        return _verify(r, Path(log), [Path(p) for p in inputs] if inputs is not None else None,
                       Path(statement) if statement is not None else None,
                       {"groups": groups, "aliases": aliases})
    except Exception as e:  # noqa: BLE001  never a traceback, never a green
        why = f"the check could not finish ({type(e).__name__})"
        r.update({"verdict": V.COULD_NOT_LOOK, "reason": why,
                  **V.could_not_look("a finished tally chain check", str(log), "unreadable", why)})
        return r


def _cnl(r: dict, looked_for: str, where: str, word: str, why: str) -> dict:
    r.update({"verdict": V.COULD_NOT_LOOK, "reason": why,
              **V.could_not_look(looked_for, where, word, why)})
    r["findings"].append(f"{V.COULD_NOT_LOOK}: {why}")
    return r


def _verify(r: dict, log: Path, inputs: list[Path] | None, spath: Path | None,
            side: dict) -> dict:
    from arcaeon.record.ledger import verify_file
    try:
        raw = _read_capped(log, MAX_LOG_BYTES)
    except FileNotFoundError as e:
        return _cnl(r, "the tally chain", str(log), "missing", str(e))
    except (OSError, ValueError) as e:
        return _cnl(r, "the tally chain", str(log), "unreadable", str(e))
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        return _cnl(r, "the tally chain", str(log), "unreadable", f"{log.name} is not UTF-8 text")
    lf = _lf(raw)
    lines = _lines(lf)
    if not lines:
        return _cnl(r, "the tally chain", str(log), "empty", f"{log.name} holds no rows")
    res = verify_file(log, strict=True)
    r["chain"] = {"ok": res.ok, "rows": res.rows, "breaks": res.breaks,
                  "first_break": res.first_break}
    broken: list[str] = []
    cnl: list[str] = []
    if res.ok is not True:
        broken.append(f"the tally chain does not verify ({res.first_break or res.verified_scope})")
    by_name: dict[str, Path] = {}
    if inputs is not None:
        for p in inputs:
            if p.name in by_name:
                cnl.append(f"two --inputs share the file name {p.name!r}")
            by_name[p.name] = p
    used: set[str] = set()
    prev_at = prev_ts = None
    for n, (_, line) in enumerate(lines, 1):
        snap: dict[str, Any] = {"row": n, "verdict": None, "reason": None}
        r["snapshots"].append(snap)
        try:
            row = loads_strict(line.decode("utf-8").strip())
        except (UnicodeDecodeError, ValueError):
            row = None
        why = _snapshot_problem(row)
        if why:
            snap.update(verdict=V.BROKEN, reason=f"row {n}: {why}")
            broken.append(snap["reason"])
            continue
        at, ts = _at(row["at"]), _at(row["ts"])
        snap.update(at=row["at"], tally_sha256=row["tally_sha256"],
                    tally_verdict=row["tally_verdict"],
                    inputs=[{"name": i["name"], "rows": i["rows"]} for i in row["inputs"]])
        found: list[str] = []
        if prev_at is not None and at < prev_at:
            found.append(f"row {n}: BACKDATED, at {row['at']} is earlier than the previous "
                         f"snapshot's {prev_at.strftime(_TS_FMT)}")
        if prev_ts is not None and ts < prev_ts:
            found.append(f"row {n}: REORDERED, ledger ts {row['ts']} is earlier than the "
                         f"previous row's {prev_ts.strftime(_TS_FMT)}")
        prev_at = max(at, prev_at) if prev_at else at
        prev_ts = max(ts, prev_ts) if prev_ts else ts
        word = V.BROKEN if found else V.VERIFIED
        notes: list[str] = []
        if inputs is not None:
            prefixes: dict[str, bytes] = {}
            for rec in row["inputs"]:
                used.add(rec["name"])
                w, why, b = _check_input(rec, by_name.get(rec["name"]))
                snap["inputs"][[i["name"] for i in snap["inputs"]].index(rec["name"])].update(
                    verdict=w, reason=why)
                if w == V.BROKEN:
                    found.append(f"row {n}: {why}")
                elif w == V.COULD_NOT_LOOK:
                    notes.append(f"row {n}: {why}")
                else:
                    prefixes[rec["name"]] = b
            if not found and not notes:
                w, why = _recompute(row, prefixes, side)
                snap["tally_rebuilt"] = w
                if w == V.BROKEN:
                    found.append(f"row {n}: {why}")
                elif w is None:
                    snap["note"] = why
        if found:
            snap.update(verdict=V.BROKEN, reason="; ".join(found))
            broken.extend(found)
        elif notes:
            snap.update(verdict=V.COULD_NOT_LOOK, reason="; ".join(notes))
            cnl.extend(notes)
        else:
            snap.update(verdict=word, reason="the row is a well-formed snapshot, in order" +
                        ("; its inputs match" if inputs is not None else ""))
    if inputs is not None:
        extra = sorted(set(by_name) - used)
        if extra:
            r["findings"].append(f"note: --inputs not read by any snapshot: {', '.join(extra)}")
    if spath is not None:
        try:
            vals = _chain_values(lines)
        except TallyChainError as e:
            vals = None
            r["statement"] = {"file": spath.name, "verdict": V.BROKEN,
                              "reason": f"the chain's values cannot be listed: {e}"}
        if vals is not None:
            r["statement"] = _check_statement(spath, lf, lines, vals)
        s = r["statement"]
        (broken if s["verdict"] == V.BROKEN else cnl if s["verdict"] == V.COULD_NOT_LOOK
         else r["findings"]).append(f"statement {spath.name}: {s['reason']}")
    r["findings"] = broken + cnl + r["findings"]
    if broken:
        r["verdict"], r["reason"] = V.BROKEN, "; ".join(broken)
    elif cnl:
        r.update({"verdict": V.COULD_NOT_LOOK, "reason": "; ".join(cnl),
                  **V.could_not_look("every input and statement asked for", str(log),
                                     "missing" if any("not given" in c or "not there" in c
                                                      for c in cnl) else "unreadable",
                                     "; ".join(cnl))})
    else:
        r["verdict"] = V.VERIFIED
        r["reason"] = (f"the tally chain verifies: {len(lines)} snapshot(s), well formed, in "
                       f"order" + ("; every input matches what was sealed"
                                   if inputs is not None else "; inputs not checked (no --inputs)")
                       + ("; the statement commits to this chain" if spath is not None else ""))
    return r


# --- CLI -----------------------------------------------------------------------------------

_SEAL_SPEC = {"--log": "value", "--out": "value", "--json": "bool", "--settled-only": "bool",
              "--checked-only": "bool", "--window": "value", "--groups": "value",
              "--aliases": "value", "--now": "value"}
_PIN_SPEC = {"--log": "value", "--dry-run": "bool", "--out": "value", "--chain-id": "value",
             "--prev-pin-sha256": "value"}
_VERIFY_SPEC = {"--log": "value", "--inputs": "list", "--statement": "value",
                "--groups": "value", "--aliases": "value", "--json": "bool"}

LIVE_PIN_REFUSAL = ("refused: --dry-run is the only mode. The live pin (a Bitcoin timestamp, "
                    "a public mirror) is the operator's scheduled task, not this verb's; "
                    "nothing was written")


class Usage(Exception):
    pass


def _parse(argv, spec):
    from arcaeon.prove.envelope import _parse as p, _Usage as EU
    try:
        return p(argv, spec)
    except EU as e:
        raise Usage(str(e)) from None


def seal_cli(argv: list[str]) -> int:
    pos, o = _parse(argv, _SEAL_SPEC)
    if not pos:
        raise Usage("seal takes one or more exchange logs")
    if "--log" not in o:
        raise Usage("seal needs --log TALLY_CHAIN.jsonl")
    try:
        out = seal(pos, log=o["--log"], window=o.get("--window", "30d"),
                   settled_only=bool(o.get("--settled-only")),
                   checked_only=bool(o.get("--checked-only")), groups=o.get("--groups"),
                   aliases=o.get("--aliases"), now=o.get("--now"), out=o.get("--out"))
    except TallyChainError as e:
        msg = str(e)
        print(f"arcaeon tally seal: {msg}", file=sys.stderr)
        return V.EXIT_COULD_NOT_LOOK if "cannot be read" in msg else V.EXIT_USAGE
    except OSError as e:
        print(f"arcaeon tally seal: the tally chain cannot be written ({type(e).__name__}); "
              f"nothing sealed", file=sys.stderr)
        return V.EXIT_USAGE
    if o.get("--json"):
        print(json.dumps({"ok": True, "log": out["log"], "row": out["row"]}, indent=1,
                         ensure_ascii=False))
    else:
        row = out["row"]
        print(f"sealed row {row['chain']} in {out['log']}: tally {row['tally_verdict']}, "
              f"tally_sha256 {row['tally_sha256']}")
        for i in row["inputs"]:
            print(f"  input {i['name']}: {i['rows']} rows, sha256 {i['sha256']}, tip "
                  f"{i['chain_tip']}")
        print("un-editable, not un-gameable: a wash trade is sealed faithfully as a wash trade")
    return V.EXIT_GOOD


def pin_cli(argv: list[str]) -> int:
    pos, o = _parse(argv, _PIN_SPEC)
    if pos:
        raise Usage(f"pin takes no positional argument (got {pos[0]!r})")
    if not o.get("--dry-run"):
        print(f"arcaeon tally pin: {LIVE_PIN_REFUSAL}", file=sys.stderr)
        return V.EXIT_USAGE
    if "--log" not in o:
        raise Usage("pin needs --log TALLY_CHAIN.jsonl")
    try:
        st = pin_statement(o["--log"], chain_id=o.get("--chain-id", DEFAULT_CHAIN_ID),
                           prev_pin_sha256=o.get("--prev-pin-sha256"))
    except TallyChainError as e:
        msg = str(e)
        print(f"arcaeon tally pin: {msg}; nothing printed", file=sys.stderr)
        if "does not verify" in msg:
            return V.EXIT_BAD
        return V.EXIT_COULD_NOT_LOOK if ("cannot be read" in msg or "no rows" in msg) \
            else V.EXIT_USAGE
    text = statement_canonical(st)
    if "--out" in o:
        try:
            with open(o["--out"], "xb") as fh:
                fh.write(text.encode("utf-8"))
        except FileExistsError:
            print(f"arcaeon tally pin: {Path(o['--out']).name} exists; a statement file is "
                  f"never overwritten", file=sys.stderr)
            return V.EXIT_USAGE
        except OSError as e:
            print(f"arcaeon tally pin: cannot write --out ({type(e).__name__})", file=sys.stderr)
            return V.EXIT_USAGE
    print(text)
    print(f"dry run: statement sha256 {statement_sha256(st)}; nothing was pinned. The live "
          f"pin is the operator's scheduled task", file=sys.stderr)
    return V.EXIT_GOOD


def render(r: dict) -> str:
    lines = [f"{r['verdict']}: {r['reason']}"]
    for s in r["snapshots"]:
        lines.append(f"row {s['row']}: {s['verdict']}" + (f" at {s['at']}" if s.get("at") else "")
                     + (f" ({s['reason']})" if s["verdict"] != V.VERIFIED else ""))
        for i in s.get("inputs", []):
            if i.get("verdict"):
                lines.append(f"  {i['verdict']}: {i['reason']}")
        if s.get("note"):
            lines.append(f"  note: {s['note']}")
    if r.get("statement"):
        lines.append(f"statement {r['statement']['file']}: {r['statement']['verdict']}: "
                     f"{r['statement']['reason']}")
    lines.append("un-editable, not un-gameable: a wash trade is sealed faithfully as a wash trade")
    return "\n".join(lines)


def verify_cli(argv: list[str]) -> int:
    # `--inputs a b c`: every following token up to the next option is an input
    fixed, i = [], 0
    while i < len(argv):
        if argv[i] == "--inputs":
            i += 1
            got = False
            while i < len(argv) and not argv[i].startswith("--"):
                fixed += ["--inputs", argv[i]]
                i += 1
                got = True
            if not got:
                raise Usage("--inputs needs one or more exchange logs")
            continue
        fixed.append(argv[i])
        i += 1
    pos, o = _parse(fixed, _VERIFY_SPEC)
    if pos:
        raise Usage(f"verify takes no positional argument (got {pos[0]!r}); "
                    f"inputs go after --inputs")
    if "--log" not in o:
        raise Usage("verify needs --log TALLY_CHAIN.jsonl")
    r = verify(o["--log"], inputs=o.get("--inputs"), statement=o.get("--statement"),
               groups=o.get("--groups"), aliases=o.get("--aliases"))
    print(json.dumps(r, indent=1, ensure_ascii=False) if o.get("--json") else render(r))
    return V.exit_for(r["verdict"])
