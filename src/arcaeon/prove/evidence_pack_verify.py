# SPDX-License-Identifier: MIT
"""`arcaeon evidence-pack verify PACK`: check an evidence pack someone handed you.

    arcaeon evidence-pack verify PACK [--json]

Step 1 (K056): rehash every file the manifest lists and compare. A changed
byte is BROKEN naming the file; a listed file that is gone is COULD NOT LOOK
`reason_word: "missing"`; a file in the pack the manifest does not list is
BROKEN (nothing vouches for it). The manifest itself is not hashed (it holds
the hashes), which is why later steps recompute what it claims from the files.

Step 2 (K057): rerun the chain check on records.jsonl and compare its head
(last chain value and row count) to the manifest's `chain_head`. This is what
catches an edit whose manifest hash was fixed to hide it: the file hash then
agrees, and the chain does not. A break is BROKEN naming the ledger line.

Step 3 (K058): every row in window.jsonl must be byte-equal to the line it
names in records.jsonl, and the window's line numbers must be the ones the
manifest lists. An edited window row whose manifest hash was fixed is BROKEN
naming the line: the window is a view of the records, never a second copy.

Build-time findings (K059R): an untouched pack whose BUILD reached COULD NOT
LOOK (an empty window, rows whose time could not be read, a witness that
could not be reached) must never verify clean. So verify reads
could_not_look.json and the manifest's `counts`: the number of entries must
equal `counts.could_not_look` (an emptied file with its hash fixed is BROKEN,
"counts mismatch"), a build that recorded a BROKEN check stays BROKEN, and
any entry makes the pack COULD NOT LOOK, exit 3, with every reason listed.

The overall verdict is the worst step: BROKEN outranks COULD NOT LOOK, which
outranks VERIFIED. COULD NOT LOOK never exits 0.

Exit codes as every verb: 0 VERIFIED, 1 BROKEN, 2 bad usage, 3 COULD NOT LOOK.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Callable

from arcaeon import verdict as V

__all__ = ["verify_pack", "main", "STEPS"]

MANIFEST = "manifest.json"


def _worst(words: list[str]) -> str:
    if V.BROKEN in words:
        return V.BROKEN
    if V.COULD_NOT_LOOK in words or not words:
        return V.COULD_NOT_LOOK
    return V.VERIFIED


def _cnl(check: str, looked_for: str, where: str, reason_word: str, reason: str) -> dict:
    return {"check": check, "verdict": V.COULD_NOT_LOOK,
            **V.could_not_look(looked_for, where, reason_word, reason)}


def _step_hashes(pack: Path, manifest: dict) -> dict:
    """Rehash every file the manifest lists; name each one that differs."""
    check = "file hashes"
    listed = manifest.get("files")
    if not isinstance(listed, dict) or not listed:
        return _cnl(check, "a file list with sha256 values", MANIFEST, "unreadable",
                    "manifest.json has no `files` table to check against")
    # Walk the WHOLE folder, not just its top level: a file planted in a
    # subfolder is in the pack and nothing vouches for it, so it is unlisted.
    on_disk = {p.relative_to(pack).as_posix() for p in pack.rglob("*")
               if p.is_file()} - {MANIFEST}
    changed, missing = [], []
    for name in sorted(listed):
        p = pack / name
        if Path(name).name != name or not p.is_file():
            missing.append(name)
            continue
        if hashlib.sha256(p.read_bytes()).hexdigest() != listed[name]:
            changed.append(name)
    unlisted = sorted(on_disk - set(listed))
    res = {"check": check, "files_checked": len(listed) - len(missing),
           "changed": changed, "missing": missing, "unlisted": unlisted}
    if changed or unlisted:
        parts = []
        if changed:
            parts.append(f"sha256 differs from the manifest: {', '.join(changed)}")
        if unlisted:
            parts.append(f"not listed in the manifest: {', '.join(unlisted)}")
        res.update({"verdict": V.BROKEN, "finding": "; ".join(parts)})
        return res
    if missing:
        res.update({"verdict": V.COULD_NOT_LOOK,
                    **V.could_not_look(", ".join(missing), str(pack), "missing",
                                       "the manifest lists these files and they are "
                                       "not in the pack, so they could not be rehashed")})
        return res
    res["verdict"] = V.VERIFIED
    return res


def _break_line(first_break: str | None) -> int | None:
    m = re.match(r"line (\d+)\b", first_break or "")
    return int(m.group(1)) if m else None


def _step_chain(pack: Path, manifest: dict) -> dict:
    """Rerun the chain on records.jsonl and compare its head to the manifest."""
    from arcaeon.record.ledger import Ledger, verify_file

    check = "records chain and head"
    records = pack / "records.jsonl"
    if not records.is_file():
        return _cnl(check, "records.jsonl", str(pack), "missing",
                    "the pack has no records.jsonl, so there is no chain to rerun")
    claimed = manifest.get("chain_head")
    if not isinstance(claimed, dict) or "chain" not in claimed:
        return _cnl(check, "the chain head recorded at export", MANIFEST, "unreadable",
                    "manifest.json has no `chain_head` to compare the chain against")
    vr = verify_file(records)
    res = {"check": check, "rows": vr.rows, "first_break": vr.first_break,
           "breaks": vr.breaks, "manifest_chain": claimed.get("chain"),
           "manifest_rows": claimed.get("rows")}
    if vr.ok is False:
        line = _break_line(vr.first_break)
        res.update({"verdict": V.BROKEN, "break_line": line,
                    "finding": f"records.jsonl chain breaks at {vr.first_break}"})
        return res
    if vr.ok is None:
        scope = getattr(vr, "verified_scope", "") or ""
        word = "empty" if scope == "empty" else "bounded"
        res.update({"verdict": V.COULD_NOT_LOOK, **V.could_not_look(
            "chain links for every record", f"records.jsonl (verified_scope={scope})",
            word, "the chain check did not cover every row, so it reached no verdict")})
        return res
    head = Ledger(records).head()
    res.update({"chain": head.chain})
    if head.chain != claimed.get("chain") or head.rows != claimed.get("rows"):
        res.update({"verdict": V.BROKEN, "finding": (
            f"records.jsonl head (rows {head.rows}, chain {head.chain}) differs from "
            f"the manifest's chain_head (rows {claimed.get('rows')}, chain "
            f"{claimed.get('chain')})")})
        return res
    res["verdict"] = V.VERIFIED
    return res


def _step_window(pack: Path, manifest: dict) -> dict:
    """Check every window.jsonl row is byte-equal to its records.jsonl line."""
    from arcaeon.prove.evidence_pack import _lines

    check = "window rows equal their records lines"
    window = pack / "window.jsonl"
    records = pack / "records.jsonl"
    for p in (window, records):
        if not p.is_file():
            return _cnl(check, p.name, str(pack), "missing",
                        f"the pack has no {p.name}, so the window rows could not be "
                        "compared with the records")
    rec_lines = _lines(records.read_bytes())
    differ, unreadable, seen = [], [], []
    for n, line in enumerate(_lines(window.read_bytes()), start=1):
        try:
            w = json.loads(line.decode("utf-8"))
            ln, raw = w["line"], w["raw"]
            if not isinstance(ln, int) or isinstance(ln, bool) or not isinstance(raw, str):
                raise ValueError("line must be an integer and raw a string")
        except (UnicodeDecodeError, ValueError, KeyError, TypeError):
            unreadable.append(n)
            continue
        seen.append(ln)
        if not 1 <= ln <= len(rec_lines) or raw.encode("utf-8") != rec_lines[ln - 1]:
            differ.append(ln)
    res = {"check": check, "rows_checked": len(seen), "differ_lines": differ,
           "unreadable_window_rows": unreadable}
    listed = (manifest.get("window") or {}).get("lines")
    problems = []
    if differ:
        problems.append("window.jsonl rows differ from records.jsonl at ledger line"
                        f"{'s' if len(differ) > 1 else ''} "
                        f"{', '.join(str(d) for d in differ)}")
    if unreadable:
        problems.append(f"window.jsonl rows {unreadable} are not "
                        '{"line": N, "raw": ...} objects')
    if isinstance(listed, list) and listed != seen:
        problems.append(f"window.jsonl names ledger lines {seen}, the manifest "
                        f"lists {listed}")
    if problems:
        res.update({"verdict": V.BROKEN, "finding": "; ".join(problems)})
        return res
    if not isinstance(listed, list):
        res.update({"verdict": V.COULD_NOT_LOOK, **V.could_not_look(
            "the window's ledger line numbers", MANIFEST, "unreadable",
            "manifest.json has no `window.lines` list to compare the window against")})
        return res
    res["verdict"] = V.VERIFIED
    return res


CNL_FILE = "could_not_look.json"
_CNL_FIELDS = ("looked_for", "where", "reason_word", "reason")


def _step_build(pack: Path, manifest: dict) -> dict:
    """What the build itself could not look at, and whether the pack still says so."""
    check = "build-time findings"
    p = pack / CNL_FILE
    if not p.is_file():
        return _cnl(check, CNL_FILE, str(pack), "missing",
                    "the pack has no could_not_look.json, so what the build could not "
                    "look at is unknown")
    try:
        entries = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
            raise ValueError("not a JSON list of objects")
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return _cnl(check, CNL_FILE, str(pack), "unreadable",
                    f"could_not_look.json could not be read as a list of entries ({e})")
    counts = manifest.get("counts")
    if not isinstance(counts, dict) or not isinstance(counts.get("could_not_look"), int):
        return _cnl(check, "the build's verdict counts", MANIFEST, "unreadable",
                    "manifest.json has no `counts.could_not_look` to check the file against")
    res = {"check": check, "entries": entries, "manifest_counts": counts}
    problems = []
    if len(entries) != counts["could_not_look"]:
        problems.append(f"counts mismatch: could_not_look.json holds {len(entries)} "
                        f"entr{'y' if len(entries) == 1 else 'ies'}, the manifest's "
                        f"counts.could_not_look is {counts['could_not_look']}")
    checks = manifest.get("checks")
    if isinstance(checks, list):
        by_word = {w: sum(isinstance(c, dict) and c.get("verdict") == w for c in checks)
                   for w in (V.VERIFIED, V.BROKEN, V.COULD_NOT_LOOK)}
        claimed = {V.VERIFIED: counts.get("verified"), V.BROKEN: counts.get("broken"),
                   V.COULD_NOT_LOOK: counts.get("could_not_look")}
        if by_word != claimed:
            problems.append("counts mismatch: the manifest's `checks` list does not add "
                            "up to its `counts`")
    if problems:
        res.update({"verdict": V.BROKEN, "finding": "; ".join(problems)})
        return res
    if (counts.get("broken") or 0) > 0 or manifest.get("verdict") == V.BROKEN:
        res.update({"verdict": V.BROKEN, "finding": (
            f"the build recorded {counts.get('broken') or 0} BROKEN check(s); "
            "integrity.json names the break")})
        return res
    if entries:
        first = entries[0]
        rw = first.get("reason_word")
        res.update({"verdict": V.COULD_NOT_LOOK, **V.could_not_look(
            first.get("looked_for"), first.get("where"),
            rw if rw in V.REASON_WORDS else "unreadable",
            f"the build could not look at {len(entries)} thing(s); first: "
            f"{first.get('reason')}")})
        return res
    res["verdict"] = V.VERIFIED
    return res


#: The verify steps, in order. Each takes (pack folder, loaded manifest) and
#: returns one check dict with a `verdict` word.
STEPS: list[Callable[[Path, dict], dict]] = [_step_hashes, _step_chain,
                                              _step_window, _step_build]


def verify_pack(pack: str | Path) -> dict:
    """Verify the pack folder `pack`. Returns `verdict`, integer `exit`,
    `pack`, `checks` (one per step) and, when BROKEN, `finding` naming what
    broke. Never raises on a damaged or absent pack: that is a verdict."""
    pack = Path(pack)
    base = {"pack": str(pack)}
    if not pack.is_dir():
        c = _cnl("pack folder", "an evidence pack folder", str(pack), "missing",
                 "no folder at that path, so there is no pack to check")
        return {**base, "verdict": V.COULD_NOT_LOOK, "exit": V.EXIT_COULD_NOT_LOOK,
                "checks": [c], **{k: c[k] for k in ("looked_for", "where", "reason_word",
                                                   "reason")}}
    mp = pack / MANIFEST
    try:
        manifest = json.loads(mp.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("not a JSON object")
    except FileNotFoundError:
        c = _cnl("manifest", MANIFEST, str(pack), "missing",
                 "the pack has no manifest.json, so nothing says what its files should be")
        manifest = None
    except (OSError, ValueError) as e:
        c = _cnl("manifest", MANIFEST, str(pack), "unreadable",
                 f"manifest.json could not be read as a JSON object ({e})")
        manifest = None
    if manifest is None:
        return {**base, "verdict": V.COULD_NOT_LOOK, "exit": V.EXIT_COULD_NOT_LOOK,
                "checks": [c], **{k: c[k] for k in ("looked_for", "where", "reason_word",
                                                   "reason")}}
    checks = [step(pack, manifest) for step in STEPS]
    word = _worst([c["verdict"] for c in checks])
    res = {**base, "verdict": word, "exit": V.EXIT_BY_WORD[word], "checks": checks}
    if word == V.BROKEN:
        res["finding"] = "; ".join(f"{c['check']}: {c['finding']}" for c in checks
                                   if c["verdict"] == V.BROKEN)
    if word != V.VERIFIED:
        # every reason, the build's own entries included, so exit 3 says why
        reasons = []
        for c in checks:
            if c["verdict"] == V.COULD_NOT_LOOK and c["check"] != "build-time findings":
                reasons.append({"check": c["check"], **{k: c[k] for k in _CNL_FIELDS}})
            for e in c.get("entries") or []:
                reasons.append({"check": e.get("check", "build"),
                                **{k: e.get(k) for k in _CNL_FIELDS}})
        res["could_not_look"] = reasons
    if word == V.COULD_NOT_LOOK:
        first = next(c for c in checks if c["verdict"] == V.COULD_NOT_LOOK)
        res.update({k: first[k] for k in _CNL_FIELDS})
    return res


def _parser(prog: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=prog, description="Verify an evidence pack: rehash "
                                "every file against its manifest, rerun the chain.")
    p.add_argument("pack", help="the evidence pack folder")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    return p


def main(argv: list[str] | None = None, *,
         prog: str = "arcaeon evidence-pack verify") -> int:
    a = _parser(prog).parse_args(argv)
    res = verify_pack(a.pack)
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        line = f"{res['verdict']}: evidence pack {res['pack']}"
        if res.get("finding"):
            line += f" ({res['finding']})"
        elif res.get("reason"):
            line += f" ({res['reason_word']}: {res['reason']})"
        print(line)
        for r in res.get("could_not_look") or []:
            print(f"  {V.COULD_NOT_LOOK} [{r['reason_word']}] {r['check']}: {r['reason']}")
    return res["exit"]


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
