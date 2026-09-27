# SPDX-License-Identifier: MIT
"""`arcaeon evidence-pack verify PACK`: check an evidence pack someone handed you.

    arcaeon evidence-pack verify PACK [--witness PINS] [--remote] [--json]

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

Step 4 (K060): pins. First, inside the pack: the manifest's pin list must
agree with integrity.json's witness block (and witness.json), the manifest's
chain_head row count with integrity.json's, and records.jsonl must still hold
each pinned head at its row (a tail cut below a pin, or a rewrite, is BROKEN).
Then against the witness itself, never the pack's copy of it. A local pin is
checked against the pin file named by `--witness`, as `arcaeon pin` writes
it: the file's own chain must hold, and it must hold the exact pin the pack
names (not merely a latest pin, which a later pin would move); with no pin
file given it is COULD NOT LOOK, "missing". A remote pin is read from the public witness through
`arcaeon.remote.check_head`, only with `--remote`; without it, or with no
network, it is COULD NOT LOOK `reason_word: "network"`, never VERIFIED. A pack
with no pin at all passes this step with `pins_checked: 0`: the tail was not
witnessed, which the README says in its does-not-show list. What no step can
catch is a pack whose every file was rewritten together with no pin to hold
it; only a witness the rewriter cannot reach does that.

Review 2 (K06xR): verify re-derives what it can from the pack itself and
never takes the manifest's word for it. `manifest.sha256` (beside the
manifest, "<hex>  manifest.json") must match the manifest's bytes: missing is
COULD NOT LOOK "missing", different is BROKEN. It catches an edit to the
manifest alone; a rewriter who recomputes it too is caught only by a pin. A
manifest without `checks` or `counts` is BROKEN "manifest incomplete".
could_not_look.json must equal the COULD NOT LOOK entries of `checks`. The
window is re-selected from records.jsonl with the manifest's own agent and
bounds; an empty window, or agent rows whose time could not be read, that the
pack does not list as COULD NOT LOOK is BROKEN (the pack hides its finding).
With `--witness` and no pin listed, the pin file is searched for this ledger
(a namespace named by `--namespace`, or one whose pin matches records.jsonl
at its row): a pin past the pack's head, taken before the pack was built, is
BROKEN "pin beyond head"; one the pack claims to predate is COULD NOT LOOK
"bounded" (its build time is its own word); pins that cannot be tied to
these records are COULD NOT LOOK "name_not_found", never VERIFIED.

AAT (K064): a pack built with --format aat lists `aat` in its manifest.
Verify recomputes aat.jsonl from records.jsonl (the same mapping, the same
JCS chain) and compares it byte for byte, reruns the chain over the file as
it stands, checks its head against the manifest, and rebuilds aat_gaps.json's
entries. Any difference is BROKEN naming the file. A pack without `aat` in
its manifest has no AAT files to check (a planted one is unlisted, step 1).

Mandate (K066): a pack built with --mandate lists `mandate` in its manifest.
Verify rebuilds mandate_rows.json from records.jsonl, the manifest's window
lines and mandate_file.json (the copied mandate), byte for byte; the copy's
sha256 must be the one the section names; the manifest's `mandate` block and
the mandate checks in its `checks` must be the ones the section stands for.
Any difference is BROKEN naming the file, so an outside row cannot be
dropped, nor a count or a could-not-look hidden, by fixing the hashes.

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
MANIFEST_SHA = "manifest.sha256"


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
               if p.is_file()} - {MANIFEST, MANIFEST_SHA}
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


def _step_manifest_hash(pack: Path, manifest: dict) -> dict:
    """The manifest's own bytes against manifest.sha256 beside it."""
    check = "manifest hash"
    side = pack / MANIFEST_SHA
    if not side.is_file():
        return _cnl(check, MANIFEST_SHA, str(pack), "missing",
                    "the pack has no manifest.sha256, so the manifest's own bytes "
                    "could not be checked")
    try:
        text = side.read_text(encoding="ascii").strip()
        want, _, name = text.partition("  ")
        if name != MANIFEST or not re.fullmatch(r"[0-9a-f]{64}", want):
            raise ValueError("not '<64 hex>  manifest.json'")
    except (OSError, UnicodeDecodeError, ValueError) as e:
        return _cnl(check, MANIFEST_SHA, str(pack), "unreadable",
                    f"manifest.sha256 could not be read ({e})")
    got = hashlib.sha256((pack / MANIFEST).read_bytes()).hexdigest()
    res = {"check": check, "manifest_sha256": got, "recorded": want}
    if got != want:
        res.update({"verdict": V.BROKEN, "finding": (
            "manifest.json's sha256 differs from manifest.sha256: the manifest was "
            "changed after it was written")})
        return res
    res["verdict"] = V.VERIFIED
    return res


def _step_aat(pack: Path, manifest: dict) -> dict:
    """Recompute the AAT export from records.jsonl and compare (K064)."""
    from arcaeon.prove.aat_export import (AAT_CHAIN_ALGORITHM, build_gaps, chain_records,
                                          gaps_sidecar_bytes, map_row, verify_aat_bytes)
    from arcaeon.record.ledger import verify_file
    from arcaeon.prove.evidence_pack import _lines

    check = "aat export"
    claim = manifest.get("aat")
    if claim is None:
        return {"check": check, "verdict": V.VERIFIED,
                "note": "this pack was built without --format aat"}
    if not isinstance(claim, dict) or not all(
            isinstance(claim.get(k), str) for k in ("file", "gaps_file")):
        return {"check": check, "verdict": V.BROKEN,
                "finding": "manifest incomplete: `aat` names no file and gaps_file"}
    if any(Path(claim[k]).name != claim[k] for k in ("file", "gaps_file")):
        return {"check": check, "verdict": V.BROKEN,
                "finding": "the manifest's `aat` names a file outside the pack folder"}
    aat, gaps_p = pack / claim["file"], pack / claim["gaps_file"]
    records = pack / "records.jsonl"
    for p in (aat, gaps_p, records):
        if not p.is_file():
            return _cnl(check, p.name, str(pack), "missing",
                        f"the pack has no {p.name}, so the AAT export could not be "
                        "recomputed")
    raw = aat.read_bytes()
    problems = []
    run = verify_aat_bytes(raw)
    if not run["ok"]:
        problems.append(f"{aat.name}: {run['finding']}")
    recs, skipped = [], []
    for n, line in enumerate(_lines(records.read_bytes()), start=1):
        try:
            row = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            skipped.append(n)
            continue
        if not isinstance(row, dict):
            skipped.append(n)
            continue
        recs.append(map_row(row, line=n))
    lines, head, refused = chain_records(recs)
    want = b"".join(b + b"\n" for b in lines)
    if raw != want:
        got = _lines(raw)
        at = next((i for i, (a, b) in enumerate(zip(got, lines), start=1) if a != b),
                  min(len(got), len(lines)) + 1)
        problems.append(f"{aat.name} differs from the export recomputed from "
                        f"records.jsonl, first at line {at}")
    if claim.get("head") != head:
        problems.append(f"{aat.name}: the manifest's aat head {claim.get('head')} is not "
                        f"the recomputed head {head}")
    vr = verify_file(records)
    side = gaps_sidecar_bytes(
        aat.name, {"algorithm": AAT_CHAIN_ALGORITHM, "records": len(lines), "head": head},
        {"ok": vr.ok, "rows": vr.rows, "first_break": vr.first_break},
        build_gaps(recs, refused, skipped))
    if gaps_p.read_bytes() != side:
        problems.append(f"{gaps_p.name} differs from the gaps list recomputed from "
                        "records.jsonl")
    res = {"check": check, "records": len(lines), "head": head}
    if problems:
        res.update({"verdict": V.BROKEN, "finding": "; ".join(problems)})
        return res
    res["verdict"] = V.VERIFIED
    return res


def _step_mandate(pack: Path, manifest: dict) -> dict:
    """Rebuild mandate_rows.json from the records and the copied mandate (K066)."""
    from arcaeon.prove.evidence_pack import (MANDATE_COPY, MANDATE_ROWS, mandate_block,
                                             mandate_checks, mandate_rows_bytes,
                                             mandate_section)

    check = "mandate rows"
    claim = manifest.get("mandate")
    if claim is None:
        return {"check": check, "verdict": V.VERIFIED,
                "note": "this pack was built without --mandate"}
    if not isinstance(claim, dict) or claim.get("file") != MANDATE_ROWS or \
            claim.get("copy") not in (MANDATE_COPY, None):
        return {"check": check, "verdict": V.BROKEN,
                "finding": f"manifest incomplete: `mandate` does not name {MANDATE_ROWS}"}
    rows_p, records = pack / MANDATE_ROWS, pack / "records.jsonl"
    for p in (rows_p, records):
        if not p.is_file():
            return _cnl(check, p.name, str(pack), "missing",
                        f"the pack has no {p.name}, so the mandate rows could not be "
                        "rebuilt")
    copy = None
    if claim.get("copy") is not None:
        cp = pack / MANDATE_COPY
        if not cp.is_file():
            return _cnl(check, MANDATE_COPY, str(pack), "missing",
                        "the pack has no mandate_file.json, so the mandate's sha256 "
                        "could not be recomputed")
        copy = cp.read_bytes()
    lines = (manifest.get("window") or {}).get("lines")
    if not isinstance(lines, list):
        return _cnl(check, "the window's ledger line numbers", MANIFEST, "unreadable",
                    "manifest.json has no `window.lines`, so the mandate rows could not "
                    "be selected again")
    section = mandate_section(records.read_bytes(), lines,
                              mandate_name=claim.get("mandate_file"), mandate_bytes=copy)
    problems = []
    if rows_p.read_bytes() != mandate_rows_bytes(section):
        problems.append(f"{MANDATE_ROWS} differs from the section rebuilt from "
                        "records.jsonl and mandate_file.json")
    if claim != mandate_block(section):
        problems.append("the manifest's `mandate` block differs from the one rebuilt "
                        f"from the records (counts {section['counts']}, sha256 "
                        f"{section['mandate_file_sha256']})")
    want = mandate_checks(section)
    names = {c["check"] for c in want} | {"mandate file read",
                                         "mandate file is the one the gate loaded",
                                         "mandate inside count"}
    got = [c for c in manifest.get("checks") or [] if isinstance(c, dict)
           and c.get("check") in names]
    if got != want:
        problems.append("the manifest's mandate checks are not the ones the rebuilt "
                        "section stands for")
    res = {"check": check, "counts": section["counts"],
           "outside_rows": len(section["outside_rows"])}
    if problems:
        res.update({"verdict": V.BROKEN, "finding": "; ".join(problems)})
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
_CNL_ENTRY_KEYS = ("check",) + _CNL_FIELDS


def _rederive(pack: Path, manifest: dict, entries: list[dict]) -> list[str]:
    """What the build must have found, found again from records.jsonl.

    The window is re-selected with the manifest's own agent and bounds (the
    ones the README states). It must name the lines window.jsonl holds; an
    empty window must be listed as COULD NOT LOOK "empty", and agent rows
    whose time could not be read as "unreadable". A pack that hides one of
    these is BROKEN, whatever its counts say.
    """
    from arcaeon.prove.evidence_pack import PackUsageError, _lines, parse_when, select_window

    records, window = pack / "records.jsonl", pack / "window.jsonl"
    if not records.is_file() or not window.is_file():
        return []  # the hash and window steps already report a missing file
    problems = []
    win_rows = len(_lines(window.read_bytes()))
    words = [e.get("reason_word") for e in entries]
    w = manifest.get("window") if isinstance(manifest.get("window"), dict) else {}
    try:
        since, until = parse_when(w.get("from")), parse_when(w.get("to"))
        agent = w.get("agent")
        if agent is not None and not isinstance(agent, str):
            raise PackUsageError("agent is not a string")
    except (PackUsageError, TypeError, AttributeError):
        problems.append("the manifest's window (agent, from, to) could not be read, so "
                        "the window could not be selected again")
        since = until = agent = None
        rederived = None
    else:
        sel, unplaced = select_window(records.read_bytes(), agent=agent, since=since,
                                      until=until)
        rederived = [x["line"] for x in sel]
        if unplaced and "unreadable" not in words:
            problems.append(f"ledger lines {unplaced} match the agent with a time that "
                            "could not be read, and could_not_look.json does not say so")
    if rederived is not None:
        seen = []
        for line in _lines(window.read_bytes()):
            try:
                seen.append(json.loads(line.decode("utf-8")).get("line"))
            except (UnicodeDecodeError, ValueError, AttributeError):
                seen.append(None)
        if seen != rederived:
            problems.append(f"selecting the window again from records.jsonl gives ledger "
                            f"lines {rederived}, window.jsonl holds {seen}")
    if win_rows == 0 and "empty" not in words:
        problems.append("the window is empty and could_not_look.json does not say so "
                        "(an empty window is COULD NOT LOOK, never VERIFIED)")
    return problems


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
    checks = manifest.get("checks")
    incomplete = []
    if not isinstance(counts, dict) or not all(
            isinstance(counts.get(k), int) and not isinstance(counts.get(k), bool)
            for k in ("verified", "broken", "could_not_look")):
        incomplete.append("`counts` (verified, broken, could_not_look)")
    if not isinstance(checks, list) or not all(isinstance(c, dict) for c in checks):
        incomplete.append("`checks`")
    if incomplete:
        return {"check": check, "entries": entries, "verdict": V.BROKEN,
                "finding": (f"manifest incomplete: it has no readable "
                            f"{' or '.join(incomplete)}, which every pack writes")}
    res = {"check": check, "entries": entries, "manifest_counts": counts}
    problems = []
    listed_cnl = [{k: c.get(k) for k in _CNL_ENTRY_KEYS} for c in checks
                  if c.get("verdict") == V.COULD_NOT_LOOK]
    if listed_cnl != [{k: e.get(k) for k in _CNL_ENTRY_KEYS} for e in entries]:
        problems.append("could_not_look.json does not hold the COULD NOT LOOK "
                        "entries of the manifest's `checks`")
    problems += _rederive(pack, manifest, entries)
    if len(entries) != counts["could_not_look"]:
        problems.append(f"counts mismatch: could_not_look.json holds {len(entries)} "
                        f"entr{'y' if len(entries) == 1 else 'ies'}, the manifest's "
                        f"counts.could_not_look is {counts['could_not_look']}")
    by_word = {w: sum(c.get("verdict") == w for c in checks)
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


_REMOTE_KEYS = ("commit", "commit_url", "raw_record_url")


def _ref(pin: dict) -> tuple:
    return (pin.get("namespace"), pin.get("rows"), pin.get("chain"))


def _load_json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        return None


def _in_pack_pins(pack: Path, manifest: dict, integrity: dict) -> list[str]:
    """What the pack's own files say about its pins, cross-checked. Returns
    one finding per disagreement (empty when they agree)."""
    from arcaeon.prove.evidence_pack import _pins
    from arcaeon.record.ledger import chain_at

    problems = []
    wb = integrity.get("witness") if isinstance(integrity.get("witness"), dict) else {}
    listed = manifest.get("pins")
    if not isinstance(listed, list) or not all(isinstance(x, dict) for x in listed):
        return ["manifest.json has no readable `pins` list"]
    expected = _pins(wb)
    if sorted(map(_ref, listed), key=repr) != sorted(map(_ref, expected), key=repr):
        problems.append(f"the manifest lists pins {[list(_ref(x)) for x in listed]}, "
                        f"integrity.json's witness block records "
                        f"{[list(_ref(x)) for x in expected]}")
    wj = pack / "witness.json"
    if wj.is_file():
        w = _load_json(wj)
        if not isinstance(w, dict):
            problems.append("witness.json is not a JSON object")
        else:
            for k in ("namespace", "witness_rows", "witness_chain"):
                if w.get(k) != wb.get(k):
                    problems.append(f"witness.json {k} {w.get(k)!r} differs from "
                                    f"integrity.json's {wb.get(k)!r}")
    head = manifest.get("chain_head") or {}
    if (isinstance(integrity.get("rows"), int) and isinstance(head.get("rows"), int)
            and integrity["rows"] != head["rows"]):
        problems.append(f"row count mismatch: integrity.json says {integrity['rows']} "
                        f"rows, the manifest's chain_head says {head['rows']}")
    records = pack / "records.jsonl"
    for x in listed:
        ns, rows, chain = _ref(x)
        if not isinstance(rows, int) or not records.is_file():
            continue
        now = chain_at(records, rows)
        if now != chain:
            problems.append(f"records.jsonl does not hold the head pinned for {ns!r} "
                            f"(row {rows}: pinned {chain}, records say {now})")
    return problems


def _is_remote(wb: dict, pin: dict) -> bool:
    return wb.get("kind") == "remote_url" or any(pin.get(k) for k in _REMOTE_KEYS)


def _check_remote(pin: dict, remote: bool) -> dict:
    ns, rows, chain = _ref(pin)
    base = {"namespace": ns, "rows": rows, "chain": chain, "where": "remote"}
    looked = f"the public pin for {ns!r} at row {rows}"
    if not remote:
        return {**base, "verdict": V.COULD_NOT_LOOK, **V.could_not_look(
            looked, "the hosted witness", "network",
            "a remote pin is read only when asked (--remote); unread, it is not verified")}
    from arcaeon import remote as R
    out = R.check_head(ns, rows, chain)
    if not isinstance(out, dict):
        out = {"status": 0, "error": "no answer"}
    where = out.get("endpoint") or "the hosted witness"
    if out.get("status") == 0:
        return {**base, "verdict": V.COULD_NOT_LOOK, **V.could_not_look(
            looked, where, "network",
            f"the public witness could not be reached ({out.get('error')})")}
    if not out.get("ok"):
        rw = "name_not_found" if out.get("status") == 404 else "unreadable"
        return {**base, "verdict": V.COULD_NOT_LOOK, **V.could_not_look(
            looked, where, rw,
            f"the public witness answered {out.get('status')}: {out.get('error')}")}
    if out.get("witnessed") is True:
        return {**base, "verdict": V.VERIFIED,
                "raw_record_url": out.get("raw_record_url")}
    if out.get("witnessed") is False:
        return {**base, "verdict": V.BROKEN, "finding": (
            f"the public witness does not hold the head the pack says was pinned "
            f"for {ns!r} (rows {rows}, chain {chain})")}
    return {**base, "verdict": V.COULD_NOT_LOOK, **V.could_not_look(
        f"`witnessed` in the public witness's answer for {ns!r}", where, "unreadable",
        "the answer did not say whether this head is witnessed")}


def _check_local(pack: Path, pin: dict, witness) -> dict:
    from arcaeon.record.ledger import Ledger
    from arcaeon.record.ledger.witness import WitnessStore, verify_against_witness

    ns, rows, chain = _ref(pin)
    base = {"namespace": ns, "rows": rows, "chain": chain, "where": "local"}
    if witness is None or not Path(witness).is_file():
        return {**base, "verdict": V.COULD_NOT_LOOK, **V.could_not_look(
            f"the local pin file holding {ns!r}",
            str(witness) if witness is not None else "--witness (not given)", "missing",
            "a pin is checked against the witness itself, not the pack's copy of it; "
            "pass the pin file with --witness")}
    store = WitnessStore(witness)
    # The pin file's own chain first, as `arcaeon pin` and the export check it:
    # agreeing with an edited pin file proves nothing.
    self_check = store.verify()
    if self_check.get("ok") is False:
        return {**base, "verdict": V.COULD_NOT_LOOK, **V.could_not_look(
            f"an intact pin file holding {ns!r}", str(witness), "unreadable",
            f"the pin file fails its own chain ({self_check.get('first_break')}), "
            "so no pin in it can vouch for anything")}
    history = store.history(ns)
    if not history:
        return {**base, "verdict": V.COULD_NOT_LOOK, **V.could_not_look(
            f"a pin for {ns!r}", str(witness), "name_not_found",
            "the pin file holds no pin for this namespace")}
    # The exact pin the pack names, not merely the latest: a pack exported
    # before a later pin is not truncated, it is older.
    hit = next((h for h in history if h.get("rows") == rows and h.get("chain") == chain),
               None)
    later = history[-1].get("rows")
    res = {**base, "pin_file_latest_rows": later}
    if hit is not None:
        # records.jsonl holding this head at this row was checked in the pack
        # step; the pin file holding it is checked here.
        via = verify_against_witness(store, ns, Ledger(pack / "records.jsonl"))
        return {**res, "verdict": V.VERIFIED, "as_of": hit.get("as_of"),
                "against_latest_pin": via.verdict}
    return {**res, "verdict": V.BROKEN, "finding": (
        f"the pin file holds no pin for {ns!r} at rows {rows} with chain {chain}, "
        "the pin the pack says it was checked against")}


def _when(text):
    from arcaeon.prove.evidence_pack import PackUsageError, parse_when
    try:
        return parse_when(text) if isinstance(text, str) else None
    except PackUsageError:
        return None


def _unlisted_pins(pack: Path, manifest: dict, witness, namespace: str | None) -> dict:
    """A pack that lists no pin, checked against the pin file anyway.

    The pack's own files cannot name its namespace once pins are stripped
    from them, so this ledger's namespace is `namespace` when given, else any
    namespace in the pin file one of whose pins matches records.jsonl at its
    row. In that namespace: a pin at or below the head that records.jsonl
    does not hold is BROKEN; a pin past the head is BROKEN "pin beyond head"
    when it was taken before the pack was built, COULD NOT LOOK "bounded"
    when the pack's (self-stated) build time predates it. Pins that cannot
    be tied to these records are COULD NOT LOOK "name_not_found".
    """
    from arcaeon.record.ledger import Ledger, chain_at
    from arcaeon.record.ledger.witness import WitnessStore

    wp = Path(witness)
    looked = "pins for this ledger in the pin file"
    if not wp.is_file():
        return {"verdict": V.COULD_NOT_LOOK, **V.could_not_look(
            looked, str(wp), "missing", "the pin file named by --witness was not found")}
    store = WitnessStore(wp)
    if store.verify().get("ok") is False:
        return {"verdict": V.COULD_NOT_LOOK, **V.could_not_look(
            f"an intact pin file", str(wp), "unreadable",
            "the pin file fails its own chain, so no pin in it can vouch for anything")}
    records = pack / "records.jsonl"
    head_rows = Ledger(records).head().rows if records.is_file() else 0
    names = sorted({r.get("namespace") for r in _pin_rows(wp)
                    if isinstance(r.get("namespace"), str)})
    if namespace is not None:
        mine = [namespace]
    else:
        mine = [ns for ns in names
                if any(isinstance(h.get("rows"), int) and h["rows"] <= head_rows
                       and chain_at(records, h["rows"]) == h.get("chain")
                       for h in store.history(ns))]
    if not mine:
        if not names:
            return {"verdict": V.VERIFIED}
        return {"verdict": V.COULD_NOT_LOOK, **V.could_not_look(
            looked, str(wp), "name_not_found",
            f"the pack lists no pin and the pin file holds pins for {names}, none of "
            "which could be tied to these records; if one is this ledger's, pass it "
            "with --namespace")}
    built = _when(manifest.get("built_at"))
    problems, predates = [], []
    for ns in mine:
        for h in store.history(ns):
            rows, chain = h.get("rows"), h.get("chain")
            if not isinstance(rows, int):
                continue
            if rows <= head_rows:
                if chain_at(records, rows) != chain:
                    problems.append(f"the witness pinned {ns!r} at row {rows} with chain "
                                    f"{chain}; records.jsonl does not hold it")
                continue
            taken = _when(h.get("received_at")) or _when(h.get("as_of"))
            # built_at has whole seconds; a pin in the same second is not later
            if (built is not None and taken is not None
                    and taken.replace(microsecond=0) > built):
                predates.append((ns, rows))
            else:
                problems.append(f"pin beyond head: the witness pinned {ns!r} at row "
                                f"{rows}, past this pack's head at row {head_rows}, and "
                                "the pack lists no pin")
    if problems:
        return {"verdict": V.BROKEN, "namespaces": mine, "finding": "; ".join(problems)}
    if predates:
        return {"verdict": V.COULD_NOT_LOOK, "namespaces": mine, **V.could_not_look(
            f"rows past row {head_rows} pinned for {mine}", str(wp), "bounded",
            f"the witness holds pins past this pack's head {predates}; the pack says it "
            "was built before them, and its build time is its own word")}
    return {"verdict": V.VERIFIED, "namespaces": mine}


def _pin_rows(wp: Path) -> list[dict]:
    rows = []
    for line in wp.read_bytes().splitlines():
        try:
            r = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            continue
        if isinstance(r, dict):
            rows.append(r)
    return rows


def _step_pins(pack: Path, manifest: dict, *, witness=None, remote: bool = False,
               namespace: str | None = None) -> dict:
    """Check each pin inside the pack, then against the witness itself."""
    check = "pins"
    ip = pack / "integrity.json"
    integrity = _load_json(ip)
    if not isinstance(integrity, dict):
        return _cnl(check, "integrity.json", str(pack),
                    "unreadable" if ip.is_file() else "missing",
                    "integrity.json holds the witness block the pins are checked against")
    problems = _in_pack_pins(pack, manifest, integrity)
    listed = manifest.get("pins") if isinstance(manifest.get("pins"), list) else []
    res = {"check": check, "pins_checked": len(listed)}
    if problems:
        res.update({"verdict": V.BROKEN, "finding": "; ".join(problems)})
        return res
    if not listed:
        if witness is not None:
            res.update(_unlisted_pins(pack, manifest, witness, namespace))
            if res["verdict"] != V.VERIFIED:
                return res
        res.update({"verdict": V.VERIFIED, "note": (
            "no pin is listed, so the tail of the records was not witnessed")})
        return res
    wb = integrity.get("witness") or {}
    results = [_check_remote(x, remote) if _is_remote(wb, x) else
               _check_local(pack, x, witness) for x in listed]
    res["pins"] = results
    word = _worst([r["verdict"] for r in results])
    res["verdict"] = word
    if word == V.BROKEN:
        res["finding"] = "; ".join(r["finding"] for r in results
                                   if r["verdict"] == V.BROKEN)
    elif word == V.COULD_NOT_LOOK:
        first = next(r for r in results if r["verdict"] == V.COULD_NOT_LOOK)
        res.update({k: first[k] for k in _CNL_FIELDS})
    return res


#: The verify steps, in order. Each takes (pack folder, loaded manifest) and
#: returns one check dict with a `verdict` word. The pins step (_step_pins)
#: runs after these, since it takes verify's --witness / --remote options.
STEPS: list[Callable[[Path, dict], dict]] = [_step_hashes, _step_chain, _step_window,
                                              _step_build, _step_manifest_hash,
                                              _step_aat, _step_mandate]


def verify_pack(pack: str | Path, *, witness: str | Path | None = None,
                remote: bool = False, namespace: str | None = None) -> dict:
    """Verify the pack folder `pack`. Returns `verdict`, integer `exit`,
    `pack`, `checks` (one per step) and, when BROKEN, `finding` naming what
    broke. Never raises on a damaged or absent pack: that is a verdict.

    `witness` is a local pin file to check local pins against; `remote`
    allows one read of the public witness per remote pin (step 4);
    `namespace` names this ledger's namespace in the pin file when the pack
    lists no pin of its own."""
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
    checks.append(_step_pins(pack, manifest, witness=witness, remote=remote,
                             namespace=namespace))
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
    p.add_argument("--witness", default=None,
                   help="the local pin file to check the pack's local pins against")
    p.add_argument("--remote", action="store_true",
                   help="read each remote pin from the public witness (network)")
    p.add_argument("--namespace", default=None,
                   help="this ledger's namespace in the pin file, checked even when "
                        "the pack lists no pin")
    p.add_argument("--json", action="store_true", help="print the result as JSON")
    return p


def main(argv: list[str] | None = None, *,
         prog: str = "arcaeon evidence-pack verify") -> int:
    a = _parser(prog).parse_args(argv)
    res = verify_pack(a.pack, witness=a.witness, remote=a.remote,
                      namespace=a.namespace)
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
