# SPDX-License-Identifier: MIT
"""`arcaeon start <memory folder>`: one command, for an agent in any shell, that
starts keeping a sealed record of the folder it already keeps its memory in.

    pip install "arcaeon>=0.11.0"
    arcaeon start ./memory

WHAT IT DOES. It reads every file under the folder (bytes are hashed, never
copied), and writes one row to a hash-chained record: each file's relative
path and sha256, and what was added, changed or removed since the row before.
Then it pins the record's head in a local pin file next to the record. That is
what "sealed" means here: chained row to row, with the head pinned, so a row
changed later, or rows cut off the end, are found by the next run and by
`arcaeon verify`. It is not the paid `seal` verb, and nothing is sent anywhere.

SAFE TO RUN TWICE. Run it again after every session, from a hook, or twice by
mistake. When nothing in the folder changed it writes nothing and says so.
When something changed it adds one row naming what. Before it adds anything it
checks the record it already has: a record that does not verify, or one cut
short against its own pin, is BROKEN (exit 1) and nothing is added on top.

NO KEY. No ARCAEON_KEY, no account, no network. The record and its pins live
under ~/.arcaeon/memory/<id>/ (ARCAEON_HOME moves ~/.arcaeon), never inside
the memory folder itself, so the agent never reads its own record as memory.
<id> is taken from the folder's full path: the same folder always finds the
same record, and a moved folder starts a new one.

PLAIN WORDS. Output is sentences, not JSON. Exit codes are the one table:
0 the record is kept (a row written, or nothing changed), 1 BROKEN (the
record already there does not check out), 2 bad usage (no folder, not a
folder, the home folder itself), 3 COULD NOT LOOK (a file could not be read;
the files that could be read are still recorded, and the ones that could not
are named in the row and on screen).

Stdlib only; no network; imports nothing heavy.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path

from arcaeon import verdict as V

__all__ = ["main", "USAGE", "record_dir", "folder_id", "look", "MAX_FILES",
           "EVT_STARTED", "EVT_CHANGED"]

USAGE = ("usage: arcaeon start <memory folder>\n"
         "Keep a sealed record of the folder an agent keeps its memory in: one\n"
         "hash-chained row per change, its head pinned in a local pin file. Safe to\n"
         "run again: it writes a row only when something in the folder changed. No\n"
         "key, no network. The record lives under ~/.arcaeon/memory/, not in the\n"
         "folder. Exit 0 kept, 1 BROKEN (the record already there does not check\n"
         "out), 2 bad usage, 3 COULD NOT LOOK (a file could not be read).")

#: The row the first run writes, and the row a later run writes when the folder
#: changed. A run that finds no change writes no row at all.
EVT_STARTED = "memory_started"
EVT_CHANGED = "memory_changed"

#: More files than this and it is not a memory folder (a home folder, a repo
#: with its dependencies): refused as bad usage before anything is written.
MAX_FILES = 20000
#: Names listed per kind on screen; the row always holds every name.
_SHOWN = 10
_CHUNK = 1 << 20

RECORD_NAME = "record.jsonl"
PINS_NAME = "pins.jsonl"


# --- where the record lives -----------------------------------------------------

def _home() -> Path:
    from arcaeon import journal
    return journal.home()


def _norm(folder: Path) -> str:
    return os.path.normcase(str(folder))


def folder_id(folder: Path) -> str:
    """16 hex of sha256 over the folder's normalized full path."""
    return hashlib.sha256(_norm(folder).encode("utf-8", "surrogatepass")).hexdigest()[:16]


def record_dir(folder: Path) -> Path:
    return _home() / "memory" / folder_id(folder)


# --- looking at the folder ------------------------------------------------------

def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        while True:
            chunk = fh.read(_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class _TooMany(Exception):
    pass


def look(folder: Path, skip: Path | None = None) -> tuple[dict[str, str], list[str], int]:
    """(manifest, unread, total bytes). The manifest maps each file's path,
    relative to the folder and written with forward slashes, to its sha256. A
    symbolic link is not followed: its value is `link:` plus the sha256 of the
    text it points to. `unread` lists the paths that could not be read.
    `skip` (the record's own folder, if it lies inside this one) is left out.
    Raises _TooMany past MAX_FILES."""
    manifest: dict[str, str] = {}
    unread: list[str] = []
    total = 0
    skip_s = _norm(skip) if skip is not None else None

    def onerror(err: OSError) -> None:
        name = getattr(err, "filename", None)
        if name:
            unread.append(_rel(Path(name)))

    def _rel(p: Path) -> str:
        try:
            return p.relative_to(folder).as_posix() or "."
        except ValueError:
            return p.as_posix()

    for dirpath, dirnames, filenames in os.walk(folder, onerror=onerror, followlinks=False):
        d = Path(dirpath)
        keep = []
        for name in sorted(dirnames):
            sub = d / name
            if skip_s is not None and _norm(sub) == skip_s:
                continue
            if sub.is_symlink():            # walk does not follow it; record it as a link
                filenames.append(name)
                continue
            keep.append(name)
        dirnames[:] = keep
        for name in sorted(filenames):
            p = d / name
            rel = _rel(p)
            if len(manifest) + len(unread) >= MAX_FILES:
                raise _TooMany()
            try:
                st = p.lstat()
                if stat.S_ISLNK(st.st_mode):
                    target = os.readlink(p)
                    manifest[rel] = "link:" + hashlib.sha256(
                        target.encode("utf-8", "surrogatepass")).hexdigest()
                elif stat.S_ISREG(st.st_mode):
                    manifest[rel] = _sha256_file(p)
                    total += st.st_size
                # sockets, fifos, devices: not memory, and reading one can block
            except OSError:
                unread.append(rel)
    return manifest, sorted(set(unread)), total


def _manifest_digest(manifest: dict[str, str]) -> str:
    text = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


# --- the record already there ---------------------------------------------------

def _last_row(record: Path) -> tuple[int, dict | None]:
    """(row count, last memory row) of a record that has already verified."""
    from arcaeon.record.ledger import Ledger
    rows, last = 0, None
    for row in Ledger(record):
        rows += 1
        if row.get("evt") in (EVT_STARTED, EVT_CHANGED):
            last = row
    return rows, last


def _check_existing(record: Path, pins: Path, ns: str) -> tuple[int, str | None]:
    """(exit code, problem) for the record already there. EXIT_GOOD and None
    when there is none yet, or when it verifies and agrees with its pins."""
    from arcaeon.record.ledger import Ledger, verify_file
    from arcaeon.record.ledger.witness import WitnessStore, verify_against_witness
    if not record.exists() and not pins.exists():
        return V.EXIT_GOOD, None
    if not record.exists():
        return V.EXIT_BAD, (f"the record is gone but its pin file is still there ({pins}); "
                            f"the record was deleted or moved")
    if not record.is_file():
        return V.EXIT_COULD_NOT_LOOK, f"the record at {record} is not a file"
    r = verify_file(record, strict=True)
    if r.ok is False:
        return V.EXIT_BAD, f"the record does not check out: {r.first_break}"
    if r.ok is not True and r.verified_scope != "empty":
        return V.EXIT_COULD_NOT_LOOK, (f"the record could not be read or checked in full "
                                       f"({r.verified_scope})")
    if not r.rows:
        if pins.exists() and pins.stat().st_size:
            return V.EXIT_BAD, "the record is empty but its pin file says it held rows"
        return V.EXIT_GOOD, None
    if not pins.exists():
        return V.EXIT_BAD, (f"the record has {r.rows} rows but its pin file is gone "
                            f"({pins}); the pins were deleted or moved")
    wv = verify_against_witness(WitnessStore(pins), ns, Ledger(record))
    if wv.verdict == "consistent":
        return V.EXIT_GOOD, None
    if wv.verdict == "truncated":
        return V.EXIT_BAD, (f"rows were cut off the end of the record: it holds "
                            f"{wv.local_rows if wv.local_rows is not None else r.rows}, "
                            f"its pin says {wv.witness_rows}")
    if wv.verdict == "rewritten":
        return V.EXIT_BAD, (f"the record was rewritten: its row {wv.witness_rows} is not "
                            f"the row its pin vouched for")
    if wv.verdict in ("witness_broken", "local_broken"):
        return V.EXIT_BAD, f"the record's pin file does not check out: {wv.detail}"
    return V.EXIT_COULD_NOT_LOOK, f"the record could not be compared with its pin: {wv.detail}"


# --- the run ---------------------------------------------------------------------

def _names(kind: str, names: list[str], out) -> None:
    if not names:
        return
    shown = ", ".join(names[:_SHOWN])
    more = len(names) - _SHOWN
    out(f"  {kind}: {shown}" + (f", and {more} more" if more > 0 else ""))


def _files(n: int) -> str:
    return f"{n} file" + ("" if n == 1 else "s")


def _q(p: Path) -> str:
    s = str(p)
    return f'"{s}"' if any(c in s for c in " '&;()") else s


def _refuse(folder_arg: str) -> tuple[Path | None, str | None]:
    """(the folder, resolved) or (None, why it cannot be used)."""
    p = Path(folder_arg).expanduser()
    if not p.exists():
        return None, f"no such folder: {folder_arg}"
    if not p.is_dir():
        return None, f"not a folder: {folder_arg} (point it at the folder the memory files are in)"
    try:
        p = p.resolve()
    except OSError as e:
        return None, f"cannot resolve {folder_arg}: {type(e).__name__}"
    home = Path.home()
    try:
        home = home.resolve()
    except OSError:
        pass
    if _norm(p) == _norm(home) or p.parent == p:
        return None, (f"{p} is a whole home or drive, not a memory folder; "
                      f"point it at the folder the agent keeps its memory in")
    return p, None


def run(folder_arg: str, out=print, err=None) -> int:
    err = err or (lambda s: print(s, file=sys.stderr))
    folder, why = _refuse(folder_arg)
    if folder is None:
        err(f"arcaeon start: {why}")
        return V.EXIT_USAGE
    from arcaeon.record.ledger import Ledger, LedgerWriteError, _append_lock
    from arcaeon.record.ledger.witness import WitnessStore, publish_head

    where = record_dir(folder)
    record, pins = where / RECORD_NAME, where / PINS_NAME
    ns = "memory-" + folder_id(folder)
    try:
        where.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        err(f"{V.COULD_NOT_LOOK}: cannot make the record folder {where} ({type(e).__name__}); "
            f"nothing was written")
        return V.EXIT_COULD_NOT_LOOK

    # One run at a time per folder: two at once must not both write the same change.
    with _append_lock(where / "start"):
        code, problem = _check_existing(record, pins, ns)
        if problem:
            word = V.BROKEN if code == V.EXIT_BAD else V.COULD_NOT_LOOK
            err(f"{word}: {problem}")
            err(f"Nothing was added. Record: {record}")
            if code == V.EXIT_BAD:
                err(f"See the detail: arcaeon verify {_q(record)} --witness {_q(pins)}")
                err(f"Keep that folder as it is: it is the evidence. To start a new record, "
                    f"move {_q(where)} somewhere else and run this command again.")
            return code
        rows, last = _last_row(record) if record.exists() else (0, None)
        if last is not None and last.get("folder") != str(folder):
            err(f"arcaeon start: the record at {record} is for another folder "
                f"({last.get('folder')}); nothing was written")
            return V.EXIT_USAGE

        # ARCAEON_HOME inside the memory folder: leave the whole of it out (the
        # record, its pins and the activity journal change on every run).
        try:
            arc_home = _home().resolve()
        except OSError:
            arc_home = _home()
        skip = arc_home if _norm(arc_home).startswith(_norm(folder) + os.sep) else None
        try:
            manifest, unread, total = look(folder, skip)
        except _TooMany:
            err(f"arcaeon start: {folder} holds more than {MAX_FILES} files, which is more "
                f"than a memory folder does; point it at the memory folder itself. "
                f"Nothing was written.")
            return V.EXIT_USAGE

        out(f"Keeping a sealed record of {folder}")
        prev = (last or {}).get("manifest") or {}
        prev_unread = set((last or {}).get("unread") or [])
        added = sorted(k for k in manifest if k not in prev)
        changed = sorted(k for k in manifest if k in prev and prev[k] != manifest[k])
        removed = sorted(k for k in prev if k not in manifest and k not in unread)
        same = last is not None and not (added or changed or removed) \
            and set(unread) == prev_unread

        if same:
            out(f"No change since row {rows}: {_files(len(manifest))}, the same as last time. "
                f"Nothing written.")
        else:
            row = {
                "evt": EVT_STARTED if last is None else EVT_CHANGED,
                "folder": str(folder),
                "files": len(manifest),
                "bytes": total,
                "manifest_sha256": _manifest_digest(manifest),
                "manifest": manifest,
                "added": added if last is not None else [],
                "changed": changed,
                "removed": removed,
                "unread": unread,
            }
            try:
                Ledger(record).append(row)
                publish_head(WitnessStore(pins), ns, Ledger(record))
            except (OSError, ValueError, LedgerWriteError) as e:
                err(f"{V.COULD_NOT_LOOK}: the row could not be written and sealed "
                    f"({type(e).__name__}). Record: {record}")
                return V.EXIT_COULD_NOT_LOOK
            if last is None:
                out(f"First look: {_files(len(manifest))}. Written as row {rows + 1} and sealed.")
            else:
                what = [f"{len(x)} {k}" for k, x in (("added", added), ("changed", changed),
                                                      ("removed", removed)) if x]
                if unread != sorted(prev_unread):
                    what.append("a different set of files could not be read")
                out(f"Changed since row {rows}: {', '.join(what)}. "
                    f"Written as row {rows + 1} and sealed.")
                _names("added", added, out)
                _names("changed", changed, out)
                _names("removed", removed, out)

        out(f"Record: {record}")
        if last is None:
            out("Run this same command again after each session. It adds a row only when "
                "something changed.")
        out(f"Anyone can check it: arcaeon verify {_q(record)} --witness {_q(pins)}")
        if unread:
            err(f"{V.COULD_NOT_LOOK}: {_files(len(unread))} could not be read, so the record "
                f"does not speak for them:")
            _names("not read", unread, err)
            return V.EXIT_COULD_NOT_LOOK
        return V.EXIT_GOOD


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(a in ("-h", "--help") for a in argv):
        print(USAGE)
        return V.EXIT_GOOD
    pos = [a for a in argv if a == "-" or not a.startswith("-")]
    flags = [a for a in argv if a.startswith("-") and a != "-"]
    if flags:
        print(f"arcaeon start: unknown option {flags[0]!r}\n{USAGE}", file=sys.stderr)
        return V.EXIT_USAGE
    if len(pos) != 1:
        print(USAGE.splitlines()[0], file=sys.stderr)
        return V.EXIT_USAGE
    return run(pos[0])


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
