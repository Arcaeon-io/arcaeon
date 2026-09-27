# SPDX-License-Identifier: MIT
"""`arcaeon connect <client> --write | --undo | --check` (K020, K021).

write   backs the config file up to `<file>.arcaeon-bak-<UTC stamp>` (a byte
        for byte copy, read back and compared before anything else happens),
        then merges ONLY the `arcaeon` entry under the client's key. Every
        other server, key, comment-free byte and line ending in the file is
        left exactly as it was: the new entry is spliced into the original
        text, never re-serialized from a parsed copy. A file that was not
        there gets an `.absent` marker in place of a copy, naming any
        directory the write created, so undo can take it all away again.
undo    moves the newest backup back over the file (the backup is consumed),
        or, for an `.absent` marker, removes the file and the directories the
        write created. write then undo leaves the home byte-identical.
        Every backup has a `<backup>.written` sidecar holding the sha256 of
        the bytes that write put in the file; undo refuses (COULD NOT LOOK,
        exit 3, `reason_word: "changed_since_write"`, nothing touched) when
        the file no longer holds exactly those bytes, so it never deletes or
        rolls back an edit made after the write. A backup with no sidecar
        (made before sidecars existed) is restored as before.
check   reads only: `present`, `absent`, or `stale` (the configured command
        no longer resolves).

A file that is not JSON arcaeon can read (a parse error, a top level that is
not an object, the client's key holding something other than an object,
bytes that are not UTF-8) is COULD NOT LOOK, exit 3, `reason_word:
"unreadable"`, and nothing is written, backed up or created. JSON with
comments (VS Code allows them) is unreadable here too: arcaeon will not
guess at a file it cannot parse. Stdlib only.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from arcaeon import verdict as V

__all__ = ["BAK", "ABSENT", "WRITTEN", "Unreadable", "merge_text", "backups", "write", "undo",
           "check", "resolves"]

BAK = ".arcaeon-bak-"
ABSENT = ".absent"
WRITTEN = ".written"
_BOM = b"\xef\xbb\xbf"
_WS = " \t\r\n"


class Unreadable(Exception):
    """The existing file is not JSON arcaeon can merge into."""


# --- a span scanner over already-validated JSON text -------------------------------

def _ws(s: str, i: int) -> int:
    while i < len(s) and s[i] in _WS:
        i += 1
    return i


def _string_end(s: str, i: int) -> int:
    j = i + 1
    while True:
        c = s[j]
        if c == "\\":
            j += 2
        elif c == '"':
            return j + 1
        else:
            j += 1


def _value_end(s: str, i: int) -> int:
    c = s[i]
    if c == '"':
        return _string_end(s, i)
    if c in "{[":
        depth, j = 0, i
        while True:
            c = s[j]
            if c == '"':
                j = _string_end(s, j)
                continue
            if c in "{[":
                depth += 1
            elif c in "}]":
                depth -= 1
                if depth == 0:
                    return j + 1
            j += 1
    j = i
    while j < len(s) and s[j] not in ",}]" + _WS:
        j += 1
    return j


def _members(s: str, i: int) -> tuple[list, int]:
    """For the object opening at s[i]: [(key, key_start, value_start,
    value_end)], and the index of its closing brace."""
    out, j = [], _ws(s, i + 1)
    if s[j] == "}":
        return out, j
    while True:
        k0 = j
        k1 = _string_end(s, j)
        j = _ws(s, _ws(s, k1) + 1)          # past the colon
        v1 = _value_end(s, j)
        out.append((json.loads(s[k0:k1]), k0, j, v1))
        j = _ws(s, v1)
        if s[j] == ",":
            j = _ws(s, j + 1)
            continue
        return out, j


def _line_indent(s: str, i: int) -> str | None:
    """The whitespace before s[i] on its line, or None if anything else is."""
    start = s.rfind("\n", 0, i) + 1
    pre = s[start:i]
    return pre if pre.strip() == "" and start > 0 else None


def _dump(value, indent: str | None) -> str:
    if indent is None:
        return json.dumps(value)
    return json.dumps(value, indent=2).replace("\n", "\n" + indent)


def _insert(s: str, obj_start: int, name: str, value) -> str:
    """s with `"name": value` added as the last member of the object at
    s[obj_start], in the style of the members already there."""
    members, close = _members(s, obj_start)
    if members:
        _, k0, _, v1 = members[-1]
        ind = _line_indent(s, k0)
        if ind is None:
            piece = f", {json.dumps(name)}: {_dump(value, None)}"
        else:
            piece = f",\n{ind}{json.dumps(name)}: {_dump(value, ind)}"
        return s[:v1] + piece + s[v1:]
    base = _line_indent(s, obj_start)
    if base is None:                      # the brace follows a key: that line's indent
        line = s[s.rfind("\n", 0, obj_start) + 1:obj_start]
        base = line[:len(line) - len(line.lstrip())]
    inner = base + "  "
    piece = f"\n{inner}{json.dumps(name)}: {_dump(value, inner)}\n{base}"
    return s[:obj_start + 1] + piece + s[close:]


def merge_text(text: str | None, key: str, name: str, value) -> tuple[str, list[dict]]:
    """The file text with `text[key][name] = value`, and the keys changed.

    None or blank text is a new file. Raises Unreadable for anything that is
    not a JSON object, or whose `key` holds something other than an object.
    Every byte outside the one spliced entry is the original's."""
    if text is None or not text.strip():
        return json.dumps({key: {name: value}}, indent=2) + "\n", [
            {"key": key, "change": "added"}, {"key": f"{key}.{name}", "change": "added"}]
    try:
        doc = json.loads(text)
    except ValueError as e:
        raise Unreadable(f"not valid JSON ({e})") from None
    if not isinstance(doc, dict):
        raise Unreadable("the top level is not a JSON object")
    crlf = "\r\n" in text
    s = text.replace("\r\n", "\n") if crlf else text
    top = _ws(s, 0)
    members, _ = _members(s, top)
    found = [m for m in members if m[0] == key]
    if not found:
        new, changed = _insert(s, top, key, {name: value}), [
            {"key": key, "change": "added"}, {"key": f"{key}.{name}", "change": "added"}]
    else:
        _, _, v0, _ = found[-1]
        if not isinstance(doc[key], dict):
            raise Unreadable(f"{key!r} holds a {type(doc[key]).__name__}, not an object")
        inner, _ = _members(s, v0)
        same = [m for m in inner if m[0] == name]
        if same:
            _, k0, e0, e1 = same[-1]
            new = s[:e0] + _dump(value, _line_indent(s, k0)) + s[e1:]
            changed = [{"key": f"{key}.{name}", "change": "replaced"}]
        else:
            new = _insert(s, v0, name, value)
            changed = [{"key": f"{key}.{name}", "change": "added"}]
    if crlf:
        new = new.replace("\n", "\r\n")
    want = dict(doc)
    want[key] = {**(doc.get(key) or {}), name: value}
    if json.loads(new) != want:                 # the splice must mean exactly this
        raise Unreadable("the merge could not be made without touching other keys")
    return new, changed


# --- backups ------------------------------------------------------------------------

def _stamp_of(p: Path, file: Path) -> str:
    rest = p.name[len(file.name + BAK):]
    return rest[:-len(ABSENT)] if rest.endswith(ABSENT) else rest


def backups(file) -> list[Path]:
    """arcaeon's backups of `file`, oldest first (the stamp sorts by time)."""
    file = Path(file)
    if not file.parent.is_dir():
        return []
    found = [p for p in file.parent.glob(file.name + BAK + "*")
             if p.is_file() and not p.name.endswith(WRITTEN)]
    return sorted(found, key=lambda p: (_stamp_of(p, file), p.name))


def _new_backup_name(file: Path, absent: bool) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    tail = ABSENT if absent else ""
    p, n = file.with_name(file.name + BAK + stamp + tail), 0
    while p.exists() or p.with_name(p.name.removesuffix(ABSENT) + ABSENT).exists():
        n += 1
        p = file.with_name(f"{file.name}{BAK}{stamp}-{n:03d}{tail}")
    return p


def _sidecar(backup: Path) -> Path:
    """Where the sha256 of the bytes a write produced is kept."""
    return backup.with_name(backup.name + WRITTEN)


def _cnl(file, reason_word: str, reason: str) -> dict:
    return {"verdict": V.COULD_NOT_LOOK, "reason_word": reason_word, "reason": reason,
            "file": str(file), "written": False, "exit": V.EXIT_COULD_NOT_LOOK}


def _read(file: Path) -> str | None:
    """The file's text (BOM dropped), None if it is not there. Raises
    Unreadable for bytes that are not UTF-8 and OSError for a failed read."""
    if not file.exists():
        return None
    if not file.is_file():
        raise Unreadable("it is not a regular file")
    raw = file.read_bytes()
    try:
        return (raw[len(_BOM):] if raw.startswith(_BOM) else raw).decode("utf-8")
    except UnicodeDecodeError:
        raise Unreadable("it is not UTF-8 text") from None


def write(file, key: str, name: str, value) -> dict:
    """Back up, then merge `value` as `file[key][name]`. Never raises for a
    file problem: an unreadable or unwritable file is COULD NOT LOOK."""
    file = Path(file)
    try:
        text = _read(file)
        new, changed = merge_text(text, key, name, value)
    except Unreadable as e:
        return _cnl(file, "unreadable", f"{file} is not JSON arcaeon can read: {e}")
    except OSError as e:
        return _cnl(file, "unreadable", f"{file} could not be read "
                                        f"({e.strerror or type(e).__name__})")
    out = {"file": str(file), "written": False, "backup": None, "changed": changed,
           "exit": V.EXIT_GOOD}
    if text is not None:
        try:
            if json.loads(text).get(key, {}).get(name) == value:
                out.update(changed=[], already=True)
                return out
        except (ValueError, AttributeError):
            pass
    raw_before = file.read_bytes() if text is not None else None
    created: list[str] = []
    backup = tmp = side = None
    try:
        if raw_before is None:
            missing, d = [], file.parent
            while not d.exists():
                missing.append(d)
                d = d.parent
            for d in reversed(missing):
                d.mkdir()
                created.append(str(d))
            backup = _new_backup_name(file, absent=True)
            with open(backup, "x", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps({"absent": True, "created_dirs": created}) + "\n")
        else:
            backup = _new_backup_name(file, absent=False)
            with open(backup, "xb") as f:
                f.write(raw_before)
            if backup.read_bytes() != raw_before or file.read_bytes() != raw_before:
                backup.unlink()
                return _cnl(file, "unreadable", f"{file} changed while it was being "
                                                "backed up; nothing written")
        bom = _BOM if raw_before is not None and raw_before.startswith(_BOM) else b""
        data = bom + new.encode("utf-8")
        side = _sidecar(backup)
        with open(side, "x", encoding="ascii", newline="\n") as f:
            f.write(hashlib.sha256(data).hexdigest() + "\n")
        tmp = file.with_name(f"{file.name}.arcaeon-tmp-{os.getpid()}")
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, file)
    except OSError as e:
        if tmp is not None and tmp.exists():
            tmp.unlink()
        if side is not None and side.exists():
            side.unlink()                        # the file never got `data`
        if raw_before is None:
            if backup is not None and backup.exists():
                backup.unlink()
            for d in reversed(created):
                try:
                    os.rmdir(d)
                except OSError:
                    pass
        elif backup is not None and backup.exists() and file.read_bytes() == raw_before:
            backup.unlink()
        return _cnl(file, "unwritable", f"{file} could not be written "
                                        f"({e.strerror or type(e).__name__}); nothing changed")
    out.update(written=True, backup=str(backup),
               backup_kind="absent" if raw_before is None else "copy")
    return out


def undo(file) -> dict:
    """Put the newest backup back (and consume it)."""
    file = Path(file)
    found = backups(file)
    if not found:
        return _cnl(file, "no_backup", f"no arcaeon backup of {file} to restore; "
                                       "nothing changed")
    b = found[-1]
    side = _sidecar(b)
    try:
        want = side.read_text(encoding="ascii").strip() if side.is_file() else None
        now = hashlib.sha256(file.read_bytes()).hexdigest() if file.is_file() else None
    except OSError as e:
        return _cnl(file, "unreadable", f"{file} could not be read "
                                        f"({e.strerror or type(e).__name__})")
    gone_is_fine = now is None and b.name.endswith(ABSENT)
    if want is not None and now != want and not gone_is_fine:
        what = ("it is gone" if now is None else "it holds edits made after the write")
        todo = ("remove the arcaeon entry by hand" if b.name.endswith(ABSENT) else
                f"compare it with the backup {b} and remove the arcaeon entry by hand")
        return _cnl(file, "changed_since_write",
                    f"{file} is not what arcaeon wrote ({what}); {todo}")
    try:
        if b.name.endswith(ABSENT):
            try:
                created = json.loads(b.read_text(encoding="utf-8")).get("created_dirs") or []
            except (ValueError, AttributeError):
                created = []
            if file.exists():
                file.unlink()
            b.unlink()
            if side.exists():
                side.unlink()
            for d in sorted(created, key=len, reverse=True):
                try:
                    os.rmdir(d)                  # only if empty; never recursive
                except OSError:
                    pass
            kind = "absent"
        else:
            os.replace(b, file)
            if side.exists():
                side.unlink()
            kind = "copy"
    except OSError as e:
        return _cnl(file, "unwritable", f"{file} could not be restored "
                                        f"({e.strerror or type(e).__name__})")
    return {"file": str(file), "restored": str(b), "backup_kind": kind,
            "backups_left": len(found) - 1, "exit": V.EXIT_GOOD}


def resolves(command) -> bool:
    """True if `command` names a program that exists: an absolute path to a
    file, or a name shutil.which finds on PATH."""
    if not isinstance(command, str) or not command:
        return False
    if os.path.isabs(command):
        return os.path.isfile(command)
    return shutil.which(command) is not None


def check(file, key: str, name: str, value=None) -> dict:
    """present (0), absent (1) or stale (1); reads only."""
    file = Path(file)
    try:
        text = _read(file)
        doc = json.loads(text) if text is not None and text.strip() else {}
    except Unreadable as e:
        return _cnl(file, "unreadable", f"{file} is not JSON arcaeon can read: {e}")
    except ValueError as e:
        return _cnl(file, "unreadable", f"{file} is not JSON arcaeon can read: "
                                        f"not valid JSON ({e})")
    except OSError as e:
        return _cnl(file, "unreadable", f"{file} could not be read "
                                        f"({e.strerror or type(e).__name__})")
    if not isinstance(doc, dict) or not isinstance(doc.get(key, {}), dict):
        return _cnl(file, "unreadable", f"{file} is not JSON arcaeon can read: "
                                        f"no {key!r} object")
    entry = doc.get(key, {}).get(name)
    out = {"file": str(file), "exists": text is not None, "backups": len(backups(file))}
    if entry is None:
        return {**out, "state": "absent", "exit": V.EXIT_BAD}
    command = entry.get("command") if isinstance(entry, dict) else None
    if not resolves(command):
        return {**out, "state": "stale", "command": command, "exit": V.EXIT_BAD}
    return {**out, "state": "present", "command": command,
            "matches": value is None or entry == value, "exit": V.EXIT_GOOD}
