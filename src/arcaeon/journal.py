# SPDX-License-Identifier: MIT
"""arcaeon.journal: a local record of what the `arcaeon` command did.

One JSON line per verb run, appended to ~/.arcaeon/activity.jsonl
(ARCAEON_HOME names another directory). `arcaeon status` reads it back.

    {"t": "2026-09-25T14:02:11Z", "verb": "verify", "word": "VERIFIED",
     "exit": 0, "target": "<sha256 of the target path, or null>"}

PRIVACY. The target is stored as sha256 of its normalized path, never the
path, never its basename, never its contents. The journal answers "was the
same thing looked at again, and what happened" without saying what it was.

OFF SWITCH. ARCAEON_JOURNAL=0 writes nothing.

NEVER IN THE WAY. append() swallows every error and returns False: a journal
that cannot be written must never change a verb's exit code or print a
traceback. Stdlib only; no network.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

__all__ = ["HOME_ENV", "OFF_ENV", "FILENAME", "home", "path", "enabled",
           "target_id", "word_for", "append", "read"]

HOME_ENV = "ARCAEON_HOME"
OFF_ENV = "ARCAEON_JOURNAL"
FILENAME = "activity.jsonl"

#: The generic word for each exit code of arcaeon.verdict's one table.
_WORD_BY_EXIT = {0: "OK", 1: "BAD FINDING", 2: "BAD USAGE", 3: "COULD NOT LOOK"}
#: Verbs whose exit 0 / 1 have a verdict word of their own.
_VERB_WORDS = {
    "verify": {0: "VERIFIED", 1: "BROKEN"},
    "compact": {0: "VERIFIED", 1: "BROKEN"},
    "reconcile": {0: "MATCHED", 1: "MISSING OR ALTERED"},
}


def home() -> Path:
    """The journal directory: $ARCAEON_HOME, else ~/.arcaeon."""
    override = os.environ.get(HOME_ENV, "").strip()
    return Path(override) if override else Path.home() / ".arcaeon"


def path() -> Path:
    return home() / FILENAME


def enabled() -> bool:
    """False only when ARCAEON_JOURNAL is exactly 0 (spaces ignored)."""
    return os.environ.get(OFF_ENV, "").strip() != "0"


def target_id(target) -> str | None:
    """sha256 of the target's normalized absolute path, or None for no target.
    Normalized so `a.jsonl` and `./a.jsonl` are the same target."""
    if target is None or target == "" or target == "-":
        return None
    try:
        norm = os.path.normcase(os.path.abspath(os.fspath(target)))
    except (TypeError, ValueError, OSError):
        norm = str(target)
    return hashlib.sha256(norm.encode("utf-8", "surrogatepass")).hexdigest()


def word_for(verb: str, exit_code) -> str:
    """The verdict word for a verb's exit code (exit-to-word)."""
    if not isinstance(exit_code, int):
        return "UNKNOWN"
    special = _VERB_WORDS.get(verb, {})
    return special.get(exit_code) or _WORD_BY_EXIT.get(exit_code, f"EXIT {exit_code}")


def append(verb: str, word: str | None, exit_code, target=None) -> bool:
    """Append one line. True if written; False if off or anything went wrong.
    Never raises."""
    try:
        if not enabled():
            return False
        row = {"t": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "verb": str(verb), "word": word if word else word_for(verb, exit_code),
               "exit": exit_code if isinstance(exit_code, int) else None,
               "target": target_id(target)}
        d = home()
        d.mkdir(parents=True, exist_ok=True)
        with open(d / FILENAME, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(row, separators=(",", ":")) + "\n")
        return True
    except Exception:  # noqa: BLE001  the journal never breaks the verb
        return False


def read(p: str | os.PathLike | None = None) -> list[dict]:
    """Every readable row, oldest first. A missing file is []; a line that
    does not parse as a JSON object is skipped."""
    p = Path(p) if p is not None else path()
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
        if isinstance(row, dict) and isinstance(row.get("verb"), str):
            rows.append(row)
    return rows
