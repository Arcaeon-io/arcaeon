"""Refresh the usage blocks in docs/VERBS.md from the real `--help` output.

    py tools/sync_verbs_usage.py          # rewrite the blocks in place
    py tools/sync_verbs_usage.py --check  # exit 1 if any block is stale

Each verb's section in docs/VERBS.md has a line `**Usage**` followed by a
```text block. That block is the `usage:` line printed by
`arcaeon <verb> --help` plus its wrapped continuation lines, byte for byte.
A verb whose --help prints no `usage:` line gets a block that says so.
tests/test_docs.py uses the same functions, so the doc and the test cannot
disagree about what "the usage line" means.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERBS_MD = ROOT / "docs" / "VERBS.md"
NO_USAGE = "(this verb's --help prints no usage: line; see the text below)"

_SECTION = re.compile(r"^## `([a-z]+)`\s*$", re.M)
_BLOCK = re.compile(r"(\*\*Usage\*\*[^\n]*\n\n```text\n)(.*?)(\n```)", re.S)


def help_output(verb: str) -> str:
    """`arcaeon <verb> --help`, run from src/ at 80 columns, no key in the env."""
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONIOENCODING="utf-8",
               COLUMNS="80")
    env.pop("ARCAEON_KEY", None)
    p = subprocess.run([sys.executable, "-m", "arcaeon", verb, "--help"],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", env=env, cwd=str(ROOT), timeout=120)
    return p.stdout


def usage_block(verb: str) -> str | None:
    """The `usage:` line and its indented continuation lines, or None."""
    lines = help_output(verb).splitlines()
    for i, line in enumerate(lines):
        if line.startswith("usage:"):
            out = [line.rstrip()]
            for more in lines[i + 1:]:
                if more.startswith(" ") and more.strip():
                    out.append(more.rstrip())
                else:
                    break
            return "\n".join(out)
    return None


def doc_blocks(text: str) -> dict[str, str]:
    """verb -> the usage block written in docs/VERBS.md."""
    heads = list(_SECTION.finditer(text))
    out = {}
    for n, h in enumerate(heads):
        end = heads[n + 1].start() if n + 1 < len(heads) else len(text)
        m = _BLOCK.search(text, h.end(), end)
        if m:
            out[h.group(1)] = m.group(2)
    return out


def sync(check: bool = False) -> int:
    text = VERBS_MD.read_text(encoding="utf-8")
    heads = list(_SECTION.finditer(text))
    pieces, pos, stale = [], 0, []
    for n, h in enumerate(heads):
        end = heads[n + 1].start() if n + 1 < len(heads) else len(text)
        m = _BLOCK.search(text, h.end(), end)
        if not m:
            continue
        want = usage_block(h.group(1)) or NO_USAGE
        if m.group(2) != want:
            stale.append(h.group(1))
        pieces += [text[pos:m.start(2)], want]
        pos = m.end(2)
    pieces.append(text[pos:])
    if check:
        if stale:
            print("stale usage blocks: " + ", ".join(stale))
        return 1 if stale else 0
    VERBS_MD.write_text("".join(pieces), encoding="utf-8", newline="\n")
    print(f"synced {len(heads)} sections ({len(stale)} changed)")
    return 0


if __name__ == "__main__":
    sys.exit(sync(check="--check" in sys.argv[1:]))
