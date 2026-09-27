# SPDX-License-Identifier: MIT
"""arcaeon.prove.evidence_pack: one folder for one agent and one window.

Spec: memory/EVIDENCE_PACK_SPEC_2026-09-27.md (sections 4 and 7). The pack is
built over `arcaeon.prove.audit.export_bundle`, so `records.jsonl` is the whole
ledger, byte for byte, and `integrity.json` / `witness.json` /
`ARTICLE_12_SUMMARY.md` are exactly what `arcaeon audit export` writes.

What a pack is evidence toward: the logging duties in the EU AI Act. What it
is not: a claim of compliance with them, or a claim that the agent behaved
well. It shows what was written was not changed after it was pinned.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from arcaeon import verdict as V

__all__ = ["build_pack", "PackUsageError"]


class PackUsageError(ValueError):
    """The pack could not start on what it was given (exit 2)."""


def _cnl_result(out: Path | None, looked_for: str, where: str, reason_word: str,
                reason: str) -> dict:
    res = {"verdict": V.COULD_NOT_LOOK, "exit": V.EXIT_COULD_NOT_LOOK,
           "out": str(out) if out is not None else None}
    res.update(V.could_not_look(looked_for, where, reason_word, reason))
    return res


def build_pack(ledger: str | Path, out: str | Path, *,
               system_id: str = "", provider: str = "",
               witness: Any = None, witness_namespace: str | None = None) -> dict:
    """Build an evidence pack from `ledger` into the empty folder `out`.

    Returns a result dict with `verdict` (one arcaeon.verdict word), an integer
    `exit` and `out`. Raises PackUsageError when `out` is a non-empty folder or
    a file (a pack never writes over an older pack's files).
    """
    from arcaeon.prove.audit import export_bundle

    ledger = Path(ledger)
    out = Path(out)
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise PackUsageError(f"{out} exists and is not an empty folder; "
                             "a pack is written into a new or empty folder")
    if not ledger.is_file():
        return _cnl_result(None, "a ledger file", str(ledger), "missing",
                           "the ledger named was not found, so there is nothing to pack")

    export_bundle(ledger, out, system_id=system_id, provider=provider,
                  witness=witness, witness_namespace=witness_namespace)
    integrity = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
    word = integrity.get("verdict") or V.COULD_NOT_LOOK
    if word not in V.EXIT_BY_WORD:
        word = V.COULD_NOT_LOOK
    return {"verdict": word, "exit": V.EXIT_BY_WORD[word], "out": str(out),
            "finding": integrity.get("finding"),
            "files": sorted(p.name for p in out.iterdir() if p.is_file())}
