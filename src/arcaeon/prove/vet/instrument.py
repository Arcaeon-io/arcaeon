"""mcp_vet.instrument: measure what one grade costs (M39, 2026-09-02).

A wrapper around `service.scan_target`, not a change to it: the scan stays the
one deterministic path, and this module only holds a stopwatch beside it. It
reports wall time and the byte counts that stand in for "clone bytes" on a
scanner that never clones anything (no network in this package):

  bytes_read   the bytes of every file the scanner actually graded
  tree_bytes   every file under the target (pruned dirs included), the
               size a fetch of the whole tree would move
  files        how many files were graded

`design/COST_PER_CHECK.md` is written from real runs of this module by
`scripts/cost_per_check.py`; nothing in that memo is estimated.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, asdict
from pathlib import Path

from .service import scan_target, _iter_source_files, TargetGrade


@dataclass
class ScanCost:
    target: str
    wall_s: float
    bytes_read: int
    tree_bytes: int
    files: int
    verdict: str

    def to_dict(self) -> dict:
        return asdict(self)


def _tree_bytes(root: Path) -> int:
    if root.is_file():
        return root.stat().st_size
    total = 0
    for p in root.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            continue
    return total


def _graded_bytes(root: Path) -> int:
    return sum(p.stat().st_size for p, _ in _iter_source_files(root))


def timed_scan_target(path: str | Path) -> tuple[TargetGrade, ScanCost]:
    """Run `scan_target` once under a monotonic clock. The byte counts are
    taken outside the timed window so the stopwatch covers only the scan."""
    root = Path(path)
    t0 = time.perf_counter()
    grade = scan_target(root)
    wall = time.perf_counter() - t0
    cost = ScanCost(
        target=str(root).replace("\\", "/"),
        wall_s=wall,
        bytes_read=_graded_bytes(root),
        tree_bytes=_tree_bytes(root),
        files=len(grade.files_scanned),
        verdict=grade.verdict,
    )
    return grade, cost


def percentile(values: list[float], q: float) -> float:
    """Nearest-rank percentile (q in 0..100) over a non-empty list. Nearest
    rank rather than interpolation so p95 of a small n is a value that was
    actually measured, not a number between two of them."""
    if not values:
        raise ValueError("percentile of an empty list")
    s = sorted(values)
    k = max(1, math.ceil(q / 100.0 * len(s)))
    return s[min(k, len(s)) - 1]
