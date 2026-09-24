# Cost per check: what one static grade costs on this box (M39)

Measured 2026-09-02 16:29 PDT. Every number below comes from one real run of
`scripts/cost_per_check.py --rounds 8` on the working trees named; nothing is
estimated. Raw JSON for the run is kept beside the script's output in the
session scratchpad (`m39/cost_run.json`), and the run is reproducible with the
one command above.

## Setup

- Tool: `mcp_vet` 0.0.17 (working tree, unpublished), Python 3.14.3, Windows 11.
- Machine: Dell 7530, Intel64 Family 6 Model 158 (12 logical CPUs), SSD.
- Instrument: `mcp_vet/instrument.py` `timed_scan_target()` wraps
  `service.scan_target()` under `time.perf_counter()`. The byte counts are
  taken outside the timed window. `service.py` was not changed.
- Targets: the PACKAGE directory of each of our five (not the repo root, so
  tests and docs do not pad the count), plus the package's own
  `tests/fixtures`. All local disk. No network, no code executed.
- Rounds: 8 per target. Round 1 is reported as the cold number; rounds 2 to 8
  (7 per target) are the warm samples.
- Percentile: nearest rank, so p95 is a value that was actually observed.

## Headline

| metric | n | median | p95 |
|---|---|---|---|
| wall time, warm (rounds 2 to 8) | 42 | 0.311 s | 1.111 s |
| wall time, cold (round 1 of each) | 6 | 0.499 s | 1.154 s |
| bytes read by the scanner (per target) | 6 | 83,168 B | 221,044 B (max) |
| bytes in the whole tree (per target) | 6 | 181,479 B | 456,826 B (max) |

"Clone bytes" is not a thing this scanner does: it reads a local tree and never
fetches. Two byte counts stand in for it. `bytes read` is what the grade is
actually about (every .py/.ts/.js file graded). `tree bytes` is every file under
the target, pruned dirs included, which is what a fetch of the tree would move.
The tree number is roughly double the read number because each working tree
carries a `__pycache__` the scanner prunes.

Dollars: zero. The scan runs on hardware already paid for and touches no
hosted service. A hosted or sandboxed variant would have a price; that is the
subject of `SANDBOX_RUNNER.md`, not this memo.

## Per target

All grades are of the WORKING TREE, UNPUBLISHED.

| target | files | bytes read | tree bytes | cold s | warm median s | verdict |
|---|---|---|---|---|---|---|
| arcaeon-ledger (working tree, unpublished) | 9 | 221,044 | 456,826 | 1.154 | 1.059 | no findings in checked classes |
| arcaeon-distill (working tree, unpublished) | 4 | 70,594 | 159,698 | 0.568 | 0.241 | no findings in checked classes |
| arcaeon-once (working tree, unpublished) | 5 | 95,742 | 203,260 | 0.443 | 0.321 | no findings in checked classes |
| arcaeon-continuity (working tree, unpublished) | 6 | 155,448 | 343,896 | 0.554 | 0.616 | no findings in checked classes |
| arcaeon_connector (working tree, unpublished) | 6 | 39,433 | 90,113 | 0.131 | 0.141 | no findings in checked classes |
| mcp_vet tests/fixtures | 33 | 27,373 | 27,373 | 0.222 | 0.236 | high-severity findings |

Warm samples per target (seconds, rounds 2 to 8):

- arcaeon-ledger: 1.193, 1.059, 1.111, 1.556, 1.024, 0.839, 0.724
- arcaeon-distill: 0.228, 0.210, 0.307, 0.249, 0.230, 0.283, 0.241
- arcaeon-once: 0.289, 0.316, 0.321, 0.429, 0.562, 0.553, 0.302
- arcaeon-continuity: 0.675, 0.598, 0.695, 0.609, 0.731, 0.559, 0.616
- arcaeon_connector: 0.141, 0.129, 0.148, 0.135, 0.132, 0.145, 0.142
- tests/fixtures: 0.236, 0.331, 0.322, 0.225, 0.266, 0.197, 0.193

## What the numbers say

- Cost scales with bytes graded, not file count. The 33 small fixture files
  grade in 0.24 s; the 9 ledger files (221 KB) take 1.06 s. Roughly 4 to 5 s per
  MB of Python on this CPU at the warm median (ledger 4.8, continuity 4.0),
  single threaded.
- The warm p95 (1.11 s) is the ledger tree, the largest target, not a tail
  from noise: five of the six targets never crossed 0.75 s.
- Cold vs warm matters little here (0.50 s vs 0.31 s median). There is no
  grammar download or JIT; the cold penalty is disk cache and tree-sitter
  grammar load, and it is under half a second.
- This box was not idle: several other agents were running test suites
  during the measurement, which is the likely source of the 1.56 s outlier
  in the ledger samples. The medians are robust to that; the p95 is inflated
  by it, and a quiet-box p95 would read lower.

## Caveats

- n = 6 targets. That is our five plus the fixtures; it is not a survey of
  the ecosystem, and a 2 MB server would land well outside this table.
- Wall time only. No CPU time, no peak memory; both are cheap to add to
  `instrument.py` if a hosted variant ever needs a resource budget.
- The two byte numbers are measured on local disk, not on a clone. A git
  clone moves history and packfiles, which are larger than the tree. If a
  runner ever fetches, measure that separately.
