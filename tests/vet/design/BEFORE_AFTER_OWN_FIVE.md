# Our own five, before and after (K37)

Written 2026-09-02, 23:40Z. Status: record of two gradings, one of what is
published and one of what sits in the working trees.

**Publishing the fixed versions is a separate gated item. Until the fixed
versions are on PyPI, nothing anywhere (README, badge, forum post, website,
registry listing, benchmark headline) may imply that our servers pass our own
checker. The installed and listed versions of all five are the gate-0 and
gate-1 code in the first table below, and a stranger who runs `mcp-vet` on
what `pip install` gives them today gets that table, not the second one.**

## What the two tables mean

The checker is mcp-vet's OWASP MCP08 `audit-record` check: four gates
(presence, completeness, tamper-evidence, reconstructability). Gate 0 means a
tool call leaves nothing behind. A tree's gate is the best gate reached by any
file in it that the check applies to (a file with tool handlers and an
entrypoint); test files and fragments are not asked and are shown as -1.

"Published version" is the code on PyPI as of 2026-09-02 23:38Z. The benchmark
run stamped `2026-09-02T2142Z` graded the LOCAL checkouts (its rows carry
`repo_url` like `arcaeon-distill`), which at 21:42Z stood at the
commits already on PyPI for distill (0.1.6, commit 4538759), once (0.2.2,
96ec297) and continuity (0.2.3, 85fc586). The ledger checkout was one commit
past its published 0.7.3 (d45cc32, a WitnessStore change that does not touch
`mcp_server.py`), so its MCP08 grade is the published server's grade. The
connector's checkout was the published 0.1.3 (private monorepo a570221a). The fix
commits landed 22:26Z to 22:33Z, after the run. So the first table is the
published-version grade, read from source, not from a wheel.

"Working tree" is what is on disk right now, graded at 23:30Z to 23:38Z.
Trees are dirty beyond the fix commits (README rewrites from the audit lane
are in flight in all four sibling repos; `arcaeon_ledger/mcp_server.py` also
has an uncommitted edit from the fuzz lane). The grade is of the bytes on
disk at that minute.

## Checker and battery

| what | mcp-vet | battery_digest (sha256 over version + checks/grade/service/ts_checks) |
|---|---|---|
| graded the published versions, 21:42Z | 0.0.16 | not recorded by that run (`unrecorded:run-predates-schema-1`); the four battery modules at every commit from 39997e2d (21:54Z) through a570221a are byte-identical (git blob ids checked), so the digest of that committed 0.0.16 is `fb2f84f8f329b39f16de1f25276221e57d915bb7a8f7d6a5e69ea4e575a8eadb`, with the caveat that the run started twelve minutes before 39997e2d was committed |
| graded the working trees, 23:30Z | 0.0.16 at a570221a, a `git archive` of HEAD run from the scratchpad | `fb2f84f8f329b39f16de1f25276221e57d915bb7a8f7d6a5e69ea4e575a8eadb` (recomputed from the archive) |
| cross-check, 23:37Z | 0.0.17, the live `projects/mcp_vet` working tree, mid-edit by the reachability lane | `e289fb186cbe983fede453822e6869dc236973b0a4aa5636faab6d040abf3109`; agrees with the 0.0.16 result on every tree |

The frozen 0.0.16 archive was used for the second table on purpose: at 23:2xZ
the live checker tree did not import (`_FR_MCP08_MIDDLEWARE` referenced before
definition, an edit in flight), and a comparison needs the same checker on
both sides. The `battery_digest_at_backfill` in the 21:42Z summary
(`c9ad2c09...`) is the live tree at 23:22Z, a mid-edit state that graded
nothing; do not cite it as the battery of either table.

The check battery, both runs, Python files: unsafe-exec, unsafe-deser, ssrf,
path-traversal, zero-auth, secret-in-code, audit-record, unreceipted-allow.
The gate below is the audit-record check's gate; the other seven checks had no
findings on any of the five in either grading.

## Table 1: published versions (bench `2026-09-02T2142Z`, mcp-vet 0.0.16)

| server | on PyPI | commit graded | tree gate | server file | audit_detail |
|---|---|---|---|---|---|
| arcaeon-ledger | 0.7.3 | d45cc32 (server file = 0.7.3) | **1** | `arcaeon_ledger/mcp_server.py` gate 1 | records a call at line 312 (ledger-style log.append()); gate 2 (completeness) unmet. Also `adapter/arcaeon_adapter/selftest.py` and `_echo_server.py` at gate 0 (fixtures for the adapter's own selftest; the adapter is a stdio proxy that writes the record at the pipe for a server that keeps none, so its echo fixture not recording is the point of the fixture) |
| arcaeon-distill | 0.1.6 | 4538759 | **0** | `arcaeon_distill/mcp_server.py` gate 0 | no call record on any tool-handling path (1 handler, first at line 137) |
| arcaeon-once | 0.2.2 | 96ec297 | **0** | `arcaeon_once/mcp_server.py` gate 0 | no call record on any tool-handling path (1 handler, first at line 179) |
| arcaeon-continuity | 0.2.3 | 85fc586 | **0** | `arcaeon_continuity/mcp_server.py` gate 0 | no call record on any tool-handling path |
| arcaeon (connector) | 0.1.3 | private monorepo a570221a | **0** | `arcaeon_connector/server.py` gate 0 | no call record on any tool-handling path (11 handlers, first at line 177); gate 1 (presence) unmet: a tool call leaves nothing behind to reconstruct |

Verdict string for every gate-0 file: "high-severity findings". Source:
`bench/results/2026-09-02T2142Z_summary.json`, `ours` block.

## Table 2: working trees after the fixes (frozen mcp-vet 0.0.16 at a570221a, 23:30Z)

| server | local version | fix commit | tree gate | server file | audit_detail |
|---|---|---|---|---|---|
| arcaeon-ledger | 0.7.4 | a57a5f6 (plus an uncommitted `mcp_server.py` edit from the fuzz lane) | **4** | `arcaeon_ledger/mcp_server.py` gate 4, "no findings in checked classes" | none. The two adapter fixtures are still gate 0 by design; the tree gate is the best file |
| arcaeon-distill | 0.1.7 | 7a18497 | **4** | `arcaeon_distill/mcp_server.py` gate 4 | none |
| arcaeon-once | 0.2.3 | eab0b6b | **4** | `arcaeon_once/mcp_server.py` gate 4 | none |
| arcaeon-continuity | 0.2.4 | c113be4 | **4** | `arcaeon_continuity/mcp_server.py` gate 4 | none |
| arcaeon (connector) | 0.1.4 | **unpublished, no commit** (working tree in the private monorepo) | **4** | `arcaeon_connector/server.py` gate 4, "no findings in checked classes" | none |

Every row in table 2 is **working tree, unpublished**. PyPI still serves the
table 1 versions for all five (`arcaeon_family_check.py --pypi`, 23:35Z:
ledger 0.7.3, continuity 0.2.3, distill 0.1.6, once 0.2.2, connector 0.1.3).

## What moved each one from 0 to 4

The same shape in all five: a `_record_call(tool, args, ...)` helper reached
from every handler within one hop, appending a row with the tool name, a UTC
timestamp and a sha256 of the canonical-JSON arguments (presence +
completeness), chained through arcaeon-ledger or a private `_ledger.py` with a
`chain` field (tamper-evidence), plus a verify path (`--verify-calls` on
distill, once and continuity; the ledger's own `verify`; `verify_call_record()`
on the connector) (reconstructability).
The connector records after the work and carries `ok` / `error`, so a failed
call is a recorded failure; the four siblings record after the tool with the
response in hand for the same reason.

## What this does not say

- Gate 4 is the static checker's reading of source. It says the shape is
  present; it does not say a row appeared at runtime (that is the runner in
  `SANDBOX_RUNNER.md`, design only).
- The shipped presence gate is a union over handlers: a server with eleven
  handlers where ten record grades gate 4. The connector's per-tool test
  (eleven rows, eleven names) and layer 2 of
  `scripts/arcaeon_family_gate0_fence.py` (per-handler walk) are what watch
  that seam; the fence's mutant run on 2026-09-02 showed the shipped gate
  staying at 4 with one connector handler stripped, and layer 2 going red.
- A stranger grading a checkout of any of the four sibling repos today gets
  table 2; a stranger grading the PyPI package gets table 1. Both are true.
  Only the second is what is sold.
