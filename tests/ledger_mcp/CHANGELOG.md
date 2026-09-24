# Changelog — arcaeon-ledger-mcp

## 2026-09-05 (dependency floors; batch-100 items 41 + 42)

- **`arcaeon-ledger` had no constraint at all.** `pip install
  arcaeon-ledger-mcp` could resolve ledger 0.2.0, and nothing would fail: every
  symbol used (`Ledger`, `verify_file`) has existed since 0.1.0 and every
  `VerifyResult` field read (`rows`, `chained`, `prechain`, `first_break`)
  since 0.2.1. The server would import, start, and answer wrongly. Floors here
  come from what an answer MEANS, not from what imports, and there are three
  rungs above the name floor: **0.5.7** made `VerifyResult.ok` three-valued
  (this server returns `bool(res.ok)`; before it, a fabricated unchained
  prepend returned a green with the skipped count parked in the sibling
  `prechain` field), **0.5.8** stopped an empty file returning `ok=True,
  verified_scope="full"` (`ledger_create` verifies any existing file, and empty
  is the ordinary post-create state), **0.7.3** stopped `verify_file` and
  friends crashing on a deeply nested line, which matters because every path
  argument to these tools comes from a model. Now `arcaeon-ledger>=0.7.3`,
  which PyPI serves.
- **`mcp>=2.0.0` gains `<3`.** `server.py` imports `mcp.server.MCPServer`,
  which is 2.x only, so the floor was already right. The ceiling is earned by
  that SDK's own history: `mcp/server/fastmcp/` is present in the 1.29.1 wheel
  and absent in 2.0.0.
- Policy: `projects/online_business/PIN_POLICY_2026-09-05.md`. Cross-package
  check: `scripts/test_pin_consistency.py`. Suite unchanged, 5 passed.


## 2026-09-01 (path containment -- reference-only status UNCHANGED; sell-code audit)

- `arcaeon_ledger_mcp/server.py`: every tool took a model-supplied `path` with
  no fence -- `ledger_append` was "append a hash-chained line to any file the
  process can write", `ledger_verify` "read the head of any file it can read".
  Now `_contained()`: the path must resolve under `ARCAEON_LEDGER_ROOT`
  (default: cwd) and end in `.jsonl`; anything else is a plain `ValueError`
  the model can read, never a silent redirect (a redirect would make the
  returned `path` a false record). `test_server.py` gains the root fixture and
  a refusal test (5 pass). Unpublished package; cheap to fix while it is.

## 2026-08-30 (import repoint only -- reference-only status UNCHANGED, board item C-agent-15b)

- `arcaeon_ledger_mcp/server.py` and `test_server.py`: repointed from
  `from ledger import Ledger, verify_file` (+ the sibling-checkout `sys.path`
  fallback onto `projects/ledger/`) to `from arcaeon_ledger import ...` -- the
  real, editable-installed package (0.7.0). The old primary import could never
  resolve (installed top-level module is `arcaeon_ledger`, not `ledger`), so
  both files always fell through and loaded the stale copy documented in
  `projects/ledger/STALE_COPY_README.md`.
- **Fallback REMOVED on purpose**: a missing package now fails loud instead of
  silently using stale code. `import sys` dropped from `server.py` as dead
  after the change; `test_server.py` no longer manipulates `sys.path`.
- API names verified present with the same semantics in `arcaeon_ledger`
  (`Ledger`, `verify_file`); no call sites needed adapting.
- Tests: 4/4 before, **4/4 after** (`python -m pytest -q test_server.py` ->
  `4 passed`).
- **Nothing else touched.** The 8/16 DO-NOT-PUBLISH / reference-only decision
  below stands unchanged; this pass only stops the reference build from
  depending on stale code.

## ⛔ DECISION 2026-08-16 (maintainer's call) — DO NOT PUBLISH / REFERENCE-ONLY
This SDK-based wrapper is **not the path forward** and must NOT be published or registry-submitted:
- It DUPLICATES the already-live zero-dependency `io.arcaeon/ledger` MCP server.
- It trades away the **zero-dependency property** (this build pulls mcp + httpx + jsonschema + sse-starlette). For a *trust/provenance* tool, minimal supply-chain surface is a genuine brand feature, and `RESEARCH_WAVE_MCP_WRAPPER` explicitly recommended keeping the hand-rolled zero-dep server for v0. My earlier "use the SDK" instruction to the build agent was the wrong call; the agent correctly flagged it rather than shipping it.
- **The zero-dep `io.arcaeon/ledger` server stays the live path.** This build is kept as a verified REFERENCE (proves the SDK path works; `mcp` 2.0.0 real API = `from mcp.server import MCPServer` / `@mcp.tool()` / `mcp.run(transport="stdio")`) and as a fallback IF SDK-only features are ever needed. Tests pass; nothing published, committed, or registered.
- Env note: the build agent `pip install`ed `mcp` into the live rig to verify the API. Confirmed harmless (bridge does not use httpx; httpx stayed 0.28.1; live system verified functional). Left installed so this reference build stays runnable.

## 0.1.0 — 2026-08-16 (LOCAL, unpublished)

- Initial build. MCP server wrapping the free `arcaeon-ledger` tools, built on
  the official MCP Python SDK (`mcp` 2.0.0, `MCPServer` decorator API).
- Three tools: `ledger_create`, `ledger_append`, `ledger_verify`. Honest
  descriptions (proves the log was not altered; does NOT prove the action was
  right or defend against a full chain rewrite).
- `pyproject.toml` (deps: arcaeon-ledger, mcp>=2.0.0), README with the
  `mcp-name: io.arcaeon/ledger-mcp` marker, and `test_server.py` (imports, tool
  registration, append/verify round-trip + tamper detection, SDK call_tool
  dispatch — all passing).
- NOT published anywhere. Awaiting human review, incl. the registry-name
  collision decision vs. the already-live `io.arcaeon/ledger`.
