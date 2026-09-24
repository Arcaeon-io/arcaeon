# Registry benchmark: sampling plan

Written 2026-09-02, BEFORE any registry repo was graded. The plan is fixed
here so the sample cannot be steered by what the first grades look like. If
the plan changes after grading starts, the change is dated below and the
grades before it are discarded.

## Question

Of the MCP servers listed in the official registry, how many leave a record
of tool calls that could be reconstructed after the fact (OWASP MCP08), and
how far up the four-gate ladder (presence, completeness, tamper-evidence,
reconstructability) do they get?

## Population

One dated snapshot: `snapshots/registry_<stamp>.jsonl`, identified by its
sha256 in the summary file. A server is a distinct `name` whose `is_latest`
row is `active`. Version rows are NOT servers (the registry returns one row
per published version). The 2026-09-02 snapshot: 88,636 version rows, 26,500
distinct names, 26,197 active. The "18,800 servers" our own docs quoted for a
week matched none of these figures.

Every server gets a bucket. Nothing is dropped from the denominator:

| bucket | meaning |
|---|---|
| `ungradable:remote-only` | a URL and nothing else; a source scanner cannot see it |
| `ungradable:no-source-no-remote` | registry row with neither |
| `gradable:package-only` | a package but no repo; NOT graded in v1 (fetching from npm/PyPI is a later step) |
| `gradable:repo` | a repository URL; the sampling frame |

## Sample

From `gradable:repo` rows, a uniform random sample of **100** servers,
seeded with the first 8 hex chars of the snapshot sha256 (`random.Random(int(sha[:8], 16))`).
A stranger with the snapshot gets the same 100 names. No stratification:
we do not know a repo's language until it is cloned, and stratifying on the
package registry (npm vs PyPI) would bake in an assumption the grade is
supposed to test. Language is recorded per repo and reported as a breakdown
after the fact.

Our own five servers (arcaeon-ledger, arcaeon-distill, arcaeon-once,
arcaeon-continuity, arcaeon_connector) are graded with the same code and
reported FIRST, outside the sample, failures included. They are not in the
sample's denominator and do not improve its numbers.

## Per-repo procedure

1. `git clone --depth 1` with a 120 s timeout, into a scratch dir, deleted
   after grading. `repo_subfolder` from the registry row narrows the tree
   when present.
2. Candidate server files: `.py`, `.ts`, `.tsx`, `.js`, `.mjs`, `.cjs` outside
   `node_modules`, `dist`, `build`, `.git`, `venv`, `test(s)`, `__tests__`,
   `examples?`, that contain a handler-registration marker
   (`@mcp.tool`, `.tool(`, `registerTool(`, `setRequestHandler(`, `addTool(`,
   `call_tool`, `tools/call`). Files with no marker are not graded: they are not the
   server's tool-handling code.
3. Each candidate graded with `mcp_vet.grade.grade_source`. Python goes to the
   full battery; TS/JS to the one-check tree-sitter front end. `checks_run`
   is recorded per file and the report never lets a TS grade imply the other
   six checks ran.
4. Server outcome (one per repo):
   * `clone-failed` (with the reason)
   * `no-handler-found` (cloned, no candidate file: another language, another
     SDK, or a monorepo we could not locate the server in; listed by name)
   * `graded`, with the highest `audit-record` gate reached across its files:
     `0` no record on any tool path, `1` presence, `2` completeness,
     `3` tamper-evidence, `4` reconstructable (= no audit-record finding).
     Where a repo has several server files the BEST file counts, because the
     question is "does this project have a way to leave a record", not
     "does every file".

## What the number can and cannot say

* It is a static read of source. A server that logs through a platform the
  scanner cannot see (a logging config file, a sidecar, an HTTP gateway)
  scores lower than it deserves. The scanner says so in every grade's
  `blind_spots` and the report repeats it.
* It grades one check for TS/JS. It says nothing about SSRF, exec, or secrets
  in those servers.
* `no-handler-found` is our blindness, not their fault, and is reported as a
  count next to the graded count, never folded into either side.
* Reachability is capped at depth 2 from the handler. Deeper records are
  "unobserved," reported as absent, and that cap is stated with the number.

## Publication

Report = the summary JSON + a markdown table + the snapshot sha + the sample
seed + the mcp-vet version. Any reader can re-run `bench/grade_sample.py`
against the same snapshot and get the same table, or the table was wrong.

## Amendments

* 2026-09-02, before the sample run: the marker list gained `tools/call`
  after the `--ours-only` pass (outside the sample) missed arcaeon-ledger's
  hand-rolled dispatcher. A 6-repo smoke that ran during the same fix is
  discarded; the sample starts from an empty results file.
* 2026-09-02, mid-sample (after row 44): the run hung for an hour at item 39
  (rooz21/x402). Cause: a private or deleted repo makes git ask for
  credentials; `GIT_TERMINAL_PROMPT=0` silences the terminal but on Windows
  git-credential-manager opens a hidden window and waits, and killing git.exe
  on timeout leaves git-remote-https + GCM holding our pipes so the timeout
  never returns. `clone()` now runs with no credential helper, GCM told to be
  non-interactive, and a tree kill on timeout. The 44 rows graded before the
  fix stand: the change only affects how a clone FAILS, never what a
  successful clone contains, and every earlier row was either graded from a
  completed clone or recorded as clone-failed with git's own reason. The
  relaunch resumed from row 45 against the same results file.
* 2026-09-02, final: 100/100 rows. Outcomes: 33 graded, 49 no-handler-found,
  18 clone-failed (all 18 = "could not read Username", i.e. private or gone).
  Gate distribution of the 33: 30 at gate 0, 2 at gate 1, 1 at gate 2, none at
  3 or 4. Ours, same code, reported first: ledger gate 1; distill, once,
  continuity, connector gate 0. Those rows were graded at 21:42Z, before the
  same-evening call-record commits (ledger a57a5f6, distill 7a18497, once,
  continuity), and they are the honest number for what a stranger installs
  today: the PUBLISHED versions are the pre-fix ones until the 6 AM window.
  The working trees regraded at 4 PM PT: ledger, distill, once, continuity
  gate 4; connector still 0. Publish the benchmark with the published-version
  row, and only re-state ours after PyPI carries the fixed versions and the
  grade is taken from `pip install`, not from the working tree.

## Addendum 2026-09-02: handler-registration markers in the SDKs we do not scan (M18)

Inventory only. NONE of these are in the scanner's `MARKER` list; a repo
written against one of these SDKs is `no-handler-found`, sub-reason
`unsupported-language` (see the next addendum). Listed so the blindness has a
name, and so a future front end knows what to look for.

| language | SDK | handler-registration marker | source |
|---|---|---|---|
| Go | `github.com/modelcontextprotocol/go-sdk` (package `mcp`) | `mcp.AddTool(server, &mcp.Tool{...}, handler)` | README of github.com/modelcontextprotocol/go-sdk |
| Go | `github.com/mark3labs/mcp-go` (community, widely used) | `s.AddTool(tool, handler)` on `server.MCPServer` | README of github.com/mark3labs/mcp-go |
| Rust | `rmcp` (github.com/modelcontextprotocol/rust-sdk) | `#[tool]` on the method; `#[tool_router]` (or `#[tool_router(server_handler)]`) on the impl; `#[tool_handler]` for `ServerHandler` | README of github.com/modelcontextprotocol/rust-sdk |
| Java | `io.modelcontextprotocol.sdk` (github.com/modelcontextprotocol/java-sdk) | `McpServerFeatures.SyncToolSpecification` / `AsyncToolSpecification` built with `.callHandler(...)`, registered by `McpSyncServer.addTool(...)` / `McpAsyncServer.addTool(...)`, or inline via `McpServer.sync(transport).toolCall(tool, handler)` | java.sdk.modelcontextprotocol.io/latest/server/ |
| C# | `ModelContextProtocol` (github.com/modelcontextprotocol/csharp-sdk) | `[McpServerToolType]` on the class, `[McpServerTool]` on the method; discovered by `AddMcpServer().WithToolsFromAssembly()` (also `WithTools<T>()`) | csharp.sdk.modelcontextprotocol.io/v1/concepts/getting-started.html |

Note the collision: Go's `AddTool(` would already match our `addTool(` marker
if the regex were case-insensitive. It is not, on purpose: matching a marker
in a `.go` file would put the file in front of a grader that cannot parse it.

## Addendum 2026-09-02: `no-handler-found` split three ways (M19, M20)

`no-handler-found` is reported as three sub-reasons, decided by a post-hoc
classifier (`grade_sample.classify_no_handler`) from fields the row carries:

* `unsupported-language`: the clone has Go/Rust/Java/C# markers (`go.mod`,
  `Cargo.toml`, `pom.xml`, `build.gradle`, `.csproj`, `.sln`, or source files
  in those languages), OR it has no `.py`/`.ts`/`.js` file at all.
* `monorepo-miss`: a `package.json` or `pyproject.toml` sits in a directory
  the walk did not read (outside `repo_subfolder`, or under a pruned name
  such as `examples/`).
* `no-handler`: a Python/TS tree the scanner read end to end, and no file
  matched a handler marker that the audit-record check then accepted.

The fields: `repo_markers` (per-language file counts over the whole clone),
`manifest_dirs` (every directory holding one of the two manifests),
`scanned_dirs` (the roots actually walked). **The 49 rows of the 2026-09-02
run were graded before these fields existed and cannot be split; they are
reported as `unclassified:pre-M20-row` (49) and the three reasons as 0.**
The counts always sum to the old `no-handler-found` number.

Procedure change for FUTURE runs (M19), effective for any row graded after
this addendum: when the `repo_subfolder` walk finds no handler, every
`manifest_dirs` entry the walk did not cover is graded too (up to 20), before
the row may say `no-handler-found`. A rescue is marked `found_via:
"manifest-scan"`. The frozen 100 are not regraded; a regrade would be a new
results file, never an overwrite (results are append-only, M30).

## Addendum 2026-09-05: per-repo precision, not the pooled number

Written after the `except-returns-success` must-hit was moved onto the
verbatim mcp-atlassian code (commit 4067d1db) and the fixture immediately
caught an `ssrf` false positive (`project.get("key")` read as a network
call). That is one repo and one check; it says nothing about the rate.

Rule for the NEXT server run, effective for any row graded after this
addendum: the report carries a **per-repo precision table** (repo, check,
findings, confirmed-true, confirmed-false, unreviewed) and never a single
pooled precision figure. A pooled number lets one large repo with a
systematic false positive stand in for a hundred small ones, and lets a
hundred quiet repos hide one that is red all the way down. Rows the reviewer
did not open stay `unreviewed`, counted in the denominator. The frozen 100
are not regraded.

## Where the snapshot lives

The full snapshot is ~36 MB and is not committed; its sha256 is in the
committed `snapshots/registry_<stamp>.summary.json` and the file itself is
published beside the report so a reader can check the hash and re-run.
