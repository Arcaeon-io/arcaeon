## unreleased (working tree) - a refused call tells the caller why again, on mcp 2.1 (2026-09-06)

- **Tool handlers cross the MCP boundary as `ToolError`.** From mcp 2.1 the
  server sorts a tool's exception by TYPE: `ToolError` is "a failure you
  anticipated" and keeps its message after the prefix, while anything else is
  a crash whose text stays on the server and the caller gets only
  `Error executing tool <name>`. So `no ledger for namespace 'ghost'` -- the
  sentence that tells a caller what to fix -- stopped reaching callers.
  `build_server` now registers all 11 handlers through `_anticipated`, which
  re-types an escaping exception as the SDK's `ToolError` with its text intact.
- **Only at the edge, deliberately.** The first attempt did the re-typing in
  `_Outcome.deliver`, which changed what a DIRECT library caller of
  `_record_call` sees; the surrogate-error test caught it by asserting a
  `FileNotFoundError` stays a `FileNotFoundError`. The re-typing belongs to
  the SDK boundary, not to the library.
- The call record was never wrong here: the row already carried `ok: false`
  and the refusal text. This was about what reached the caller.
- Found by CI on the mirror (red on mcp 2.1.1, green locally on 2.0.0, which
  is why the suite looked fine here). Reproduced in a clean venv on 2.1.1,
  proven red before the fix and green after, on both versions.

## unreleased (working tree) - an upstream error quoting a lone surrogate no longer loses the call-record row (2026-09-05)

- **`_record_call` cleans the error text before the chained write.** An
  upstream can quote the caller's own argument back verbatim (mcp-vet without
  its `[audit]` extra raises `FileNotFoundError("not a readable file: <path>")`
  as-is), and `"\ud800"` is legal JSON that arrives as a lone surrogate.
  `Ledger.append` writes strict utf-8, so that one character failed the
  connector's own record write and the caller got "ran but its call record
  could not be written": the call gone from the record, the caller misinformed.
  The text is now `encode("utf-8", "replace")`d first; the row lands as
  `ok: false`. In the default install (mcp-vet with audit on, arcaeon-ledger
  0.7.4) the upstream already re-raises an ASCII codec error, so this is
  defense in depth for the other install shapes and for any future upstream.
  Two tests in `test_call_record.py` (one drives all seven string-taking tools
  with the character end-to-end, one hits `_record_call` directly and is red
  without the fix). Found by the input fuzz at `projects/online_business/audit_arcaeon_mcp_input_fuzz_2026-09-05.md`. Needs a version bump
  to reach users; not bumped, not published.

## unreleased (working tree) - dependency pins (2026-09-05, batch-100 item 42)

- **`mcp>=1.0` raised to `mcp>=2.0.0,<3`** (batch-100 item 42, 2026-09-05). The
  old floor named a version this package cannot start on: mcp 1.0.0's wheel has
  no `mcp/server/fastmcp/`, so the `except` branch labelled "SDK 1.x" at
  `server.py:287` fails to import there, and `test_call_record.py` /
  `test_connector.py` both do `from mcp import Client`, which no 1.x ships, so
  1.x was never once tested. 2.0.0 removed fastmcp and added
  `mcp.server.mcpserver` plus `Client`; `<3` is earned by that removal. Matches
  `arcaeon-mcp-vet` and `arcaeon-ledger-mcp`, which is what makes the three
  co-installable at one resolved version. Policy:
  `projects/online_business/PIN_POLICY_2026-09-05.md`; enforced by
  `scripts/test_pin_consistency.py`.


## unreleased (working tree) - an empty ARCAEON_KEY is proven refused, and cannot reach the wire (2026-09-05)

Board item 39 (BATCH_100_2026-09-05_PROPOSED.md): prove `server.py:123` refuses
on an empty `ARCAEON_KEY`, because defaulting a key to `""` is the
fail-open-to-unauthenticated shape until the gate is shown to reject it.

- **The finding: it already refuses, and nothing proved it.** `_key()` is
  `os.environ.get("ARCAEON_KEY", "").strip() or None`, where the `""` is a
  SENTINEL for `.strip()` and not a default credential. Both `""` and `"   "`
  collapse to None, which is exactly what an unset variable produces, so
  `_witness_call` returns the upgrade message that names the variable,
  `arcaeon_status` reports `key_present: false`, and nothing reaches
  `witness._http_post`. Probed all four states directly before writing a line of
  code: unset, empty, whitespace and set. The fail-open shape the item was right
  to suspect looks like `os.environ.get("ARCAEON_KEY", "")` returned bare, which
  would put `Authorization: Bearer ` on the wire and let the witness decide what
  an unauthenticated caller is.
- **So the gap was evidence, not behaviour.** The suite covered unset and set.
  Nothing covered empty or whitespace-only, which is the state a half-written
  `.env`, a shell `export ARCAEON_KEY=`, or a secrets manager that resolved to
  nothing actually produces. A correct behaviour with no test is one refactor
  away from being an incorrect one.
- **NEW `test_empty_key.py`, 19 tests.** MUST-HIT: empty, spaces, and tab/newline
  all refuse, on BOTH paid tools, with a message naming `ARCAEON_KEY`, with the
  HTTP hop replaced by a counter so "never sent" is measured at the seam rather
  than inferred from a return value; the blank refusal is asserted BYTE-EQUAL to
  the unset one, so a blank key cannot become a quieter second-class state; and
  `arcaeon_status` reports `key_present: false` for each. MUST-MISS: a real key
  still passes through with the exact key the gate handed it, a padded key is
  stripped and still works (whitespace is a normalisation, not a rejection), and
  status reports `key_present: true`. Without that must-miss half, a gate that
  refused everything would pass every must-hit arm.
- **NEW second gate in `witness._write`.** Through the MCP server this branch is
  unreachable, since the handler refuses first. It exists for the other caller:
  `witness` is an importable module, and `witness.pin(ns, rows, chain, "")`
  called straight from Python would otherwise put a blank bearer on the wire.
  The guard now sits at the layer that OWNS the credential and not only at the
  layer that owns the product decision, and it names `ARCAEON_KEY` in its
  refusal. Returned as data, never raised, which is that module's whole contract.
- **NOT a startup refusal, deliberately.** Ten of the eleven tools are free and
  need no key, so refusing to start over a blank optional variable would take the
  whole free lane down to enforce a gate on two tools. The refusal lives at the
  call, which is also where every other config value here is read: a key set
  after the server started is honoured, and a key blanked after it started is
  refused. The reasoning is written into `_key()`'s docstring so the next reader
  does not have to re-derive it from the absence of a check.
- **Red-then-green, three sabotages on a scratch copy.** (A) `_key()` reverted to
  the bare env read, guard intact: 6 red. (B) transport guard removed, resolver
  intact: 4 red, all four direct-call arms. (C) both together, the full fail-open
  shape: 14 of 19 red, and the receipt is explicit - a whitespace-only key
  returns `{"ok": true, "status": 201}` where the fixed code returns a refusal.
- Suite: 37 to 56 passing. No behaviour change for any existing caller. Not
  published, not deployed, not committed.

## 0.1.4 (unreleased, working tree) - the connector records its own calls (2026-09-02)

- **Why.** mcp-vet's OWASP MCP08 `audit-record` check graded
  `arcaeon_connector/server.py` gate 0 of 4 on 2026-09-02 (bench run 21:42Z,
  `mcp_vet` 0.0.16): eleven tool handlers, none of which wrote a record of its
  own invocation. Every recording test in the suite was about somebody
  else's record (the caller's ledger, mcp-vet's audit ledger). A connector
  that sells tamper-evident conduct records and keeps none of its own calls
  is a claim the checker was right to refuse.
- **What.** One shared `_record_call(tool, args, outcome)` is the last line
  of all eleven handlers. Each call appends one row to a hash-chained JSONL
  (`$ARCAEON_CALL_RECORD`, default `arcaeon.calls.jsonl` beside the ledger
  log): `op`, `tool`, `ts` (UTC ISO), `args_digest` (sha256 of the
  canonical-JSON arguments) + `args_bytes`, `ok`, `error` when there is one,
  and arcaeon-ledger's `chain` (sha256 over previous chain + row), so the
  file verifies with `verify_call_record()`, `arcaeon-ledger verify`, or the
  connector's own `ledger_verify_peer_ledger` tool.
- **Record after the work, with the outcome.** The handler runs first
  through `_attempt`, which captures the result or the exception; the record
  carries `ok:false` + the error text for a failed call and the caller still
  gets the error. A record written before the work would say `ok:true` for
  calls that then failed; a record written only on the success path would
  lose the failures entirely. If the record itself cannot be written the
  caller gets an error saying the tool ran but was not recorded.
- **Arguments are digested, never copied.** `ledger_append` carries the
  caller's conduct records; the call record must not become a second copy of
  them. A separate file from the caller's ledger, so `ledger_verify` row
  counts are unchanged.
- **Tests** (`test_call_record.py`, 6): one record per tool with the eleven
  names in call order; the chain verifies by three verifiers and a tampered
  row is named by line; a refused call records as a failure; a paid-tool
  refusal records as a success with the right digest; the env var and the
  default path; no record is `ok: None`, not green. `conftest.py` redirects
  the record under tmp for the whole suite so tests never grow a record in
  the repo.
- `arcaeon_status` reports `call_record_path`. README gains the env row.
- Graded after the fix (working tree, unpublished): gate 4 of 4, no
  findings. **Publishing is a separate gated item.**

## 0.1.3 — `uvx arcaeon` works; README stops confessing a fixed problem (2026-09-01 audit)

- **Console script `arcaeon` added** (alias of `arcaeon-mcp`). An MCP-registry
  client runs a pypi package as `uvx <identifier>`; the identifier is `arcaeon`
  and 0.1.2 shipped no script by that name, so registry-driven launches failed
  at the first step. `server.json` gains `runtimeHint: uvx` to say so.
- **README install block** said `pip install arcaeon` "does not work yet" long
  after all three packages were live on PyPI (checked live 2026-09-01: arcaeon
  0.1.2, arcaeon-ledger 0.7.1, arcaeon-mcp-vet 0.0.9). Rewritten; a test now
  refuses that sentence.
- Publishes through the 6 AM window with gates green.

# Changelog

All notable changes to `arcaeon` (the connector). Newest first.


## 2026-08-31 — README hardened for MCP-registry audience

Rewrote README for strangers: audit-record property stated plainly and cited to the
three tests that prove it (vet calls through the connector land in mcp_vet's ledger);
fixed a stale "fifteen tests" overclaim (actual 30, with a re-run-pytest caveat);
added links to arcaeon.io/ai and /ledger. Staged server.json for the registry
(io.github.arcaeon-io/arcaeon namespace) + MCP_REGISTRY_PUBLISH_NOTES with the honest
open steps (console-script mismatch, mcp-name marker needs a PyPI re-release). 30 tests, unchanged.
## Unreleased — 2026-08-30

Idea I-daniel-17 ("keep a subscription or entanglement to any good ideas",
msg 33827): an OPTIONAL license entanglement gate in front of the two paid
witness tools. Version deliberately not bumped — with the gate off, which is
the default and the shipped behaviour, this release is byte-for-byte the same
product as 0.1.2, and a version bump would advertise a change nobody gets.

### Added

- **`arcaeon_connector/licensing.py`** — optional, off by default. Turns on
  only with `LICENSE_GATE_REQUIRED=1`; while off it imports nothing and every
  call returns `None` in microseconds, so the free-and-ungated install is
  unchanged. Implementation lives outside this package (resolved at call time
  by module name, overridable with `LICENSE_GATE_MODULE`), because a pip
  install of `arcaeon` does not carry it.
- The license is bound to the **ledger namespace being pinned**, not to a
  machine or a user. A borrowed key would have to pin under the lender's
  namespace, into the lender's public pin history. That is the entanglement;
  the gate is only the door in front of it.
- `arcaeon_status` now reports a `license_gate` block (required / key present /
  which module answered). It never reports the key itself.
- Four tests, one per outcome. The one that matters is
  `test_a_required_gate_with_no_gate_installed_fails_closed`: a required check
  that passes because its own implementation is missing looks enforced and is
  nothing, so it refuses instead. And
  `test_a_key_for_another_namespace_is_refused_and_never_reaches_the_witness`
  asserts the refusal happens BEFORE the HTTP hop — a refusal that still spends
  a pin is not a gate.
- README: the gate's env vars, its default-off promise, and the honest limit
  (a client-side check deters, it does not prevent; the real moat is updates
  and the ledger identity).

### Honest limits

The gate is HMAC-based, so buyer-side verification is binding-only: we do not
ship our signing secret, which means a determined forger can relabel a key and
it will pass on their machine. Asserted in the gate's own tests rather than
hand-waved. The fix is asymmetric signatures, and it is a contained swap. Full
statement: `bridge/license_gate/README.md`.

## 0.1.2 — 2026-08-30

Board C-agent-31: `vet_scan` / `vet_grade` called `mcp_vet.checks.scan_source`
/ `mcp_vet.grade.grade_source` directly — the scanner and grader worked, but
that path never touched mcp-vet's `_record_call`, so a vet call made through
the connector left no row in mcp-vet's audit ledger while the identical call
made through mcp-vet's own server did. A caller running `vet_audit_verify`
through the connector would see a chain that was silently missing every scan
it actually ran through this door.

Fixed at the layer that owns the ledger, not the layer that called it:
mcp-vet 0.0.8 added two library-level recorded entry points,
`mcp_vet.server.scan_recorded(path)` / `grade_recorded(path)`, which run the
same read → scan/grade → `_record_call` sequence mcp-vet's own MCP tool
handlers run. The connector now calls those instead of the bare scanner/grader
functions.

### Fixed

- **`vet_scan` / `vet_grade` now write to mcp-vet's audit ledger**, same as a
  call made directly against mcp-vet's own server. No change to either tool's
  return shape — the finding list and the grade artifact are byte-identical to
  before; the only difference is the row that now lands in
  `$MCP_VET_AUDIT_LEDGER`.
- **`vet_scan` / `vet_grade` descriptions are now imported, not hand-copied.**
  They come off `mcp_vet.server.SCAN_DESCRIPTION` / `GRADE_DESCRIPTION`
  (new in mcp-vet 0.0.8) instead of a string typed out here — the hand-copied
  version had already drifted (missing the "call is recorded" sentence added
  in mcp-vet 0.0.7) before this fix caught it. `vet_audit_verify`'s
  description stays connector-authored on purpose: it explains the shared
  ledger in the connector's own terms, which mcp-vet's own wording for that
  tool does not need to.
- **`mcp-vet` dependency floor raised to `>=0.0.8`** (was `>=0.0.7`) — the
  `scan_recorded` / `grade_recorded` functions this file now imports don't
  exist before 0.0.8.

### Tests (+8 — the README client-config guard)

`test_readme_config.py` — the README's client-config block, parsed instead of
eyeballed (board C-agent-32). Nobody installs this connector by reading the
source; they copy the `.mcp.json` stanza out of the README and restart their
client, which makes that block executable documentation with none of the
protections executable things get. Rename the console script and the README
goes on telling strangers to run a binary that no longer exists — and the only
symptom is somebody else's client failing to start. Eight guards, each owning
one quoted fact:

- **`test_every_command_is_a_console_script_this_package_installs`** — every
  `"command"` in every `mcpServers` block must appear in `[project.scripts]`,
  read off `pyproject.toml` rather than a second copy kept by hand here.
  Verified red: renaming the README's `arcaeon-mcp` to `arcaeon-server` fails
  with `README tells clients to run 'arcaeon-server' ... but pip installs
  ['arcaeon-mcp']`.
- **`test_the_console_script_target_still_exists_and_is_callable`** — the other
  end of the wire. `arcaeon-mcp = "arcaeon_connector.__main__:main"` is only a
  promise until something imports it; a renamed `main` breaks the installed
  binary while every in-process test stays green.
- **`test_every_flag_in_the_readme_args_is_accepted_by_the_cli`** — the
  README's exact argv goes through the real parser (`--tools` returns before
  any server starts), with paths redirected to tmp so parsing the docs never
  writes a ledger into the repo.
- **`test_the_python_m_fallback_in_the_readme_names_a_real_module`**,
  **`test_every_env_var_in_the_readme_block_is_read_by_the_code`** (a stanza
  setting `ARCAEON_KEY` for a package that stopped reading it is a user who
  thinks the paid lane is on), **`test_the_readme_install_line_names_the_distribution_pyproject_declares`**, plus two that keep the guard from going
  vacuously green (the block still exists; every JSON fence in the README parses).

### Tests (18, up from 15)

- **`test_vet_scan_through_the_connector_is_recorded_in_mcp_vets_ledger`** —
  points `$MCP_VET_AUDIT_LEDGER` at a throwaway file, makes one `vet_scan`
  call through the connector, and asserts the ledger has exactly one
  `mcp_vet_scan` row AND the connector's own `vet_audit_verify` reports
  `rows == 1, ok is True`. Red against the pre-fix code (no ledger file
  written at all — `FileNotFoundError` reading it back) before the fix landed.
- **`test_vet_grade_through_the_connector_is_recorded_too`** — same guard on
  the sibling tool, so a fix that only covered `vet_scan` couldn't pass by
  half.
- **`test_vet_scan_and_grade_descriptions_match_upstream`** — lists tools
  through both mcp-vet's own server and the connector and asserts the
  descriptions are byte-identical for the shared pair. Red against the pre-fix
  hand-copied strings (missing mcp-vet's "the call is recorded" sentence).

## 0.1.1 — 2026-08-30

mcp-vet 0.0.7 added a third tool, `mcp_vet_audit_verify` — the drift guard
(`test_every_underlying_vet_tool_is_re_exported`) went red the moment the
editable install picked it up, which is exactly the failure mode that test
exists to catch loudly instead of silently.

### Added

- **`vet_audit_verify`** — re-exports `mcp_vet.server.verify_audit_ledger`
  (mcp-vet 0.0.7), free tier, following the `vet_scan` / `vet_grade` pattern:
  call the upstream function directly rather than dispatching through a
  JSON-RPC envelope, because this one has no source file to read and no
  server-side call to make. Recomputes the hash chain over mcp-vet's OWN
  call-record ledger and reports whether it is intact — `ok` (three-valued:
  true / false / null-and-bounded, passed through unflattened), `rows`,
  `breaks`, `first_break`. The ledger location is `$MCP_VET_AUDIT_LEDGER`,
  read by mcp-vet at call time, same as every other mcp-vet caller.

### Changed

- **`mcp-vet` dependency floor raised to `>=0.0.7`** (was `>=0.0.5`) — the
  audit-ledger module the new tool imports from didn't exist before 0.0.7.
- **Tool count: ten → eleven.** `test_one_install_exposes_the_full_tool_list`'s
  exact-names assertion and the README tool table both updated; the arithmetic
  assertion (`len(LEDGER_TOOLS) + len(VET_TOOLS) + len(WITNESS_TOOLS) + 1`)
  needed no change — it was already deriving the count from `VET_TOOLS`
  instead of a hardcoded number.

### Tests (15, up from 14)

- **`test_vet_audit_verify_reads_the_shared_audit_ledger`** — populates a
  throwaway `$MCP_VET_AUDIT_LEDGER` with two real `mcp_vet_scan` calls against
  mcp-vet's own server (mirroring mcp-vet's own `conftest.py` isolation
  pattern), then asserts the connector's `vet_audit_verify` reports `ok is
  True`, `rows == 2`, `breaks == 0` over that same ledger. A re-export that
  silently pointed at a different ledger, or one that flattened the
  three-valued `ok`, would still return something here — just not this.

## 0.1.0 — 2026-08-30

First cut. One MCP stdio server bundling the Arcaeon shelf under the company
name, free to install, with the two money-spending tools gated behind a key that
explains itself.

**Why this exists.** The shelf was the product and the shelf was the problem: an
agent that would use three Arcaeon packages had to find three, install three,
and wire three client stanzas. Distribution was the constraint, not capability.
One install, one stanza, ten tools.

### Added

- **`arcaeon_connector.server`** — the whole tool list on one server:
  - `ledger_append`, `ledger_verify`, `ledger_prove_my_conduct`,
    `ledger_verify_peer_ledger`, `ledger_declare_break` (arcaeon-ledger 0.7.0)
  - `vet_scan`, `vet_grade` (mcp-vet 0.0.5)
  - `witness_pin`, `witness_renew` (hosted witness, **paid**)
  - `arcaeon_status` — versions, the free/paid split, whether a key is set, and
    where the ledger it writes to lives. Called first by anything that got
    refused.
- **`arcaeon-mcp` console script** with `--log`, `--ns-dir`, and `--tools`
  (print the list and exit, for checking an install without starting a server).
- **`arcaeon_connector.witness`** — the one place in the package that speaks a
  protocol instead of re-exporting a package, because the hosted witness is HTTP
  and has no Python client. Stdlib urllib, one POST function. HTTP failure is
  DATA here, never an exception: a 401, a 409 monotonic rejection, a 429
  over-cap and an unreachable host all come back as a dict with the status and
  the server's own reason. A tool that raises on a 429 hands the agent a stack
  trace where it needed the sentence "you are out of pins".
- **`arcaeon_connector.offers`** — the price snapshot and the upgrade message.

### Design decisions worth arguing with

- **Re-export, never reimplement.** The ledger tools build a real JSON-RPC
  envelope and dispatch into `arcaeon_ledger.mcp_server.handle` — the exact
  function the standalone server runs — rather than reaching past it into the
  private helpers. It looks like ceremony and it is the point: two paths to the
  same answer is two answers that can disagree, and the day they disagree is the
  day the connector lies about a chain. Ledger tool DESCRIPTIONS are read off
  upstream's own `TOOLS` list at build time, so the text a client reads is the
  text upstream wrote.
- **Wrappers are hand-written, and a test pays for that.** The SDK derives each
  tool's JSON schema from a real Python signature; generating signatures from
  upstream's `inputSchema` would create a second schema that can drift from the
  first. The cost is that a new upstream tool does not appear here for free — so
  `test_every_underlying_ledger_tool_is_re_exported` walks upstream's TOOLS and
  goes red naming anything this package forgot. The failure mode of a bundler is
  silently shipping less than it bundles; this one fails loudly instead.
- **The gate is a product surface, not an error path.** No key means a plain
  sentence naming the free tier FIRST (100 pins/month, no card), then the $5
  entry pack and its checkout link, then what to set, then the seven tools that
  still work for free in the same install. A paywall that hides the free door is
  selling something the catalog says is free.
- **The refusal message is ASCII-only.** It is the one string here that gets
  PRINTED to a terminal rather than rendered by a client, and a Windows console
  at cp1252 turns a well-meant em-dash into a replacement glyph. A payment
  message that arrives visibly corrupted reads like the bug it is denying.
  Caught by printing it, not by reasoning about it.
- **`requires-python = ">=3.10"`** even though arcaeon-ledger runs on 3.9: a
  bundle's floor is the highest floor on the shelf (mcp-vet's), and claiming 3.9
  would install cleanly and then fail at import.
- **Config is read at CALL time, never cached at import.** A cached ledger path
  is a path that ignores the client's environment on the second call, and
  clients do change it between sessions.

### Tests (14, written before the package existed)

The first run failed at `import arcaeon_connector`, which is the point.

- one install exposes the full tool list — count AND exact names (a count alone
  passes if a tool is silently renamed)
- drift guards, both directions: every upstream ledger tool and every upstream
  vet tool is re-exported
- a ledger round trip through the connector, asserted against the FILE on disk:
  the row's `chain` on disk must equal the chain the tool reported. A re-export
  that returned plausible JSON without touching the ledger passes a shape check
  and fails this.
- a `vet_scan` of the planted-vulnerable fixture returns the ssrf finding at its
  exact line
- paid tool with no key → the pack URL, the price, `ARCAEON_KEY`, and no
  traceback leak (`Traceback`, `File "`, `urllib`, `Exception` all asserted
  absent)
- paid tool with a dummy key → the gate is out of the way and the exact
  arguments reach the underlying call (the HTTP hop is stubbed at one named
  seam, so no live pin is spent proving it)
- `witness_renew` is gated AND routed to its own endpoint — the second paid tool
  must not be a copy that forgot the gate
- a free tool never asks for a key (a gate that fires on the free lane turns a
  free install into a paywall)
- the upgrade message is ASCII
- **the installed entry point serves over real stdio**: spawns
  `python -m arcaeon_connector` as a subprocess and speaks raw newline-delimited
  JSON-RPC down the pipe — initialize, tools/list, two tools/call. Raw rather
  than through the SDK's client on purpose: that client's constructor changed
  between SDK 2.0 and 2.1, and a transport test that only passes on the SDK
  version we happen to have installed is not a transport test. Verified green on
  both.

### Honest gaps at 0.1.0

- **`pip install arcaeon` does not work from PyPI yet**, and the README says so
  in the install section rather than in a footnote. `arcaeon-ledger>=0.7.0` and
  `mcp-vet>=0.0.5` are the declared dependencies; PyPI has arcaeon-ledger 0.5.9
  and no mcp-vet. The pins are honest and the resolver error is honest; loosening
  them to whatever PyPI holds would trade a clear error for an import crash.
- **Only two of the shelf's ten-plus packages are bundled.** The rest (adapter,
  audit, dedup, compact, meter, baseline, distill, continuity, once) are not
  here yet. The name claims the company; the contents claim two products and a
  witness, and this line exists so nobody reads more into the name than shipped.
- **The witness pass-through is proven against a stub, not against production.**
  The gate, the routing, the argument shape and the endpoint are all asserted;
  what is NOT asserted by the test suite is that a real key gets a real 201. A
  live pin costs a pin and belongs in a manual check, not in `pytest`.
- **No packaging test.** mcp-vet ships one (`test_packaging.py`); this package
  proves its install by hand — `pip install -e .` in a clean venv, `arcaeon-mcp
  --tools`, and the subprocess test above — and should grow the automated
  version before it is published.
