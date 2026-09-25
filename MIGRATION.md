# MIGRATION: 13 packages into one `arcaeon`

## Unreleased: 0.9.1

- `arcaeon verify` on a path it cannot read (missing, a directory, no
  permission) now answers COULD NOT LOOK, exit 3. 0.9.0 answered BROKEN,
  exit 1, which claimed a break in a file nothing had read. The JSON report is
  unchanged except its `verdict` word (`first_break` still says
  `unreadable: ...`). `--legacy-exit` returns the old 1 for the 0.9.x
  releases. The `arcaeon-ledger verify` shim (0.8.1) runs `arcaeon verify`
  without that flag, so it sees 3 as well.
- Every verb's usage line reads `arcaeon <verb>`. Seven printed the old tool
  name (`arcaeon-receipt`, `arcaeon-audit`, `arcaeon-baseline`,
  `arcaeon-meter`, `arcaeon-mcp`, `python -m arcaeon.record.adapter.proxy`,
  and `arcaeon vet badge` for `badge`).
- Each shim module's `__version__` is its own release (the version in its
  pyproject), not the moved code's internal string; `arcaeon_ledger` said
  0.8.0 inside the 0.8.1 wheel.
- The `arcaeon.cli` docstring's NETWORK note names the two verbs that go
  online on request: `receipt cite` (CourtListener, unless `--fixture`) and
  `proxy --pin-witness URL`.

## If you used the old packages

Short version: nothing breaks the day you upgrade. Each old name has one last
release that installs `arcaeon` and forwards the old import and the old
command to it (how: [shims/README.md](shims/README.md)). The old import raises
one DeprecationWarning that names the new one. Change your imports and
commands when it suits you, before 1.0.0, when the old names stop getting
releases.

For each old package: the import to change, the command to change, and
whether an exit code moved.

| old name | old import | new import | old command | new command | exit code changed? |
|---|---|---|---|---|---|
| arcaeon-ledger | `import arcaeon_ledger` | `import arcaeon.record.ledger` | `arcaeon-ledger verify LOG`, `append LOG ROW`, `reconcile A B` | `arcaeon verify LOG`, `arcaeon log LOG ROW`, `arcaeon reconcile A B` | yes: reconcile's COULD NOT LOOK 2 -> 3. verify unchanged (3 already). |
| arcaeon-adapter | `import arcaeon_adapter` | `import arcaeon.record.adapter` | `arcaeon-adapter ...`, `arcaeon-adapter-selftest` | `arcaeon proxy ...`, `arcaeon selftest adapter` | no |
| arcaeon-receipt | `import arcaeon_receipt` | `import arcaeon.record.receipt` | `arcaeon-receipt verify R` | `arcaeon receipt verify R` | yes: failed verify 2 -> 1, flagged check 3 -> 1, COULD NOT LOOK 4 -> 3 |
| arcaeon-audit | `import arcaeon_audit` | `import arcaeon.prove.audit` | `arcaeon-audit verify LOG` | `arcaeon audit verify LOG` | yes: could not complete 2 -> 3. Also: integrity.json's `verdict` changed meaning in 0.9.0 (now VERIFIED, BROKEN or COULD NOT LOOK); the old string (PASS, FAIL, ...) moved to `finding` |
| arcaeon-mcp-vet | `import mcp_vet` | `import arcaeon.prove.vet` | `mcp-vet badge PATH` | `arcaeon vet badge PATH` (or `arcaeon badge PATH`) | yes: badge refused --sealed 4 -> 3, verify and audit-verify 2 -> 1, probe could not connect 2 -> 3 |
| arcaeon-once | `import arcaeon_once` | `import arcaeon.record.once` | `arcaeon-once receipt LOG KEY` | `arcaeon once receipt LOG KEY` | no |
| arcaeon-compact | `import arcaeon_compact` | `import arcaeon.prove.compact` | (had no command) | `arcaeon compact ROW` (new) | no |
| arcaeon-continuity | `import arcaeon_continuity` | `import arcaeon.prove.continuity` | (had no command) | (none; `python -m arcaeon.prove.continuity`) | no |
| arcaeon-baseline | `import arcaeon_baseline` | `import arcaeon.prove.baseline` | `arcaeon-baseline compare ...` | `arcaeon baseline compare ...` | no |
| arcaeon-dedup | `import arcaeon_dedup` | `import arcaeon.save.dedup` | (had no command) | `arcaeon dedup FILE` (new) | no |
| arcaeon-distill | `import arcaeon_distill` | `import arcaeon.save.distill` | (had no command) | `arcaeon distill FILE` (new) | no |
| arcaeon-meter | `import arcaeon_meter` | `import arcaeon.save.meter` | `arcaeon-meter usage ...` | `arcaeon meter usage ...` | no |
| arcaeon-all | `import arcaeon_all` | `import arcaeon` | (had no command) | `arcaeon version` lists every part | no |

Where an exit code moved, it moved on the NEW command only. The old command,
run through its shim, passes `--legacy-exit` and keeps the old code for the
0.9.x releases, so a CI gate wired to it keeps its meaning. Add
`--legacy-exit` to the new command to get the old code there too while you
rewire. Both go away in 1.0.0. The codes come from `arcaeon.verdict.LEGACY`
(reconcile's move lives in `arcaeon.prove.reconcile` itself).

One output change: `arcaeon verify` adds a `"verdict"` field (VERIFIED,
BROKEN or COULD NOT LOOK) as the first key of the report it always printed.
Every other field is unchanged. `arcaeon-ledger verify`, which now runs
`arcaeon verify`, prints it too.

One field changed meaning: `arcaeon audit export`'s integrity.json. Through
arcaeon-audit 0.1.8 its `verdict` held a detailed string (PASS,
VERIFIED_MODULO_TRUNCATION, EMPTY_LOG, FAIL, TRUNCATION_DETECTED,
REWRITE_DETECTED, WITNESS_CHECK_FAILED, UNVERIFIED_SCOPE,
UNRECOGNIZED_WITNESS_VERDICT:...). In 0.9.0 `verdict` is the first key and
holds the one word from `arcaeon.verdict`, and the old string moved, exactly
as it was, to `finding`, the second key. `finding` is permanent, not
deprecated; nothing is removed in 1.0.0. The headline word follows the exit
code: VERIFIED for PASS and VERIFIED_MODULO_TRUNCATION (exit 0); BROKEN for
FAIL, TRUNCATION_DETECTED and REWRITE_DETECTED (exit 1); COULD NOT LOOK for
EMPTY_LOG and the rest (exit 3). So the word does not tell a truncation that
was never checked from a full pass: `finding` carries that case. A script that read `integrity["verdict"] == "PASS"` should read
`integrity["finding"]`; `arcaeon.prove.audit.finding_of()` reads either
bundle shape, so bundles exported by the old code still read and still verify.
Exit codes are unchanged except one: an empty log (EMPTY_LOG) was exit 0 and
is now COULD NOT LOOK, exit 3 (2 under `--legacy-exit`), for both `audit
verify` and `audit export`, the same answer `arcaeon verify` gives an empty
file. `audit verify` on a clean log now prints VERIFIED where it printed PASS;
the rest of the line is unchanged. Every other field is unchanged.

The bundled `arcaeon/remote/offers.json` (the snapshot `arcaeon buy` reads)
was re-synced on 2026-09-24 from the site's `.well-known/offers.json`, which
now lists one product, arcaeon (site commit f071863e).

A Python 3.9 user who installs an old name keeps getting that name's last
real release, because the shims need 3.10.

## How the merge was done

Day 1 of the merge (W1, 2026-09-23). Everything here was COPIED from the source
trees below; no source tree was modified. A one-off merge script (kept
with the private merge history, not in this tree) did the mechanical move
(commit 830124f, no hand edits); every judgment call after it is
its own commit. `tools/port_moves.tsv` lists every package file's old and new
path; the per-module tables at the bottom were generated by a
second one-off script and name every top-level function and class.

## Where each source came from

| key | source | checked-out branch, tip | package files | ported tests |
|---|---|---|---|---|
| ledger | arcaeon-ledger 0.8.0 + arcaeon-adapter 0.2.0, `arcaeon-ledger-rel080` | reconcile-hardening-2026-09-23, f1c162a (unreleased reconcile hardening included) | 21 | 855 (adapter 217, prepublish tool 29) |
| receipt | arcaeon-receipt 0.2.0, `arcaeon-receipt-rel` | receipt-release-2026-09-23, 4af2b2c | 19 | 385 |
| once | arcaeon-once 0.2.3, `arcaeon-once` | audit/2026-08-28-silent-clean-checks, 1d5aa38 | 6 | 64 |
| audit | arcaeon-audit 0.1.8, `arcaeon-audit` | master, e12034c | 2 | 86 |
| compact | arcaeon-compact 0.1.5, `arcaeon-compact` | main, e6da45a | 2 | 56 |
| continuity | arcaeon-continuity 0.2.4, `arcaeon-continuity` | main, ba426e4 | 6 (1 dropped as duplicate) | 147 |
| baseline | arcaeon-baseline 0.1.9, `arcaeon-baseline` | leak-fixes-2026-09-15, c863ad9 | 6 | 100 |
| vet | arcaeon-mcp-vet 0.0.17, `private monorepo projects/mcp_vet` | private monorepo a3922be6 | 16 | 494 |
| dedup | arcaeon-dedup 0.1.5, `arcaeon-dedup` | master, d52a218 | 1 | 48 |
| distill | arcaeon-distill 0.1.7, `arcaeon-distill` | main, 66464de | 4 (1 dropped as duplicate) | 74 |
| meter | arcaeon-meter 0.1.7, `arcaeon-meter` | audit/2026-08-28-silent-clean-checks, a8a0f26 | 5 | 62 |
| connector | the current `arcaeon` 0.1.4 (connector), `private monorepo projects/arcaeon_connector` | private monorepo a3922be6 | 7 | 76 |
| ledger_mcp | arcaeon-ledger-mcp 0.1.0 (never published), `private monorepo projects/arcaeon_mcp` | private monorepo a3922be6 | 2 (1 folded) | 6 |
| **total** | | | **97 files, 96 modules** | **2453** |

Each checked-out branch was the newest branch in its repo (checked with
`git for-each-ref --sort=-committerdate`), and every tree was clean. The stale
copies were NOT used: `arcaeon-adapter` (0.1.0, fenced "do not
publish from here"), `arcaeon-ledger` (0.7.5), and
`arcaeon-receipt` (0.1.0).

## The layout

    src/arcaeon/__init__.py      version 0.9.0; imports nothing
    src/arcaeon/verdict.py       the words + ONE exit-code table (new)
    src/arcaeon/cli.py           `arcaeon <verb>`, 22 council verbs + `deal` (new)
    src/arcaeon/record/          row (new), ledger, adapter, receipt, once, call_record, deal (new)
    src/arcaeon/prove/           reconcile, audit, compact, continuity, baseline, vet
    src/arcaeon/save/            dedup, distill, meter
    src/arcaeon/remote/          witness, offers, sealed_scan, licensing (from the connector) + new client calls
    src/arcaeon/mcp/             the connector server; ledger_server (was arcaeon-ledger-mcp)

## Old import path -> new import path

| old | new |
|---|---|
| `arcaeon_ledger` (and every submodule except reconcile) | `arcaeon.record.ledger` |
| `arcaeon_ledger.reconcile` | `arcaeon.prove.reconcile` |
| `arcaeon_adapter` | `arcaeon.record.adapter` |
| `arcaeon_receipt` | `arcaeon.record.receipt` |
| `arcaeon_once` | `arcaeon.record.once` |
| `arcaeon_once._ledger`, `arcaeon_distill._ledger`, `arcaeon_continuity._ledger` | `arcaeon.record.call_record` (one copy) |
| `arcaeon_audit` | `arcaeon.prove.audit` |
| `arcaeon_compact` | `arcaeon.prove.compact` |
| `arcaeon_continuity` | `arcaeon.prove.continuity` |
| `arcaeon_baseline` | `arcaeon.prove.baseline` |
| `mcp_vet` | `arcaeon.prove.vet` |
| `arcaeon_dedup` | `arcaeon.save.dedup` |
| `arcaeon_distill` | `arcaeon.save.distill` |
| `arcaeon_meter` | `arcaeon.save.meter` |
| `arcaeon_connector` | `arcaeon.mcp` |
| `arcaeon_connector.witness` / `.offers` / `.sealed_scan` / `.licensing` | `arcaeon.remote.witness` / `.offers` / `.sealed_scan` / `.licensing` |
| `arcaeon_ledger_mcp`, `arcaeon_ledger_mcp.server` | `arcaeon.mcp.ledger_server` |
| new in 0.9.0: `arcaeon.record.deal` (no old package) | `arcaeon.record.deal`, verb `arcaeon deal` (docs/DEAL.md) |

Old names are NOT importable from `arcaeon` (the kickoff: compat modules live in
the W2 shims, never in `arcaeon`). The test suite blocks them in-process
(`conftest.py`), because this machine still has the old packages installed and
a test that said `import arcaeon_ledger` would otherwise pass against old code.

Each family keeps its component `__version__` (ledger 0.8.0, vet 0.0.17, and so
on; `arcaeon.mcp.__version__` is still the connector's 0.1.4) so the shims can
re-export the old public names unchanged. `arcaeon.__version__` is 0.9.0.

## The deal lane: `arcaeon.record.deal` (new, no old package)

A witnessed transaction recorded on both sides' ledgers (docs/DEAL.md). It
writes ordinary ledger rows (`kind` = "deal.<step>", no new reserved keys),
reuses reconcile's `load_pins`, pin check and `_cannot_read`, and speaks the
`arcaeon.verdict` words and exit codes; `--legacy-exit` changes nothing on it.
Stdlib only (`tests/test_import_weight.py` covers it).

Not added: MCP tools `deal_step` / `deal_dispute`. `arcaeon.mcp.server`
registers each tool as a hand-written wrapper inside `build_server()`, not from
a table, so the design's condition for adding them was not met; they wait for a
deliberate change to that server (and its tool-count tests). `--remote` does not
send deal tapes: `arcaeon.remote.reconcile_tapes` takes agent/tool tapes
(`arcaeon-tape/1`), so it prints that the hosted deal verdict is not yet
available and keeps the local verdict and exit code.

## The row spine: `arcaeon.record.row`

The ledger row format (chain rule, genesis, json-c14n canonicalization, the two
self-describing digests, the pin self-digest, the reserved keys, and the
readers that refuse duplicate keys and retype deep nesting) now lives in one
file. Every copy it replaced, and where each one came from:

| copy | old home | now |
|---|---|---|
| `_chain`, `_GENESIS`, `_CHAIN_LEN` | arcaeon_ledger/__init__.py | imported from row |
| `DuplicateKeyError`, `_reject_duplicate_keys`, `_loads`, `_loads_strict` | arcaeon_ledger/__init__.py | imported from row |
| `_canon_json`, `digest_json`, `digest_bytes` | arcaeon_ledger/artefact.py | imported from row |
| `WitnessStore._digest_record` body | arcaeon_ledger/witness.py | `row.body_digest(rec, ("prev", "self"))` |
| `canon_json`, `_chain`, `_GENESIS`, fallback digests | arcaeon_adapter/_ledger.py | imported from row (the no-library fallback path is kept and still tested) |
| `_chain`, `_GENESIS`, `CallRecord` | arcaeon_once/_ledger.py | `arcaeon.record.call_record`, chain from row |
| same file, byte-identical | arcaeon_distill/_ledger.py | dropped (duplicate of once's) |
| same file, byte-identical | arcaeon_continuity/_ledger.py | dropped (duplicate of once's) |
| `_pin_self_digest` fallback recipe | arcaeon_receipt/core.py | `row.body_digest` |
| `DuplicateKeyError`, `_reject_duplicate_keys`, `loads_strict` | arcaeon_receipt/core.py | imported from row |
| `_canon_json`, `_digest_json_fallback` | arcaeon_continuity/__init__.py | imported from row |
| `_digest_bytes_raw`, `_digest_json_c14n` (with try/except fallback) | arcaeon_distill/__init__.py | imported from row |
| item canonicalization | arcaeon_compact/__init__.py | `row.canon_json` |
| JCS bytes (after refusing floats) | mcp_vet/receipts.py | `row.canon_json` |
| `_RESERVED_ROW_KEYS` | arcaeon_audit/__init__.py | `row.RESERVED_KEYS` plus `"system_id"` |
| duplicate-key/nesting readers | arcaeon_ledger/reconcile.py (imported from ledger) | imported from row |

Reconcile, audit, compact, continuity, distill, receipt, the witness head and
the adapter all import the format from `arcaeon.record.row`. Dedup and meter
have no row code of their own (dedup writes no rows; meter writes through
`Ledger`), so there was nothing to move. `tests/test_import_weight.py::
test_the_row_format_has_no_second_copy_in_src` fails if a second copy of the
chain body, the json-c14n digest or the strict reader appears in src/ (two
deliberately WRONG recipes, used by selftests to prove drift is caught, are
named exceptions). Old private names (`_chain`, `_loads`, ...) are kept as
imports so the moved code and its tests read the same.

## seal

Decision (a), 2026-09-24, branch `seal-for-strangers`: the hosted witness's
pin is the seal, so `arcaeon seal` needs `ARCAEON_KEY` and nothing else.

Before this, `seal` (and `badge --sealed`) refused any badge that was not
signed locally with a key from `MCP_VET_RECEIPT_KEY`. The only such key that
ever existed was a private default path on the maintainer's machine, removed
from the wheel on 2026-09-24. So for every other buyer `seal` had never
worked.

What the witness actually checks, read from the witness source
(arcaeon-witness; `api/pin.js` is byte-identical in the `-rc3b`, `-verdict`
and `-reconcile` trees, the newest three):

- `api/pin.js` line 5: "Body: {namespace, rows, chain, intent?}. Fingerprints
  only".
- `api/pin.js` lines 467-478: auth is the bearer key's namespace prefix
  (`store.keyPrefixFor`, then `issuedKeys.issuedKeyPrefix`); 401 when neither
  knows the key.
- `api/pin.js` lines 482-486: the body goes through `store.validatePin` and
  only `namespace`, `rows`, `chain` are read from it.
- `lib/_store.js` lines 468-479 (`validatePin`): namespace matches
  `[a-z0-9-]{1,64}`, rows is a positive integer, chain is 8 to 64 hex
  characters. Nothing else.
- `api/pin.js` lines 499-503: 403 unless the namespace starts with the key's
  prefix.
- No Ed25519 or signature verification anywhere in `api/pin.js`; its
  `require`s (lines 25-36) are crypto (for ids), `_store`, `_verdict`,
  `_meter`, `_balance`, `_keys`, `_pending`. The Ed25519 code in the witness
  (`lib/_check_record.js`) belongs to the check-record lane, not to pins.
- The client matches: `arcaeon.remote.witness._write` sends exactly
  `{"namespace", "rows", "chain"}`; the badge and its receipt never leave the
  machine.

So the local signature was never what made a seal a seal. Now:

- `seal` with only `ARCAEON_KEY` appends the report to the local sealed-scan
  ledger, pins the head, and records `"signed": "UNSIGNED"` (in the ledger
  row and in `sealed_scan` in the JSON). Exit 0.
- With `arcaeon[sign]` and `MCP_VET_RECEIPT_KEY` the report is also signed,
  the receipt goes into the ledger row, and the seal says `"signed":
  "SIGNED"`.
- With no `ARCAEON_KEY` the one refusal names that key and where to get one;
  it no longer mentions signing. Exit 3, nothing sent, nothing written.
- New `--ns` on `seal` and `badge --sealed`. A key pins only under its own
  prefix (the 403 above), so the old fixed namespace `mcp-vet-sealed-scans`
  only worked for a key whose prefix covers it. A 403 now says "pass --ns
  <your-prefix>-sealed-scans" and that no credit was spent.

### Namespace from the key (branch `ns-from-key`, 2026-09-24)

Decision (a): the key's prefix is readable by the client with no new witness
endpoint, so `seal` no longer makes a stranger pass `--ns`. Where the prefix
is and is not exposed (arcaeon-witness, `-reconcile` tree):

- `api/pin.js` lines 499-503: the 403 body is `this key may only pin
  namespaces starting with "<prefix>"`. It is sent before the rate limiter
  (line 505) and before any metering, so it spends nothing.
- `api/balance.js` lines 192-204: the JSON answer has `key_id`, credit and
  free-tier fields, no prefix. The prefix appears only in the HTML face (line
  104), which is a human page, not a contract.
- `lib/_keys.js` lines 133-146: a key is `wk_` plus 24 random bytes; the
  prefix is `wk-` plus 6 other random bytes, "derived from nothing". The key
  string says nothing about it.

So with no `--ns`, `seal` tries `mcp-vet-sealed-scans` (a key that covers it,
the operator's, keeps its old history there, in one request). On a 403 that
names a prefix it caches the prefix for the process (keyed by the key's
sha256) and retries once under `<prefix>-sealed-scans` (no double dash after
an auto-minted `wk-...-` prefix). At most one extra request, only on the first
seal of a process, and never a second credit. An explicit `--ns` is never
retried; its 403 names the namespace tried and the exact `--ns` to pass. A 403
that names no prefix gets the generic `--ns <your-prefix>-sealed-scans` line.
The result carries `namespace`: where the pin landed.

Tests: `tests/connector/test_sealed_scan.py` (the ns-from-key block) and
`tests/vet/test_sealed_scan_cli.py::test_cli_seal_without_ns_follows_the_keys_prefix`.

Tests: `tests/vet/test_sealed_scan_cli.py` (network mocked at
`witness._http_post`, never a real call). The old test
`test_seal_badge_refuses_unsigned_without_importing_the_connector` asserted
the refusal this decision removes, and was replaced.

## Exit codes (arcaeon.verdict)

One table for every verb: 0 good, 1 a bad finding, 2 bad usage, 3 COULD NOT
LOOK. What changed, and how to keep the old code for the 0.9.x release:

| tool | old code | new code | `--legacy-exit` |
|---|---|---|---|
| reconcile | 2 = COULD NOT LOOK | 3 (`reconcile().exit_code` too) | 2 |
| audit | 2 = could not complete | 3 | 2 |
| receipt | 2 verify failed, 3 flagged check, 4 COULD NOT LOOK | 1, 1, 3 | 2, 3, 4 |
| vet badge | 4 = refused --sealed | 3 | 4 |
| vet verify / audit-verify | 2 = not reproduced / broken | 1 | 2 |
| vet probe | 2 = could not connect | 3 | 2 |
| ledger verify | 3 bounded chain; 1 unreadable file | 3 for both (unreadable: from 0.9.1) | 3; 1 |

Reconcile speaks the table natively; the others' moved code still returns its
old code and `arcaeon <verb>` translates it through `verdict.LEGACY`. An argparse
usage error is never translated. The `--legacy-exit` flag and the no-TTY MCP
fallback go away in 1.0.0.

Reconcile's JSON keeps its machine spelling `"COULD_NOT_LOOK"` (the hosted
service returns the same); `verdict.COULD_NOT_LOOK_TOKEN` names it.

## Tests

- Source suites, collected in place (`pytest --collect-only`): **2453**
  (855 + 385 + 64 + 86 + 56 + 147 + 100 + 494 + 48 + 74 + 62 + 76 + 6).
- Ported: **2453**, all of them. Each tree's test-side files sit in
  `tests/<key>/` at the same position relative to the old repo root, so
  `Path(__file__).parent` lookups still land; each ported test runs with
  `tests/<key>/` as its working directory, as it did at the source.
- Dropped as duplicates: **0**. Two look-alike families were checked and kept:
  `test_error_truncation.py` in continuity, distill and once (same body, but
  each drives a different MCP server's own truncation code), and
  `test_call_record.py` in continuity, once and connector (each drives a
  different server's call record). They share `call_record`, and that is fine;
  their subject is the server.
- Renamed on collision (one pytest session cannot import two modules with one
  basename): `test_call_record`, `test_cli`, `test_concurrency`,
  `test_conformance_failure`, `test_error_truncation`, `test_hardening`,
  `test_mcp_server`, `test_receipts` became `test_<key>_<name>.py`.
- New: 84 tests in four files: `test_import_weight.py` (23), `test_verdict.py` (16),
  `test_cli.py` (44), `test_chain_end_to_end.py` (1, every link asserted).
- Full run on 2026-09-23 (Python 3.14.3): 2537 collected; 2527 passed + 7 xfailed
  (xfails carried from the sources) + 3 skipped, before the sealed_scan fix; after it
  the 2 connector skips run and pass. The one remaining skip is vet's symlink test
  (Windows needs a privilege to create a symlink), skipped at the source too.

### Ported tests whose assertion changed, and why

| test | change |
|---|---|
| ledger/test_reconcile_hardening.py `_cnl` helper (every COULD NOT LOOK assertion in the file, 26 test cases) | COULD NOT LOOK exit 2 -> 3 |
| ledger/test_reconcile.py `test_cli_exit_codes_and_json[c_missing_file]` | 2 -> 3 |
| baseline/test_sdist_hygiene.py (3 tests) | RE-TARGETED: builds the `arcaeon` sdist, not the retired arcaeon-baseline one; probe sets now ship as package data |
| connector/test_readme_config.py (2 tests) | RE-TARGETED at the merged pyproject; the legacy README fixture's client-config stanzas say `arcaeon mcp` |
| vet/test_packaging.py `test_console_script_points_at_a_real_callable` | old `mcp-vet` script target resolved at the moved module (the W2 shim keeps that script) |
| vet/test_action.py (fixture) | `run_vet.py` stays byte-identical to the Marketplace copy; the tests point `MCP_VET_BIN` at a wrapper around the moved code, because this machine still has the old mcp-vet installed |
| vet/test_receipt_key_published.py | reads the published key doc from the site checkout (was a sibling path) |
| connector/test_connector.py license-gate pair | PRIVATE PIECE: named skip unless the private `bridge/license_gate` is present (set by env var on the maintainer's machine) |
| vet/test_gate_drift.py seal_chain gates | PRIVATE PIECE: named skip unless the private `bridge/witness/seal_chain.py` is present (set by env var on the maintainer's machine) |
| sibling-checkout lookups (adapter test_http_forward, receipt test_call_proxy_tape, vet test_audit_record, vet test_sealed_scan_cli, once test_hypothesis_once, vet test_audit_ledger) | read the moved file in src/ instead of a sibling repo; tests that used to SKIP when the sibling was absent now always run |

## Gaps, by name

- **Book pay-guard**: private, not included (it was in no source tree).
- **vet's two `seal_chain.*` gates**: match against the private monorepo's
  `bridge/witness/seal_chain.py`; `arcaeon.prove.vet.gate_drift` reaches it only
  via `ARCAEON_VET_PRIVATE_ROOT`, else raises a named ImportError (the gates
  report it). Not shipped.
- **Connector license gate implementation** (`bridge.license_gate.gate`):
  private, not shipped; `arcaeon.remote.licensing` still resolves it by name,
  default off, fail-closed when required (unchanged behaviour).
- **Hosted pieces** (witness, stamp, reconcile service, balance): Node on
  Vercel, stay there. `arcaeon.remote` reaches them. Still reaching the
  witness directly, outside `arcaeon.remote`, as they did before:
  `record.ledger.witness.HostedWitness`, `record.adapter.tape.pin_at_session_end`,
  `record.receipt.core._witness_pin` (hosted branch), receipt's OTS anchor and
  CourtListener lookup, `record.ledger.artefact` URL fetch. Folding those behind
  `arcaeon.remote` is a follow-up, not a day-1 move.
- **Continuity has no verb**: the council's 22 verbs do not include one;
  continuity is library-only plus `python -m arcaeon.prove.continuity`, and runs
  in `arcaeon selftest`.
- **Not moved**: `arcaeon-recall` (unpublished, not in the kickoff layout), the
  two Apify actors, `arcaeon-all` (metadata only; becomes a W2 shim).
- **Prose still names old packages**: module docstrings, some user-facing hints
  (for example vet's "pip install 'arcaeon-mcp-vet[mcp]'", once's
  "arcaeon_once.rebuild_index()"), and the legacy README/CHANGELOG fixtures under
  `tests/<key>/`. Format identifiers that LOOK like module names were kept on
  purpose: the ASGI scope key `"arcaeon_meter"`, vet's `tool="mcp_vet"` in grade
  artifacts, and vet's default ledger `~/.mcp_vet/audit.jsonl`. W3 owns the docs.

## Per-module tables (generated)


### ledger: arcaeon-ledger 0.8.0 + adapter 0.2.0 (arcaeon-ledger-rel080, branch reconcile-hardening-2026-09-23, f1c162a)

21 module(s).

| old module | new module | names (def/class) now at the new module, unless marked |
|---|---|---|
| `arcaeon_adapter` | `arcaeon.record.adapter` | `__getattr__`, `__dir__` |
| `arcaeon_adapter.__main__` | `arcaeon.record.adapter.__main__` | (no defs: constants / entry point) |
| `arcaeon_adapter._echo_server` | `arcaeon.record.adapter._echo_server` | `handle`, `main`, `_serve` |
| `arcaeon_adapter._ledger` | `arcaeon.record.adapter._ledger` | `backend`, `canon_json` -> `arcaeon.record.row.canon_json`, `digest_json`, `digest_of_frame`, `_now_iso`, `_chain` -> `arcaeon.record.row.chain`, `_FallbackLedger`, `open_ledger`, `_FallbackVerify`, `verify_seam_log` |
| `arcaeon_adapter._version` | `arcaeon.record.adapter._version` | (no defs: constants / entry point) |
| `arcaeon_adapter.http_forward` | `arcaeon.record.adapter.http_forward` | `_connection_named`, `_SSEFrames`, `_AnswerWatcher`, `_upstream_short`, `_Handler`, `ForwardServer`, `_fault_env`, `_parse_listen`, `check_upstream`, `_label`, `build_forward_server`, `run_http_forward` |
| `arcaeon_adapter.observer` | `arcaeon.record.adapter.observer` | `FrameSplitter`, `_parse`, `_id_key`, `_Pending`, `SeamObserver`, `_scoped`, `_render_id`, `_safe_digest`, `_escape_unencodable`, `_status_of` |
| `arcaeon_adapter.proxy` | `arcaeon.record.adapter.proxy` | `_Corruptor`, `_read_some`, `relay`, `_server_label`, `run`, `_digest`, `_looks_like_secret_slot`, `_looks_like_secret_value`, `_plausible_credential`, `_redact_argv`, `_binary_stdin`, `_binary_stdout`, `main` |
| `arcaeon_adapter.selftest` | `arcaeon.record.adapter.selftest` | `SelftestFailure`, `_require`, `json_objects`, `_noop_guard`, `_child_env`, `_run_direct`, `_run_proxied`, `_rows`, `case_passthrough_fidelity`, `_first_diff`, `_count_tool_calls`, `case_one_row_per_call`, `_replay_into`, `_find_unanswered`, `case_unanswered_call_logged`, `case_tamper_detected`, `case_digest_recipe_frozen`, `main` |
| `arcaeon_adapter.tape` | `arcaeon.record.adapter.tape` | `valid_rpc_id`, `render_invalid_id`, `_safe`, `request_digest`, `response_digest`, `_status`, `TapeWriter`, `pin_at_session_end` |
| `arcaeon_ledger` | `arcaeon.record.ledger` | `_absent`, `DuplicateKeyError` -> `arcaeon.record.row.DuplicateKeyError`, `_reject_duplicate_keys` -> `arcaeon.record.row._reject_duplicate_keys`, `_loads_strict` -> `arcaeon.record.row.loads_strict`, `_loads` -> `arcaeon.record.row.loads`, `_now_iso`, `_line_start_before`, `_chain` -> `arcaeon.record.row.chain`, `LedgerWriteError`, `UnverifiedLedgerError`, `_append_lock`, `authority`, `VerifyResult`, `Head`, `Ledger`, `chain_at`, `declare_break`, `_scan_declarations`, `_excused`, `verify_file` |
| `arcaeon_ledger.adversarial` | `arcaeon.record.ledger.adversarial` | `_req`, `Outcome`, `_classify`, `_pump`, `fuzz_line`, `sanity`, `run_all`, `failures`, `python_module_cmd` |
| `arcaeon_ledger.artefact` | `arcaeon.record.ledger.artefact` | `_now_iso`, `_canon_json` -> `arcaeon.record.row.canon_json`, `_digest_string`, `digest_bytes` -> `arcaeon.record.row.digest_bytes`, `digest_json` -> `arcaeon.record.row.digest_json`, `_looks_like_url`, `_strip_userinfo`, `bind_artefact`, `_parse_digest`, `verify_artefact` |
| `arcaeon_ledger.bundle` | `arcaeon.record.ledger.bundle` | `_now_iso`, `_sha256_file`, `_default_fetcher`, `BundleResult`, `_witness_section`, `_readme_text`, `build_bundle`, `main` |
| `arcaeon_ledger.cli` | `arcaeon.record.ledger.cli` | `main` |
| `arcaeon_ledger.mcp_server` | `arcaeon.record.ledger.mcp_server` | `_ToolError`, `_ns_path`, `_bool_arg`, `_line_of`, `_verdict`, `_verify_text`, `_result`, `_error`, `_clip_error`, `_text_content`, `_prove_my_conduct`, `_declare_break_tool`, `calls_path`, `_utf8_clean`, `_record_call`, `_calls_verdict`, `_dispatch_tool`, `handle`, `main` |
| `arcaeon_ledger.mutation_harness` | `arcaeon.record.ledger.mutation_harness` | `MutationFailure`, `_require`, `_noop_guard`, `_mint`, `case_byte_edit_in_row`, `case_row_reorder`, `case_mid_row_delete`, `case_unchained_row_after_chain_start`, `case_chain_comparison_is_full_width`, `case_damage_is_counted_without_cascading`, `case_large_row_does_not_reset_the_chain`, `case_non_object_row_is_typed_not_a_crash`, `case_truncation_vs_witness`, `case_remint_vs_witness`, `case_artefact_digest_mismatch`, `case_canonicalization_recipe_drift`, `case_unknown_recipe_version`, `case_unknown_algorithm`, `case_nan_rejection`, `case_noop_guard_guards_itself`, `_finding_subject_absent`, `run` |
| `arcaeon_ledger.reconcile` | `arcaeon.prove.reconcile` | `Finding`, `Reconciliation`, `_Tape`, `_depth_before_stop`, `_cannot_read`, `_is_tape_row`, `_load`, `_peek_side`, `_walk_index`, `load_pins`, `_pin_targets`, `_check_pin`, `_align`, `_headline`, `reconcile`, `_reconcile`, `main` |
| `arcaeon_ledger.selftest` | `arcaeon.record.ledger.selftest` | `_rejects_nan`, `_plant`, `run` |
| `arcaeon_ledger.tape_pin` | `arcaeon.record.ledger.tape_pin` | `_tape_facts`, `pin_tape` |
| `arcaeon_ledger.witness` | `arcaeon.record.ledger.witness` | `WitnessVerdict`, `WitnessVerify`, `WitnessStore`, `publish_head`, `HostedWitnessError`, `HostedWitness`, `verify_against_witness` |

### receipt: arcaeon-receipt 0.2.0 (arcaeon-receipt-rel, branch receipt-release-2026-09-23, 4af2b2c)

19 module(s).

| old module | new module | names (def/class) now at the new module, unless marked |
|---|---|---|
| `arcaeon_receipt` | `arcaeon.record.receipt` | (no defs: constants / entry point) |
| `arcaeon_receipt.approval` | `arcaeon.record.receipt.approval` | `ApprovalGate`, `_line`, `exhibit`, `hash_artifact`, `artifact_approval_receipt`, `_artifact_line`, `artifact_exhibit` |
| `arcaeon_receipt.approval_mcp` | `arcaeon.record.receipt.approval_mcp` | `_ToolError`, `_empty_state`, `_load_state`, `_save_state`, `_quarantine`, `_process_decisions`, `_approval_propose`, `_approval_status`, `_approval_list_pending`, `_approval_executed`, `_result`, `_error`, `_clip_error`, `_text_content`, `_Server`, `main` |
| `arcaeon_receipt.archive` | `arcaeon.record.receipt.archive` | `ArchiveIntegrityError`, `_now`, `_sha256`, `_ledger_files`, `_exhibit_of`, `gather`, `_receipt_rows`, `build_manifest`, `manifest_json`, `exit_code`, `readme_text`, `_write_zip`, `_audit`, `build_archive`, `summary_line` |
| `arcaeon_receipt.authorship` | `arcaeon.record.receipt.authorship` | `_fold`, `AuthorshipSession`, `replay`, `_line`, `exhibit` |
| `arcaeon_receipt.authorship_ingest` | `arcaeon.record.receipt.authorship_ingest` | `_load`, `verify_export`, `from_export`, `main` |
| `arcaeon_receipt.authorship_mcp` | `arcaeon.record.receipt.authorship_mcp` | `_ToolError`, `_authorship_open`, `_get_session`, `_authorship_event`, `_authorship_close`, `_authorship_ingest_export`, `_result`, `_error`, `_clip_error`, `_text_content`, `_Server`, `main` |
| `arcaeon_receipt.ballot` | `arcaeon.record.receipt.ballot` | `pin_ledger_path`, `pin_cost_usd`, `record_pin_request`, `pin_ceiling_status`, `branding`, `ballot_receipt`, `_line`, `_brand_of`, `exhibit`, `RosterError`, `_slug`, `read_roster`, `mint_cohort`, `cohort_summary` |
| `arcaeon_receipt.call` | `arcaeon.record.receipt.call` | `_digest_any`, `_payment_header`, `call_receipt`, `receipted`, `_line`, `exhibit`, `_reject_phone_like`, `_parse_iso`, `phone_call_receipt`, `_phone_line`, `phone_exhibit` |
| `arcaeon_receipt.call_mcp` | `arcaeon.record.receipt.call_mcp` | `_ToolError`, `_require_dict`, `_call_receipt`, `_result`, `_error`, `_clip_error`, `_text_content`, `_Server`, `main` |
| `arcaeon_receipt.call_proxy` | `arcaeon.record.receipt.call_proxy` | `ReceiptStore`, `_build_call_receipt`, `_load_tape_writer`, `_valid_rpc_id`, `_render_invalid_id`, `_tape_calls`, `_decoded`, `_tape_answers`, `_id_key`, `_ToolTape`, `_read_chunked`, `CallProxyHandler`, `build_server`, `main` |
| `arcaeon_receipt.cite` | `arcaeon.record.receipt.cite` | `default_transport`, `fixture_transport`, `_check_from_api`, `normalize_text`, `_shape_key`, `local_citations`, `reconcile`, `check_citations`, `summarize`, `citation_receipt`, `_line`, `exhibit` |
| `arcaeon_receipt.cite_batch` | `arcaeon.record.receipt.cite_batch` | `_paragraphs`, `_split_oversize_paragraph`, `_paragraph_offsets`, `_group_paragraphs`, `split_for_lookup`, `_rebase`, `_paragraph_index_for_offset`, `_units_in_paragraph`, `_sort_key`, `check_citations_batched`, `citation_receipt_batched` |
| `arcaeon_receipt.cite_extract` | `arcaeon.record.receipt.cite_extract` | `_text_from_txt`, `_text_from_pdf`, `_text_from_docx`, `text_from_path` |
| `arcaeon_receipt.cite_mcp` | `arcaeon.record.receipt.cite_mcp` | `_ToolError`, `_cite_check`, `_result`, `_error`, `_clip_error`, `_text_content`, `_Server`, `main` |
| `arcaeon_receipt.cli` | `arcaeon.record.receipt.cli` | `_exhibit`, `_does_not_prove`, `main` |
| `arcaeon_receipt.core` | `arcaeon.record.receipt.core` | `_now_iso`, `_body_of`, `_witness_pin`, `ots_exe`, `_run_ots`, `_anchor_bytes`, `_ots_stamp`, `ots_verify`, `engagement_scope`, `attestation`, `attach_attestation_signature`, `_pin_self_digest`, `_check_witness`, `_check_attestation_signature`, `_claimed_fields`, `build_receipt`, `verify_receipt`, `DuplicateKeyError` -> `arcaeon.record.row.DuplicateKeyError`, `_reject_duplicate_keys` -> `arcaeon.record.row._reject_duplicate_keys`, `loads_strict` -> `arcaeon.record.row.loads_strict`, `load_receipt`, `save_receipt`, `render_exhibit` |
| `arcaeon_receipt.roster_report` | `arcaeon.record.receipt.roster_report` | `_now`, `score_of`, `_check`, `_facts`, `_load`, `resolve_target`, `verify_pages`, `passes_line`, `_one_of`, `_scope_text`, `build_report`, `exit_code`, `to_csv`, `to_json`, `summary_line` |
| `arcaeon_receipt.verify_batch` | `arcaeon.record.receipt.verify_batch` | `CapExceeded`, `NoReceiptsFound`, `collect_paths`, `resolve_ledger`, `verify_one`, `_verify_one_guarded`, `verify_batch`, `summary_line`, `render`, `exit_code` |

### once: arcaeon-once 0.2.3 (arcaeon-once, 1d5aa38)

5 module(s).

| old module | new module | names (def/class) now at the new module, unless marked |
|---|---|---|
| `arcaeon_once` | `arcaeon.record.once` | `_now_iso`, `_outcome_form`, `_outcome_digest`, `_check_key`, `_default_index_path`, `_connect`, `_index_setup_lock`, `_index_is_usable`, `_set_wal`, `_init_index`, `_migrate_lease_columns`, `_run_with_retry`, `_index_txn`, `_claim`, `_mark_executed`, `_read_generation`, `_reclaim_after_indeterminate`, `rebuild_index`, `_pid_alive`, `reclaim`, `Receipt`, `receipt`, `_receipt_with_vr`, `complete`, `AlreadyExecuted`, `Indeterminate`, `HolderAlive`, `LivenessUnknown`, `IndexUnavailable`, `TamperDetected`, `GuardContext`, `guard` |
| `arcaeon_once._ledger` | `arcaeon.record.call_record` | `default_path`, `_chain` -> `arcaeon.record.row.chain`, `CallRecord`, `verify_call_record` |
| `arcaeon_once.cli` | `arcaeon.record.once.cli` | `main` |
| `arcaeon_once.mcp_server` | `arcaeon.record.once.mcp_server` | `_result`, `_error`, `_clip_error`, `_text_content`, `_call_guard`, `handle`, `_record_call`, `_dispatch_tool`, `main` |
| `arcaeon_once.selftest` | `arcaeon.record.once.selftest` | `run` |

### audit: arcaeon-audit 0.1.8 (arcaeon-audit, e12034c)

2 module(s).

| old module | new module | names (def/class) now at the new module, unless marked |
|---|---|---|
| `arcaeon_audit` | `arcaeon.prove.audit` | `_now_iso`, `AuditLog`, `_read_rows`, `_summ`, `_resolve_witness`, `_verify_query`, `_reverify_recipe`, `_witness_nature`, `witness_nature_of`, `export_bundle` |
| `arcaeon_audit.cli` | `arcaeon.prove.audit.cli` | `_InstrumentNotesError`, `_read_instrument_notes`, `main` |

### compact: arcaeon-compact 0.1.5 (arcaeon-compact, e6da45a)

2 module(s).

| old module | new module | names (def/class) now at the new module, unless marked |
|---|---|---|
| `arcaeon_compact` | `arcaeon.prove.compact` | `_now_iso`, `_digest_item`, `_digest_content`, `_well_formed`, `_is_count`, `CompactionReceipt`, `_core_body`, `verify_receipt` |
| `arcaeon_compact.selftest` | `arcaeon.prove.compact.selftest` | `_build_legacy_v1_row`, `run` |

### continuity: arcaeon-continuity 0.2.4 (arcaeon-continuity, ba426e4)

6 module(s).

| old module | new module | names (def/class) now at the new module, unless marked |
|---|---|---|
| `arcaeon_continuity` | `arcaeon.prove.continuity` | `ContinuityDependencyError`, `UnsupportedVerdictVersion`, `_now_iso`, `_canon_json` -> `arcaeon.record.row.canon_json`, `_digest_json_fallback` -> `arcaeon.record.row.digest_json`, `digest_json`, `_require`, `_stringify`, `_probe_set_digest`, `_require_unique`, `_explicit_id_item`, `_content_id`, `_list_item_probe_spec`, `_derive_probes`, `restate`, `_coerce_probes`, `_probe_to_dict`, `_write_probes_jsonl`, `_identity_runner`, `_RecordingRunner`, `_exact_divergences`, `_normalize_divergence`, `_base_severity`, `_apply_severity`, `_restated_runner`, `ContinuitySnapshot`, `snapshot`, `ContinuationVerdict`, `verdict_from_dict`, `verify_continuation`, `CheckpointReceipt`, `classify_checkpoint`, `_positive_refusal`, `_positive_delivery_receipt`, `DeliveryReceipt`, `added_since_seal`, `diff_seals`, `CarryResult`, `carry_forward`, `DropReceipt`, `drop_receipt` |
| `arcaeon_continuity.__main__` | `arcaeon.prove.continuity.__main__` | `main` |
| `arcaeon_continuity._ledger` | dropped: byte-identical duplicate of `arcaeon_once._ledger`, now `arcaeon.record.call_record` | all names via `arcaeon.record.call_record` |
| `arcaeon_continuity.calibration` | `arcaeon.prove.continuity.calibration` | `load_fixtures`, `fixture_set_digest`, `run_curve`, `render_table`, `main` |
| `arcaeon_continuity.mcp_server` | `arcaeon.prove.continuity.mcp_server` | `_result`, `_error`, `_clip_error`, `_text_content`, `_call_continuity_snapshot`, `handle`, `_record_call`, `_dispatch_tool`, `main` |
| `arcaeon_continuity.selftest` | `arcaeon.prove.continuity.selftest` | `_restated_from_snapshot`, `run` |

### baseline: arcaeon-baseline 0.1.9 (arcaeon-baseline, c863ad9)

6 module(s).

| old module | new module | names (def/class) now at the new module, unless marked |
|---|---|---|
| `arcaeon_baseline` | `arcaeon.prove.baseline` | `_now_iso`, `_slug`, `Probe`, `_parse_probe_line`, `load_probes`, `probe_set_digest`, `_items_digest`, `run_probes`, `aggregate`, `_significance_note`, `_ledger_opt_out`, `register`, `_compare_scope`, `_coverage_note`, `compare` |
| `arcaeon_baseline.__main__` | `arcaeon.prove.baseline.__main__` | (no defs: constants / entry point) |
| `arcaeon_baseline.cli` | `arcaeon.prove.baseline.cli` | `_add_common_runner_args`, `main` |
| `arcaeon_baseline.runner` | `arcaeon.prove.baseline.runner` | `RunnerError`, `Runner`, `CmdRunner`, `CallableRunner` |
| `arcaeon_baseline.scoring` | `arcaeon.prove.baseline.scoring` | `_normalize`, `is_abstention`, `ScoreResult`, `_contains`, `score_exact_match`, `score_numeric_tolerance`, `score_calibration`, `score_item` |
| `arcaeon_baseline.selftest` | `arcaeon.prove.baseline.selftest` | `_write_fixture`, `_good_model`, `_degraded_model`, `run` |

### vet: arcaeon-mcp-vet 0.0.17 (private monorepo projects/mcp_vet, a3922be6)

16 module(s).

| old module | new module | names (def/class) now at the new module, unless marked |
|---|---|---|
| `mcp_vet` | `arcaeon.prove.vet` | (no defs: constants / entry point) |
| `mcp_vet.__main__` | `arcaeon.prove.vet.__main__` | `main` |
| `mcp_vet.badge` | `arcaeon.prove.vet.badge` | `battery_digest`, `BadgeClaimError`, `_static_line`, `_dynamic_line`, `_assert_no_runtime_claim`, `BadgeReport`, `_result_line`, `badge_report`, `_severity_counts`, `_assert_required`, `assert_no_banned_language`, `_esc`, `render_svg` |
| `mcp_vet.badge_cli` | `arcaeon.prove.vet.badge_cli` | `_count_pruned_test_fixture_files`, `_key_source`, `_receipt_block`, `build_badge`, `seal_badge`, `render_badge_text` |
| `mcp_vet.checks` | `arcaeon.prove.vet.checks` | `Finding`, `register`, `check_names`, `_const_str`, `_call_name`, `_import_bindings`, `_canon_call`, `_has_shell_true`, `_first_arg_is_shell_list`, `check_unsafe_exec`, `_is_dynamic_import_exec`, `_yaml_load_is_unsafe`, `check_unsafe_deser`, `_is_tool_handler`, `_tainted_names`, `_arg_is_tainted`, `_is_mapping_lookup`, `check_ssrf`, `check_path_traversal`, `check_zero_auth`, `_entropy`, `_is_public_shape`, `_redact`, `_vendor_hits`, `_is_secret_name`, `_looks_like_a_live_secret`, `_assign_name`, `_named_string_constants`, `_comments`, `_offset_line`, `_env_line_findings`, `check_secret_in_code`, `_short`, `_receiver_name`, `_words`, `_string_words`, `_idents`, `_dispatch_handlers`, `_has_entrypoint`, `_Mod`, `_mod_from_tree`, `_dotted`, `_methods`, `_Walker`, `_call_sites`, `_flatten`, `_middleware_roots`, `_merge_origins`, `_reachable`, `_open_is_append`, `_sql_is_insert`, `_record_kind`, `_record_fields`, `_has_timestamp`, `_tamper_evidence`, `_reconstructable`, `_audit_roots`, `audit_record_applies`, `check_audit_record`, `_dict_str_items`, `_gate_verdict`, `_receipt_fields`, `_own_returns`, `check_unreceipted_allow`, `_own_nodes`, `_is_none`, `_error_marked`, `_success_shape`, `_polarity_documented`, `_catches_keyerror`, `_get_default_only_body`, `_dead_keyerror_candidates`, `_except_success_hits`, `_scan_root`, `_rel_site`, `_except_success_scan`, `_via_phrase`, `_merge_via`, `check_except_returns_success`, `except_success_coverage`, `_takes_package_dir`, `scan_source_ex`, `scan_source`, `scan_file` |
| `mcp_vet.dynamic_checks` | `arcaeon.prove.vet.dynamic_checks` | `register_dynamic`, `dynamic_check_names`, `impossible_string`, `unknown_key`, `_scalar_type`, `_mentions_filter_word`, `filter_shaped_params`, `neutral_args`, `impossible_value`, `cardinality`, `_is_read_only`, `param_binding_liveness` |
| `mcp_vet.fixture_census` | `arcaeon.prove.vet.fixture_census` | `_project_root`, `_own_test_files`, `_literal_len`, `_module_string_aliases`, `_FileCounter`, `fixture_coverage` |
| `mcp_vet.gate_drift` | `arcaeon.prove.vet.gate_drift` | `as_matcher`, `GateSpec`, `register_gate`, `resolve_matcher`, `accept_set`, `_corpus_path`, `_baseline_path`, `load_corpus`, `load_baseline`, `write_baseline`, `DriftReport`, `check_gate`, `update_baseline_from_corpus`, `_vendor_shape_pattern`, `_seal_chain`, `main` |
| `mcp_vet.grade` | `arcaeon.prove.vet.grade` | `_verdict`, `Grade`, `record_static_from`, `grade_source`, `dynamic_record`, `verify`, `pass_receipt_gaps` |
| `mcp_vet.instrument` | `arcaeon.prove.vet.instrument` | `ScanCost`, `_tree_bytes`, `_graded_bytes`, `timed_scan_target`, `percentile` |
| `mcp_vet.probe` | `arcaeon.prove.vet.probe` | `CapReached`, `CallOutcome`, `ProbeSession`, `_looks_rate_limited`, `_leaf_error`, `_error_text`, `_call_once`, `_artifact`, `run_probe`, `_run_on_loop`, `render_probe_text` |
| `mcp_vet.receipts` | `arcaeon.prove.vet.receipts` | `_probe`, `receipts_status_line`, `ReceiptsUnavailable`, `_require_backend`, `_sign_bytes`, `_verify_bytes`, `public_key_from_seed`, `generate_seed`, `load_seed`, `_b58encode`, `did_key`, `_canonical`, `_reject_floats`, `canonical_sha256`, `_as_grade_dict`, `sign_grade`, `verify_receipt_detail`, `verify_receipt` |
| `mcp_vet.server` | `arcaeon.prove.vet.server` | `_audit_off_reason`, `audit_ledger_path`, `audit_status_line`, `_clip`, `_record_call`, `verify_audit_ledger`, `build_instructions`, `_server_class`, `_fenced_root`, `_read`, `_fenced`, `_severity_verdict`, `scan_recorded`, `grade_recorded`, `_tool_error_class`, `_anticipated`, `build_server`, `serve` |
| `mcp_vet.service` | `arcaeon.prove.vet.service` | `_gradeable`, `_is_test_or_fixture`, `select_files`, `TargetGrade`, `_iter_source_files`, `_skipped_files`, `scan_target` |
| `mcp_vet.ts_checks` | `arcaeon.prove.vet.ts_checks` | `available`, `_language`, `_text`, `_walk`, `_callee`, `_short`, `_receiver`, `_args`, `_idents`, `_string_words`, `_object_keys`, `_func_like`, `_tool_name_of`, `_unwrap`, `_decorators_of`, `_decorator_name`, `_handler_roots`, `_has_entrypoint`, `_local_funcs`, `_default_export`, `_imports`, `_parse`, `_link_siblings`, `_lookup`, `_reachable`, `_record_kind`, `_has_timestamp`, `_tamper_evidence`, `_reconstructable`, `audit_record_applies`, `check_audit_record_ts`, `_pairs`, `_ts_error_marked`, `_ts_success_shape`, `_ts_polarity_documented`, `_catch_param_names`, `_root_handler_name`, `_ts_catch_sites`, `ts_check_catch_returns_success`, `_handler_label`, `ts_except_success_coverage`, `is_ts_path`, `file_resolver`, `scan_source_ts_ex` |
| `mcp_vet.verify_page` | `arcaeon.prove.vet.verify_page` | `blind_spot_items`, `_checks_line`, `render_verify_page` |

### dedup: arcaeon-dedup 0.1.5 (arcaeon-dedup, d52a218)

1 module(s).

| old module | new module | names (def/class) now at the new module, unless marked |
|---|---|---|
| `arcaeon_dedup` | `arcaeon.save.dedup` | `_normalize`, `_char_grams`, `_word_bigrams`, `_jaccard`, `_overlap`, `_shingles`, `_feature_hash`, `simhash`, `hamming`, `DedupeReport`, `dedupe` |

### distill: arcaeon-distill 0.1.7 (arcaeon-distill, 66464de)

4 module(s).

| old module | new module | names (def/class) now at the new module, unless marked |
|---|---|---|
| `arcaeon_distill` | `arcaeon.save.distill` | `_digest_bytes_raw` -> `arcaeon.record.row.digest_bytes`, `_digest_json_c14n` -> `arcaeon.record.row.digest_json`, `_digest_value`, `_well_formed`, `_now_iso`, `estimate_tokens`, `_char_budget`, `DropReceipt`, `verify_receipt`, `_receipt_full`, `DistilledResult`, `_walk_json`, `_distill_json`, `_is_row_list`, `_looks_tabular_text`, `_distill_rows`, `_distill_tabular_rows`, `_distill_tabular_text`, `_split_sentences`, `_distill_text`, `_detect_strategy`, `_reject_surrogates`, `_reject_undistillable`, `distill`, `_distill_admitted` |
| `arcaeon_distill._ledger` | dropped: byte-identical duplicate of `arcaeon_once._ledger`, now `arcaeon.record.call_record` | all names via `arcaeon.record.call_record` |
| `arcaeon_distill.mcp_server` | `arcaeon.save.distill.mcp_server` | `_result`, `_error`, `_clip_error`, `_text_content`, `_call_distill`, `_receipt_payload`, `handle`, `_record_call`, `_dispatch_tool`, `main` |
| `arcaeon_distill.selftest` | `arcaeon.save.distill.selftest` | `run` |

### meter: arcaeon-meter 0.1.7 (arcaeon-meter, a8a0f26)

5 module(s).

| old module | new module | names (def/class) now at the new module, unless marked |
|---|---|---|
| `arcaeon_meter` | `arcaeon.save.meter` | `_utc_month`, `_now_iso`, `_check_month`, `key_hash`, `key_id_of`, `Allowance`, `Denied`, `Usage`, `MeterDenied`, `Meter`, `_NoCapSentinel` |
| `arcaeon_meter.__main__` | `arcaeon.save.meter.__main__` | (no defs: constants / entry point) |
| `arcaeon_meter.asgi` | `arcaeon.save.meter.asgi` | `build_middleware` |
| `arcaeon_meter.cli` | `arcaeon.save.meter.cli` | `_add_keys_arg`, `main`, `_run` |
| `arcaeon_meter.keys` | `arcaeon.save.meter.keys` | `new_secret`, `_reject_constant`, `load`, `_locked`, `save`, `add_key`, `_find`, `revoke_key`, `list_keys` |

### connector: arcaeon (connector) 0.1.4 (private monorepo projects/arcaeon_connector, a3922be6)

7 module(s).

| old module | new module | names (def/class) now at the new module, unless marked |
|---|---|---|
| `arcaeon_connector` | `arcaeon.mcp` | (no defs: constants / entry point) |
| `arcaeon_connector.__main__` | `arcaeon.mcp.__main__` | `main` |
| `arcaeon_connector.licensing` | `arcaeon.remote.licensing` | `required`, `load_gate`, `refusal_for`, `_refusal_text`, `status` |
| `arcaeon_connector.offers` | `arcaeon.remote.offers` | `resolve_sealed_scan_sku`, `sealed_scan_sku_unconfigured`, `upgrade_message` |
| `arcaeon_connector.sealed_scan` | `arcaeon.remote.sealed_scan` | `sealed_scan_log_path`, `_key`, `sealed_scan_refusal`, `_insufficient_credit`, `seal` |
| `arcaeon_connector.server` | `arcaeon.mcp.server` | `ledger_path`, `ns_dir`, `_key`, `call_record_path`, `_tool_error_class`, `_anticipated`, `_Outcome`, `_attempt`, `_args_digest`, `_record_call`, `verify_call_record`, `_ledger_call`, `_witness_call`, `_server_class`, `build_server`, `_status_payload`, `serve` |
| `arcaeon_connector.witness` | `arcaeon.remote.witness` | `base_url`, `_http_post`, `_json_or_text`, `_write`, `pin`, `renew` |

### ledger_mcp: arcaeon-ledger-mcp 0.1.0, never published (private monorepo projects/arcaeon_mcp, a3922be6)

2 module(s).

| old module | new module | names (def/class) now at the new module, unless marked |
|---|---|---|
| `arcaeon_ledger_mcp` | dropped: byte-identical duplicate of `arcaeon_once._ledger`, now `arcaeon.record.call_record` | all names via `arcaeon.record.call_record` |
| `arcaeon_ledger_mcp.server` | `arcaeon.mcp.ledger_server` | `_ledger_root`, `_contained`, `ledger_create`, `_args_digest`, `ledger_append`, `ledger_verify`, `main` |

## The MCP door after 0.9.0 (decision, 2026-09-24)

The base install has no dependencies, so `arcaeon mcp` needs the `[mcp]` extra. The registry
entry for `io.arcaeon/arcaeon` carries a runtime argument (`uvx --with "mcp>=2.0.0,<3" arcaeon mcp`)
so registry clients get the SDK. Anyone who typed bare `uvx arcaeon` against the old connector
(0.1.x, which depended on the SDK) will, after 0.9.0 is on PyPI, see one line naming
`pip install 'arcaeon[mcp]'` and exit 2 instead of a server. That is the accepted cost of a
dependency-free base; the two old registry listings are marked deprecated with a message
pointing at the new entry once it reads back. Reversal, if the cost proves too high: add
`mcp>=2,<3` to the base dependencies in 0.9.1.
