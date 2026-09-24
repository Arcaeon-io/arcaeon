# The old package names (shims)

Before 0.9, Arcaeon shipped as thirteen separate packages: `arcaeon-ledger`,
`arcaeon-adapter`, `arcaeon-receipt`, `arcaeon-audit`, `arcaeon-mcp-vet`,
`arcaeon-once`, `arcaeon-compact`, `arcaeon-continuity`, `arcaeon-baseline`,
`arcaeon-dedup`, `arcaeon-distill`, `arcaeon-meter` and `arcaeon-all`. Now there
is one package, `arcaeon`, with one command, `arcaeon`.

## What a shim is

A shim is a tiny package that keeps an old name working. Each folder here is one
old name's last release. It contains two things and nothing else:

1. **A forwarding module under the old import name.** `import arcaeon_ledger`
   still works, and `arcaeon_ledger.Ledger` is the very same class as
   `arcaeon.record.ledger.Ledger`. Old submodule paths (`arcaeon_ledger.witness`,
   `mcp_vet.checks`, ...) point at their new homes too. Importing the old name
   raises one DeprecationWarning that names the new module to import instead.
2. **The old command, if the package had one.** `arcaeon-ledger verify log.jsonl`
   now runs `arcaeon verify log.jsonl`; `mcp-vet probe` runs `arcaeon vet probe`;
   and so on. Where the new command changed an exit code (reconcile, audit,
   receipt, vet), the old command asks for the old one (`--legacy-exit`), so a
   CI gate wired to the old code keeps its meaning.

The code itself is not in the shim. It lives in `arcaeon`, and the forwarding
modules live only here, never inside `arcaeon`, so no two packages ever ship
the same file.

## Installing an old name installs the new package

Each shim depends on `arcaeon>=0.9,<1` and nothing else (`arcaeon-all` depends on
`arcaeon[all]`, which adds every optional extra). So `pip install arcaeon-ledger`
gives you `arcaeon` plus the forwarding module, and an existing
`requirements.txt` keeps installing without an edit. The shims need Python 3.10
or newer; on Python 3.9, pip keeps resolving the last real release of each old
name, which still works.

| old name | last release (shim) | old import | new import | old command -> new verb |
|---|---|---|---|---|
| arcaeon-ledger | 0.8.1 | `arcaeon_ledger` | `arcaeon.record.ledger` | `arcaeon-ledger` -> `arcaeon verify` / `log` / `reconcile` |
| arcaeon-adapter | 0.2.1 | `arcaeon_adapter` | `arcaeon.record.adapter` | `arcaeon-adapter` -> `arcaeon proxy`; `arcaeon-adapter-selftest` -> `arcaeon selftest adapter` |
| arcaeon-receipt | 0.2.1 | `arcaeon_receipt` | `arcaeon.record.receipt` | `arcaeon-receipt` -> `arcaeon receipt` |
| arcaeon-audit | 0.1.9 | `arcaeon_audit` | `arcaeon.prove.audit` | `arcaeon-audit` -> `arcaeon audit` |
| arcaeon-mcp-vet | 0.0.18 | `mcp_vet` | `arcaeon.prove.vet` | `mcp-vet` -> `arcaeon vet` |
| arcaeon-once | 0.2.4 | `arcaeon_once` | `arcaeon.record.once` | `arcaeon-once` -> `arcaeon once` |
| arcaeon-compact | 0.1.6 | `arcaeon_compact` | `arcaeon.prove.compact` | (had no command) |
| arcaeon-continuity | 0.2.5 | `arcaeon_continuity` | `arcaeon.prove.continuity` | (had no command) |
| arcaeon-baseline | 0.1.10 | `arcaeon_baseline` | `arcaeon.prove.baseline` | `arcaeon-baseline` -> `arcaeon baseline` |
| arcaeon-dedup | 0.1.6 | `arcaeon_dedup` | `arcaeon.save.dedup` | (had no command) |
| arcaeon-distill | 0.1.8 | `arcaeon_distill` | `arcaeon.save.distill` | (had no command) |
| arcaeon-meter | 0.1.8 | `arcaeon_meter` | `arcaeon.save.meter` | `arcaeon-meter` -> `arcaeon meter` |
| arcaeon-all | 0.2.3 | `arcaeon_all` (a marker) | `arcaeon` | (had no command) |

Every shim version is one patch above that name's last version. For
`arcaeon-mcp-vet` that is 0.0.18: the moved code was 0.0.17, which (like 0.0.16)
was never published, so PyPI's last is 0.0.15.

## When they go away

With `arcaeon` 1.0.0. That release also removes `--legacy-exit` and the
no-terminal MCP fallback. Until then the shims are the last release of each old
name and receive no changes; to stop seeing the warning, change the import to
the new module in the table above.

The checks for all of this are in `tests/test_shims.py`.
