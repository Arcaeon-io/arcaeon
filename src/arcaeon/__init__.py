# SPDX-License-Identifier: MIT
"""arcaeon: a record of what an agent did that the agent cannot quietly
rewrite, and a way for anyone who doubts it to check.

One package, three families and two doors:

    arcaeon.record   ledger, row, adapter, receipt, once, call_record
    arcaeon.prove    audit, compact, continuity, baseline, reconcile, vet
    arcaeon.save     dedup, distill, meter
    arcaeon.verdict  the shared verdict words and the one exit-code table
    arcaeon.remote   the hosted witness (pin, renew, stamp, balance), HTTPS,
                     only when a verb asks for it; one setting, ARCAEON_KEY
    arcaeon.mcp      the MCP connector server (`arcaeon mcp`, needs [mcp])

Importing `arcaeon` imports nothing else: no submodule, no third-party
package, no network. The base install has zero runtime dependencies; the
heavy parts sit behind extras ([mcp], [ts], [sign], [all]).
"""
__version__ = "0.9.0"
