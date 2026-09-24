# SPDX-License-Identifier: MIT
"""Prove: check a record, and say what the check could not see.

    arcaeon.prove.reconcile   two tapes and a counter (was arcaeon_ledger.reconcile)
    arcaeon.prove.audit       regulator-ready bundles (was arcaeon-audit)
    arcaeon.prove.compact     compaction receipts (was arcaeon-compact)
    arcaeon.prove.continuity  continuity snapshots (was arcaeon-continuity)
    arcaeon.prove.baseline    pre-registered probe sets (was arcaeon-baseline)
    arcaeon.prove.vet         the MCP-server source checker (was arcaeon-mcp-vet)

Nothing is imported here on purpose (vet's optional parts pull tree-sitter
and cryptography when asked).
"""
