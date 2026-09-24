# SPDX-License-Identifier: MIT
"""Record: write the row, and keep it honest.

    arcaeon.record.row          the row format every tool reads and writes
    arcaeon.record.ledger       the hash-chained JSONL ledger (was arcaeon-ledger)
    arcaeon.record.adapter      the stdio/HTTP seam proxy (was arcaeon-adapter)
    arcaeon.record.receipt      portable receipts (was arcaeon-receipt)
    arcaeon.record.once         executed-once receipts (was arcaeon-once)
    arcaeon.record.call_record  the MCP servers' own call record

Nothing is imported here on purpose: the adapter sits in front of every MCP
call, and `import arcaeon.record.adapter` must stay stdlib-only.
"""
