# SPDX-License-Identifier: MIT
"""arcaeon.connector: another vendor's verdict, relayed into our chain; our row,
exported as an in-toto Statement an outside tool can read.

Not the MCP connector (that is `arcaeon.mcp`). This package is the truth-economy
connector, phase 1: the adapter SHAPE, with one mock vendor. docs/CONNECTOR_ADAPTER.md
says how to write an adapter for a real vendor and what this cannot prove.

    from arcaeon.connector import import_verdict, recheck, export_row, parse_statement
    from arcaeon.connector.mockscan import MOCKSCAN

    row = import_verdict(MOCKSCAN, raw_bytes)      # never raises on vendor input
    chain = Ledger("checks.jsonl").append(row)      # a chain row like any other
    recheck(row, raw_bytes)                         # VERIFIED / BROKEN / COULD NOT LOOK
    stmt = export_row(row, row_chain=chain, ledger="checks.jsonl")  # in-toto Statement v1
    parse_statement(statement_bytes(stmt))          # what an outside reader does

Stdlib only.
"""
from __future__ import annotations

from .core import (ATTESTATION_CLAIMED, ATTESTATION_NONE, JCS_DIGEST_PREFIX, JCS_DIGEST_SCHEME,
                   MAX_DEPTH, MAX_PAYLOAD_BYTES, MAX_STR, OUR_WORDS, ROW_KIND, AdapterError,
                   Extracted, VendorAdapter, adapter_for, import_verdict, jcs_digest, map_word,
                   mark_could_not_look, recheck, register, relayed_row)
from .intoto import (MEDIA_TYPE, PREDICATE_TYPE, STATEMENT_TYPE, StatementError, export_row,
                     parse_statement, statement_bytes, statement_for_check)

__all__ = ["ATTESTATION_CLAIMED", "ATTESTATION_NONE", "MAX_DEPTH", "MAX_PAYLOAD_BYTES",
           "MAX_STR", "OUR_WORDS", "ROW_KIND", "AdapterError", "Extracted", "VendorAdapter",
           "adapter_for", "import_verdict", "map_word", "recheck", "register",
           "JCS_DIGEST_PREFIX", "JCS_DIGEST_SCHEME", "jcs_digest", "mark_could_not_look",
           "relayed_row",
           "MEDIA_TYPE", "PREDICATE_TYPE", "STATEMENT_TYPE", "StatementError", "export_row",
           "parse_statement", "statement_bytes", "statement_for_check"]
