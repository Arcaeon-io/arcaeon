"""arcaeon.mcp: the connector server (was the `arcaeon` 0.1.x package, `arcaeon_connector`).

Arcaeon ships a shelf of small, single-purpose packages, and a shelf is a
distribution problem: an agent that would use three of them has to find three
of them, install three of them, and wire three stanzas into its client config.
Most never get past the first. This package is the one door — `pip install
arcaeon`, one stdio server, every tool on one list:

    ledger_*   arcaeon-ledger, re-exported whole (append, verify, and the
               agent-facing prove_my_conduct / verify_peer_ledger /
               declare_break)
    vet_*      mcp-vet, the static checker for MCP-server source
    witness_*  the hosted witness's pin/renew — the PAID lane
    arcaeon_status  versions, and which of the above costs money

It re-exports; it does not reimplement. The ledger tools dispatch into
`arcaeon_ledger.mcp_server.handle` — the same function the standalone server
runs — and their descriptions are read off that package's own TOOLS list, so
the text a client reads is the text upstream wrote. The vet tools call
`mcp_vet`'s scanner directly. Two verifiers that can disagree is one verifier
too many; the same rule applies to two copies of a tool.

FREE by default, and the free part is the large part. The gate covers exactly
the two tools that spend money on our side (a hosted pin is a GitHub commit
somebody pays for), and when it fires it hands back a plain sentence with the
price and the link — never a stack trace, never a silent nothing.
"""
# serverInfo.version is the PACKAGE version (qa-fixes 2026-09-24: it said
# 0.1.4, the connector's last standalone release, on a 0.9.0 install).
# The standalone connector's last version is kept for the record only.
from arcaeon import __version__  # noqa: E402

CONNECTOR_STANDALONE_VERSION = "0.1.4"
