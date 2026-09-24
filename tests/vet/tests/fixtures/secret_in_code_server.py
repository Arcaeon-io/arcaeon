"""PLANTED FIXTURE — mcp_vet MCP01 (secret-in-code) design/test fixture.

Every credential-shaped string below is FAKE, generated for this fixture on
2026-08-30, and clearly marked as such. None of these values are wired to
any real account and none should ever be treated as a live secret by any
scanner, human, or automation that encounters this file. This file is not a
real MCP server and is never imported or run — it exists only so
`check_secret_in_code` (design: `mcp_vet/design/MCP01_secret_in_code.md`)
has something concrete to develop and test against.

Three planted positives (one per vendor-shape class from the design doc) plus
one negative control that MUST NOT fire once the check exists.
"""
from __future__ import annotations

import os
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fixture-secret-server")

# --- PLANTED #1: AWS access key ID shape (AKIA + 16 chars) -- FAKE ----------
# Not a real AWS account. Pattern-only: AKIA[0-9A-Z]{16}.
AWS_ACCESS_KEY_ID = "AKIAFAKEFAKEFAKE1234"  # FAKE — planted for MCP01, do not use

# --- PLANTED #2: Stripe secret key shape (sk_live_ + 24+ alnum) -- FAKE ----
# Not a real Stripe account. Pattern-only: sk_live_[0-9a-zA-Z]{24,}.
STRIPE_SECRET_KEY = "sk_live_FAKEFAKEFAKEFAKEFAKEFAKEFAKE"  # FAKE — planted for MCP01, do not use

# --- PLANTED #3: GitHub PAT shape (ghp_ + 36 chars) -- FAKE -----------------
# Not a real GitHub token. Pattern-only: ghp_[A-Za-z0-9]{36}.
GITHUB_TOKEN = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"  # FAKE — planted for MCP01, do not use

# --- NEGATIVE CONTROL: correctly loaded from environment -------------------
# The check must stay silent here. No literal secret value anywhere in this
# assignment — it's a Call/Subscript node, not an ast.Constant string, so
# MCP01 should never flag it by construction (see design doc, "what it
# deliberately does not catch").
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")


@mcp.tool()
def echo_config_status() -> dict:
    """Trivial tool handler so this fixture also parses as a plausible,
    minimally-realistic MCP server shape (decorator present) for any test
    that wants to run the full check suite over it, not just MCP01."""
    return {
        "aws_key_configured": bool(AWS_ACCESS_KEY_ID),
        "stripe_key_configured": bool(STRIPE_SECRET_KEY),
        "github_token_configured": bool(GITHUB_TOKEN),
        "openai_key_configured": bool(OPENAI_API_KEY),
    }
