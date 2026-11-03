"""Where Arcaeon's prices live, and the refusal a paid tool gives without a key.

The one place of record for what Arcaeon charges for is the site's
`.well-known/offers.json` (CATALOG_URL). This package carries no copy of it
and no payment link: `arcaeon buy` reads the live file (arcaeon.remote.catalog),
and everything else names no price either. A price or a link typed here would
outlive the day it was retired.

Everything else in this package is free, permanently, and says so.
"""
from __future__ import annotations

import os

from .catalog import CATALOG_URL, FALLBACK_LINE, PRICING_URL  # noqa: F401 (re-exported)

WITNESS_ENDPOINT = "https://witness.arcaeon.io"

# What a key is and where it comes from: two sentences, no link, no price.
KEY_SENTENCES = (
    "An Arcaeon key (ARCAEON_KEY) is a secret that lets the hosted witness record "
    "pins in your name and counts each pin against that key's plan. "
    "You get one by buying a plan: `arcaeon buy` lists what is on sale, and the "
    "page you reach after paying gives you the key.")

# --- the sealed-scan SKU (board item 84, 2026-09-05) ------------------------
#
# A DOCUMENTED STOREFRONT SKU, not a live one. A sealed scan spends exactly one
# ordinary credit from the SAME balance the credit packs top up -- no second
# ledger, no new billing rail -- but a dedicated $5-for-50 page prices that unit
# on its own terms ($0.10/scan) rather than the generic $0.005/pin rate, the
# same way a retailer can sell the same bolt of cloth by the yard on one shelf
# and pre-cut on another. Until Daniel sets the checkout env var below AND
# wires a real Stripe Payment Link, this SKU is not purchasable anywhere: there
# is no `checkout` key here, and `resolve_sealed_scan_sku()` is built so a missing var can
# never be read as a granted purchase.
SEALED_SCAN_PACK = {
    "sku": "sealed_scan_50",
    "price_usd": 5,
    "scans": 50,
    "price_per_scan_usd": 0.10,
    "checkout_env": "STRIPE_PAYMENT_LINK_SEALED_SCAN_50",
}


def resolve_sealed_scan_sku(payment_link: str | None) -> str | None:
    """Mirror of ascenvo's stripe-webhook `resolvePurchaseFromSession` shape
    (`projects/ascenvo_site/api/stripe-webhook.js`), narrowed to one SKU.

    Returns the sku id when `payment_link` matches the configured env var,
    else `None` -- for BOTH "nobody bought anything" (`payment_link` falsy) and
    "the mapping var isn't set" (nothing to compare against). Those two `None`
    cases are NOT the same fact; `sealed_scan_sku_unconfigured()` names the
    second one so a caller can tell "no purchase" from "cannot tell what was
    bought" -- the distinction ascenvo's webhook answers with a 503-and-park
    rather than a silent 200. This connector has no purchase-fulfilment path
    of its own yet to wire either function into; they exist, tested, so the
    discipline is proven ahead of that wiring rather than improvised at it.
    """
    if not payment_link:
        return None
    configured = os.environ.get(SEALED_SCAN_PACK["checkout_env"], "").strip()
    if configured and payment_link == configured:
        return SEALED_SCAN_PACK["sku"]
    return None


def sealed_scan_sku_unconfigured(payment_link: str | None) -> bool:
    """True only in the "missing MAPPING var, not an unknown price" case: a
    real-looking `payment_link` presented while the env var is unset, so
    nobody can tell what was bought. `False` for "no purchase at all"
    (`payment_link` falsy) -- an unconfigured var is not a finding when nothing
    is trying to resolve against it."""
    if not payment_link:
        return False
    return not os.environ.get(SEALED_SCAN_PACK["checkout_env"], "").strip()


def upgrade_message(tool: str, free_tools: list[str] | None = None) -> str:
    """The plain sentence a caller gets instead of an error when a paid tool is
    invoked with no key.

    Deliberately plain text and deliberately complete: what a key is, where it
    comes from, what to set, and what still works for free right now. It names
    no price and no link: those live on the site and change there. An
    agent reading this should be able to act on it without a second call, and a
    human reading it should not have to guess whether they just hit a bug.
    """
    # ASCII only, on purpose. This string is the one thing here that gets PRINTED
    # to a terminal rather than rendered by a client, and a Windows console at
    # cp1252 turns a well-meant em-dash into a replacement glyph. A refusal
    # message that arrives visibly corrupted reads like the bug it is denying.
    lines = [
        f"{tool} is a paid Arcaeon tool and no ARCAEON_KEY is set, so nothing was sent.",
        "",
        "It pins your ledger head with the hosted witness: a party "
        "you cannot advance, which is the only thing that catches truncation.",
        "",
        KEY_SENTENCES,
        "",
        "Then set ARCAEON_KEY=<your witness key> in the environment this runs in and "
        "call again.",
    ]
    if free_tools:
        lines += [
            "",
            "Free in this same install, no key needed: " + ", ".join(sorted(free_tools)) + ".",
        ]
    return "\n".join(lines)
