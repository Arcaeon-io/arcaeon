"""The bundled offers.json is a mirror of the site's, byte for byte.

The package cannot read the site at runtime, so `src/arcaeon/remote/offers.json`
ships as a copy. A copy that drifts quotes an offer the catalog no longer makes.
Where the site copy is named by ARCAEON_SITE_OFFERS (a path to its
offers.json), the two must be byte-identical; unset or missing (an end-user
install), this skips.
"""
import os
from pathlib import Path

import pytest

from arcaeon.remote import offers

BUNDLED = Path(offers.__file__).with_name("offers.json")


def test_bundled_offers_is_byte_identical_to_the_site_copy():
    raw = os.environ.get("ARCAEON_SITE_OFFERS")
    if not raw:
        pytest.skip("ARCAEON_SITE_OFFERS is not set; no site offers.json to compare")
    site = Path(raw)
    if not site.is_file():
        pytest.skip("ARCAEON_SITE_OFFERS does not name a file")
    assert BUNDLED.read_bytes() == site.read_bytes(), (
        f"{BUNDLED} has drifted from {site}; copy the site file over, do not hand-edit")


def test_upgrade_message_names_the_free_monthly_pins_not_a_grant():
    """The live price list gives each key free pins every month and no
    registration grant; the refusal names that free door, not a number."""
    msg = offers.upgrade_message("witness_pin")
    assert ("Each key has free pins every month; the numbers and plans: "
            "https://arcaeon.io/pricing.") in msg
    assert "500 credits" not in msg and "per verified email" not in msg
    assert "buy.stripe.com" not in msg
    msg.encode("ascii")
