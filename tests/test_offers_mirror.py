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


def test_upgrade_message_names_the_registration_grant_not_a_monthly_tier():
    g = offers.REGISTRATION_GRANT
    assert g and g["credits"] == 500 and g["once"] is True
    msg = offers.upgrade_message("witness_pin")
    # Registration is dark until offers.json switches it on (test_registration_link.py).
    assert ("Every new key comes with 500 credits, one time, per verified email; "
            "the current offer is at https://arcaeon.io/pricing.") in msg
    assert "regist" not in msg.lower()
    assert "pins/month" not in msg and "no card" not in msg
    assert not hasattr(offers, "FREE_TIER")
    msg.encode("ascii")
