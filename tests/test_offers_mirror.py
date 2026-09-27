"""The bundled offers.json is a mirror of the site's, byte for byte.

The package cannot read the site at runtime, so `src/arcaeon/remote/offers.json`
ships as a copy. A copy that drifts quotes an offer the catalog no longer makes.
Where the site checkout is on disk, the two must be byte-identical; elsewhere
(an end-user install) this skips.
"""
import os
from pathlib import Path

import pytest

from arcaeon.remote import offers

BUNDLED = Path(offers.__file__).with_name("offers.json")
SITE = Path(os.environ.get(
    "ARCAEON_SITE_ROOT",
    r"C:\Users\USER\velouria\projects\arcaeon_site")) / ".well-known" / "offers.json"


def test_bundled_offers_is_byte_identical_to_the_site_copy():
    if not SITE.is_file():
        pytest.skip(f"no site offers.json at {SITE}")
    assert BUNDLED.read_bytes() == SITE.read_bytes(), (
        f"{BUNDLED} has drifted from {SITE}; copy the site file over, do not hand-edit")


def test_upgrade_message_names_the_registration_grant_not_a_monthly_tier():
    g = offers.REGISTRATION_GRANT
    assert g and g["credits"] == 500 and g["once"] is True
    msg = offers.upgrade_message("witness_pin")
    assert ("Every new key comes with 500 credits, one time, per verified email; "
            "registration is at https://arcaeon.io/pricing.") in msg
    assert "pins/month" not in msg and "no card" not in msg
    assert not hasattr(offers, "FREE_TIER")
    msg.encode("ascii")
