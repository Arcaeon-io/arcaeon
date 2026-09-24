"""The upgrade message quotes a price and a checkout URL. Those live in ONE
place of record — the site's `.well-known/offers.json`, which the honesty
contract calls "the single source of truth for what Arcaeon charges for".

A shipped package cannot read a path outside itself, so the pack is snapshotted
in `arcaeon_connector.offers`. A snapshot with no drift guard is how a surface
ends up quoting last month's price at a customer (it has happened here twice —
see the two `correction_` entries in offers.json itself). This test closes the
loop: where the catalog is on disk, the snapshot must still match it.

It SKIPS when the site checkout is not present, because an end user installing
from PyPI has no copy of the catalog — the guard is for the workstation that
edits the price, which is the only place the drift can start.
"""
import json
import os
from pathlib import Path

import pytest

from arcaeon.remote.offers import MINI_PACK, WITNESS_ENDPOINT


def _catalog():
    root = os.environ.get("ARCAEON_SITE_ROOT")
    if not root:
        pytest.skip("ARCAEON_SITE_ROOT is not set (no site checkout to compare against)")
    p = Path(root) / ".well-known" / "offers.json"
    if not p.is_file():
        pytest.skip("ARCAEON_SITE_ROOT has no .well-known/offers.json")
    return json.loads(p.read_text(encoding="utf-8"))


def _hosted_witness(cat):
    for prod in cat["products"]:
        if prod["id"] == "hosted-witness":
            return prod
    pytest.fail("hosted-witness is gone from offers.json; the paid lane has no offer behind it")


def test_the_mini_pack_snapshot_still_matches_the_catalog():
    witness = _hosted_witness(_catalog())
    mini = next((t for t in witness["tiers"] if t.get("plan") == "mini"), None)
    assert mini is not None, "the $5 Mini pack is gone from offers.json"

    assert MINI_PACK["price_usd"] == mini["price_usd"], (MINI_PACK, mini)
    assert MINI_PACK["pins"] == int(str(mini["cap"]).split()[0].replace(",", "")), (MINI_PACK, mini)
    assert MINI_PACK["checkout"] == mini["checkout"], (MINI_PACK, mini)
    assert mini.get("status") == "live", (
        "the connector points paying customers at a checkout the catalog no "
        f"longer calls live: {mini.get('status')!r}")


def test_the_witness_endpoint_snapshot_still_matches_the_catalog():
    witness = _hosted_witness(_catalog())
    assert WITNESS_ENDPOINT == witness["endpoint"], (WITNESS_ENDPOINT, witness["endpoint"])
