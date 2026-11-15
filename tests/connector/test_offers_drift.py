"""The package names the witness endpoint. Prices and checkout links it does
not name at all (`arcaeon buy` reads them live); the endpoint lives in ONE
place of record — the site's `.well-known/offers.json`, which the honesty
contract calls "the single source of truth for what Arcaeon charges for".

The endpoint is snapshotted in `arcaeon.remote.offers`. A snapshot with no drift guard is how a surface
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

from arcaeon.remote.offers import WITNESS_ENDPOINT


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


def test_the_witness_endpoint_snapshot_still_matches_the_catalog():
    witness = _hosted_witness(_catalog())
    assert WITNESS_ENDPOINT == witness["endpoint"], (WITNESS_ENDPOINT, witness["endpoint"])
